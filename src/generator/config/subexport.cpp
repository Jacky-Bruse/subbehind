#include <algorithm>
#include <iostream>
#include <numeric>
#include <cmath>
#include <climits>

#include "config/regmatch.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "handler/settings.h"
#include "parser/config/proxy.h"
#include "script/script_quickjs.h"
#include "utils/bitwise.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "nodemanip.h"
#include "ruleconvert.h"

extern string_array ss_ciphers, ssr_ciphers;

const string_array clashr_protocols = {
    "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a",
    "auth_chain_b"
};
const string_array clashr_obfs = {
    "plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth"
};
const string_array clash_ssr_ciphers = {
    "rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
    "aes-192-cfb", "aes-256-cfb", "chacha20-ietf", "xchacha20", "none"
};
bool isNumeric(const std::string &str) {
    for (char c: str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

bool isIntegerString(const std::string &str) {
    if (str.empty())
        return false;

    size_t start = str[0] == '-' ? 1 : 0;
    if (start == str.size())
        return false;

    for (size_t i = start; i < str.size(); i++) {
        if (!std::isdigit(static_cast<unsigned char>(str[i])))
            return false;
    }
    return true;
}

YAML::Node yamlScalarFromString(const std::string &value) {
    YAML::Node node;
    if (value == "true")
        node = true;
    else if (value == "false")
        node = false;
    else if (isIntegerString(value))
        node = to_int(value);
    else
        node = value;
    return node;
}

std::string
vmessLinkConstruct(const std::string &remarks, const std::string &add, const std::string &port, const std::string &type,
                   const std::string &id, const std::string &aid, const std::string &net, const std::string &path,
                   const std::string &host, const std::string &tls) {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.Key("v");
    writer.String("2");
    writer.Key("ps");
    writer.String(remarks.data());
    writer.Key("add");
    writer.String(add.data());
    writer.Key("port");
    writer.String(port.data());
    writer.Key("type");
    writer.String(type.empty() ? "none" : type.data());
    writer.Key("id");
    writer.String(id.data());
    writer.Key("aid");
    writer.String(aid.data());
    writer.Key("net");
    writer.String(net.empty() ? "tcp" : net.data());
    writer.Key("path");
    writer.String(path.data());
    writer.Key("host");
    writer.String(host.data());
    writer.Key("tls");
    writer.String(tls.data());
    writer.EndObject();
    return sb.GetString();
}

bool matchRange(const std::string &range, int target) {
    string_array vArray = split(range, ",");
    bool match = false;
    std::string range_begin_str, range_end_str;
    int range_begin, range_end;
    static const std::string reg_num = "-?\\d+", reg_range = "(\\d+)-(\\d+)", reg_not = "\\!-?(\\d+)", reg_not_range =
            "\\!(\\d+)-(\\d+)", reg_less = "(\\d+)-", reg_more = "(\\d+)\\+";
    for (std::string &x: vArray) {
        if (regMatch(x, reg_num)) {
            if (to_int(x, INT_MAX) == target)
                match = true;
        } else if (regMatch(x, reg_range)) {
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if (target >= range_begin && target <= range_end)
                match = true;
        } else if (regMatch(x, reg_not)) {
            match = true;
            if (to_int(regReplace(x, reg_not, "$1"), INT_MAX) == target)
                match = false;
        } else if (regMatch(x, reg_not_range)) {
            match = true;
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if (target >= range_begin && target <= range_end)
                match = false;
        } else if (regMatch(x, reg_less)) {
            if (to_int(regReplace(x, reg_less, "$1"), INT_MAX) >= target)
                match = true;
        } else if (regMatch(x, reg_more)) {
            if (to_int(regReplace(x, reg_more, "$1"), INT_MIN) <= target)
                match = true;
        }
    }
    return match;
}

bool applyMatcher(const std::string &rule, std::string &real_rule, const Proxy &node) {
    std::string target, ret_real_rule;
    static const std::string groupid_regex = R"(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)", group_regex =
            R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
    static const std::string type_regex = R"(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)", port_regex =
            R"(^!!(?:PORT)=(.+?)(?:!!(.*))?$)", server_regex = R"(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)";
    static const std::map<ProxyType, const char *> types = {
        {ProxyType::Shadowsocks, "SS"},
        {ProxyType::ShadowsocksR, "SSR"},
        {ProxyType::VMess, "VMESS"},
        {ProxyType::Trojan, "TROJAN"},
        {ProxyType::Snell, "SNELL"},
        {ProxyType::HTTP, "HTTP"},
        {ProxyType::HTTPS, "HTTPS"},
        {ProxyType::SOCKS5, "SOCKS5"},
        {ProxyType::WireGuard, "WIREGUARD"},
        {ProxyType::VLESS, "Vless"},
        {ProxyType::Hysteria, "HYSTERIA"},
        {ProxyType::Hysteria2, "HYSTERIA2"}
    };
    if (startsWith(rule, "!!GROUP=")) {
        regGetMatch(rule, group_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Group, target);
    } else if (startsWith(rule, "!!GROUPID=") || startsWith(rule, "!!INSERT=")) {
        int dir = startsWith(rule, "!!INSERT=") ? -1 : 1;
        regGetMatch(rule, groupid_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, dir * node.GroupId);
    } else if (startsWith(rule, "!!TYPE=")) {
        regGetMatch(rule, type_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        if (node.Type == ProxyType::Unknown)
            return false;
        std::string target_lower = toLower(target);
        std::string type_lower = toLower(types.at(node.Type));
        return regMatch(type_lower, target_lower);
    } else if (startsWith(rule, "!!PORT=")) {
        regGetMatch(rule, port_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, node.Port);
    } else if (startsWith(rule, "!!SERVER=")) {
        regGetMatch(rule, server_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Hostname, target);
    } else
        real_rule = rule;
    return true;
}

void processRemark(std::string &remark, const string_array &remarks_list, bool proc_comma = true) {
    // Replace every '=' with '-' in the remark string to avoid parse errors from the clients.
    //     Surge is tested to yield an error when handling '=' in the remark string,
    //     not sure if other clients have the same problem.
    std::replace(remark.begin(), remark.end(), '=', '-');

    if (proc_comma) {
        if (remark.find(',') != std::string::npos) {
            remark.insert(0, "\"");
            remark.append("\"");
        }
    }
    std::string tempRemark = remark;
    int cnt = 2;
    while (std::find(remarks_list.cbegin(), remarks_list.cend(), tempRemark) != remarks_list.cend()) {
        tempRemark = remark + " " + std::to_string(cnt);
        cnt++;
    }
    remark = tempRemark;
}

void
groupGenerate(const std::string &rule, std::vector<Proxy> &nodelist, string_array &filtered_nodelist, bool add_direct,
              extra_settings &ext) {
    std::string real_rule;
    if (startsWith(rule, "[]") && add_direct) {
        filtered_nodelist.emplace_back(rule.substr(2));
    }
#ifndef NO_JS_RUNTIME
    else if (startsWith(rule, "script:") && ext.authorized) {
        script_safe_runner(ext.js_runtime, ext.js_context, [&](qjs::Context &ctx) {
            std::string script = fileGet(rule.substr(7), true);
            try {
                ctx.eval(script);
                auto filter = (std::function<std::string(const std::vector<Proxy> &)>) ctx.eval("filter");
                std::string result_list = filter(nodelist);
                filtered_nodelist = split(regTrim(result_list), "\n");
            } catch (qjs::exception) {
                script_print_stack(ctx);
            }
        }, global.scriptCleanContext);
    }
#endif // NO_JS_RUNTIME
    else {
        for (Proxy &x: nodelist) {
            if (applyMatcher(rule, real_rule, x) && (real_rule.empty() || regFind(x.Remark, real_rule)) &&
                std::find(filtered_nodelist.begin(), filtered_nodelist.end(), x.Remark) == filtered_nodelist.end())
                filtered_nodelist.emplace_back(x.Remark);
        }
    }
}

// mihomo 的 parseXHTTPExtra 对这类字段断言 .(float64)，写成字符串会被静默丢弃；
// 但范围值（"100-200"）只能是字符串，Xray 的 Int32Range 两种都收、mihomo 收不了范围。
// 故按形态定型：纯数字走 JSON 数字（两端都认），范围保持字符串（至少 Xray 侧不丢）。
static void addExtraNumericOrRange(rapidjson::Document &obj, const char *key,
                                   const std::string &val,
                                   rapidjson::Document::AllocatorType &alloc) {
    if (val.empty())
        return;
    if (val.find_first_not_of("0123456789") == std::string::npos)
        obj.AddMember(rapidjson::Value(key, alloc),
                      rapidjson::Value(static_cast<int64_t>(atoll(val.c_str()))), alloc);
    else
        obj.AddMember(rapidjson::Value(key, alloc), rapidjson::Value(val.c_str(), alloc), alloc);
}

// yaml-cpp 写字符串标量时不加引号，形似布尔/数字的值被读回来就不再是字符串：
// 密码 "0123" 变数字丢前导零，"true" 变布尔更会让 mihomo 的 decodeString 报
// unconvertible type 而丢弃整个节点。这里判断一个值是否需要锚定类型。
// ponytail: 首字符像数字起始就一律锚定，宁可多一个引号也不漏判；
// 副作用只是 "1abc" 这类值也带上引号，无害。
// 值是否会被 YAML 读成数字。只认真正的数字形态——"1,a"、"16-32"、"1abc"
// 这类本就是字符串，不该锚定：给它们打标签只会让 beautifyStringTags 的
// 文本定界撞上逗号等分隔符而截断，产出损坏的 YAML。
static bool looksLikeYamlNumber(const std::string &v) {
    size_t i = 0;
    if (v[i] == '+' || v[i] == '-')
        ++i;
    if (i >= v.size())
        return false;
    // 0x / 0o / 0b 进制前缀
    if (v.size() - i > 2 && v[i] == '0' && strchr("xXoObB", v[i + 1]) != nullptr)
        return v.find_first_not_of("0123456789abcdefABCDEF", i + 2) == std::string::npos;
    bool digit = false, dot = false, exp = false;
    for (; i < v.size(); ++i) {
        if (isdigit(static_cast<unsigned char>(v[i]))) {
            digit = true;
            continue;
        }
        if (v[i] == '.' && !dot && !exp) {
            dot = true;
            continue;
        }
        if ((v[i] == 'e' || v[i] == 'E') && digit && !exp) {
            exp = true;
            if (i + 1 < v.size() && (v[i + 1] == '+' || v[i + 1] == '-'))
                ++i;
            continue;
        }
        return false;
    }
    return digit;
}

static bool yamlNeedsStringTag(const std::string &v) {
    // 空串无需锚定：yaml-cpp 本就把它输出成 ""，再套一层会变成 """"
    if (v.empty())
        return false;
    const std::string lower = toLower(v);
    if (lower == "true" || lower == "false" || lower == "null" || lower == "~" ||
        lower == "yes" || lower == "no" || lower == "on" || lower == "off")
        return true;
    return looksLikeYamlNumber(v);
}

// 写入字符串标量并在必要时打 !<str> 标签锚定类型，由 beautifyStringTags 还原成
// 标准引号。标签随 Node 走，即使某条输出路径漏了美化，mihomo 读到的依然是字符串
// （yaml.v3 的 resolve 对不可解析的标签原样返回字符串），只是不够好看。
// force 用于语义上必须是字符串的字段，如十六进制的 short-id。
static void setYamlString(YAML::Node node, const std::string &value, bool force = false) {
    node = value;
    if (force || yamlNeedsStringTag(value))
        node.SetTag("str");
}

// JSON object（标量成员）→ YAML map，保留 bool/int/string 类型
static void jsonObjToYamlMap(const rapidjson::Value &obj, YAML::Node out) {
    for (const auto &kv : obj.GetObject()) {
        const char *k = kv.name.GetString();
        if (kv.value.IsBool())
            out[k] = kv.value.GetBool();
        else if (kv.value.IsInt())
            out[k] = kv.value.GetInt();
        else if (kv.value.IsString())
            setYamlString(out[k], kv.value.GetString());
    }
}

// name-cert-verify 与 ech/shadow-tls/restls/jls-opts 写回 YAML（主节点与 download-settings 共用）
static void addMihomoTlsOptsToYaml(const rapidjson::Value &d, YAML::Node out) {
    // 成员存在即为显式覆盖，含空串
    if (d.HasMember("name-cert-verify") && d["name-cert-verify"].IsString())
        setYamlString(out["name-cert-verify"], d["name-cert-verify"].GetString());
    for (const char *k : MIHOMO_TLS_OPT_KEYS) {
        // 注意传 out[k]：未绑定的空 Node 按值传入后赋值不会回传到父树。
        // 空对象是"清除继承"的显式覆盖，同样要写出。
        if (d.HasMember(k) && d[k].IsObject()) {
            jsonObjToYamlMap(d[k], out[k]);
            if (!out[k].IsDefined())
                out[k] = YAML::Node(YAML::NodeType::Map);
        }
    }
}

// Mihomo canonical download JSON → Xray downloadSettings（放进链接的 extra 内）。
// 两边的继承模型不同，不能逐字段照搬：mihomo 用 lo.FromPtrOr(子, 父) 逐项回退到
// 主连接（adapter/outbound/vless.go），而 Xray 的 c.DownloadSettings.Build() 是独立
// 构建、零继承。故此处必须先用父节点物化出完整配置，再套用 download-settings 的覆盖。
// 另：Xray 的 StreamConfig.Build() 默认 ProtocolName="tcp"，只有显式 network 才切换，
// 所以生成的配置必须自带 network=xhttp，否则下行会退回 TCP。
static std::string mihomoDownloadToXrayJson(const Proxy &x, const std::string &download_json) {
    if (download_json.empty())
        return "";
    rapidjson::Document d;
    d.Parse(download_json.data());
    if (d.HasParseError() || !d.IsObject())
        return "";

    rapidjson::Document out;
    out.SetObject();
    auto &alloc = out.GetAllocator();

    // 成员存在即为显式覆盖，缺失则物化父连接的值
    auto pick = [&d](const char *key, const std::string &parent) {
        return (d.HasMember(key) && d[key].IsString()) ? std::string(d[key].GetString()) : parent;
    };

    const std::string address = pick("server", x.Hostname);
    if (!address.empty())
        out.AddMember("address", rapidjson::Value(address.c_str(), alloc), alloc);
    const int port = (d.HasMember("port") && d["port"].IsInt()) ? d["port"].GetInt() : x.Port;
    if (port > 0)
        out.AddMember("port", port, alloc);
    out.AddMember("network", rapidjson::Value("xhttp", alloc), alloc);

    // reality-opts 对象存在即为显式覆盖（空对象表示清除继承的 reality）
    const bool dsHasReality = d.HasMember("reality-opts") && d["reality-opts"].IsObject();
    std::string pbk, sid;
    if (dsHasReality) {
        pbk = GetMember(d["reality-opts"], "public-key");
        sid = GetMember(d["reality-opts"], "short-id");
    } else {
        pbk = x.PublicKey;
        sid = x.ShortId;
    }
    const bool tlsOn = (d.HasMember("tls") && d["tls"].IsBool()) ? d["tls"].GetBool() : x.TLSSecure;
    const bool realityOn = !pbk.empty();
    out.AddMember("security",
                  rapidjson::Value(realityOn ? "reality" : (tlsOn ? "tls" : "none"), alloc), alloc);

    if (realityOn || tlsOn) {
        rapidjson::Value ts(rapidjson::kObjectType);
        const std::string sn = pick("servername", x.ServerName);
        if (!sn.empty())
            ts.AddMember("serverName", rapidjson::Value(sn.c_str(), alloc), alloc);
        const std::string cfp = pick("client-fingerprint", x.ClientFingerprint);
        if (!cfp.empty())
            ts.AddMember("fingerprint", rapidjson::Value(cfp.c_str(), alloc), alloc);
        const bool scv = (d.HasMember("skip-cert-verify") && d["skip-cert-verify"].IsBool())
                             ? d["skip-cert-verify"].GetBool()
                             : x.AllowInsecure.get();
        if (scv)
            ts.AddMember("allowInsecure", true, alloc);
        if (d.HasMember("alpn") && d["alpn"].IsArray() && !d["alpn"].Empty())
            ts.AddMember("alpn", rapidjson::Value(d["alpn"], alloc), alloc);
        else if (!x.AlpnList.empty()) {
            rapidjson::Value alpnArr(rapidjson::kArrayType);
            for (const auto &a : x.AlpnList)
                alpnArr.PushBack(rapidjson::Value(a.c_str(), alloc), alloc);
            ts.AddMember("alpn", alpnArr, alloc);
        }
        if (realityOn) {
            ts.AddMember("publicKey", rapidjson::Value(pbk.c_str(), alloc), alloc);
            if (!sid.empty())
                ts.AddMember("shortId", rapidjson::Value(sid.c_str(), alloc), alloc);
        }
        if (!ts.ObjectEmpty())
            out.AddMember(rapidjson::Value(realityOn ? "realitySettings" : "tlsSettings", alloc),
                          ts, alloc);
    }

    rapidjson::Value xs(rapidjson::kObjectType);
    if (d.HasMember("path") && d["path"].IsString())
        xs.AddMember("path", rapidjson::Value(d["path"], alloc), alloc);
    if (d.HasMember("host") && d["host"].IsString())
        xs.AddMember("host", rapidjson::Value(d["host"], alloc), alloc);
    if (d.HasMember("headers") && d["headers"].IsObject())
        xs.AddMember("headers", rapidjson::Value(d["headers"], alloc), alloc);
    if (d.HasMember("reuse-settings") && d["reuse-settings"].IsObject()) {
        const auto &rs = d["reuse-settings"];
        rapidjson::Value xmux(rapidjson::kObjectType);
        static const struct { const char *mihomo; const char *xray; } reuseMap[] = {
            {"max-connections", "maxConnections"}, {"max-concurrency", "maxConcurrency"},
            {"c-max-reuse-times", "cMaxReuseTimes"}, {"h-max-request-times", "hMaxRequestTimes"},
            {"h-max-reusable-secs", "hMaxReusableSecs"},
        };
        for (const auto &f : reuseMap) {
            if (rs.HasMember(f.mihomo) && rs[f.mihomo].IsString() && rs[f.mihomo].GetStringLength() > 0)
                xmux.AddMember(rapidjson::Value(f.xray, alloc),
                               rapidjson::Value(rs[f.mihomo].GetString(), alloc), alloc);
        }
        // hKeepAlivePeriod 在 Xray 是裸 int64，无字符串反序列化
        if (rs.HasMember("h-keep-alive-period") && rs["h-keep-alive-period"].IsString())
            xmux.AddMember("hKeepAlivePeriod", atoi(rs["h-keep-alive-period"].GetString()), alloc);
        if (!xmux.ObjectEmpty())
            xs.AddMember("xmux", xmux, alloc);
    }
    if (!xs.ObjectEmpty())
        out.AddMember("xhttpSettings", xs, alloc);

    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
    out.Accept(writer);
    return buf.GetString();
}

// Export Mihomo canonical download JSON to xhttp-opts.download-settings YAML node.
// canonical 里成员存在即为显式覆盖（含空串、空对象），必须原样写出；
// 成员缺失才表示沿用主连接，此时不写该键。
static void addXhttpDownloadToYaml(YAML::Node opts, const std::string &download_json) {
    if (download_json.empty())
        return;
    rapidjson::Document d;
    d.Parse(download_json.data());
    if (d.HasParseError() || !d.IsObject())
        return;

    // 必须是已定义的 Map：未绑定的 Node 传值给辅助函数后，函数内的赋值不会
    // 回传到此处（download-settings 只含 TLS 对象时前面的写入都不会执行）
    YAML::Node ds(YAML::NodeType::Map);
    auto emitString = [&](const char *key) {
        if (d.HasMember(key) && d[key].IsString())
            setYamlString(ds[key], d[key].GetString());
    };

    emitString("server");
    if (d.HasMember("port") && d["port"].IsInt())
        ds["port"] = d["port"].GetInt();
    if (d.HasMember("tls") && d["tls"].IsBool())
        ds["tls"] = d["tls"].GetBool();
    emitString("servername");
    if (d.HasMember("alpn") && d["alpn"].IsArray()) {
        for (const auto &a : d["alpn"].GetArray())
            ds["alpn"].push_back(std::string(a.GetString()));
    }
    emitString("client-fingerprint");

    if (d.HasMember("reality-opts") && d["reality-opts"].IsObject()) {
        const auto &ro = d["reality-opts"];
        if (ro.HasMember("public-key") && ro["public-key"].IsString())
            setYamlString(ds["reality-opts"]["public-key"], ro["public-key"].GetString());
        if (ro.HasMember("short-id") && ro["short-id"].IsString())
            setYamlString(ds["reality-opts"]["short-id"], ro["short-id"].GetString(), true);
        if (ro.HasMember("support-x25519mlkem768") && ro["support-x25519mlkem768"].IsBool())
            ds["reality-opts"]["support-x25519mlkem768"] = ro["support-x25519mlkem768"].GetBool();
        // 显式空对象同样是"清除继承"的有效覆盖，必须写出
        if (!ds["reality-opts"].IsDefined())
            ds["reality-opts"] = YAML::Node(YAML::NodeType::Map);
    }

    emitString("path");
    emitString("host");
    if (d.HasMember("headers") && d["headers"].IsObject()) {
        for (const auto &kv : d["headers"].GetObject())
            setYamlString(ds["headers"][kv.name.GetString()], kv.value.GetString());
        if (!ds["headers"].IsDefined())
            ds["headers"] = YAML::Node(YAML::NodeType::Map);
    }

    if (d.HasMember("reuse-settings") && d["reuse-settings"].IsObject()) {
        const auto &rs = d["reuse-settings"];
        for (const char *k : {"max-connections", "max-concurrency", "c-max-reuse-times",
                              "h-max-request-times", "h-max-reusable-secs", "h-keep-alive-period"}) {
            if (rs.HasMember(k) && rs[k].IsString())
                setYamlString(ds["reuse-settings"][k], rs[k].GetString());
        }
        if (!ds["reuse-settings"].IsDefined())
            ds["reuse-settings"] = YAML::Node(YAML::NodeType::Map);
    }

    if (d.HasMember("skip-cert-verify") && d["skip-cert-verify"].IsBool())
        ds["skip-cert-verify"] = d["skip-cert-verify"].GetBool();
    emitString("fingerprint");
    emitString("certificate");
    emitString("private-key");

    addMihomoTlsOptsToYaml(d, ds);

    if (ds.size() > 0)
        opts["download-settings"] = ds;
}

void
proxyToClash(std::vector<Proxy> &nodes, YAML::Node &yamlnode, const ProxyGroupConfigs &extra_proxy_group, bool clashR,
             extra_settings &ext) {
    YAML::Node proxies, original_groups;
    std::vector<Proxy> nodelist;
    string_array remarks_list;
    /// proxies style

    bool proxy_block = false, proxy_compact = false, group_block = false, group_compact = false;
    switch (hash_(ext.clash_proxies_style)) {
        case "block"_hash:
            proxy_block = true;
            break;
        default:
        case "flow"_hash:
            break;
        case "compact"_hash:
            proxy_compact = true;
            break;
    }
    switch (hash_(ext.clash_proxy_groups_style)) {
        case "block"_hash:
            group_block = true;
            break;
        default:
        case "flow"_hash:
            break;
        case "compact"_hash:
            group_compact = true;
            break;
    }

    for (Proxy &x: nodes) {
        YAML::Node singleproxy;

        std::string type = getProxyTypeName(x.Type);
        std::string pluginopts = replaceAllDistinct(x.PluginOption, ";", "&");
        if (ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp;
        tribool xudp = ext.xudp;
        tribool scv = ext.skip_cert_verify;
        tribool tfo = ext.tfo;
        udp.define(x.UDP);
        xudp.define(x.XUDP);
        scv.define(x.AllowInsecure);
        tfo.define(x.TCPFastOpen);
        singleproxy["name"] = x.Remark;
        singleproxy["server"] = x.Hostname;
        singleproxy["port"] = x.Port;

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                //latest clash core removed support for chacha20 encryption
                if (ext.filter_deprecated && x.EncryptMethod == "chacha20")
                    continue;
                singleproxy["type"] = "ss";
                singleproxy["cipher"] = x.EncryptMethod;
                setYamlString(singleproxy["password"], x.Password);
                // 新增 mihomo 参数输出
                if (!x.UdpOverTcp.is_undef()) {
                    singleproxy["udp-over-tcp"] = x.UdpOverTcp.get();
                    if (x.UdpOverTcpVersion > 0)
                        singleproxy["udp-over-tcp-version"] = x.UdpOverTcpVersion;
                }
                if (!x.SmuxEnabled.is_undef() && x.SmuxEnabled.get()) {
                    singleproxy["smux"]["enabled"] = true;
                    if (!x.SmuxProtocol.empty())
                        singleproxy["smux"]["protocol"] = x.SmuxProtocol;
                    if (x.SmuxMaxConnections > 0)
                        singleproxy["smux"]["max-connections"] = x.SmuxMaxConnections;
                    if (x.SmuxMinStreams > 0)
                        singleproxy["smux"]["min-streams"] = x.SmuxMinStreams;
                    if (x.SmuxMaxStreams > 0)
                        singleproxy["smux"]["max-streams"] = x.SmuxMaxStreams;
                    if (!x.SmuxPadding.is_undef())
                        singleproxy["smux"]["padding"] = x.SmuxPadding.get();
                    if (!x.SmuxStatistic.is_undef())
                        singleproxy["smux"]["statistic"] = x.SmuxStatistic.get();
                    if (!x.SmuxOnlyTcp.is_undef())
                        singleproxy["smux"]["only-tcp"] = x.SmuxOnlyTcp.get();
                }
                switch (hash_(x.Plugin)) {
                    case "simple-obfs"_hash:
                    case "obfs-local"_hash:
                        singleproxy["plugin"] = "obfs";
                        singleproxy["plugin-opts"]["mode"] = urlDecode(getUrlArg(pluginopts, "obfs"));
                        singleproxy["plugin-opts"]["host"] = urlDecode(getUrlArg(pluginopts, "obfs-host"));
                        break;
                    case "v2ray-plugin"_hash:
                        singleproxy["plugin"] = "v2ray-plugin";
                        singleproxy["plugin-opts"]["mode"] = getUrlArg(pluginopts, "mode");
                        singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                        singleproxy["plugin-opts"]["path"] = getUrlArg(pluginopts, "path");
                        singleproxy["plugin-opts"]["tls"] = pluginopts.find("tls") != std::string::npos;
                        singleproxy["plugin-opts"]["mux"] = pluginopts.find("mux") != std::string::npos;
                        if (!scv.is_undef())
                            singleproxy["plugin-opts"]["skip-cert-verify"] = scv.get();
                        break;
                }
                break;
            case ProxyType::VMess:
                singleproxy["type"] = "vmess";
                setYamlString(singleproxy["uuid"], x.UserId);
                singleproxy["alterId"] = x.AlterId;
                singleproxy["cipher"] = x.EncryptMethod;
                singleproxy["tls"] = x.TLSSecure;
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                } else if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.ServerName.empty())
                    singleproxy["servername"] = x.ServerName;
                // VMess AEAD 专有能力（mihomo VmessOption 的 global-padding /
                // authenticated-length），此前被错接在 VLESS 分支上
                if (!x.GlobalPadding.is_undef())
                    singleproxy["global-padding"] = x.GlobalPadding.get();
                if (!x.AuthenticatedLength.is_undef())
                    singleproxy["authenticated-length"] = x.AuthenticatedLength.get();
                // 新增 mihomo 参数输出
                if (!x.ClientFingerprint.empty())
                    singleproxy["client-fingerprint"] = x.ClientFingerprint;
                if (!x.IpVersion.empty())
                    singleproxy["ip-version"] = x.IpVersion;
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        break;
                    case "ws"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        if (ext.clash_new_field_name) {
                            singleproxy["ws-opts"]["path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                            if (!x.V2rayHttpUpgrade.is_undef())
                                singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                            if (!x.V2rayHttpUpgradeFastOpen.is_undef())
                                singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"] = x.V2rayHttpUpgradeFastOpen.get();
                            if (x.WsMaxEarlyData > 0)
                                singleproxy["ws-opts"]["max-early-data"] = x.WsMaxEarlyData;
                            if (!x.WsEarlyDataHeaderName.empty())
                                singleproxy["ws-opts"]["early-data-header-name"] = x.WsEarlyDataHeaderName;
                        } else {
                            singleproxy["ws-path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-headers"]["Edge"] = x.Edge;
                        }
                        break;
                    case "http"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["http-opts"]["method"] = "GET";
                        singleproxy["http-opts"]["path"].push_back(x.Path);
                        if (!x.Host.empty())
                            singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                        if (!x.Edge.empty())
                            singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                        break;
                    case "h2"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["h2-opts"]["path"] = x.Path;
                        if (!x.Host.empty())
                            singleproxy["h2-opts"]["host"].push_back(x.Host);
                        break;
                    case "grpc"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["servername"] = x.Host;
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                        break;
                    default:
                        writeLog(0, "Skipping VMess node '" + x.Remark + "': unsupported network '" +
                                    x.TransferProtocol + "'", LOG_LEVEL_WARNING);
                        continue;
                }
                break;
            case ProxyType::ShadowsocksR:
                //ignoring all nodes with unsupported obfs, protocols and encryption
                if (ext.filter_deprecated) {
                    if (!clashR &&
                        std::find(clash_ssr_ciphers.cbegin(), clash_ssr_ciphers.cend(), x.EncryptMethod) ==
                        clash_ssr_ciphers.cend())
                        continue;
                    if (std::find(clashr_protocols.cbegin(), clashr_protocols.cend(), x.Protocol) ==
                        clashr_protocols.cend())
                        continue;
                    if (std::find(clashr_obfs.cbegin(), clashr_obfs.cend(), x.OBFS) == clashr_obfs.cend())
                        continue;
                }

                singleproxy["type"] = "ssr";
                singleproxy["cipher"] = x.EncryptMethod == "none" ? "dummy" : x.EncryptMethod;
                setYamlString(singleproxy["password"], x.Password);
                singleproxy["protocol"] = x.Protocol;
                singleproxy["obfs"] = x.OBFS;
                if (clashR) {
                    singleproxy["protocolparam"] = x.ProtocolParam;
                    singleproxy["obfsparam"] = x.OBFSParam;
                } else {
                    singleproxy["protocol-param"] = x.ProtocolParam;
                    singleproxy["obfs-param"] = x.OBFSParam;
                }
                break;
            case ProxyType::SOCKS5:
                singleproxy["type"] = "socks5";
                if (!x.Username.empty())
                    setYamlString(singleproxy["username"], x.Username);
                if (!x.Password.empty()) {
                    setYamlString(singleproxy["password"], x.Password);
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                singleproxy["type"] = "http";
                if (!x.Username.empty())
                    setYamlString(singleproxy["username"], x.Username);
                if (!x.Password.empty()) {
                    setYamlString(singleproxy["password"], x.Password);
                }
                singleproxy["tls"] = x.TLSSecure;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                break;
            case ProxyType::Trojan:
                // mihomo 的 trojan 强制 TLS，明文(security=none)节点无法表达，
                // 输出会成为必超时的假可用节点，跳过并留日志
                if (!x.TLSSecure) {
                    writeLog(0, "Skipping Trojan node '" + x.Remark + "': mihomo requires TLS for trojan",
                             LOG_LEVEL_WARNING);
                    continue;
                }
                singleproxy["type"] = "trojan";
                setYamlString(singleproxy["password"], x.Password);
                if (!x.ServerName.empty())
                    singleproxy["sni"] = x.ServerName;
                else if (!x.Host.empty()) {
                    singleproxy["sni"] = x.Host;
                }
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                } else if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                // Reality（与 VLESS 同承载字段）；Reality 节点指纹缺省需回退 random，
                // 否则 mihomo uTLS 无法握手
                if (!x.PublicKey.empty()) {
                    singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                    if (!x.ShortId.empty())
                        setYamlString(singleproxy["reality-opts"]["short-id"], x.ShortId, true);
                    if (!x.SupportX25519MLKEM768.is_undef())
                        singleproxy["reality-opts"]["support-x25519mlkem768"] =
                            x.SupportX25519MLKEM768.get();
                }
                // 新增 mihomo 参数输出
                if (!x.ClientFingerprint.empty())
                    singleproxy["client-fingerprint"] = x.ClientFingerprint;
                else if (!x.PublicKey.empty())
                    singleproxy["client-fingerprint"] = "random";
                if (!x.IpVersion.empty())
                    singleproxy["ip-version"] = x.IpVersion;
                if (!x.TrojanSsMethod.empty()) {
                    singleproxy["ss-opts"]["method"] = x.TrojanSsMethod;
                    if (!x.TrojanSsPassword.empty())
                        singleproxy["ss-opts"]["password"] = x.TrojanSsPassword;
                }
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        break;
                    case "grpc"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        if (!x.Path.empty())
                            singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                        break;
                    case "ws"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["ws-opts"]["path"] = x.Path;
                        if (!x.Host.empty())
                            singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                        break;
                }
                break;
            case ProxyType::Snell:
                singleproxy["type"] = "snell";
                setYamlString(singleproxy["psk"], x.Password);
                if (x.SnellVersion != 0)
                    singleproxy["version"] = x.SnellVersion;
                if (!x.OBFS.empty()) {
                    singleproxy["obfs-opts"]["mode"] = x.OBFS;
                    if (!x.Host.empty())
                        singleproxy["obfs-opts"]["host"] = x.Host;
                }
                break;
            case ProxyType::WireGuard:
                singleproxy["type"] = "wireguard";
                singleproxy["public-key"] = x.PublicKey;
                singleproxy["private-key"] = x.PrivateKey;
                singleproxy["ip"] = x.SelfIP;
                if (!x.SelfIPv6.empty())
                    singleproxy["ipv6"] = x.SelfIPv6;
                if (!x.PreSharedKey.empty())
                    singleproxy["preshared-key"] = x.PreSharedKey;
                if (!x.DnsServers.empty())
                    singleproxy["dns"] = x.DnsServers;
                if (x.Mtu > 0)
                    singleproxy["mtu"] = x.Mtu;
                break;
            case ProxyType::Hysteria:
                singleproxy["type"] = "hysteria";
                singleproxy["auth_str"] = x.Auth;
                setYamlString(singleproxy["auth-str"], x.Auth);
                singleproxy["up"] = x.UpMbps;
                singleproxy["down"] = x.DownMbps;
                if (!x.Ports.empty()) {
                    singleproxy["ports"] = x.Ports;
                }
                // fast-open: 节点设置优先于全局设置
                if (!x.FastOpen.is_undef()) {
                    singleproxy["fast-open"] = x.FastOpen.get();
                } else if (!tfo.is_undef()) {
                    singleproxy["fast-open"] = tfo.get();
                }
                if (!x.FakeType.empty())
                    singleproxy["protocol"] = x.FakeType;
                if (!x.ServerName.empty())
                    singleproxy["sni"] = x.ServerName;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (x.Insecure == "1")
                    singleproxy["skip-cert-verify"] = true;
                if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!x.OBFSParam.empty())
                    singleproxy["obfs"] = x.OBFSParam;
                // 新增 mihomo 参数输出
                if (!x.CertFingerprint.empty())
                    singleproxy["fingerprint"] = x.CertFingerprint;
                if (!x.Ca.empty())
                    singleproxy["ca"] = x.Ca;
                if (!x.CaStr.empty())
                    singleproxy["ca-str"] = x.CaStr;
                if (x.RecvWindowConn > 0)
                    singleproxy["recv-window-conn"] = x.RecvWindowConn;
                if (x.RecvWindow > 0)
                    singleproxy["recv-window"] = x.RecvWindow;
                if (!x.DisableMtuDiscovery.is_undef())
                    singleproxy["disable-mtu-discovery"] = x.DisableMtuDiscovery.get();
                if (x.HopInterval > 0)
                    singleproxy["hop-interval"] = x.HopInterval;
                break;
            case ProxyType::Hysteria2:
                singleproxy["type"] = "hysteria2";
                setYamlString(singleproxy["password"], x.Password);
                if (!x.CaStr.empty()) {
                    singleproxy["ca-str"] = x.CaStr;
                } else if (!x.PublicKey.empty()) {
                    singleproxy["ca-str"] = x.PublicKey;
                }
                if (!x.ServerName.empty()) {
                    singleproxy["sni"] = x.ServerName;
                }
                if (!x.UpMbps.empty())
                    singleproxy["up"] = x.UpMbps;
                if (!x.DownMbps.empty())
                    singleproxy["down"] = x.DownMbps;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!x.OBFSParam.empty())
                    singleproxy["obfs"] = x.OBFSParam;
                if (!x.OBFSPassword.empty())
                    setYamlString(singleproxy["obfs-password"], x.OBFSPassword);
                if (!x.Ports.empty())
                    singleproxy["ports"] = x.Ports;
                // mport 非 mihomo 字段：端口跳跃由上方 ports 输出，此处仅在 ports 缺省时补为合法 ports
                if (x.Ports.empty() && !x.Mport.empty())
                    singleproxy["ports"] = x.Mport;
                if (!x.CertFingerprint.empty())
                    singleproxy["fingerprint"] = x.CertFingerprint;
                if (!x.Ca.empty())
                    singleproxy["ca"] = x.Ca;
                if (x.CWND > 0)
                    singleproxy["cwnd"] = x.CWND;
                if (x.HopInterval > 0)
                    singleproxy["hop-interval"] = x.HopInterval;
                if (x.InitialStreamReceiveWindow > 0)
                    singleproxy["initial-stream-receive-window"] = x.InitialStreamReceiveWindow;
                if (x.MaxStreamReceiveWindow > 0)
                    singleproxy["max-stream-receive-window"] = x.MaxStreamReceiveWindow;
                if (x.InitialConnectionReceiveWindow > 0)
                    singleproxy["initial-connection-receive-window"] = x.InitialConnectionReceiveWindow;
                if (x.MaxConnectionReceiveWindow > 0)
                    singleproxy["max-connection-receive-window"] = x.MaxConnectionReceiveWindow;
                break;
            case ProxyType::TUIC:
                singleproxy["type"] = "tuic";
                if (!x.Password.empty()) {
                    setYamlString(singleproxy["password"], x.Password);
                }
                if (!x.UserId.empty()) {
                    setYamlString(singleproxy["uuid"], x.UserId);
                }
                if (!x.token.empty()) {
                    setYamlString(singleproxy["token"], x.token);
                }
                if (!x.ServerName.empty()) {
                    singleproxy["sni"] = x.ServerName;
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!x.DisableSni.is_undef())
                    singleproxy["disable-sni"] = x.DisableSni.get();
                if (!x.ReduceRtt.is_undef())
                    singleproxy["reduce-rtt"] = x.ReduceRtt.get();
                if (x.RequestTimeout > 0)
                    singleproxy["request-timeout"] = x.RequestTimeout;
                if (!x.UdpRelayMode.empty()) {
                    if (x.UdpRelayMode == "native" || x.UdpRelayMode == "quic") {
                        singleproxy["udp-relay-mode"] = x.UdpRelayMode;
                    }
                }
                if (!x.CongestionControl.empty()) {
                    singleproxy["congestion-controller"] = x.CongestionControl;
                }
                // 新增 mihomo 参数输出
                if (x.MaxDatagramFrameSize > 0)
                    singleproxy["max-datagram-frame-size"] = x.MaxDatagramFrameSize;
                if (!x.HeartbeatInterval.empty())
                    singleproxy["heartbeat-interval"] = x.HeartbeatInterval;
                if (x.MaxOpenStreams > 0)
                    singleproxy["max-open-streams"] = x.MaxOpenStreams;
                break;
            case ProxyType::AnyTLS:
                singleproxy["type"] = "anytls";
                if (!x.Password.empty()) {
                    setYamlString(singleproxy["password"], x.Password);
                }
                if (!x.ClientFingerprint.empty()) {
                    singleproxy["client-fingerprint"] = x.ClientFingerprint;
                }
                if (!udp.is_undef()) {
                    singleproxy["udp"] = udp.get();
                }
                if (!x.SNI.empty()) {
                    singleproxy["sni"] = x.SNI;
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                }
                // idle-session 三字段：仅在非 mihomo 默认值时输出，避免噪音
                if (x.IdleSessionCheckInterval != 30)
                    singleproxy["idle-session-check-interval"] = x.IdleSessionCheckInterval;
                if (x.IdleSessionTimeout != 30)
                    singleproxy["idle-session-timeout"] = x.IdleSessionTimeout;
                if (x.MinIdleSession > 0)
                    singleproxy["min-idle-session"] = x.MinIdleSession;
                break;
            case ProxyType::Mieru:
                singleproxy["type"] = "mieru";
                if (!x.Password.empty()) {
                    setYamlString(singleproxy["password"], x.Password);
                }
                if (!x.Username.empty()) {
                    setYamlString(singleproxy["username"], x.Username);
                }
                if (!x.Multiplexing.empty()) {
                    singleproxy["multiplexing"] = x.Multiplexing;
                }
                if (!x.TransferProtocol.empty()) {
                    singleproxy["transport"] = x.TransferProtocol;
                }
                if (!x.Ports.empty()) {
                    singleproxy["port-range"] = x.Ports;
                    singleproxy.remove("port");
                }
                break;
            case ProxyType::VLESS:
                singleproxy["type"] = "vless";
                setYamlString(singleproxy["uuid"], x.UserId);
                singleproxy["tls"] = x.TLSSecure;
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                }
                if (!tfo.is_undef())
                    singleproxy["tfo"] = tfo.get();
                // XUDP 支持
                if (!x.XUDP.is_undef()) {
                    singleproxy["xudp"] = x.XUDP.get();
                } else if (xudp && udp) {
                    singleproxy["xudp"] = true;
                }
                if (!x.PacketEncoding.empty()) {
                    singleproxy["packet-encoding"] = x.PacketEncoding;
                }
                if (!x.Flow.empty())
                    singleproxy["flow"] = x.Flow;
                if (!x.Encryption.empty() && x.Encryption != "none")
                    singleproxy["encryption"] = x.Encryption;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.PublicKey.empty()) {
                    singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                }
                if (!x.ServerName.empty())
                    singleproxy["servername"] = x.ServerName;
                if (!x.ShortId.empty()) {
                    setYamlString(singleproxy["reality-opts"]["short-id"], x.ShortId, true);
                }
                // 仅在确有 reality 配置时写出，避免产生只含该项的孤立 reality-opts
                if (!x.PublicKey.empty() && !x.SupportX25519MLKEM768.is_undef())
                    singleproxy["reality-opts"]["support-x25519mlkem768"] =
                        x.SupportX25519MLKEM768.get();
                // 客户端指纹（uTLS）：显式设置时始终输出（含非 Reality 的普通 TLS 节点）；
                // Reality 节点（有 public-key）即使未显式设置也需默认 random，否则 mihomo uTLS 无法握手。
                // 只认 ClientFingerprint：证书指纹另有 CertFingerprint 承载，
                // 二者混用会让 mihomo 的 uTLS 拿到无效的指纹名
                if (!x.ClientFingerprint.empty()) {
                    singleproxy["client-fingerprint"] = x.ClientFingerprint;
                } else if (!x.PublicKey.empty()) {
                    singleproxy["client-fingerprint"] = "random";
                }
                // 新增 mihomo 参数输出
                if (!x.IpVersion.empty()) {
                    singleproxy["ip-version"] = x.IpVersion;
                }
                if (!x.PacketAddr.is_undef()) {
                    singleproxy["packet-addr"] = x.PacketAddr.get();
                }
                // global-padding / authenticated-length 不在此输出：它们是 VMess AEAD
                // 的能力，mihomo 的 VlessOption 没有这两个字段，写了也只是被静默忽略。
                // mihomo 的 ECH 键是 ech-opts{enable,config}；顶层 ech/ech-config 是历史误写不再输出。
                // ech-opts 已随 MihomoTlsOpts 透传时以其为准，避免重复写
                if (x.MihomoTlsOpts.find("\"ech-opts\"") == std::string::npos) {
                    if (!x.EchEnable.is_undef())
                        singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                    if (!x.EchConfig.empty())
                        singleproxy["ech-opts"]["config"] = x.EchConfig;
                }
                if (!x.MihomoTlsOpts.empty()) {
                    rapidjson::Document td;
                    td.Parse(x.MihomoTlsOpts.data());
                    if (!td.HasParseError() && td.IsObject())
                        addMihomoTlsOptsToYaml(td, singleproxy);
                }
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        break;
                    case "ws"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        if (ext.clash_new_field_name) {
                            singleproxy["ws-opts"]["path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                            if (!x.V2rayHttpUpgrade.is_undef()) {
                                singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                            }
                            if (!x.V2rayHttpUpgradeFastOpen.is_undef()) {
                                singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"] = x.V2rayHttpUpgradeFastOpen.get();
                            }
                            if (x.WsMaxEarlyData > 0) {
                                singleproxy["ws-opts"]["max-early-data"] = x.WsMaxEarlyData;
                            }
                            if (!x.WsEarlyDataHeaderName.empty()) {
                                singleproxy["ws-opts"]["early-data-header-name"] = x.WsEarlyDataHeaderName;
                            }
                        } else {
                            singleproxy["ws-path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-headers"]["Edge"] = x.Edge;
                        }
                        break;
                    case "http"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["http-opts"]["method"] = "GET";
                        singleproxy["http-opts"]["path"].push_back(x.Path);
                        if (!x.Host.empty())
                            singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                        if (!x.Edge.empty())
                            singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                        break;
                    case "h2"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["h2-opts"]["path"] = x.Path;
                        if (!x.Host.empty())
                            singleproxy["h2-opts"]["host"].push_back(x.Host);
                        break;
                    case "grpc"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["grpc-opts"]["grpc-mode"] = x.GRPCMode;
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.GRPCServiceName;
                        if (x.GRPCMaxConnections > 0)
                            singleproxy["grpc-opts"]["max-connections"] = x.GRPCMaxConnections;
                        if (x.GRPCMinStreams > 0)
                            singleproxy["grpc-opts"]["min-streams"] = x.GRPCMinStreams;
                        if (x.GRPCMaxStreams > 0)
                            singleproxy["grpc-opts"]["max-streams"] = x.GRPCMaxStreams;
                        break;
                    case "xhttp"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["xhttp-opts"]["path"] = x.Path.empty() ? "/" : x.Path;
                        if (!x.Host.empty())
                            singleproxy["xhttp-opts"]["host"] = x.Host;
                        if (!x.XhttpMode.empty())
                            singleproxy["xhttp-opts"]["mode"] = x.XhttpMode;
                        if (!x.XhttpHeaders.empty()) {
                            rapidjson::Document hd;
                            hd.Parse(x.XhttpHeaders.data());
                            if (!hd.HasParseError() && hd.IsObject()) {
                                for (const auto &kv : hd.GetObject())
                                    singleproxy["xhttp-opts"]["headers"][kv.name.GetString()] =
                                        std::string(kv.value.GetString());
                            }
                        }
                        if (!x.XhttpNoGrpcHeader.is_undef())
                            singleproxy["xhttp-opts"]["no-grpc-header"] = x.XhttpNoGrpcHeader.get();
                        if (!x.XhttpPaddingBytes.empty())
                            singleproxy["xhttp-opts"]["x-padding-bytes"] = x.XhttpPaddingBytes;
                        if (!x.XhttpScMaxEachPostBytes.empty())
                            singleproxy["xhttp-opts"]["sc-max-each-post-bytes"] = x.XhttpScMaxEachPostBytes;
                        if (!x.XhttpReuseSettings.empty()) {
                            rapidjson::Document rd;
                            rd.Parse(x.XhttpReuseSettings.data());
                            if (!rd.HasParseError() && rd.IsObject()) {
                                YAML::Node rsYaml;
                                const char *reuseKeys[] = {"max-connections", "max-concurrency",
                                                           "c-max-reuse-times", "h-max-request-times",
                                                           "h-max-reusable-secs", "h-keep-alive-period"};
                                for (const char *k : reuseKeys) {
                                    if (rd.HasMember(k) && rd[k].IsString() && rd[k].GetStringLength() > 0)
                                        rsYaml[k] = std::string(rd[k].GetString());
                                }
                                if (rsYaml.IsDefined())
                                    singleproxy["xhttp-opts"]["reuse-settings"] = rsYaml;
                            }
                        }
                        if (!x.XhttpClashOpts.empty()) {
                            // 文档其余标量字段原样写回，布尔保持布尔、其余保持字符串
                            rapidjson::Document od;
                            od.Parse(x.XhttpClashOpts.data());
                            if (!od.HasParseError() && od.IsObject()) {
                                for (const auto &kv : od.GetObject()) {
                                    if (kv.value.IsBool())
                                        singleproxy["xhttp-opts"][kv.name.GetString()] = kv.value.GetBool();
                                    else if (kv.value.IsString())
                                        singleproxy["xhttp-opts"][kv.name.GetString()] =
                                            std::string(kv.value.GetString());
                                }
                            }
                        }
                        addXhttpDownloadToYaml(singleproxy["xhttp-opts"], x.XhttpDownload);
                        break;
                    default:
                        // 回退为 tcp 而非丢弃：mihomo 运行时对未知 network 也是
                        // default 分支当 tcp 处理，丢节点会让用户静默少节点
                        writeLog(0, "VLESS node '" + x.Remark + "': unsupported network '" +
                                    x.TransferProtocol + "', falling back to tcp", LOG_LEVEL_WARNING);
                        singleproxy["network"] = "tcp";
                        break;
                }
                break;
            default:
                continue;
        }

        // TLS 证书类字段，mihomo 的 VlessOption/VmessOption/TrojanOption 共有。
        // CertFingerprint 是服务器证书 pinning，与 client-fingerprint 分属两个键
        switch (x.Type) {
            case ProxyType::VLESS:
            case ProxyType::VMess:
            case ProxyType::Trojan:
            case ProxyType::AnyTLS:
                if (!x.CertFingerprint.empty())
                    setYamlString(singleproxy["fingerprint"], x.CertFingerprint);
                if (!x.Certificate.empty())
                    singleproxy["certificate"] = x.Certificate;
                if (!x.PrivateKeyPem.empty())
                    singleproxy["private-key"] = x.PrivateKeyPem;
                break;
            default:
                break;
        }

        // Snell UDP is available in mihomo-compatible Snell v3+ nodes.
        if (udp && (x.Type != ProxyType::Snell || x.SnellVersion >= 3) && x.Type != ProxyType::TUIC)
            singleproxy["udp"] = true;
        if (!clashR && !x.UnderlyingProxy.empty())
            singleproxy["dialer-proxy"] = x.UnderlyingProxy;
        // BasicOption 拨号选项，所有协议共有；未配置的一律不写出
        if (!x.MPTCP.is_undef())
            singleproxy["mptcp"] = x.MPTCP.get();
        if (!x.InterfaceName.empty())
            singleproxy["interface-name"] = x.InterfaceName;
        if (x.RoutingMark != 0)
            singleproxy["routing-mark"] = x.RoutingMark;
        if (proxy_block)
            singleproxy.SetStyle(YAML::EmitterStyle::Block);
        else
            singleproxy.SetStyle(YAML::EmitterStyle::Flow);
        proxies.push_back(singleproxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (proxy_compact)
        proxies.SetStyle(YAML::EmitterStyle::Flow);

    if (ext.nodelist) {
        YAML::Node provider;
        provider["proxies"] = proxies;
        yamlnode.reset(provider);
        return;
    }

    if (ext.clash_new_field_name)
        yamlnode["proxies"] = proxies;
    else
        yamlnode["Proxy"] = proxies;


    for (const ProxyGroupConfig &x: extra_proxy_group) {
        YAML::Node singlegroup;
        string_array filtered_nodelist;

        singlegroup["name"] = x.Name;
        if (x.Type == ProxyGroupType::Smart)
            singlegroup["type"] = "url-test";
        else
            singlegroup["type"] = x.TypeStr();

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::Relay:
                break;
            case ProxyGroupType::LoadBalance:
                singlegroup["strategy"] = x.StrategyStr();
                [[fallthrough]];
            case ProxyGroupType::Smart:
                [[fallthrough]];
            case ProxyGroupType::URLTest:
                if (!x.Lazy.is_undef())
                    singlegroup["lazy"] = x.Lazy.get();
                [[fallthrough]];
            case ProxyGroupType::Fallback:
                singlegroup["url"] = x.Url;
                if (x.Interval > 0)
                    singlegroup["interval"] = x.Interval;
                if (x.Tolerance > 0)
                    singlegroup["tolerance"] = x.Tolerance;
                break;
            default:
                continue;
        }
        if (!x.DisableUdp.is_undef())
            singlegroup["disable-udp"] = x.DisableUdp.get();
        for (const auto &[key, value] : x.Extras)
            singlegroup[key] = yamlScalarFromString(value);

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (!x.UsingProvider.empty())
            singlegroup["use"] = x.UsingProvider;
        else {
            if (filtered_nodelist.empty())
                filtered_nodelist.emplace_back("DIRECT");
        }
        if (!filtered_nodelist.empty())
            singlegroup["proxies"] = filtered_nodelist;
        if (group_block)
            singlegroup.SetStyle(YAML::EmitterStyle::Block);
        else
            singlegroup.SetStyle(YAML::EmitterStyle::Flow);

        bool replace_flag = false;
        for (auto &&original_group: original_groups) {
            if (original_group["name"].as<std::string>() == x.Name) {
                original_group.reset(singlegroup);
                replace_flag = true;
                break;
            }
        }
        if (!replace_flag)
            original_groups.push_back(singlegroup);
    }
    if (group_compact)
        original_groups.SetStyle(YAML::EmitterStyle::Flow);

    if (ext.clash_new_field_name)
        yamlnode["proxy-groups"] = original_groups;
    else
        yamlnode["Proxy Group"] = original_groups;
}


std::string beautifyStringTags(std::string input) {
    std::string target = "!<str>";
    size_t startPos = input.find(target);

    while (startPos != std::string::npos) {
        // 查找被锚定值的结束边界：flow 风格到 ',' 或 '}'，block 风格到换行。
        // 只找 '}' 会在 xhttp download-settings（被锚定值后仍有 path/host 等键）
        // 及 block 风格下越界，吞掉后续键值对导致输出损坏。
        size_t valStart = startPos + target.length();
        size_t endPos = std::string::npos;
        for (char term : {',', '}', '\n'}) {
            size_t p = input.find(term, valStart);
            if (p < endPos)
                endPos = p;
        }

        if (endPos != std::string::npos) {
            // 提取原始值
            std::string originalId = input.substr(startPos + target.length(), endPos - startPos - target.length());

            originalId = trim(originalId);

            // 含引号或反斜杠说明文本定界不可靠（值里可能本就有分隔符），
            // 保留 !<str> 标签而不强行加引号——yaml.v3 的 resolve 对不可解析
            // 标签原样返回字符串，功能正确，只是不够美观。
            if (originalId.find_first_of("\"\\") == std::string::npos)
                input.replace(startPos, endPos - startPos, "\"" + originalId + "\"");
        }

        // 继续查找下一个实例
        startPos = input.find(target, startPos + 1);
    }
    return input;
}

std::string proxyToClash(std::vector<Proxy> &nodes, const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         bool clashR, extra_settings &ext) {
    YAML::Node yamlnode;

    try {
        yamlnode = YAML::Load(base_conf);
    } catch (std::exception &e) {
        writeLog(0, std::string("Clash base loader failed with error: ") + e.what(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToClash(nodes, yamlnode, extra_proxy_group, clashR, ext);

    if (ext.nodelist)
        return beautifyStringTags(YAML::Dump(yamlnode));

    /*
    if(ext.enable_rule_generator)
        rulesetToClash(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);

    return YAML::Dump(yamlnode);
    */
    if (!ext.enable_rule_generator)
        return beautifyStringTags(YAML::Dump(yamlnode));

    if (!ext.managed_config_prefix.empty() || ext.clash_script) {
        if (yamlnode["mode"].IsDefined()) {
            if (ext.clash_new_field_name)
                yamlnode["mode"] = ext.clash_script ? "script" : "rule";
            else
                yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
        }

        renderClashScript(yamlnode, ruleset_content_array, ext.managed_config_prefix, ext.clash_script,
                          ext.overwrite_original_rules, ext.clash_classical_ruleset);
        return beautifyStringTags(YAML::Dump(yamlnode));
    }

    std::string output_content = rulesetToClashStr(yamlnode, ruleset_content_array, ext.overwrite_original_rules,
                                                   ext.clash_new_field_name);
    std::string yamlnode_str = YAML::Dump(yamlnode);
    output_content.insert(0, yamlnode_str);
    //rulesetToClash(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);
    //std::string output_content = YAML::Dump(yamlnode);
    return beautifyStringTags(std::move(output_content));
}

void replaceAll(std::string &input, const std::string &search, const std::string &replace) {
    size_t pos = 0;
    while ((pos = input.find(search, pos)) != std::string::npos) {
        input.replace(pos, search.length(), replace);
        pos += replace.length();
    }
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
std::string generatePeer(Proxy &node, bool client_id_as_reserved = false) {
    std::string result;
    result += "public-key = " + node.PublicKey;
    result += ", endpoint = " + node.Hostname + ":" + std::to_string(node.Port);
    if (!node.AllowedIPs.empty())
        result += ", allowed-ips = \"" + node.AllowedIPs + "\"";
    if (!node.ClientId.empty()) {
        if (client_id_as_reserved)
            result += ", reserved = [" + node.ClientId + "]";
        else
            result += ", client-id = " + node.ClientId;
    }
    return result;
}

std::string proxyToSurge(std::vector<Proxy> &nodes, const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         int surge_ver, extra_settings &ext) {
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;
    unsigned short local_port = 1080;
    string_array remarks_list;

    ini.store_any_line = true;
    // filter out sections that requires direct-save
    ini.add_direct_save_section("General");
    ini.add_direct_save_section("Replica");
    ini.add_direct_save_section("Rule");
    ini.add_direct_save_section("MITM");
    ini.add_direct_save_section("Script");
    ini.add_direct_save_section("Host");
    ini.add_direct_save_section("URL Rewrite");
    ini.add_direct_save_section("Header Rewrite");
    if (ini.parse(base_conf) != 0 && !ext.nodelist) {
        writeLog(0, "Surge base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();
    ini.set("{NONAME}", "DIRECT = direct");

    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &sni = x.ServerName, &username = x.Username, &password = x.Password, &method
                = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &edge = x.Edge, &
                path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.
                OBFSParam, &plugin = x.Plugin, &pluginopts = x.PluginOption, &underlying_proxy = x.UnderlyingProxy;
        std::string port = std::to_string(x.Port);;
        bool &tlssecure = x.TLSSecure;

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        std::string proxy, section, real_section;
        string_array args, headers;
        std::string search = " Mbps";

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (surge_ver >= 3 || surge_ver == -3) {
                    proxy = "ss, " + hostname + ", " + port + ", encrypt-method=" + method + ", password=" +
                            password;
                } else {
                    proxy = "custom, " + hostname + ", " + port + ", " + method + ", " + password +
                            ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module";
                }
                if (!plugin.empty()) {
                    switch (hash_(plugin)) {
                        case "simple-obfs"_hash:
                        case "obfs-local"_hash:
                            if (!pluginopts.empty())
                                proxy += "," + replaceAllDistinct(pluginopts, ";", ",");
                            break;
                        default:
                            continue;
                    }
                }
                break;
            case ProxyType::VMess:
                if (surge_ver < 4 && surge_ver != -3)
                    continue;
                proxy = "vmess, " + hostname + ", " + port + ", username=" + id + ", tls=" +
                        (tlssecure ? "true" : "false") + ", vmess-aead=" + (x.AlterId == 0 ? "true" : "false");
                if (tlssecure && !tls13.is_undef())
                    proxy += ", tls13=" + std::string(tls13 ? "true" : "false");
                switch (hash_(transproto)) {
                    case "tcp"_hash:
                        break;
                    case "ws"_hash:
                        if (host.empty())
                            proxy += ", ws=true, ws-path=" + path + ", sni=" + hostname;
                        else
                            proxy += ", ws=true, ws-path=" + path + ", sni=" + host;
                        if (!host.empty())
                            headers.push_back("Host:" + host);
                        if (!edge.empty())
                            headers.push_back("Edge:" + edge);
                        if (!headers.empty())
                            proxy += ", ws-headers=" + join(headers, "|");
                        break;
                    default:
                        continue;
                }
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::ShadowsocksR:
                if (ext.surge_ssr_path.empty() || surge_ver < 2)
                    continue;
                proxy = "external, exec=\"" + ext.surge_ssr_path + "\", args=\"";
                args = {
                    "-l", std::to_string(local_port), "-s", hostname, "-p", port, "-m", method, "-k", password,
                    "-o", obfs, "-O", protocol
                };
                if (!obfsparam.empty()) {
                    args.emplace_back("-g");
                    args.emplace_back(std::move(obfsparam));
                }
                if (!protoparam.empty()) {
                    args.emplace_back("-G");
                    args.emplace_back(std::move(protoparam));
                }
                proxy += join(args, "\", args=\"");
                proxy += "\", local-port=" + std::to_string(local_port);
                if (isIPv4(hostname) || isIPv6(hostname))
                    proxy += ", addresses=" + hostname;
                else if (global.surgeResolveHostname)
                    proxy += ", addresses=" + hostnameToIPAddr(hostname);
                local_port++;
                break;
            case ProxyType::SOCKS5:
                proxy = "socks5, " + hostname + ", " + port;
                if (!username.empty())
                    proxy += ", username=" + username;
                if (!password.empty())
                    proxy += ", password=" + password;
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::HTTPS:
                if (surge_ver == -3) {
                    proxy = "https, " + hostname + ", " + port + ", " + username + ", " + password;
                    if (!scv.is_undef())
                        proxy += ", skip-cert-verify=" + scv.get_str();
                    break;
                }
                [[fallthrough]];
            case ProxyType::HTTP:
                proxy = "http, " + hostname + ", " + port;
                if (!username.empty())
                    proxy += ", username=" + username;
                if (!password.empty())
                    proxy += ", password=" + password;
                proxy += std::string(", tls=") + (x.TLSSecure ? "true" : "false");
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::Trojan:
                if (surge_ver < 4 && surge_ver != -3)
                    continue;
                proxy = "trojan, " + hostname + ", " + port + ", password=" + password;
                if (x.SnellVersion != 0)
                    proxy += ", version=" + std::to_string(x.SnellVersion);
                if (!sni.empty()) {
                    proxy += ", sni=" + sni;
                } else if (!host.empty()) {
                    proxy += ", sni=" + host;
                }
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::Snell:
                proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
                if (!obfs.empty()) {
                    proxy += ", obfs=" + obfs;
                    if (!host.empty())
                        proxy += ", obfs-host=" + host;
                }
                if (x.SnellVersion != 0)
                    proxy += ", version=" + std::to_string(x.SnellVersion);
                break;
            case ProxyType::Hysteria2:
                if (surge_ver < 4)
                    continue;
                proxy = "hysteria2, " + hostname + ", " + port + ", password=" + password;
                if (!x.DownMbps.empty()) {
                    if (!isNumeric(x.DownMbps)) {
                        size_t pos = x.DownMbps.find(search);
                        if (pos != std::string::npos) {
                            x.DownMbps.replace(pos, search.length(), "");
                        }
                    }
                    proxy += ", download-bandwidth=" +x.DownMbps;
                }

                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                if (!x.CertFingerprint.empty())
                    proxy += ",server-cert-fingerprint-sha256=" + x.CertFingerprint;
                if (!x.ServerName.empty())
                    proxy += ",sni=" + x.ServerName;
                if (!x.Ports.empty())
                    proxy += ",port-hopping=" + x.Ports;
                break;
            case ProxyType::AnyTLS:
                if (surge_ver < 4)
                    continue;
                proxy = "anytls, " + hostname + ", " + port + ", password=" + password;
                if (!x.SNI.empty())
                    proxy += ", sni=" + x.SNI;
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                if (!x.CertFingerprint.empty())
                    proxy += ", server-cert-fingerprint-sha256=" + x.CertFingerprint;
                if (!tls13.is_undef())
                    proxy += ", tls13=" + std::string(tls13 ? "true" : "false");
                break;
            case ProxyType::WireGuard:
                if (surge_ver < 4 && surge_ver != -3)
                    continue;
                section = randomStr(5);
                real_section = "WireGuard " + section;
                proxy = "wireguard, section-name=" + section;
                if (!x.TestUrl.empty())
                    proxy += ", test-url=" + x.TestUrl;
                ini.set(real_section, "private-key", x.PrivateKey);
                ini.set(real_section, "self-ip", x.SelfIP);
                if (!x.SelfIPv6.empty())
                    ini.set(real_section, "self-ip-v6", x.SelfIPv6);
                if (!x.PreSharedKey.empty())
                    ini.set(real_section, "preshared-key", x.PreSharedKey);
                if (!x.DnsServers.empty())
                    ini.set(real_section, "dns-server", join(x.DnsServers, ","));
                if (x.Mtu > 0)
                    ini.set(real_section, "mtu", std::to_string(x.Mtu));
                if (x.KeepAlive > 0)
                    ini.set(real_section, "keepalive", std::to_string(x.KeepAlive));
                ini.set(real_section, "peer", "(" + generatePeer(x) + ")");
                break;
            default:
                continue;
        }

        if (!tfo.is_undef())
            proxy += ", tfo=" + tfo.get_str();
        if (!udp.is_undef())
            proxy += ", udp-relay=" + udp.get_str();
        if (underlying_proxy != "")
            proxy += ", underlying-proxy=" + underlying_proxy;
        if (ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
        }
        remarks_list.emplace_back(x.Remark);
    }

    if (ext.nodelist)
        return output_nodelist;

    ini.set_current_section("Proxy Group");
    ini.erase_section();
    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string group;

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::Smart:
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
                break;
            case ProxyGroupType::LoadBalance:
                if (surge_ver < 1 && surge_ver != -3)
                    continue;
                break;
            case ProxyGroupType::SSID:
                group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
                group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
                ini.set("{NONAME}", x.Name + " = " + group); //insert order
                continue;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        if (filtered_nodelist.size() == 1) {
            group = toLower(filtered_nodelist[0]);
            switch (hash_(group)) {
                case "direct"_hash:
                case "reject"_hash:
                case "reject-tinygif"_hash:
                    ini.set("Proxy", "{NONAME}", x.Name + " = " + group);
                    continue;
            }
        }

        group = x.TypeStr() + ",";
        group += join(filtered_nodelist, ",");
        if (x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Fallback ||
            x.Type == ProxyGroupType::LoadBalance) {
            group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
            if (x.Tolerance > 0)
                group += ",tolerance=" + std::to_string(x.Tolerance);
            if (x.Timeout > 0)
                group += ",timeout=" + std::to_string(x.Timeout);
            if (!x.Persistent.is_undef())
                group += ",persistent=" + x.Persistent.get_str();
            if (!x.EvaluateBeforeUse.is_undef())
                group += ",evaluate-before-use=" + x.EvaluateBeforeUse.get_str();
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, surge_ver, ext.overwrite_original_rules,
                       ext.managed_config_prefix);

    return ini.to_string();
}

std::string proxyToSingle(std::vector<Proxy> &nodes, int types, extra_settings &ext) {
    /// types: SS=1 SSR=2 VMess=4 Trojan=8,hysteria2=16,vless=32
    std::string proxyStr, allLinks;
    bool ss = GETBIT(types, 1), ssr = GETBIT(types, 2), vmess = GETBIT(types, 3), trojan = GETBIT(types, 4), hysteria2 =
            GETBIT(types, 5), vless = GETBIT(types, 6);

    for (Proxy &x: nodes) {
        std::string remark = x.Remark;
        std::string &hostname = x.Hostname, &sni = x.ServerName, &password = x.Password, &method = x.EncryptMethod, &
                        plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &protoparam = x.
                        ProtocolParam, &flow = x.Flow, &pbk = x.PublicKey, &sid = x.ShortId, &fp = x.ClientFingerprint,
                &packet_encoding = x.PacketEncoding, &fake_type = x.FakeType, &mode = x.GRPCMode,
                &obfs = x.OBFS, &obfsparam = x.OBFSParam, &obfsPassword = x.OBFSPassword, &id = x.UserId, &transproto =
                        x.TransferProtocol, &host = x.
                        Host, &tls = x.TLSStr, &path = x.Path, &faketype = x.FakeType, &ports = x.Ports;
        bool &tlssecure = x.TLSSecure;
        std::vector<string> alpns = x.AlpnList;
        std::string port = std::to_string(x.Port);
        std::string aid = std::to_string(x.AlterId);
        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (ss) {
                    proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                    if (!plugin.empty() && !pluginopts.empty()) {
                        proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                    }
                    proxyStr += "#" + urlEncode(remark);
                } else if (ssr) {
                    if (std::find(ssr_ciphers.begin(), ssr_ciphers.end(), method) != ssr_ciphers.end() &&
                        plugin.empty())
                        proxyStr = "ssr://" + urlSafeBase64Encode(
                                       hostname + ":" + port + ":origin:" + method + ":plain:" +
                                       urlSafeBase64Encode(password)
                                       + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(
                                           remark));
                } else
                    continue;
                break;
            case ProxyType::ShadowsocksR:
                if (ssr) {
                    proxyStr = "ssr://" + urlSafeBase64Encode(
                                   hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" +
                                   urlSafeBase64Encode(password)
                                   + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(
                                       remark)
                                   + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" +
                                   urlSafeBase64Encode(protoparam));
                } else if (ss) {
                    if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
                        protocol == "origin" && obfs == "plain")
                        proxyStr =
                                "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" +
                                port +
                                "#" + urlEncode(remark);
                } else
                    continue;
                break;
            case ProxyType::VMess:
                if (!vmess)
                    continue;
                proxyStr = "vmess://" + base64Encode(
                               vmessLinkConstruct(remark, hostname, port, faketype, id, aid, transproto, path, host,
                                                  tlssecure ? "tls" : ""));
                break;
            case ProxyType::Hysteria2:
                if (!hysteria2)
                    continue;
                proxyStr = "hysteria2://" + password + "@" + hostname + ":" + port + (ports.empty() ? "" : "," + ports)
                           + "?insecure=" +
                           (x.AllowInsecure.get() ? "1" : "0");
                if (!obfsparam.empty()) {
                    proxyStr += "&obfs=" + obfsparam;
                    if (!obfsPassword.empty()) {
                        proxyStr += "&obfs-password=" + obfsparam;
                    }
                }
                if (!sni.empty()) {
                    proxyStr += "&sni=" + sni;
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::VLESS: {
                if (!vless)
                    continue;
            // tls = getUrlArg(addition, "security");
            // net = getUrlArg(addition, "type");
            // flow = getUrlArg(addition, "flow");
            // pbk = getUrlArg(addition, "pbk");
            // sid = getUrlArg(addition, "sid");
            // fp = getUrlArg(addition, "fp");
            // std::string packet_encoding = getUrlArg(addition, "packet-encoding");
            // std::string alpn = getUrlArg(addition, "alpn");
                proxyStr = "vless://" +
                           (id.empty() ? "00000000-0000-0000-0000-000000000000" : id) + "@" + hostname + ":" + port +
                           "?";
                auto addVlessParam = [&](const std::string &k, const std::string &v) {
                    proxyStr += (proxyStr.back() == '?' ? "" : "&");
                    proxyStr += k + "=" + v;
                };

                if (!tls.empty()) {
                    if (!pbk.empty())
                        addVlessParam("security", "reality");
                    else
                        addVlessParam("security", tls);
                }

                if (!flow.empty())
                    addVlessParam("flow", flow);
                addVlessParam("encryption", urlEncode(x.Encryption.empty() ? "none" : x.Encryption));
                if (!pbk.empty())
                    addVlessParam("pbk", pbk);
                if (!sid.empty())
                    addVlessParam("sid", sid);
                if (!fp.empty())
                    addVlessParam("fp", fp);
                if (!packet_encoding.empty())
                    addVlessParam("packet-encoding", packet_encoding);
                if (!alpns.empty())
                    addVlessParam("alpn", urlEncode(join(alpns, ",")));
                if (!sni.empty())
                    addVlessParam("sni", sni);
                if (!transproto.empty()) {
                    addVlessParam("type", transproto);
                    switch (hash_(transproto)) {
                        case "tcp"_hash:
                        case "ws"_hash:
                        case "h2"_hash:
                            if (!host.empty()) {
                                addVlessParam("host", host);
                            }
                            addVlessParam("headerType", fake_type);
                            addVlessParam("path", urlEncode(path.empty() ? "/" : path));
                            break;
                        case "grpc"_hash:
                            addVlessParam("serviceName", path);
                            addVlessParam("mode", mode);
                            break;
                        case "xhttp"_hash:
                            if (!host.empty())
                                addVlessParam("host", host);
                            addVlessParam("path", urlEncode(path.empty() ? "/" : path));
                            if (!x.XhttpMode.empty())
                                addVlessParam("mode", x.XhttpMode);
                            {
                                // XhttpExtra (from Xray input) already encodes all extra fields.
                                // For Clash-parsed nodes, synthesize extra from individual fields.
                                // 先取已有 extra（Xray 输入原样保留），没有则由各
                                // 独立字段合成；随后无论哪种来源都把 downloadSettings
                                // 并进去——它在 Xray 里的正式位置就是 extra 内。
                                rapidjson::Document ed;
                                ed.SetObject();
                                auto &ea = ed.GetAllocator();
                                bool hasExtra = false;
                                if (!x.XhttpExtra.empty()) {
                                    rapidjson::Document src;
                                    src.Parse(x.XhttpExtra.data());
                                    if (!src.HasParseError() && src.IsObject()) {
                                        for (const auto &kv : src.GetObject())
                                            ed.AddMember(rapidjson::Value(kv.name, ea),
                                                         rapidjson::Value(kv.value, ea), ea);
                                        hasExtra = true;
                                    }
                                }
                                if (!hasExtra) {
                                    addExtraNumericOrRange(ed, "scMaxEachPostBytes",
                                                           x.XhttpScMaxEachPostBytes, ea);
                                    if (!x.XhttpNoGrpcHeader.is_undef())
                                        ed.AddMember("noGRPCHeader", x.XhttpNoGrpcHeader.get(), ea);
                                    if (!x.XhttpPaddingBytes.empty())
                                        ed.AddMember("xPaddingBytes",
                                                     rapidjson::Value(x.XhttpPaddingBytes.c_str(), ea), ea);
                                    if (!x.XhttpHeaders.empty()) {
                                        rapidjson::Document hd;
                                        hd.Parse(x.XhttpHeaders.data());
                                        if (!hd.HasParseError() && hd.IsObject() && !hd.ObjectEmpty())
                                            ed.AddMember("headers", rapidjson::Value(hd, ea), ea);
                                    }
                                    if (!x.XhttpReuseSettings.empty()) {
                                        rapidjson::Document rd;
                                        rd.Parse(x.XhttpReuseSettings.data());
                                        if (!rd.HasParseError() && rd.IsObject()) {
                                            rapidjson::Value xmux(rapidjson::kObjectType);
                                            bool hasXmux = false;
                                            static const struct { const char *mihomo; const char *xray; } reuseMap[] = {
                                                {"max-connections",   "maxConnections"},
                                                {"max-concurrency",   "maxConcurrency"},
                                                {"c-max-reuse-times", "cMaxReuseTimes"},
                                                {"h-max-request-times","hMaxRequestTimes"},
                                                {"h-max-reusable-secs","hMaxReusableSecs"},
                                            };
                                            for (const auto &f : reuseMap) {
                                                if (rd.HasMember(f.mihomo) && rd[f.mihomo].IsString()
                                                    && rd[f.mihomo].GetStringLength() > 0) {
                                                    xmux.AddMember(rapidjson::Value(f.xray, ea),
                                                                   rapidjson::Value(rd[f.mihomo].GetString(), ea), ea);
                                                    hasXmux = true;
                                                }
                                            }
                                            if (rd.HasMember("h-keep-alive-period") &&
                                                rd["h-keep-alive-period"].IsString()) {
                                                int hkap = atoi(rd["h-keep-alive-period"].GetString());
                                                if (hkap != 0) {
                                                    xmux.AddMember("hKeepAlivePeriod", hkap, ea);
                                                    hasXmux = true;
                                                }
                                            }
                                            if (hasXmux)
                                                ed.AddMember("xmux", xmux, ea);
                                        }
                                    }
                                    if (!x.XhttpClashOpts.empty()) {
                                        rapidjson::Document cd;
                                        cd.Parse(x.XhttpClashOpts.data());
                                        if (!cd.HasParseError() && cd.IsObject()) {
                                            for (const auto &f : XHTTP_DOC_FIELDS) {
                                                if (!cd.HasMember(f.mihomo))
                                                    continue;
                                                const auto &v = cd[f.mihomo];
                                                if (f.type == XhttpFieldType::Bool) {
                                                    if (v.IsBool())
                                                        ed.AddMember(rapidjson::Value(f.xray, ea),
                                                                     rapidjson::Value(v.GetBool()), ea);
                                                } else if (!v.IsString() || v.GetStringLength() == 0) {
                                                    continue;
                                                } else if (f.type == XhttpFieldType::Numeric) {
                                                    addExtraNumericOrRange(ed, f.xray, v.GetString(), ea);
                                                } else {
                                                    ed.AddMember(rapidjson::Value(f.xray, ea),
                                                                 rapidjson::Value(v.GetString(), ea), ea);
                                                }
                                            }
                                        }
                                    }
                                }
                                {
                                    // 原始 Xray 输入原样透传，不补 network，以免改变其
                                    // 默认网络行为；从 mihomo canonical 生成的才需要完整
                                    // StreamConfig。用替换而非追加，避免同名键重复。
                                    std::string dsJson = x.XhttpDownloadSettings;
                                    if (dsJson.empty())
                                        dsJson = mihomoDownloadToXrayJson(x, x.XhttpDownload);
                                    if (!dsJson.empty()) {
                                        rapidjson::Document dsd;
                                        dsd.Parse(dsJson.data());
                                        if (!dsd.HasParseError() && dsd.IsObject()) {
                                            // RemoveMember 只移除首个同名成员，
                                            // 输入 extra 自带重复键时需循环清除
                                            while (ed.HasMember("downloadSettings"))
                                                ed.RemoveMember("downloadSettings");
                                            ed.AddMember("downloadSettings",
                                                         rapidjson::Value(dsd, ea), ea);
                                        }
                                    }
                                }
                                std::string extraToExport;
                                if (!ed.ObjectEmpty()) {
                                    rapidjson::StringBuffer ebuf;
                                    rapidjson::Writer<rapidjson::StringBuffer> ew(ebuf);
                                    ed.Accept(ew);
                                    extraToExport = ebuf.GetString();
                                }
                                if (!extraToExport.empty())
                                    addVlessParam("extra", urlEncode(extraToExport));
                            }
                            break;
                        case "quic"_hash:
                            addVlessParam("headerType", fake_type);
                            addVlessParam("quicSecurity", host.empty() ? sni : host);
                            addVlessParam("key", path);
                            break;
                        default:
                            break;
                    }
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            }
            case ProxyType::Trojan:
                if (!trojan)
                    continue;
                proxyStr = "trojan://" + password + "@" + hostname + ":" + port + "?allowInsecure=" +
                           (x.AllowInsecure.get() ? "1" : "0");
                if (!sni.empty()) {
                    proxyStr += "&sni=" + sni;
                } else if (!host.empty()) {
                    proxyStr += "&sni=" + host;
                }
                if (!fp.empty())
                    proxyStr += "&fp=" + urlEncode(fp);
                if (!pbk.empty()) {
                    proxyStr += "&security=reality&pbk=" + urlEncode(pbk);
                    if (!sid.empty())
                        proxyStr += "&sid=" + urlEncode(sid);
                } else if (!tlssecure) {
                    proxyStr += "&security=none";
                }
                if (transproto == "ws") {
                    // 同时输出旧式(ws=1&wspath)与 v2rayN 式(type=ws&path&host)参数以兼容两类客户端
                    proxyStr += "&ws=1&type=ws";
                    if (!path.empty())
                        proxyStr += "&wspath=" + urlEncode(path) + "&path=" + urlEncode(path);
                    if (!host.empty())
                        proxyStr += "&host=" + urlEncode(host);
                } else if (transproto == "grpc" && !path.empty()) {
                    proxyStr += "&type=grpc&serviceName=" + urlEncode(path);
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            default:
                continue;
        }
        allLinks += proxyStr + "\n";
    }

    if (ext.nodelist)
        return allLinks;
    return base64Encode(allLinks);
}

std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document base;

    auto &alloc = base.GetAllocator();

    base_conf = trimWhitespace(base_conf);
    if (base_conf.empty())
        base_conf = "{}";
    rapidjson::ParseResult result = base.Parse(base_conf.data());
    if (!result)
        writeLog(0, std::string("SIP008 base loader failed with error: ") +
                    rapidjson::GetParseError_En(result.Code()) +
                    " (" + std::to_string(result.Offset()) + ")", LOG_LEVEL_ERROR);

    rapidjson::Value proxies(rapidjson::kArrayType);
    for (Proxy &x: nodes) {
        std::string &remark = x.Remark;
        std::string &hostname = x.Hostname;
        std::string &password = x.Password;
        std::string &method = x.EncryptMethod;
        std::string &plugin = x.Plugin;
        std::string &pluginopts = x.PluginOption;
        std::string &protocol = x.Protocol;
        std::string &obfs = x.OBFS;

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (plugin == "simple-obfs")
                    plugin = "obfs-local";
                break;
            case ProxyType::ShadowsocksR:
                if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) == ss_ciphers.end() ||
                    protocol != "origin" || obfs != "plain")
                    continue;
                break;
            default:
                continue;
        }
        rapidjson::Value proxy(rapidjson::kObjectType);
        proxy.CopyFrom(base, alloc)
                | AddMemberOrReplace("remarks", rapidjson::Value(remark.c_str(), remark.size()), alloc)
                | AddMemberOrReplace("server", rapidjson::Value(hostname.c_str(), hostname.size()), alloc)
                | AddMemberOrReplace("server_port", rapidjson::Value(x.Port), alloc)
                | AddMemberOrReplace("method", rapidjson::Value(method.c_str(), method.size()), alloc)
                | AddMemberOrReplace("password", rapidjson::Value(password.c_str(), password.size()), alloc)
                | AddMemberOrReplace("plugin", rapidjson::Value(plugin.c_str(), plugin.size()), alloc)
                | AddMemberOrReplace("plugin_opts", rapidjson::Value(pluginopts.c_str(), pluginopts.size()), alloc);
        proxies.PushBack(proxy, alloc);
    }
    return proxies | SerializeObject();
}

std::string
proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf,
            std::vector<RulesetContent> &ruleset_content_array,
            const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;
    if (!ext.nodelist && ini.parse(base_conf) != 0) {
        writeLog(0, "Quantumult base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuan(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist) {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("SERVER", "{NONAME}", allnodes);
        if (!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return base64Encode(allLinks);
    }
    return ini.to_string();
}

void proxyToQuan(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array,
                 const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    std::string proxyStr;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("SERVER");
    ini.erase_section();
    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &password = x.Password, &id = x.UserId, &
                        transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &edge = x.Edge, &protocol = x.
                        Protocol,
                &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &plugin = x.Plugin, &pluginopts
                        = x.
                        PluginOption, &username = x.Username;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;
        tribool scv;

        switch (x.Type) {
            case ProxyType::VMess:
                scv = ext.skip_cert_verify;
                scv.define(x.AllowInsecure);

                if (method == "auto")
                    method = "chacha20-ietf-poly1305";
                proxyStr =
                        x.Remark + " = vmess, " + hostname + ", " + port + ", " + method + ", \"" + id +
                        "\", group=" +
                        x.Group;
                if (tlssecure) {
                    proxyStr += ", over-tls=true, tls-host=" + host;
                    if (!scv.is_undef())
                        proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
                }
                if (transproto == "ws") {
                    proxyStr += ", obfs=ws, obfs-path=\"" + path + "\", obfs-header=\"Host: " + host;
                    if (!edge.empty())
                        proxyStr += "[Rr][Nn]Edge: " + edge;
                    proxyStr += "\"";
                }

                if (ext.nodelist)
                    proxyStr = "vmess://" + urlSafeBase64Encode(proxyStr);
                break;
            case ProxyType::ShadowsocksR:
                if (ext.nodelist) {
                    proxyStr = "ssr://" + urlSafeBase64Encode(
                                   hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" +
                                   urlSafeBase64Encode(password)
                                   + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(
                                       x.Remark)
                                   + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" +
                                   urlSafeBase64Encode(protoparam));
                } else {
                    proxyStr = x.Remark + " = shadowsocksr, " + hostname + ", " + port + ", " + method + ", \"" +
                               password + "\", group=" + x.Group + ", protocol=" + protocol + ", obfs=" + obfs;
                    if (!protoparam.empty())
                        proxyStr += ", protocol_param=" + protoparam;
                    if (!obfsparam.empty())
                        proxyStr += ", obfs_param=" + obfsparam;
                }
                break;
            case ProxyType::Shadowsocks:
                if (ext.nodelist) {
                    proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                    if (!plugin.empty() && !pluginopts.empty()) {
                        proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                    }
                    proxyStr += "&group=" + urlSafeBase64Encode(x.Group) + "#" + urlEncode(x.Remark);
                } else {
                    proxyStr =
                            x.Remark + " = shadowsocks, " + hostname + ", " + port + ", " + method + ", \"" +
                            password +
                            "\", group=" + x.Group;
                    if (plugin == "obfs-local" && !pluginopts.empty()) {
                        proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                    }
                }
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                proxyStr =
                        x.Remark + " = http, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port +
                        ", group=" + x.Group;
                if (!username.empty() && !password.empty())
                    proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username +
                            ", upstream-proxy-password=" + password;
                else
                    proxyStr += ", upstream-proxy-auth=false";

                if (tlssecure) {
                    proxyStr += ", over-tls=true";
                    if (!host.empty())
                        proxyStr += ", tls-host=" + host;
                    if (!scv.is_undef())
                        proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
                }

                if (ext.nodelist)
                    proxyStr = "http://" + urlSafeBase64Encode(proxyStr);
                break;
            case ProxyType::SOCKS5:
                proxyStr = x.Remark + " = socks, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" +
                           port +
                           ", group=" + x.Group;
                if (!username.empty() && !password.empty())
                    proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username +
                            ", upstream-proxy-password=" + password;
                else
                    proxyStr += ", upstream-proxy-auth=false";

                if (tlssecure) {
                    proxyStr += ", over-tls=true";
                    if (!host.empty())
                        proxyStr += ", tls-host=" + host;
                    if (!scv.is_undef())
                        proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
                }

                if (ext.nodelist)
                    proxyStr = "socks://" + urlSafeBase64Encode(proxyStr);
                break;
            default:
                continue;
        }

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (ext.nodelist)
        return;

    ini.set_current_section("POLICY");
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string type;
        std::string singlegroup;
        std::string name, proxies;

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::Fallback:
                type = "static";
                break;
            case ProxyGroupType::URLTest:
                type = "auto";
                break;
            case ProxyGroupType::LoadBalance:
                type = "balance, round-robin";
                break;
            case ProxyGroupType::SSID: {
                singlegroup = x.Name + " : wifi = " + x.Proxies[0];
                std::string content, celluar, celluar_matcher = R"(^(.*?),?celluar\s?=\s?(.*?)(,.*)$)", rem_a, rem_b;
                for (auto iter = x.Proxies.begin() + 1; iter != x.Proxies.end(); iter++) {
                    if (regGetMatch(*iter, celluar_matcher, 4, 0, &rem_a, &celluar, &rem_b)) {
                        content += *iter + "\n";
                        continue;
                    }
                    content += rem_a + rem_b + "\n";
                }
                if (!celluar.empty())
                    singlegroup += ", celluar = " + celluar;
                singlegroup += "\n" + replaceAllDistinct(trimOf(content, ','), ",", "\n");
                ini.set("{NONAME}", base64Encode(singlegroup)); //insert order
            }
                continue;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("direct");

        if (filtered_nodelist.size() < 2) // force groups with 1 node to be static
            type = "static";

        proxies = join(filtered_nodelist, "\n");

        singlegroup = x.Name + " : " + type;
        if (type == "static")
            singlegroup += ", " + filtered_nodelist[0];
        singlegroup += "\n" + proxies + "\n";
        ini.set("{NONAME}", base64Encode(singlegroup));
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -2, ext.overwrite_original_rules, "");
}

std::string proxyToQuanX(std::vector<Proxy> &nodes, const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;
    ini.add_direct_save_section("general");
    ini.add_direct_save_section("dns");
    ini.add_direct_save_section("rewrite_remote");
    ini.add_direct_save_section("rewrite_local");
    ini.add_direct_save_section("task_local");
    ini.add_direct_save_section("mitm");
    ini.add_direct_save_section("server_remote");
    if (!ext.nodelist && ini.parse(base_conf) != 0) {
        writeLog(0, "QuantumultX base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuanX(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist) {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("server_local", "{NONAME}", allnodes);
        if (!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return allLinks;
    }
    return ini.to_string();
}

void proxyToQuanX(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array,
                  const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    std::string proxyStr;
    tribool udp, tfo, scv, tls13;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("server_local");
    ini.erase_section();
    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path, &password = x.Password, &plugin = x.Plugin, &pluginopts = x.PluginOption
                , &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &
                        username = x.Username, &sni = x.ServerName, &publickey = x.PublicKey, &shortid = x.ShortId, &flow = x.Flow;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        udp = ext.udp;
        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        switch (x.Type) {
            case ProxyType::VMess:
                if (method == "auto")
                    method = "chacha20-ietf-poly1305";
                proxyStr = "vmess = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
                if (x.AlterId != 0)
                    proxyStr += ", aead=false";
                if (tlssecure && !tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                if (transproto == "ws") {
                    if (tlssecure)
                        proxyStr += ", obfs=wss";
                    else
                        proxyStr += ", obfs=ws";
                    proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
                } else if (tlssecure)
                    proxyStr += ", obfs=over-tls, obfs-host=" + host;
                break;
            case ProxyType::VLESS:
                if (transproto == "xhttp") {
                    writeLog(0, "Skipping xhttp node for unsupported target: Quantumult X", LOG_LEVEL_WARNING);
                    continue;
                }
                method = "none";
                proxyStr = "vless = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
                if (tlssecure && !tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                if (transproto == "ws") {
                    proxyStr += tlssecure ? ", obfs=wss" : ", obfs=ws";

                    if (tlssecure && !publickey.empty() && sni.empty())
                        writeLog(0, "Quantumult X vless reality: public key present but SNI missing; skipping reality output.", LOG_LEVEL_WARNING);
                    if (tlssecure && !shortid.empty() && publickey.empty())
                        writeLog(0, "Quantumult X vless reality: shortid present but public key missing; skipping reality output.", LOG_LEVEL_WARNING);

                    if (tlssecure && !publickey.empty() && !sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    else if (!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    if (!path.empty())
                        proxyStr += ", obfs-uri=" + path;
                    if (tlssecure && !publickey.empty() && !sni.empty()) {
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if (!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                    }
                } else if (transproto == "http") {
                    proxyStr += ", obfs=http";
                    if (!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    if (!path.empty())
                        proxyStr += ", obfs-uri=" + path;
                } else if (tlssecure) {
                    proxyStr += ", obfs=over-tls";

                    if (!publickey.empty() && sni.empty())
                        writeLog(0, "Quantumult X vless reality: public key present but SNI missing; skipping reality output.", LOG_LEVEL_WARNING);
                    if (!shortid.empty() && publickey.empty())
                        writeLog(0, "Quantumult X vless reality: shortid present but public key missing; skipping reality output.", LOG_LEVEL_WARNING);

                    if (!publickey.empty() && !sni.empty()) {
                        proxyStr += ", obfs-host=" + sni;
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if (!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                        if (!flow.empty())
                            proxyStr += ", vless-flow=" + flow;
                    } else if (!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    else if (!host.empty())
                        proxyStr += ", obfs-host=" + host;
                }
                break;
            case ProxyType::Shadowsocks:
                proxyStr =
                        "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password;
                if (!plugin.empty()) {
                    switch (hash_(plugin)) {
                        case "simple-obfs"_hash:
                        case "obfs-local"_hash:
                            if (!pluginopts.empty())
                                proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                            break;
                        case "v2ray-plugin"_hash:
                            pluginopts = replaceAllDistinct(pluginopts, ";", "&");
                            plugin = getUrlArg(pluginopts, "mode") == "websocket" ? "ws" : "";
                            host = getUrlArg(pluginopts, "host");
                            path = getUrlArg(pluginopts, "path");
                            tlssecure = pluginopts.find("tls") != std::string::npos;
                            if (tlssecure && plugin == "ws") {
                                plugin += 's';
                                if (!tls13.is_undef())
                                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                            }
                            proxyStr += ", obfs=" + plugin;
                            if (!host.empty())
                                proxyStr += ", obfs-host=" + host;
                            if (!path.empty())
                                proxyStr += ", obfs-uri=" + path;
                            break;
                        default:
                            continue;
                    }
                }

                break;
            case ProxyType::ShadowsocksR:
                proxyStr =
                        "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password +
                        ", ssr-protocol=" + protocol;
                if (!protoparam.empty())
                    proxyStr += ", ssr-protocol-param=" + protoparam;
                proxyStr += ", obfs=" + obfs;
                if (!obfsparam.empty())
                    proxyStr += ", obfs-host=" + obfsparam;
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                proxyStr =
                        "http = " + hostname + ":" + port + ", username=" + (username.empty() ? "none" : username) +
                        ", password=" + (password.empty() ? "none" : password);
                if (tlssecure) {
                    proxyStr += ", over-tls=true";
                    if (!tls13.is_undef())
                        proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                } else {
                    proxyStr += ", over-tls=false";
                }
                break;
            case ProxyType::Trojan:
                proxyStr = "trojan = " + hostname + ":" + port + ", password=" + password;
                if (tlssecure) {
                    proxyStr += ", over-tls=true, tls-host=" + host;
                    if (!tls13.is_undef())
                        proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                } else {
                    proxyStr += ", over-tls=false";
                }
                break;
            case ProxyType::SOCKS5:
                proxyStr = "socks5 = " + hostname + ":" + port;
                if (!username.empty() && !password.empty()) {
                    proxyStr += ", username=" + username + ", password=" + password;
                    if (tlssecure) {
                        proxyStr += ", over-tls=true, tls-host=" + host;
                        if (!tls13.is_undef())
                            proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                    } else {
                        proxyStr += ", over-tls=false";
                    }
                }
                break;
            default:
                continue;
        }
        if (!tfo.is_undef())
            proxyStr += ", fast-open=" + tfo.get_str();
        if (!udp.is_undef())
            proxyStr += ", udp-relay=" + udp.get_str();
        if (tlssecure && !scv.is_undef() &&
            (x.Type != ProxyType::Shadowsocks && x.Type != ProxyType::ShadowsocksR && x.Type != ProxyType::VLESS))
            proxyStr += ", tls-verification=" + scv.reverse().get_str();
        proxyStr += ", tag=" + x.Remark;

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (ext.nodelist)
        return;

    string_multimap original_groups;
    ini.set_current_section("policy");
    ini.get_items(original_groups);
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        std::string type;
        string_array filtered_nodelist;

        switch (x.Type) {
            case ProxyGroupType::Select:
                type = "static";
                break;
            case ProxyGroupType::URLTest:
                type = "url-latency-benchmark";
                break;
            case ProxyGroupType::Fallback:
                type = "available";
                break;
            case ProxyGroupType::LoadBalance:
                type = "round-robin";
                break;
            case ProxyGroupType::SSID:
                type = "ssid";
                for (const auto &proxy: x.Proxies)
                    filtered_nodelist.emplace_back(replaceAllDistinct(proxy, "=", ":"));
                break;
            default:
                continue;
        }

        if (x.Type != ProxyGroupType::SSID) {
            for (const auto &y: x.Proxies)
                groupGenerate(y, nodelist, filtered_nodelist, true, ext);

            if (filtered_nodelist.empty())
                filtered_nodelist.emplace_back("direct");

            if (filtered_nodelist.size() < 2) // force groups with 1 node to be static
                type = "static";
        }

        auto iter = std::find_if(original_groups.begin(), original_groups.end(),
                                 [&](const string_multimap::value_type &n) {
                                     std::string groupdata = n.second;
                                     std::string::size_type cpos = groupdata.find(',');
                                     if (cpos != std::string::npos)
                                         return trim(groupdata.substr(0, cpos)) == x.Name;
                                     else
                                         return false;
                                 });
        if (iter != original_groups.end()) {
            string_array vArray = split(iter->second, ",");
            if (vArray.size() > 1) {
                if (trim(vArray[vArray.size() - 1]).find("img-url") == 0)
                    filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
            }
        }

        std::string proxies = join(filtered_nodelist, ", ");

        std::string singlegroup = type + "=" + x.Name + ", " + proxies;
        if (x.Type != ProxyGroupType::Select && x.Type != ProxyGroupType::SSID) {
            singlegroup += ", check-interval=" + std::to_string(x.Interval);
            if (x.Tolerance > 0)
                singlegroup += ", tolerance=" + std::to_string(x.Tolerance);
        }
        ini.set("{NONAME}", singlegroup);
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -1, ext.overwrite_original_rules, ext.managed_config_prefix);
}

std::string proxyToSSD(std::vector<Proxy> &nodes, std::string &group, std::string &userinfo, extra_settings &ext) {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    int index = 0;

    if (group.empty())
        group = "SSD";

    writer.StartObject();
    writer.Key("airport");
    writer.String(group.data());
    writer.Key("port");
    writer.Int(1);
    writer.Key("encryption");
    writer.String("aes-128-gcm");
    writer.Key("password");
    writer.String("password");
    if (!userinfo.empty()) {
        std::string data = replaceAllDistinct(userinfo, "; ", "&");
        std::string upload = getUrlArg(data, "upload"), download = getUrlArg(data, "download"), total = getUrlArg(
            data,
            "total"), expiry = getUrlArg(
            data, "expire");
        double used = (to_number(upload, 0.0) + to_number(download, 0.0)) / std::pow(1024, 3) * 1.0, tot =
                to_number(total, 0.0) / std::pow(1024, 3) * 1.0;
        writer.Key("traffic_used");
        writer.Double(used);
        writer.Key("traffic_total");
        writer.Double(tot);
        if (!expiry.empty()) {
            const time_t rawtime = to_int(expiry);
            char buffer[30];
            struct tm *dt = localtime(&rawtime);
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", dt);
            writer.Key("expiry");
            writer.String(buffer);
        }
    }
    writer.Key("servers");
    writer.StartArray();

    for (Proxy &x: nodes) {
        std::string &hostname = x.Hostname, &password = x.Password, &method = x.EncryptMethod, &plugin = x.Plugin, &
                pluginopts = x.PluginOption, &protocol = x.Protocol, &obfs = x.OBFS;

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (plugin == "obfs-local")
                    plugin = "simple-obfs";
                writer.StartObject();
                writer.Key("server");
                writer.String(hostname.data());
                writer.Key("port");
                writer.Int(x.Port);
                writer.Key("encryption");
                writer.String(method.data());
                writer.Key("password");
                writer.String(password.data());
                writer.Key("plugin");
                writer.String(plugin.data());
                writer.Key("plugin_options");
                writer.String(pluginopts.data());
                writer.Key("remarks");
                writer.String(x.Remark.data());
                writer.Key("id");
                writer.Int(index);
                writer.EndObject();
                break;
            case ProxyType::ShadowsocksR:
                if (std::count(ss_ciphers.begin(), ss_ciphers.end(), method) > 0 && protocol == "origin" &&
                    obfs == "plain") {
                    writer.StartObject();
                    writer.Key("server");
                    writer.String(hostname.data());
                    writer.Key("port");
                    writer.Int(x.Port);
                    writer.Key("encryption");
                    writer.String(method.data());
                    writer.Key("password");
                    writer.String(password.data());
                    writer.Key("remarks");
                    writer.String(x.Remark.data());
                    writer.Key("id");
                    writer.Int(index);
                    writer.EndObject();
                    break;
                } else
                    continue;
            default:
                continue;
        }
        index++;
    }
    writer.EndArray();
    writer.EndObject();
    return "ssd://" + base64Encode(sb.GetString());
}

std::string proxyToMellow(std::vector<Proxy> &nodes, const std::string &base_conf,
                          std::vector<RulesetContent> &ruleset_content_array,
                          const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;
    if (ini.parse(base_conf) != 0) {
        writeLog(0, "Mellow base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToMellow(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    return ini.to_string();
}

void proxyToMellow(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array,
                   const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    std::string proxy;
    std::string username, password, method;
    std::string plugin, pluginopts;
    std::string id, aid, transproto, faketype, host, path, quicsecure, quicsecret, tlssecure;
    std::string url;
    tribool tfo, scv;
    std::vector<Proxy> nodelist;
    string_array vArray, remarks_list;

    ini.set_current_section("Endpoint");

    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, port = std::to_string(x.Port);

        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (!x.Plugin.empty())
                    continue;
                proxy = x.Remark + ", ss, ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname +
                        ":" +
                        port;
                break;
            case ProxyType::VMess:
                proxy = x.Remark + ", vmess1, vmess1://" + id + "@" + hostname + ":" + port;
                if (!path.empty())
                    proxy += path;
                proxy += "?network=" + transproto;
                switch (hash_(transproto)) {
                    case "ws"_hash:
                        proxy += "&ws.host=" + urlEncode(host);
                        break;
                    case "http"_hash:
                        if (!host.empty())
                            proxy += "&http.host=" + urlEncode(host);
                        break;
                    case "quic"_hash:
                        if (!quicsecure.empty())
                            proxy += "&quic.security=" + quicsecure + "&quic.key=" + quicsecret;
                        break;
                    case "kcp"_hash:
                    case "tcp"_hash:
                        break;
                }
                proxy += "&tls=" + tlssecure;
                if (tlssecure == "true") {
                    if (!host.empty())
                        proxy += "&tls.servername=" + urlEncode(host);
                }
                if (!scv.is_undef())
                    proxy += "&tls.allowinsecure=" + scv.get_str();
                if (!tfo.is_undef())
                    proxy += "&sockopt.tcpfastopen=" + tfo.get_str();
                break;
            case ProxyType::SOCKS5:
                proxy = x.Remark + ", builtin, socks, address=" + hostname + ", port=" + port + ", user=" +
                        username +
                        ", pass=" + password;
                break;
            case ProxyType::HTTP:
                proxy = x.Remark + ", builtin, http, address=" + hostname + ", port=" + port + ", user=" +
                        username +
                        ", pass=" + password;
                break;
            default:
                continue;
        }

        ini.set("{NONAME}", proxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    ini.set_current_section("EndpointGroup");

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        url.clear();
        proxy.clear();

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
            case ProxyGroupType::LoadBalance:
                break;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, false, ext);

        if (filtered_nodelist.empty()) {
            if (remarks_list.empty())
                filtered_nodelist.emplace_back("DIRECT");
            else
                filtered_nodelist = remarks_list;
        }

        //don't process these for now
        /*
        proxy = vArray[1];
        for(std::string &x : filtered_nodelist)
            proxy += "," + x;
        if(vArray[1] == "url-test" || vArray[1] == "fallback" || vArray[1] == "load-balance")
            proxy += ",url=" + url;
        */

        proxy = x.Name + ", ";
        /*
        for(std::string &y : filtered_nodelist)
            proxy += y + ":";
        proxy = proxy.substr(0, proxy.size() - 1);
        */
        proxy += join(filtered_nodelist, ":");
        proxy += ", latency, interval=300, timeout=6"; //use hard-coded values for now

        ini.set("{NONAME}", proxy); //insert order
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, 0, ext.overwrite_original_rules, "");
}

std::string
proxyToLoon(std::vector<Proxy> &nodes, const std::string &base_conf,
            std::vector<RulesetContent> &ruleset_content_array,
            const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;

    string_array remarks_list;

    ini.store_any_line = true;
    ini.add_direct_save_section("Plugin");
    if (ini.parse(base_conf) != INIREADER_EXCEPTION_NONE && !ext.nodelist) {
        writeLog(0, "Loon base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();

    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }
        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &username = x.Username, &password = x.Password, &method = x.EncryptMethod, &
                plugin = x.Plugin, &pluginopts = x.PluginOption, &id = x.UserId, &transproto = x.TransferProtocol, &host
                = x.Host, &path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &
                obfsparam = x.OBFSParam, flow = x.Flow, pk = x.PublicKey, shortId = x.ShortId, sni = x.ServerName;
        std::string port = std::to_string(x.Port), aid = std::to_string(x.AlterId);
        bool &tlssecure = x.TLSSecure;

        tribool scv = ext.skip_cert_verify;
        scv.define(x.AllowInsecure);
        tribool udp = x.UDP.is_undef() ? ext.udp.is_undef() ? false : ext.udp.get() : x.UDP.get();
        std::string proxy;

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                proxy = "Shadowsocks," + hostname + "," + port + "," + method + ",\"" + password + "\"";
                if (plugin == "simple-obfs" || plugin == "obfs-local") {
                    if (!pluginopts.empty())
                        proxy += "," +
                                replaceAllDistinct(replaceAllDistinct(pluginopts, ";obfs-host=", ","), "obfs=",
                                                   "");
                } else if (!plugin.empty())
                    continue;
                break;
            case ProxyType::VMess:
                if (method == "auto")
                    method = "chacha20-ietf-poly1305";

                proxy = "vmess," + hostname + "," + port + "," + method + ",\"" + id + "\",over-tls=" +
                        (tlssecure ? "true" : "false");

                if (!sni.empty())
                    host = sni;

                if (tlssecure)
                    proxy += ",tls-name=" + host;
                switch (hash_(transproto)) {
                    case "tcp"_hash:
                        proxy += ",transport=tcp";
                        break;
                    case "ws"_hash:
                        proxy += ",transport=ws,path=" + path + ",host=" + host;
                        break;
                    default:
                        continue;
                }
                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                break;
            case ProxyType::VLESS:
                if (flow != "xtls-rprx-vision") {
                    if (transproto == "ws") {
                        proxy = "Vless," + hostname + "," + port + ",\"" + id + "\"" +
                            ",path=" + path + ",host=" + host + ",transport=" + transproto +
                            ",udp=" + (udp.get() ? "true" : "false") + ",over-tls=" + (
                                tlssecure ? "true" : "false") + ",sni=" + sni;
                    } else {
                        continue;
                    }
                } else {
                    proxy = "Vless," + hostname + "," + port + ",\"" + id + "\",flow=" + flow + ",public-key=\"" + pk +
                            "\",short-id=" + shortId + ",udp=" + (udp.get() ? "true" : "false") + ",over-tls=" + (
                                tlssecure ? "true" : "false") + ",sni=" + sni;
                }

                switch (hash_(transproto)) {
                    case "tcp"_hash:
                        proxy += ",transport=tcp";
                        break;
                    default:
                        if (transproto != "ws") {
                            continue;
                        } else {
                            break;;
                        }
                }
                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                break;
            case ProxyType::ShadowsocksR:
                proxy = "ShadowsocksR," + hostname + "," + port + "," + method + ",\"" + password + "\",protocol=" +
                        protocol + ",protocol-param=" + protoparam + ",obfs=" + obfs + ",obfs-param=" + obfsparam;
                break;
            case ProxyType::HTTP:
                proxy = "http," + hostname + "," + port + "," + username + ",\"" + password + "\"";
                break;
            case ProxyType::HTTPS:
                proxy = "https," + hostname + "," + port + "," + username + ",\"" + password + "\"";
                if (!host.empty())
                    proxy += ",tls-name=" + host;
                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                break;
            case ProxyType::Trojan:
                proxy = "trojan," + hostname + "," + port + ",\"" + password + "\"";
                if (!host.empty())
                    proxy += ",tls-name=" + host;
                switch (hash_(transproto)) {
                    case "tcp"_hash:
                        proxy += ",transport=tcp";
                        break;
                    case "ws"_hash:
                        proxy += ",transport=ws,path=" + path + ",host=" + host;
                        break;
                    default:
                        continue;
                }
                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                break;
            case ProxyType::SOCKS5:
                proxy = "socks5," + hostname + "," + port;
                if (!username.empty() && !password.empty())
                    proxy += "," + username + ",\"" + password + "\"";
                proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
                if (tlssecure) {
                    if (!host.empty())
                        proxy += ",tls-name=" + host;
                    if (!scv.is_undef())
                        proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                }
                break;
            case ProxyType::WireGuard:
                proxy = "wireguard, interface-ip=" + x.SelfIP;
                if (!x.SelfIPv6.empty())
                    proxy += ", interface-ipv6=" + x.SelfIPv6;
                proxy += ", private-key=" + x.PrivateKey;
                for (const auto &y: x.DnsServers) {
                    if (isIPv4(y))
                        proxy += ", dns=" + y;
                    else if (isIPv6(y))
                        proxy += ", dnsv6=" + y;
                }
                if (x.Mtu > 0)
                    proxy += ", mtu=" + std::to_string(x.Mtu);
                if (x.KeepAlive > 0)
                    proxy += ", keepalive=" + std::to_string(x.KeepAlive);
                proxy += ", peers=[{" + generatePeer(x, true) + "}]";
                break;
            case ProxyType::Hysteria2:
                proxy = "Hysteria2," + hostname + "," + port + ",\"" + password + "\"";
                if (!x.ServerName.empty()) {
                    proxy += ",sni=" + x.ServerName;
                }
                if (!x.UpMbps.empty()) {
                    std::string search = " Mbps";
                    size_t pos = x.UpMbps.find(search);
                    if (pos != std::string::npos) {
                        x.UpMbps.replace(pos, search.length(), "");
                    } else {
                        search = "Mbps";
                        pos = x.UpMbps.find(search);
                        if (pos != std::string::npos) {
                            x.UpMbps.replace(pos, search.length(), "");
                        }
                    }
                    proxy += ",download-bandwidth=" + x.UpMbps;
                } else {
                    proxy += ",download-bandwidth=100";
                }
                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                break;
            default:
                continue;
        }

        if (ext.tfo) {
            proxy += ",fast-open=true";
        } else {
            if (x.Type == ProxyType::Hysteria2) {
                proxy += ",fast-open=false";
            }
        }
        if (ext.udp) {
            proxy += ",udp=true";
        } else {
            if (x.Type == ProxyType::Hysteria2) {
                proxy += ",udp=true";
            }
        }


        if (ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
            remarks_list.emplace_back(x.Remark);
        }
    }

    if (ext.nodelist)
        return output_nodelist;

    string_multimap original_groups;
    ini.set_current_section("Proxy Group");
    ini.get_items(original_groups);
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string group, group_extra;

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::LoadBalance:
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
                break;
            case ProxyGroupType::SSID:
                if (x.Proxies.size() < 2)
                    continue;
                group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
                group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
                ini.set("{NONAME}", x.Name + " = " + group); //insert order
                continue;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        auto iter = std::find_if(original_groups.begin(), original_groups.end(),
                                 [&](const string_multimap::value_type &n) {
                                     return trim(n.first) == x.Name;
                                 });

        if (iter != original_groups.end()) {
            string_array vArray = split(iter->second, ",");
            if (vArray.size() > 1) {
                if (trim(vArray[vArray.size() - 1]).find("img-url") == 0)
                    filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
            }
        }

        group = x.TypeStr() + ",";
        /*
        for(std::string &y : filtered_nodelist)
            group += "," + y;
        */
        group += join(filtered_nodelist, ",");
        if (x.Type != ProxyGroupType::Select) {
            group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
            if (x.Type == ProxyGroupType::LoadBalance) {
                group += ",algorithm=" +
                        std::string(x.Strategy == BalanceStrategy::RoundRobin ? "round-robin" : "pcc");
                if (x.Timeout > 0)
                    group += ",max-timeout=" + std::to_string(x.Timeout);
            }
            if (x.Type == ProxyGroupType::URLTest) {
                if (x.Tolerance > 0)
                    group += ",tolerance=" + std::to_string(x.Tolerance);
            }
            if (x.Type == ProxyGroupType::Fallback)
                group += ",max-timeout=" + std::to_string(x.Timeout);
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -4, ext.overwrite_original_rules, ext.managed_config_prefix);

    return ini.to_string();
}

static std::string formatSingBoxInterval(Integer interval) {
    std::string result;
    if (interval >= 3600) {
        result += std::to_string(interval / 3600) + "h";
        interval %= 3600;
    }
    if (interval >= 60) {
        result += std::to_string(interval / 60) + "m";
        interval %= 60;
    }
    if (interval > 0)
        result += std::to_string(interval) + "s";
    return result;
}

static rapidjson::Value buildSingBoxTransport(const Proxy &proxy, rapidjson::MemoryPoolAllocator<> &allocator) {
    rapidjson::Value transport(rapidjson::kObjectType);
    switch (hash_(proxy.TransferProtocol)) {
        case "http"_hash: {
            if (!proxy.Host.empty())
                transport.AddMember("host", rapidjson::StringRef(proxy.Host.c_str()), allocator);
            [[fallthrough]];
        }
        case "ws"_hash: {
            transport.AddMember("type", rapidjson::StringRef(proxy.TransferProtocol.c_str()), allocator);
            if (proxy.Path.empty())
                transport.AddMember("path", "/", allocator);
            else
                transport.AddMember("path", rapidjson::StringRef(proxy.Path.c_str()), allocator);

            rapidjson::Value headers(rapidjson::kObjectType);
            if (!proxy.Host.empty())
                headers.AddMember("Host", rapidjson::StringRef(proxy.Host.c_str()), allocator);
            if (!proxy.Edge.empty())
                headers.AddMember("Edge", rapidjson::StringRef(proxy.Edge.c_str()), allocator);
            transport.AddMember("headers", headers, allocator);
            break;
        }
        case "grpc"_hash: {
            transport.AddMember("type", "grpc", allocator);
            if (!proxy.Path.empty())
                transport.AddMember("service_name", rapidjson::StringRef(proxy.Path.c_str()), allocator);
            break;
        }
        default:
            break;
    }
    return transport;
}

static void addSingBoxCommonMembers(rapidjson::Value &proxy, const Proxy &x,
                                    const rapidjson::GenericStringRef<rapidjson::Value::Ch> &type,
                                    rapidjson::MemoryPoolAllocator<> &allocator) {
    proxy.AddMember("type", type, allocator);
    proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
    proxy.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()), allocator);
    proxy.AddMember("server_port", x.Port, allocator);
    if (!x.UnderlyingProxy.empty()) {
        proxy.AddMember("detour", rapidjson::Value(x.UnderlyingProxy.c_str(), allocator), allocator);
    }
    if (!x.InterfaceName.empty())
        proxy.AddMember("bind_interface", rapidjson::Value(x.InterfaceName.c_str(), allocator), allocator);
    if (x.RoutingMark != 0)
        proxy.AddMember("routing_mark", x.RoutingMark, allocator);
    if (!x.MPTCP.is_undef())
        proxy.AddMember("tcp_multi_path", x.MPTCP.get(), allocator);
}

static void addHeaders(rapidjson::Value &transport, const Proxy &x,
                       rapidjson::MemoryPoolAllocator<> &allocator) {
    rapidjson::Value headers(rapidjson::kObjectType);
    if (!x.Host.empty())
        headers.AddMember("Host", rapidjson::StringRef(x.Host.c_str()), allocator);
    if (!x.Edge.empty())
        headers.AddMember("Edge", rapidjson::StringRef(x.Edge.c_str()), allocator);
    transport.AddMember("headers", headers, allocator);
}

static rapidjson::Value stringArrayToJsonArray(const std::string &array, const std::string &delimiter,
                                               rapidjson::MemoryPoolAllocator<> &allocator) {
    rapidjson::Value result(rapidjson::kArrayType);
    string_array vArray = split(array, delimiter);
    for (const auto &x: vArray)
        result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
    return result;
}

static rapidjson::Value
vectorToJsonArray(const std::vector<std::string> &array, rapidjson::MemoryPoolAllocator<> &allocator) {
    rapidjson::Value result(rapidjson::kArrayType);
    for (const auto &x: array)
        result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
    return result;
}

void
proxyToSingBox(std::vector<Proxy> &nodes, rapidjson::Document &json,
               std::vector<RulesetContent> &ruleset_content_array,
               const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document::AllocatorType &allocator = json.GetAllocator();
    rapidjson::Value outbounds(rapidjson::kArrayType), route(rapidjson::kArrayType);
    std::vector<Proxy> nodelist;
    string_array remarks_list;
    std::string search = " Mbps";

    if (!ext.nodelist) {
        auto direct = buildObject(allocator, "type", "direct", "tag", "DIRECT");
        outbounds.PushBack(direct, allocator);
        // 注释掉 REJECT 和 dns-out
        // auto reject = buildObject(allocator, "type", "block", "tag", "REJECT");
        // outbounds.PushBack(reject, allocator);
        // auto dns = buildObject(allocator, "type", "dns", "tag", "dns-out");
        // outbounds.PushBack(dns, allocator);
    }

    for (Proxy &x: nodes) {
        std::string type = getProxyTypeName(x.Type);
        if (ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, xudp = ext.xudp;
        udp.define(x.UDP);
        xudp.define(x.XUDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);

        rapidjson::Value proxy(rapidjson::kObjectType);
        switch (x.Type) {
            case ProxyType::Shadowsocks: {
                addSingBoxCommonMembers(proxy, x, "shadowsocks", allocator);
                proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if (!x.Plugin.empty() && !x.PluginOption.empty()) {
                    std::string plugin = x.Plugin;
                    if (plugin == "simple-obfs" || plugin == "obfs")
                        x.Plugin = "obfs-local";
                    if (x.Plugin != "obfs-local" && x.Plugin != "v2ray-plugin") {
                        continue;
                    }
                    proxy.AddMember("plugin", rapidjson::Value(x.Plugin.c_str(), allocator).Move(), allocator);
                    proxy.AddMember("plugin_opts", rapidjson::Value(x.PluginOption.c_str(), allocator).Move(), allocator);
                }
                break;
            }
            //            case ProxyType::ShadowsocksR: {
            //                addSingBoxCommonMembers(proxy, x, "shadowsocksr", allocator);
            //                proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
            //                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
            //                proxy.AddMember("protocol", rapidjson::StringRef(x.Protocol.c_str()), allocator);
            //                proxy.AddMember("protocol_param", rapidjson::StringRef(x.ProtocolParam.c_str()), allocator);
            //                proxy.AddMember("obfs", rapidjson::StringRef(x.OBFS.c_str()), allocator);
            //                proxy.AddMember("obfs_param", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
            //                break;
            //            }
            case ProxyType::VMess: {
                addSingBoxCommonMembers(proxy, x, "vmess", allocator);
                proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()), allocator);
                proxy.AddMember("alter_id", x.AlterId, allocator);
                proxy.AddMember("security", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
                if (!x.GlobalPadding.is_undef())
                    proxy.AddMember("global_padding", x.GlobalPadding.get(), allocator);
                if (!x.AuthenticatedLength.is_undef())
                    proxy.AddMember("authenticated_length", x.AuthenticatedLength.get(), allocator);

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);
                break;
            }
            case ProxyType::VLESS: {
                addSingBoxCommonMembers(proxy, x, "vless", allocator);
                proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()), allocator);
                // 节点自身的 packet-encoding 优先；缺省时才用全局 xudp 开关。
                // 两者各写一次会产生重复的 packet_encoding 键（rapidjson 不去重）
                if (!x.PacketEncoding.empty())
                    proxy.AddMember("packet_encoding",
                                    rapidjson::StringRef(x.PacketEncoding.c_str()), allocator);
                else if (xudp && udp)
                    proxy.AddMember("packet_encoding", rapidjson::StringRef("xudp"), allocator);
                if (!x.Flow.empty())
                    proxy.AddMember("flow", rapidjson::StringRef(x.Flow.c_str()), allocator);
                if (!x.Encryption.empty() && x.Encryption != "none")
                    proxy.AddMember("encryption", rapidjson::StringRef(x.Encryption.c_str()), allocator);
                rapidjson::Value vlesstransport(rapidjson::kObjectType);
                rapidjson::Value vlessheaders(rapidjson::kObjectType);
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        break;
                    case "ws"_hash:
                        if (x.Path.empty())
                            vlesstransport.AddMember("path", "/", allocator);
                        else
                            vlesstransport.AddMember("path", rapidjson::StringRef(x.Path.c_str()), allocator);
                        if (!x.Host.empty())
                            vlessheaders.AddMember("Host", rapidjson::StringRef(x.Host.c_str()), allocator);
                        if (!x.Edge.empty())
                            vlessheaders.AddMember("Edge", rapidjson::StringRef(x.Edge.c_str()), allocator);
                        vlesstransport.AddMember("type", rapidjson::StringRef("ws"), allocator);
                        addHeaders(vlesstransport, x, allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    case "http"_hash:
                        vlesstransport.AddMember("type", rapidjson::StringRef("http"), allocator);
                        vlesstransport.AddMember("host", rapidjson::StringRef(x.Host.c_str()), allocator);
                        vlesstransport.AddMember("method", rapidjson::StringRef("GET"), allocator);
                        vlesstransport.AddMember("path", rapidjson::StringRef(x.Path.c_str()), allocator);
                        addHeaders(vlesstransport, x, allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    case "h2"_hash:
                        vlesstransport.AddMember("type", rapidjson::StringRef("httpupgrade"), allocator);
                        vlesstransport.AddMember("host", rapidjson::StringRef(x.Host.c_str()), allocator);
                        vlesstransport.AddMember("path", rapidjson::StringRef(x.Path.c_str()), allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    case "grpc"_hash:
                        vlesstransport.AddMember("type", rapidjson::StringRef("grpc"), allocator);
                        vlesstransport.AddMember("service_name", rapidjson::StringRef(x.GRPCServiceName.c_str()),
                                                 allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    default:
                        continue;
                }
                break;
            }
            case ProxyType::Trojan: {
                addSingBoxCommonMembers(proxy, x, "trojan", allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);
                break;
            }
            case ProxyType::WireGuard: {
                proxy.AddMember("type", "wireguard", allocator);
                proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
                proxy.AddMember("inet4_bind_address", rapidjson::StringRef(x.SelfIP.c_str()), allocator);
                rapidjson::Value addresses(rapidjson::kArrayType);
                addresses.PushBack(rapidjson::StringRef(x.SelfIP.append("/32").c_str()), allocator);
                //                if (!x.SelfIPv6.empty())
                //                    addresses.PushBack(rapidjson::StringRef(x.SelfIPv6.c_str()), allocator);
                proxy.AddMember("local_address", addresses, allocator);
                if (!x.SelfIPv6.empty())
                    proxy.AddMember("inet6_bind_address", rapidjson::StringRef(x.SelfIPv6.c_str()), allocator);
                proxy.AddMember("private_key", rapidjson::StringRef(x.PrivateKey.c_str()), allocator);
                rapidjson::Value peer(rapidjson::kObjectType);
                peer.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()), allocator);
                peer.AddMember("server_port", x.Port, allocator);
                peer.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                if (!x.PreSharedKey.empty())
                    peer.AddMember("pre_shared_key", rapidjson::StringRef(x.PreSharedKey.c_str()), allocator);

                if (!x.AllowedIPs.empty()) {
                    auto allowed_ips = stringArrayToJsonArray(x.AllowedIPs, ",", allocator);
                    peer.AddMember("allowed_ips", allowed_ips, allocator);
                }

                if (!x.ClientId.empty()) {
                    auto reserved = stringArrayToJsonArray(x.ClientId, ",", allocator);
                    peer.AddMember("reserved", reserved, allocator);
                }
                if (!x.Password.empty()) {
                    proxy.AddMember("pre_shared_key", rapidjson::StringRef(x.Password.c_str()), allocator);
                }
                rapidjson::Value peers(rapidjson::kArrayType);
                peers.PushBack(peer, allocator);
                proxy.AddMember("peers", peers, allocator);
                proxy.AddMember("mtu", x.Mtu, allocator);
                break;
            }
            case ProxyType::HTTP:
            case ProxyType::HTTPS: {
                addSingBoxCommonMembers(proxy, x, "http", allocator);
                proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                break;
            }
            case ProxyType::SOCKS5: {
                addSingBoxCommonMembers(proxy, x, "socks", allocator);
                proxy.AddMember("version", "5", allocator);
                proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                break;
            }
            case ProxyType::Hysteria: {
                addSingBoxCommonMembers(proxy, x, "hysteria", allocator);
                proxy.AddMember("auth_str", rapidjson::StringRef(x.Auth.c_str()), allocator);
                if (isNumeric(x.UpMbps)) {
                    proxy.AddMember("up_mbps", std::stoi(x.UpMbps), allocator);
                } else {
                    size_t pos = x.UpMbps.find(search);
                    if (pos != std::string::npos) {
                        x.UpMbps.replace(pos, search.length(), "");
                    }
                    proxy.AddMember("up_mbps", std::stoi(x.UpMbps), allocator);
                }
                if (isNumeric(x.DownMbps)) {
                    proxy.AddMember("down_mbps", std::stoi(x.DownMbps), allocator);
                } else {
                    size_t pos = x.DownMbps.find(search);
                    if (pos != std::string::npos) {
                        x.DownMbps.replace(pos, search.length(), "");
                    }
                    proxy.AddMember("down_mbps", std::stoi(x.DownMbps), allocator);
                }
                if (!x.TLSSecure) {
                    rapidjson::Value tls(rapidjson::kObjectType);
                    tls.AddMember("enabled", true, allocator);
                    if (!x.Alpn.empty()) {
                        auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
                        tls.AddMember("alpn", alpns, allocator);
                    }
                    if (!x.ServerName.empty()) {
                        tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
                    }
                    tls.AddMember("insecure", buildBooleanValue(scv), allocator);
                    proxy.AddMember("tls", tls, allocator);
                }
                if (!x.FakeType.empty() && x.FakeType != "none")
                    proxy.AddMember("network", rapidjson::StringRef(x.FakeType.c_str()), allocator);
                if (!x.OBFSParam.empty())
                    proxy.AddMember("obfs", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
                break;
            }
            case ProxyType::Hysteria2: {
                addSingBoxCommonMembers(proxy, x, "hysteria2", allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if (!x.TLSSecure) {
                    rapidjson::Value tls(rapidjson::kObjectType);
                    tls.AddMember("enabled", true, allocator);
                    if (!x.ServerName.empty())
                        tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
                    if (!x.Alpn.empty()) {
                        auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
                        tls.AddMember("alpn", alpns, allocator);
                    }
                    if (!x.PublicKey.empty()) {
                        tls.AddMember("certificate", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                    }
                    tls.AddMember("insecure", buildBooleanValue(scv), allocator);
                    proxy.AddMember("tls", tls, allocator);
                }
                if (!x.UpMbps.empty()) {
                    if (!isNumeric(x.UpMbps)) {
                        size_t pos = x.UpMbps.find(search);
                        if (pos != std::string::npos) {
                            x.UpMbps.replace(pos, search.length(), "");
                        }
                    }
                    proxy.AddMember("up_mbps", std::stoi(x.UpMbps), allocator);
                }
                if (!x.DownMbps.empty()) {
                    if (!isNumeric(x.DownMbps)) {
                        size_t pos = x.DownMbps.find(search);
                        if (pos != std::string::npos) {
                            x.DownMbps.replace(pos, search.length(), "");
                        }
                    }
                    proxy.AddMember("down_mbps", std::stoi(x.DownMbps), allocator);
                }
                if (!x.OBFSParam.empty()) {
                    rapidjson::Value obfs(rapidjson::kObjectType);
                    obfs.AddMember("type", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
                    if (!x.OBFSPassword.empty()) {
                        obfs.AddMember("password", rapidjson::StringRef(x.OBFSPassword.c_str()), allocator);
                    }
                    proxy.AddMember("obfs", obfs, allocator);
                }
                break;
            }
            case ProxyType::TUIC: {
                addSingBoxCommonMembers(proxy, x, "tuic", allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()), allocator);
                if (!x.TLSSecure && !x.Alpn.empty()) {
                    rapidjson::Value tls(rapidjson::kObjectType);
                    tls.AddMember("enabled", true, allocator);
                    if (!scv.is_undef()) {
                        tls.AddMember("insecure", buildBooleanValue(scv), allocator);
                    }
                    if (!x.ServerName.empty())
                        tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
                    if (!x.Alpn.empty()) {
                        auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
                        tls.AddMember("alpn", alpns, allocator);
                    }
                    if (!x.DisableSni.is_undef()) {
                        tls.AddMember("disable_sni", buildBooleanValue(x.DisableSni), allocator);
                    }
                    proxy.AddMember("tls", tls, allocator);
                }
                if (!x.CongestionControl.empty()) {
                    proxy.AddMember("congestion_control", rapidjson::StringRef(x.CongestionControl.c_str()),
                                    allocator);
                }
                if (!x.UdpRelayMode.empty()) {
                    proxy.AddMember("udp_relay_mode", rapidjson::StringRef(x.UdpRelayMode.c_str()), allocator);
                }
                if (!x.ReduceRtt.is_undef()) {
                    proxy.AddMember("zero_rtt_handshake", buildBooleanValue(x.ReduceRtt), allocator);
                }
                break;
            }
            case ProxyType::AnyTLS: {
                addSingBoxCommonMembers(proxy, x, "anytls", allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!scv.is_undef()) {
                    tls.AddMember("insecure", buildBooleanValue(scv), allocator);
                }
                if (!x.SNI.empty())
                    tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()), allocator);
                if (!x.AlpnList.empty()) {
                    auto alpns = vectorToJsonArray(x.AlpnList, allocator);
                    tls.AddMember("alpn", alpns, allocator);
                }
                if (!x.ClientFingerprint.empty()) {
                    rapidjson::Value utls(rapidjson::kObjectType);
                    utls.AddMember("enabled", true, allocator);
                    utls.AddMember("fingerprint", rapidjson::StringRef(x.ClientFingerprint.c_str()), allocator);
                    tls.AddMember("utls", utls, allocator);
                }
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            default:
                continue;
        }
        if (x.TLSSecure) {
            rapidjson::Value tls(rapidjson::kObjectType);
            tls.AddMember("enabled", true, allocator);
            if (!x.ServerName.empty())
                tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
            if (!x.AlpnList.empty()) {
                auto alpns = vectorToJsonArray(x.AlpnList, allocator);
                tls.AddMember("alpn", alpns, allocator);
            } else if (!x.Alpn.empty()) {
                auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
                tls.AddMember("alpn", alpns, allocator);
            }
            tls.AddMember("insecure", buildBooleanValue(scv), allocator);
            if (x.Type == ProxyType::VLESS || x.Type == ProxyType::Trojan) {
                rapidjson::Value reality(rapidjson::kObjectType);
                if (!x.PublicKey.empty() || !x.ShortId.empty()) {
                    rapidjson::Value utls(rapidjson::kObjectType);
                    utls.AddMember("enabled", true, allocator);
                    utls.AddMember("fingerprint", rapidjson::StringRef("chrome"), allocator);
                    tls.AddMember("utls", utls, allocator);
                    reality.AddMember("enabled", true, allocator);
                    if (!x.PublicKey.empty()) {
                        reality.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                    }
                    //                    auto shortIds = stringArrayToJsonArray(x.ShortId, ",", allocator);
                    if (!x.ShortId.empty()) {
                        reality.AddMember("short_id", rapidjson::StringRef(x.ShortId.c_str()), allocator);
                    } else {
                        reality.AddMember("short_id", rapidjson::StringRef(""), allocator);
                    }
                    tls.AddMember("reality", reality, allocator);
                }
            }
            proxy.AddMember("tls", tls, allocator);
        }
        if (!x.UnderlyingProxy.empty()) {
            proxy.AddMember("detour", rapidjson::Value(x.UnderlyingProxy.c_str(), allocator), allocator);
        }
        if (!udp.is_undef() && !udp) {
            proxy.AddMember("network", "tcp", allocator);
        }
        if (!tfo.is_undef()) {
            proxy.AddMember("tcp_fast_open", buildBooleanValue(tfo), allocator);
        }
        nodelist.push_back(x);
        remarks_list.emplace_back(x.Remark);
        outbounds.PushBack(proxy, allocator);
    }

    if (ext.nodelist) {
        json | AddMemberOrReplace("outbounds", outbounds, allocator);
        return;
    }

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string type;
        switch (x.Type) {
            case ProxyGroupType::Select: {
                type = "selector";
                break;
            }
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
            case ProxyGroupType::LoadBalance: {
                type = "urltest";
                break;
            }
            default:
                continue;
        }
        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        rapidjson::Value group(rapidjson::kObjectType);

        group.AddMember("type", rapidjson::Value(type.c_str(), allocator), allocator);
        group.AddMember("tag", rapidjson::Value(x.Name.c_str(), allocator), allocator);

        rapidjson::Value group_outbounds(rapidjson::kArrayType);
        for (const std::string &y: filtered_nodelist) {
            group_outbounds.PushBack(rapidjson::Value(y.c_str(), allocator), allocator);
        }
        group.AddMember("outbounds", group_outbounds, allocator);

        if (x.Type == ProxyGroupType::URLTest) {
            group.AddMember("url", rapidjson::Value(x.Url.c_str(), allocator), allocator);
            group.AddMember("interval", rapidjson::Value(formatSingBoxInterval(x.Interval).c_str(), allocator),
                            allocator);
            if (x.Tolerance > 0)
                group.AddMember("tolerance", x.Tolerance, allocator);
        }
        outbounds.PushBack(group, allocator);
    }

    if (global.singBoxAddClashModes) {
        auto global_group = rapidjson::Value(rapidjson::kObjectType);
        global_group.AddMember("type", "selector", allocator);
        global_group.AddMember("tag", "GLOBAL", allocator);
        global_group.AddMember("outbounds", rapidjson::Value(rapidjson::kArrayType), allocator);
        global_group["outbounds"].PushBack("DIRECT", allocator);
        for (auto &x: remarks_list) {
            global_group["outbounds"].PushBack(rapidjson::Value(x.c_str(), allocator), allocator);
        }
        outbounds.PushBack(global_group, allocator);
    }

    json | AddMemberOrReplace("outbounds", outbounds, allocator);
}

std::string proxyToSingBox(std::vector<Proxy> &nodes, const std::string &base_conf,
                           std::vector<RulesetContent> &ruleset_content_array,
                           const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document json;

    if (!ext.nodelist) {
        json.Parse(base_conf.data());
        if (json.HasParseError()) {
            writeLog(0, "sing-box base loader failed with error: " +
                        std::string(rapidjson::GetParseError_En(json.GetParseError())), LOG_LEVEL_ERROR);
            return "";
        }
    } else {
        json.SetObject();
    }

    proxyToSingBox(nodes, json, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist || !ext.enable_rule_generator)
        return json | SerializeObject();

    rulesetToSingBox(json, ruleset_content_array, ext.overwrite_original_rules);

    return json | SerializeObject();
}

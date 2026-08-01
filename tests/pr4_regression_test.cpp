#include <exception>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/binding.h"
#include "generator/config/subexport.h"
#include "generator/config/ruleconvert.h"
#include "generator/template/templates.h"
#include "parser/subparser.h"
#include "utils/base64/base64.h"
#include "utils/urlencode.h"

namespace {

void require(bool condition, const std::string &message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

Proxy parse_clash(const std::string &content) {
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected exactly one Clash node");
    return nodes.front();
}

Proxy parse_v2ray_conf(const std::string &content) {
    std::vector<Proxy> nodes;
    explodeConfContent(content, nodes);
    require(nodes.size() == 1, "expected exactly one V2Ray node");
    return nodes.front();
}

Proxy parse_singbox(const std::string &content) {
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected exactly one sing-box node");
    return nodes.front();
}

Proxy parse_link(const std::string &content) {
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected exactly one link node");
    return nodes.front();
}

void test_vmess_conf_reads_mixed_case_wssettings() {
    const std::string content = R"({
  "outbounds": [
    {
      "settings": {
        "vnext": [
          {
            "address": "example.com",
            "port": 443,
            "users": [
              {
                "id": "12345678-1234-1234-1234-123456789012",
                "alterId": 0,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "StreamSettings": {
        "network": "ws",
        "security": "tls",
        "WsSettings": {
          "path": "/socket",
          "headers": {
            "Host": "cdn.example.com"
          }
        }
      }
    }
  ]
})";

    const Proxy node = parse_v2ray_conf(content);
    require(node.Type == ProxyType::VMess, "expected VMess node");
    require(node.Path == "/socket", "expected mixed-case WsSettings path to be preserved");
    require(node.Host == "cdn.example.com", "expected mixed-case WsSettings host to be preserved");
}

void test_clash_ss_mux_pluginopts_do_not_duplicate() {
    const std::string content = R"(proxies:
  - name: ss-mux
    type: ss
    server: 1.2.3.4
    port: 443
    cipher: aes-128-gcm
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: ws
      host: cdn.example.com
      path: /ws
      tls: true
      mux: true
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::Shadowsocks, "expected Shadowsocks node");
    require(node.PluginOption == "mode=ws;tls;host=cdn.example.com;path=/ws;mux=4;",
            "expected stable v2ray-plugin mux serialization");
}

void test_clash_round_trip_preserves_dialer_proxy() {
    const std::string content = R"(proxies:
  - name: dialer-node
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: user
    password: pass
    dialer-proxy: DIRECT
)";

    Proxy node = parse_clash(content);
    require(node.Type == ProxyType::SOCKS5, "expected SOCKS5 node");
    require(node.UnderlyingProxy == "DIRECT", "expected dialer-proxy to be parsed into UnderlyingProxy");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("dialer-proxy: DIRECT") != std::string::npos,
            "expected dialer-proxy to be emitted for Mihomo/Clash.Meta");
}

void test_clash_vless_xhttp_export_preserves_transport() {
    std::vector<Proxy> nodes;
    explodeSub(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=reality&type=xhttp&host=cdn.example.com&path=%2Fxhttp&mode=auto"
        "&pbk=pubkey-123&sid=abcd1234&fp=chrome&sni=reality.example.com"
        "#xhttp-node",
        nodes);

    require(nodes.size() == 1, "expected one node");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("name: xhttp-node") != std::string::npos, "expected Clash export to keep the xhttp node");
    require(exported.find("network: xhttp") != std::string::npos, "expected Clash export to emit xhttp network");
    require(exported.find("xhttp-opts:") != std::string::npos, "expected Clash export to emit xhttp-opts");
    require(exported.find("path: /xhttp") != std::string::npos, "expected Clash export to emit xhttp path");
    require(exported.find("host: cdn.example.com") != std::string::npos, "expected Clash export to emit xhttp host");
    require(exported.find("mode: auto") != std::string::npos, "expected Clash export to emit xhttp mode");
}

void test_vless_xhttp_padding_link_mapping() {
    const Proxy legacy = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&path=%2Fxhttp&x_padding_bytes=100-500#legacy-padding");
    require(legacy.XhttpPaddingBytes == "100-500", "expected top-level x_padding_bytes to be mapped");

    const Proxy extra = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&path=%2Fxhttp"
        "&extra=%7B%22xPaddingBytes%22%3A%22200-600%22%7D#extra-padding");
    require(extra.XhttpPaddingBytes == "200-600", "expected extra.xPaddingBytes to be mapped");

    std::vector<Proxy> nodes{extra};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("x-padding-bytes: 200-600") != std::string::npos,
            "expected Clash export to emit mapped x-padding-bytes");
}

void test_clash_vless_xhttp_parse_preserves_transport() {
    const std::string content = R"(proxies:
  - name: xhttp-node
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    servername: reality.example.com
    client-fingerprint: chrome
    network: xhttp
    reality-opts:
      public-key: pubkey-123
      short-id: abcd1234
    xhttp-opts:
      host: cdn.example.com
      path: /xhttp
      mode: auto
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected Clash parser to keep xhttp network");
    require(node.Host == "cdn.example.com", "expected Clash parser to keep xhttp host");
    require(node.Path == "/xhttp", "expected Clash parser to keep xhttp path");
    require(node.XhttpMode == "auto", "expected Clash parser to keep xhttp mode");
    require(node.PublicKey == "pubkey-123", "expected Clash parser to keep reality public key");
    require(node.ShortId == "abcd1234", "expected Clash parser to keep reality short id");
    require(node.ServerName == "reality.example.com", "expected Clash parser to keep servername");
    require(node.ClientFingerprint == "chrome", "expected Clash parser to keep client fingerprint");
}

void test_clash_vless_ws_reality_preserves_transport_host() {
    const std::string content = R"(proxies:
  - name: ws-reality
    type: vless
    server: ws.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    servername: reality.example.com
    client-fingerprint: chrome
    network: ws
    reality-opts:
      public-key: pubkey-ws
      short-id: ws1234
    ws-opts:
      path: /ws-path
      headers:
        Host: ws-transport.example.com
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "ws", "expected ws network");
    require(node.Host == "ws-transport.example.com",
            "ws+reality: transport Host must come from ws-opts, not sni/servername");
    require(node.ServerName == "reality.example.com",
            "ws+reality: ServerName must come from servername field");
    require(node.Path == "/ws-path", "ws+reality: path must be preserved");
    require(node.PublicKey == "pubkey-ws", "ws+reality: reality public key must be preserved");
}

void test_clash_vless_h2_reality_preserves_transport_host() {
    const std::string content = R"(proxies:
  - name: h2-reality
    type: vless
    server: h2.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    servername: reality.example.com
    client-fingerprint: chrome
    network: h2
    reality-opts:
      public-key: pubkey-h2
      short-id: h21234
    h2-opts:
      path: /h2-path
      host:
        - h2-transport.example.com
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "h2", "expected h2 network");
    require(node.Host == "h2-transport.example.com",
            "h2+reality: transport Host must come from h2-opts, not sni/servername");
    require(node.ServerName == "reality.example.com",
            "h2+reality: ServerName must come from servername field");
    require(node.Path == "/h2-path", "h2+reality: path must be preserved");
    require(node.PublicKey == "pubkey-h2", "h2+reality: reality public key must be preserved");
}

void test_singbox_round_trip_preserves_detour_and_vless_encryption() {
    const std::string content = R"({
  "inbounds": [],
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-node",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012",
      "flow": "xtls-rprx-vision",
      "encryption": "zero",
      "packet_encoding": "xudp",
      "detour": "DIRECT",
      "tls": {
        "enabled": true,
        "server_name": "vless.example.com"
      },
      "transport": {
        "type": "ws",
        "path": "/vless",
        "headers": {
          "Host": "cdn.example.com"
        }
      }
    }
  ],
  "route": {}
})";

    Proxy node = parse_singbox(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.UnderlyingProxy == "DIRECT", "expected sing-box detour to be parsed into UnderlyingProxy");
    require(node.Encryption == "zero", "expected sing-box VLESS encryption to be preserved");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;

    const std::string exported = proxyToSingBox(nodes, "", rulesets, groups, ext);
    require(exported.find("\"detour\":\"DIRECT\"") != std::string::npos,
            "expected sing-box detour to be emitted");
    require(exported.find("\"encryption\":\"zero\"") != std::string::npos,
            "expected sing-box VLESS encryption to be emitted");
}

void test_vless_link_preserves_xhttp_transport() {
    const std::string content =
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=reality&type=xhttp&host=cdn.example.com&path=%2Fxhttp&mode=packet-up"
        "&extra=%7B%22scMaxEachPostBytes%22%3A1000000%7D"
        "#xhttp-node";

    const Proxy node = parse_link(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.Host == "cdn.example.com", "expected xhttp host");
    require(node.Path == "/xhttp", "expected xhttp path");
    require(node.XhttpMode == "packet-up", "expected xhttp mode");
    require(node.XhttpExtra == "{\"scMaxEachPostBytes\":1000000}", "expected xhttp extra");
}

void test_v2ray_vless_xhttp_conf_preserves_transport() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "xhttp.example.com",
            "port": 443,
            "users": [
              {
                "id": "12345678-1234-1234-1234-123456789012",
                "flow": "xtls-rprx-vision",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "publicKey": "pubkey-123",
          "shortId": "abcd1234",
          "fingerprint": "chrome",
          "serverName": "reality.example.com"
        },
        "xhttpSettings": {
          "host": "cdn.example.com",
          "path": "/xhttp",
          "mode": "stream-up",
          "extra": {
            "scMaxEachPostBytes": 1000000
          }
        }
      }
    }
  ]
})";

    const Proxy node = parse_v2ray_conf(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.Host == "cdn.example.com", "expected xhttp host");
    require(node.Path == "/xhttp", "expected xhttp path");
    require(node.XhttpMode == "stream-up", "expected xhttp mode");
    require(node.XhttpExtra == "{\"scMaxEachPostBytes\":1000000}", "expected xhttp extra");
    require(node.Flow == "xtls-rprx-vision", "expected v2ray VLESS flow to be preserved");
    require(node.Encryption == "none", "expected v2ray VLESS encryption to be preserved");
    require(node.PublicKey == "pubkey-123", "expected v2ray VLESS reality public key to be preserved");
    require(node.ShortId == "abcd1234", "expected v2ray VLESS reality short id to be preserved");
    require(node.ClientFingerprint == "chrome",
            "expected v2ray VLESS reality fingerprint to be preserved");
    require(node.ServerName == "reality.example.com", "expected v2ray VLESS reality server name to be preserved");
}

void test_v2ray_vless_tls_settings_preserve_sni_and_alpn() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "tls.example.com",
            "port": 443,
            "users": [
              {
                "id": "12345678-1234-1234-1234-123456789012"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "sni.example.com",
          "alpn": ["h2", "http/1.1"]
        },
        "xhttpSettings": {
          "host": "cdn.example.com",
          "path": "/tls-xhttp",
          "mode": "packet-up"
        }
      }
    }
  ]
})";

    const Proxy node = parse_v2ray_conf(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.ServerName == "sni.example.com", "expected tlsSettings server name to be preserved");
    require(node.AlpnList.size() == 2, "expected tlsSettings alpn list to be preserved");
    require(node.AlpnList[0] == "h2", "expected first ALPN entry to be preserved");
    require(node.AlpnList[1] == "http/1.1", "expected second ALPN entry to be preserved");
}

void test_vless_xhttp_round_trip_preserves_type() {
    std::vector<Proxy> nodes;
    explodeSub(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&host=cdn.example.com&path=%2Fxhttp&mode=packet-up#xhttp-node",
        nodes);

    require(nodes.size() == 1, "expected one node");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    // proxyToSingle returns a base64-encoded subscription — decode before inspecting
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    require(decoded.find("type=xhttp") != std::string::npos, "expected exported link to keep xhttp");
    require(decoded.find("mode=packet-up") != std::string::npos, "expected exported link to keep xhttp mode");
    require(decoded.find("host=cdn.example.com") != std::string::npos, "expected exported link to keep host");
    require(decoded.find("path=%2Fxhttp") != std::string::npos || decoded.find("path=/xhttp") != std::string::npos,
            "expected exported link to keep path");
}

void test_singbox_vless_xhttp_preserves_transport() {
    const std::string content = R"({
  "inbounds": [],
  "outbounds": [
    {
      "type": "vless",
      "tag": "xhttp-node",
      "server": "xhttp.example.com",
      "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012",
      "tls": {
        "enabled": true,
        "server_name": "xhttp.example.com"
      },
      "transport": {
        "type": "xhttp",
        "host": "cdn.example.com",
        "path": "/xhttp",
        "mode": "packet-up",
        "extra": {
          "scMaxEachPostBytes": 1000000
        }
      }
    }
  ],
  "route": {}
})";

    const Proxy node = parse_singbox(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.Host == "cdn.example.com", "expected xhttp host");
    require(node.Path == "/xhttp", "expected xhttp path");
    require(node.XhttpMode == "packet-up", "expected xhttp mode");
    require(node.XhttpExtra == "{\"scMaxEachPostBytes\":1000000}", "expected xhttp extra");
}

void test_clash_vless_xhttp_sc_max_and_reuse_settings() {
    const std::string content = R"(proxies:
  - name: xhttp-full
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      host: cdn.example.com
      path: /xhttp
      mode: packet-up
      sc-max-each-post-bytes: 2000000
      reuse-settings:
        max-connections: "16-32"
        max-concurrency: "0"
        c-max-reuse-times: "0"
        h-max-request-times: "600-900"
        h-max-reusable-secs: "1800-3000"
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.XhttpScMaxEachPostBytes == "2000000", "expected sc-max-each-post-bytes to be parsed");
    require(!node.XhttpReuseSettings.empty(), "expected reuse-settings to be parsed");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("sc-max-each-post-bytes: 2000000") != std::string::npos,
            "expected sc-max-each-post-bytes to be exported");
    require(exported.find("reuse-settings:") != std::string::npos,
            "expected reuse-settings to be exported");
    require(exported.find("max-connections: 16-32") != std::string::npos,
            "expected reuse-settings.max-connections to be exported");
    require(exported.find("h-max-reusable-secs: 1800-3000") != std::string::npos,
            "expected reuse-settings.h-max-reusable-secs to be exported");
}

void test_clash_vless_xhttp_extra_exported_to_link() {
    // Clash YAML with sc-max-each-post-bytes + reuse-settings → export to vless:// link
    const std::string content = R"(proxies:
  - name: xhttp-link
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      sc-max-each-post-bytes: 1500000
      reuse-settings:
        max-connections: "16-32"
        max-concurrency: "0"
        h-max-reusable-secs: "1800-3000"
)";

    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected one node");
    require(nodes[0].XhttpScMaxEachPostBytes == "1500000", "expected XhttpScMaxEachPostBytes to be set");
    require(!nodes[0].XhttpReuseSettings.empty(), "expected XhttpReuseSettings to be set");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    // proxyToSingle returns a base64-encoded subscription — decode before inspecting
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    require(decoded.find("extra=") != std::string::npos,
            "expected vless link to contain extra=");
    require(decoded.find("scMaxEachPostBytes") != std::string::npos,
            "expected extra to contain scMaxEachPostBytes");
    require(decoded.find("xmux") != std::string::npos,
            "expected extra to contain xmux for reuse-settings");
    require(decoded.find("maxConnections") != std::string::npos,
            "expected xmux to contain maxConnections");
}

void test_xray_download_settings_xmux_and_sc_max() {
    // Xray config with downloadSettings containing scMaxEachPostBytes and xmux
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "xhttp.example.com",
            "port": 443,
            "users": [{"id": "12345678-1234-1234-1234-123456789012", "encryption": "none"}]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "host": "cdn.example.com",
          "path": "/up",
          "mode": "packet-up",
          "downloadSettings": {
            "address": "dl.example.com",
            "port": 443,
            "security": "tls",
            "xhttpSettings": {
              "path": "/down",
              "scMaxEachPostBytes": 500000,
              "xmux": {
                "maxConnections": "16-32",
                "maxConcurrency": "0",
                "cMaxReuseTimes": "0",
                "hMaxRequestTimes": "600-900",
                "hMaxReusableSecs": "1800-3000",
                "hKeepAlivePeriod": 30
              }
            }
          }
        }
      }
    }
  ]
})";

    const Proxy node = parse_v2ray_conf(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(!node.XhttpDownload.empty(), "expected XhttpDownload to be set");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("download-settings:") != std::string::npos,
            "expected download-settings to be exported");
    require(exported.find("sc-max-each-post-bytes") == std::string::npos,
            "xray scMaxEachPostBytes must be dropped: mihomo download-settings has no such field");
    require(exported.find("reuse-settings:") != std::string::npos,
            "expected download-settings.reuse-settings from xray xmux");
    {
        const YAML::Node rs =
            YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"]["reuse-settings"];
        require(rs["max-connections"].as<std::string>() == "16-32",
                "expected reuse-settings.max-connections from xray xmux.maxConnections");
        require(rs["h-max-reusable-secs"].as<std::string>() == "1800-3000",
                "expected reuse-settings.h-max-reusable-secs from xray xmux.hMaxReusableSecs");
        require(rs["h-keep-alive-period"].as<std::string>() == "30",
                "expected reuse-settings.h-keep-alive-period from xray xmux.hKeepAlivePeriod");
    }
}

void test_clash_vless_xhttp_download_settings_full() {
    // mihomo 的 XHTTPDownloadSettings 没有 x-padding-bytes / sc-max-each-post-bytes /
    // no-grpc-header 字段，输入里带上它们必须被丢弃，不得出现在导出中
    const std::string content = R"(proxies:
  - name: xhttp-ds
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        server: dl.example.com
        port: 443
        tls: true
        servername: dl.example.com
        path: /down
        x-padding-bytes: "100-500"
        sc-max-each-post-bytes: 500000
        no-grpc-header: true
        skip-cert-verify: false
        reuse-settings:
          max-connections: "8"
          h-max-reusable-secs: "900"
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(!node.XhttpDownload.empty(), "expected download-settings to be parsed");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("download-settings:") != std::string::npos,
            "expected download-settings to be exported");
    require(exported.find("sc-max-each-post-bytes: 500000") == std::string::npos,
            "download-settings must not carry sc-max-each-post-bytes (not a mihomo field)");
    require(exported.find("x-padding-bytes: 100-500") == std::string::npos,
            "download-settings must not carry x-padding-bytes (not a mihomo field)");
    require(exported.find("no-grpc-header") == std::string::npos,
            "download-settings must not carry no-grpc-header (not a mihomo field)");
    require(exported.find("reuse-settings:") != std::string::npos,
            "expected download-settings.reuse-settings to be exported");
    require(YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"]
                ["reuse-settings"]["max-connections"].as<std::string>() == "8",
            "expected download-settings.reuse-settings.max-connections to be exported");
    require(exported.find("skip-cert-verify: 0") != std::string::npos ||
            exported.find("skip-cert-verify: false") != std::string::npos,
            "expected download-settings.skip-cert-verify to be exported");
}

// mihomo 文档 xhttp-opts 其余 16 个标量字段必须原样透传（clash → clash），
// 键名与 wiki.metacubex.one/config/proxies/transport/#xhttp-opts 逐一对应
void test_clash_xhttp_doc_scalar_fields_roundtrip() {
    const std::string content = R"(proxies:
  - name: xhttp-doc-fields
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      x-padding-obfs-mode: true
      x-padding-key: xp_key
      x-padding-header: X-Padding
      x-padding-placement: cookie
      x-padding-method: tokenish
      uplink-http-method: PUT
      session-placement: query
      session-key: sess
      session-table: Base62
      session-length: 16-32
      seq-placement: query
      seq-key: seq
      uplink-data-placement: header
      uplink-data-key: chunk
      uplink-chunk-size: 4096
      sc-min-posts-interval-ms: 25
)";

    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node opts = YAML::Load(exported)["proxies"][0]["xhttp-opts"];
    require(opts["x-padding-obfs-mode"].as<bool>(), "x-padding-obfs-mode must round-trip as bool");
    const std::pair<const char *, const char *> expected[] = {
        {"x-padding-key", "xp_key"},
        {"x-padding-header", "X-Padding"},
        {"x-padding-placement", "cookie"},
        {"x-padding-method", "tokenish"},
        {"uplink-http-method", "PUT"},
        {"session-placement", "query"},
        {"session-key", "sess"},
        {"session-table", "Base62"},
        {"session-length", "16-32"},
        {"seq-placement", "query"},
        {"seq-key", "seq"},
        {"uplink-data-placement", "header"},
        {"uplink-data-key", "chunk"},
        {"uplink-chunk-size", "4096"},
        {"sc-min-posts-interval-ms", "25"},
    };
    for (const auto &kv : expected)
        require(opts[kv.first].IsDefined() && opts[kv.first].as<std::string>() == kv.second,
                std::string("xhttp-opts.") + kv.first + " must round-trip");
}

// clash 输入的 16 个文档标量字段导出 vless:// 链接时必须映射进 extra=（Xray 驼峰键名）。
// 键名对照 Xray infra/conf/transport_method.go 的 SplitHTTPConfig；
// Int32Range 字段（sessionIDLength/uplinkChunkSize/scMinPostsIntervalMs）字符串形式即合法
void test_clash_xhttp_doc_fields_exported_to_link_extra() {
    const std::string content = R"(proxies:
  - name: xhttp-extra-out
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      x-padding-obfs-mode: true
      x-padding-key: xp_key
      x-padding-header: X-Padding
      x-padding-placement: cookie
      x-padding-method: tokenish
      uplink-http-method: PUT
      session-placement: query
      session-key: sess
      session-table: Base62
      session-length: 16-32
      seq-placement: query
      seq-key: seq
      uplink-data-placement: header
      uplink-data-key: chunk
      uplink-chunk-size: 4096
      sc-min-posts-interval-ms: 25
)";

    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected one node");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    const auto extraPos = decoded.find("extra=");
    require(extraPos != std::string::npos, "expected exported link to contain extra=");
    auto extraEnd = decoded.find_first_of("&#", extraPos);
    if (extraEnd == std::string::npos)
        extraEnd = decoded.size();
    const std::string extraJson = urlDecode(decoded.substr(extraPos + 6, extraEnd - extraPos - 6));

    const std::pair<const char *, const char *> expected[] = {
        {"\"xPaddingObfsMode\"", "true"},
        {"\"xPaddingKey\"", "\"xp_key\""},
        {"\"xPaddingHeader\"", "\"X-Padding\""},
        {"\"xPaddingPlacement\"", "\"cookie\""},
        {"\"xPaddingMethod\"", "\"tokenish\""},
        {"\"uplinkHTTPMethod\"", "\"PUT\""},
        {"\"sessionIDPlacement\"", "\"query\""},
        {"\"sessionIDKey\"", "\"sess\""},
        {"\"sessionIDTable\"", "\"Base62\""},
        {"\"sessionIDLength\"", "\"16-32\""},
        {"\"seqPlacement\"", "\"query\""},
        {"\"seqKey\"", "\"seq\""},
        {"\"uplinkDataPlacement\"", "\"header\""},
        {"\"uplinkDataKey\"", "\"chunk\""},
        // mihomo 的 parseXHTTPExtra 对这两个断言 .(float64)，字符串会被静默丢弃
        {"\"uplinkChunkSize\"", "4096"},
        {"\"scMinPostsIntervalMs\"", "25"},
    };
    for (const auto &kv : expected)
        require(extraJson.find(std::string(kv.first) + ":" + kv.second) != std::string::npos,
                std::string("extra must contain ") + kv.first + ":" + kv.second);
}

// x-padding-bytes 必须随 extra 出链接：顶层 x_padding_bytes 不是链接规范，
// mihomo 的 convert 只读 path/host/mode 三个顶层参数，且 xPaddingBytes 断言 .(string)。
// 数值型字段则要按形态定型——纯数字走数字，范围只能留字符串。
void test_clash_xhttp_padding_and_range_exported_to_link_extra() {
    const std::string content = R"(proxies:
  - name: xhttp-padding-out
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      x-padding-bytes: "100-500"
      sc-max-each-post-bytes: "1000000-2000000"
      uplink-chunk-size: "3072"
)";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected one node");
    require(nodes[0].XhttpPaddingBytes == "100-500", "x-padding-bytes must be parsed");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    require(decoded.find("extra=") != std::string::npos, "expected link to contain extra=");
    auto extraEnd = decoded.find_first_of("&#", decoded.find("extra="));
    if (extraEnd == std::string::npos)
        extraEnd = decoded.size();
    const std::string extraJson =
        urlDecode(decoded.substr(decoded.find("extra=") + 6, extraEnd - decoded.find("extra=") - 6));

    require(extraJson.find("\"xPaddingBytes\":\"100-500\"") != std::string::npos,
            "x-padding-bytes must reach extra as a string, got: " + extraJson);
    // 范围值留字符串（mihomo 收不了范围，但 Xray 的 Int32Range 能解析）
    require(extraJson.find("\"scMaxEachPostBytes\":\"1000000-2000000\"") != std::string::npos,
            "range sc-max-each-post-bytes must stay a string, got: " + extraJson);
    // 单值走数字，否则 mihomo 的 .(float64) 断言失败而丢弃
    require(extraJson.find("\"uplinkChunkSize\":3072") != std::string::npos,
            "single-value uplink-chunk-size must be numeric, got: " + extraJson);
    // 顶层参数不该出现，它不是链接规范
    require(decoded.find("x_padding_bytes=") == std::string::npos,
            "x_padding_bytes must not be emitted as a top-level param, got: " + decoded);
}

// 反方向：链接 extra 里的 Xray 驼峰字段要翻译成 clash 的 xhttp-opts 键
void test_vless_link_extra_doc_fields_mapped_to_clash() {
    // extra = {"xPaddingObfsMode":true,"sessionIDPlacement":"query","sessionIDLength":"16-32",
    //          "uplinkChunkSize":4096,"scMinPostsIntervalMs":25,"uplinkHTTPMethod":"PUT"}
    const std::string content =
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&path=%2Fxhttp&mode=packet-up"
        "&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22sessionIDPlacement%22%3A%22query%22%2C"
        "%22sessionIDLength%22%3A%2216-32%22%2C%22uplinkChunkSize%22%3A4096%2C"
        "%22scMinPostsIntervalMs%22%3A25%2C%22uplinkHTTPMethod%22%3A%22PUT%22%7D#extra-in";

    std::vector<Proxy> nodes{parse_link(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node opts = YAML::Load(exported)["proxies"][0]["xhttp-opts"];
    require(opts["x-padding-obfs-mode"].as<bool>(), "extra.xPaddingObfsMode must map to bool");
    require(opts["session-placement"].as<std::string>() == "query",
            "extra.sessionIDPlacement must map to session-placement");
    require(opts["session-length"].as<std::string>() == "16-32",
            "extra.sessionIDLength must map to session-length");
    require(opts["uplink-chunk-size"].as<std::string>() == "4096",
            "extra.uplinkChunkSize (int) must map to uplink-chunk-size");
    require(opts["sc-min-posts-interval-ms"].as<std::string>() == "25",
            "extra.scMinPostsIntervalMs (int) must map to sc-min-posts-interval-ms");
    require(opts["uplink-http-method"].as<std::string>() == "PUT",
            "extra.uplinkHTTPMethod must map to uplink-http-method");
}

// 主节点级 TLS 伪装层选项（mihomo VlessOption 均支持）clash → clash 透传
void test_clash_vless_tls_layer_opts_roundtrip() {
    const std::string content = R"(proxies:
  - name: vless-tls-opts
    type: vless
    server: t.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    name-cert-verify: cert.example.com
    ech-opts:
      enable: true
      config: ECHCONFIGBASE64
    shadow-tls-opts:
      password: stpw
      version: 3
    restls-opts:
      password: rpw
      version-hint: tls13
    jls-opts:
      password: jpw
      username: juser
)";

    std::vector<Proxy> nodes{parse_clash(content)};
    require(!nodes[0].MihomoTlsOpts.empty(), "TLS layer opts must be parsed into MihomoTlsOpts");
    require(nodes[0].MihomoTlsOpts.find("ech-opts") != std::string::npos,
            "ech-opts must be present in MihomoTlsOpts, got: " + nodes[0].MihomoTlsOpts);
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node p = YAML::Load(exported)["proxies"][0];
    require(p["name-cert-verify"].as<std::string>() == "cert.example.com",
            "name-cert-verify must round-trip");
    require(p["ech-opts"]["enable"].as<bool>(), "ech-opts.enable must stay boolean");
    require(p["ech-opts"]["config"].as<std::string>() == "ECHCONFIGBASE64",
            "ech-opts.config must round-trip");
    require(p["shadow-tls-opts"]["password"].as<std::string>() == "stpw",
            "shadow-tls-opts.password must round-trip");
    require(p["shadow-tls-opts"]["version"].as<int>() == 3,
            "shadow-tls-opts.version must stay numeric");
    require(p["restls-opts"]["version-hint"].as<std::string>() == "tls13",
            "restls-opts.version-hint must round-trip");
    require(p["jls-opts"]["password"].as<std::string>() == "jpw",
            "jls-opts.password must round-trip");
    require(p["jls-opts"]["username"].as<std::string>() == "juser",
            "jls-opts.username must round-trip");
}

// download-settings 的 proxy 部分同样要透传这五个 TLS 键
void test_clash_xhttp_download_settings_tls_layer_opts() {
    const std::string content = R"(proxies:
  - name: xhttp-ds-tls
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        server: dl.example.com
        port: 443
        tls: true
        name-cert-verify: dl-cert.example.com
        ech-opts:
          enable: true
          config: DLECH
        shadow-tls-opts:
          password: dl-stpw
        restls-opts:
          password: dl-rpw
        jls-opts:
          password: dl-jpw
)";

    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ds = YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"];
    require(ds["name-cert-verify"].as<std::string>() == "dl-cert.example.com",
            "download-settings.name-cert-verify must round-trip");
    require(ds["ech-opts"]["enable"].as<bool>(), "download-settings.ech-opts.enable must stay boolean");
    require(ds["ech-opts"]["config"].as<std::string>() == "DLECH",
            "download-settings.ech-opts.config must round-trip");
    require(ds["shadow-tls-opts"]["password"].as<std::string>() == "dl-stpw",
            "download-settings.shadow-tls-opts must round-trip");
    require(ds["restls-opts"]["password"].as<std::string>() == "dl-rpw",
            "download-settings.restls-opts must round-trip");
    require(ds["jls-opts"]["password"].as<std::string>() == "dl-jpw",
            "download-settings.jls-opts must round-trip");
}

// 顶层 ech/ech-config 是历史误写（mihomo 只认 ech-opts{enable,config}），
// 旧键输入要迁移导出为 ech-opts，且不再输出旧键；新键输入要能进 EchEnable/EchConfig
void test_clash_vless_ech_keys_unified_to_ech_opts() {
    const std::string legacy = R"(proxies:
  - name: ech-legacy
    type: vless
    server: e.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    ech: true
    ech-config: LEGACYECH
)";
    std::vector<Proxy> nodes{parse_clash(legacy)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node p = YAML::Load(exported)["proxies"][0];
    require(p["ech-opts"]["enable"].as<bool>(), "legacy ech must migrate to ech-opts.enable");
    require(p["ech-opts"]["config"].as<std::string>() == "LEGACYECH",
            "legacy ech-config must migrate to ech-opts.config");
    require(!p["ech"].IsDefined(), "top-level ech key must not be emitted (not a mihomo key)");
    require(!p["ech-config"].IsDefined(), "top-level ech-config key must not be emitted");

    const std::string modern = R"(proxies:
  - name: ech-modern
    type: vless
    server: e.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    ech-opts:
      enable: true
      config: MODERNECH
)";
    const Proxy n2 = parse_clash(modern);
    require(!n2.EchEnable.is_undef() && n2.EchEnable.get(),
            "ech-opts.enable must feed EchEnable");
    require(n2.EchConfig == "MODERNECH", "ech-opts.config must feed EchConfig");
}

// no-grpc-header ↔ extra.noGRPCHeader 双向映射
void test_xhttp_no_grpc_header_link_mapping() {
    const std::string clashIn = R"(proxies:
  - name: ngh-out
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: stream-up
      no-grpc-header: true
)";
    std::vector<Proxy> nodes;
    explodeSub(clashIn, nodes);
    require(nodes.size() == 1, "expected one node");
    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    require(decoded.find("extra=") != std::string::npos, "expected link to contain extra=");
    const std::string extraJson = urlDecode(decoded.substr(decoded.find("extra=") + 6));
    require(extraJson.find("\"noGRPCHeader\":true") != std::string::npos,
            "clash no-grpc-header must map to extra.noGRPCHeader");

    // 反方向：extra.noGRPCHeader → clash no-grpc-header
    const Proxy node = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&path=%2Fxhttp&mode=stream-up"
        "&extra=%7B%22noGRPCHeader%22%3Atrue%7D#ngh-in");
    require(!node.XhttpNoGrpcHeader.is_undef() && node.XhttpNoGrpcHeader.get(),
            "extra.noGRPCHeader must map to XhttpNoGrpcHeader");
}

// reuse-settings.h-keep-alive-period ↔ xmux.hKeepAlivePeriod 双向映射
// Xray XmuxConfig.HKeepAlivePeriod 是 int64（无字符串反序列化），extra 里必须是数值
void test_xhttp_h_keep_alive_period_xmux_mapping() {
    const std::string clashIn = R"(proxies:
  - name: hkap-out
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      reuse-settings:
        max-connections: "16"
        h-keep-alive-period: "30"
)";
    std::vector<Proxy> nodes;
    explodeSub(clashIn, nodes);
    require(nodes.size() == 1, "expected one node");
    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    const std::string extraJson = urlDecode(decoded.substr(decoded.find("extra=") + 6));
    require(extraJson.find("\"hKeepAlivePeriod\":30") != std::string::npos,
            "h-keep-alive-period must map to numeric xmux.hKeepAlivePeriod");
}

// 链接/Xray 输入 extra 里的 scMaxEachPostBytes 与 xmux 要翻译到 clash 顶层
// sc-max-each-post-bytes / reuse-settings（此前只在链接→链接时随 extra 原样保留）
void test_vless_link_extra_scmax_xmux_mapped_to_clash() {
    // extra = {"scMaxEachPostBytes":1500000,"xmux":{"maxConnections":"16-32","hKeepAlivePeriod":30}}
    const Proxy node = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&path=%2Fxhttp&mode=packet-up"
        "&extra=%7B%22scMaxEachPostBytes%22%3A1500000%2C%22xmux%22%3A%7B"
        "%22maxConnections%22%3A%2216-32%22%2C%22hKeepAlivePeriod%22%3A30%7D%7D#scmax-xmux-in");
    require(node.XhttpScMaxEachPostBytes == "1500000",
            "extra.scMaxEachPostBytes must feed XhttpScMaxEachPostBytes");
    require(!node.XhttpReuseSettings.empty(), "extra.xmux must feed XhttpReuseSettings");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node opts = YAML::Load(exported)["proxies"][0]["xhttp-opts"];
    require(opts["sc-max-each-post-bytes"].as<std::string>() == "1500000",
            "extra.scMaxEachPostBytes must reach clash sc-max-each-post-bytes");
    require(opts["reuse-settings"]["max-connections"].as<std::string>() == "16-32",
            "extra.xmux.maxConnections must reach clash reuse-settings");
    require(opts["reuse-settings"]["h-keep-alive-period"].as<std::string>() == "30",
            "extra.xmux.hKeepAlivePeriod must reach clash reuse-settings");
}

// 形似布尔/数字的字符串标量必须在两侧都守住类型：
// 输入侧按形状猜类型会把 "0123" 变成 123（丢前导零）、"true" 变成布尔；
// 输出侧 yaml-cpp 写字符串不加引号，裸标量被 mihomo 读回时同样变形。
// mihomo 的 decodeString 无 bool→string 分支，密码变布尔会让整个节点解析失败。
void test_clash_string_scalars_keep_string_type() {
    const std::string content = R"(proxies:
  - name: type-hazard
    type: vless
    server: t.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    shadow-tls-opts:
      password: "0123"
      version: 3
    jls-opts:
      username: "true"
      password: "0123456789"
    restls-opts:
      password: normalpass
    ech-opts:
      enable: true
      config: ECHBASE64
)";
    const Proxy node = parse_clash(content);
    // 输入侧：带引号的标量是明确的字符串意图，不得按形状改写
    require(node.MihomoTlsOpts.find("\"0123\"") != std::string::npos,
            "quoted 0123 must stay a JSON string, got: " + node.MihomoTlsOpts);
    require(node.MihomoTlsOpts.find("\"username\":\"true\"") != std::string::npos,
            "quoted true must stay a JSON string, got: " + node.MihomoTlsOpts);
    // 无引号的才按 YAML 语义定型
    require(node.MihomoTlsOpts.find("\"version\":3") != std::string::npos,
            "unquoted 3 must stay a JSON number, got: " + node.MihomoTlsOpts);
    require(node.MihomoTlsOpts.find("\"enable\":true") != std::string::npos,
            "unquoted true must stay a JSON bool, got: " + node.MihomoTlsOpts);

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);

    // 输出侧：往返后仍须是字符串。Tag 为 "?" 表示裸标量，会被 mihomo 读成数字/布尔
    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    const std::pair<std::string, std::string> mustStayString[] = {
        {"shadow-tls-opts|password", "0123"},
        {"jls-opts|username", "true"},
        {"jls-opts|password", "0123456789"},
    };
    for (const auto &c : mustStayString) {
        const auto bar = c.first.find('|');
        const YAML::Node v = rt[c.first.substr(0, bar)][c.first.substr(bar + 1)];
        require(v.as<std::string>() == c.second,
                c.first + " value must survive, got: " + v.as<std::string>());
        require(v.Tag() != "?",
                c.first + " must round-trip as an anchored string, not a bare scalar");
    }
    // 真布尔/真数字不得被引号化，否则 mihomo 的 decodeBool 无 string 分支会报错
    require(rt["ech-opts"]["enable"].Tag() == "?" && rt["ech-opts"]["enable"].as<bool>(),
            "ech-opts.enable must stay a plain YAML bool");
    require(rt["shadow-tls-opts"]["version"].Tag() == "?" &&
            rt["shadow-tls-opts"]["version"].as<int>() == 3,
            "shadow-tls-opts.version must stay a plain YAML int");
    // 无歧义的字符串不该被无谓锚定，避免输出到处是引号
    require(rt["restls-opts"]["password"].Tag() == "?" &&
            rt["restls-opts"]["password"].as<std::string>() == "normalpass",
            "unambiguous strings must stay plain");
    // 锚定标签是内部手段，不得泄漏到最终输出
    require(exported.find("!<str>") == std::string::npos,
            "internal !<str> tag must be beautified away, got:\n" + exported);
}

// flow 风格下被锚定值的边界是 ',' 与 '}' 而非换行，美化不得越界吞掉后续键。
// 这是 short-id 旧实现出过的 bug，换成通用机制后必须保持不回归。
void test_clash_string_anchor_beautify_in_flow_style() {
    const std::string content = R"(proxies:
  - name: flow-style
    type: vless
    server: t.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    reality-opts:
      public-key: pbk
      short-id: "11223344"
    jls-opts:
      password: "0123"
      username: after-anchor
)";
    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    ext.clash_proxies_style = "compact";
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);

    require(exported.find("!<str>") == std::string::npos,
            "flow style must not leak the internal tag, got:\n" + exported);
    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    require(rt["reality-opts"]["short-id"].as<std::string>() == "11223344",
            "short-id must survive beautification in flow style");
    require(rt["jls-opts"]["password"].as<std::string>() == "0123",
            "anchored value must survive beautification in flow style");
    // 被锚定值之后的键不得被吞掉
    require(rt["jls-opts"]["username"].as<std::string>() == "after-anchor",
            "key following an anchored value must not be swallowed");
}

// 敏感字段（密码类）走同一套锚定机制，纯数字密码不得被读成数字
void test_clash_password_numeric_keeps_string_type() {
    std::vector<Proxy> nodes;
    explodeSub("ss://YWVzLTEyOC1nY206MDEyMw@ss.example.com:443#numeric-pass", nodes);
    require(nodes.size() == 1, "expected one ss node");
    require(nodes[0].Password == "0123", "expected password 0123 from base64 userinfo");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    require(rt["password"].as<std::string>() == "0123", "numeric password value must survive");
    require(rt["password"].Tag() != "?",
            "numeric password must round-trip as an anchored string");
}

// global-padding / authenticated-length 是 VMess AEAD 的特性：mihomo 的 VmessOption
// 和 sing-box 的 VMessOutboundOptions 都有，VlessOption 与 sing-box VLESS 都没有，
// VLESS 协议本身也无此概念。此前这两个字段被错接在 VLESS 路径上，VMess 反而没有。
void test_clash_vmess_padding_and_auth_length_roundtrip() {
    const std::string content = R"(proxies:
  - name: vmess-aead
    type: vmess
    server: v.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    alterId: 0
    cipher: auto
    network: ws
    global-padding: true
    authenticated-length: true
)";
    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VMess, "expected VMess node");
    require(!node.GlobalPadding.is_undef() && node.GlobalPadding.get(),
            "vmess global-padding must be parsed");
    require(!node.AuthenticatedLength.is_undef() && node.AuthenticatedLength.get(),
            "vmess authenticated-length must be parsed");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    require(rt["global-padding"].as<bool>(), "vmess global-padding must be exported");
    require(rt["authenticated-length"].as<bool>(), "vmess authenticated-length must be exported");
}

// sing-box 的 VMess outbound 用 global_padding / authenticated_length 承载同一能力
void test_singbox_vmess_padding_and_auth_length() {
    const std::string content = R"({
  "inbounds": [],
  "outbounds": [
    {
      "type": "vmess",
      "tag": "vmess-aead",
      "server": "v.example.com",
      "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012",
      "alter_id": 0,
      "security": "auto",
      "global_padding": true,
      "authenticated_length": true
    }
  ],
  "route": {}
})";
    const Proxy node = parse_singbox(content);
    require(node.Type == ProxyType::VMess, "expected VMess node");
    require(!node.GlobalPadding.is_undef() && node.GlobalPadding.get(),
            "sing-box global_padding must be parsed");
    require(!node.AuthenticatedLength.is_undef() && node.AuthenticatedLength.get(),
            "sing-box authenticated_length must be parsed");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    const std::string exported = proxyToSingBox(nodes, "", rulesets, groups, ext);
    require(exported.find("\"global_padding\":true") != std::string::npos,
            "sing-box export must emit global_padding");
    require(exported.find("\"authenticated_length\":true") != std::string::npos,
            "sing-box export must emit authenticated_length");
}

// 反向：VLESS 节点不得再输出这两个键，mihomo 的 VlessOption 根本没有它们
void test_clash_vless_omits_vmess_only_fields() {
    const std::string content = R"(proxies:
  - name: vless-node
    type: vless
    server: v.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    global-padding: true
    authenticated-length: true
)";
    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("global-padding") == std::string::npos,
            "VLESS must not emit global-padding (not a VlessOption field), got:\n" + exported);
    require(exported.find("authenticated-length") == std::string::npos,
            "VLESS must not emit authenticated-length (not a VlessOption field), got:\n" + exported);
}

// mihomo 的 VlessOption/VmessOption/TrojanOption 都有 fingerprint（服务器证书 pinning）、
// certificate + private-key（mTLS 客户端证书），语义与 client-fingerprint（uTLS）互不相同。
// component/ca/fingerprint.go 会拒绝把浏览器名填进 fingerprint，反之 SHA256 填进
// client-fingerprint 也会让 uTLS 拿到无效指纹名，两个方向都不能串。
void test_clash_tls_cert_fields_roundtrip_all_protocols() {
    const std::string sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string tmpl = R"(proxies:
  - name: cert-node
    type: %TYPE%
    server: c.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    password: secret
    alterId: 0
    cipher: auto
    tls: true
    network: tcp
    client-fingerprint: chrome
    fingerprint: %FP%
    certificate: |
      -----BEGIN CERTIFICATE-----
      MIIB
      -----END CERTIFICATE-----
    private-key: |
      -----BEGIN PRIVATE KEY-----
      MIIE
      -----END PRIVATE KEY-----
)";
    for (const char *type : {"vless", "vmess", "trojan"}) {
        std::string content = tmpl;
        content.replace(content.find("%TYPE%"), 6, type);
        content.replace(content.find("%FP%"), 4, sha256);

        const Proxy node = parse_clash(content);
        require(node.CertFingerprint == sha256,
                std::string(type) + ": fingerprint must be parsed as a cert fingerprint");
        require(node.Certificate.find("BEGIN CERTIFICATE") != std::string::npos,
                std::string(type) + ": certificate must be parsed");
        require(node.PrivateKeyPem.find("BEGIN PRIVATE KEY") != std::string::npos,
                std::string(type) + ": private-key must be parsed into PrivateKeyPem");

        std::vector<Proxy> nodes{node};
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.nodelist = true;
        ext.clash_new_field_name = true;
        const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
        const YAML::Node rt = YAML::Load(exported)["proxies"][0];

        require(rt["fingerprint"].as<std::string>() == sha256,
                std::string(type) + ": fingerprint must be exported under its own key");
        require(rt["certificate"].as<std::string>().find("BEGIN CERTIFICATE") != std::string::npos,
                std::string(type) + ": certificate must be exported");
        require(rt["private-key"].as<std::string>().find("BEGIN PRIVATE KEY") != std::string::npos,
                std::string(type) + ": private-key must be exported");
        // 证书指纹绝不能跑进 uTLS 指纹字段
        require(rt["client-fingerprint"].as<std::string>() == "chrome",
                std::string(type) + ": client-fingerprint must stay the browser fingerprint");
    }
}

// 回归：链接的 fp= 是浏览器指纹，不得因新增证书指纹字段而泄漏到 fingerprint 键
// （mihomo 的 NewFingerprintVerifier 遇到浏览器名会直接报错拒绝节点）
void test_vless_link_browser_fingerprint_not_leaked_as_cert_fingerprint() {
    std::vector<Proxy> nodes;
    explodeSub(
        "vless://12345678-1234-1234-1234-123456789012@e.example.com:443"
        "?security=tls&type=tcp&fp=chrome&sni=e.example.com#fp-node",
        nodes);
    require(nodes.size() == 1, "expected one node");
    require(nodes[0].CertFingerprint.empty(),
            "link fp= must not be treated as a cert fingerprint");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    require(rt["client-fingerprint"].as<std::string>() == "chrome",
            "link fp= must still land in client-fingerprint");
    require(!rt["fingerprint"].IsDefined(),
            "browser fingerprint must never be emitted as the cert-pinning fingerprint");
}

// mihomo 的 RealityOptions 有三个字段，support-x25519mlkem768 此前被漏掉。
// 它控制 ClientHello 是否保留 X25519MLKEM768 密钥共享组（component/tls/reality.go:58
// 在其为 false 时调 BuildRemovedX25519MLKEM768HandshakeState 移除），丢失会静默
// 关掉后量子密钥交换。Xray 与 sing-box 都无对应字段，故只做 clash 双向。
void test_clash_reality_support_x25519mlkem768_roundtrip() {
    const std::string tmpl = R"(proxies:
  - name: reality-pq
    type: %TYPE%
    server: r.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    password: secret
    tls: true
    network: tcp
    client-fingerprint: chrome
    reality-opts:
      public-key: pbk-value
      short-id: aabbccdd
      support-x25519mlkem768: true
)";
    for (const char *type : {"vless", "trojan"}) {
        std::string content = tmpl;
        content.replace(content.find("%TYPE%"), 6, type);

        const Proxy node = parse_clash(content);
        require(!node.SupportX25519MLKEM768.is_undef() && node.SupportX25519MLKEM768.get(),
                std::string(type) + ": support-x25519mlkem768 must be parsed");

        std::vector<Proxy> nodes{node};
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.nodelist = true;
        ext.clash_new_field_name = true;
        const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
        const YAML::Node ro = YAML::Load(exported)["proxies"][0]["reality-opts"];
        require(ro["support-x25519mlkem768"].as<bool>(),
                std::string(type) + ": support-x25519mlkem768 must be exported");
        require(ro["public-key"].as<std::string>() == "pbk-value",
                std::string(type) + ": public-key must still survive");
    }
}

// 未配置时不得凭空写出 false，否则等于替用户做了决定
void test_clash_reality_omits_unset_x25519mlkem768() {
    const std::string content = R"(proxies:
  - name: reality-plain
    type: vless
    server: r.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    reality-opts:
      public-key: pbk-value
      short-id: aabbccdd
)";
    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("support-x25519mlkem768") == std::string::npos,
            "unset support-x25519mlkem768 must not be emitted, got:\n" + exported);
}

// download-settings 的 reality-opts 同样承载这个字段
void test_clash_download_settings_x25519mlkem768() {
    const std::string content = R"(proxies:
  - name: xhttp-ds-pq
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        server: dl.example.com
        port: 443
        tls: true
        reality-opts:
          public-key: dl-pbk
          short-id: 11aa22bb
          support-x25519mlkem768: true
)";
    const Proxy node = parse_clash(content);
    require(node.XhttpDownload.find("support-x25519mlkem768") != std::string::npos,
            "download-settings support-x25519mlkem768 must be parsed, got: " + node.XhttpDownload);

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ro =
        YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"]["reality-opts"];
    require(ro["support-x25519mlkem768"].as<bool>(),
            "download-settings support-x25519mlkem768 must be exported");
    require(ro["public-key"].as<std::string>() == "dl-pbk",
            "download-settings public-key must still survive");
}

// mihomo 的 BasicOption 被所有出站协议嵌入，其中 mptcp / interface-name /
// routing-mark 此前全项目零处理。放在公共位置处理，故用多个协议验证覆盖面。
void test_clash_basic_option_dialer_fields_roundtrip() {
    const std::string tmpl = R"(proxies:
  - name: dialer-opts
    type: %TYPE%
    server: d.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    password: secret
    cipher: aes-128-gcm
    alterId: 0
    mptcp: true
    interface-name: eth0
    routing-mark: 1234
)";
    for (const char *type : {"vless", "vmess", "trojan", "ss"}) {
        std::string content = tmpl;
        content.replace(content.find("%TYPE%"), 6, type);

        const Proxy node = parse_clash(content);
        require(!node.MPTCP.is_undef() && node.MPTCP.get(),
                std::string(type) + ": mptcp must be parsed");
        require(node.InterfaceName == "eth0",
                std::string(type) + ": interface-name must be parsed");
        require(node.RoutingMark == 1234,
                std::string(type) + ": routing-mark must be parsed");

        std::vector<Proxy> nodes{node};
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.nodelist = true;
        ext.clash_new_field_name = true;
        const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
        const YAML::Node rt = YAML::Load(exported)["proxies"][0];
        require(rt["mptcp"].as<bool>(), std::string(type) + ": mptcp must be exported");
        require(rt["interface-name"].as<std::string>() == "eth0",
                std::string(type) + ": interface-name must be exported");
        require(rt["routing-mark"].as<int>() == 1234,
                std::string(type) + ": routing-mark must be exported");
    }
}

// 未配置时不得凭空写出 mptcp: false / routing-mark: 0
void test_clash_basic_option_omits_unset_dialer_fields() {
    const std::string content = R"(proxies:
  - name: plain
    type: vless
    server: d.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
)";
    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("mptcp") == std::string::npos,
            "unset mptcp must not be emitted, got:\n" + exported);
    require(exported.find("interface-name") == std::string::npos,
            "unset interface-name must not be emitted, got:\n" + exported);
    require(exported.find("routing-mark") == std::string::npos,
            "unset routing-mark must not be emitted, got:\n" + exported);
}

// sing-box 侧对应 bind_interface / routing_mark / tcp_multi_path
void test_singbox_dialer_fields_roundtrip() {
    const std::string content = R"({
  "inbounds": [],
  "outbounds": [
    {
      "type": "vless",
      "tag": "dialer-sb",
      "server": "d.example.com",
      "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012",
      "bind_interface": "eth0",
      "routing_mark": 1234,
      "tcp_multi_path": true
    }
  ],
  "route": {}
})";
    const Proxy node = parse_singbox(content);
    require(node.InterfaceName == "eth0", "sing-box bind_interface must be parsed");
    require(node.RoutingMark == 1234, "sing-box routing_mark must be parsed");
    require(!node.MPTCP.is_undef() && node.MPTCP.get(), "sing-box tcp_multi_path must be parsed");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    const std::string exported = proxyToSingBox(nodes, "", rulesets, groups, ext);
    require(exported.find("\"bind_interface\":\"eth0\"") != std::string::npos,
            "sing-box export must emit bind_interface");
    require(exported.find("\"routing_mark\":1234") != std::string::npos,
            "sing-box export must emit routing_mark");
    require(exported.find("\"tcp_multi_path\":true") != std::string::npos,
            "sing-box export must emit tcp_multi_path");
}

// AnyTLS 此前把 client-fingerprint 存进 Proxy.Fingerprint，而该字段的另外两条
// 导出路径把它当证书指纹用：Surge 会输出 server-cert-fingerprint-sha256=chrome。
// mihomo 的 AnyTLSOption 本就有 ClientFingerprint 与 Fingerprint 两个独立字段，
// 两种语义必须在解析阶段就分开存放。
void test_anytls_fingerprint_semantics_separated() {
    const std::string sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string content = R"(proxies:
  - name: anytls-fp
    type: anytls
    server: a.example.com
    port: 443
    password: secret
    sni: a.example.com
    client-fingerprint: firefox
    fingerprint: )" + sha256 + "\n";

    const Proxy node = parse_clash(content);
    require(node.ClientFingerprint == "firefox",
            "anytls client-fingerprint must land in ClientFingerprint, got: " + node.ClientFingerprint);
    require(node.CertFingerprint == sha256,
            "anytls fingerprint must land in CertFingerprint, got: " + node.CertFingerprint);

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    require(rt["client-fingerprint"].as<std::string>() == "firefox",
            "anytls client-fingerprint must round-trip");
    require(rt["fingerprint"].as<std::string>() == sha256,
            "anytls cert fingerprint must round-trip under its own key");

    // Surge 的 server-cert-fingerprint-sha256 必须来自证书指纹，不能是浏览器名
    const std::string surge = proxyToSurge(nodes, "", rulesets, groups, 4, ext);
    require(surge.find("server-cert-fingerprint-sha256=chrome") == std::string::npos &&
            surge.find("server-cert-fingerprint-sha256=firefox") == std::string::npos,
            "Surge must never emit a browser fingerprint as a cert fingerprint, got:\n" + surge);
    require(surge.find(sha256) != std::string::npos,
            "Surge must emit the real cert fingerprint, got:\n" + surge);

    // sing-box 的 utls.fingerprint 是浏览器指纹，不能拿证书指纹去填
    const std::string sb = proxyToSingBox(nodes, "", rulesets, groups, ext);
    require(sb.find("\"fingerprint\":\"firefox\"") != std::string::npos,
            "sing-box utls.fingerprint must be the browser fingerprint, got:\n" + sb);
    require(sb.find(sha256) == std::string::npos,
            "sing-box must not put the cert fingerprint into utls, got:\n" + sb);
}

// anytls 链接里 fp= 是浏览器指纹，hpkp= 是证书 pinning，两者不能落进同一个字段
void test_anytls_link_fp_and_hpkp_separated() {
    const std::string sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const Proxy byFp = parse_link(
        "anytls://secret@a.example.com:443?sni=a.example.com&fp=chrome#anytls-fp");
    require(byFp.ClientFingerprint == "chrome",
            "anytls link fp= must be a browser fingerprint, got: " + byFp.ClientFingerprint);
    require(byFp.CertFingerprint.empty(),
            "anytls link fp= must not be treated as a cert fingerprint");

    const Proxy byHpkp = parse_link(
        "anytls://secret@a.example.com:443?sni=a.example.com&hpkp=" + sha256 + "#anytls-hpkp");
    require(byHpkp.CertFingerprint == sha256,
            "anytls link hpkp= must be a cert fingerprint, got: " + byHpkp.CertFingerprint);
    require(byHpkp.ClientFingerprint.empty(),
            "anytls link hpkp= must not be treated as a browser fingerprint");
}

// vless/trojan 的 construct 曾把浏览器指纹同时写进 Fingerprint 与 ClientFingerprint，
// 链接导出的 fp= 取的是前者。清理后 Fingerprint 不再承载客户端指纹，链接导出必须
// 改取 ClientFingerprint——本测试锁定清理前后行为一致。
void test_vless_trojan_link_fp_uses_client_fingerprint() {
    struct { const char *link; const char *name; } cases[] = {
        {"vless://12345678-1234-1234-1234-123456789012@e.example.com:443"
         "?security=tls&type=tcp&fp=chrome&sni=e.example.com#vless-fp", "vless"},
        {"trojan://pass@e.example.com:443?security=tls&type=tcp&fp=firefox&sni=e.example.com#trojan-fp",
         "trojan"},
    };
    for (const auto &c : cases) {
        std::vector<Proxy> nodes;
        explodeSub(c.link, nodes);
        require(nodes.size() == 1, std::string(c.name) + ": expected one node");
        require(nodes[0].ClientFingerprint == (std::string(c.name) == "vless" ? "chrome" : "firefox"),
                std::string(c.name) + ": link fp= must land in ClientFingerprint");
        // 浏览器指纹不属于证书指纹，绝不能落进 CertFingerprint
        require(nodes[0].CertFingerprint.empty(),
                std::string(c.name) + ": link fp= must not become a cert fingerprint");

        extra_settings ext;
        constexpr int kVlessMask = 32, kTrojanMask = 8;
        const std::string decoded = urlSafeBase64Decode(
            proxyToSingle(nodes, std::string(c.name) == "vless" ? kVlessMask : kTrojanMask, ext));
        const std::string want =
            std::string("fp=") + (std::string(c.name) == "vless" ? "chrome" : "firefox");
        require(decoded.find(want) != std::string::npos,
                std::string(c.name) + ": exported link must keep " + want + ", got: " + decoded);
    }
}

// Hysteria 系的 fingerprint 是服务器证书指纹（clash 的 fingerprint 键、
// Surge 的 server-cert-fingerprint-sha256）。此前无测试覆盖，先锁定行为，
// 以便把它从 Fingerprint 字段迁往 CertFingerprint 时能确认无行为变化。
void test_hysteria_cert_fingerprint_roundtrip() {
    const std::string sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string hy = R"(proxies:
  - name: hy-node
    type: hysteria
    server: h.example.com
    port: 443
    auth-str: authpass
    up: "100 Mbps"
    down: "100 Mbps"
    sni: h.example.com
    fingerprint: )" + sha256 + "\n";
    const std::string hy2 = R"(proxies:
  - name: hy2-node
    type: hysteria2
    server: h.example.com
    port: 443
    password: pass
    sni: h.example.com
    fingerprint: )" + sha256 + "\n";

    for (const auto &content : {hy, hy2}) {
        const Proxy node = parse_clash(content);
        std::vector<Proxy> nodes{node};
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.nodelist = true;
        ext.clash_new_field_name = true;
        const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
        const YAML::Node rt = YAML::Load(exported)["proxies"][0];
        require(rt["fingerprint"].as<std::string>() == sha256,
                "hysteria cert fingerprint must round-trip, got:\n" + exported);
    }

    // Hysteria2 的 Surge 导出走 server-cert-fingerprint-sha256
    std::vector<Proxy> nodes{parse_clash(hy2)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    const std::string surge = proxyToSurge(nodes, "", rulesets, groups, 4, ext);
    require(surge.find("server-cert-fingerprint-sha256=" + sha256) != std::string::npos,
            "hysteria2 Surge export must keep the cert fingerprint, got:\n" + surge);
}

// type 缺省或未知都不该丢弃整个节点：mihomo 的 convert/v.go 明确
// `if network == "" { network = "tcp" }`，其运行时对未知 network 也是
// `default: // default tcp network`。丢节点会让用户静默少节点且无从排查。
void test_vless_link_missing_or_unknown_type_falls_back_to_tcp() {
    struct { const char *link; const char *what; } cases[] = {
        {"vless://12345678-1234-1234-1234-123456789012@e.example.com:443"
         "?security=tls&sni=e.example.com#no-type", "missing type"},
        {"vless://12345678-1234-1234-1234-123456789012@e.example.com:443"
         "?security=tls&type=futuretransport&sni=e.example.com#unknown-type", "unknown type"},
    };
    for (const auto &c : cases) {
        std::vector<Proxy> nodes;
        explodeSub(c.link, nodes);
        require(nodes.size() == 1,
                std::string(c.what) + ": node must not be dropped");
        require(nodes[0].Type == ProxyType::VLESS,
                std::string(c.what) + ": expected a VLESS node");
        require(nodes[0].TransferProtocol == "tcp",
                std::string(c.what) + ": must fall back to tcp, got: " + nodes[0].TransferProtocol);
    }
}

// Clash 侧同理：未知 network 既不该在解析时丢，也不该在导出时被静默跳过
void test_clash_unknown_network_falls_back_instead_of_dropping() {
    const std::string content = R"(proxies:
  - name: future-net
    type: vless
    server: e.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: futuretransport
)";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "clash parser must not drop unknown network");
    require(nodes[0].TransferProtocol == "tcp",
            "unknown network must fall back to tcp, got: " + nodes[0].TransferProtocol);

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("name: future-net") != std::string::npos,
            "exporter must not silently skip the node, got:\n" + exported);
    require(exported.find("network: futuretransport") == std::string::npos,
            "invalid network value must not be emitted, got:\n" + exported);
}

// xudp 全局开关与节点自身的 packet-encoding 是两个独立来源，此前各自
// AddMember，rapidjson 不去重，会输出两个同名的 packet_encoding 键
void test_singbox_packet_encoding_not_duplicated() {
    std::vector<Proxy> nodes;
    explodeSub("vless://12345678-1234-1234-1234-123456789012@e.example.com:443"
               "?security=tls&type=tcp&packet-encoding=packetaddr&sni=e.example.com#pe",
               nodes);
    require(nodes.size() == 1, "expected one node");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.udp = true;
    ext.xudp = true;   // 与节点的 packet-encoding 同时成立
    const std::string exported = proxyToSingBox(nodes, "", rulesets, groups, ext);
    const auto first = exported.find("packet_encoding");
    require(first != std::string::npos, "expected packet_encoding in output");
    require(exported.find("packet_encoding", first + 1) == std::string::npos,
            "packet_encoding must appear exactly once, got:\n" + exported);
}

// Clash 输入的 xhttp-opts.headers 与 download-settings 此前都进不了链接
void test_clash_xhttp_headers_and_download_exported_to_link() {
    const std::string content = R"(proxies:
  - name: xhttp-full
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      mode: packet-up
      headers:
        X-Forwarded-For: 1.2.3.4
      download-settings:
        server: dl.example.com
        port: 8443
        path: /down
)";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected one node");
    require(!nodes[0].XhttpHeaders.empty(), "headers must be parsed");
    require(!nodes[0].XhttpDownload.empty(), "download-settings must be parsed");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    const std::string extraJson = urlDecode(decoded.substr(decoded.find("extra=") + 6));
    require(extraJson.find("X-Forwarded-For") != std::string::npos,
            "xhttp-opts.headers must reach the link extra, got: " + extraJson);
    // Clash 侧的 download-settings 不再进链接（无法无损表达），headers 不受影响
    require(extraJson.find("\"downloadSettings\"") == std::string::npos,
            "clash-side download-settings must not be synthesised, got: " + extraJson);
}

// Xray 允许把 xhttp 参数直接写在 xhttpSettings 下而不套 extra，
// 此前只读 host/path/mode/extra/downloadSettings，其余全部丢弃
void test_xray_xhttp_settings_direct_fields_parsed() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {"serverName": "x.example.com", "allowInsecure": true},
        "xhttpSettings": {
          "path": "/up",
          "xPaddingBytes": "100-500",
          "noGRPCHeader": true,
          "scMaxEachPostBytes": 500000,
          "xmux": {"maxConnections": "8"}
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    require(node.XhttpPaddingBytes == "100-500",
            "xhttpSettings.xPaddingBytes must be parsed, got: " + node.XhttpPaddingBytes);
    require(!node.XhttpNoGrpcHeader.is_undef() && node.XhttpNoGrpcHeader.get(),
            "xhttpSettings.noGRPCHeader must be parsed");
    require(node.XhttpScMaxEachPostBytes == "500000",
            "xhttpSettings.scMaxEachPostBytes must be parsed, got: " + node.XhttpScMaxEachPostBytes);
    require(node.XhttpReuseSettings.find("max-connections") != std::string::npos,
            "xhttpSettings.xmux must be parsed, got: " + node.XhttpReuseSettings);
    require(!node.AllowInsecure.is_undef() && node.AllowInsecure.get(),
            "tlsSettings.allowInsecure must map to skip-cert-verify");
}

// mihomo 的 parseXHTTPExtra 接受 sessionPlacement / sessionKey 作为旧别名
void test_vless_link_extra_legacy_session_aliases() {
    const Proxy node = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@x.example.com:443"
        "?security=tls&type=xhttp&path=%2Fx"
        "&extra=%7B%22sessionPlacement%22%3A%22query%22%2C%22sessionKey%22%3A%22sk%22%7D#legacy");
    require(node.XhttpClashOpts.find("\"session-placement\":\"query\"") != std::string::npos,
            "legacy sessionPlacement must map, got: " + node.XhttpClashOpts);
    require(node.XhttpClashOpts.find("\"session-key\":\"sk\"") != std::string::npos,
            "legacy sessionKey must map, got: " + node.XhttpClashOpts);
}

// download-settings 的 tlsSettings.allowInsecure 同样要映射
void test_xray_download_settings_allow_insecure() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": "tls",
            "tlsSettings": {"serverName": "dl.example.com", "allowInsecure": true},
            "xhttpSettings": {"path": "/down"}
          }
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    require(node.XhttpDownload.find("skip-cert-verify") != std::string::npos,
            "download-settings allowInsecure must map, got: " + node.XhttpDownload);
}

// mihomo 的 XHTTPDownloadSettings 全部用指针类型，缺失表示"沿用上游"，
// 显式值（含 false 与空串）表示"覆盖上游"。项目此前用空串表示"没有"，
// 无法区分二者：security: none 不写 tls，显式 path: "" 也被当成未配置。
void test_xray_download_settings_explicit_values_preserved() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": "none",
            "xhttpSettings": {"path": "/down"}
          }
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    // security: none 是显式的"下行不加密"，必须落成 tls: false 而非缺失
    require(node.XhttpDownload.find("\"tls\":false") != std::string::npos,
            "security: none must become an explicit tls:false, got: " + node.XhttpDownload);

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ds = YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"];
    require(ds["tls"].IsDefined() && !ds["tls"].as<bool>(),
            "explicit tls:false must survive to clash, got:\n" + exported);
}

// Clash 侧显式写空的值同样是"覆盖上游为空"，不能退化成缺失
void test_clash_download_settings_explicit_empty_preserved() {
    const std::string content = R"(proxies:
  - name: ds-empty
    type: vless
    server: x.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      host: upstream.example.com
      download-settings:
        server: dl.example.com
        host: ""
)";
    const Proxy node = parse_clash(content);
    require(node.XhttpDownload.find("\"host\":\"\"") != std::string::npos,
            "explicit empty host must be preserved, got: " + node.XhttpDownload);

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ds = YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"];
    require(ds["host"].IsDefined() && ds["host"].as<std::string>().empty(),
            "explicit empty host must not degrade into inheriting upstream, got:\n" + exported);
}

// Xray 的 SplitHTTPConfig.Build()：extra 存在时把它整个反序列化成新配置，
// 只把外层 host/path/mode 覆盖回去，其余外层直写字段一律忽略。
// 逐键合并会让本该被忽略的外层字段重新生效，与运行语义不符。
void test_xray_xhttp_extra_replaces_outer_fields() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "host": "outer.example.com",
          "mode": "packet-up",
          "xPaddingBytes": "999-999",
          "scMaxEachPostBytes": 111,
          "extra": {"xPaddingBytes": "100-500"}
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    // extra 里的值生效
    require(node.XhttpPaddingBytes == "100-500",
            "extra.xPaddingBytes must win, got: " + node.XhttpPaddingBytes);
    // 外层直写字段在 extra 存在时应被整体忽略
    require(node.XhttpScMaxEachPostBytes.empty(),
            "outer scMaxEachPostBytes must be ignored when extra exists, got: " +
                node.XhttpScMaxEachPostBytes);
    // host/path/mode 仍从外层保留
    require(node.Host == "outer.example.com" && node.Path == "/up" && node.XhttpMode == "packet-up",
            "outer host/path/mode must survive");
}

// 无 extra 时，直写的 Xray 正式字段全部生效（旧别名的边界见
// test_xray_xhttp_direct_fields_follow_official_names）
void test_xray_xhttp_direct_official_fields() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "headers": {"X-Forwarded-For": "1.2.3.4"},
          "sessionIDPlacement": "query",
          "sessionIDKey": "sk",
          "xPaddingBytes": "100-500"
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    require(node.XhttpHeaders.find("X-Forwarded-For") != std::string::npos,
            "direct headers must reach XhttpHeaders, got: " + node.XhttpHeaders);
    require(node.XhttpClashOpts.find("\"session-placement\":\"query\"") != std::string::npos,
            "direct sessionIDPlacement must map, got: " + node.XhttpClashOpts);
    require(node.XhttpClashOpts.find("\"session-key\":\"sk\"") != std::string::npos,
            "direct sessionIDKey must map, got: " + node.XhttpClashOpts);
    require(node.XhttpPaddingBytes == "100-500", "direct xPaddingBytes must still work");
}

// Xray 的 security 缺失或空串都明确表示无 TLS，不存在"未指定"。
// 转成 mihomo 时必须落成显式 tls:false，否则会被当作"继承上游"。
void test_xray_download_settings_missing_security_means_no_tls() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443,
            "xhttpSettings": {"path": "/down"}
          }
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    require(node.XhttpDownload.find("\"tls\":false") != std::string::npos,
            "missing security must become explicit tls:false, got: " + node.XhttpDownload);
}

// Clash 侧的 download-settings 不再生成到链接：mihomo 是"复制父 XHTTP 配置再覆盖
// 四项"，Xray 的 downloadSettings 则零继承独立构建，且 ShadowTLS/Restls/JLS 等在
// Xray 无等价表达。生成部分正确的下行配置比不生成更危险，故跳过并告警，
// 但节点本身照常导出——丢的只是一项可选的下行优化。
void test_clash_download_settings_omitted_from_link_but_node_kept() {
    const std::string content = R"(proxies:
  - name: ds-omitted
    type: vless
    server: main.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    servername: sni.example.com
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        path: /down
)";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected one node");
    require(!nodes[0].XhttpDownload.empty(),
            "download-settings must still be parsed for the clash side");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    require(decoded.find("vless://") != std::string::npos,
            "the node itself must still be exported");
    require(decoded.find("downloadSettings") == std::string::npos,
            "clash-side download-settings must not be synthesised into the link, got: " + decoded);
}

// 原始 Xray downloadSettings 是原样透传，不得擅自补 network，
// 否则会改变原配置的默认网络行为
void test_xray_download_settings_passthrough_untouched() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {"address": "dl.example.com", "port": 8443, "security": "none"}
        }
      }
    }
  ]
})";
    std::vector<Proxy> nodes{parse_v2ray_conf(content)};
    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    auto pos = decoded.find("extra=");
    require(pos != std::string::npos, "expected extra= in link");
    auto end = decoded.find_first_of("&#", pos);
    if (end == std::string::npos) end = decoded.size();
    const std::string extraJson = urlDecode(decoded.substr(pos + 6, end - pos - 6));

    rapidjson::Document d;
    d.Parse(extraJson.data());
    require(!d.HasParseError() && d.IsObject(), "extra must be valid JSON: " + extraJson);
    require(d.HasMember("downloadSettings"), "passthrough downloadSettings must survive");
    require(!d["downloadSettings"].HasMember("network"),
            "passthrough must not gain a synthesised network, got: " + extraJson);
    require(std::string(d["downloadSettings"]["address"].GetString()) == "dl.example.com",
            "passthrough content must stay intact, got: " + extraJson);
}

// mihomo 的 XHTTPDownloadSettings 全部是指针字段：缺失=沿用主连接，
// 显式值（含空串、空对象）=覆盖。canonical JSON 用成员存在性承载这一语义，
// 四个转换方向都必须守恒，否则显式空会退化成缺失而错误继承上游。
void test_download_settings_explicit_empty_all_fields_preserved() {
    const std::string content = R"(proxies:
  - name: ds-empty-all
    type: vless
    server: main.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    servername: sni.example.com
    client-fingerprint: chrome
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        host: ""
        servername: ""
        client-fingerprint: ""
        fingerprint: ""
        name-cert-verify: ""
)";
    const Proxy node = parse_clash(content);
    for (const char *k : {"host", "servername", "client-fingerprint",
                          "fingerprint", "name-cert-verify"}) {
        require(node.XhttpDownload.find(std::string("\"") + k + "\":\"\"") != std::string::npos,
                std::string("explicit empty ") + k + " must be preserved, got: " + node.XhttpDownload);
    }

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ds = YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"];
    for (const char *k : {"host", "servername", "client-fingerprint",
                          "fingerprint", "name-cert-verify"}) {
        require(ds[k].IsDefined() && ds[k].as<std::string>().empty(),
                std::string("explicit empty ") + k + " must survive to clash, got:\n" + exported);
    }
}

// reality-opts 的三种状态必须可区分：
// 无该键=沿用主连接；空对象或空 public-key=清除继承（mihomo 的
// RealityOptions.Parse 在 PublicKey 为空时返回 nil）；有值=覆盖
void test_download_settings_reality_opts_three_states() {
    auto build = [](const char *dsBody) {
        return std::string(R"(proxies:
  - name: ds-reality
    type: vless
    server: main.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    reality-opts:
      public-key: parent-pbk
      short-id: aabb
    xhttp-opts:
      path: /up
      download-settings:
)") + dsBody;
    };

    // 状态一：无 reality-opts → canonical 不含该成员（沿用主连接）
    const Proxy inherit = parse_clash(build("        path: /down\n"));
    require(inherit.XhttpDownload.find("reality-opts") == std::string::npos,
            "absent reality-opts must stay absent, got: " + inherit.XhttpDownload);

    // 状态二：空 public-key → 显式清除，canonical 必须保留该对象
    const Proxy cleared = parse_clash(build("        reality-opts:\n          public-key: \"\"\n"));
    require(cleared.XhttpDownload.find("reality-opts") != std::string::npos,
            "reality-opts clearing override must be preserved, got: " + cleared.XhttpDownload);

    // 状态三：有值 → 覆盖
    const Proxy override = parse_clash(build("        reality-opts:\n          public-key: dl-pbk\n"));
    require(override.XhttpDownload.find("dl-pbk") != std::string::npos,
            "reality-opts override must be preserved, got: " + override.XhttpDownload);

    // 物化已撤除，此处只验证 canonical 三态；清除语义对 clash 侧的效果
    // 由 test_clash_download_settings_x25519mlkem768 等用例覆盖
}

// Xray 的 c.Extra 是 json.RawMessage：只要键存在（含 null）就进入整体替换，
// 得到的空配置再被外层 host/path/mode 覆盖回来；只有非对象非 null 才是
// unmarshal 失败。故判定必须用"成员是否存在"，不能用"内容是否非空"。
void test_xray_xhttp_extra_null_and_empty_still_replace() {
    auto build = [](const char *extraLiteral) {
        return std::string(R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "host": "outer.example.com",
          "mode": "packet-up",
          "xPaddingBytes": "999-999",
          "extra": )") + extraLiteral + R"(
        }
      }
    }
  ]
})";
    };

    for (const char *lit : {"null", "{}"}) {
        const Proxy node = parse_v2ray_conf(build(lit));
        // 整体替换成空配置：外层直写字段一律失效
        require(node.XhttpPaddingBytes.empty(),
                std::string("extra: ") + lit +
                    " must replace wholesale, outer xPaddingBytes should vanish, got: " +
                    node.XhttpPaddingBytes);
        // host/path/mode 仍由外层覆盖回来
        require(node.Host == "outer.example.com" && node.Path == "/up" &&
                    node.XhttpMode == "packet-up",
                std::string("extra: ") + lit + " must keep outer host/path/mode");
    }
}

// extra 为非对象非 null 时 Xray 的 json.Unmarshal 会失败并拒绝构建，
// 转换器不能静默退回外层字段当作没有 extra
void test_xray_xhttp_invalid_extra_rejects_node() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {"path": "/up", "xPaddingBytes": "999-999", "extra": 123}
      }
    }
  ]
})";
    std::vector<Proxy> nodes;
    explodeConfContent(content, nodes);
    require(nodes.empty(),
            "node with an invalid extra must be rejected rather than silently falling back");
}

// downloadSettings 必须与 extra 同源：extra 存在时只认 extra.downloadSettings，
// 外层的那份要被忽略；extra 不存在时才用外层
void test_xray_xhttp_download_settings_follows_extra() {
    const std::string withExtra = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {"address": "outer-dl.example.com", "port": 1111},
          "extra": {"downloadSettings": {"address": "inner-dl.example.com", "port": 2222}}
        }
      }
    }
  ]
})";
    const Proxy withE = parse_v2ray_conf(withExtra);
    require(withE.XhttpDownloadSettings.find("inner-dl.example.com") != std::string::npos,
            "extra.downloadSettings must win, got: " + withE.XhttpDownloadSettings);
    require(withE.XhttpDownloadSettings.find("outer-dl.example.com") == std::string::npos,
            "outer downloadSettings must be ignored when extra exists, got: " +
                withE.XhttpDownloadSettings);

    const std::string noExtra = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {"address": "outer-dl.example.com", "port": 1111}
        }
      }
    }
  ]
})";
    const Proxy noE = parse_v2ray_conf(noExtra);
    require(noE.XhttpDownloadSettings.find("outer-dl.example.com") != std::string::npos,
            "outer downloadSettings must be used when extra is absent, got: " +
                noE.XhttpDownloadSettings);
}

// 白名单按 Xray 当前正式字段过滤：headers 是正式字段应生效，
// 而 sessionPlacement 只是 mihomo 的链接兼容别名，Xray 自己会忽略它，
// 转换器不能借旧别名把它在 Xray JSON 路径上激活
void test_xray_xhttp_direct_fields_follow_official_names() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "headers": {"X-Forwarded-For": "1.2.3.4"},
          "sessionPlacement": "header"
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    require(node.XhttpHeaders.find("X-Forwarded-For") != std::string::npos,
            "headers is an official Xray field and must be honoured, got: " + node.XhttpHeaders);
    // 只给旧别名、不给正式名：Xray 自身会忽略它，转换器也不该在此路径激活
    require(node.XhttpClashOpts.find("session-placement") == std::string::npos,
            "legacy sessionPlacement must not be activated on the Xray JSON path, got: " +
                node.XhttpClashOpts);
}

// Xray 与 mihomo 的 null 语义不同，不能套用同一条规则：
// Xray 的 SplitHTTPConfig/StreamConfig 字段多为非指针类型，JSON null 经
// encoding/json 反序列化是 no-op，结果为零值（空串），随后由运行时各自回退
// （如 dialer 里 Host 为空才取 tls.ServerName）——这是运行时回退，不是配置层继承。
// 而 mihomo 的 XHTTPDownloadSettings 是指针字段，缺失才表示沿用主连接。
// 故 Xray 侧的 null 必须落成显式零值，只有键缺失才对应 canonical 的缺失。
void test_xray_download_settings_null_means_zero_not_inherit() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": "tls",
            "tlsSettings": {"serverName": null},
            "xhttpSettings": {"path": null, "host": "dl-host.example.com"}
          }
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    // null 是显式零值，必须写成空串而非省略（省略会让 mihomo 继承主连接）
    require(node.XhttpDownload.find("\"path\":\"\"") != std::string::npos,
            "Xray null path must become an explicit empty value, got: " + node.XhttpDownload);
    require(node.XhttpDownload.find("\"servername\":\"\"") != std::string::npos,
            "Xray null serverName must become an explicit empty value, got: " +
                node.XhttpDownload);
    // 同级中真正给了值的字段不受影响
    require(node.XhttpDownload.find("dl-host.example.com") != std::string::npos,
            "sibling values must be unaffected, got: " + node.XhttpDownload);
}

// 对照组：键缺失才是"沿用主连接"，canonical 里不应出现该成员
void test_xray_download_settings_absent_key_means_inherit() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": "tls",
            "xhttpSettings": {"host": "dl-host.example.com"}
          }
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    require(node.XhttpDownload.find("\"path\"") == std::string::npos,
            "absent path must stay absent so mihomo inherits, got: " + node.XhttpDownload);
    require(node.XhttpDownload.find("\"servername\"") == std::string::npos,
            "absent serverName must stay absent, got: " + node.XhttpDownload);
}

// 字符串保型此前只在 nodelist 路径验证过，而规则生成路径（ext.nodelist=false）
// 会先 replaceAll("!<str> ", "") 把锚定标签整体删除，再调美化函数——标签已不存在，
// 值随即裸化。这条才是最常用的输出路径。
void test_string_anchoring_survives_rule_generation_path() {
    std::vector<Proxy> nodes;
    explodeSub("ss://YWVzLTEyOC1nY206MDEyMw@ss.example.com:443#numeric-pass", nodes);
    require(nodes.size() == 1 && nodes[0].Password == "0123", "expected password 0123");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.nodelist = false;  // 规则生成路径
    const std::string exported = proxyToClash(nodes, "proxies:\n", rulesets, groups, false, ext);

    const YAML::Node rt = YAML::Load(exported)["proxies"][0];
    require(rt["password"].as<std::string>() == "0123",
            "numeric password must survive the rule path, got:\n" + exported);
    require(rt["password"].Tag() != "?",
            "numeric password must stay anchored on the rule path, got:\n" + exported);
}

// 只有真正会被 YAML 读成非字符串的值才需要锚定。像 1,a / 1abc 本就是字符串，
// 锚定它们反而会让 beautifyStringTags 的文本定界撞上逗号而截断，产出损坏的 YAML。
void test_anchoring_skips_values_that_are_already_strings() {
    const std::string content = R"(proxies:
  - name: tricky
    type: vless
    server: t.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    jls-opts:
      password: "1,a"
      username: "16-32"
      iv2: "1abc"
)";
    std::vector<Proxy> nodes{parse_clash(content)};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);

    // 输出必须是合法 YAML，且值完整——含逗号的值被截断时这里会直接解析失败
    const YAML::Node j = YAML::Load(exported)["proxies"][0]["jls-opts"];
    require(j["password"].as<std::string>() == "1,a",
            "comma-containing value must survive intact, got:\n" + exported);
    require(j["username"].as<std::string>() == "16-32",
            "range-like value must survive intact, got:\n" + exported);
    require(j["iv2"].as<std::string>() == "1abc",
            "digit-prefixed string must survive intact, got:\n" + exported);
    // 精确判定的收益：本就是字符串的值根本不该被锚定，
    // 否则要靠美化阶段的兜底逻辑才能避免截断
    require(exported.find("!<str>") == std::string::npos,
            "values that are already strings must not be anchored at all, got:\n" + exported);
}

// A1：ech-opts / shadow-tls-opts 等在 download-settings 里是指针字段，
// 空对象表示"清除继承"，不能因为内容为空而退化成缺失（即继承主连接）
void test_download_settings_empty_tls_opts_preserved() {
    const std::string content = R"(proxies:
  - name: ds-empty-tls
    type: vless
    server: main.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    ech-opts:
      enable: true
      config: PARENTECH
    xhttp-opts:
      path: /up
      download-settings:
        ech-opts: {}
        shadow-tls-opts: {}
)";
    const Proxy node = parse_clash(content);
    require(node.XhttpDownload.find("ech-opts") != std::string::npos,
            "empty ech-opts must be preserved as an explicit clear, got: " + node.XhttpDownload);
    require(node.XhttpDownload.find("shadow-tls-opts") != std::string::npos,
            "empty shadow-tls-opts must be preserved, got: " + node.XhttpDownload);

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ds = YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"];
    require(ds["ech-opts"].IsDefined(),
            "empty ech-opts must survive to clash as an explicit clear, got:\n" + exported);
}

// A4：Xray 对 "xhttpSettings": 123 会反序列化失败，转换器不该静默接受
void test_xray_non_object_xhttp_settings_rejected() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {"network": "xhttp", "security": "tls", "xhttpSettings": 123}
    }
  ]
})";
    std::vector<Proxy> nodes;
    explodeConfContent(content, nodes);
    require(nodes.empty(), "non-object xhttpSettings must be rejected, not silently accepted");
}

// S5：Xray 用 strings.ToLower 判定 security，且未知值会报 Unknown security。
// 大小写变体必须识别；未知值不能被静默降级成明文。
void test_xray_security_case_insensitive_and_unknown_rejected() {
    auto build = [](const char *sec) {
        return std::string(R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": ")") + sec + R"(",
            "xhttpSettings": {"path": "/down"}
          }
        }
      }
    }
  ]
})";
    };

    const Proxy upper = parse_v2ray_conf(build("TLS"));
    require(upper.XhttpDownload.find("\"tls\":true") != std::string::npos,
            "security is matched case-insensitively by Xray, got: " + upper.XhttpDownload);

    std::vector<Proxy> nodes;
    explodeConfContent(build("bogus"), nodes);
    require(nodes.empty(),
            "unknown security must be rejected rather than silently downgraded to plaintext");
}

// S6：显式 port: 0 与 support-x25519mlkem768: null 的守恒
void test_download_settings_zero_and_null_conserved() {
    const std::string content = R"(proxies:
  - name: ds-zero
    type: vless
    server: main.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        port: 0
        reality-opts:
          public-key: pbk
          support-x25519mlkem768: null
)";
    const Proxy node = parse_clash(content);
    require(node.XhttpDownload.find("\"port\":0") != std::string::npos,
            "explicit port 0 must be preserved, got: " + node.XhttpDownload);
    require(node.XhttpDownload.find("support-x25519mlkem768") == std::string::npos,
            "YAML null must be treated as unset, not as an explicit false, got: " +
                node.XhttpDownload);
}

// B：链接路径此前"拒绝"是假的——vlessConstruct 已把 node.Type 设为 VLESS，
// 函数内 return 拦不住外层，explodeSub 的接受条件只看 Type 是否为 Unknown，
// 于是日志说跳过、节点照样入列且丢掉了 download-settings。
void test_vless_link_invalid_download_settings_actually_drops_node() {
    // downloadSettings 里 security 为未知值，Xray 会拒绝构建
    const std::string bad = urlEncode(R"({"address":"dl.example.com","port":443,"security":"bogus"})");
    std::vector<Proxy> nodes;
    explodeSub("vless://12345678-1234-1234-1234-123456789012@x.example.com:443"
               "?security=tls&type=xhttp&path=%2Fup&downloadSettings=" + bad + "#bad-ds",
               nodes);
    require(nodes.empty(),
            "a link with invalid downloadSettings must be dropped, not accepted without it");
}

// 坏 JSON 或非对象的 downloadSettings 在 Xray 侧同样构建失败，
// 不能静默当作"没有下行配置"而放行节点
void test_link_malformed_download_settings_drops_node() {
    for (const char *bad : {"123", "%7Bbroken"}) {
        std::vector<Proxy> nodes;
        explodeSub(std::string("vless://12345678-1234-1234-1234-123456789012@x.example.com:443")
                   + "?security=tls&type=xhttp&path=%2Fup&downloadSettings=" + bad + "#bad",
                   nodes);
        require(nodes.empty(),
                std::string("malformed downloadSettings (") + bad + ") must drop the node");
    }
}

// D：ALPN 数组元素未校验类型即 GetString()。rapidjson 内部是
// RAPIDJSON_ASSERT(IsString())，release 构建下 assert 被禁用，非字符串元素
// 会导致未定义行为。订阅内容不可信，必须逐元素校验。
void test_xray_download_settings_alpn_non_string_elements_are_safe() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": "tls",
            "tlsSettings": {"alpn": ["h2", 123, null, "http/1.1"]},
            "xhttpSettings": {"path": "/down"}
          }
        }
      }
    }
  ]
})";
    const Proxy node = parse_v2ray_conf(content);
    // 不崩溃即为通过；同时非字符串元素应被跳过而不是产出垃圾
    require(node.XhttpDownload.find("h2") != std::string::npos,
            "string alpn entries must survive, got: " + node.XhttpDownload);
    require(node.XhttpDownload.find("http/1.1") != std::string::npos,
            "string alpn entries must survive, got: " + node.XhttpDownload);
}

// S3：Xray 对 security: xtls 是 PrintRemovedFeatureError("Legacy XTLS") 明确拒绝，
// 不是"视为无 TLS"。把它降级成明文放行有安全含义。
void test_xray_download_settings_xtls_is_rejected() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "downloadSettings": {
            "address": "dl.example.com", "port": 443, "security": "xtls",
            "xhttpSettings": {"path": "/down"}
          }
        }
      }
    }
  ]
})";
    std::vector<Proxy> nodes;
    explodeConfContent(content, nodes);
    require(nodes.empty(),
            "legacy xtls must be rejected like Xray does, not downgraded to plaintext");
}

// S4：Xray 的正式结构就是 SplitHTTPConfig.DownloadSettings，即 extra.downloadSettings。
// 导出侧已按此位置生成，解析侧却只读旧的顶层参数，导致项目自己生成的标准形式
// 在"链接 → 内部字段 → Clash"这条链路上丢失下行配置（链接原样转链接因保留了
// XhttpExtra 而不会立刻暴露）。
void test_link_extra_download_settings_is_parsed() {
    const std::string extra = urlEncode(
        R"({"downloadSettings":{"address":"inner-dl.example.com","port":2222,"security":"tls"}})");
    const Proxy node = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@x.example.com:443"
        "?security=tls&type=xhttp&path=%2Fup&extra=" + extra + "#nested-ds");
    require(node.XhttpDownloadSettings.find("inner-dl.example.com") != std::string::npos,
            "extra.downloadSettings must be extracted, got: " + node.XhttpDownloadSettings);
    require(node.XhttpDownload.find("inner-dl.example.com") != std::string::npos,
            "extra.downloadSettings must reach canonical, got: " + node.XhttpDownload);
}

// 顶层参数仅作旧格式兼容，与 extra 内的同时出现时以 extra 为准
void test_link_nested_download_settings_wins_over_legacy_param() {
    const std::string extra = urlEncode(
        R"({"downloadSettings":{"address":"inner-dl.example.com","port":2222,"security":"tls"}})");
    const std::string legacy = urlEncode(
        R"({"address":"legacy-dl.example.com","port":1111,"security":"tls"})");
    const Proxy node = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@x.example.com:443"
        "?security=tls&type=xhttp&path=%2Fup&downloadSettings=" + legacy + "&extra=" + extra +
        "#both");
    require(node.XhttpDownloadSettings.find("inner-dl.example.com") != std::string::npos,
            "nested extra.downloadSettings must win, got: " + node.XhttpDownloadSettings);
    require(node.XhttpDownloadSettings.find("legacy-dl.example.com") == std::string::npos,
            "legacy top-level param must lose to nested, got: " + node.XhttpDownloadSettings);
}

// 导出侧：已有 extra 时也必须把 downloadSettings 并入，而不是跳过合成；
// 且同名键只能有一个（rapidjson 的 AddMember 不去重）
void test_link_export_merges_download_settings_into_existing_extra() {
    // Xray 输入：外层直写 headers（构成 extra）+ 外层 downloadSettings（不在 extra 内）
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "headers": {"X-Test": "1"},
          "downloadSettings": {"address": "dl.example.com", "port": 8443, "security": "tls"}
        }
      }
    }
  ]
})";
    std::vector<Proxy> nodes{parse_v2ray_conf(content)};
    require(!nodes[0].XhttpExtra.empty(), "headers should have produced an extra");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    auto pos = decoded.find("extra=");
    require(pos != std::string::npos, "expected extra= in link");
    auto end = decoded.find_first_of("&#", pos);
    if (end == std::string::npos) end = decoded.size();
    const std::string extraJson = urlDecode(decoded.substr(pos + 6, end - pos - 6));

    rapidjson::Document d;
    d.Parse(extraJson.data());
    require(!d.HasParseError() && d.IsObject(), "extra must be valid JSON: " + extraJson);
    require(d.HasMember("downloadSettings"),
            "downloadSettings must be merged into the existing extra, got: " + extraJson);
    // 必须是原样透传的那份，而不是回落到 canonical 重新生成的：
    // 后者会补 network 并物化父节点值，内容与原配置不同
    require(d["downloadSettings"]["port"].GetInt() == 8443,
            "passthrough content must be used, got: " + extraJson);
    require(!d["downloadSettings"].HasMember("network"),
            "passthrough must not be replaced by a synthesised config, got: " + extraJson);
    require(d.HasMember("headers"), "existing extra content must survive, got: " + extraJson);
    // 同名键只应出现一次
    size_t first = extraJson.find("\"downloadSettings\"");
    require(extraJson.find("\"downloadSettings\"", first + 1) == std::string::npos,
            "downloadSettings must not be duplicated, got: " + extraJson);
}

// S2：旧 session 别名要按来源隔离。mihomo 的链接转换器兼容它们，所以 VLESS URI
// 必须继续接受；而 Xray 的 SplitHTTPConfig 只有 sessionIDPlacement/sessionIDKey，
// 旧键作为未知字段会被忽略，Xray JSON 路径就不该激活。
void test_legacy_session_aliases_are_source_scoped() {
    // URI 来源：保留兼容
    const std::string extra = urlEncode(R"({"sessionPlacement":"query","sessionKey":"sk"})");
    const Proxy fromUri = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@x.example.com:443"
        "?security=tls&type=xhttp&path=%2Fup&extra=" + extra + "#uri-alias");
    require(fromUri.XhttpClashOpts.find("\"session-placement\":\"query\"") != std::string::npos,
            "URI extra must keep accepting legacy aliases, got: " + fromUri.XhttpClashOpts);

    // Xray JSON 来源：不得激活
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {"path": "/up", "extra": {"sessionPlacement": "header"}}
      }
    }
  ]
})";
    const Proxy fromXray = parse_v2ray_conf(content);
    require(fromXray.XhttpClashOpts.find("session-placement") == std::string::npos,
            "Xray extra must ignore legacy aliases like Xray itself does, got: " +
                fromXray.XhttpClashOpts);
}

// 来源隔离只挡住了内部映射，原始 extra 仍被原样带进链接：
// Xray 的 extra.sessionPlacement 对 Xray 自己是无效未知字段，但一旦原样写进
// VLESS URI，mihomo 读链接时会用兼容分支重新激活它——等于把 Xray 忽略的配置
// 洗白成了生效配置。这些键对 Xray 无意义，导出前应从 effective extra 中剔除。
void test_xray_legacy_aliases_do_not_leak_into_link() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "extra": {"sessionPlacement": "header", "sessionKey": "sk", "xPaddingBytes": "100-500"}
        }
      }
    }
  ]
})";
    std::vector<Proxy> nodes{parse_v2ray_conf(content)};
    // 内部不激活（已有保障）
    require(nodes[0].XhttpClashOpts.find("session-placement") == std::string::npos,
            "legacy alias must not be activated internally");

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    auto pos = decoded.find("extra=");
    require(pos != std::string::npos, "expected extra= in link");
    auto end = decoded.find_first_of("&#", pos);
    if (end == std::string::npos) end = decoded.size();
    const std::string extraJson = urlDecode(decoded.substr(pos + 6, end - pos - 6));

    require(extraJson.find("sessionPlacement") == std::string::npos,
            "legacy alias must not leak into the exported link, got: " + extraJson);
    require(extraJson.find("sessionKey") == std::string::npos,
            "legacy alias must not leak into the exported link, got: " + extraJson);
    // 有效字段不受影响
    require(extraJson.find("xPaddingBytes") != std::string::npos,
            "valid fields must survive, got: " + extraJson);
}

// nested 优先规则要按"成员是否存在"判断：extra 里显式写 downloadSettings: null
// 表示明确没有下行配置，不能再回退到旧的顶层参数
void test_link_nested_null_download_settings_does_not_fall_back() {
    const std::string extra = urlEncode(R"({"downloadSettings":null})");
    const std::string legacy = urlEncode(
        R"({"address":"legacy-dl.example.com","port":1111,"security":"tls"})");
    const Proxy node = parse_link(
        "vless://12345678-1234-1234-1234-123456789012@x.example.com:443"
        "?security=tls&type=xhttp&path=%2Fup&downloadSettings=" + legacy + "&extra=" + extra +
        "#nested-null");
    require(node.XhttpDownloadSettings.find("legacy-dl.example.com") == std::string::npos,
            "explicit nested null must not fall back to the legacy param, got: " +
                node.XhttpDownloadSettings);
    require(node.XhttpDownload.empty(),
            "explicit nested null means no download settings, got: " + node.XhttpDownload);
}

// RemoveMember 只移除首个同名成员，输入 extra 自带重复键时会有残留
void test_link_export_removes_all_duplicate_download_settings() {
    const std::string content = R"({
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "x.example.com", "port": 443,
        "users": [{"id": "12345678-1234-1234-1234-123456789012"}]}]},
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/up",
          "extra": {"downloadSettings": {"address": "a.example.com", "port": 1},
                    "downloadSettings": {"address": "b.example.com", "port": 2}}
        }
      }
    }
  ]
})";
    std::vector<Proxy> nodes{parse_v2ray_conf(content)};
    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string decoded = urlSafeBase64Decode(proxyToSingle(nodes, kVlessMask, ext));
    auto pos = decoded.find("extra=");
    require(pos != std::string::npos, "expected extra= in link");
    auto end = decoded.find_first_of("&#", pos);
    if (end == std::string::npos) end = decoded.size();
    const std::string extraJson = urlDecode(decoded.substr(pos + 6, end - pos - 6));

    const size_t first = extraJson.find("\"downloadSettings\"");
    require(first != std::string::npos, "expected downloadSettings, got: " + extraJson);
    require(extraJson.find("\"downloadSettings\"", first + 1) == std::string::npos,
            "duplicate downloadSettings keys must all be removed, got: " + extraJson);
}

// download-settings 的 reality 参数在 mihomo 里是嵌套的 reality-opts，
// 平铺的 public-key/short-id 会被 mihomo 静默忽略导致下行丢失 reality 配置
void test_clash_xhttp_download_settings_reality_opts_nested() {
    const std::string content = R"(proxies:
  - name: xhttp-ds-reality
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      download-settings:
        server: dl.example.com
        port: 443
        tls: true
        servername: dl.example.com
        reality-opts:
          public-key: dl-pbk
          short-id: 11aa22bb
        path: /down
)";

    const Proxy node = parse_clash(content);
    require(node.XhttpDownload.find("dl-pbk") != std::string::npos,
            "nested reality-opts.public-key must be parsed from download-settings");
    require(node.XhttpDownload.find("11aa22bb") != std::string::npos,
            "nested reality-opts.short-id must be parsed from download-settings");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    const YAML::Node ds = YAML::Load(exported)["proxies"][0]["xhttp-opts"]["download-settings"];
    require(ds["reality-opts"].IsDefined() && ds["reality-opts"].IsMap(),
            "download-settings must emit nested reality-opts");
    require(ds["reality-opts"]["public-key"].as<std::string>() == "dl-pbk",
            "download-settings.reality-opts.public-key must survive");
    require(ds["reality-opts"]["short-id"].as<std::string>() == "11aa22bb",
            "download-settings.reality-opts.short-id must survive");
    require(!ds["public-key"].IsDefined(),
            "download-settings must not emit flat public-key (mihomo ignores it)");
    require(!ds["short-id"].IsDefined(),
            "download-settings must not emit flat short-id (mihomo ignores it)");
}

void test_clash_vless_xhttp_reuse_settings_h_keep_alive_period() {
    // h-keep-alive-period 是 mihomo Apr 9 新增字段，验证解析与导出
    const std::string content = R"(proxies:
  - name: xhttp-reuse-hkap
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      reuse-settings:
        max-connections: "16"
        h-keep-alive-period: "30"
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(!node.XhttpReuseSettings.empty(), "expected reuse-settings to be parsed");
    require(node.XhttpReuseSettings.find("h-keep-alive-period") != std::string::npos,
            "expected h-keep-alive-period to be stored in XhttpReuseSettings JSON");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("h-keep-alive-period: 30") != std::string::npos,
            "expected h-keep-alive-period to be exported in reuse-settings");
}

void test_clash_vless_xhttp_sc_max_range_passthrough() {
    // sc-max-each-post-bytes 支持范围格式字符串（如 "100-200"），验证透传正确
    const std::string content = R"(proxies:
  - name: xhttp-sc-range
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: packet-up
      sc-max-each-post-bytes: "1000000-2000000"
)";

    const Proxy node = parse_clash(content);
    require(node.XhttpScMaxEachPostBytes == "1000000-2000000",
            "expected range format sc-max-each-post-bytes to be stored as-is");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("sc-max-each-post-bytes: 1000000-2000000") != std::string::npos,
            "expected range format sc-max-each-post-bytes to be exported as-is");
}

void test_clash_vless_grpc_new_opts() {
    // grpc-opts 新增 max-connections/min-streams/max-streams（mihomo Apr 5）
    const std::string content = R"(proxies:
  - name: grpc-node
    type: vless
    server: grpc.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: grpc
    grpc-opts:
      grpc-service-name: myservice
      grpc-mode: gun
      max-connections: 4
      min-streams: 2
      max-streams: 8
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "grpc", "expected grpc network");
    require(node.GRPCServiceName == "myservice", "expected grpc-service-name");
    require(node.GRPCMode == "gun", "expected grpc-mode");
    require(node.GRPCMaxConnections == 4, "expected max-connections to be parsed");
    require(node.GRPCMinStreams == 2, "expected min-streams to be parsed");
    require(node.GRPCMaxStreams == 8, "expected max-streams to be parsed");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("network: grpc") != std::string::npos, "expected grpc network in export");
    require(exported.find("grpc-service-name: myservice") != std::string::npos,
            "expected grpc-service-name in export");
    require(exported.find("max-connections: 4") != std::string::npos,
            "expected max-connections in grpc-opts export");
    require(exported.find("min-streams: 2") != std::string::npos,
            "expected min-streams in grpc-opts export");
    require(exported.find("max-streams: 8") != std::string::npos,
            "expected max-streams in grpc-opts export");
}

void test_quanx_export_skips_vless_xhttp_node() {
    std::vector<Proxy> nodes;
    explodeSub(
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=tls&type=xhttp&host=cdn.example.com&path=%2Fxhttp&mode=packet-up#xhttp-node",
        nodes);

    require(nodes.size() == 1, "expected one node");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    const std::string exported = proxyToQuanX(nodes, "", rulesets, groups, ext);
    require(exported.find("xhttp-node") == std::string::npos, "expected QuanX export to skip xhttp node");
    require(exported.find("obfs=over-tls") == std::string::npos,
            "expected QuanX export to avoid misleading over-tls fallback");
}

void test_proxy_group_toml_extras_preserve_scalar_types() {
    std::istringstream input(R"(
[[custom_groups]]
name = "Proxy"
type = "select"
rule = ["[]DIRECT"]
extra = { icon = "https://example.com/icon.png", hidden = true, threshold = 7 }
)");
    const toml::value root = toml::parse(input, "proxy-group-regression.toml");
    const auto values = toml::find<std::vector<toml::value>>(root, "custom_groups");
    const ProxyGroupConfigs groups = toml::get<ProxyGroupConfigs>(toml::value(values));

    std::vector<Proxy> nodes;
    YAML::Node output;
    extra_settings ext;
    ext.clash_new_field_name = true;
    proxyToClash(nodes, output, groups, false, ext);

    const YAML::Node group = output["proxy-groups"][0];
    require(group["icon"].as<std::string>() == "https://example.com/icon.png",
            "TOML string extra must not retain serialization quotes");
    require(group["hidden"].as<bool>(), "TOML boolean extra must remain boolean");
    require(group["threshold"].as<int>() == 7, "TOML integer extra must remain integer");
}

void test_proxy_group_trailing_provider_is_not_treated_as_extra() {
    const ProxyGroupConfigs groups = INIBinding::from<ProxyGroupConfig>::from_ini({
        "Provider`select`!!PROVIDER=one,two"
    });

    require(groups.size() == 1, "expected one proxy group");
    require(groups[0].UsingProvider == StrArray({"one", "two"}),
            "trailing !!PROVIDER must remain provider syntax");
}

void test_ruleset_format_is_parsed_and_validated() {
    std::istringstream valid_input(R"(
[[rulesets]]
group = "Proxy"
ruleset = "https://example.com/domains.txt"
type = "clash-domain"
format = "text"
)");
    const toml::value valid_root = toml::parse(valid_input, "ruleset-format.toml");
    const auto values = toml::find<std::vector<toml::value>>(valid_root, "rulesets");
    const RulesetConfigs rulesets = toml::get<RulesetConfigs>(toml::value(values));
    require(rulesets.size() == 1 && rulesets[0].Format == "text",
            "explicit rule-provider format must be preserved");

    RulesetContent text_ruleset;
    text_ruleset.rule_group = "Proxy";
    text_ruleset.rule_path = "https://example.com/domains.txt";
    text_ruleset.rule_path_typed = "clash-domain:https://example.com/domains.txt";
    text_ruleset.rule_format = "text";
    text_ruleset.rule_type = RULESET_CLASH_DOMAIN;

    RulesetContent mrs_ruleset;
    mrs_ruleset.rule_group = "Proxy";
    mrs_ruleset.rule_path = "https://example.com/ips.mrs";
    mrs_ruleset.rule_path_typed = "clash-ipcidr:https://example.com/ips.mrs";
    mrs_ruleset.rule_format = "mrs";
    mrs_ruleset.rule_type = RULESET_CLASH_IPCIDR;

    YAML::Node output;
    std::vector<RulesetContent> contents{text_ruleset, mrs_ruleset};
    renderClashScript(output, contents, "", false, true, true);
    const std::string rendered = YAML::Dump(output);
    require(rendered.find("format: text") != std::string::npos,
            "text rule-provider format must be emitted");
    require(rendered.find("format: mrs") != std::string::npos,
            "MRS rule-provider format must be emitted");

    std::istringstream invalid_input(R"(
[[rulesets]]
group = "Proxy"
ruleset = "https://example.com/classical.mrs"
type = "clash-classic"
format = "mrs"
)");
    bool rejected = false;
    try {
        const toml::value invalid_root = toml::parse(invalid_input, "invalid-ruleset-format.toml");
        const auto invalid_values = toml::find<std::vector<toml::value>>(invalid_root, "rulesets");
        (void) toml::get<RulesetConfigs>(toml::value(invalid_values));
    } catch (const toml::serialization_error &) {
        rejected = true;
    }
    require(rejected, "MRS format must be rejected for classical rule providers");
}

void test_quanx_export_preserves_vless_reality() {
    std::vector<Proxy> nodes;
    explodeSub(
        "vless://12345678-1234-1234-1234-123456789012@reality.example.com:443"
        "?security=reality&type=tcp&sni=apple.com&pbk=public-key&sid=01234567"
        "&flow=xtls-rprx-vision#quanx-reality",
        nodes);
    require(nodes.size() == 1, "expected one VLESS Reality node");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    const std::string exported = proxyToQuanX(nodes, "", rulesets, groups, ext);
    require(exported.find("reality-base64-pubkey=public-key") != std::string::npos,
            "QuanX export must preserve Reality public key");
    require(exported.find("reality-hex-shortid=01234567") != std::string::npos,
            "QuanX export must preserve Reality short id");
    require(exported.find("vless-flow=xtls-rprx-vision") != std::string::npos,
            "QuanX export must preserve VLESS flow");
}

void test_quanx_export_preserves_vless_wss_reality() {
    std::vector<Proxy> nodes;
    explodeSub(
        "vless://12345678-1234-1234-1234-123456789012@reality.example.com:443"
        "?security=reality&type=ws&host=cdn.example.com&path=%2Fws&sni=apple.com"
        "&pbk=public-key&sid=01234567#quanx-wss-reality",
        nodes);
    require(nodes.size() == 1, "expected one VLESS WSS Reality node");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    const std::string exported = proxyToQuanX(nodes, "", rulesets, groups, ext);
    require(exported.find("obfs=wss") != std::string::npos,
            "QuanX WSS Reality export must preserve WSS transport");
    require(exported.find("obfs-host=apple.com") != std::string::npos,
            "QuanX WSS Reality export must use SNI as Reality host");
    require(exported.find("obfs-uri=/ws") != std::string::npos,
            "QuanX WSS Reality export must preserve websocket path");
    require(exported.find("reality-base64-pubkey=public-key") != std::string::npos,
            "QuanX WSS Reality export must preserve public key");
    require(exported.find("reality-hex-shortid=01234567") != std::string::npos,
            "QuanX WSS Reality export must preserve short id");
}

// P1-1: formatterShortId 不得越界吞掉 download-settings 中 short-id 之后的键
void test_formatter_short_id_preserves_xhttp_download_settings() {
    const std::string content = R"(proxies:
  - name: xhttp-reality-ds
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: xhttp
    reality-opts:
      public-key: main-pbk
      short-id: aabbccdd
    xhttp-opts:
      path: /up
      download-settings:
        server: dl.example.com
        port: 443
        reality-opts:
          public-key: dl-pbk
          short-id: 11223344
        path: /down
        host: dl-host.example.com
)";

    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;

    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    // download-settings 中 short-id 之后的键必须完整保留（旧实现会被吞进引号）
    require(exported.find("path: /down") != std::string::npos,
            "download-settings.path after short-id must survive");
    require(exported.find("dl-host.example.com") != std::string::npos,
            "download-settings.host after short-id must survive");
    // 两个 short-id 都应被引号包裹且值未被污染
    require(exported.find("\"aabbccdd\"") != std::string::npos,
            "reality-opts.short-id must be quoted and intact");
    require(exported.find("\"11223344\"") != std::string::npos,
            "download-settings.short-id must be quoted and intact");
}

// P1-4: 链接同时带 host= 与 sni= 时，Host 头取 host，不得被 sni 覆盖
void test_vless_link_ws_host_and_sni_distinct() {
    const std::string content =
        "vless://12345678-1234-1234-1234-123456789012@edge.example.com:443"
        "?security=tls&type=ws&host=ws-host.example.com&sni=tls-sni.example.com&path=%2Fws"
        "#ws-node";

    const Proxy node = parse_link(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "ws", "expected ws transport");
    require(node.Host == "ws-host.example.com",
            "WS Host header must come from host=, not sni=");
    // VLESS 链接的 sni 存入 ServerName（vlessConstruct 的映射）
    require(node.ServerName == "tls-sni.example.com", "SNI must come from sni=");
}

// P1-3: 非 Reality 节点若链接带 fp，client-fingerprint 需输出；Reality 无 short-id 仍需默认 random
void test_vless_client_fingerprint_output() {
    // 普通 TLS ws 节点，链接带 fp=chrome
    {
        const std::string content =
            "vless://12345678-1234-1234-1234-123456789012@edge.example.com:443"
            "?security=tls&type=ws&host=h.example.com&path=%2Fws&fp=chrome#plain-fp";
        std::vector<Proxy> nodes;
        explodeSub(content, nodes);
        require(nodes.size() == 1, "expected one node");
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.nodelist = true;
        ext.clash_new_field_name = true;
        const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
        require(exported.find("client-fingerprint: chrome") != std::string::npos,
                "plain TLS node must export client-fingerprint from fp=");
    }
    // Reality 有 public-key、无 short-id、未显式 fp → 默认 random
    {
        const std::string content = R"(proxies:
  - name: reality-no-sid
    type: vless
    server: r.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true
    network: tcp
    reality-opts:
      public-key: only-pbk
)";
        const Proxy node = parse_clash(content);
        std::vector<Proxy> nodes{node};
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.nodelist = true;
        ext.clash_new_field_name = true;
        const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
        require(exported.find("client-fingerprint: random") != std::string::npos,
                "reality node without short-id must default client-fingerprint to random");
    }
}

// P1-5: hysteria2 端口跳跃范围链接不得被丢弃，密码需 URL 解码
void test_hysteria2_link_port_hopping_and_password_decode() {
    const std::string content =
        "hysteria2://p%40ss@hop.example.com:40000-50000?insecure=1&sni=h.example.com#hy2-hop";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "port-hopping hy2 link must not be dropped");
    require(nodes.front().Type == ProxyType::Hysteria2, "expected Hysteria2 node");
    require(nodes.front().Port == 40000, "base port must be first port of range");
    require(nodes.front().Ports == "40000-50000", "ports must retain full hop range");
    require(nodes.front().Password == "p@ss", "password must be URL-decoded");
}

// P1-6: 明文 mieru 链接不得被 base64 误解码，应正确解析账号密码
void test_mieru_plaintext_link() {
    const std::string content =
        "mieru://myuser:mypass@mieru.example.com:8964?protocol=TCP#mieru-node";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "plaintext mieru link must parse to one node");
    require(nodes.front().Type == ProxyType::Mieru, "expected Mieru node");
    require(nodes.front().Username == "myuser", "mieru username must parse correctly");
    require(nodes.front().Password == "mypass", "mieru password must parse correctly");
}

// P1-2 + P2-2: AnyTLS 往返保留 sni、client-fingerprint、全部 alpn 与 idle 字段
void test_anytls_clash_roundtrip_fields() {
    const std::string content = R"(proxies:
  - name: anytls-node
    type: anytls
    server: at.example.com
    port: 443
    password: secret
    sni: at-sni.example.com
    client-fingerprint: firefox
    idle-session-check-interval: 45
    min-idle-session: 3
    alpn:
      - h2
      - http/1.1
)";
    const Proxy node = parse_clash(content);
    require(node.Type == ProxyType::AnyTLS, "expected AnyTLS node");

    std::vector<Proxy> nodes{node};
    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("sni: at-sni.example.com") != std::string::npos,
            "AnyTLS sni must be exported");
    require(exported.find("client-fingerprint: firefox") != std::string::npos,
            "AnyTLS client-fingerprint must round-trip (not read from wrong key)");
    require(exported.find("h2") != std::string::npos && exported.find("http/1.1") != std::string::npos,
            "all alpn entries must survive");
    require(exported.find("idle-session-check-interval: 45") != std::string::npos,
            "non-default idle-session-check-interval must be exported");
    require(exported.find("min-idle-session: 3") != std::string::npos,
            "non-default min-idle-session must be exported");
}

// P2-1: hysteria2 导出不得包含非 mihomo 字段 auth/mport
void test_hysteria2_export_omits_nonstandard_fields() {
    const std::string content =
        "hysteria2://pw@h.example.com:443?insecure=1&sni=h.example.com#hy2";
    std::vector<Proxy> nodes;
    explodeSub(content, nodes);
    require(nodes.size() == 1, "expected one node");

    std::vector<RulesetContent> rulesets;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    const std::string exported = proxyToClash(nodes, "", rulesets, groups, false, ext);
    require(exported.find("auth:") == std::string::npos,
            "hysteria2 export must not contain non-mihomo 'auth' field");
    require(exported.find("mport:") == std::string::npos,
            "hysteria2 export must not contain non-mihomo 'mport' field");
    require(exported.find("password: pw") != std::string::npos,
            "hysteria2 export must keep password");
}

// R1: overwrite_original_rules=false 时，base 模板已有规则须参与去重，
// 拉取到的同名规则（type+pattern 相同）不得重复输出
void test_ruleset_dedup_against_base_rules() {
    YAML::Node base = YAML::Load("rules:\n  - DOMAIN-SUFFIX,dup.com,DIRECT\n");

    RulesetContent rc;
    rc.rule_group = "PROXY";
    rc.rule_type = RULESET_SURGE;
    std::promise<std::string> pr;
    pr.set_value("DOMAIN-SUFFIX,dup.com\nDOMAIN-SUFFIX,unique.com");
    rc.rule_content = pr.get_future().share();

    std::vector<RulesetContent> rulesets{rc};
    const std::string out = rulesetToClashStr(base, rulesets, false, true);

    // dup.com 只能出现一次（来自 base，拉取的重复项被去重）
    size_t first = out.find("dup.com");
    require(first != std::string::npos, "base rule dup.com must be present");
    require(out.find("dup.com", first + 1) == std::string::npos,
            "duplicate rule matching a base rule must be deduplicated");
    // 非重复规则仍需正常输出
    require(out.find("DOMAIN-SUFFIX,unique.com,PROXY") != std::string::npos,
            "non-duplicate fetched rule must still be exported");
}

// xhttp + reality：reality 参数在 network 分支之外读取，两条信息必须同时存活。
// Clash 方向已由 test_formatter_short_id_preserves_xhttp_download_settings 覆盖，
// Xray JSON 方向由 test_v2ray_vless_xhttp_conf_preserves_transport 覆盖，此处补链接与 sing-box。
void test_vless_link_xhttp_reality_preserves_both() {
    const std::string content =
        "vless://12345678-1234-1234-1234-123456789012@xhttp.example.com:443"
        "?security=reality&type=xhttp&pbk=pubkey-link&sid=aabb1122&fp=firefox"
        "&sni=reality.example.com&host=cdn.example.com&path=%2Fxhttp&mode=stream-up"
        "#xhttp-reality-link";

    const Proxy node = parse_link(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.XhttpMode == "stream-up", "xhttp mode must survive alongside reality");
    require(node.Path == "/xhttp", "xhttp path must survive alongside reality");
    // host 是传输层 Host 头，sni 是 reality 握手域名，二者不可互相覆盖
    require(node.Host == "cdn.example.com", "xhttp Host must come from host=, not sni=");
    require(node.ServerName == "reality.example.com", "reality server name must come from sni=");
    require(node.PublicKey == "pubkey-link", "reality public key must survive alongside xhttp");
    require(node.ShortId == "aabb1122", "reality short id must survive alongside xhttp");
    require(node.ClientFingerprint == "firefox", "reality fingerprint must survive alongside xhttp");
    require(node.TLSSecure, "security=reality implies TLS");
}

// 空 host= 时 xhttp 的 Host 必须回退到 sni，与 Xray/mihomo 自身的回退顺序一致：
// Xray  splithttp/dialer.go: Host → tls.ServerName → reality.ServerName → 目标地址
// mihomo adapter/outbound/vless.go: XHTTPOpts.Host → ServerName → Server
// 落到服务器地址会跳过 SNI 这一级，Host 头与原生客户端不符。
void test_vless_link_xhttp_empty_host_falls_back_to_sni() {
    const std::string content =
        "vless://12345678-1234-1234-1234-123456789012@real.example.com:24218"
        "?security=reality&type=xhttp&pbk=pubkey-link&sid=d3e7"
        "&sni=masquerade.example.com&host=&path=%2Fhttp&mode=auto"
        "#xhttp-empty-host";

    const Proxy node = parse_link(content);
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.ServerName == "masquerade.example.com", "sni must still become the reality server name");
    require(node.Host == "masquerade.example.com",
            "empty host= must fall back to the sni, matching Xray/mihomo's own fallback order");
}

void test_singbox_vless_xhttp_reality_preserves_both() {
    const std::string content = R"({
  "inbounds": [],
  "outbounds": [
    {
      "type": "vless",
      "tag": "xhttp-reality",
      "server": "xhttp.example.com",
      "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012",
      "tls": {
        "enabled": true,
        "server_name": "reality.example.com",
        "utls": {
          "enabled": true,
          "fingerprint": "firefox"
        },
        "reality": {
          "enabled": true,
          "public_key": "pubkey-sb",
          "short_id": "ccdd3344"
        }
      },
      "transport": {
        "type": "xhttp",
        "host": "cdn.example.com",
        "path": "/xhttp",
        "mode": "packet-up"
      }
    }
  ],
  "route": {}
})";

    const Proxy node = parse_singbox(content);
    require(node.Type == ProxyType::VLESS, "expected VLESS node");
    require(node.TransferProtocol == "xhttp", "expected xhttp transport");
    require(node.XhttpMode == "packet-up", "xhttp mode must survive alongside reality");
    require(node.Path == "/xhttp", "xhttp path must survive alongside reality");
    require(node.Host == "cdn.example.com", "xhttp Host must come from transport.host");
    require(node.ServerName == "reality.example.com", "reality server name must come from tls.server_name");
    require(node.PublicKey == "pubkey-sb", "reality public key must survive alongside xhttp");
    require(node.ShortId == "ccdd3344", "reality short id must survive alongside xhttp");
    require(node.TLSSecure, "tls.reality implies TLS");
    require(node.ClientFingerprint == "firefox",
            "tls.utls.fingerprint must reach the node, not be replaced by the \"chrome\" default");
}

std::string render_all_base_clash(const string_map &globals) {
    std::ifstream file(std::string(TEST_SOURCE_DIR) + "/base/base/all_base.tpl", std::ios::binary);
    require(file.is_open(), "cannot open base/base/all_base.tpl");
    std::ostringstream buffer;
    buffer << file.rdbuf();

    template_args args;
    args.global_vars = globals;
    args.request_params["target"] = "clash";
    args.local_vars["clash.new_field_name"] = "true";

    std::string output;
    require(render_template(buffer.str(), args, output, "") == 0, "all_base.tpl render failed: " + output);
    return output;
}

void test_all_base_clash_node_domain_omitted_when_empty() {
    const std::string out = render_all_base_clash({{"clash.node_domain", ""}});
    // 留空时整条不输出，而不是输出一个只剩前缀的 "+."
    require(out.find("\"+.\"") == std::string::npos,
            "empty node_domain must not emit a fake-ip-filter entry");
}

void test_all_base_clash_node_domain_emitted_when_set() {
    const std::string out = render_all_base_clash({{"clash.node_domain", "example.com"}});
    YAML::Node doc = YAML::Load(out);

    bool found = false;
    for (const auto &item : doc["dns"]["fake-ip-filter"])
        found = found || item.as<std::string>() == "+.example.com";
    require(found, "node_domain must be emitted as \"+.<domain>\" in fake-ip-filter");
}

void test_all_base_clash_secret_with_quote_keeps_yaml_valid() {
    // 单引号是合法密码字符，早先的 secret: '{{ ... }}' 写法会让 YAML 解析失败
    const std::string secret = "ab'cd\"ef\\gh";
    const std::string out = render_all_base_clash({{"clash.secret", secret}});
    YAML::Node doc = YAML::Load(out);

    require(doc["secret"].as<std::string>() == secret, "secret must round-trip unchanged");
}

void test_all_base_clash_template_values_cannot_inject_yaml() {
    // 值里同时含引号和换行时，早先的写法可以闭合标量并追加任意字段
    const std::string secret = "x'\nmode: global\n#";
    const std::string domain = "ex.com\"\n    - \"+.evil.com";
    const std::string out = render_all_base_clash({{"clash.secret", secret}, {"clash.node_domain", domain}});
    YAML::Node doc = YAML::Load(out);

    require(doc["secret"].as<std::string>() == secret, "secret must round-trip unchanged");
    require(doc["mode"].as<std::string>() == "rule", "secret must not be able to override mode");

    for (const auto &item : doc["dns"]["fake-ip-filter"])
        require(item.as<std::string>() != "+.evil.com",
                "node_domain must not be able to inject extra fake-ip-filter entries");
}

} // namespace

int main() {
    try {
        test_vmess_conf_reads_mixed_case_wssettings();
        test_clash_ss_mux_pluginopts_do_not_duplicate();
        test_clash_round_trip_preserves_dialer_proxy();
        test_clash_vless_xhttp_export_preserves_transport();
        test_vless_xhttp_padding_link_mapping();
        test_clash_vless_xhttp_parse_preserves_transport();
        test_clash_vless_ws_reality_preserves_transport_host();
        test_clash_vless_h2_reality_preserves_transport_host();
        test_singbox_round_trip_preserves_detour_and_vless_encryption();
        test_vless_link_preserves_xhttp_transport();
        test_v2ray_vless_xhttp_conf_preserves_transport();
        test_v2ray_vless_tls_settings_preserve_sni_and_alpn();
        test_vless_xhttp_round_trip_preserves_type();
        test_singbox_vless_xhttp_preserves_transport();
        test_clash_vless_xhttp_sc_max_and_reuse_settings();
        test_clash_vless_xhttp_extra_exported_to_link();
        test_xray_download_settings_xmux_and_sc_max();
        test_clash_vless_xhttp_download_settings_full();
        test_clash_xhttp_doc_scalar_fields_roundtrip();
        test_clash_xhttp_download_settings_reality_opts_nested();
        test_clash_xhttp_doc_fields_exported_to_link_extra();
        test_clash_xhttp_padding_and_range_exported_to_link_extra();
        test_vless_link_extra_doc_fields_mapped_to_clash();
        test_clash_vless_tls_layer_opts_roundtrip();
        test_clash_xhttp_download_settings_tls_layer_opts();
        test_clash_vless_ech_keys_unified_to_ech_opts();
        test_xhttp_no_grpc_header_link_mapping();
        test_xhttp_h_keep_alive_period_xmux_mapping();
        test_vless_link_extra_scmax_xmux_mapped_to_clash();
        test_string_anchoring_survives_rule_generation_path();
        test_anchoring_skips_values_that_are_already_strings();
        test_clash_string_scalars_keep_string_type();
        test_clash_password_numeric_keeps_string_type();
        test_clash_string_anchor_beautify_in_flow_style();
        test_clash_vmess_padding_and_auth_length_roundtrip();
        test_singbox_vmess_padding_and_auth_length();
        test_clash_vless_omits_vmess_only_fields();
        test_clash_tls_cert_fields_roundtrip_all_protocols();
        test_vless_link_browser_fingerprint_not_leaked_as_cert_fingerprint();
        test_clash_reality_support_x25519mlkem768_roundtrip();
        test_clash_reality_omits_unset_x25519mlkem768();
        test_clash_download_settings_x25519mlkem768();
        test_clash_basic_option_dialer_fields_roundtrip();
        test_clash_basic_option_omits_unset_dialer_fields();
        test_singbox_dialer_fields_roundtrip();
        test_anytls_fingerprint_semantics_separated();
        test_anytls_link_fp_and_hpkp_separated();
        test_vless_trojan_link_fp_uses_client_fingerprint();
        test_hysteria_cert_fingerprint_roundtrip();
        test_vless_link_missing_or_unknown_type_falls_back_to_tcp();
        test_clash_unknown_network_falls_back_instead_of_dropping();
        test_singbox_packet_encoding_not_duplicated();
        test_clash_xhttp_headers_and_download_exported_to_link();
        test_xray_xhttp_settings_direct_fields_parsed();
        test_vless_link_extra_legacy_session_aliases();
        test_xray_download_settings_allow_insecure();
        test_download_settings_empty_tls_opts_preserved();
        test_xray_legacy_aliases_do_not_leak_into_link();
        test_link_nested_null_download_settings_does_not_fall_back();
        test_link_export_removes_all_duplicate_download_settings();
        test_link_extra_download_settings_is_parsed();
        test_link_nested_download_settings_wins_over_legacy_param();
        test_link_export_merges_download_settings_into_existing_extra();
        test_legacy_session_aliases_are_source_scoped();
        test_vless_link_invalid_download_settings_actually_drops_node();
        test_link_malformed_download_settings_drops_node();
        test_xray_download_settings_alpn_non_string_elements_are_safe();
        test_xray_download_settings_xtls_is_rejected();
        test_xray_non_object_xhttp_settings_rejected();
        test_xray_security_case_insensitive_and_unknown_rejected();
        test_download_settings_zero_and_null_conserved();
        test_download_settings_explicit_empty_all_fields_preserved();
        test_download_settings_reality_opts_three_states();
        test_clash_download_settings_omitted_from_link_but_node_kept();
        test_xray_download_settings_passthrough_untouched();
        test_xray_xhttp_extra_null_and_empty_still_replace();
        test_xray_xhttp_invalid_extra_rejects_node();
        test_xray_xhttp_download_settings_follows_extra();
        test_xray_xhttp_direct_fields_follow_official_names();
        test_xray_xhttp_extra_replaces_outer_fields();
        test_xray_xhttp_direct_official_fields();
        test_xray_download_settings_null_means_zero_not_inherit();
        test_xray_download_settings_absent_key_means_inherit();
        test_xray_download_settings_missing_security_means_no_tls();
        test_xray_download_settings_explicit_values_preserved();
        test_clash_download_settings_explicit_empty_preserved();
        test_quanx_export_skips_vless_xhttp_node();
        test_proxy_group_toml_extras_preserve_scalar_types();
        test_proxy_group_trailing_provider_is_not_treated_as_extra();
        test_ruleset_format_is_parsed_and_validated();
        test_quanx_export_preserves_vless_reality();
        test_quanx_export_preserves_vless_wss_reality();
        test_clash_vless_xhttp_reuse_settings_h_keep_alive_period();
        test_clash_vless_xhttp_sc_max_range_passthrough();
        test_clash_vless_grpc_new_opts();
        test_formatter_short_id_preserves_xhttp_download_settings();
        test_vless_link_ws_host_and_sni_distinct();
        test_vless_client_fingerprint_output();
        test_hysteria2_link_port_hopping_and_password_decode();
        test_mieru_plaintext_link();
        test_anytls_clash_roundtrip_fields();
        test_hysteria2_export_omits_nonstandard_fields();
        test_ruleset_dedup_against_base_rules();
        test_vless_link_xhttp_reality_preserves_both();
        test_vless_link_xhttp_empty_host_falls_back_to_sni();
        test_singbox_vless_xhttp_reality_preserves_both();
        test_all_base_clash_node_domain_omitted_when_empty();
        test_all_base_clash_node_domain_emitted_when_set();
        test_all_base_clash_secret_with_quote_keeps_yaml_valid();
        test_all_base_clash_template_values_cannot_inject_yaml();
    } catch (const std::exception &e) {
        std::cerr << "pr4_regression_test failed: " << e.what() << '\n';
        return 1;
    }

    std::cout << "pr4_regression_test passed\n";
    return 0;
}

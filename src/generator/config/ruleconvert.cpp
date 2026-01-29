#include <string>
#include <unordered_set>

#include "handler/settings.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/rapidjson_extra.h"
#include "subexport.h"

/// rule type lists
#define basic_types "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR", "GEOIP", "MATCH", "FINAL"
// 新增meta路由规则
//string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME"};
string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "DOMAIN-REGEX", "GEOSITE", "IP-SUFFIX", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-SUFFIX", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "PROCESS-PATH-REGEX", "PROCESS-PATH", "PROCESS-NAME-REGEX", "UID", "NETWORK", "DSCP", "SUB-RULE", "RULE-SET", "AND", "OR", "NOT"};
string_array Surge2RuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SurgeRuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array QuanXRuleTypes = {basic_types, "USER-AGENT", "HOST", "HOST-SUFFIX", "HOST-KEYWORD"};
string_array SurfRuleTypes = {basic_types, "IP-CIDR6", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SingBoxRuleTypes = {basic_types, "IP-VERSION", "INBOUND", "PROTOCOL", "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT", "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID"};

/// IP 类规则类型，这些规则需要检查 no-resolve flag
static const string_array IpRuleTypes = {"IP-CIDR", "IP-CIDR6", "GEOIP", "SRC-IP-CIDR", "SRC-GEOIP", "SRC-IP-ASN", "IP-SUFFIX", "SRC-IP-SUFFIX", "IP-ASN"};

/// 提取规则去重 key
/// 去重 key = 规则匹配条件（不含策略组，但保留匹配相关的 flag）
/// 返回小写归一化的 key，确保大小写不同的相同规则被正确去重
static std::string extractRuleKey(const std::string &rule)
{
    if(rule.empty())
        return "";

    // 特判 AND/OR/NOT 规则
    // 格式：TYPE,(...expression...),group
    if(startsWith(rule, "AND") || startsWith(rule, "OR") || startsWith(rule, "NOT"))
    {
        // 找到第一个 ,( 的位置
        auto exprStart = rule.find(",(");
        if(exprStart == std::string::npos)
            return toLower(rule); // 格式异常，返回原规则

        // 从末尾向前找最后一个 ) 的位置
        auto exprEnd = rule.rfind(')');
        if(exprEnd == std::string::npos || exprEnd <= exprStart)
            return toLower(rule); // 格式异常，返回原规则

        // key = TYPE + 从 exprStart 到 exprEnd（含括号）的内容
        return toLower(rule.substr(0, exprEnd + 1));
    }

    // 按逗号分割
    string_view_array parts;
    split(parts, rule, ',');
    if(parts.empty())
        return "";

    std::string type(parts[0]);

    // 特判无 pattern 规则：MATCH 或 FINAL
    if(type == "MATCH" || type == "FINAL")
        return toLower(type);

    // 至少需要两部分：TYPE,pattern
    if(parts.size() < 2)
        return toLower(rule);

    std::string pattern(parts[1]);

    // RULE-SET / SUB-RULE 规则
    // 格式：TYPE,url/name,group[,配置参数...]
    // key = TYPE,url/name
    if(type == "RULE-SET" || type == "SUB-RULE")
        return toLower(type + "," + pattern);

    // 普通规则
    // 格式：TYPE,pattern[,group][,flag]
    std::string key = type + "," + pattern;

    // 判断是否为 IP 类规则
    bool isIpType = std::any_of(IpRuleTypes.begin(), IpRuleTypes.end(),
        [&type](const std::string &t) { return type == t; });

    // IP 类规则检查 no-resolve flag
    if(isIpType && parts.size() > 2)
    {
        for(size_t i = 2; i < parts.size(); i++)
        {
            if(parts[i] == "no-resolve")
            {
                key += ",no-resolve";
                break;
            }
        }
    }

    return toLower(key);
}

std::string convertRuleset(const std::string &content, int type)
{
    /// Target: Surge type,pattern[,flag]
    /// Source: QuanX type,pattern[,group]
    ///         Clash payload:\n  - 'ipcidr/domain/classic(Surge-like)'

    std::string output, strLine;

    if(type == RULESET_SURGE)
        return content;

    if(regFind(content, "^payload:\\r?\\n")) /// Clash
    {
        output = regReplace(regReplace(content, "payload:\\r?\\n", "", true), R"(\s?^\s*-\s+('|"?)(.*)\1$)", "\n$2", true);
        if(type == RULESET_CLASH_CLASSICAL) /// classical type
            return output;
        std::stringstream ss;
        ss << output;
        char delimiter = getLineBreak(output);
        output.clear();
        string_size pos, lineSize;
        while(getline(ss, strLine, delimiter))
        {
            strLine = trim(strLine);
            lineSize = strLine.size();
            if(lineSize && strLine[lineSize - 1] == '\r') //remove line break
                strLine.erase(--lineSize);

            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            if(!strLine.empty() && (strLine[0] != ';' && strLine[0] != '#' && !(lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')))
            {
                pos = strLine.find('/');
                if(pos != std::string::npos) /// ipcidr
                {
                    if(isIPv4(strLine.substr(0, pos)))
                        output += "IP-CIDR,";
                    else
                        output += "IP-CIDR6,";
                }
                else
                {
                    if(strLine[0] == '.' || (lineSize >= 2 && strLine[0] == '+' && strLine[1] == '.')) /// suffix
                    {
                        bool keyword_flag = false;
                        while(endsWith(strLine, ".*"))
                        {
                            keyword_flag = true;
                            strLine.erase(strLine.size() - 2);
                        }
                        output += "DOMAIN-";
                        if(keyword_flag)
                            output += "KEYWORD,";
                        else
                            output += "SUFFIX,";
                        strLine.erase(0, 2 - (strLine[0] == '.'));
                    }
                    else
                        output += "DOMAIN,";
                }
            }
            output += strLine;
            output += '\n';
        }
        return output;
    }
    else /// QuanX
    {
        output = regReplace(regReplace(content, "^(?i:host)", "DOMAIN", true), "^(?i:ip6-cidr)", "IP-CIDR6", true); //translate type
        output = regReplace(output, "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$", "\\U$1\\E$2${3:-}", true); //remove group
        return output;
    }
}

static std::string transformRuleToCommon(string_view_array &temp, const std::string &input, const std::string &group, bool no_resolve_only = false)
{
    temp.clear();
    std::string strLine;
    split(temp, input, ',');
    if(temp.size() < 2)
    {
        strLine = temp[0];
        strLine += ",";
        strLine += group;
    }
    else
    {
        strLine = temp[0];
        strLine += ",";
        strLine += temp[1];
        strLine += ",";
        strLine += group;
        if(temp.size() > 2 && (!no_resolve_only || temp[2] == "no-resolve"))
        {
            strLine += ",";
            strLine += temp[2];
        }
    }
    return strLine;
}

void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name)
{
    string_array allRules;
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    YAML::Node rules;
    size_t total_rules = 0;
    std::unordered_set<std::string> seenKeys; // 去重用的 seen set

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
        rules = base_rule[field_name];

    std::vector<std::string_view> temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL"))
                strLine.replace(0, 5, "MATCH");
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            // 去重检查
            std::string key = extractRuleKey(strLine);
            if(seenKeys.find(key) == seenKeys.end())
            {
                seenKeys.insert(key);
                allRules.emplace_back(strLine);
                total_rules++;
            }
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            // 去重检查
            std::string key = extractRuleKey(strLine);
            if(seenKeys.find(key) == seenKeys.end())
            {
                seenKeys.insert(key);
                allRules.emplace_back(strLine);
                total_rules++;
            }
        }
    }

    for(std::string &x : allRules)
    {
        rules.push_back(x);
    }

    base_rule[field_name] = rules;
}

std::string rulesetToClashStr(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name)
{
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    std::string output_content = "\n" + field_name + ":\n";
    size_t total_rules = 0;
    std::unordered_set<std::string> seenKeys; // 去重用的 seen set

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        for(size_t i = 0; i < base_rule[field_name].size(); i++)
            output_content += "  - " + safe_as<std::string>(base_rule[field_name][i]) + "\n";
    }
    base_rule.remove(field_name);

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL"))
                strLine.replace(0, 5, "MATCH");
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            // 去重检查
            std::string key = extractRuleKey(strLine);
            if(seenKeys.find(key) == seenKeys.end())
            {
                seenKeys.insert(key);
                output_content += "  - " + strLine + "\n";
                total_rules++;
            }
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){ return startsWith(strLine, type); }))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            std::string finalRule;
            //AND & OR & NOT
            if(startsWith(strLine, "AND") || startsWith(strLine, "OR") || startsWith(strLine, "NOT"))
            {
                finalRule = strLine + "," + rule_group;
            }
            //SUB-RULE & RULE-SET
            else if (startsWith(strLine, "SUB-RULE") || startsWith(strLine, "RULE-SET"))
            {
                finalRule = strLine;
            }
            else
            //OTHER
            {
                finalRule = transformRuleToCommon(temp, strLine, rule_group);
            }

            // 去重检查
            std::string key = extractRuleKey(finalRule);
            if(seenKeys.find(key) == seenKeys.end())
            {
                seenKeys.insert(key);
                output_content += "  - " + finalRule + "\n";
                total_rules++;
            }
        }
    }
    return output_content;
}

void rulesetToSurge(INIReader &base_rule, std::vector<RulesetContent> &ruleset_content_array, int surge_ver, bool overwrite_original_rules, const std::string &remote_path_prefix)
{
    string_array allRules;
    std::string rule_group, rule_path, rule_path_typed, retrieved_rules, strLine;
    std::stringstream strStrm;
    size_t total_rules = 0;
    std::unordered_set<std::string> seenKeys; // 去重用的 seen set，路径 A 和路径 B 共用

    switch(surge_ver) //other version: -3 for Surfboard, -4 for Loon
    {
    case 0:
        base_rule.set_current_section("RoutingRule"); //Mellow
        break;
    case -1:
        base_rule.set_current_section("filter_local"); //Quantumult X
        break;
    case -2:
        base_rule.set_current_section("TCP"); //Quantumult
        break;
    default:
        base_rule.set_current_section("Rule");
    }

    if(overwrite_original_rules)
    {
        base_rule.erase_section();
        switch(surge_ver)
        {
        case -1:
            base_rule.erase_section("filter_remote");
            break;
        case -4:
            base_rule.erase_section("Remote Rule");
            break;
        default:
            break;
        }
    }

    const std::string rule_match_regex = "^(.*?,.*?)(,.*)(,.*)$";

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        rule_path = x.rule_path;
        rule_path_typed = x.rule_path_typed;
        if(rule_path.empty())
        {
            strLine = x.rule_content.get().substr(2);
            if(strLine == "MATCH")
                strLine = "FINAL";
            if(surge_ver == -1 || surge_ver == -2)
            {
                strLine = transformRuleToCommon(temp, strLine, rule_group, true);
            }
            else
            {
                if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                    strLine = transformRuleToCommon(temp, strLine, rule_group);
            }
            strLine = replaceAllDistinct(strLine, ",,", ",");
            // 去重检查
            std::string key = extractRuleKey(strLine);
            if(seenKeys.find(key) == seenKeys.end())
            {
                seenKeys.insert(key);
                allRules.emplace_back(strLine);
                total_rules++;
            }
            continue;
        }
        else
        {
            if(surge_ver == -1 && x.rule_type == RULESET_QUANX && isLink(rule_path))
            {
                strLine = rule_path + ", tag=" + rule_group + ", force-policy=" + rule_group + ", enabled=true";
                // 去重检查：remote rule 使用 url 作为 key
                std::string key = rule_path;
                if(seenKeys.find(key) == seenKeys.end())
                {
                    seenKeys.insert(key);
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                }
                continue;
            }
            if(fileExist(rule_path))
            {
                if(surge_ver > 2 && !remote_path_prefix.empty())
                {
                    strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);
                    // 去重检查
                    std::string key = extractRuleKey(strLine);
                    if(seenKeys.find(key) == seenKeys.end())
                    {
                        seenKeys.insert(key);
                        allRules.emplace_back(strLine);
                    }
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    // 去重检查：remote rule 使用 url 作为 key
                    std::string key = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed);
                    if(seenKeys.find(key) == seenKeys.end())
                    {
                        seenKeys.insert(key);
                        base_rule.set("filter_remote", "{NONAME}", strLine);
                    }
                    continue;
                }
                else if(surge_ver == -4 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    // 去重检查：remote rule 使用 url 作为 key
                    std::string key = remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed);
                    if(seenKeys.find(key) == seenKeys.end())
                    {
                        seenKeys.insert(key);
                        base_rule.set("Remote Rule", "{NONAME}", strLine);
                    }
                    continue;
                }
            }
            else if(isLink(rule_path))
            {
                if(surge_ver > 2)
                {
                    if(x.rule_type != RULESET_SURGE)
                    {
                        if(!remote_path_prefix.empty())
                            strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                        else
                            continue;
                    }
                    else
                        strLine = "RULE-SET," + rule_path + "," + rule_group;

                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);

                    // 去重检查
                    std::string key = extractRuleKey(strLine);
                    if(seenKeys.find(key) == seenKeys.end())
                    {
                        seenKeys.insert(key);
                        allRules.emplace_back(strLine);
                    }
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    // 去重检查：remote rule 使用 url 作为 key
                    std::string key = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed);
                    if(seenKeys.find(key) == seenKeys.end())
                    {
                        seenKeys.insert(key);
                        base_rule.set("filter_remote", "{NONAME}", strLine);
                    }
                    continue;
                }
                else if(surge_ver == -4)
                {
                    strLine = rule_path + "," + rule_group;
                    // 去重检查：remote rule 使用 url 作为 key
                    std::string key = rule_path;
                    if(seenKeys.find(key) == seenKeys.end())
                    {
                        seenKeys.insert(key);
                        base_rule.set("Remote Rule", "{NONAME}", strLine);
                    }
                    continue;
                }
            }
            else
                continue;
            retrieved_rules = x.rule_content.get();
            if(retrieved_rules.empty())
            {
                writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
                continue;
            }

            retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
            char delimiter = getLineBreak(retrieved_rules);

            strStrm.clear();
            strStrm<<retrieved_rules;
            std::string::size_type lineSize;
            while(getline(strStrm, strLine, delimiter))
            {
                if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                    break;
                strLine = trimWhitespace(strLine, true, true);
                lineSize = strLine.size();
                if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                    continue;

                /// remove unsupported types
                switch(surge_ver)
                {
                case -2:
                    if(startsWith(strLine, "IP-CIDR6"))
                        continue;
                    [[fallthrough]];
                case -1:
                    if(!std::any_of(QuanXRuleTypes.begin(), QuanXRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                case -3:
                    if(!std::any_of(SurfRuleTypes.begin(), SurfRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                default:
                    if(surge_ver > 2)
                    {
                        if(!std::any_of(SurgeRuleTypes.begin(), SurgeRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                    else
                    {
                        if(!std::any_of(Surge2RuleTypes.begin(), Surge2RuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                }

                if(strFind(strLine, "//"))
                {
                    strLine.erase(strLine.find("//"));
                    strLine = trimWhitespace(strLine);
                }

                if(surge_ver == -1 || surge_ver == -2)
                {
                    if(startsWith(strLine, "IP-CIDR6"))
                        strLine.replace(0, 8, "IP6-CIDR");
                    strLine = transformRuleToCommon(temp, strLine, rule_group, true);
                }
                else
                {
                    if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                        strLine = transformRuleToCommon(temp, strLine, rule_group);
                }
                // 去重检查
                std::string key = extractRuleKey(strLine);
                if(seenKeys.find(key) == seenKeys.end())
                {
                    seenKeys.insert(key);
                    allRules.emplace_back(strLine);
                    total_rules++;
                }
            }
        }
    }

    for(std::string &x : allRules)
    {
        base_rule.set("{NONAME}", x);
    }
}

static rapidjson::Value transformRuleToSingBox(std::vector<std::string_view> &args, const std::string& rule, const std::string &group, rapidjson::MemoryPoolAllocator<>& allocator)
{
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2) return rapidjson::Value(rapidjson::kObjectType);
    auto type = toLower(std::string(args[0]));
    auto value = toLower(std::string(args[1]));
//    std::string_view option;
//    if (args.size() >= 3) option = args[2];

    rapidjson::Value rule_obj(rapidjson::kObjectType);
    type = replaceAllDistinct(type, "-", "_");
    type = replaceAllDistinct(type, "ip_cidr6", "ip_cidr");
    type = replaceAllDistinct(type, "src_", "source_");
    if (type == "match" || type == "final")
    {
        rule_obj.AddMember("outbound", rapidjson::Value(value.data(), value.size(), allocator), allocator);
    }
    else
    {
        rule_obj.AddMember(rapidjson::Value(type.c_str(), allocator), rapidjson::Value(value.data(), value.size(), allocator), allocator);
        rule_obj.AddMember("outbound", rapidjson::Value(group.c_str(), allocator), allocator);
    }
    return rule_obj;
}

static void appendSingBoxRule(std::vector<std::string_view> &args, rapidjson::Value &rules, const std::string& rule, rapidjson::MemoryPoolAllocator<>& allocator)
{
    using namespace rapidjson_ext;
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2) return;
    auto type = args[0];
//    std::string_view option;
//    if (args.size() >= 3) option = args[2];

    if (none_of(SingBoxRuleTypes, [&](const std::string& t){ return type == t; }))
        return;

    auto realType = toLower(std::string(type));
    auto value = toLower(std::string(args[1]));
    realType = replaceAllDistinct(realType, "-", "_");
    realType = replaceAllDistinct(realType, "ip_cidr6", "ip_cidr");

    rules | AppendToArray(realType.c_str(), rapidjson::Value(value.c_str(), value.size(), allocator), allocator);
}

void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules)
{
    using namespace rapidjson_ext;
    std::string rule_group, retrieved_rules, strLine, final;
    std::stringstream strStrm;
    size_t total_rules = 0;
    auto &allocator = base_rule.GetAllocator();

    rapidjson::Value rules(rapidjson::kArrayType);
    if (!overwrite_original_rules)
    {
        if (base_rule.HasMember("route") && base_rule["route"].HasMember("rules") && base_rule["route"]["rules"].IsArray())
            rules.Swap(base_rule["route"]["rules"]);
    }

    if (global.singBoxAddClashModes)
    {
        auto global_object = buildObject(allocator, "clash_mode", "Global", "outbound", "GLOBAL");
        auto direct_object = buildObject(allocator, "clash_mode", "Direct", "outbound", "DIRECT");
        rules.PushBack(global_object, allocator);
        rules.PushBack(direct_object, allocator);
    }

    // auto dns_object = buildObject(allocator, "protocol", "dns", "outbound", "dns-out");
    // rules.PushBack(dns_object, allocator);

    std::vector<std::string_view> temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL") || startsWith(strLine, "MATCH"))
            {
                final = rule_group;
                continue;
            }
            rules.PushBack(transformRuleToSingBox(temp, strLine, rule_group, allocator), allocator);
            total_rules++;
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;

        std::string::size_type lineSize;
        rapidjson::Value rule(rapidjson::kObjectType);

        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            appendSingBoxRule(temp, rule, strLine, allocator);
        }
        if (rule.ObjectEmpty()) continue;
        rule.AddMember("outbound", rapidjson::Value(rule_group.c_str(), allocator), allocator);
        rules.PushBack(rule, allocator);
    }

    if (!base_rule.HasMember("route"))
        base_rule.AddMember("route", rapidjson::Value(rapidjson::kObjectType), allocator);

    auto finalValue = rapidjson::Value(final.c_str(), allocator);
    base_rule["route"]
    | AddMemberOrReplace("rules", rules, allocator)
    | AddMemberOrReplace("final", finalValue, allocator);
}

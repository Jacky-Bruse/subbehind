# 规则去重实现方案（非 Sing-box）

## 目标

- 在最终输出的 rules 规则列表中进行去重：基于规则匹配条件判定，保留首条，删除后续重复项，顺序不变。
- 适用范围：Clash / Surge / QuanX / Mellow / Surfboard / Loon。
- 当前配置为 overwrite_original_rules=true，因此最终规则仅来自 ruleset；模板原有 rules 不参与最终输出。

## 去重 key 定义

去重 key = **规则匹配条件**（不含策略组，但保留匹配相关的 flag）。

理由：相同匹配条件的规则，即使分配到不同策略组，也只有第一条会生效，后续的是"死规则"。

### Flag 定义

**匹配 flag**：影响规则匹配行为的标志，计入 key。
- `no-resolve` — 仅适用于 IP 类规则，跳过 DNS 解析

**配置参数**：影响规则集配置，不计入 key。
- `update-interval` — RULE-SET 的更新间隔

**适用规则类型**：

| 规则类型 | 可能的 flag |
|----------|-------------|
| IP-CIDR, IP-CIDR6, GEOIP, SRC-IP-CIDR 等 IP 类 | `no-resolve` |
| DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD 等域名类 | 无 |
| PROCESS-NAME, USER-AGENT 等 | 无 |
| RULE-SET, SUB-RULE | 无（附加参数不算 flag） |
| AND, OR, NOT | 无 |

### 提取规则示例

| 原始规则 | 去重 key |
|----------|----------|
| `DOMAIN,x.com,GroupA` | `DOMAIN,x.com` |
| `DOMAIN,x.com,GroupB` | `DOMAIN,x.com` |
| `IP-CIDR,1.1.1.0/24,GroupA,no-resolve` | `IP-CIDR,1.1.1.0/24,no-resolve` |
| `IP-CIDR,1.1.1.0/24,GroupB` | `IP-CIDR,1.1.1.0/24` |
| `GEOIP,CN,GroupA,no-resolve` | `GEOIP,CN,no-resolve` |
| `MATCH,GroupA` | `MATCH` |
| `FINAL,GroupB` | `FINAL` |
| `RULE-SET,http://x.com/rules,GroupA` | `RULE-SET,http://x.com/rules` |
| `RULE-SET,http://x.com/rules,GroupA,update-interval=86400` | `RULE-SET,http://x.com/rules` |
| `AND,((DOMAIN,a),(DOMAIN,b)),GroupA` | `AND,((DOMAIN,a),(DOMAIN,b))` |

### 辅助函数 extractRuleKey()

需实现静态函数提取去重 key，按规则类型分别处理：

#### 普通规则

格式：`TYPE,pattern[,group][,flag]`

提取逻辑：
1. 按逗号分割，取 `TYPE`（第 0 段）
2. **特判无 pattern 规则**：如果 TYPE 是 MATCH 或 FINAL，key 直接为 TYPE，结束
3. 取 `pattern`（第 1 段）
4. 判断 TYPE 是否为 IP 类规则（IP-CIDR, IP-CIDR6, GEOIP, SRC-IP-CIDR 等）
5. 如果是 IP 类，检查剩余段是否包含 `no-resolve`，有则追加到 key
6. 非 IP 类规则不检查 flag

```
输入: MATCH,GroupA
      TYPE=MATCH (无pattern规则), 直接返回
key:  MATCH

输入: IP-CIDR,1.0.0.0/8,GroupA,no-resolve
      TYPE=IP-CIDR (IP类), 检查flag
      -> 发现 no-resolve, 保留
key:  IP-CIDR,1.0.0.0/8,no-resolve

输入: DOMAIN,x.com,GroupA
      TYPE=DOMAIN (非IP类), 不检查flag
key:  DOMAIN,x.com
```

#### AND/OR/NOT 规则

格式：`TYPE,(...expression...),group`

前提假设：输入已经过 trimWhitespace 处理，逗号后无多余空白。

提取逻辑（不能简单按逗号 split，因为括号内有逗号）：
1. 找到第一个 `,(` 的位置，记为 exprStart
2. 从末尾向前找最后一个 `)` 的位置，记为 exprEnd
3. key = `TYPE` + 从 exprStart 到 exprEnd（含括号）的内容

```
输入: AND,((DOMAIN,a),(DOMAIN,b)),GroupA
      ^  ^                      ^
      |  exprStart              exprEnd
key:  AND,((DOMAIN,a),(DOMAIN,b))
```

#### RULE-SET / SUB-RULE 规则

格式：`TYPE,url/name,group[,配置参数...]`

提取逻辑：
1. 按逗号分割
2. 取前两部分 `TYPE,url/name`
3. 忽略 group 和配置参数（如 `update-interval`）

```
输入: RULE-SET,http://x.com/rules,GroupA,update-interval=86400
key:  RULE-SET,http://x.com/rules
```

## 方案

### 数据结构

使用 `std::unordered_set<std::string>` 存储已见规则 key，O(1) 平均查找/插入复杂度。

### 接入点

在 `src/generator/config/ruleconvert.cpp` 内新增通用去重助手，在规则生成路径中接入去重：

#### rulesetToClash

- 对 `allRules` 的加入做去重
- 独立维护 seen set

#### rulesetToClashStr

- 对输出行做去重（包括 AND/OR/NOT、SUB-RULE、RULE-SET 等分支）
- 独立维护 seen set
- 与 rulesetToClash 互斥调用，无需跨函数共享 seen

#### rulesetToSurge

- **路径 A**：`allRules.emplace_back()` — 第 342、361、395、481 行
- **路径 B**：`base_rule.set()` — 第 351、368、374、402、408 行（filter_remote / Remote Rule）
- **两条路径共用同一个 seen set**，实现跨 section 去重
- remote rule 的 key 提取：取 url 部分

### 去重判定

- 基于 key 判定，不含策略组
- 不做大小写、空白归一化，仅 key 完全一致才算重复

## overwrite_original_rules=false 的处理

当前配置为 true，暂不涉及此场景。

未来如果改为 false：
- 应先将模板原有规则提取 key 并加入 seen set
- 然后处理 ruleset，与模板重复的规则也会被去除

## 不在本次范围

- Sing-box 规则去重暂不处理
- 大小写/空白归一化

## 风险

- 规则来源多样且格式差异大，key 提取逻辑需覆盖各种规则类型
- AND/OR/NOT 规则嵌套括号可能存在边界情况，需充分测试

## 验证

- 使用当前 ruleset 列表生成配置，检查重复来源（如 dnsproxy.list 重复引用）仅保留第一次出现
- 对比生成前后规则顺序，确认顺序不变
- 覆盖 Clash 与 Surge 系列输出格式各生成一次，检查规则段无重复项
- 测试同规则不同策略组的场景，确认只保留第一条
- 测试 IP 类规则有/无 no-resolve 的场景，确认不被误判为重复
- 测试 MATCH/FINAL 不同策略组的场景，确认正确去重
- 测试 AND/OR/NOT 嵌套规则的去重
- 测试 RULE-SET 带 update-interval 的去重
- 测试 rulesetToSurge 跨 section（本地规则与 remote rule）的去重

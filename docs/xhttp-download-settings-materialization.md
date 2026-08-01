# XHTTP Download Settings Canonical 与完整物化方案

## 0. 实施范围（2026-07-31 确定）

本文档整体作为设计存档保留，但**当前阶段只实施其中一部分**。

**已实施：**

- 撤除 Clash → VLESS URI 方向的 download-settings 生成。链接导出仅原样透传
  Xray 输入的 downloadSettings；Clash 侧的 download-settings 不再合成，跳过时
  记录警告日志（含节点名），节点本身照常导出——丢的只是一项可选的下行优化。

**待实施（与物化解耦，可独立落地）：**

- 第 3 节 canonical 三态（`""` / `{}` / 其他）
- 第 4.2 节 主 reuse-settings 的存在性保真
- canonical 定义为完整、可前向兼容的 Mihomo Map：解析 download-settings 时保留
  全部字段而非白名单过滤，使 mihomo 将来新增字段能自动透传；严格的可转换性
  检查放在物化边界，而不是由解析器决定字段是否存在

**暂不实施：**

- 第 5 至 11 节的完整物化。理由是主链路为「VLESS 链接 → 转换 → Mihomo 配置」，
  物化处理的是反方向，不在该链路上；而不完整的物化会产出看似完整、实际缺少
  父 path/host/headers/reuse 的下行配置，比不生成更危险。
- 第 4.1 节的原始 host 保真。它是为物化提供「父 raw XHTTP host」而设，物化撤除
  后失去用途，链接解析的 sni 回退保持现状不动。

将来若需要 Clash → 链接方向，按第 5 至 11 节实施即可，设计无需重做。

**范围之外：** 本方案不含 sing-box 方向。

**关于安全模式的分类（讨论结论，供物化实施时参考）：**

- 协议不可表达、必须失败：ShadowTLS、Restls、JLS。忽略后通常无法连接。
- 能力可能降级、允许导出：support-x25519mlkem768。保留 pbk/sid/fp 并继续生成
  链接，记录警告即可，不因此跳过整个节点。
- pqv / mldsa65Verify：mihomo 尚不支持，不增加解析、存储与导出，待其正式支持
  后再补。

## 1. 目标

本方案用于在 Mihomo/Clash 的 **xhttp-opts.download-settings** 与 VLESS URI 中的 Xray **extra.downloadSettings** 之间建立无歧义、可验证的转换链路。

核心保证：

- download-settings 的“缺失”和“存在但为空”必须严格区分；
- Mihomo 的继承模型必须先展开为实际有效配置，再编码成独立的 Xray StreamConfig；
- 显式空字符串、false、0、空数组和空对象不得退化为继承；
- 能严格等价表达的配置才允许转换；
- 无法严格表达时必须明确失败，禁止静默丢字段或生成部分正确的链接。

## 2. 转换边界

项目内部保留两种 download-settings 表示：

| 字段 | 内容 | 用途 |
|---|---|---|
| **XhttpDownloadSettings** | 原始 Xray StreamConfig JSON | Xray/VLESS URI 输入的无损透传 |
| **XhttpDownload** | Mihomo canonical JSON | Clash/Mihomo 输入的语义化存储与物化 |

导出 VLESS URI 时的优先级固定为：

1. XhttpDownloadSettings 非空：原样使用 Xray JSON，不进行物化；
2. XhttpDownload 非空：物化为完整的 Xray StreamConfig；
3. 两者均为空：不输出 extra.downloadSettings。

物化函数只负责：

~~~text
Mihomo canonical download-settings
    + Mihomo 主节点配置
    → 实际有效下行配置
    → 独立 Xray StreamConfig
~~~

extra 的解析、保留和 downloadSettings 成员替换由链接导出层统一负责，物化函数不处理 extra。

## 3. Canonical 三态契约

XhttpDownload 使用现有字符串即可表达三种状态：

| XhttpDownload | 语义 |
|---|---|
| 空字符串 | download-settings 不存在 |
| **{}** | download-settings 存在，所有字段继承主节点 |
| 其他 JSON 对象 | download-settings 存在，并按成员覆盖主节点 |

### 3.1 Clash → canonical

clashDownloadToMihomoJson 必须按以下规则处理：

~~~text
YAML 未定义、null 或非 Map → 空字符串
YAML 空 Map                → {}
YAML 非空 Map              → 对应 canonical JSON
~~~

只要输入是已定义的 Map，就必须序列化，包括空 Map。不得使用输出对象是否为空来判断 download-settings 是否存在。

### 3.2 canonical → Clash

addXhttpDownloadToYaml 必须按以下规则处理：

~~~text
download_json 为空 → 不写 download-settings
download_json 有效 → 始终写 download-settings，包括 {}
~~~

输出条件必须依据 canonical 字符串是否存在，不能依据生成的 YAML Map 是否包含成员。

### 3.3 原子落地要求

“{}” canonical 会触发完整物化，因此 canonical 三态与新物化实现必须同时启用。不得先让空 Map 进入现有的不完整物化路径。

## 4. 父节点状态保真

完整物化的前提是 Proxy 中保存的父节点状态足以还原 Mihomo 的实际行为。

### 4.1 保存原始 XHTTP host

XHTTP 解析阶段必须保存用户配置的原始 host，包括空字符串。不得在 vlessConstruct 中提前把空 host 替换为 server。

最终有效 host 由物化阶段统一计算：

~~~text
下行 host 覆盖
→ 主 XHTTP 原始 host
→ 有效 servername
→ 有效 server
~~~

如果解析阶段已经把空 host 改成 server，物化阶段将无法判断该 server 是用户显式值还是解析器补出的值，也无法正确经过 servername 回退。

### 4.2 保存主 reuse-settings 的存在性

主节点 reuse-settings 需要区分：

~~~text
XhttpReuseSettings 为空 → 未配置
XhttpReuseSettings 为 {} → 显式空对象
~~~

使用现有字符串字段即可，不需要新增布尔字段。

### 4.3 其他父状态

下列状态必须继续保留：

- 空 headers Map；
- 显式 no-grpc-header: false；
- TLS 选项空对象；
- Reality 的显式 false/空值状态；
- ALPN 空数组。

只保留会影响实际运行行为或继承判断的存在性，不新增无运行时差异的状态模型。

## 5. 物化函数接口

建议使用一个明确区分成功与失败的返回类型：

~~~cpp
struct DownloadMaterializationResult {
    std::string json;
    std::string error;
};

DownloadMaterializationResult materializeMihomoDownload(
    const Proxy &parent,
    const std::string &canonical);
~~~

约定：

- error 为空：物化成功，json 为完整 Xray StreamConfig；
- error 非空：配置无效或无法无损表达，json 必须为空；
- 调用方只在 canonical 非空时调用，因此函数不承担“download-settings 不存在”的状态。

除主函数外，只保留两个职责明确的内部 helper：

~~~text
buildParentProxySnapshot()
buildParentXrayXhttpSettings()
~~~

允许增加一个 JSON 成员整体替换辅助函数。无需新增类层级、接口或大型 nullable 数据结构，也无需扩展 Proxy。

## 6. 构造父代理快照

先使用 Mihomo canonical 字段名构造父节点快照 effective：

~~~text
server
port
tls
alpn
servername
client-fingerprint
skip-cert-verify
name-cert-verify
fingerprint
certificate
private-key
ech-opts
shadow-tls-opts
restls-opts
jls-opts
reality-opts
~~~

字段来源：

| canonical 字段 | Proxy 来源 |
|---|---|
| server | Hostname |
| port | Port |
| tls | TLSSecure |
| alpn | AlpnList |
| servername | ServerName |
| client-fingerprint | ClientFingerprint |
| skip-cert-verify | AllowInsecure |
| fingerprint | CertFingerprint |
| certificate | Certificate |
| private-key | PrivateKeyPem |
| reality-opts | PublicKey、ShortId、SupportX25519MLKEM768 |
| TLS 扩展对象 | MihomoTlsOpts |

MihomoTlsOpts 中的 ech-opts 优先于旧的 EchEnable/EchConfig 字段，保持与 Clash 导出逻辑相同的优先级。

父快照表示实际继承默认值，因此基础值应完整建立：

- ALPN 使用数组表示，包括空数组；
- skip-cert-verify 使用明确布尔值；
- servername 和 client fingerprint 可保留空字符串；
- TLS/Reality 扩展对象仅在父配置实际存在时加入。

## 7. 应用 download-settings 覆盖

解析 canonical 后，只处理 Mihomo XHTTPDownloadSettings 支持的字段。

唯一覆盖规则：

~~~text
canonical 成员存在 → 整体替换 effective 中的同名成员
canonical 成员缺失 → 保留父快照成员
~~~

禁止递归深合并。

以下值均为有效覆盖：

- 空字符串；
- false；
- 0；
- 空数组；
- 空对象。

典型语义：

~~~json
{"alpn":[]}
~~~

清除父 ALPN，不得回填父数组。

~~~json
{"reality-opts":{}}
~~~

清除父 Reality。

~~~json
{"ech-opts":{}}
~~~

清除父 ECH。

~~~json
{"tls":false}
~~~

关闭下行 TLS，不得继承父 TLS。

## 8. 构造完整 XHTTP 快照

独立下行使用一个不含 extra 的 Xray xhttpSettings 对象，全部采用 Xray 正式字段名。

### 8.1 复制父 XHTTP 配置

完整复制：

~~~text
mode
path
host
headers
noGRPCHeader

xPaddingBytes
xPaddingObfsMode
xPaddingKey
xPaddingHeader
xPaddingPlacement
xPaddingMethod

uplinkHTTPMethod

sessionIDPlacement
sessionIDKey
sessionIDTable
sessionIDLength

seqPlacement
seqKey

uplinkDataPlacement
uplinkDataKey
uplinkChunkSize

scMaxEachPostBytes
scMinPostsIntervalMs

xmux
~~~

来源：

- path、host、mode：Proxy 直接字段；
- headers：XhttpHeaders；
- noGRPCHeader、padding bytes、scMaxEachPostBytes：专用字段；
- 其余文档字段：XhttpClashOpts；
- xmux：XhttpReuseSettings。

复用现有 XHTTP_DOC_FIELDS、reuse-settings ↔ xmux 映射和 numeric/range 输出逻辑，不建立新的重复映射表。

### 8.2 应用下行传输层覆盖

Mihomo 下行仅允许覆盖四项：

~~~text
path
host
headers
reuse-settings
~~~

规则：

- 子成员缺失：使用父值；
- 子成员存在：整体替换；
- headers: {}：清空父 headers；
- reuse-settings: {}：替换为显式空 xmux，不得继承父 reuse；
- 其他 XHTTP 字段始终来自父快照。

### 8.3 计算最终 host

在代理字段覆盖完成后计算：

~~~text
若 canonical 存在 host：使用子 host
否则：使用父 raw XHTTP host

若结果为空：使用 effective servername
若仍为空：使用 effective server
~~~

最终值显式写入 Xray xhttpSettings.host，避免依赖目标实现再次推导回退。

## 9. 有效性校验

编码 Xray JSON 前必须完成全部校验。

### 9.1 Mihomo 运行时规则

至少复现：

- 主 XHTTP mode 为 stream-one 时禁止 download-settings；
- ShadowTLS、Restls、JLS、Reality 互斥；
- 上述安全模式启用时必须 tls: true；
- server 不能为空；
- port 必须位于合法范围；
- canonical 各字段必须符合预期 JSON 类型。

安全模式是否启用应依据覆盖后的有效对象及 Mihomo 的实际解析条件判断，不能只看父节点是否曾经配置过。

例如父 ShadowTLS 被子 shadow-tls-opts: {} 清除后，不应继续按 ShadowTLS 有效处理。

### 9.2 Xray 可表达性

只转换已验证存在严格等价映射的有效配置。

第一阶段允许：

- 明文；
- 标准 TLS；
- Reality；
- server、port、servername；
- ALPN；
- skip-cert-verify/allowInsecure；
- client fingerprint；
- XHTTP 正式传输字段；
- path、host、headers、xmux 覆盖。

以下能力在完成严格等价映射验证前视为不可转换：

- ShadowTLS；
- Restls；
- JLS；
- name-cert-verify；
- 证书 pinning fingerprint；
- certificate/private-key；
- support-x25519mlkem768；
- 启用状态的 ECH。

不可表达性检查必须基于覆盖后的有效状态：父配置若已被子空对象明确清除，不再构成阻塞。

物化失败时应返回包含具体字段的错误，例如：

~~~text
xhttp download-settings cannot be represented in Xray: shadow-tls-opts
~~~

禁止忽略该字段后继续返回 JSON。

## 10. 编码独立 Xray StreamConfig

成功结果必须是完整、独立的 Xray 配置：

~~~json
{
  "address": "download.example.com",
  "port": 443,
  "network": "xhttp",
  "security": "tls",
  "tlsSettings": {
    "serverName": "download.example.com",
    "fingerprint": "chrome",
    "allowInsecure": false,
    "alpn": []
  },
  "xhttpSettings": {
    "mode": "packet-up",
    "path": "/download",
    "host": "download.example.com",
    "headers": {},
    "xPaddingBytes": "100-1000",
    "xmux": {}
  }
}
~~~

编码要求：

- 始终输出 network: "xhttp"；
- 始终明确输出 security: "none"、"tls" 或 "reality"；
- Reality 使用 realitySettings；
- 普通 TLS 使用 tlsSettings；
- 明文不输出 TLS/Reality settings；
- xhttpSettings 是完整有效快照；
- xhttpSettings 内不再使用 extra；
- 不允许在下行配置内嵌套第二层 downloadSettings。

## 11. 接入链接导出

链接导出层执行：

~~~text
1. 解析或合成 extra 对象 ed
2. 获取 dsJson：
   a. XhttpDownloadSettings 非空 → 原样使用
   b. 否则 XhttpDownload 非空 → 调用 materializeMihomoDownload
3. 删除 ed 中所有既有 downloadSettings 同名成员
4. 添加唯一的 downloadSettings
5. 序列化 extra 并写入 VLESS URI
~~~

删除同名成员时应确保全部删除，不能只删除第一个重复成员。

如果物化失败：

- 日志必须包含节点名和具体不可表达字段；
- 跳过该节点的 VLESS 链接导出；
- 不得删除 downloadSettings 后继续输出主链接；
- 不得生成缺少部分字段的下行配置。

## 12. 测试方案

### 12.1 Canonical 三态

验证：

~~~text
download-settings 缺失 → XhttpDownload 为空
download-settings: {}   → XhttpDownload 为 {}
非空 download-settings → XhttpDownload 为非空对象 JSON
~~~

并验证 canonical → Clash 能恢复相同三态。

### 12.2 空对象全继承

输入：

~~~yaml
xhttp-opts:
  download-settings: {}
~~~

父节点配置 server、TLS、SNI、ALPN、path、host、headers、padding、session 和 reuse。

生成的 Xray downloadSettings 必须包含这些父配置的实际有效值。

### 12.3 显式清除

输入下行覆盖：

~~~yaml
tls: false
alpn: []
host: ""
headers: {}
reuse-settings: {}
reality-opts: {}
~~~

验证生成配置中不得重新出现对应父值。

### 12.4 部分覆盖

子节点只覆盖 server 和 path，验证：

- server/path 使用子值；
- 其余代理字段继承父值；
- 其余 XHTTP 字段完整继承父值。

### 12.5 安全模式

覆盖：

- 普通 TLS；
- Reality；
- Reality 显式清除后回到普通 TLS；
- 安全模式互斥冲突；
- 安全模式配合 tls: false；
- 主 mode 为 stream-one。

### 12.6 不可表达字段

对 ShadowTLS、JLS、证书 pinning 等配置验证：

- 物化明确失败；
- 错误包含具体字段；
- 不生成部分链接。

### 12.7 真实闭环

执行完整链路：

~~~text
Clash
→ 生成 VLESS URI
→ 重新解析 URI
→ 导出 Clash
→ 比较 download-settings 的实际有效值
~~~

断言应解码 extra JSON 后逐字段检查，不能只进行字符串包含判断。

## 13. 验收标准

满足以下条件后可认为实现完成：

- download-settings 缺失与空对象不再混淆；
- “{}” 能完整继承主节点并生成独立 Xray 配置；
- false、0、空字符串、空数组和空对象均能覆盖父值；
- 父 XHTTP 全字段均进入下行快照；
- path、host、headers、reuse 的覆盖与 Mihomo 一致；
- 原始 Xray downloadSettings 保持透传；
- 不可表达字段不会被静默丢弃；
- 生成的 VLESS URI 能被项目自身重新解析并恢复相同有效语义；
- 新增回归测试全部通过；
- 不扩展 Proxy，不引入重复字段映射和额外长期中间模型。

## 14. 实施顺序

1. 修复父 XHTTP host 和空 reuse-settings 的状态保留；
2. 实现父代理快照与父 XHTTP 快照构造；
3. 实现 canonical 整体覆盖；
4. 实现有效性和可表达性校验；
5. 编码完整 Xray StreamConfig；
6. 接入 canonical “{}” 三态；
7. 接入链接导出层的唯一成员替换和失败处理；
8. 增加三态、继承、清除、冲突、不可表达和真实闭环测试。

上述步骤应作为一个完整功能提交交付，避免 canonical 三态先进入不完整的物化路径。


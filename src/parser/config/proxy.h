#ifndef PROXY_H_INCLUDED
#define PROXY_H_INCLUDED

#include <map>
#include <string>
#include <vector>

#include "utils/tribool.h"

using String = std::string;
using StringArray = std::vector<String>;
using StringMap = std::map<String, String>;

// mihomo xhttp-opts 文档标量字段 ↔ Xray xhttp extra 键名映射。
// 键名以 Xray infra/conf/transport_method.go 的 SplitHTTPConfig 为准；
// 类型以链接消费侧 mihomo common/convert/v.go 的 parseXHTTPExtra 为准——
// 它的类型断言并不统一：多数 .(string)，布尔 .(bool)，而 uplinkChunkSize 与
// scMinPostsIntervalMs 只接受 .(float64)，写成字符串会被静默丢弃。
// Numeric 字段按值的形态定型：纯数字走 JSON 数字（两端都认），范围值只能留字
// 符串（Xray 的 Int32Range 收，mihomo 不收范围，无解）。
enum class XhttpFieldType { String, Bool, Numeric };
struct XhttpDocField
{
    const char *mihomo;
    const char *xray;
    XhttpFieldType type;
};
inline constexpr XhttpDocField XHTTP_DOC_FIELDS[] = {
    {"x-padding-obfs-mode", "xPaddingObfsMode", XhttpFieldType::Bool},
    {"x-padding-key", "xPaddingKey", XhttpFieldType::String},
    {"x-padding-header", "xPaddingHeader", XhttpFieldType::String},
    {"x-padding-placement", "xPaddingPlacement", XhttpFieldType::String},
    {"x-padding-method", "xPaddingMethod", XhttpFieldType::String},
    {"uplink-http-method", "uplinkHTTPMethod", XhttpFieldType::String},
    {"session-placement", "sessionIDPlacement", XhttpFieldType::String},
    {"session-key", "sessionIDKey", XhttpFieldType::String},
    {"session-table", "sessionIDTable", XhttpFieldType::String},
    // sessionIDLength 是少数同时收 string 与 float64 的字段，保持字符串即可
    {"session-length", "sessionIDLength", XhttpFieldType::String},
    {"seq-placement", "seqPlacement", XhttpFieldType::String},
    {"seq-key", "seqKey", XhttpFieldType::String},
    {"uplink-data-placement", "uplinkDataPlacement", XhttpFieldType::String},
    {"uplink-data-key", "uplinkDataKey", XhttpFieldType::String},
    {"uplink-chunk-size", "uplinkChunkSize", XhttpFieldType::Numeric},
    {"sc-min-posts-interval-ms", "scMinPostsIntervalMs", XhttpFieldType::Numeric},
};

// mihomo VlessOption 顶层 TLS 伪装层选项（download-settings 的 proxy 部分同样适用）
inline constexpr const char *MIHOMO_TLS_OPT_KEYS[] = {
    "ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts"};

enum class ProxyType
{
    Unknown,
    Shadowsocks,
    ShadowsocksR,
    VMess,
    Trojan,
    Snell,
    HTTP,
    HTTPS,
    SOCKS5,
    WireGuard,
    VLESS,
    Hysteria,
    Hysteria2,
    TUIC,
    AnyTLS,
    Mieru
};

inline String getProxyTypeName(ProxyType type) {
    switch (type) {
        case ProxyType::Shadowsocks:
            return "SS";
        case ProxyType::ShadowsocksR:
            return "SSR";
        case ProxyType::VMess:
            return "VMess";
        case ProxyType::VLESS:
            return "Vless";
        case ProxyType::Trojan:
            return "Trojan";
        case ProxyType::Snell:
            return "Snell";
        case ProxyType::HTTP:
            return "HTTP";
        case ProxyType::HTTPS:
            return "HTTPS";
        case ProxyType::SOCKS5:
            return "SOCKS5";
        case ProxyType::WireGuard:
            return "WireGuard";
        case ProxyType::Hysteria:
            return "Hysteria";
        case ProxyType::Hysteria2:
            return "Hysteria2";
        case ProxyType::TUIC:
            return "Tuic";
        case ProxyType::AnyTLS:
            return "AnyTLS";
        case ProxyType::Mieru:
            return "Mieru";
        default:
            return "Unknown";
    }
}

struct Proxy {
    // ===== Basic Info =====
    ProxyType Type = ProxyType::Unknown;
    uint32_t Id = 0;
    uint32_t GroupId = 0;
    String Group;
    String Remark;
    String Hostname;
    uint16_t Port = 0;

    // ===== Authentication =====
    String Username;
    String Password;
    String EncryptMethod;
    String Plugin;
    String PluginOption;
    String Protocol;
    String ProtocolParam;
    String OBFS;
    String OBFSParam;
    String UserId;
    uint16_t AlterId = 0;

    // ===== Transport =====
    String TransferProtocol;
    String FakeType;
    String AuthStr;
    bool TLSSecure = false;
    String TLSStr;  // Local: TLS type string (tls/xtls/reality)

    String Host;
    String Path;
    String Edge;

    // ===== QUIC =====
    String QUICSecure;
    String QUICSecret;

    // ===== gRPC =====
    String GRPCServiceName;
    String GRPCMode;
    uint32_t GRPCMaxConnections = 0;
    uint32_t GRPCMinStreams = 0;
    uint32_t GRPCMaxStreams = 0;

    // ===== XHTTP =====
    String XhttpMode;
    String XhttpExtra;
    String XhttpDownloadSettings;  // Xray JSON format (for VLESS link round-trip)
    String XhttpHeaders;              // JSON object string {"Key": "Val"} (xhttp-opts.headers)
    tribool XhttpNoGrpcHeader;        // xhttp-opts.no-grpc-header
    String XhttpPaddingBytes;         // xhttp-opts.x-padding-bytes
    String XhttpScMaxEachPostBytes;   // xhttp-opts.sc-max-each-post-bytes
    String XhttpReuseSettings;        // JSON object for xhttp-opts.reuse-settings
    String XhttpClashOpts;            // JSON object：文档其余 xhttp-opts 标量字段（键名同 mihomo 文档）
    String XhttpDownload;             // Mihomo canonical JSON for download-settings export
    String MihomoTlsOpts;             // JSON object：name-cert-verify 及 ech/shadow-tls/restls/jls-opts 透传

    // ===== Basic Flags =====
    tribool UDP;
    tribool XUDP;
    tribool TCPFastOpen;
    tribool AllowInsecure;
    tribool TLS13;

    // ===== Shadowsocks UDP-over-TCP =====
    tribool UdpOverTcp;
    uint32_t UdpOverTcpVersion = 0;

    // ===== Underlying Proxy =====
    String UnderlyingProxy;

    // ===== Snell =====
    uint16_t SnellVersion = 0;
    String ServerName;

    // ===== WireGuard =====
    String SelfIP;
    String SelfIPv6;
    String PublicKey;
    String PrivateKey;
    String PreSharedKey;
    StringArray DnsServers;
    uint16_t Mtu = 0;
    String AllowedIPs = "0.0.0.0/0, ::/0";
    uint16_t KeepAlive = 0;
    String TestUrl;
    String ClientId;

    // ===== Hysteria/Hysteria2 =====
    String Ports;
    String Mport;  // Hysteria2 port hopping
    String Auth;
    String Alpn;   // Single string version
    StringArray AlpnList;  // Array version
    String Up;
    String Down;
    String UpMbps;   // Local: string bandwidth
    String DownMbps; // Local: string bandwidth
    uint32_t UpSpeed = 0;
    uint32_t DownSpeed = 0;
    String Insecure;
    String Fingerprint;
    String OBFSPassword;
    String Ca;
    String CaStr;
    uint32_t RecvWindowConn = 0;
    uint32_t RecvWindow = 0;
    uint64_t InitialStreamReceiveWindow = 0;
    uint64_t MaxStreamReceiveWindow = 0;
    uint64_t InitialConnectionReceiveWindow = 0;
    uint64_t MaxConnectionReceiveWindow = 0;
    uint32_t UdpMTU = 0;
    tribool DisableMtuDiscovery;
    uint32_t HopInterval = 0;
    uint32_t CWND = 0;

    // ===== VLESS =====
    String ShortId;
    String Flow;
    String Encryption;  // Local: VLESS encryption field
    String VlessEncryption;  // MetaCubeX: mlkem768x25519plus.native/xorpub/random.1rtt/0rtt
    bool FlowShow = false;  // Local: flow display flag
    tribool FlowSet;  // Flag to indicate if Flow was explicitly set
    uint32_t XTLS = 0;
    String PacketEncoding;
    tribool PacketAddr;
    tribool GlobalPadding;
    tribool AuthenticatedLength;

    // ===== TUIC =====
    String UUID;
    String IP;
    String HeartbeatInterval;
    String CongestionControl;
    tribool DisableSni;
    tribool ReduceRtt;
    String UdpRelayMode = "native";
    uint32_t RequestTimeout = 15000;
    uint32_t MaxUdpRelayPacketSize = 0;
    uint32_t MaxDatagramFrameSize = 0;
    tribool FastOpen;
    uint32_t MaxOpenStreams = 0;
    String token;

    // ===== AnyTLS =====
    uint32_t IdleSessionCheckInterval = 30;
    uint32_t IdleSessionTimeout = 30;
    uint32_t MinIdleSession = 0;

    // ===== TLS/Security =====
    String SNI;
    String IpVersion;  // ipv4/ipv6/dual/ipv4-prefer/ipv6-prefer
    String ClientFingerprint;  // chrome/firefox/safari/ios/random/none
    tribool EchEnable;
    String EchConfig;

    // ===== SMUX (multiplexing) =====
    tribool SmuxEnabled;
    String SmuxProtocol;  // smux/yamux/h2mux
    uint32_t SmuxMaxConnections = 0;
    uint32_t SmuxMinStreams = 0;
    uint32_t SmuxMaxStreams = 0;
    tribool SmuxPadding;
    tribool SmuxStatistic;
    tribool SmuxOnlyTcp;

    // ===== mTLS =====
    String Certificate;
    String PrivateKeyPem;
    // reality-opts.support-x25519mlkem768：控制 ClientHello 是否保留 X25519MLKEM768
    // 密钥共享组。用 tribool 以区分"未配置"与"显式 false"，未配置时不写出。
    tribool SupportX25519MLKEM768;

    // ===== BasicOption 拨号选项（mihomo 所有出站协议共有）=====
    // sing-box 侧对应 tcp_multi_path / bind_interface / routing_mark
    tribool MPTCP;            // mptcp，tribool 以区分未配置与显式 false
    String InterfaceName;     // interface-name
    int RoutingMark = 0;      // routing-mark，0 即未配置（与 mihomo 的 omitempty 一致）
    // 服务器证书指纹校验（mihomo 的 fingerprint，SHA256 十六进制）。
    // 不能复用上面的 Fingerprint：那个字段在 vless/trojan/anytls 路径上实际承载的是
    // 客户端指纹，还被链接导出的 fp= 和 sing-box 的 utls.fingerprint 消费。
    String CertFingerprint;

    // ===== WebSocket =====
    uint32_t WsMaxEarlyData = 0;
    String WsEarlyDataHeaderName;
    tribool V2rayHttpUpgrade;
    tribool V2rayHttpUpgradeFastOpen;

    // ===== HTTP options =====
    String HttpMethod;
    StringArray HttpPath;

    // ===== Trojan SS =====
    String TrojanSsMethod;
    String TrojanSsPassword;

    // ===== Mieru (Local) =====
    String Multiplexing;
};

#define SS_DEFAULT_GROUP "SSProvider"
#define SSR_DEFAULT_GROUP "SSRProvider"
#define V2RAY_DEFAULT_GROUP "V2RayProvider"
#define VLESS_DEFAULT_GROUP "VLESSProvider"
#define SOCKS_DEFAULT_GROUP "SocksProvider"
#define HTTP_DEFAULT_GROUP "HTTPProvider"
#define TROJAN_DEFAULT_GROUP "TrojanProvider"
#define SNELL_DEFAULT_GROUP "SnellProvider"
#define WG_DEFAULT_GROUP "WireGuardProvider"
#define XRAY_DEFAULT_GROUP "XRayProvider"
#define HYSTERIA_DEFAULT_GROUP "HysteriaProvider"
#define HYSTERIA2_DEFAULT_GROUP "Hysteria2Provider"
#define TUIC_DEFAULT_GROUP "TUICProvider"
#define ANYTLS_DEFAULT_GROUP "AnyTLSProvider"
#define MIERU_DEFAULT_GROUP "MieruProvider"

#endif // PROXY_H_INCLUDED

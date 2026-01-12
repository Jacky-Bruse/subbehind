#ifndef SUBPARSER_H_INCLUDED
#define SUBPARSER_H_INCLUDED

#include <string>

#include "config/proxy.h"

enum class ConfType {
    Unknow,
    SS,
    SSR,
    V2Ray,
    SSConf,
    SSTap,
    Netch,
    SOCKS,
    HTTP,
    SUB,
    Local
};

void hysteriaConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                       const std::string &port, const std::string &type, const std::string &auth,
                       const std::string &auth_str, const std::string &host, const std::string &up,
                       const std::string &down, const std::string &alpn, const std::string &obfsParam,
                       const std::string &insecure, const std::string &ports, const std::string &sni,
                       tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(),
                       tribool tls13 = tribool(), const std::string &underlying_proxy = "",
                       const std::string &fingerprint = "", const std::string &ca = "", const std::string &ca_str = "",
                       uint32_t recv_window_conn = 0, uint32_t recv_window = 0,
                       tribool disable_mtu_discovery = tribool(), uint32_t hop_interval = 0, tribool fast_open = tribool());

void hysteria2Construct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                        const std::string &port, const std::string &password, const std::string &host,
                        const std::string &up, const std::string &down, const std::string &alpn,
                        const std::string &obfsParam, const std::string &obfsPassword, const std::string &sni,
                        const std::string &publicKey, const std::string &ports,
                        tribool udp, tribool tfo, tribool scv, const std::string &underlying_proxy = "",
                        const std::string &mport = "", const std::string &fingerprint = "",
                        const std::string &ca = "", const std::string &ca_str = "",
                        uint32_t cwnd = 0, uint32_t hop_interval = 0,
                        uint64_t init_stream_recv_window = 0, uint64_t max_stream_recv_window = 0,
                        uint64_t init_conn_recv_window = 0, uint64_t max_conn_recv_window = 0);

void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                    const std::string &port, const std::string &type, const std::string &id, const std::string &aid,
                    const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode,
                    const std::string &path, const std::string &host, const std::string &edge, const std::string &tls,
                    const std::string &pkd, const std::string &sid, const std::string &fp, const std::string &sni,
                    const std::vector<std::string> &alpnList, const std::string &packet_encoding,
                    tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(),
                    tribool tls13 = tribool(), const std::string &underlying_proxy = "", tribool v2ray_http_upgrade = tribool(),
                    const std::string &encryption = "", const std::string &ip_version = "", tribool xudp = tribool(),
                    tribool packet_addr = tribool(), tribool global_padding = tribool(), tribool authenticated_length = tribool(),
                    tribool ech_enable = tribool(), const std::string &ech_config = "",
                    uint32_t ws_max_early_data = 0, const std::string &ws_early_data_header_name = "",
                    tribool v2ray_http_upgrade_fast_open = tribool());

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                    const std::string &port, const std::string &type, const std::string &id, const std::string &aid,
                    const std::string &net, const std::string &cipher, const std::string &path, const std::string &host,
                    const std::string &edge, const std::string &tls, const std::string &sni,
                    const std::vector<std::string> &alpnList, tribool udp = tribool(),
                    tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(),
                    const std::string &underlying_proxy = "",
                    const std::string &client_fingerprint = "", tribool v2ray_http_upgrade = tribool(),
                    uint32_t ws_max_early_data = 0, const std::string &ws_early_data_header_name = "",
                    tribool v2ray_http_upgrade_fast_open = tribool(), const std::string &ip_version = "");

void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                  const std::string &port, const std::string &protocol, const std::string &method,
                  const std::string &obfs, const std::string &password, const std::string &obfsparam,
                  const std::string &protoparam, tribool udp = tribool(), tribool tfo = tribool(),
                  tribool scv = tribool(),const std::string& underlying_proxy="");

void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                 const std::string &port, const std::string &password, const std::string &method,
                 const std::string &plugin, const std::string &pluginopts, tribool udp = tribool(),
                 tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(),
                 const std::string &underlying_proxy = "",
                 tribool udp_over_tcp = tribool(), uint32_t udp_over_tcp_version = 0,
                 tribool smux_enabled = tribool(), const std::string &smux_protocol = "",
                 uint32_t smux_max_connections = 0, uint32_t smux_min_streams = 0, uint32_t smux_max_streams = 0,
                 tribool smux_padding = tribool(), tribool smux_statistic = tribool(), tribool smux_only_tcp = tribool());

void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                    const std::string &port, const std::string &username, const std::string &password,
                    tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(),const std::string& underlying_proxy="");

void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                   const std::string &port, const std::string &username, const std::string &password, bool tls,
                   tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(),const std::string& underlying_proxy="");

void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                     const std::string &port, const std::string &password, const std::string &network,
                     const std::string &host, const std::string &path, const std::string &fp, const std::string &sni,
                     const std::vector<std::string> &alpnList,
                     bool tlssecure, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(),
                     tribool tls13 = tribool(), const std::string &underlying_proxy = "",
                     const std::string &client_fingerprint = "", const std::string &ss_method = "",
                     const std::string &ss_password = "", const std::string &ip_version = "");
void anyTlSConstruct(Proxy &node, const std::string &group, const std::string &remarks,
                       const std::string &port, const std::string &password,
                       const std::string &host, const std::vector<String> &AlpnList,
                       const std::string &fingerprint,
                       const std::string &sni, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(),
                     tribool tls13 = tribool(),const std::string& underlying_proxy="",uint16_t idleSessionCheckInterval=30,uint16_t idleSessionTimeout=30,uint16_t minIdleSession=0);
void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                    const std::string &port, const std::string &password, const std::string &obfs,
                    const std::string &host, uint16_t version = 0, tribool udp = tribool(), tribool tfo = tribool(),
                    tribool scv = tribool(),const std::string& underlying_proxy="");

void tuicConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                   const std::string &port, const std::string &password, const std::string &congestion_control,
                   const std::string &alpn,
                   const std::string &sni, const std::string &uuid, const std::string &udpRelayMode,
                   const std::string &token,
                   tribool udp = tribool(), tribool tfo = tribool(),
                   tribool scv = tribool(), tribool reduceRtt = tribool(), tribool disableSni = tribool(),
                   uint32_t request_timeout = 15000, const std::string &underlying_proxy = "",
                   uint32_t max_datagram_frame_size = 0, const std::string &heartbeat_interval = "",
                   uint32_t max_open_streams = 0);
void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks,
                    const std::string &port, const std::string &password,
                    const std::string &host, const std::string &ports,
                    const std::string &username,const std::string &multiplexing,
                    const std::string &transfer_protocol, tribool udp,
                    tribool tfo, tribool scv,
                    tribool tls13, const std::string &underlying_proxy);
void explodeVmess(std::string vmess, Proxy &node);

void explodeSSR(std::string ssr, Proxy &node);

void explodeSS(std::string ss, Proxy &node);

void explodeTrojan(std::string trojan, Proxy &node);

void explodeQuan(const std::string &quan, Proxy &node);
void explodeMierus(std::string mieru, Proxy &node);
void explodeStdVMess(std::string vmess, Proxy &node);

void explodeStdVless(std::string vless, Proxy &node);
void explodeStdMieru(std::string mieru, Proxy &node);
void explodeStdHysteria(std::string hysteria, Proxy &node);

void explodeStdHysteria2(std::string hysteria2, Proxy &node);

void explodeShadowrocket(std::string kit, Proxy &node);

void explodeKitsunebi(std::string kit, Proxy &node);

void explodeVless(std::string vless, Proxy &node);

void explodeHysteria(std::string hysteria, Proxy &node);

void explodeHysteria2(std::string hysteria2, Proxy &node);

void explodeAnyTLS(std::string anytls, Proxy &node);

/// Parse a link
void explode(const std::string &link, Proxy &node);

void explodeSSD(std::string link, std::vector<Proxy> &nodes);

void explodeSub(std::string sub, std::vector<Proxy> &nodes);

int explodeConf(const std::string &filepath, std::vector<Proxy> &nodes);

int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes);

#endif // SUBPARSER_H_INCLUDED

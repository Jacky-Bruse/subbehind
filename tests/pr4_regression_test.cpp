#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "generator/config/subexport.h"
#include "parser/subparser.h"

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
    const std::string exported = proxyToSingle(nodes, kVlessMask, ext);
    require(exported.find("type=xhttp") != std::string::npos, "expected exported link to keep xhttp");
    require(exported.find("mode=packet-up") != std::string::npos, "expected exported link to keep xhttp mode");
    require(exported.find("host=cdn.example.com") != std::string::npos, "expected exported link to keep host");
    require(exported.find("path=%2Fxhttp") != std::string::npos || exported.find("path=/xhttp") != std::string::npos,
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

} // namespace

int main() {
    try {
        test_vmess_conf_reads_mixed_case_wssettings();
        test_clash_ss_mux_pluginopts_do_not_duplicate();
        test_clash_round_trip_preserves_dialer_proxy();
        test_singbox_round_trip_preserves_detour_and_vless_encryption();
        test_vless_link_preserves_xhttp_transport();
        test_v2ray_vless_xhttp_conf_preserves_transport();
        test_v2ray_vless_tls_settings_preserve_sni_and_alpn();
        test_vless_xhttp_round_trip_preserves_type();
        test_singbox_vless_xhttp_preserves_transport();
        test_quanx_export_skips_vless_xhttp_node();
    } catch (const std::exception &e) {
        std::cerr << "pr4_regression_test failed: " << e.what() << '\n';
        return 1;
    }

    std::cout << "pr4_regression_test passed\n";
    return 0;
}

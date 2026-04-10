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
    std::cerr << "[debug] TransferProtocol=" << nodes[0].TransferProtocol
              << " XhttpMode=" << nodes[0].XhttpMode
              << " TLSStr=" << nodes[0].TLSStr << "\n";

    extra_settings ext;
    constexpr int kVlessMask = 32;
    const std::string exported = proxyToSingle(nodes, kVlessMask, ext);
    std::cerr << "[debug] exported=" << exported << "\n";
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
    const std::string exported = proxyToSingle(nodes, kVlessMask, ext);
    require(exported.find("extra=") != std::string::npos,
            "expected vless link to contain extra=");
    require(exported.find("scMaxEachPostBytes") != std::string::npos,
            "expected extra to contain scMaxEachPostBytes");
    require(exported.find("xmux") != std::string::npos,
            "expected extra to contain xmux for reuse-settings");
    require(exported.find("maxConnections") != std::string::npos,
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
                "hMaxReusableSecs": "1800-3000"
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
    require(exported.find("sc-max-each-post-bytes: 500000") != std::string::npos,
            "expected download-settings.sc-max-each-post-bytes from xray scMaxEachPostBytes");
    require(exported.find("reuse-settings:") != std::string::npos,
            "expected download-settings.reuse-settings from xray xmux");
    require(exported.find("max-connections: 16-32") != std::string::npos,
            "expected reuse-settings.max-connections from xray xmux.maxConnections");
    require(exported.find("h-max-reusable-secs: 1800-3000") != std::string::npos,
            "expected reuse-settings.h-max-reusable-secs from xray xmux.hMaxReusableSecs");
}

void test_clash_vless_xhttp_download_settings_full() {
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
    require(exported.find("sc-max-each-post-bytes: 500000") != std::string::npos,
            "expected download-settings.sc-max-each-post-bytes to be exported");
    require(exported.find("reuse-settings:") != std::string::npos,
            "expected download-settings.reuse-settings to be exported");
    require(exported.find("max-connections: 8") != std::string::npos,
            "expected download-settings.reuse-settings.max-connections to be exported");
    require(exported.find("skip-cert-verify: 0") != std::string::npos ||
            exported.find("skip-cert-verify: false") != std::string::npos,
            "expected download-settings.skip-cert-verify to be exported");
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

} // namespace

int main() {
    try {
        test_vmess_conf_reads_mixed_case_wssettings();
        test_clash_ss_mux_pluginopts_do_not_duplicate();
        test_clash_round_trip_preserves_dialer_proxy();
        test_clash_vless_xhttp_export_preserves_transport();
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
        test_quanx_export_skips_vless_xhttp_node();
        test_clash_vless_xhttp_reuse_settings_h_keep_alive_period();
        test_clash_vless_xhttp_sc_max_range_passthrough();
        test_clash_vless_grpc_new_opts();
    } catch (const std::exception &e) {
        std::cerr << "pr4_regression_test failed: " << e.what() << '\n';
        return 1;
    }

    std::cout << "pr4_regression_test passed\n";
    return 0;
}

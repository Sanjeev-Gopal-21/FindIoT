/**
 * pcap_flow_extractor.cpp
 * ─────────────────────────────────────────────────────────────────────────────
 * Flow-level feature extraction from UNSW-NB15 PCAPs with IoT/Non-IoT
 * heuristic labelling.
 *
 * Key enhancements over the packet-level extractor:
 *   • Bidirectional flow aggregation  (canonical 5-tuple key)
 *   • Welford online mean/variance    (O(1) memory per flow)
 *   • 39-feature flow CSV             (stats + TCP flags + IoT indicators)
 *   • OUI-based IoT device detection  (~30 known IoT vendors)
 *   • Protocol-port IoT scoring       (MQTT, CoAP, mDNS, Modbus …)
 *   • Per-file flow flush             (graceful recovery from crashes)
 *   • Flow timeout eviction           (configurable idle / active timeouts)
 *
 * Build
 *   g++ -O2 -std=c++17 pcap_flow_extractor.cpp -lpcap -o pcap_flow_extractor
 *
 * Usage
 *   ./pcap_flow_extractor [OPTIONS] <pcap_dir> <output.csv>
 *
 * Options
 *   -r            Recurse into sub-directories
 *   -v            Verbose per-file stats
 *   -m <bytes>    CSV write-buffer size (default 131072)
 *   -i <secs>     Flow idle timeout     (default 60 s)
 *   -a <secs>     Flow active timeout   (default 300 s)
 *   -t <thresh>   IoT score threshold for iot_hint label (default 3)
 *   -d <csv>      Device inventory CSV  (ip,label) to override heuristic
 *
 * Output CSV columns (39)
 *   start_time, duration, src_ip, dst_ip, src_port, dst_port, protocol,
 *   fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
 *   pkt_len_mean, pkt_len_std, pkt_len_min, pkt_len_max,
 *   iat_mean, iat_std, iat_min, iat_max,
 *   syn_cnt, ack_cnt, psh_cnt, rst_cnt, fin_cnt,
 *   is_mqtt, is_coap, is_mdns, is_ssdp, is_ntp, is_telnet, is_modbus,
 *   is_http, is_https, is_dns,
 *   src_oui, oui_is_iot, iot_score, iot_hint, file_tag
 * ─────────────────────────────────────────────────────────────────────────────
 */

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <chrono>
#include <stdexcept>
#include <optional>

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════════════════
//  IoT OUI Database  (IEEE-registered prefixes for known IoT manufacturers)
//  Format: lowercase 6-char hex  (e.g. "b827eb" = B8:27:EB)
//  Extend from: https://maclookup.app/  or the full IEEE OUI registry
// ═══════════════════════════════════════════════════════════════════════════════

static const std::unordered_set<std::string> IOT_OUI_DB = {
    // Raspberry Pi Foundation
    "b827eb", "dca632", "e45f01",
    // Philips Lighting (Hue)
    "001788",
    // Nest Labs / Google Home
    "18b430", "641666", "d8334f", "54607e",
    // Amazon (Echo, Ring, Fire TV)
    "4465d0", "fc65de", "44650d", "74c246", "f0272d", "a002dc", "cc9e00",
    // Google Chromecast / Google Home
    "b0b982", "b4750e", "6c4008",
    // Samsung SmartThings / ZigBee coordinator
    "0021d1", "000d6f", "286c07",
    // Belkin (WeMo smart plugs)
    "606bff", "ec1a59",
    // Espressif Systems (ESP8266 / ESP32 — extremely common in DIY IoT)
    "d83add", "5ccf7f", "a020a6", "30aea4", "240ac4", "3c71bf", "24b2de",
    // Arduino LLC
    "ac233f",
    // Particle Industries (Photon, Electron)
    "98076b",
    // TP-Link (Kasa smart plugs, bulbs)
    "b0be76", "50c7bf", "10feed",
    // Tuya/TYWE generic IoT modules
    "7cf666",
    // LIFX smart bulbs
    "d073d5",
    // Sonos speakers (often counted as IoT)
    "48a6b8", "54a5ef", "b8e937",
    // Hikvision cameras
    "c05627", "8ca9ff",
    // Dahua cameras
    "703a51",
    // Shelly / Allterco Robotics
    "e8db84",
};

// ═══════════════════════════════════════════════════════════════════════════════
//  IoT-associated port constants
// ═══════════════════════════════════════════════════════════════════════════════

struct IotPorts {
    static constexpr uint16_t MQTT        = 1883;
    static constexpr uint16_t MQTT_TLS    = 8883;
    static constexpr uint16_t COAP        = 5683;
    static constexpr uint16_t COAP_DTLS   = 5684;
    static constexpr uint16_t MDNS        = 5353;
    static constexpr uint16_t SSDP        = 1900;
    static constexpr uint16_t NTP         = 123;
    static constexpr uint16_t TELNET      = 23;   // IoT malware favourite
    static constexpr uint16_t MODBUS      = 502;
    static constexpr uint16_t BACNET      = 47808;
    static constexpr uint16_t AMQP        = 5672;
    static constexpr uint16_t XMPP        = 5222;
    static constexpr uint16_t HTTP        = 80;
    static constexpr uint16_t HTTP_ALT    = 8080;
    static constexpr uint16_t HTTPS       = 443;
    static constexpr uint16_t DNS         = 53;
};

// ═══════════════════════════════════════════════════════════════════════════════
//  Canonical flow key  (bidirectional: lower-endpoint always "A")
// ═══════════════════════════════════════════════════════════════════════════════

struct FlowKey {
    std::string ip_a, ip_b;
    uint16_t    port_a, port_b;
    uint8_t     protocol;

    FlowKey() = default;
    FlowKey(const std::string &si, const std::string &di,
            uint16_t sp, uint16_t dp, uint8_t p) : protocol(p) {
        if (si < di || (si == di && sp <= dp)) {
            ip_a = si; ip_b = di; port_a = sp; port_b = dp;
        } else {
            ip_a = di; ip_b = si; port_a = dp; port_b = sp;
        }
    }

    bool operator==(const FlowKey &o) const noexcept {
        return protocol == o.protocol && port_a == o.port_a &&
               port_b == o.port_b && ip_a == o.ip_a && ip_b == o.ip_b;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey &k) const noexcept {
        std::size_t h = std::hash<std::string>{}(k.ip_a);
        h ^= std::hash<std::string>{}(k.ip_b)    + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.port_a)     + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.port_b)     + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(k.protocol)    + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
//  Flow statistics accumulator
//  Uses Welford's online algorithm for mean / variance in O(1) memory
// ═══════════════════════════════════════════════════════════════════════════════

struct FlowStats {
    // Timing
    double   start_time = 0.0;
    double   last_time  = 0.0;

    // Initiator (first-seen src IP, used to determine fwd vs bwd)
    std::string initiator_ip;

    // Packet / byte counts per direction
    uint64_t fwd_pkts  = 0, bwd_pkts  = 0;
    uint64_t fwd_bytes = 0, bwd_bytes = 0;

    // Packet length (Welford) — both directions combined
    uint64_t pkt_count    = 0;
    double   pkt_len_mean = 0.0;
    double   pkt_len_M2   = 0.0;
    uint32_t pkt_len_min  = UINT32_MAX;
    uint32_t pkt_len_max  = 0;

    // Inter-arrival time (Welford)
    uint64_t iat_count  = 0;
    double   iat_mean   = 0.0;
    double   iat_M2     = 0.0;
    double   iat_min    = 1e18;
    double   iat_max    = 0.0;

    // TCP flags (cumulative counts)
    uint32_t syn_cnt = 0, ack_cnt = 0, psh_cnt = 0;
    uint32_t rst_cnt = 0, fin_cnt = 0, urg_cnt = 0;

    // IoT protocol indicators (set on first occurrence)
    bool is_mqtt    = false;
    bool is_coap    = false;
    bool is_mdns    = false;
    bool is_ssdp    = false;
    bool is_ntp     = false;
    bool is_telnet  = false;
    bool is_modbus  = false;
    bool is_http    = false;
    bool is_https   = false;
    bool is_dns     = false;

    // MAC OUI of initiator
    std::string src_oui;
    bool        oui_is_iot = false;

    // Computed IoT score (0-10)
    int  iot_score = 0;
    int  iot_hint  = 0;   // binary label from heuristic

    // Source PCAP stem
    std::string file_tag;

    // ── Welford update for packet length ─────────────────────────────────────
    void update_pkt_len(uint32_t len) {
        ++pkt_count;
        double delta = static_cast<double>(len) - pkt_len_mean;
        pkt_len_mean += delta / static_cast<double>(pkt_count);
        pkt_len_M2   += delta * (static_cast<double>(len) - pkt_len_mean);
        pkt_len_min   = std::min(pkt_len_min, len);
        pkt_len_max   = std::max(pkt_len_max, len);
    }

    double pkt_len_std() const {
        return (pkt_count > 1) ? std::sqrt(pkt_len_M2 / (pkt_count - 1)) : 0.0;
    }

    // ── Welford update for IAT ────────────────────────────────────────────────
    void update_iat(double ts) {
        if (last_time > 0.0) {
            double iat = ts - last_time;
            if (iat < 0.0) iat = 0.0;   // clock skew guard
            ++iat_count;
            double delta = iat - iat_mean;
            iat_mean += delta / static_cast<double>(iat_count);
            iat_M2   += delta * (iat - iat_mean);
            iat_min   = std::min(iat_min, iat);
            iat_max   = std::max(iat_max, iat);
        }
        last_time = ts;
    }

    double iat_std() const {
        return (iat_count > 1) ? std::sqrt(iat_M2 / (iat_count - 1)) : 0.0;
    }

    // ── IoT scoring heuristic ─────────────────────────────────────────────────
    // Score 0-10; threshold (default 3) → iot_hint = 1
    //
    // Evidence FOR IoT:
    //  +3  OUI matches a known IoT vendor
    //  +2  Uses MQTT or CoAP (quintessential IoT protocols)
    //  +1  Uses Modbus / BACNET (industrial IoT)
    //  +1  Uses mDNS / SSDP (device discovery typical in IoT LANs)
    //  +1  Uses NTP (small devices sync time this way)
    //  +1  Uses Telnet port 23 (IoT malware / old devices)
    //  +1  Mean packet size < 200 B with > 5 packets  (sensor payloads)
    //  +1  Traffic is periodic  (IAT std < 0.3 × mean, min 5 IATs)
    //
    // Evidence AGAINST IoT:
    //  -1  Uses HTTP/HTTPS (typical human-browsing traffic)
    //  -1  Uses DNS  (desktops/servers generate bulk DNS)
    //
    void compute_iot_score(int threshold) {
        int s = 0;
        if (oui_is_iot)                                         s += 3;
        if (is_mqtt || is_coap)                                 s += 2;
        if (is_modbus)                                          s += 1;
        if (is_mdns || is_ssdp)                                 s += 1;
        if (is_ntp)                                             s += 1;
        if (is_telnet)                                          s += 1;
        if (pkt_len_mean < 200.0 && pkt_count > 5)             s += 1;
        if (iat_count >= 5 && iat_mean > 0.0 &&
            iat_std() < 0.3 * iat_mean)                        s += 1;
        if (is_http || is_https)                                s -= 1;
        if (is_dns)                                             s -= 1;

        iot_score = std::max(0, std::min(10, s));
        iot_hint  = (iot_score >= threshold) ? 1 : 0;
    }

    // ── CSV serialisation ─────────────────────────────────────────────────────
    static void write_header(std::ostream &out) {
        out << "start_time,duration,src_ip,dst_ip,src_port,dst_port,protocol,"
               "fwd_pkts,bwd_pkts,fwd_bytes,bwd_bytes,"
               "pkt_len_mean,pkt_len_std,pkt_len_min,pkt_len_max,"
               "iat_mean,iat_std,iat_min,iat_max,"
               "syn_cnt,ack_cnt,psh_cnt,rst_cnt,fin_cnt,"
               "is_mqtt,is_coap,is_mdns,is_ssdp,is_ntp,"
               "is_telnet,is_modbus,is_http,is_https,is_dns,"
               "src_oui,oui_is_iot,iot_score,iot_hint,file_tag\n";
    }

    void write_csv(std::ostream &out,
                   const FlowKey &key) const
    {
        // Emit with initiator as "src" so CSV aligns with human intuition
        bool fwd_is_a = (initiator_ip == key.ip_a);
        const std::string &src_ip = fwd_is_a ? key.ip_a : key.ip_b;
        const std::string &dst_ip = fwd_is_a ? key.ip_b : key.ip_a;
        uint16_t src_port = fwd_is_a ? key.port_a : key.port_b;
        uint16_t dst_port = fwd_is_a ? key.port_b : key.port_a;

        double duration = last_time - start_time;
        double iat_min_out = (iat_count > 0) ? iat_min : 0.0;
        double iat_max_out = (iat_count > 0) ? iat_max : 0.0;

        out << std::fixed << std::setprecision(6)
            << start_time    << ','
            << duration      << ','
            << src_ip        << ','
            << dst_ip        << ','
            << src_port      << ','
            << dst_port      << ','
            << static_cast<int>(key.protocol) << ','
            << fwd_pkts      << ','
            << bwd_pkts      << ','
            << fwd_bytes     << ','
            << bwd_bytes     << ','
            << pkt_len_mean  << ','
            << pkt_len_std() << ','
            << (pkt_count > 0 ? pkt_len_min : 0u) << ','
            << pkt_len_max   << ','
            << iat_mean      << ','
            << iat_std()     << ','
            << iat_min_out   << ','
            << iat_max_out   << ','
            << syn_cnt << ',' << ack_cnt << ',' << psh_cnt << ','
            << rst_cnt << ',' << fin_cnt << ','
            << is_mqtt   << ',' << is_coap  << ',' << is_mdns   << ','
            << is_ssdp   << ',' << is_ntp   << ',' << is_telnet << ','
            << is_modbus << ',' << is_http  << ',' << is_https  << ','
            << is_dns    << ','
            << src_oui   << ','
            << oui_is_iot << ','
            << iot_score  << ','
            << iot_hint   << ','
            << file_tag   << '\n';
    }
};

using FlowTable = std::unordered_map<FlowKey, FlowStats, FlowKeyHash>;

// ═══════════════════════════════════════════════════════════════════════════════
//  Buffered CSV writer
// ═══════════════════════════════════════════════════════════════════════════════

class CsvWriter {
public:
    CsvWriter(const fs::path &path, std::size_t buf_limit)
        : buf_limit_(buf_limit)
    {
        ofs_.open(path, std::ios::out | std::ios::trunc);
        if (!ofs_) throw std::runtime_error("Cannot open output: " + path.string());
        FlowStats::write_header(ofs_);
    }

    void write(const FlowKey &key, const FlowStats &st) {
        std::ostringstream ss;
        st.write_csv(ss, key);
        buf_ += ss.str();
        ++rows_written;
        if (buf_.size() >= buf_limit_) flush();
    }

    void flush() {
        if (!buf_.empty()) { ofs_ << buf_; buf_.clear(); }
    }

    ~CsvWriter() { flush(); }

    uint64_t rows_written = 0;

private:
    std::ofstream ofs_;
    std::string   buf_;
    std::size_t   buf_limit_;
};

// ═══════════════════════════════════════════════════════════════════════════════
//  Device inventory  (optional ground-truth override)
//  CSV format:  ip_address,label   (label: 0=non-IoT, 1=IoT)
// ═══════════════════════════════════════════════════════════════════════════════

using DeviceMap = std::unordered_map<std::string, int>;

static DeviceMap load_device_inventory(const fs::path &csv_path) {
    DeviceMap dm;
    if (csv_path.empty() || !fs::exists(csv_path)) return dm;
    std::ifstream f(csv_path);
    std::string line;
    std::getline(f, line); // skip header
    while (std::getline(f, line)) {
        auto comma = line.find(',');
        if (comma == std::string::npos) continue;
        std::string ip  = line.substr(0, comma);
        int         lbl = std::stoi(line.substr(comma + 1));
        dm[ip] = lbl;
    }
    return dm;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Packet handler context
// ═══════════════════════════════════════════════════════════════════════════════

struct PacketCtx {
    FlowTable   &flows;
    CsvWriter   &writer;
    std::string  file_tag;
    int          iot_threshold;
    double       idle_timeout;
    double       active_timeout;
    const DeviceMap &device_map;

    uint64_t pkt_count  = 0;
    uint64_t skip_count = 0;

    // Flush flows that have exceeded idle or active timeout
    void evict_stale(double now) {
        std::vector<FlowKey> to_remove;
        for (auto &[k, s] : flows) {
            bool idle   = (now - s.last_time)  > idle_timeout;
            bool active = (now - s.start_time) > active_timeout;
            if (idle || active) to_remove.push_back(k);
        }
        for (const auto &k : to_remove) {
            auto &s = flows[k];
            s.compute_iot_score(iot_threshold);
            // Ground-truth override if device_map provided
            if (!device_map.empty()) {
                auto it = device_map.find(s.initiator_ip);
                if (it != device_map.end()) s.iot_hint = it->second;
            }
            writer.write(k, s);
            flows.erase(k);
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
//  Packet handler  (called by pcap_loop for every captured frame)
// ═══════════════════════════════════════════════════════════════════════════════

static void packet_handler(u_char *user,
                            const struct pcap_pkthdr *header,
                            const u_char *data)
{
    auto *ctx = reinterpret_cast<PacketCtx *>(user);
    ++ctx->pkt_count;

    if (header->caplen < 14) { ++ctx->skip_count; return; }

    double ts = header->ts.tv_sec + header->ts.tv_usec * 1e-6;

    // ── Ethernet ──────────────────────────────────────────────────────────────
    // Extract source OUI (bytes 6-8 of frame = source MAC octets 0-2)
    char oui_buf[7];
    snprintf(oui_buf, sizeof(oui_buf), "%02x%02x%02x",
             data[6], data[7], data[8]);
    std::string src_oui = oui_buf;
    bool oui_is_iot = IOT_OUI_DB.count(src_oui) > 0;

    const u_char *ip_ptr = data + 14;
    uint32_t      ip_cap = header->caplen - 14;
    uint8_t       ip_ver = (ip_cap > 0) ? (ip_ptr[0] >> 4) : 0;

    // ── IP layer ──────────────────────────────────────────────────────────────
    std::string src_ip, dst_ip;
    uint8_t     proto = 0;
    uint32_t    ip_hdr_len = 0;
    uint8_t     ttl = 0, tos = 0;

    if (ip_ver == 4) {
        if (ip_cap < sizeof(struct ip)) { ++ctx->skip_count; return; }
        const auto *iph = reinterpret_cast<const struct ip *>(ip_ptr);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->ip_src, buf, sizeof(buf)); src_ip = buf;
        inet_ntop(AF_INET, &iph->ip_dst, buf, sizeof(buf)); dst_ip = buf;
        proto      = iph->ip_p;
        ip_hdr_len = static_cast<uint32_t>(iph->ip_hl) * 4u;
        ttl        = iph->ip_ttl;
        tos        = iph->ip_tos;

    } else if (ip_ver == 6) {
        if (ip_cap < sizeof(struct ip6_hdr)) { ++ctx->skip_count; return; }
        const auto *ip6h = reinterpret_cast<const struct ip6_hdr *>(ip_ptr);
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6h->ip6_src, buf, sizeof(buf)); src_ip = buf;
        inet_ntop(AF_INET6, &ip6h->ip6_dst, buf, sizeof(buf)); dst_ip = buf;
        proto      = ip6h->ip6_nxt;
        ip_hdr_len = 40;
        ttl        = ip6h->ip6_hlim;
        tos        = static_cast<uint8_t>((ntohl(ip6h->ip6_flow) >> 20) & 0xFF);

    } else {
        ++ctx->skip_count; return;
    }

    if (ip_cap < ip_hdr_len) { ++ctx->skip_count; return; }

    const u_char *tp_ptr = ip_ptr + ip_hdr_len;
    uint32_t      tp_cap = ip_cap - ip_hdr_len;

    // ── Transport layer ───────────────────────────────────────────────────────
    uint16_t src_port = 0, dst_port = 0;
    uint8_t  tcp_flags = 0;
    uint32_t payload_len = 0;

    if (proto == IPPROTO_TCP) {
        if (tp_cap < sizeof(struct tcphdr)) { ++ctx->skip_count; return; }
        const auto *tcph = reinterpret_cast<const struct tcphdr *>(tp_ptr);
        src_port  = ntohs(tcph->th_sport);
        dst_port  = ntohs(tcph->th_dport);
        tcp_flags = tcph->th_flags;
        uint32_t th_len = static_cast<uint32_t>(tcph->th_off) * 4u;
        payload_len = (tp_cap > th_len) ? tp_cap - th_len : 0;

    } else if (proto == IPPROTO_UDP) {
        if (tp_cap < sizeof(struct udphdr)) { ++ctx->skip_count; return; }
        const auto *udph = reinterpret_cast<const struct udphdr *>(tp_ptr);
        src_port    = ntohs(udph->uh_sport);
        dst_port    = ntohs(udph->uh_dport);
        payload_len = (tp_cap > 8) ? tp_cap - 8 : 0;
    } else {
        payload_len = tp_cap;
    }

    // ── Evict stale flows periodically (every 512 packets) ───────────────────
    if ((ctx->pkt_count & 0x1FF) == 0)
        ctx->evict_stale(ts);

    // ── Upsert into flow table ────────────────────────────────────────────────
    FlowKey key(src_ip, dst_ip, src_port, dst_port, proto);
    auto   [it, inserted] = ctx->flows.emplace(key, FlowStats{});
    FlowStats &st = it->second;

    if (inserted) {
        st.start_time   = ts;
        st.initiator_ip = src_ip;
        st.src_oui      = src_oui;
        st.oui_is_iot   = oui_is_iot;
        st.file_tag     = ctx->file_tag;
    }

    // Direction
    bool is_fwd = (src_ip == st.initiator_ip);
    if (is_fwd) { ++st.fwd_pkts; st.fwd_bytes += header->len; }
    else        { ++st.bwd_pkts; st.bwd_bytes += header->len; }

    st.update_pkt_len(header->len);
    st.update_iat(ts);

    // ── TCP flag counters ─────────────────────────────────────────────────────
    if (proto == IPPROTO_TCP) {
        if (tcp_flags & TH_SYN)  ++st.syn_cnt;
        if (tcp_flags & TH_ACK)  ++st.ack_cnt;
        if (tcp_flags & TH_PUSH) ++st.psh_cnt;
        if (tcp_flags & TH_RST)  ++st.rst_cnt;
        if (tcp_flags & TH_FIN)  ++st.fin_cnt;
        if (tcp_flags & TH_URG)  ++st.urg_cnt;
    }

    // ── Protocol / port indicators ────────────────────────────────────────────
    auto ports_match = [&](uint16_t p) {
        return src_port == p || dst_port == p;
    };

    if (ports_match(IotPorts::MQTT)     || ports_match(IotPorts::MQTT_TLS)) st.is_mqtt   = true;
    if (ports_match(IotPorts::COAP)     || ports_match(IotPorts::COAP_DTLS)) st.is_coap  = true;
    if (ports_match(IotPorts::MDNS))                                          st.is_mdns   = true;
    if (ports_match(IotPorts::SSDP))                                          st.is_ssdp   = true;
    if (ports_match(IotPorts::NTP))                                           st.is_ntp    = true;
    if (ports_match(IotPorts::TELNET))                                        st.is_telnet = true;
    if (ports_match(IotPorts::MODBUS)   || ports_match(IotPorts::BACNET))    st.is_modbus = true;
    if (ports_match(IotPorts::HTTP)     || ports_match(IotPorts::HTTP_ALT))  st.is_http   = true;
    if (ports_match(IotPorts::HTTPS))                                         st.is_https  = true;
    if (ports_match(IotPorts::DNS))                                           st.is_dns    = true;

    (void)ttl; (void)tos; (void)payload_len;   // available for future features
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Process one PCAP file
// ═══════════════════════════════════════════════════════════════════════════════

struct FileStats {
    uint64_t    packets = 0;
    uint64_t    flows   = 0;
    uint64_t    skipped = 0;
    bool        ok      = true;
    std::string error_msg;
};

static FileStats process_file(const fs::path &path,
                               CsvWriter     &writer,
                               int            iot_threshold,
                               double         idle_timeout,
                               double         active_timeout,
                               const DeviceMap &device_map)
{
    FileStats stats;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(path.c_str(), errbuf);
    if (!handle) { stats.ok = false; stats.error_msg = errbuf; return stats; }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        stats.ok        = false;
        stats.error_msg = "Non-Ethernet datalink (" +
                          std::to_string(pcap_datalink(handle)) + ")";
        pcap_close(handle);
        return stats;
    }

    FlowTable flows;
    flows.reserve(4096);

    PacketCtx ctx{flows, writer, path.stem().string(),
                  iot_threshold, idle_timeout, active_timeout, device_map};

    int rc = pcap_loop(handle, 0, packet_handler,
                       reinterpret_cast<u_char *>(&ctx));
    if (rc == -1) { stats.ok = false; stats.error_msg = pcap_geterr(handle); }
    pcap_close(handle);

    // ── Flush all remaining flows ──────────────────────────────────────────────
    for (auto &[k, s] : flows) {
        s.compute_iot_score(iot_threshold);
        if (!device_map.empty()) {
            auto it = device_map.find(s.initiator_ip);
            if (it != device_map.end()) s.iot_hint = it->second;
        }
        writer.write(k, s);
    }

    stats.packets = ctx.pkt_count;
    stats.flows   = flows.size();
    stats.skipped = ctx.skip_count;
    return stats;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════════════════════════

static std::vector<fs::path> collect_pcaps(const fs::path &dir, bool recursive)
{
    std::vector<fs::path> files;
    auto add = [&](const fs::directory_entry &e) {
        if (!e.is_regular_file()) return;
        auto ext = e.path().extension().string();
        if (ext == ".pcap" || ext == ".pcapng" || ext == ".cap")
            files.push_back(e.path());
    };
    if (recursive)
        for (const auto &e : fs::recursive_directory_iterator(dir)) add(e);
    else
        for (const auto &e : fs::directory_iterator(dir)) add(e);
    std::sort(files.begin(), files.end());
    return files;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Configuration + CLI
// ═══════════════════════════════════════════════════════════════════════════════

struct Config {
    fs::path    pcap_dir;
    fs::path    output_csv;
    fs::path    device_csv;
    bool        recursive      = false;
    bool        verbose        = false;
    std::size_t write_buf_sz   = 131'072;   // 128 KiB
    double      idle_timeout   = 60.0;
    double      active_timeout = 300.0;
    int         iot_threshold  = 3;
};

static void usage(const char *prog) {
    std::cerr
        << "Usage: " << prog
        << " [-r] [-v] [-m bytes] [-i secs] [-a secs] [-t thresh] [-d inv.csv]"
           " <pcap_dir> <out.csv>\n\n"
        << "  -r          Recurse sub-directories\n"
        << "  -v          Verbose per-file stats\n"
        << "  -m bytes    Write buffer  (default 131072)\n"
        << "  -i secs     Idle flow timeout   (default 60)\n"
        << "  -a secs     Active flow timeout (default 300)\n"
        << "  -t thresh   IoT score threshold (default 3, range 0-10)\n"
        << "  -d inv.csv  Device inventory CSV (ip,label) to override heuristic\n";
}

static Config parse_args(int argc, char **argv) {
    Config cfg;
    int i = 1;
    for (; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "-r")                   cfg.recursive     = true;
        else if (a == "-v")                   cfg.verbose       = true;
        else if (a == "-m" && i+1 < argc)     cfg.write_buf_sz  = std::stoul(argv[++i]);
        else if (a == "-i" && i+1 < argc)     cfg.idle_timeout  = std::stod(argv[++i]);
        else if (a == "-a" && i+1 < argc)     cfg.active_timeout= std::stod(argv[++i]);
        else if (a == "-t" && i+1 < argc)     cfg.iot_threshold = std::stoi(argv[++i]);
        else if (a == "-d" && i+1 < argc)     cfg.device_csv    = argv[++i];
        else break;
    }
    if (i + 2 != argc) { usage(argv[0]); exit(1); }
    cfg.pcap_dir   = argv[i];
    cfg.output_csv = argv[i+1];
    return cfg;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════════════════════

int main(int argc, char **argv)
{
    Config cfg = parse_args(argc, argv);

    if (!fs::is_directory(cfg.pcap_dir)) {
        std::cerr << "Error: " << cfg.pcap_dir << " is not a directory\n";
        return 1;
    }

    auto files = collect_pcaps(cfg.pcap_dir, cfg.recursive);
    if (files.empty()) {
        std::cerr << "No PCAP files found in " << cfg.pcap_dir << '\n';
        return 1;
    }

    DeviceMap device_map = load_device_inventory(cfg.device_csv);
    if (!device_map.empty())
        std::cout << "Loaded " << device_map.size()
                  << " device labels from inventory.\n";

    std::cout << "Found " << files.size() << " PCAP file(s).\n"
              << "IoT threshold: " << cfg.iot_threshold
              << "  |  idle timeout: " << cfg.idle_timeout << " s"
              << "  |  active timeout: " << cfg.active_timeout << " s\n"
              << "Output: " << cfg.output_csv << "\n\n";

    CsvWriter writer(cfg.output_csv, cfg.write_buf_sz);

    uint64_t total_pkts = 0, total_flows = 0, err_files = 0;
    auto t0 = std::chrono::steady_clock::now();

    for (std::size_t idx = 0; idx < files.size(); ++idx) {
        const auto &path = files[idx];
        int pct = static_cast<int>(100.0 * idx / files.size());
        std::cout << '\r' << std::setw(3) << pct << "%  "
                  << path.filename().string().substr(0, 50)
                  << std::string(20, ' ') << std::flush;

        auto st = process_file(path, writer, cfg.iot_threshold,
                               cfg.idle_timeout, cfg.active_timeout, device_map);

        if (!st.ok) {
            ++err_files;
            std::cerr << "\n[SKIP] " << path.filename() << ": " << st.error_msg << '\n';
        } else {
            total_pkts  += st.packets;
            total_flows += st.flows;
            if (cfg.verbose)
                std::cout << "\n  " << path.filename().string()
                          << "  pkts=" << st.packets << "  flows=" << st.flows
                          << "  skipped=" << st.skipped << '\n';
        }
        writer.flush();   // flush after each file for crash resilience
    }

    auto   t1  = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();

    std::cout << "\r100%  done" << std::string(60, ' ') << '\n'
              << "\n══════════════════════════════════════════════════\n"
              << "  Files processed : " << (files.size() - err_files)
                                        << " / " << files.size()  << '\n'
              << "  Total packets   : " << total_pkts              << '\n'
              << "  Flows exported  : " << writer.rows_written     << '\n'
              << "  Error files     : " << err_files               << '\n'
              << "  Elapsed         : " << std::fixed
                                        << std::setprecision(2) << sec << " s\n"
              << "  Throughput      : "
              << static_cast<uint64_t>(total_pkts / (sec + 1e-9))
              << " pkt/s\n"
              << "══════════════════════════════════════════════════\n";
    return 0;
}

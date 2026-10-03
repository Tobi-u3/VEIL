@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load policy/tuning/json-logs

module VEIL;
export {
    redef enum Log::ID += { LOG };
    const protected_servers: set[addr] = {} &redef;
    global observed_destination: function(dst: addr): bool;
    type Info: record {
        ts: time &log;
        kind: string &log;
        uid: string &log;
        src: addr &log;
        dst: addr &log;
        sport: count &log &default=0;
        dport: count &log &default=0;
        length: count &log &default=0;
        proto: string &log &default="other";
        tcp_flags: count &log &optional;
        syn: bool &log &default=F;
        start: bool &log &default=F;
        query: string &log &optional;
        qtype: count &log &optional;
        ja4: string &log &optional;
    };
}
function observed_destination(dst: addr): bool {
    return |protected_servers| == 0 || dst in protected_servers;
}
event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="veil_events"]);
    Log::set_buf(LOG, F);
}
event new_packet(c: connection, p: pkt_hdr) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local length: count = 0;
    if (p?$ip) { src=p$ip$src; dst=p$ip$dst; length=p$ip$len; }
    else if (p?$ip6) { src=p$ip6$src; dst=p$ip6$dst; length=p$ip6$len+40; }
    else return;
    if (!observed_destination(dst)) return;
    local sp: count = 0;
    local dp: count = 0;
    local syn = F;
    local beginning = F;
    local proto = "other";
    if (p?$tcp) {
        proto="tcp";
        sp=port_to_count(p$tcp$sport); dp=port_to_count(p$tcp$dport);
        syn=(p$tcp$flags % 4 >= 2) && (p$tcp$flags % 32 < 16);
        beginning=syn;
    }
    else if (p?$udp) {
        proto="udp";
        sp=port_to_count(p$udp$sport); dp=port_to_count(p$udp$dport);
        beginning=(c$orig$num_pkts == 1);
    }
    else if (p?$icmp) proto="icmp";
    local rec: Info = [$ts=network_time(),$kind="packet",$uid=c$uid,$src=src,$dst=dst,
        $sport=sp,$dport=dp,$length=length,$proto=proto,$syn=syn,$start=beginning];
    if (p?$tcp) rec$tcp_flags=p$tcp$flags;
    Log::write(LOG, rec);
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    if (!observed_destination(c$id$resp_h)) return;
    Log::write(LOG, [$ts=network_time(),$kind="dns",$uid=c$uid,$src=c$id$orig_h,
        $dst=c$id$resp_h,$query=query,$qtype=qtype]);
}

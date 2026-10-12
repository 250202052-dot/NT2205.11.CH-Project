@load base/protocols/conn

# Moi packet: chi doc header va thoi gian. Khong doc packet_contents/payload.
module PacketMetadata;
export {
    redef enum Log::ID += { LOG };
    const max_sequence_packets: count = 32 &redef;
    type Side: record {
        packets: count &default=0;
        last_ts: time &optional;
        intervals: count &default=0;
        mean: double &default=0.0;
        m2: double &default=0.0;
        unordered: count &default=0;
        # Thu tu flags: FIN,SYN,RST,PSH,ACK,URG,ECE,CWR.
        flags: vector of count &default=vector(0,0,0,0,0,0,0,0);
    };
    type State: record {
        orig: Side &default=[];
        resp: Side &default=[];
        sizes: vector of count &default=vector();
        directions: vector of count &default=vector();
    };
    type Info: record {
        ts: time &log;
        uid: string &log;
        metadata_version: string &log &default="packet-metadata-v1";
        sequence_limit: count &log;
        orig_observed_packets: count &log;
        resp_observed_packets: count &log;
        orig_iat_count: count &log;
        resp_iat_count: count &log;
        orig_iat_mean: double &log &optional;
        orig_iat_std: double &log &optional;
        resp_iat_mean: double &log &optional;
        resp_iat_std: double &log &optional;
        unordered_timestamps: count &log;
        pkt_size_vector: vector of count &log;
        # 0 = originator; 1 = responder. Size = IPv4 total len / IPv6 len+40.
        pkt_direction_vector: vector of count &log;
        sequence_truncated: bool &log;
        tcp_flags_orig: vector of count &log &optional;
        tcp_flags_resp: vector of count &log &optional;
    };
    global update_side: function(side: Side, ts: time, flags: count): Side;
}
redef record connection += { packet_metadata: State &optional; };

function update_side(side: Side, ts: time, flags: count): Side
    {
    # Welford: tinh mean/std khong can luu toan bo timestamp.
    if ( side?$last_ts )
        {
        if ( ts < side$last_ts ) ++side$unordered;
        else
            {
            local gap = interval_to_double(ts - side$last_ts);
            ++side$intervals;
            local delta = gap - side$mean;
            side$mean += delta / side$intervals;
            side$m2 += delta * (gap - side$mean);
            }
        }
    if ( ! side?$last_ts || ts >= side$last_ts ) side$last_ts = ts;
    ++side$packets;
    local masks: vector of count = vector(1,2,4,8,16,32,64,128);
    for ( i in masks )
        if ( (flags / masks[i]) % 2 == 1 ) ++side$flags[i];
    return side;
    }

event zeek_init() &priority=5
    {
    if ( max_sequence_packets < 1 || max_sequence_packets > 128 )
        Reporter::fatal("Packet sequence limit must be 1..128");
    Log::create_stream(LOG, [$columns=Info, $path="packet_metadata"]);
    }

event new_packet(c: connection, p: pkt_hdr)
    {
    if ( ! p?$ip && ! p?$ip6 ) return;
    if ( ! c?$packet_metadata ) c$packet_metadata = [];
    local size = p?$ip ? p$ip$len : p$ip6$len + 40;
    local source = p?$ip ? p$ip$src : p$ip6$src;
    local is_orig = source == c$id$orig_h;
    # Neu hai dau cung IP, port giup phan biet chieu TCP/UDP.
    if ( p?$tcp ) is_orig = is_orig && p$tcp$sport == c$id$orig_p;
    else if ( p?$udp ) is_orig = is_orig && p$udp$sport == c$id$orig_p;
    local flags: count = p?$tcp ? p$tcp$flags : 0;
    if ( is_orig ) c$packet_metadata$orig = update_side(c$packet_metadata$orig, network_time(), flags);
    else c$packet_metadata$resp = update_side(c$packet_metadata$resp, network_time(), flags);
    if ( |c$packet_metadata$sizes| < max_sequence_packets )
        {
        c$packet_metadata$sizes[|c$packet_metadata$sizes|] = size;
        c$packet_metadata$directions[|c$packet_metadata$directions|] = is_orig ? 0 : 1;
        }
    }

event connection_state_remove(c: connection) &priority=-10
    {
    if ( ! c?$packet_metadata ) return;
    local s = c$packet_metadata;
    local r: Info = [$ts=c$start_time, $uid=c$uid, $sequence_limit=max_sequence_packets,
        $orig_observed_packets=s$orig$packets, $resp_observed_packets=s$resp$packets,
        $orig_iat_count=s$orig$intervals, $resp_iat_count=s$resp$intervals,
        $unordered_timestamps=s$orig$unordered+s$resp$unordered,
        $pkt_size_vector=s$sizes, $pkt_direction_vector=s$directions,
        $sequence_truncated=s$orig$packets+s$resp$packets > max_sequence_packets];
    if ( s$orig$intervals > 0 )
        { r$orig_iat_mean=s$orig$mean; r$orig_iat_std=sqrt(s$orig$m2 < 0.0 ? 0.0 : s$orig$m2 / s$orig$intervals); }
    if ( s$resp$intervals > 0 )
        { r$resp_iat_mean=s$resp$mean; r$resp_iat_std=sqrt(s$resp$m2 < 0.0 ? 0.0 : s$resp$m2 / s$resp$intervals); }
    if ( get_port_transport_proto(c$id$orig_p) == tcp )
        { r$tcp_flags_orig=s$orig$flags; r$tcp_flags_resp=s$resp$flags; }
    Log::write(LOG, r);
    }

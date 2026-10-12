# Fixture event/header only. Raw sentinel duoc truyen vao event nhung khong log.
function check(value: bool, msg: string)
    { if ( ! value ) Reporter::fatal(msg); }
event zeek_init() &priority=-30
    {
    local s: PacketMetadata::Side = [];
    s = PacketMetadata::update_side(s, double_to_time(1.0), 2);
    s = PacketMetadata::update_side(s, double_to_time(1.1), 18);
    s = PacketMetadata::update_side(s, double_to_time(1.3), 16);
    check(s$intervals == 2 && s$packets == 3, "IAT count");
    check(s$mean > 0.14999 && s$mean < 0.15001, "IAT mean");
    check(sqrt(s$m2 / s$intervals) > 0.04999 && sqrt(s$m2 / s$intervals) < 0.05001, "population std");
    check(s$flags[1] == 2 && s$flags[4] == 2, "TCP SYN/ACK bit counters");
    s = PacketMetadata::update_side(s, double_to_time(1.2), 0);
    check(s$unordered == 1 && s$intervals == 2, "unordered timestamp not counted");
    local sides: PacketMetadata::State = [];
    sides$orig = PacketMetadata::update_side(sides$orig,double_to_time(1.0),2);
    sides$resp = PacketMetadata::update_side(sides$resp,double_to_time(1.05),18);
    sides$orig = PacketMetadata::update_side(sides$orig,double_to_time(1.2),16);
    sides$resp = PacketMetadata::update_side(sides$resp,double_to_time(1.45),16);
    check(sides$orig$mean > 0.19999 && sides$orig$mean < 0.20001, "originator IAT independent");
    check(sides$resp$mean > 0.39999 && sides$resp$mean < 0.40001, "responder IAT independent");
    local packet: PacketMetadata::Info = [$ts=double_to_time(1.0), $uid="testExtra", $sequence_limit=32,
        $orig_observed_packets=3, $resp_observed_packets=0, $orig_iat_count=2, $resp_iat_count=0,
        $orig_iat_mean=0.15, $orig_iat_std=0.05, $unordered_timestamps=0,
        $pkt_size_vector=vector(60,60,52), $pkt_direction_vector=vector(0,0,0), $sequence_truncated=F,
        $tcp_flags_orig=vector(0,2,0,0,2,0,0,0), $tcp_flags_resp=vector(0,0,0,0,0,0,0,0)];
    Log::write(PacketMetadata::LOG, packet);
    local id: conn_id=[$orig_h=192.0.2.1,$orig_p=12345/tcp,$resp_h=192.0.2.2,$resp_p=443/tcp,$proto=6];
    local ep: endpoint=[$size=0,$state=0,$flow_label=0];
    local services: set[string] = set();
    local c: connection=[$id=id,$orig=ep,$resp=ep,$start_time=double_to_time(1.0),
        $duration=0secs,$service=services,$history="",$uid="testExtra"];
    c$conn=[$ts=double_to_time(1.0),$uid="testExtra",$id=id,$proto=tcp];
    event ssl_extension(c,T,65037,"PRIVATE_PAYLOAD_MARKER");
    event ssl_extension(c,T,13,"PRIVATE_PAYLOAD_MARKER");
    event ssl_client_hello(c,771,771,double_to_time(1.0),"PRIVATE_PAYLOAD_MARKER","PRIVATE_PAYLOAD_MARKER",vector(4865),vector(0));
    event ssl_extension_signature_algorithm(c,T,vector([$HashAlgorithm=8,$SignatureAlgorithm=4]));
    event ssl_server_signature(c,[$HashAlgorithm=4,$SignatureAlgorithm=1],"PRIVATE_PAYLOAD_MARKER");
    event connection_state_remove(c);
    print "PASS extended metadata events";
    }

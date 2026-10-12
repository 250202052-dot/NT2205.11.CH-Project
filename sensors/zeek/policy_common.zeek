@load base/frameworks/notice

module MetadataPolicy;
export {
    const version = "metadata-crypto-v1" &redef;
    global emit: function(uid: string, id: conn_id, note: Notice::Type, rule: string, observed: string);
}
redef record Notice::Info += {
    rule_id: string &log &optional;
    policy_version: string &log &optional;
    observed_metadata: string &log &optional;
};
function emit(uid: string, id: conn_id, note: Notice::Type, rule: string, observed: string)
    {
    # Only algorithm/status/size tokens supplied by our rules, no payload text.
    local safe = |observed| <= 160 && /^[A-Za-z0-9_.:@+ -]+$/ == observed ? observed : "unparsed_metadata";
    NOTICE([$note=note, $uid=uid, $id=id, $msg=rule,
            $rule_id=rule, $policy_version=version, $observed_metadata=safe,
            $identifier=cat(uid, ":", rule)]);
    }

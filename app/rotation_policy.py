"""Only complete TCP observations may count toward automated replacement."""


def complete_observation(observation):
    if observation.get("error"):
        return False
    samples = observation.get("samples")
    attempts = observation.get("attempts", [])
    count = observation.get("success_count")
    if type(samples) is not int or not 1 <= samples <= 5 or type(count) is not int:
        return False
    if not isinstance(attempts, list) or len(attempts) != samples:
        return False
    if any(not isinstance(a, dict) or type(a.get("ok")) is not bool for a in attempts):
        return False
    if sum(a["ok"] for a in attempts) != count:
        return False
    # Explicit local network/permission errors are not target failures.
    return all(a["ok"] or a.get("error") in {"timeout", "connection_refused", "connection_reset"} for a in attempts)


def qualifying_failure(record, result):
    if result.get("status") not in {"reachable", "unreachable"} or not result.get("target_ip"):
        return False
    observations = [o for o in result.get("observations", []) if complete_observation(o)]
    if record.get("rotation_trigger", "tcp_failure") == "tcp_failure":
        local = [o for o in observations if o.get("region_type") == "local"]
        return bool(local) and all(o["success_count"] == 0 for o in local)
    if result.get("gfw_status") != "suspected_filtering":
        return False
    mainland = [o for o in observations if o.get("region_type") == "mainland"]
    overseas = [o for o in observations if o.get("region_type") == "overseas"]
    return bool(mainland and overseas) and all(o["success_count"] == 0 for o in mainland) and any(o["success_count"] > 0 for o in overseas)

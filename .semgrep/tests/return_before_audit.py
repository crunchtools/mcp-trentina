# Fixture for trentina-return-before-audit.


async def _route_tools_call(profile, req_id, params):
    name = params.get("name")
    if name is None:
        # ruleid: trentina-return-before-audit
        return _err(req_id, -32602, "Unknown tool")
    if not filter_tools(name):
        _audit(profile.name, "b", name, "denied_allowlist", 0)
        # ok: trentina-return-before-audit
        return _err(req_id, -32602, "not permitted")
    guard = check(name)
    if guard:
        # ruleid: trentina-return-before-audit
        return _err(req_id, -32602, guard)
    try:
        result = await dispatch(name)
    except BackendCallError as exc:
        _audit(profile.name, "b", name, classify_exception(exc), 0)
        # ok: trentina-return-before-audit
        return _err(req_id, -32603, "failed")
    return _ok(req_id, result)


async def _route_tools_list(profile, req_id):
    # ok: trentina-return-before-audit
    return _err(req_id, -32601, "not handled here")

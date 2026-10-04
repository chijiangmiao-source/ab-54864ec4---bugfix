"""One-shot smoke checks for the Compose `verify` service.

Waits for the app container's /health, then exercises the review page and
the verification API over HTTP.  Exits 0 when every check passes, 1 otherwise.
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from builder import (illegal_lookupswitch_case_class,
                     legal_construction_class,
                     legal_tableswitch_class,
                     sparse_lookupswitch_class,
                     switch_join_conflict_class,
                     switch_target_middle_class,
                     switch_uninit_escape_class,
                     tableswitch_low_gt_high_class,
                     truncated_lookupswitch_class,
                     truncated_tableswitch_class,
                     uninitialized_escape_class,
                     unordered_lookupswitch_class,
                     duplicate_lookupswitch_key_class)  # noqa: E402

APP = os.environ.get("APP_URL", "http://app:8080").rstrip("/")

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""),
          flush=True)
    if not cond:
        FAILURES.append(name)


def get(path):
    try:
        with urllib.request.urlopen(APP + path, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # connection refused etc.
        return None, str(e).encode()


def post(obj):
    req = urllib.request.Request(
        APP + "/api/verify", data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait_for_health():
    for _ in range(60):
        status, body = get("/health")
        if status == 200:
            return True
        time.sleep(0.5)
    return False


def main():
    print(f"smoke against {APP}", flush=True)
    check("health endpoint becomes ready", wait_for_health())

    status, body = get("/health")
    check("GET /health -> 200 {\"status\":\"ok\"}",
          status == 200 and json.loads(body) == {"status": "ok"},
          f"status={status} body={body!r}")

    status, body = get("/")
    check("GET / serves the review page",
          status == 200 and b"<textarea" in body and b"/api/verify" in body,
          f"status={status}")

    ok_class = base64.b64encode(legal_construction_class()).decode("ascii")
    status, res = post({"class_b64": ok_class})
    check("POST legal class -> ok=true with per-offset states",
          status == 200 and res.get("ok") is True and len(res.get("states", [])) > 0,
          f"status={status} res={res}")
    handler_ok = (res.get("handlers") and
                  res["handlers"][0]["stack"] == ["ref java/lang/Throwable"])
    check("handler entry state reported", bool(handler_ok),
          f"handlers={res.get('handlers')}")

    bad_class = base64.b64encode(uninitialized_escape_class()).decode("ascii")
    status, res = post({"class_b64": bad_class})
    err = res.get("error") or {}
    check("POST half-initialized class -> ok=false, first evidence at offset 4",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "uninitialized-escapes-to-handler"
          and err.get("offset") == 4,
          f"status={status} res={res}")

    status, res = post({"class_b64": "###not-base64###"})
    check("invalid Base64 -> 400 invalid-base64",
          status == 400 and (res.get("error") or {}).get("kind") == "invalid-base64",
          f"status={status} res={res}")

    big = base64.b64encode(b"\x00" * 70000).decode("ascii")
    status, res = post({"class_b64": big})
    check("oversize class -> 400 class-too-large",
          status == 400 and (res.get("error") or {}).get("kind") == "class-too-large",
          f"status={status} res={res}")

    # -- sparse multi-way branches ---------------------------------------
    def verify_bytes(data):
        return post({"class_b64": base64.b64encode(data).decode("ascii")})

    def state_map(res):
        return {s["offset"]: s for s in res.get("states", [])}

    bad_switch, sw_marks = illegal_lookupswitch_case_class()
    status, res = verify_bytes(bad_switch)
    err = res.get("error") or {}
    check("illegal matched switch case rejected at the case offset",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "stack-underflow"
          and err.get("offset") == sw_marks["bad"] == 21,
          f"status={status} res={res}")
    sm = state_map(res)
    check("matched case target is reachable (not hidden as unreachable)",
          sm.get(sw_marks["bad"], {}).get("reachable") is True
          and sm.get(sw_marks["d"], {}).get("reachable") is True,
          f"states={res.get('states')}")

    sparse, sp_marks = sparse_lookupswitch_class()
    status, res = verify_bytes(sparse)
    check("legal sparse lookupswitch (negative + far keys) passes",
          status == 200 and res.get("ok") is True,
          f"status={status} res={res}")
    sm = state_map(res)
    frames_ok = (
        sm[sp_marks["ret_neg"]]["reachable"]
        and sm[sp_marks["ret_neg"]]["stack"] == []
        and sm[sp_marks["join"]]["locals"] == ["int"]
        and sm[sp_marks["construct"]]["insn"].startswith("new ")
        and sm[sp_marks["h"]]["stack"] == ["ref java/lang/Throwable"]
    )
    check("per-offset frames for return/local-join/construction/handler",
          bool(frames_ok),
          f"marks={sp_marks} states={res.get('states')} "
          f"handlers={res.get('handlers')}")
    check("construction-range handler carries no half-initialized object",
          len(res.get("handlers", [])) == 1
          and res["handlers"][0]["reachable"]
          and res["handlers"][0]["locals"] == ["top"]
          and (res["handlers"][0]["start_pc"], res["handlers"][0]["end_pc"])
          == (sp_marks["construct"], sp_marks["h"]),
          f"handlers={res.get('handlers')}")

    table_ok, tb_marks = legal_tableswitch_class()
    status, res = verify_bytes(table_ok)
    check("legal tableswitch passes with reachable join",
          status == 200 and res.get("ok") is True
          and state_map(res)[tb_marks["join"]]["locals"] == ["int"],
          f"status={status} res={res}")

    conflict, cf_marks = switch_join_conflict_class()
    status, res = verify_bytes(conflict)
    err = res.get("error") or {}
    check("switch branch join conflict rejected at join offset",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "stack-height-mismatch"
          and err.get("offset") == cf_marks["join"],
          f"status={status} res={res}")

    mid, mid_marks = switch_target_middle_class()
    status, res = verify_bytes(mid)
    err = res.get("error") or {}
    check("switch target into instruction middle rejected",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "bad-branch-target"
          and err.get("offset") == 1
          and f"offset {mid_marks['mid']}" in err.get("message", ""),
          f"status={status} res={res}")

    for label, data, kind in (
        ("truncated lookupswitch", truncated_lookupswitch_class(),
         "truncated-instruction"),
        ("unordered lookupswitch keys", unordered_lookupswitch_class(),
         "bad-lookupswitch"),
        ("duplicate lookupswitch keys", duplicate_lookupswitch_key_class(),
         "bad-lookupswitch"),
        ("truncated tableswitch", truncated_tableswitch_class(),
         "truncated-instruction"),
        ("tableswitch low>high", tableswitch_low_gt_high_class(),
         "bad-tableswitch"),
    ):
        status, res = verify_bytes(data)
        err = res.get("error") or {}
        check(f"{label} -> {kind} at offset 1",
              status == 200 and res.get("ok") is False
              and err.get("kind") == kind and err.get("offset") == 1,
              f"status={status} res={res}")

    leak, leak_marks = switch_uninit_escape_class()
    status, res = verify_bytes(leak)
    err = res.get("error") or {}
    check("half-initialized object via switch block rejected",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "uninitialized-escapes-to-handler"
          and err.get("offset") == leak_marks["leak"],
          f"status={status} res={res}")

    if FAILURES:
        print(f"SMOKE FAILED: {len(FAILURES)} check(s): {FAILURES}", flush=True)
        return 1
    print("SMOKE OK: all checks passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

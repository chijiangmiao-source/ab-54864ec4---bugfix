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

from builder import (Asm, ClassBuilder, illegal_switch_match_class,
                     legal_construction_class, legal_sparse_switch_class,
                     uninitialized_escape_class)  # noqa: E402

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

    # --- sparse multiway branches -------------------------------------
    sw_bad = base64.b64encode(illegal_switch_match_class()).decode("ascii")
    status, res = post({"class_b64": sw_bad})
    err = res.get("error") or {}
    check("POST illegal switch match -> ok=false, underflow at the match target",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "stack-underflow"
          and err.get("offset") == 36,
          f"status={status} res={res}")
    # Partial evidence must not hide the match target as unreachable.
    analyzed = {s["offset"]: s for s in res.get("states", [])}
    check("illegal switch match target was analyzed (not shown unreachable)",
          36 in analyzed and analyzed[36].get("reachable") is True,
          f"states={res.get('states')}")

    sw_ok = base64.b64encode(legal_sparse_switch_class()).decode("ascii")
    status, res = post({"class_b64": sw_ok})
    check("POST legal sparse switch -> ok=true",
          status == 200 and res.get("ok") is True,
          f"status={status} res={res}")
    states = {s["offset"]: s for s in res.get("states", [])}
    # Negative-key target (return), small-key join, far-apart-key construction.
    per_target = (
        states.get(36, {}).get("reachable") is True
        and states.get(36, {}).get("insn") == "return"
        and states.get(38, {}).get("stack") == ["int"]
        and states.get(41, {}).get("stack") == []
        and states.get(44, {}).get("stack", []) == [
            "uninit(new@41 com/acme/Diag)"]
        and states.get(48, {}).get("stack") == ["ref com/acme/Diag"]
        and states.get(50, {}).get("stack") == ["int"]
    )
    check("legal sparse switch gives reviewable states at every target",
          bool(per_target), f"states={res.get('states')}")

    # Switch fed with no selector: rejected at the switch itself.
    b = ClassBuilder()
    a = Asm()
    a.lookupswitch("d", [(0, "t")])
    a.label("t")
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    err = res.get("error") or {}
    check("switch with empty stack -> stack-underflow at the switch",
          res.get("ok") is False and err.get("kind") == "stack-underflow"
          and err.get("offset") == 0,
          f"res={res}")

    # Join conflict reached through two switch cases.
    b = ClassBuilder()
    a = Asm()
    a.op(0x03)
    a.lookupswitch("d", [(1, "one"), (2, "two")])
    a.label("one")
    a.op(0x03)
    a.branch(0xA7, "j")
    a.label("two")
    a.branch(0xA7, "j")
    a.label("j")
    a.op(0x57)
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    err = res.get("error") or {}
    check("switch join stack-height conflict -> stack-height-mismatch",
          res.get("ok") is False
          and err.get("kind") == "stack-height-mismatch",
          f"res={res}")

    # Unordered (descending) match keys are a structural rejection.
    b = ClassBuilder()
    a = Asm()
    a.op(0x03)
    a.lookupswitch("d", [(2, "x"), (1, "x")])
    a.label("x")
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    err = res.get("error") or {}
    check("unordered lookupswitch keys -> bad-lookupswitch",
          res.get("ok") is False and err.get("kind") == "bad-lookupswitch",
          f"res={res}")

    # Truncated switch table: npairs promises a pair that is not there.
    b = ClassBuilder()
    a = Asm()
    a.op(0x03)
    a.lookupswitch("d", [(1, "x"), (2, "x"), (3, "x")])
    a.label("x")
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    full = a.build()
    b.add_method("run", full[:-8], max_stack=1, max_locals=0)
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    err = res.get("error") or {}
    check("truncated lookupswitch table -> truncated-instruction",
          res.get("ok") is False
          and err.get("kind") == "truncated-instruction",
          f"res={res}")

    # A case target landing inside another instruction.
    b = ClassBuilder()
    a = Asm()
    a.op(0x03)
    a.lookupswitch("d", [(1, "mid")])
    a.op(0x11)
    a.label("mid")
    a.u2(0x1234)
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    err = res.get("error") or {}
    check("switch case into instruction middle -> bad-branch-target",
          res.get("ok") is False and err.get("kind") == "bad-branch-target"
          and err.get("offset") == 1,
          f"res={res}")

    # Construction inside a switch case with a handler covering the range:
    # initialized refs may cross the exception edge; the handler reports
    # the Throwable entry state.
    b = ClassBuilder("Smoke")
    x = b.cp.cls("com/acme/Diag")
    init = b.cp.methodref("com/acme/Diag", "<init>", "()V")
    a = Asm()
    a.op(0x03)
    a.lookupswitch("d", [(1, "make")])
    a.label("make")
    a.op(0xBB).u2(x)
    a.op(0x59)
    a.op(0xB7).u2(init)
    a.op(0x57)
    a.op(0xB1)
    a.label("h")
    a.op(0x57)
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    raw = a.build()
    b.add_method("run", raw, max_stack=2, max_locals=1,
                 exceptions=[(0, a.labels["h"], a.labels["h"], 0)])
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    ok = res.get("ok") is True
    handler = (res.get("handlers") or [{}])[0]
    check("switch construction path + exception table passes, handler reviewed",
          status == 200 and ok
          and handler.get("reachable") is True
          and handler.get("stack") == ["ref java/lang/Throwable"],
          f"res={res}")

    # Half-initialized object created inside a switch case must still not
    # cross an exception edge into the handler.
    b = ClassBuilder("Bad")
    x = b.cp.cls("com/acme/Diag")
    init = b.cp.methodref("com/acme/Diag", "<init>", "()V")
    a = Asm()
    a.op(0x03)
    a.lookupswitch("d", [(1, "make")])
    a.label("make")
    a.op(0xBB).u2(x)
    a.op(0x4B)
    a.label("nop")
    a.op(0x00)
    a.op(0x2A)
    a.op(0xB7).u2(init)
    a.op(0xB1)
    a.label("h")
    a.op(0x57)
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    raw = a.build()
    b.add_method("run", raw, max_stack=2, max_locals=1,
                 exceptions=[(0, a.labels["h"], a.labels["h"], 0)])
    status, res = post({"class_b64": base64.b64encode(b.build()).decode()})
    err = res.get("error") or {}
    check("half-init object via switch case blocked from handler",
          res.get("ok") is False
          and err.get("kind") == "uninitialized-escapes-to-handler"
          and err.get("offset") == a.labels["nop"],
          f"res={res}")

    status, res = post({"class_b64": "###not-base64###"})
    check("invalid Base64 -> 400 invalid-base64",
          status == 400 and (res.get("error") or {}).get("kind") == "invalid-base64",
          f"status={status} res={res}")

    big = base64.b64encode(b"\x00" * 70000).decode("ascii")
    status, res = post({"class_b64": big})
    check("oversize class -> 400 class-too-large",
          status == 400 and (res.get("error") or {}).get("kind") == "class-too-large",
          f"status={status} res={res}")

    if FAILURES:
        print(f"SMOKE FAILED: {len(FAILURES)} check(s): {FAILURES}", flush=True)
        return 1
    print("SMOKE OK: all checks passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

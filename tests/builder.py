"""Test helper: build real JVM class files (constant pool + Code) by hand.

Used by the unit tests and by the Compose `verify` smoke service to produce
both well-formed and deliberately malformed class files.
"""
import struct

ACC_PUBLIC = 0x0001
ACC_STATIC = 0x0008
ACC_SUPER = 0x0020


def u1(v):
    return struct.pack(">B", v)


def u2(v):
    return struct.pack(">H", v)


def u4(v):
    return struct.pack(">I", v)


class Cp:
    """Constant-pool builder with de-duplication."""

    def __init__(self):
        self.entries = [None]
        self.index = {}

    def _add(self, key, entry):
        if key in self.index:
            return self.index[key]
        idx = len(self.entries)
        self.entries.append(entry)
        self.index[key] = idx
        return idx

    def utf8(self, s):
        return self._add(("Utf8", s), ("utf8", s))

    def cls(self, name):
        return self._add(("Class", name), ("class", self.utf8(name)))

    def string(self, s):
        return self._add(("String", s), ("string", self.utf8(s)))

    def integer(self, v):
        return self._add(("Integer", v), ("int", v))

    def nameandtype(self, n, d):
        return self._add(("NT", n, d), ("nat", self.utf8(n), self.utf8(d)))

    def methodref(self, c, n, d):
        return self._add(("MR", c, n, d),
                         ("methodref", self.cls(c), self.nameandtype(n, d)))

    def render(self):
        out = [u2(len(self.entries))]
        for e in self.entries[1:]:
            tag = e[0]
            if tag == "utf8":
                b = e[1].encode("utf-8")
                out.append(u1(1) + u2(len(b)) + b)
            elif tag == "int":
                out.append(u1(3) + struct.pack(">i", e[1]))
            elif tag == "class":
                out.append(u1(7) + u2(e[1]))
            elif tag == "string":
                out.append(u1(8) + u2(e[1]))
            elif tag == "nat":
                out.append(u1(12) + u2(e[1]) + u2(e[2]))
            elif tag == "methodref":
                out.append(u1(10) + u2(e[1]) + u2(e[2]))
            else:
                raise AssertionError(tag)
        return b"".join(out)


class Asm:
    """Tiny assembler: emits bytes, resolves branch fixups to labels."""

    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (operand_pos, insn_pos, label, width)

    @property
    def pc(self):
        return len(self.buf)

    def label(self, name):
        self.labels[name] = len(self.buf)
        return self

    def op(self, *bs):
        self.buf += bytes(bs)
        return self

    def u2(self, v):
        self.buf += u2(v)
        return self

    def branch(self, opcode, label, wide=False):
        insn = len(self.buf)
        self.buf.append(opcode)
        width = 4 if wide else 2
        self.fixups.append((len(self.buf), insn, label, width))
        self.buf += b"\x00" * width
        return self

    def lookupswitch(self, default, cases):
        """Emit lookupswitch. `cases` is a list of (signed key, label) in
        strictly ascending key order; `default` is the default label.

        Padding to the 4-byte boundary (relative to the method start) is
        emitted automatically; all offsets are resolved as label fixups.
        """
        insn = len(self.buf)
        self.buf.append(0xAB)
        pad = (4 - (len(self.buf) % 4)) % 4
        self.buf += b"\x00" * pad
        default_pos = len(self.buf)
        self.buf += b"\x00" * 4                    # default offset
        self.buf += struct.pack(">i", len(cases))  # npairs
        for key, label in cases:
            self.buf += struct.pack(">i", key)
            self.fixups.append((len(self.buf), insn, label, 4))
            self.buf += b"\x00" * 4
        self.fixups.append((default_pos, insn, default, 4))
        return self

    def tableswitch(self, default, low, labels):
        """Emit tableswitch covering values low .. low+len(labels)-1."""
        insn = len(self.buf)
        self.buf.append(0xAA)
        pad = (4 - (len(self.buf) % 4)) % 4
        self.buf += b"\x00" * pad
        default_pos = len(self.buf)
        high = low + len(labels) - 1
        self.buf += b"\x00" * 4
        self.buf += struct.pack(">ii", low, high)
        for label in labels:
            self.fixups.append((len(self.buf), insn, label, 4))
            self.buf += b"\x00" * 4
        self.fixups.append((default_pos, insn, default, 4))
        return self

    def build(self):
        for pos, insn, label, width in self.fixups:
            off = self.labels[label] - insn
            self.buf[pos:pos + width] = off.to_bytes(width, "big", signed=True)
        return bytes(self.buf)


class ClassBuilder:
    """Assembles a complete class file; `marks` records interesting offsets."""

    def __init__(self, this_name="Test", super_name="java/lang/Object"):
        self.cp = Cp()
        self.this_name = this_name
        self.super_name = super_name
        self.methods = []
        self.marks = {}

    def add_method(self, name, code, max_stack=8, max_locals=4, exceptions=(),
                   desc="()V", access=ACC_PUBLIC | ACC_STATIC):
        self.methods.append({
            "name": name, "code": bytes(code), "max_stack": max_stack,
            "max_locals": max_locals, "exceptions": list(exceptions),
            "desc": desc, "access": access,
        })
        return len(self.methods) - 1

    def build(self):
        cp = self.cp
        this_idx = cp.cls(self.this_name)
        super_idx = cp.cls(self.super_name)
        code_utf = cp.utf8("Code")
        for m in self.methods:
            m["name_idx"] = cp.utf8(m["name"])
            m["desc_idx"] = cp.utf8(m["desc"])
            m["catch_idx"] = [
                cp.cls(c) if isinstance(c, str) else 0
                for (_s, _e, _h, c) in m["exceptions"]
            ]
        out = bytearray()
        out += u4(0xCAFEBABE) + u2(0) + u2(52)
        out += cp.render()
        out += u2(ACC_PUBLIC | ACC_SUPER) + u2(this_idx) + u2(super_idx)
        out += u2(0)  # interfaces
        out += u2(0)  # fields
        out += u2(len(self.methods))
        for i, m in enumerate(self.methods):
            body = bytearray()
            body += u2(m["max_stack"]) + u2(m["max_locals"])
            body += u4(len(m["code"])) + m["code"]
            body += u2(len(m["exceptions"]))
            for (s, e, h, _), ci in zip(m["exceptions"], m["catch_idx"]):
                body += u2(s) + u2(e) + u2(h) + u2(ci)
            body += u2(0)  # Code attributes
            out += u2(m["access"]) + u2(m["name_idx"]) + u2(m["desc_idx"])
            out += u2(1)  # one attribute
            self.marks[f"method{i}.attr_name_off"] = len(out)
            out += u2(code_utf)
            self.marks[f"method{i}.attr_len_off"] = len(out)
            out += u4(len(body))
            out += body
        out += u2(0)  # class attributes
        return bytes(out)


# ---------------------------------------------------------------------------
# Shared fixtures (unit tests, API tests and the Compose smoke service)
# ---------------------------------------------------------------------------

def legal_construction_class():
    """A passing class: new/dup/invokespecial inside a try, handler after it."""
    b = ClassBuilder("Smoke")
    x = b.cp.cls("com/acme/Diag")
    init = b.cp.methodref("com/acme/Diag", "<init>", "()V")
    a = Asm()
    a.op(0xBB).u2(x)       # 0 new
    a.op(0x59)             # 3 dup
    a.op(0xB7).u2(init)    # 4 invokespecial <init>
    a.op(0x4B)             # 7 astore_0
    a.op(0xB1)             # 8 return
    a.label("h")           # 9
    a.op(0x57)             # 9 pop
    a.op(0xB1)             # 10 return
    b.add_method("run", a.build(), max_stack=2, max_locals=1,
                 exceptions=[(0, 9, 9, 0)])
    return b.build()


def uninitialized_escape_class():
    """A rejected class: local 0 holds an uninitialized object across an
    exception edge (first rejection expected at code offset 4)."""
    b = ClassBuilder("Bad")
    x = b.cp.cls("com/acme/Diag")
    init = b.cp.methodref("com/acme/Diag", "<init>", "()V")
    a = Asm()
    a.op(0xBB).u2(x)       # 0 new
    a.op(0x4B)             # 3 astore_0   (uninitialized -> local 0)
    a.op(0x00)             # 4 nop        <- exception edge carries uninit
    a.op(0x2A)             # 5 aload_0
    a.op(0xB7).u2(init)    # 6 invokespecial <init>
    a.op(0xB1)             # 9 return
    a.label("h")           # 10
    a.op(0x57)             # 10 pop
    a.op(0xB1)             # 11 return
    b.add_method("run", a.build(), max_stack=2, max_locals=1,
                 exceptions=[(0, 10, 10, 0)])
    return b.build()


# ---------------------------------------------------------------------------
# Sparse multi-way branch (lookupswitch / tableswitch) fixtures
#
# The switch fixtures return (class_bytes, marks); marks maps label names to
# code offsets so tests can assert against stable, reviewable positions.
# ---------------------------------------------------------------------------

DIAG_NAME = "com/acme/Diag"


def illegal_lookupswitch_case_class():
    """Rejected: the default target simply returns, but the target of a
    matched key continues at `iadd` with an empty operand stack. The class is
    structurally legal (alignment, length, sorted keys, valid boundaries)."""
    b = ClassBuilder("BadSwitch")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1 (switch key)
    a.lookupswitch("d", [(1, "bad")])
    a.label("d")
    a.op(0xB1)                       # default: return
    a.label("bad")
    a.op(0x60)                       # matched case: iadd underflows
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=2, max_locals=0)
    return b.build(), dict(a.labels)


def sparse_lookupswitch_class():
    """Passing: sparse keys (a negative far value, -7, 42 and a positive far
    value) fan out to a plain return, two int/local join paths and an object
    construction block guarded by its own exception handler."""
    b = ClassBuilder("Sparse")
    x = b.cp.cls(DIAG_NAME)
    init = b.cp.methodref(DIAG_NAME, "<init>", "()V")
    a = Asm()
    a.op(0x10, 0x01)                 # 0 bipush 1
    a.lookupswitch("d", [
        (-2147483648, "ret_neg"),
        (-7, "int_a"),
        (42, "construct"),
        (2147483647, "int_b"),
    ])
    a.label("ret_neg")
    a.op(0xB1)                       # legal return path
    a.label("int_a")
    a.op(0x08)                       # iconst_5
    a.op(0x3B)                       # istore_0
    a.branch(0xA7, "join")
    a.label("construct")
    a.op(0xBB).u2(x)
    a.op(0x59)                       # dup
    a.op(0xB7).u2(init)
    a.op(0x57)
    a.op(0xB1)
    a.label("h")                     # handler of the construction range only
    a.op(0x57)
    a.op(0xB1)
    a.label("int_b")
    a.op(0x02)                       # iconst_m1
    a.op(0x3B)                       # istore_0
    a.branch(0xA7, "join")
    a.label("d")
    a.op(0xB1)                       # default: return
    a.label("join")
    a.op(0x1A)                       # iload_0 (int from both join paths)
    a.op(0x57)
    a.op(0xB1)
    code = a.build()
    b.add_method("run", code, max_stack=2, max_locals=1,
                 exceptions=[(a.labels["construct"], a.labels["h"],
                              a.labels["h"], 0)])
    return b.build(), dict(a.labels)


def switch_join_conflict_class():
    """Rejected: two matched targets converge at `join` with different
    operand-stack heights."""
    b = ClassBuilder("SwitchConflict")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.lookupswitch("d", [(1, "a"), (2, "b")])
    a.label("a")
    a.op(0x03)                       # iconst_0 (one value left on the stack)
    a.branch(0xA7, "join")
    a.label("b")
    a.branch(0xA7, "join")           # empty stack
    a.label("d")
    a.op(0xB1)
    a.label("join")
    a.op(0x57)
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    return b.build(), dict(a.labels)


def switch_target_middle_class():
    """Rejected: a matched offset lands in the middle of a sipush immediate."""
    b = ClassBuilder("SwitchMid")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.lookupswitch("d", [(1, "mid")])
    a.label("d")
    a.op(0xB1)
    a.op(0x11)                       # sipush
    a.label("mid")
    a.u2(0x1234)                     # <- case target points here
    a.op(0x57)
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    return b.build(), dict(a.labels)


def unordered_lookupswitch_class():
    """Rejected while decoding: match keys are not strictly ascending."""
    b = ClassBuilder("SwitchUnordered")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.lookupswitch("d", [(1, "d"), (0, "d")])
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    return b.build()


def duplicate_lookupswitch_key_class():
    """Rejected while decoding: two pairs carry the same match value."""
    b = ClassBuilder("SwitchDup")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.lookupswitch("d", [(1, "d"), (1, "d")])
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    return b.build()


def truncated_lookupswitch_class():
    """Rejected while decoding: npairs reaches past the code array."""
    b = ClassBuilder("SwitchTrunc")
    body = bytearray([0x04])                    # 0 iconst_1
    body += bytes([0xAB, 0x00, 0x00])           # switch at 1 + 2 pad bytes
    body += struct.pack(">ii", 20, 2)           # default, npairs = 2
    body += struct.pack(">ii", 1, 20)           # only one pair actually present
    b.add_method("run", bytes(body), max_stack=2, max_locals=0)
    return b.build()


def truncated_tableswitch_class():
    """Rejected while decoding: [low..high] offsets reach past the code."""
    b = ClassBuilder("TableTrunc")
    body = bytearray([0x04])                    # 0 iconst_1
    body += bytes([0xAA, 0x00, 0x00])           # tableswitch at 1 + pad
    body += struct.pack(">iii", 20, 0, 9)       # default, low=0, high=9
    body += struct.pack(">i", 20)               # one of ten offsets present
    b.add_method("run", bytes(body), max_stack=1, max_locals=0)
    return b.build()


def tableswitch_low_gt_high_class():
    """Rejected while decoding: low > high."""
    b = ClassBuilder("TableBad")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.tableswitch("d", 5, [])        # high = 4 < low = 5
    a.label("d")
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=0)
    return b.build()


def legal_tableswitch_class():
    """Passing: tableswitch over -1..1, two int join paths plus a return."""
    b = ClassBuilder("TableOk")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.tableswitch("d", -1, ["m1", "z", "p1"])
    a.label("m1")
    a.op(0x08)                       # iconst_5
    a.op(0x3B)                       # istore_0
    a.branch(0xA7, "join")
    a.label("z")
    a.op(0xB1)
    a.label("p1")
    a.op(0x02)                       # iconst_m1
    a.op(0x3B)                       # istore_0
    a.branch(0xA7, "join")
    a.label("d")
    a.op(0xB1)
    a.label("join")
    a.op(0x1A)                       # iload_0
    a.op(0x57)
    a.op(0xB1)
    b.add_method("run", a.build(), max_stack=1, max_locals=1)
    return b.build(), dict(a.labels)


def switch_uninit_escape_class():
    """Rejected: a switch case builds an object, stores the half-initialized
    reference in local 0, and an exception range covering that block would
    carry it into the handler."""
    b = ClassBuilder("SwitchUninit")
    x = b.cp.cls(DIAG_NAME)
    init = b.cp.methodref(DIAG_NAME, "<init>", "()V")
    a = Asm()
    a.op(0x04)                       # 0 iconst_1
    a.lookupswitch("d", [(1, "mk")])
    a.label("mk")
    a.op(0xBB).u2(x)
    a.op(0x4B)                       # astore_0 (uninitialized)
    a.label("leak")
    a.op(0x00)                       # nop <- first edge carrying uninit
    a.op(0x2A)
    a.op(0xB7).u2(init)
    a.op(0xB1)
    a.label("h")
    a.op(0x57)
    a.op(0xB1)
    a.label("d")
    a.op(0xB1)
    code = a.build()
    b.add_method("run", code, max_stack=2, max_locals=1,
                 exceptions=[(a.labels["mk"], a.labels["d"],
                              a.labels["h"], 0)])
    return b.build(), dict(a.labels)

"""Unit tests for the JVM type-state verifier."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.verifier import verify_class  # noqa: E402
from builder import (ACC_PUBLIC, ACC_STATIC, Asm, ClassBuilder,  # noqa: E402
                     illegal_switch_match_class,
                     legal_construction_class, legal_sparse_switch_class,
                     uninitialized_escape_class)

DIAG = "com/acme/Diag"


def diag_builder():
    b = ClassBuilder()
    x = b.cp.cls(DIAG)
    init = b.cp.methodref(DIAG, "<init>", "()V")
    return b, x, init


def state_at(res, off):
    for s in res["states"]:
        if s["offset"] == off:
            return s
    raise AssertionError(f"no state at offset {off} in {res['states']}")


class LegalPathTests(unittest.TestCase):
    def test_legal_construction_passes(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x4B)              # 7 astore_0
        a.op(0x2A)              # 8 aload_0
        a.op(0x57)              # 9 pop
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["method"], "run")
        self.assertEqual(state_at(res, 0)["insn"], f"new {DIAG}")
        self.assertEqual(state_at(res, 4)["stack"],
                         [f"uninit(new@0 {DIAG})", f"uninit(new@0 {DIAG})"])
        self.assertEqual(state_at(res, 8)["locals"], [f"ref {DIAG}"])

    def test_construction_inside_try_passes_and_handler_state(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x4B)              # 7 astore_0
        a.op(0xB1)              # 8 return
        a.label("h")            # 9
        a.op(0x57)              # 9 pop
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1,
                     exceptions=[(0, 9, 9, 0)])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(len(res["handlers"]), 1)
        h = res["handlers"][0]
        self.assertEqual((h["start_pc"], h["end_pc"], h["handler_pc"]), (0, 9, 9))
        self.assertEqual(h["catch"], "java/lang/Throwable")
        self.assertEqual(h["stack"], ["ref java/lang/Throwable"])
        self.assertEqual(h["locals"], ["top"])
        self.assertTrue(h["reachable"])

    def test_typed_catch_reported(self):
        b, x, init = diag_builder()
        exc = b.cp.cls("java/lang/Exception")
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.op(0x57)              # 1 pop
        a.op(0xB1)              # 2 return
        a.label("h")            # 3
        a.op(0x57)              # 3 pop
        a.op(0xB1)              # 4 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0,
                     exceptions=[(0, 3, 3, "java/lang/Exception")])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["handlers"][0]["catch"], "java/lang/Exception")
        self.assertEqual(res["handlers"][0]["stack"],
                         ["ref java/lang/Exception"])

    def test_init_initializes_every_copy_of_the_identity(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0x4B)              # 4 astore_0  (one copy into local 0)
        a.op(0xB7).u2(init)     # 5 invokespecial <init>
        a.op(0x2A)              # 8 aload_0
        a.op(0x57)              # 9 pop
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(state_at(res, 8)["locals"], [f"ref {DIAG}"])

    def test_constructor_with_arguments(self):
        b = ClassBuilder()
        x = b.cp.cls(DIAG)
        init = b.cp.methodref(DIAG, "<init>", "(I)V")
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0x08)              # 4 iconst_5
        a.op(0xB7).u2(init)     # 5 invokespecial <init>(I)V
        a.op(0x57)              # 8 pop
        a.op(0xB1)              # 9 return
        b.add_method("run", a.build(), max_stack=3, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))

    def test_same_identity_uninitialized_merge_passes(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x4B)              # 3 astore_0
        a.op(0x03)              # 4 iconst_0
        a.branch(0x99, "j")     # 5 ifeq j
        a.branch(0xA7, "j")     # 8 goto j
        a.label("j")            # 11
        a.op(0x2A)              # 11 aload_0
        a.op(0xB7).u2(init)     # 12 invokespecial <init>
        a.op(0xB1)              # 15 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))

    def test_distinct_refs_merge_to_object(self):
        b, x, init = diag_builder()
        s = b.cp.string("hello")
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "l1")    # 1 ifeq l1
        a.op(0xBB).u2(x)        # 4 new
        a.op(0x59)              # 7 dup
        a.op(0xB7).u2(init)     # 8 invokespecial <init>
        a.op(0x4B)              # 11 astore_0
        a.branch(0xA7, "j")     # 12 goto j
        a.label("l1")           # 15
        a.op(0x12, s)           # 15 ldc "hello"
        a.op(0x4B)              # 17 astore_0
        a.label("j")            # 18
        a.op(0x2A)              # 18 aload_0
        a.op(0x57)              # 19 pop
        a.op(0xB1)              # 20 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(state_at(res, 18)["locals"], ["ref java/lang/Object"])

    def test_athrow_of_initialized_object_passes(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0xBF)              # 7 athrow
        a.label("h")            # 8
        a.op(0x57)              # 8 pop
        a.op(0xB1)              # 9 return
        b.add_method("run", a.build(), max_stack=2, max_locals=0,
                     exceptions=[(0, 8, 8, 0)])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertTrue(res["handlers"][0]["reachable"])

    def test_goto_w_and_iinc_and_ldc(self):
        b = ClassBuilder()
        s = b.cp.string("x")
        a = Asm()
        a.branch(0xC8, "over", wide=True)  # 0 goto_w over
        a.op(0x00)              # 5 nop
        a.label("over")         # 6
        a.op(0x03)              # 6 iconst_0
        a.op(0x3B)              # 7 istore_0
        a.op(0x84, 0x00, 0x01)  # 8 iinc 0 1
        a.op(0x1A)              # 11 iload_0
        a.op(0x57)              # 12 pop
        a.op(0x12, s)           # 13 ldc "x"
        a.op(0x4B)              # 15 astore_0
        a.op(0xB1)              # 16 return
        b.add_method("run", a.build(), max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(state_at(res, 16)["locals"],
                         ["ref java/lang/String"])
        self.assertFalse(state_at(res, 5)["reachable"])

    def test_if_acmpeq_on_nulls(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x01)              # 0 aconst_null
        a.op(0x01)              # 1 aconst_null
        a.branch(0xA5, "t")     # 2 if_acmpeq t
        a.op(0xB1)              # 5 return
        a.label("t")            # 6
        a.op(0xB1)              # 6 return
        b.add_method("run", a.build(), max_stack=2, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))


class RejectionTests(unittest.TestCase):
    def test_uninitialized_local_escapes_to_handler(self):
        res = verify_class(uninitialized_escape_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "uninitialized-escapes-to-handler")
        self.assertEqual(res["error"]["offset"], 4)
        self.assertIn("new@0", res["error"]["message"])
        self.assertIn("handler@10", res["error"]["message"])

    def test_uninitialized_merges_with_initialized_ref_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "l1")    # 1 ifeq l1
        a.op(0xBB).u2(x)        # 4 new
        a.branch(0xA7, "j")     # 7 goto j
        a.label("l1")           # 10
        a.op(0x01)              # 10 aconst_null
        a.label("j")            # 11
        a.op(0x4B)              # 11 astore_0
        a.op(0xB1)              # 12 return
        b.add_method("run", a.build(), max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "incompatible-types")
        self.assertEqual(res["error"]["offset"], 11)

    def test_stack_height_mismatch_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "j")     # 1 ifeq j
        a.op(0x04)              # 4 iconst_1
        a.branch(0xA7, "j")     # 5 goto j
        a.label("j")            # 8
        a.op(0xB1)              # 8 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-height-mismatch")
        self.assertEqual(res["error"]["offset"], 8)

    def test_jump_into_instruction_middle_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.branch(0xA7, "mid")   # 0 goto mid
        a.op(0x11)              # 3 sipush ...
        a.label("mid")          # 4 (middle of the sipush immediate)
        a.u2(0x1234)            # 4..5
        a.op(0x57)              # 6 pop
        a.op(0xB1)              # 7 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-branch-target")
        self.assertEqual(res["error"]["offset"], 0)
        self.assertIn("offset 4", res["error"]["message"])

    def test_truncated_file_rejected(self):
        data = legal_construction_class()
        res = verify_class(data[:len(data) - 7])
        self.assertFalse(res["ok"])
        self.assertIn(res["error"]["kind"], ("truncated", "truncated-attribute"))
        self.assertIsInstance(res["error"]["offset"], int)

    def test_truncated_attribute_length_rejected(self):
        b, x, init = diag_builder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0)
        data = bytearray(b.build())
        off = b.marks["method0.attr_len_off"]
        orig = int.from_bytes(data[off:off + 4], "big")
        data[off:off + 4] = (orig + 32).to_bytes(4, "big")
        res = verify_class(bytes(data))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")
        self.assertEqual(res["error"]["offset"], b.marks["method0.attr_name_off"])

    def test_invalid_handler_ranges_rejected(self):
        # code: 0: bipush 5 (2 bytes) ; 2: return
        cases = [
            ("end_pc beyond code", (0, 99, 2, 0)),
            ("handler into mid-instruction", (0, 2, 1, 0)),
            ("empty range", (2, 2, 0, 0)),
            ("end_pc mid-instruction", (0, 1, 2, 0)),
        ]
        for name, entry in cases:
            with self.subTest(name=name):
                b = ClassBuilder()
                b.add_method("run", bytes([0x10, 0x05, 0xB1]),
                             max_stack=1, max_locals=0, exceptions=[entry])
                res = verify_class(b.build())
                self.assertFalse(res["ok"])
                self.assertEqual(res["error"]["kind"], "bad-handler-range")
                self.assertIsInstance(res["error"]["offset"], int)
                self.assertGreater(res["error"]["offset"], 0)

    def test_double_init_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0xB7).u2(init)     # 7 invokespecial <init> again
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "already-initialized")
        self.assertEqual(res["error"]["offset"], 7)

    def test_athrow_of_uninitialized_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0xBF)              # 3 athrow
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "uninitialized-object-used")
        self.assertEqual(res["error"]["offset"], 3)

    def test_init_on_null_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0x01)              # 0 aconst_null
        a.op(0xB7).u2(init)     # 1 invokespecial <init>
        a.op(0xB1)              # 4 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "type-mismatch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_non_constructor_invokespecial_rejected(self):
        b = ClassBuilder()
        x = b.cp.cls(DIAG)
        m = b.cp.methodref(DIAG, "ping", "()V")
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0xB7).u2(m)        # 3 invokespecial ping
        a.op(0xB1)              # 6 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unsupported-invokespecial")
        self.assertEqual(res["error"]["offset"], 3)

    def test_stack_underflow(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x60, 0xB1]), max_stack=2, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-underflow")
        self.assertEqual(res["error"]["offset"], 0)

    def test_stack_overflow(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03, 0x03, 0x57, 0x57, 0xB1]),
                     max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-overflow")
        self.assertEqual(res["error"]["offset"], 1)

    def test_local_index_out_of_range(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03, 0x3E, 0xB1]),
                     max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "local-index-out-of-range")
        self.assertEqual(res["error"]["offset"], 1)

    def test_astore_of_int_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03, 0x4B, 0xB1]),
                     max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "type-mismatch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_fall_off_end_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03]), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "fall-off-end")
        self.assertEqual(res["error"]["offset"], 0)

    def test_unknown_opcode_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xCA, 0xB1]), max_stack=0, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unknown-opcode")
        self.assertEqual(res["error"]["offset"], 0)

    def test_truncated_instruction_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xBB, 0x00]), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-instruction")
        self.assertEqual(res["error"]["offset"], 0)

    def test_empty_code_rejected(self):
        b = ClassBuilder()
        b.add_method("run", b"", max_stack=0, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "empty-code")

    def test_bad_magic_rejected(self):
        res = verify_class(b"\x00" * 32)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-magic")
        self.assertEqual(res["error"]["offset"], 0)

    def test_non_converging_guard(self):
        res = verify_class(legal_construction_class(), max_steps=2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "non-converging")
        self.assertIsInstance(res["error"]["offset"], int)


class SwitchTests(unittest.TestCase):
    """Sparse multiway branches (lookupswitch / tableswitch)."""

    def test_illegal_match_target_rejected_at_first_stack_violation(self):
        res = verify_class(illegal_switch_match_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-underflow")
        # The violation is inside the matched target, not at the switch.
        self.assertEqual(res["error"]["offset"], 36)
        # Every switch target must have been analyzed (not left unreachable).
        offsets = {s["offset"]: s for s in res["states"]}
        for t in (36, 38, 39, 41):
            self.assertIn(t, offsets)
            self.assertTrue(offsets[t]["reachable"], f"target {t} unreachable")

    def test_switch_with_empty_stack_rejected_at_switch_offset(self):
        b = ClassBuilder()
        a = Asm()
        a.lookupswitch("d", [(0, "t")])  # no selector pushed
        a.label("t")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-underflow")
        self.assertEqual(res["error"]["offset"], 0)

    def test_legal_sparse_switch_passes_with_reviewable_target_states(self):
        res = verify_class(legal_sparse_switch_class())
        self.assertTrue(res["ok"], res.get("error"))
        by = {s["offset"]: s for s in res["states"]}
        # negative key -> legal return target
        self.assertTrue(by[36]["reachable"])
        self.assertEqual(by[36]["insn"], "return")
        self.assertEqual(by[36]["stack"], [])
        # small key -> int falls into the join
        self.assertEqual(by[38]["stack"], ["int"])
        # far-apart key -> construction path
        self.assertEqual(by[41]["stack"], [])
        self.assertEqual(by[44]["stack"],
                         [f"uninit(new@41 {DIAG})"])
        self.assertEqual(by[48]["stack"], [f"ref {DIAG}"])
        # the join merges the goto edge and the construction fall-through
        self.assertEqual(by[50]["locals"], ["top"])
        self.assertEqual(by[50]["stack"], ["int"])

    def test_switch_join_stack_height_conflict_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # iconst_0 selector
        a.lookupswitch("dflt", [(1, "one"), (2, "two")])
        a.label("one")
        a.op(0x03)              # iconst_0 -> join carries one int
        a.branch(0xA7, "j")
        a.label("two")
        a.branch(0xA7, "j")     # join carries empty stack
        a.label("j")
        a.op(0x57)
        a.label("dflt")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-height-mismatch")

    def test_switch_join_type_conflict_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("dflt", [(1, "one"), (2, "two")])
        a.label("one")
        a.op(0xBB).u2(b.cp.cls(DIAG))
        a.branch(0xA7, "j")
        a.label("two")
        a.op(0x01)              # aconst_null
        a.label("j")
        a.op(0x4B)              # astore_0: uninit vs null -> conflict
        a.label("dflt")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "incompatible-types")

    def test_unordered_lookupswitch_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("d", [(2, "a"), (1, "a")])  # descending keys
        a.label("a")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-lookupswitch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_truncated_lookupswitch_table_rejected(self):
        # Declare 3 pairs but cut the code so the last pair is missing.
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("d", [(1, "a"), (2, "a"), (3, "a")])
        a.label("a")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        code = a.build()
        b.add_method("run", code[:-8], max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-instruction")
        self.assertEqual(res["error"]["offset"], 1)

    def test_switch_target_into_instruction_middle_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("d", [(1, "mid")])
        a.op(0x11)              # sipush, 3 bytes
        a.label("mid")         # -> middle of its immediate
        a.u2(0x1234)
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-branch-target")
        self.assertEqual(res["error"]["offset"], 1)

    def test_switch_default_target_into_middle_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("dmid", [(1, "a")])
        a.op(0x11)
        a.label("dmid")
        a.u2(0x1234)
        a.op(0xB1)
        a.label("a")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-branch-target")

    def test_switch_alignment_when_starting_at_pc_2(self):
        # bipush (2 bytes) puts the switch at pc 2: payload starts at 3,
        # so one padding byte aligns the header to pc 4.
        b = ClassBuilder()
        a = Asm()
        a.op(0x10, 0x05)       # 0 bipush 5 (selector)
        a.lookupswitch("d", [(-7, "t"), (999, "t")])
        a.label("t")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        sw = next(s for s in res["states"] if s["insn"].startswith("lookupswitch"))
        self.assertEqual(sw["offset"], 2)
        # both keys and default land on return targets, all reachable
        rets = [s for s in res["states"] if s["insn"] == "return"]
        self.assertTrue(rets)
        self.assertTrue(all(s["reachable"] for s in rets))
        self.assertTrue(all(s["stack"] == [] for s in rets))

    def test_tableswitch_legal(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.tableswitch(10, 12, "d", ["a", "b", "c"])
        a.label("a")
        a.op(0xB1)
        a.label("b")
        a.op(0xB1)
        a.label("c")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))

    def test_tableswitch_bad_range_rejected(self):
        # Build a valid table then corrupt the header so high < low.
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.tableswitch(1, 2, "d", ["x", "x"])
        a.label("x")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        code = bytearray(a.build())
        # switch starts at 1; padding to a 4-byte boundary puts the header at
        # offset 4: default@4, low@8, high@12.  Set high below low.
        code[12:16] = (0).to_bytes(4, "big", signed=True)
        b.add_method("run", bytes(code), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-tableswitch")

    def test_tableswitch_truncated_payload_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.tableswitch(1, 4, "d", ["x", "x", "x", "x"])
        a.label("x")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        code = a.build()
        b.add_method("run", code[:-4], max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-instruction")

    def test_switch_dedups_shared_target_frame(self):
        # Two matches sharing one target is one edge, not a conflicting join.
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("d", [(-9, "t"), (9, "t")])
        a.label("t")
        a.op(0xB1)
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))

    def test_switch_with_construction_and_exception_table(self):
        b, x, init = diag_builder()
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
        hpc = a.labels["h"]
        b.add_method("run", raw, max_stack=2, max_locals=1,
                     exceptions=[(0, hpc, hpc, 0)])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        h = res["handlers"][0]
        self.assertTrue(h["reachable"])
        self.assertEqual(h["stack"], ["ref java/lang/Throwable"])

    def test_switch_construction_target_halfinit_blocked_from_handler(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0x03)
        a.lookupswitch("d", [(1, "make")])
        a.label("make")
        a.op(0xBB).u2(x)       # new
        a.op(0x4B)             # astore_0 (uninitialized into a local)
        a.label("nop")
        a.op(0x00)             # nop covered by the handler range
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
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"],
                         "uninitialized-escapes-to-handler")
        self.assertEqual(res["error"]["offset"], a.labels["nop"])


class MethodSelectionTests(unittest.TestCase):
    def _two_method_class(self):
        b = ClassBuilder()
        b.add_method("ma", bytes([0xB1]), max_stack=0, max_locals=0)
        b.add_method("mb", bytes([0xB1]), max_stack=0, max_locals=0)
        return b.build()

    def test_ambiguous_static_void_methods(self):
        res = verify_class(self._two_method_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "ambiguous-method")
        self.assertEqual(res["error"]["candidates"], ["ma", "mb"])

    def test_named_method_selected(self):
        res = verify_class(self._two_method_class(), method_name="mb")
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["method"], "mb")

    def test_unknown_method_name(self):
        res = verify_class(self._two_method_class(), method_name="zz")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "no-target-method")

    def test_instance_method_not_a_target(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=1,
                     access=ACC_PUBLIC)  # not static
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "no-target-method")


if __name__ == "__main__":
    unittest.main()

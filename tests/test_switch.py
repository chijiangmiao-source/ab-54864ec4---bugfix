"""Unit tests for sparse multi-way branches: lookupswitch / tableswitch.

Covers the JVM type-state requirements for switch tables:

  * the matched-key targets are analyzed like any other successor, so a case
    block that violates stack typing is rejected at the case's first illegal
    instruction (the default target merely returning must not mask it);
  * sparse signed keys (negative and far apart) fanning out to legal return,
    local-variable merge and object construction paths pass, and every
    reachable target gets a reviewable per-offset frame;
  * table alignment/length, match-key ordering and target instruction
    boundaries are structurally checked;
  * half-initialized objects still cannot cross an exception edge into a
    handler reached from a switch block.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.verifier import verify_class  # noqa: E402
from builder import (Asm, ClassBuilder,  # noqa: E402
                     illegal_lookupswitch_case_class,
                     legal_tableswitch_class,
                     sparse_lookupswitch_class,
                     switch_join_conflict_class,
                     switch_target_middle_class,
                     switch_uninit_escape_class,
                     tableswitch_low_gt_high_class,
                     truncated_lookupswitch_class,
                     truncated_tableswitch_class,
                     unordered_lookupswitch_class,
                     duplicate_lookupswitch_key_class)

DIAG = "com/acme/Diag"


def state_at(res, off):
    for s in res["states"]:
        if s["offset"] == off:
            return s
    raise AssertionError(f"no state at offset {off}")


class IllegalCaseTests(unittest.TestCase):
    def test_matched_case_underflow_rejected_at_case_offset(self):
        data, marks = illegal_lookupswitch_case_class()
        res = verify_class(data)
        self.assertFalse(res["ok"])
        # The default block (return) is fine; the violation first occurs at
        # the matched target, where iadd has no operands.
        self.assertEqual(res["error"]["kind"], "stack-underflow")
        self.assertEqual(res["error"]["offset"], marks["bad"])
        self.assertEqual(marks["bad"], 21)
        # Both blocks are reachable: the default target and the case target.
        self.assertTrue(state_at(res, marks["d"])["reachable"])
        bad = state_at(res, marks["bad"])
        self.assertTrue(bad["reachable"])
        self.assertEqual(bad["stack"], [])  # the switch key was consumed

    def test_switch_requires_int_key(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x01)                    # 0 aconst_null (not an int key)
        a.lookupswitch("d", [(1, "d")])
        a.label("d")
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "type-mismatch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_default_only_never_reaches_dropped_case(self):
        # No pushed key matches the case; statically both successors are
        # still analyzed, so a legal case block passes and is reachable.
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)                    # 0 iconst_0
        a.lookupswitch("d", [(1, "c")])
        a.label("d")
        a.op(0xB1)                    # default return
        a.label("c")
        a.op(0x03)                    # case: iconst_0 / pop / return
        a.op(0x57)
        a.op(0xB1)
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))


class SparseLegalPathTests(unittest.TestCase):
    def test_sparse_keys_reviewable_frames(self):
        data, m = sparse_lookupswitch_class()
        res = verify_class(data)
        self.assertTrue(res["ok"], res.get("error"))

        # The switch sits after the 2-byte bipush: padding/length decoded
        # correctly and every signed key appears in the disassembly.
        sw = state_at(res, 2)
        self.assertTrue(sw["insn"].startswith("lookupswitch"))
        for key in ("-2147483648", "-7", "42", "2147483647"):
            self.assertIn(key, sw["insn"])
        self.assertEqual(sw["stack"], ["int"])

        # Negative far key -> plain legal return.
        ret = state_at(res, m["ret_neg"])
        self.assertTrue(ret["reachable"])
        self.assertEqual(ret["stack"], [])

        # Both int/local paths converge: stored int at each istore site.
        self.assertEqual(state_at(res, m["int_a"] + 1)["stack"], ["int"])
        self.assertEqual(state_at(res, m["int_b"] + 1)["stack"], ["int"])
        join = state_at(res, m["join"])
        self.assertTrue(join["reachable"])
        self.assertEqual(join["locals"], ["int"])

        # Construction path: uninitialized identity before <init>, reference
        # afterwards, with per-offset reviewable states.
        new = state_at(res, m["construct"])
        self.assertTrue(new["reachable"])
        self.assertEqual(new["insn"], f"new {DIAG}")
        init_off = m["construct"] + 4   # new (3) + dup (1) -> invokespecial
        self.assertEqual(
            state_at(res, init_off)["stack"],
            [f"uninit(new@{m['construct']} {DIAG})",
             f"uninit(new@{m['construct']} {DIAG})"])

        # Exception handler covering only the construction range is
        # reachable, holds the throwable on an otherwise empty stack, and
        # carries no half-initialized object in its locals.
        self.assertEqual(len(res["handlers"]), 1)
        h = res["handlers"][0]
        self.assertTrue(h["reachable"])
        self.assertEqual((h["start_pc"], h["end_pc"], h["handler_pc"]),
                         (m["construct"], m["h"], m["h"]))
        self.assertEqual(h["stack"], ["ref java/lang/Throwable"])
        self.assertEqual(h["locals"], ["top"])
        hp = state_at(res, m["h"])
        self.assertTrue(hp["reachable"])
        self.assertEqual(hp["stack"], ["ref java/lang/Throwable"])

    def test_switch_alignment_at_unaligned_pc(self):
        # The illegal fixture places the switch at pc 1 (three pad bytes);
        # its targets decode to the expected instruction boundaries.
        data, marks = illegal_lookupswitch_case_class()
        res = verify_class(data)
        sw = state_at(res, 1)
        self.assertEqual(sw["insn"], "lookupswitch default 20 (1 case(s): 1)")
        self.assertEqual(marks["d"], 20)
        self.assertEqual(marks["bad"], 21)

    def test_legal_tableswitch_frames_and_join(self):
        data, m = legal_tableswitch_class()
        res = verify_class(data)
        self.assertTrue(res["ok"], res.get("error"))
        sw = state_at(res, 1)
        self.assertEqual(sw["insn"], "tableswitch default 39 (-1..1)")
        for label in ("m1", "z", "p1", "d", "join"):
            self.assertTrue(state_at(res, m[label])["reachable"], label)
        self.assertEqual(state_at(res, m["join"])["locals"], ["int"])


class SwitchStructureRejectionTests(unittest.TestCase):
    def test_join_height_conflict_rejected_at_join(self):
        data, marks = switch_join_conflict_class()
        res = verify_class(data)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-height-mismatch")
        self.assertEqual(res["error"]["offset"], marks["join"])

    def test_target_into_instruction_middle_rejected(self):
        data, marks = switch_target_middle_class()
        res = verify_class(data)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-branch-target")
        self.assertEqual(res["error"]["offset"], 1)
        self.assertIn(f"offset {marks['mid']}", res["error"]["message"])

    def test_unordered_keys_rejected(self):
        res = verify_class(unordered_lookupswitch_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-lookupswitch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_duplicate_keys_rejected(self):
        res = verify_class(duplicate_lookupswitch_key_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-lookupswitch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_truncated_lookupswitch_rejected(self):
        res = verify_class(truncated_lookupswitch_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-instruction")
        self.assertEqual(res["error"]["offset"], 1)

    def test_truncated_tableswitch_rejected(self):
        res = verify_class(truncated_tableswitch_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-instruction")
        self.assertEqual(res["error"]["offset"], 1)

    def test_tableswitch_low_greater_than_high_rejected(self):
        res = verify_class(tableswitch_low_gt_high_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-tableswitch")
        self.assertEqual(res["error"]["offset"], 1)


class SwitchExceptionEdgeTests(unittest.TestCase):
    def test_half_initialized_object_via_switch_block_rejected(self):
        data, marks = switch_uninit_escape_class()
        res = verify_class(data)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"],
                         "uninitialized-escapes-to-handler")
        self.assertEqual(res["error"]["offset"], marks["leak"])


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import unittest

from e2e import main, protect, verify


class CounterCycleTests(unittest.TestCase):
    def test_profile1_counter_wraps_from_14_to_zero(self):
        frame = protect(b"abc", 0, 0x1234)
        self.assertEqual(
            verify(frame, 0x1234, previous=14),
            {"ok": True, "counter": 0, "payload": "616263"},
        )

    def test_reserved_counter_15_cannot_be_protected(self):
        with self.assertRaisesRegex(ValueError, r"counter must be 0\.\.14"):
            protect(b"abc", 15, 0x1234)

    def test_reserved_counter_15_is_rejected_before_crc(self):
        # The old implementation generated and accepted this real frame.
        # Counter 15 is an error value regardless of its CRC or payload.
        frame = bytes.fromhex("0f36616263")
        self.assertEqual(
            verify(frame, 0x1234, previous=14),
            {"ok": False, "reason": "counter_range"},
        )

    def test_previous_counter_15_is_not_valid_sequence_state(self):
        frame = protect(b"abc", 0, 0x1234)
        self.assertEqual(
            verify(frame, 0x1234, previous=15),
            {"ok": False, "reason": "previous_counter_range"},
        )

    def test_full_cycle_preserves_repeat_and_jump_detection(self):
        for previous in range(15):
            with self.subTest(previous=previous):
                following = protect(b"abc", (previous + 1) % 15, 0x1234)
                self.assertTrue(verify(following, 0x1234, previous)["ok"])
                repeated = protect(b"abc", previous, 0x1234)
                self.assertEqual(
                    verify(repeated, 0x1234, previous)["reason"],
                    "repeated_counter",
                )
                skipped = protect(b"abc", (previous + 2) % 15, 0x1234)
                self.assertEqual(
                    verify(skipped, 0x1234, previous)["reason"], "counter_jump"
                )

    def test_cli_accepts_rollover_and_rejects_reserved_counter(self):
        frame = protect(b"abc", 0, 0x1234)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([
                "verify", frame.hex(), "--data-id", "4660", "--previous", "14"
            ]), 0)
            self.assertEqual(main([
                "protect", "616263", "--data-id", "4660", "--counter", "15"
            ]), 2)


if __name__ == "__main__":
    unittest.main()

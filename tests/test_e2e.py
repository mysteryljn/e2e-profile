import contextlib
import io
import unittest
from e2e import crc8, main, protect,verify
class E2ETests(unittest.TestCase):
    def test_crc8_uses_autosar_profile_parameters(self):
        # Profile 1 uses polynomial 0x1D with init=0x00/final_xor=0x00.
        # A one-byte 0x01 vector distinguishes it from generic SAE J1850
        # (which uses init=0xFF/final_xor=0xFF and returns 0x4C here).
        self.assertEqual(crc8(b"\x01"), 0x1D)

    def test_round_trip(self):
        frame=protect(b"abc",3,0x1234); result=verify(frame,0x1234,2)
        self.assertTrue(result["ok"]); self.assertEqual(result["payload"],"616263")

    def test_data_id_is_serialized_low_byte_first(self):
        # Profile 1's Data ID contribution is low byte followed by high byte.
        # This vector catches a big-endian implementation that still passes a
        # protect/verify round trip because both sides make the same mistake.
        self.assertEqual(protect(b"abc", 3, 0x1234), bytes.fromhex("0339616263"))
    def test_crc_and_counter(self):
        frame=protect(b"x",1,1); bad=bytes([frame[0],frame[1]^1])+frame[2:]
        self.assertEqual(verify(bad,1)["reason"],"crc"); self.assertEqual(verify(frame,1,1)["reason"],"repeated_counter")

    def test_data_id_is_bounded_without_crashing_verify(self):
        frame = protect(b"x", 1, 1)
        for invalid in (-1, 0x10000, "1", True):
            with self.subTest(data_id=invalid):
                self.assertEqual(verify(frame, invalid), {"ok": False, "reason": "data_id_range"})

        with self.assertRaisesRegex(ValueError, r"data_id must be an integer in 0\.\.65535"):
            protect(b"x", 1, 0x10000)

    def test_invalid_previous_counter_cannot_bypass_sequence_check(self):
        frame = protect(b"x", 0, 1)
        for previous in (-1, 16, 1.5, True):
            with self.subTest(previous=previous):
                self.assertEqual(
                    verify(frame, 1, previous),
                    {"ok": False, "reason": "previous_counter_range"},
                )

    def test_protect_rejects_non_integer_counter_without_internal_error(self):
        for counter in (-1, 16, 1.5, "1", True, None):
            with self.subTest(counter=counter):
                with self.assertRaisesRegex(ValueError, r"counter must be 0\.\.15"):
                    protect(b"x", counter, 1)

    def test_protect_rejects_non_bytes_payload_without_internal_error(self):
        for payload in (None, "x", [120], 1, True):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, r"payload must be bytes-like"):
                    protect(payload, 1, 1)

    def test_verify_rejects_non_bytes_frame_without_crashing(self):
        for frame in (None, "0100", [1, 0], 1, True):
            with self.subTest(frame=frame):
                self.assertEqual(
                    verify(frame, 1),
                    {"ok": False, "reason": "frame_type"},
                )

    def test_bytes_like_frames_are_normalized(self):
        frame = protect(b"x", 1, 1)
        self.assertTrue(verify(bytearray(frame), 1)["ok"])
        self.assertTrue(verify(memoryview(frame), 1)["ok"])

    def test_cli_rejects_malformed_hex_without_traceback(self):
        for argv in (
            ["protect", "abc", "--counter", "1", "--data-id", "1"],
            ["verify", "010", "--data-id", "1"],
            ["verify", "zz", "--data-id", "1"],
        ):
            output = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stdout(output):
                self.assertEqual(main(argv), 2)
            self.assertIn("error:", output.getvalue())

    def test_verify_cli_fails_for_invalid_frame(self):
        frame = protect(b"x", 1, 1)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["verify", frame.hex(), "--data-id", "1"]), 0)
            invalid = bytes([frame[0], frame[1] ^ 1]) + frame[2:]
            self.assertEqual(main(["verify", invalid.hex(), "--data-id", "1"]), 1)
        self.assertIn("'ok': False", output.getvalue())

if __name__=="__main__": unittest.main()

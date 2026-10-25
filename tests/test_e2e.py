import unittest
from e2e import crc8, protect,verify
class E2ETests(unittest.TestCase):
    def test_crc8_uses_autosar_profile_parameters(self):
        # Profile 1 uses polynomial 0x1D with init=0x00/final_xor=0x00.
        # A one-byte 0x01 vector distinguishes it from generic SAE J1850
        # (which uses init=0xFF/final_xor=0xFF and returns 0x4C here).
        self.assertEqual(crc8(b"\x01"), 0x1D)

    def test_round_trip(self):
        frame=protect(b"abc",3,0x1234); result=verify(frame,0x1234,2)
        self.assertTrue(result["ok"]); self.assertEqual(result["payload"],"616263")
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
if __name__=="__main__": unittest.main()

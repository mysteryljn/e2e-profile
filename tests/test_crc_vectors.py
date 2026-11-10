import contextlib
import io
import unittest

from e2e import main, protect, verify


class CrcVectorTests(unittest.TestCase):
    # AUTOSAR R22-11 E2E Protocol, section 6.5.5, Tables 6.20/6.21:
    # Data ID 0x0123, six zero data bytes, counters 0/1 -> CRCs 0xCC/0x91.
    # This lab stores counter before CRC, so only those two frame bytes are
    # swapped from the published examples.  The CRC input is unchanged.
    # https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_PRS_E2EProtocol.pdf
    VECTORS = (
        (0, 0x0123, "000000000000", "00cc000000000000"),
        (1, 0x0123, "000000000000", "0191000000000000"),
        # Independent polynomial long division of 0x34120361626300 by
        # 0x11D gives remainder 0xD2 (Data ID low/high, counter, payload).
        (3, 0x1234, "616263", "03d2616263"),
    )

    def test_protect_matches_fixed_crc_vectors(self):
        for counter, data_id, payload_hex, frame_hex in self.VECTORS:
            with self.subTest(counter=counter, data_id=data_id):
                self.assertEqual(
                    protect(bytes.fromhex(payload_hex), counter, data_id),
                    bytes.fromhex(frame_hex),
                )

    def test_verify_accepts_fixed_frames_without_calling_protect(self):
        for counter, data_id, payload_hex, frame_hex in self.VECTORS:
            with self.subTest(counter=counter, data_id=data_id):
                self.assertEqual(
                    verify(bytes.fromhex(frame_hex), data_id),
                    {"ok": True, "counter": counter, "payload": payload_hex},
                )

    def test_verify_rejects_crc_computed_with_counter_before_data_id(self):
        self.assertEqual(
            verify(bytes.fromhex("0339616263"), 0x1234),
            {"ok": False, "reason": "crc"},
        )

    def test_cli_uses_the_same_fixed_vector(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["protect", "616263", "--counter", "3", "--data-id", "4660"]), 0)
        self.assertEqual(output.getvalue().strip(), "03d2616263")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify", "03d2616263", "--data-id", "4660"]), 0)


if __name__ == "__main__":
    unittest.main()

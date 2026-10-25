import unittest
from e2e import protect,verify
class E2ETests(unittest.TestCase):
    def test_round_trip(self):
        frame=protect(b"abc",3,0x1234); result=verify(frame,0x1234,2)
        self.assertTrue(result["ok"]); self.assertEqual(result["payload"],"616263")
    def test_crc_and_counter(self):
        frame=protect(b"x",1,1); bad=bytes([frame[0],frame[1]^1])+frame[2:]
        self.assertEqual(verify(bad,1)["reason"],"crc"); self.assertEqual(verify(frame,1,1)["reason"],"repeated_counter")
if __name__=="__main__": unittest.main()

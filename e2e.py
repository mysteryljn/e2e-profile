#!/usr/bin/env python3
import argparse


def _encode_data_id(data_id):
    """Return the two-byte AUTOSAR Data ID in low-byte-first order."""
    if isinstance(data_id, bool) or not isinstance(data_id, int) or not 0 <= data_id <= 0xffff:
        raise ValueError("data_id must be an integer in 0..65535")
    # AUTOSAR E2E Profile 1 feeds the low byte and then the high byte into
    # the CRC calculation (PRS_E2E_00227).  Using network-byte order here
    # creates frames that pass this module's round-trip check but fail against
    # an AUTOSAR receiver.
    return data_id.to_bytes(2, "little")


def _is_counter(counter):
    """Return whether *counter* is a valid four-bit sequence counter."""
    return isinstance(counter, int) and not isinstance(counter, bool) and 0 <= counter <= 0xf


def _as_bytes(value, name):
    """Normalize a bytes-like value and reject text/container surprises."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("%s must be bytes-like" % name)
    return bytes(value)


def crc8(data):
    # AUTOSAR E2E Profile 1 uses the SAE J1850 polynomial with a
    # logical start value and final XOR of 0x00.  The commonly quoted
    # SAE J1850 variant uses 0xFF for both, but that variant is not
    # interoperable with E2E Profile 1 receivers.
    crc=0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc=((crc<<1)^0x1d)&0xff if crc&0x80 else (crc<<1)&0xff
    return crc
def protect(payload,counter,data_id):
    if not _is_counter(counter): raise ValueError("counter must be 0..15")
    payload = _as_bytes(payload, "payload")
    body=bytes([counter])+_encode_data_id(data_id)+payload
    return bytes([counter,crc8(body)])+payload
def verify(frame,data_id,previous=None):
    try:
        data_id_bytes = _encode_data_id(data_id)
    except ValueError:
        return {"ok":False,"reason":"data_id_range"}
    try:
        frame = _as_bytes(frame, "frame")
    except ValueError:
        return {"ok":False,"reason":"frame_type"}
    if len(frame)<2: return {"ok":False,"reason":"too_short"}
    counter,checksum=frame[0],frame[1]; payload=frame[2:]
    if not 0<=counter<=0xf: return {"ok":False,"reason":"counter_range"}
    if crc8(bytes([counter])+data_id_bytes+payload)!=checksum: return {"ok":False,"reason":"crc"}
    if previous is not None:
        if not _is_counter(previous):
            return {"ok":False,"reason":"previous_counter_range"}
        delta=(counter-previous)%16
        if delta==0: return {"ok":False,"reason":"repeated_counter"}
        if delta>1: return {"ok":False,"reason":"counter_jump"}
    return {"ok":True,"counter":counter,"payload":payload.hex()}
def main(argv=None):
    p=argparse.ArgumentParser(description="Protect or verify a small E2E frame"); sub=p.add_subparsers(dest="cmd")
    a=sub.add_parser("protect"); a.add_argument("payload"); a.add_argument("--counter",type=int,required=True); a.add_argument("--data-id",type=int,required=True)
    b=sub.add_parser("verify"); b.add_argument("frame"); b.add_argument("--data-id",type=int,required=True); b.add_argument("--previous",type=int)
    x=p.parse_args(argv)
    if x.cmd=="protect": print(protect(bytes.fromhex(x.payload),x.counter,x.data_id).hex())
    elif x.cmd=="verify": print(verify(bytes.fromhex(x.frame),x.data_id,x.previous))
    else: p.error("choose protect or verify")
    return 0
if __name__=="__main__": raise SystemExit(main())

#!/usr/bin/env python3
"""
Lumi / GR-3 guard interlock CTF solver.

Dependency-free Modbus/TCP client (raw socket). It:
  1. Samples the 6 discrete inputs (FC02, addr 0-5) and the 4 coils
     (FC01, addr 0-3) across the replayed test pattern.
  2. Derives the live Motor_Run *hold* permissive contacts by a
     necessary-condition test: a contact C=(bit,sense) is a required
     permissive iff in EVERY sample where Motor_Run(O:0/0)=1, C is true.
     (START I:1/4 is momentary/sealed-in, so it correctly drops out.)
  3. Diffs that live set against the documented baseline permissive set
     to find the single changed contact.
  4. Reads the resident checksum from holding regs N7:2/N7:3 (FC03).
  5. Prints the flag.

Usage:  python grinder_solve.py [host] [port] [seconds]
Default: 127.0.0.1 502 90
Addresses are zero-based, Unit ID 1 (matches the point map).
"""
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
SECS = float(sys.argv[3]) if len(sys.argv) > 3 else 90.0
UNIT = 1

INPUT_SYM = {0: "GuardDoor_Open", 1: "EStop_Pressed", 2: "Local_Mode",
             3: "MaintKey_Inserted", 4: "StartPB", 5: "ThermalOL_Trip"}

# Baseline Motor_Run hold permissives, from page 2 + symbol DB.
# sense 'C' = XIC (true when bit=1), 'O' = XIO (true when bit=0)
BASELINE = {(0, "O"), (1, "O"), (2, "C"), (5, "O")}


class Modbus:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), 5)
        self.s.settimeout(5)
        self.tid = 0

    def _txn(self, fc, start, count):
        self.tid = (self.tid + 1) & 0xFFFF
        pdu = struct.pack(">BHH", fc, start, count)
        adu = struct.pack(">HHHB", self.tid, 0, len(pdu) + 1, UNIT) + pdu
        self.s.sendall(adu)
        head = self._recv(7)
        tid, proto, length, unit = struct.unpack(">HHHB", head)
        body = self._recv(length - 1)
        if body[0] & 0x80:
            raise RuntimeError(f"Modbus exception fc={fc} code={body[1]}")
        return body[2:]  # skip echoed fc + byte count

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            c = self.s.recv(n - len(buf))
            if not c:
                raise ConnectionError("short read")
            buf += c
        return buf

    def bits(self, fc, start, count):
        data = self._txn(fc, start, count)
        return [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]

    def regs(self, start, count):
        data = self._txn(3, start, count)
        return list(struct.unpack(">" + "H" * count, data))

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def main():
    m = Modbus(HOST, PORT)
    samples = []
    seen = set()
    t0 = time.time()
    print(f"Sampling {HOST}:{PORT} for {SECS:.0f}s (pattern steps held 2s)...")
    while time.time() - t0 < SECS:
        di = m.bits(2, 0, 6)          # discrete inputs I:1/0..5
        coils = m.bits(1, 0, 4)       # coils O:0/0..3
        row = tuple(di) + tuple(coils)
        samples.append(row)
        if row not in seen:
            seen.add(row)
        time.sleep(0.4)
    chk_regs = m.regs(0, 4)           # N7:0..3
    m.close()

    motor = [r[6] for r in samples]   # O:0/0
    n_run = sum(motor)
    print(f"\n{len(samples)} samples, {len(seen)} distinct states, "
          f"Motor_Run=1 in {n_run} of them.")

    # Necessary-condition test for each (bit, sense).
    live = set()
    print("\nContact            required? (violations while Motor_Run=1)")
    for bit in range(6):
        for sense in ("C", "O"):
            want = 1 if sense == "C" else 0
            viol = sum(1 for r in samples if r[6] == 1 and r[bit] != want)
            instr = "XIC" if sense == "C" else "XIO"
            tag = f"{instr} I:1/{bit} ({INPUT_SYM[bit]})"
            if n_run and viol == 0:
                live.add((bit, sense))
                print(f"  HOLD  {tag:<34} 0")
            else:
                print(f"        {tag:<34} {viol}")

    # Diff against baseline.
    base_only = BASELINE - live
    live_only = live - BASELINE
    print(f"\nBaseline permissives: {fmt(BASELINE)}")
    print(f"Live permissives:     {fmt(live)}")

    checksum = (chk_regs[2] << 16) | chk_regs[3]
    print(f"\nN7 regs: EventCount={chk_regs[0]} Step={chk_regs[1]} "
          f"CHK_HI=0x{chk_regs[2]:04X} CHK_LO=0x{chk_regs[3]:04X}")
    print(f"Resident checksum = 0x{checksum:08X} "
          f"(archived baseline was 0x5C14A7B3)")

    if len(base_only) == 1 and len(live_only) == 1:
        (bb, bs) = next(iter(base_only))
        (lb, ls) = next(iter(live_only))
        bi = "XIC" if bs == "C" else "XIO"
        li = "XIC" if ls == "C" else "XIO"
        flag = (f"nexsec26{{{bi}_I_1_{bb}_{li}_I_1_{lb}_"
                f"{checksum:08X}}}")
        print(f"\n*** CHANGED CONTACT ***")
        print(f"  baseline: {bi} I:1/{bb} ({INPUT_SYM[bb]})")
        print(f"  live:     {li} I:1/{lb} ({INPUT_SYM[lb]})")
        print(f"\nFLAG: {flag}")
    else:
        print("\nCould not isolate exactly one changed contact; "
              "sample longer or inspect the table above.")


def fmt(s):
    return "{" + ", ".join(
        f"{'XIC' if sense=='C' else 'XIO'} I:1/{b}"
        for b, sense in sorted(s)) + "}"


if __name__ == "__main__":
    main()

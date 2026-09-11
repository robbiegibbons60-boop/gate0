import os, ctypes, struct, time
from ctypes import c_ubyte, c_ulonglong, c_uint64, cast, POINTER, addressof, byref

g = ctypes.CDLDL(os.path.expanduser("~/gate0/libgate0.so"))
s = ctypes.CDLDL("libsodium.so")
s.sodium_init()

s.crypto_sign_keypair.argtypes = [POINTER(c_ubyte)] * 2
s.crypto_sign_detached.argtypes = [POINTER(c_ubyte), POINTER(c_ulonglong), ctypes.c_void_p, c_ulonglong, POINTER(c_ubyte)]
g.evaluate_command.argtypes = [ctypes.c_void_p] * 3 + [c_uint64]
g.evaluate_command.restype = ctypes.c_int

pub = (c_ubyte * 32)()
priv = (c_ubyte * 64)()
s.crypto_sign_keypair(pub, priv)

def sign(buf):
    sl = c_ulonglong(0)
    arr = (c_ubyte * len(buf)).from_buffer(buf)
    s.crypto_sign_detached(
        cast(addressof(arr), POINTER(c_ubyte)),
        byref(sl),
        cast(addressof(arr) + 64, ctypes.c_void_p),
        448,
        cast(addressof(priv), POINTER(c_ubyte))
    )

print("[*] PASS-002 Matrix Starting...")

# V1 Time Anomaly
c1 = bytearray(512)
c1[92:96] = struct.pack("<I", 0xDEADBEEF)
c1[96:128] = bytes(pub)
c1[68:76] = struct.pack("<Q", 1)
c1[76:84] = struct.pack("<Q", 2000000000)
c1[84:92] = struct.pack("<Q", 1000000000)
sign(c1)
s1 = bytearray(41)
i1 = bytearray(4)
r1 = g.evaluate_command(addressof((c_ubyte*512).from_buffer(c1)), addressof((c_ubyte*41).from_buffer(s1)), addressof((c_ubyte*4).from_buffer(i1)), 1500000000)
print(f"V1 Time: {r1} (Exp: 2)")

# V2 Sequence Replay
c2 = bytearray(512)
c2[92:96] = struct.pack("<I", 0xDEADBEEF)
c2[96:128] = bytes(pub)
c2[68:76] = struct.pack("<Q", 0)
n2 = int(time.time() * 1e9)
c2[76:84] = struct.pack("<Q", n2)
c2[84:92] = struct.pack("<Q", n2 + 5000000000)
sign(c2)
s2 = bytearray(41)
struct.pack_into("<Q", s2, 32, 1)
s2[40] = 1
i2 = bytearray(4)
r2 = g.evaluate_command(addressof((c_ubyte*512).from_buffer(c2)), addressof((c_ubyte*41).from_buffer(s2)), addressof((c_ubyte*4).from_buffer(i2)), n2)
print(f"V2 Seq: {r2} (Exp: 3)")

# V3 Valid Bootstrap
c3 = bytearray(512)
c3[92:96] = struct.pack("<I", 0xDEADBEEF)
c3[96:128] = bytes(pub)
c3[68:76] = struct.pack("<Q", 1)
n3 = int(time.time() * 1e9)
c3[76:84] = struct.pack("<Q", n3)
c3[84:92] = struct.pack("<Q", n3 + 5000000000)
sign(c3)
s3 = bytearray(41)
i3 = bytearray(4)
r3 = g.evaluate_command(addressof((c_ubyte*512).from_buffer(c3)), addressof((c_ubyte*41).from_buffer(s3)), addressof((c_ubyte*4).from_buffer(i3)), n3)
print(f"V3 Bootstrap: {r3} (Exp: 0)")

if s3[40] == 1 and s3[0:32] == bytes(pub):
    print("V3 Integrity: PASS")
else:
    print("V3 Integrity: FAIL")

print("[*] PASS-002 Complete.")

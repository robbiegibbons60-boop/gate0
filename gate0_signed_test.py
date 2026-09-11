import os, ctypes, time
g = ctypes.CDLL(os.path.expanduser("~/gate0/libgate0.so"))
s = ctypes.CDLL("libsodium.so")
s.sodium_init()
s.crypto_sign_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte)] * 2
s.crypto_sign_detached.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]

class D(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("a", ctypes.c_char * 32), ("b", ctypes.c_char * 32), ("c", ctypes.c_char * 32), ("d", ctypes.c_char * 64)]

class E(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("v", ctypes.c_uint32), ("sq", ctypes.c_uint64), ("ia", ctypes.c_uint64), ("ea", ctypes.c_uint64), ("p", ctypes.c_ubyte * 256), ("ra", ctypes.c_uint32), ("di", D)]

class C(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("sig", ctypes.c_ubyte * 64), ("env", E)]

class R(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("pk", ctypes.c_ubyte * 32), ("ls", ctypes.c_uint64), ("u", ctypes.c_bool)]

class I(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("e", ctypes.c_bool), ("o", ctypes.c_bool), ("t", ctypes.c_bool), ("v", ctypes.c_bool)]

g.evaluate_command.argtypes = [ctypes.POINTER(C), ctypes.POINTER(R), ctypes.POINTER(I), ctypes.c_uint64]
g.evaluate_command.restype = ctypes.c_int

pub = (ctypes.c_ubyte * 32)()
priv = (ctypes.c_ubyte * 64)()
s.crypto_sign_keypair(pub, priv)

cmd = C()
ctypes.memset(ctypes.byref(cmd), 0, ctypes.sizeof(C))
cmd.env.v = 1
cmd.env.sq = 1
now = int(time.time() * 1e9)
cmd.env.ia = now
cmd.env.ea = now + 5000000000

# Secure Bootstrap: Token 0xDEADBEEF at offset 0, PubKey at offset 4
token = ctypes.c_uint32(0xDEADBEEF)
ctypes.memmove(ctypes.addressof(cmd.env.p), ctypes.byref(token), 4)
ctypes.memmove(ctypes.addressof(cmd.env.p) + 4, ctypes.addressof(pub), 32)

buf = ctypes.string_at(ctypes.addressof(cmd.env), ctypes.sizeof(E))
sl = ctypes.c_ulonglong(0)
s.crypto_sign_detached(cmd.sig, ctypes.byref(sl), buf, len(buf), priv)

sender = R()
ctypes.memset(ctypes.byref(sender), 0, ctypes.sizeof(R))
interlocks = I()
ctypes.memset(ctypes.byref(interlocks), 0, ctypes.sizeof(I))

res = g.evaluate_command(ctypes.byref(cmd), ctypes.byref(sender), ctypes.byref(interlocks), now)
print(f"RESULT: {res}")

def test_missing_token():
    print("\n[TEST 1] Missing Bootstrap Token")
    pub = (ctypes.c_ubyte * 32)()
    priv = (ctypes.c_ubyte * 64)()
    s.crypto_sign_keypair(pub, priv)
    cmd = C()
    ctypes.memset(ctypes.byref(cmd), 0, ctypes.sizeof(C))
    cmd.env.v = 1; cmd.env.sq = 1
    now = int(time.time() * 1e9)
    cmd.env.ia = now; cmd.env.ea = now + 5000000000
    # Place pubkey at offset 4, but leave offset 0-3 as zeros (No Token)
    ctypes.memmove(ctypes.addressof(cmd.env.p) + 4, ctypes.addressof(pub), 32)
    buf = ctypes.string_at(ctypes.addressof(cmd.env), ctypes.sizeof(E))
    sl = ctypes.c_ulonglong(0)
    s.crypto_sign_detached(cmd.sig, ctypes.byref(sl), buf, len(buf), priv)
    sender = R(); ctypes.memset(ctypes.byref(sender), 0, ctypes.sizeof(R))
    il = I(); ctypes.memset(ctypes.byref(il), 0, ctypes.sizeof(I))
    res = g.evaluate_command(ctypes.byref(cmd), ctypes.byref(sender), ctypes.byref(il), now)
    print(f"RESULT: {res} (Expected: 5)")

test_missing_token()

def test_bad_signature():
    print("\n[TEST 2] Invalid Signature")
    pub = (ctypes.c_ubyte * 32)()
    priv = (ctypes.c_ubyte * 64)()
    s.crypto_sign_keypair(pub, priv)
    cmd = C()
    ctypes.memset(ctypes.byref(cmd), 0, ctypes.sizeof(C))
    cmd.env.v = 1; cmd.env.sq = 1
    now = int(time.time() * 1e9)
    cmd.env.ia = now; cmd.env.ea = now + 5000000000
    token = ctypes.c_uint32(0xDEADBEEF)
    ctypes.memmove(ctypes.addressof(cmd.env.p), ctypes.byref(token), 4)
    ctypes.memmove(ctypes.addressof(cmd.env.p) + 4, ctypes.addressof(pub), 32)
    # Tamper with payload AFTER signing
    buf = ctypes.string_at(ctypes.addressof(cmd.env), ctypes.sizeof(E))
    sl = ctypes.c_ulonglong(0)
    s.crypto_sign_detached(cmd.sig, ctypes.byref(sl), buf, len(buf), priv)
    cmd.env.p[10] = 0xFF # Corrupt one byte
    sender = R(); ctypes.memset(ctypes.byref(sender), 0, ctypes.sizeof(R))
    il = I(); ctypes.memset(ctypes.byref(il), 0, ctypes.sizeof(I))
    res = g.evaluate_command(ctypes.byref(cmd), ctypes.byref(sender), ctypes.byref(il), now)
    print(f"RESULT: {res} (Expected: 1)")

test_bad_signature()

def test_replay():
    print("\n[TEST 3] Replay Attack (Sequence Mismatch)")
    pub = (ctypes.c_ubyte * 32)()
    priv = (ctypes.c_ubyte * 64)()
    s.crypto_sign_keypair(pub, priv)
    cmd = C()
    ctypes.memset(ctypes.byref(cmd), 0, ctypes.sizeof(C))
    cmd.env.v = 1; cmd.env.sq = 1 # Sequence 1
    now = int(time.time() * 1e9)
    cmd.env.ia = now; cmd.env.ea = now + 5000000000
    token = ctypes.c_uint32(0xDEADBEEF)
    ctypes.memmove(ctypes.addressof(cmd.env.p), ctypes.byref(token), 4)
    ctypes.memmove(ctypes.addressof(cmd.env.p) + 4, ctypes.addressof(pub), 32)
    buf = ctypes.string_at(ctypes.addressof(cmd.env), ctypes.sizeof(E))
    sl = ctypes.c_ulonglong(0)
    s.crypto_sign_detached(cmd.sig, ctypes.byref(sl), buf, len(buf), priv)
    
    sender = R(); ctypes.memset(ctypes.byref(sender), 0, ctypes.sizeof(R))
    sender.u = True; sender.ls = 1 # Pretend we already processed seq 1
    il = I(); ctypes.memset(ctypes.byref(il), 0, ctypes.sizeof(I))
    
    # Send same packet again
    res = g.evaluate_command(ctypes.byref(cmd), ctypes.byref(sender), ctypes.byref(il), now)
    print(f"RESULT: {res} (Expected: 3)")

test_replay()

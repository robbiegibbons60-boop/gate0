import os, ctypes, time, struct
from ctypes import c_uint64, c_uint32, c_ubyte, c_ulonglong

# Load libraries
g = ctypes.CDLL(os.path.expanduser("~/gate0/libgate0.so"))
s = ctypes.CDLL("libsodium.so")
s.sodium_init()
s.crypto_sign_keypair.argtypes = [ctypes.POINTER(c_ubyte)] * 2
s.crypto_sign_detached.argtypes = [ctypes.POINTER(c_ubyte), ctypes.POINTER(c_ulonglong), ctypes.c_void_p, c_ulonglong, ctypes.POINTER(c_ubyte)]
s.crypto_sign_verify_detached.argtypes = [ctypes.POINTER(c_ubyte), ctypes.c_void_p, c_ulonglong, ctypes.POINTER(c_ubyte)]

# Define raw function signature for evaluate_command
# We will pass raw pointers to our bytearrays
g.evaluate_command.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, c_uint64]
g.evaluate_command.restype = ctypes.c_int

# Helper to create a zeroed 512-byte command
def make_raw_cmd():
    return bytearray(512)

# Helper to create a zeroed 41-byte sender record
def make_raw_sender():
    return bytearray(41)

# Helper to create a zeroed 4-byte interlock struct
def make_raw_interlocks():
    return bytearray(4)

# Helper to sign the envelope (bytes 64-511) in place
def sign_envelope(cmd_buf, privkey):
    env_ptr = ctypes.addressof(ctypes.c_char.from_buffer(cmd_buf, 64))
    sig_ptr = ctypes.addressof(ctypes.c_char.from_buffer(cmd_buf, 0))
    sl = ctypes.c_ulonglong(0)
    s.crypto_sign_detached(
        ctypes.cast(sig_ptr, ctypes.POINTER(c_ubyte)),
        ctypes.byref(sl),
        ctypes.cast(env_ptr, ctypes.c_void_p),
        448,
        ctypes.cast(ctypes.addressof(privkey), ctypes.POINTER(c_ubyte))
    )

# Generate a valid keypair for testing
pub = (c_ubyte * 32)()
priv = (c_ubyte * 64)()
s.crypto_sign_keypair(pub, priv)

print("[*] Adversarial Harness Initialized. ABI: 512B cmd, 41B sender, 4B interlocks.")
print(f"[*] Test PubKey: {bytes(pub).hex()[:16]}...")

# --- TEST VECTORS WILL BE APPENDED BELOW ---


def test_time_anomaly():
    print("\n[VECTOR 1] Time Anomaly (issued > expires)")
    cmd = make_raw_cmd()
    sender = make_raw_sender()
    il = make_raw_interlocks()
    
    # Set valid bootstrap token and pubkey
    cmd[92:96] = struct.pack("<I", 0xDEADBEEF)
    cmd[96:128] = bytes(pub)
    
    # Set sequence to 1
    cmd[68:76] = struct.pack("<Q", 1)
    
    # ANOMALY: issued_at_ns > expires_at_ns
    cmd[76:84] = struct.pack("<Q", 2000000000) # issued
    cmd[84:92] = struct.pack("<Q", 1000000000) # expires
    
    sign_envelope(cmd, priv)
    
    now = 1500000000 # Between expires and issued
    res = g.evaluate_command(
        ctypes.addressof(ctypes.c_char.from_buffer(cmd)),
        ctypes.addressof(ctypes.c_char.from_buffer(sender)),
        ctypes.addressof(ctypes.c_char.from_buffer(il)),
        now
    )
    print(f"RESULT: {res} (Expected: 2 = GO_EXPIRED)")

test_time_anomaly()


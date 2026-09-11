import socket
import struct
import ctypes
import time
import os

ENVELOPE_FMT = "<IQQQ256sI32s32s32s64s"
SIGNED_COMMAND_FMT = "<64s" + ENVELOPE_FMT[1:]

sodium = ctypes.CDLL("libsodium.so")
sodium.sodium_init()
pk = ctypes.create_string_buffer(32)
sk = ctypes.create_string_buffer(64)
sodium.crypto_sign_keypair(pk, sk)

SOCKET_PATH = os.path.expanduser("~/gate0/run/gate0.sock")

def send_packet(packet_bytes):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(SOCKET_PATH)
        s.sendall(packet_bytes)
        res = s.recv(4)
        s.close()
        if len(res) == 4:
            return struct.unpack("<I", res)[0]
        return -1
    except Exception as e:
        return str(e)

def build_packet(seq=1, expired=False, truncate=0):
    now_ns = int(time.time_ns())
    if expired:
        issued = 1000
        expires = 2000
    else:
        issued = now_ns
        expires = now_ns + 10_000_000_000

    bootstrap_token = struct.pack("<I", 0xDEADBEEF)
    payload = bootstrap_token + pk.raw + b"\x00" * (256 - 4 - 32)
    
    env = struct.pack(ENVELOPE_FMT,
        1, seq, issued, expires, payload, 1,
        b"Linux", b"Release", b"Arch", b"Hostname"
    )
    
    sig = ctypes.create_string_buffer(64)
    sig_len = ctypes.c_ulonglong()
    sodium.crypto_sign_detached(sig, ctypes.byref(sig_len), env, len(env), sk)
    
    packet = bytes(sig.raw) + env
    if truncate > 0:
        packet = packet[:-truncate]
    return packet

print("[*] Running Full Matrix Execution...")

r_ok = send_packet(build_packet(seq=1))
print(f"[TEST] Control Valid (Seq 1) -> Result: {r_ok} (Expected: 0)")

r_exp = send_packet(build_packet(seq=2, expired=True))
print(f"[TEST] Expired Timestamp -> Result: {r_exp} (Expected: 2)")

r_trunc = send_packet(build_packet(seq=3, truncate=64))
print(f"[TEST] Truncated Packet -> Result: {r_trunc} (Expected: Closed/Error)")


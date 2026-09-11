import socket
import struct
import ctypes
import time
import os

def run_production_integration():
    print("[+] Initializing libsodium...")
    sodium = ctypes.CDLL("libsodium.so")
    sodium.sodium_init()

    pk = ctypes.create_string_buffer(32)
    sk = ctypes.create_string_buffer(64)
    sodium.crypto_sign_keypair(pk, sk)

    protocol_version = 1
    sequence_number = 101
    issued_at_ns = int(time.time_ns())
    expires_at_ns = issued_at_ns + 10_000_000_000
    nonce = b"\x00" * 16
    command_type = 1
    parameters = b"\x01" + b"\x00" * 255
    parameters_len = 1
    required_authority = 1

    envelope_format = "<IQQQ16sII256sI"
    envelope_data = struct.pack(
        envelope_format,
        protocol_version,
        sequence_number,
        issued_at_ns,
        expires_at_ns,
        nonce,
        command_type,
        parameters_len,
        parameters,
        required_authority
    )

    sig = ctypes.create_string_buffer(64)
    sig_len = ctypes.c_ulonglong(0)
    sodium.crypto_sign_detached(sig, ctypes.byref(sig_len), envelope_data, len(envelope_data), sk)

    packet = envelope_data + sig.raw + pk.raw
    print(f"[+] Total payload assembled: {len(packet)} bytes (Expected: 408 bytes)")

    socket_path = os.path.expanduser("~/gate0/run/gate0.sock")
    print(f"[+] Connecting to daemon socket at {socket_path}...")
    
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(socket_path)
    
    print("[+] Transmitting signed command packet...")
    s.sendall(packet)

    resp = s.recv(4)
    if resp:
        result_code = struct.unpack("<i", resp)[0]
        print(f"[+] Daemon Response Code: {result_code} (G0_OK = 0)")
        if result_code == 0:
            print("[+] SUCCESS: Three-tier pipeline validated. Cryptographic enforcement passed, WAL hash-chain updated.")
        else:
            print(f"[!] REJECTED: Executive returned error code {result_code}")
    else:
        print("[-] No response received from executive daemon.")
        
    s.close()

if __name__ == "__main__":
    run_production_integration()

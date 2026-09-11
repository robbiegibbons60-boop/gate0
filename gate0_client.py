import socket
import struct
import time
from nacl.signing import SigningKey

HOST = '127.0.0.1'
PORT = 9090

def create_gate0_packet():
    # 1. Generate Ed25519 keypair
    signing_key = SigningKey.generate()
    public_key_bytes = bytes(signing_key.verify_key)
    print(f"[+] Generated Public Key: {public_key_bytes.hex()}")

    # 2. Build CommandEnvelope (448 bytes)
    envelope = bytearray(448)
    
    # Offsets based on grep output:
    # version (uint32_t) at 0
    struct.pack_into('<I', envelope, 0, 1)
    
    # sequence (uint64_t) at 4
    struct.pack_into('<Q', envelope, 4, 1)
    
    # issued_at_ns (uint64_t) at 12
    now_ns = int(time.time() * 1e9)
    struct.pack_into('<Q', envelope, 12, now_ns)
    
    # expires_at_ns (uint64_t) at 20
    struct.pack_into('<Q', envelope, 20, now_ns + 10_000_000_000)
    
    # payload (uint8_t[256]) starts at 28
    # Place public key in first 32 bytes of payload (bytes 28-59)
    envelope[28:60] = public_key_bytes
    
    # Set a simple command type in the rest of the payload (e.g., byte 60)
    envelope[60] = 0x01 
    
    # required_authority (uint32_t) at 284
    struct.pack_into('<I', envelope, 284, 1)
    
    # DeviceInfo (160 bytes) starts at 288. Left as zeros.

    # 3. Sign the Envelope
    signature = signing_key.sign(bytes(envelope)).signature[:64]

    # 4. Construct SignedCommand (512 bytes)
    packet = signature + bytes(envelope)
    return packet

def send_packet(packet):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(packet)
            print("[+] Packet sent. Waiting for response...")
            data = s.recv(4)
            if data:
                result = int.from_bytes(data, byteorder='little')
                print(f"[+] Daemon Response Code: {result}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    pkt = create_gate0_packet()
    if len(pkt) == 512:
        send_packet(pkt)
    else:
        print(f"[-] Packet size error: {len(pkt)}")

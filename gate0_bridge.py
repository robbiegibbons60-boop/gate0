import os
import socket
import struct
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SOCKET_PATH = "/data/data/com.termux/files/home/gate0/kernel.sock"

def main():
    print("[*] Initializing Python-to-C Gate Zero IPC Bridge...")
    
    # 1. Generate Ed25519 keypair using production crypto primitives
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # 2. Construct the binary CommandEnvelope matching C struct layout
    # Layout: protocol_version(1), command_id(4), node_id(4), issued_at(8), 
    #         expires_at(8), sequence(8), nonce(16), command_type(1), 
    #         parameters_len(2), parameters(256), required_authority(1)
    protocol_version = 0x01
    command_id = 701
    node_id = 0x01
    issued_at_ns = int(time.time() * 1e9)
    expires_at_ns = issued_at_ns + 1000000000  # +1 second
    sequence_number = 1
    nonce = os.urandom(16)
    command_type = 0x01
    parameters_len = 0
    parameters = b'\x00' * 256
    required_authority = 1  # AUTH_OPERATOR

    envelope_format = "<BIIQQQ 16s H 256s B"
    envelope_data = struct.pack(
        envelope_format,
        protocol_version,
        command_id,
        node_id,
        issued_at_ns,
        expires_at_ns,
        sequence_number,
        nonce,
        command_type,
        parameters_len,
        parameters,
        required_authority
    )

    # 3. Sign the envelope using Ed25519 detached signature
    signature = private_key.sign(envelope_data)

    # 4. Pack the full SignedCommand (Envelope + Signature [64 bytes] + Pubkey [32 bytes])
    signed_command = envelope_data + signature + pub_bytes

    # 5. Transmit over UNIX domain socket to the C11 daemon
    if not os.path.exists(SOCKET_PATH):
        print(f"[-] Error: Socket not found at {SOCKET_PATH}. Is gate0_daemon running?")
        return

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(SOCKET_PATH)
    client.sendall(signed_command)

    # 6. Read back authoritative C11 kernel result code (4 bytes integer)
    response = client.recv(4)
    client.close()

    if len(response) == 4:
        result_code = struct.unpack("<i", response)[0]
        print(f"[+] KERNEL IPC RESPONSE: Code {result_code} ('0' = G0_OK Authorized)")
    else:
        print("[-] Error: Malformed response received from C11 daemon.")

if __name__ == "__main__":
    main()

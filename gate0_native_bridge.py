import os
import ctypes
import time

lib_path = os.path.expanduser("~/gate0/libgate0.so")
gate0 = ctypes.CDLL(lib_path)

class CommandEnvelope(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ("protocol_version", ctypes.c_uint8),
        ("command_id", ctypes.c_uint32),
        ("node_id", ctypes.c_uint32),
        ("issued_at_ns", ctypes.c_uint64),
        ("expires_at_ns", ctypes.c_uint64),
        ("sequence_number", ctypes.c_uint64),
        ("nonce", ctypes.c_ubyte * 16),
        ("command_type", ctypes.c_uint8),
        ("parameters_len", ctypes.c_uint16),
        ("parameters", ctypes.c_ubyte * 256),
        ("required_authority", ctypes.c_uint8)
    ]

class SignedCommand(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ("envelope", CommandEnvelope),
        ("signature", ctypes.c_ubyte * 64),
        ("sender_pubkey", ctypes.c_ubyte * 32)
    ]

class SenderRecord(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ("used", ctypes.c_bool),
        ("public_key", ctypes.c_ubyte * 32),
        ("current_sequence", ctypes.c_uint64),
        ("allowed_nodes", ctypes.c_uint32),
        ("authority", ctypes.c_uint32)
    ]

class SafetyInterlocks(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ("estop", ctypes.c_bool),
        ("overspeed", ctypes.c_bool),
        ("overtemp", ctypes.c_bool),
        ("overvoltage", ctypes.c_bool)
    ]

gate0.evaluate_command.argtypes = [
    ctypes.POINTER(SignedCommand),
    ctypes.POINTER(SenderRecord),
    ctypes.POINTER(SafetyInterlocks),
    ctypes.c_uint64
]
gate0.evaluate_command.restype = ctypes.c_int

def main():
    print("[*] Executing clean native C-core evaluation...")
    
    cmd = SignedCommand()
    ctypes.memset(ctypes.byref(cmd), 0, ctypes.sizeof(SignedCommand))
    
    cmd.envelope.protocol_version = 0x01
    cmd.envelope.command_id = 902
    cmd.envelope.node_id = 0x01
    cmd.envelope.issued_at_ns = int(time.time() * 1e9)
    cmd.envelope.expires_at_ns = cmd.envelope.issued_at_ns + 2000000000
    cmd.envelope.sequence_number = 1
    cmd.envelope.required_authority = 1

    sender = SenderRecord()
    ctypes.memset(ctypes.byref(sender), 0, ctypes.sizeof(SenderRecord))
    
    interlocks = SafetyInterlocks()
    ctypes.memset(ctypes.byref(interlocks), 0, ctypes.sizeof(SafetyInterlocks))

    result = gate0.evaluate_command(ctypes.byref(cmd), ctypes.byref(sender), ctypes.byref(interlocks), cmd.envelope.issued_at_ns)
    print(f"[+] NATIVE C CORE RESULT CODE: {result} (Note: non-zero expected here due to dummy signature bypass check)")

if __name__ == "__main__":
    main()

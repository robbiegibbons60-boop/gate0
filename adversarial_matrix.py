class CommandEnvelope(ctypes.Structure):
 _fields_=[("node_id",ctypes.c_uint8*32),
 ("sequence",ctypes.c_uint64),
 ("issued_at_ns",ctypes.c_uint64),
 ("expires_at_ns",ctypes.c_uint64),
 ("command_id",ctypes.c_uint32),
 ("payload",ctypes.c_uint8*256),
 ("payload_len",ctypes.c_uint32)]
class SignedCommand(ctypes.Structure):
 _fields_=[("envelope",CommandEnvelope),
 ("signature",ctypes.c_uint8*64)]
class SenderRecord(ctypes.Structure):
 _fields_=[("public_key",ctypes.c_uint8*32),
 ("last_sequence",ctypes.c_uint64),
 ("used",ctypes.c_bool)]
class SafetyInterlocks(ctypes.Structure):
 _fields_=[("estop",ctypes.c_bool),
 ("overspeed",ctypes.c_bool),
 ("overtemp",ctypes.c_bool),
 ("overvoltage",ctypes.c_bool)]

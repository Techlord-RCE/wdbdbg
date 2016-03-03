#! /usr/bin/env python
# coding: utf-8
#
# Author: Yannick Formaggio
from enum import Enum


# RPC Protocol constants
CALL = 0
REPLY = 1

# Credential flavors
AUTH_NULL = 0
AUTH_UNIX = 1
AUTH_SHORT = 2
AUTH_DES = 3

MSG_ACCEPTED = 0
MSG_DENIED = 1
SUCCESS = 0                             # RPC executed successfully
PROG_UNAVAIL = 1                        # remote hasn't exported program
PROG_MISMATCH = 2                       # remote can't support version #
PROC_UNAVAIL = 3                        # program can't support procedure
GARBAGE_ARGS = 4                        # procedure can't decode params
RPC_MISMATCH = 0                        # RPC version number != 2
AUTH_ERROR = 1                          # remote can't authenticate caller
AUTH_BADCRED = 1                        # bad credentials (seal broken)
AUTH_REJECTEDCRED = 2                   # client must begin new session
AUTH_BADVERF = 3                        # bad verifier (seal broken)
AUTH_REJECTEDVERF = 4                   # verifier expired or replayed
AUTH_TOOWEAK = 5                        # rejected for security reasons


# Fields offsets
class CallOffsets(Enum):
    RPC_XID = 0
    RPC_MID = 1 * 4
    RPC_VER = 2 * 4
    RPC_PRG = 3 * 4
    RPC_PRG_VER = 4 * 4
    RPC_PROC = 5 * 4
    WDB_CHKSM = 10 * 4
    WDB_PKTSZ = 11 * 4
    WDB_SEQNO = 12 * 4


class ReplyOffsets(Enum):
    RPC_XID = 0
    RPC_MID = 1 * 4
    RPC_VER = 2 * 4
    RPC_VERIF = 3 * 4
    RPC_VERIF_LEN = 4 * 4
    RPC_STATUS = 5 * 4
    WDB_CHKSM = 6 * 4
    WDB_PKTSZ = 7 * 4
    WDB_ERR = 8 * 4

# WDB Procedures numbers.
# Session Management
WDB_TARGET_CONNECT = 1	                # connect to the agent

# Memory Operations
WDB_MEM_READ = 10	                    # read a memory block


# Register Manipulation
WDB_REGS_GET = 40                       # get register(s)

# Events
WDB_EVENT_GET = 70                      # get info about an event

# New set of procedures for VxWorks v6+
WDB_TARGET_CONNECT2 = 122               # connect to the agent

# WDB Error codes
WDB_OK = 0                              # success

# Session specific constants
WDBPORT = 0x4321                        # UDP Port
WDBPROG = 0x55555555                    # RPC Program number
RPCVERS = 2                             # RPC Protocol version
WDBVERS = 1                             # WDB Protocol version

WDB_REQ_HDR_SZ = 52                     # RPC Req header size + Param wrapper
WDB_RESP_HDR_SZ = 36                    # RPC Resp header size + Param wrapper

# Registers
X86_REGS = ["EDI", "ESI", "EBP", "ESP", "EBX", "EDX", "ECX", "EAX", "EFLAGS", "PC"]

# Exceptions
exceptions = [
    'DIVIDE_ERROR', 'DEBUG', 'NON_MASKABLE', 'BREAKPOINT', 'OVERFLOW', 'BOUND', 'INVALID_OPCODE',
    'NO_DEVICE', 'DOUBLE_FAULT', 'CP_OVERRUN', 'INVALID_TSS', 'NO_SEGMENT', 'STACK_FAULT',
    'PROTECTION_FAULT', 'PAGE_FAULT', 'RESERVED', 'CP_ERROR', 'ALIGNMENT', 'MACHINE_CHECK', 'SIMD'
]

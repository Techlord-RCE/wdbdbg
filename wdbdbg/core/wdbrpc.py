# Copyright (C) 2016 Yannick Formaggio for Istuary Innovation Labs, Inc. 
# and/or its affiliates. All rights reserved.
#
# This file is part of WdbDBG.
#
# WdbDBG is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# WdbDBG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WdbDBG.  If not, see <http://www.gnu.org/licenses/>.

import socket
import struct
import xdrlib
import logging
from random import randint
from defines import *

logging.basicConfig()
logger = logging.getLogger(__name__)

try:
    from select import select
except ImportError:
    logger.warning("Cannot import select, RPC request may hang...")
    select = None


class WdbRPCException(Exception):
    """ WDB RPC Protocol specific exception
    """
    pass


class WdbPacker(xdrlib.Packer):

    def __init__(self):
        xdrlib.Packer.__init__(self)

    def pack_call_header(self, xid, rpc_ver, program, version, procedure, cred,
                         verifier):
        self.pack_uint(xid)
        self.pack_enum(0)
        self.pack_uint(rpc_ver)
        self.pack_uint(program)
        self.pack_uint(version)
        self.pack_uint(procedure)
        self.pack_auth(cred)
        self.pack_auth(verifier)

    def pack_auth(self, auth):
        # unpack auth
        flavor, length = auth
        self.pack_enum(flavor)
        self.pack_uint(length)

    def pack_wdb_param_wrapper(self, seq_no):
        self.pack_uint(0)               # Checksum is set to 0
        self.pack_uint(0)               # Packet size too
        self.pack_uint(seq_no)

    def pack_call_args(self, call_args):
        for ca in call_args:
            if isinstance(ca, int):
                self.pack_uint(ca)
            elif isinstance(ca, str):
                self.pack_string(ca)


class WdbUnpacker(xdrlib.Unpacker):

    def __init__(self, data):
        xdrlib.Unpacker.__init__(self, data)

    def unpack_reply_header(self):
        xid = self.unpack_uint()
        msg_type = self.unpack_enum()

        if msg_type is not REPLY:
            raise WdbRPCException("Not a reply ({}).".format(msg_type))
        status = self.unpack_enum()

        if status is MSG_DENIED:
            status = self.unpack_enum()

            if status is RPC_MISMATCH:
                low = self.unpack_uint()
                high = self.unpack_uint()
                raise WdbRPCException("Message denied: RPC_MISMATCH: {}".format((low, high)))

            if status is AUTH_ERROR:
                status = self.unpack_uint()
                raise WdbRPCException("Message denied: AUTH_ERROR {}".format(status))

            raise WdbRPCException("Message denied: {}".format(status))

        if status is not MSG_ACCEPTED:
            raise WdbRPCException("Neither message denied nor message accepted: {}".format(status))

        verifier = self.unpack_auth()
        status = self.unpack_enum()

        if status is PROG_UNAVAIL:
            raise WdbRPCException("Call failed, program unavailable")

        if status is PROG_MISMATCH:
            low = self.unpack_uint()
            high = self.unpack_uint()
            raise WdbRPCException("Call failed, program mismatch: {}".format((low, high)))

        if status is PROC_UNAVAIL:
            raise WdbRPCException("Call failed: procedure unavailable")

        if status is GARBAGE_ARGS:
            raise WdbRPCException("Call failed: garbage arguments.")

        if status is not SUCCESS:
            raise WdbRPCException("Call failed: {}".format(status))

        return xid, verifier

    def unpack_auth(self):
        flavor = self.unpack_enum()
        length = self.unpack_uint()
        return flavor, length

    def unpack_reply_param_wrapper(self):
        checksum = self.unpack_uint()
        pkt_size = self.unpack_uint()
        wdb_error_status = self.unpack_uint()

        return checksum, pkt_size, wdb_error_status


class WdbRPC(object):
    """ WdbRPC class for VxWorks version < 6.
    """
    _request_seqno = 0x49530000                                     # "IS.." for Istuary Security ;)

    def __init__(self, tgt_ip, timeout):
        """
        :param tgt_ip: target IP address
        :type tgt_ip: str
        :param timeout: connection timeout
        :type timeout: int
        :return: None
        :rtype: NoneType
        """
        self.target = (tgt_ip, WDBPORT)
        self.last_xid = randint(1024, 2**32-1)

        self.packer = WdbPacker()
        self.unpacker = WdbUnpacker("")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(int(timeout))

        except socket.error as exc:
            raise WdbRPCException(exc)

    @staticmethod
    def __length(data):
        return struct.pack("!I", len(data) - 4)                     # Do not count XID

    @staticmethod
    def __checksum(data):
        """ Computes the checksum and adds it to the WDB request packet.

        :param data: data to be summed
        :type data: str
        :return: WDB request with checksum included
        :rtype: str
        """
        # tmp = "\x00" * 4 + data[4:]
        chksum = sum([elt for elt in struct.unpack('!{}H'.format(len(data) / 2), data)])
        chksum = (chksum & 0xffff) + (chksum >> 16)
        checksum = ((~chksum) & 0xffff) | 0xffff0000

        return struct.pack("!I", checksum)

    def __xid(self):
        """ Returns the packed last message ID.

        To be called once the checksum has been computed and added to the packet as it should not be included.
        :return: packed last message ID
        :rtype: str
        """
        return struct.pack('!I', self.last_xid)

    def call_procedure(self, procedure_number, parameters, unpack_function=None):
        """ Prepare the request, then sends it to the target.

        :param procedure_number: WDB Request procedure number
        :type procedure_number: int
        :param parameters:
        :type parameters:
        :param unpack_function:
        :type unpack_function:
        :return: checksum, size of reply and error status
        :rtype: tuple
        """

        self.last_xid += 1

        packer = self.packer

        packer.reset()

        # Add RPC Header
        packer.pack_call_header(0, RPCVERS, WDBPROG, WDBVERS, int(procedure_number), (0, 0), (0, 0))

        # Add WDB Param wrapper
        self._request_seqno += 1
        packer.pack_wdb_param_wrapper(self._request_seqno)

        # if pack_function:
        #     pack_function(parameters)
        if parameters is not None:
            packer.pack_call_args(parameters)

        call = bytearray(self.packer.get_buffer())
        call[CallOffsets.WDB_PKTSZ.value:CallOffsets.WDB_SEQNO.value] = self.__length(call)
        call[CallOffsets.WDB_CHKSM.value:CallOffsets.WDB_PKTSZ.value] = self.__checksum(bytes(call))
        call[CallOffsets.RPC_XID.value:CallOffsets.RPC_MID.value] = self.__xid()

        # Send request and wait for reply
        try:
            self.sock.sendto(call, self.target)

        except socket.error as exc:
            raise WdbRPCException("Request sending failed: {}".format(exc))

        buffsize = 8192
        timeout = 1
        count = 5

        while True:
            r, w, x = [self.sock], [], []

            if select:
                r, w, x = select(r, w, x, timeout)
            if self.sock not in r:
                count -= 1
                if count < 0:
                    raise WdbRPCException("Timeout")
                if timeout < 25:
                    timeout *= 2

                try:
                    logger.debug("resending, timeout = {0}, count = {1}".format(timeout, count))
                    self.sock.sendto(call, self.target)

                except socket.error as exc:
                    raise WdbRPCException("Request sending failed: {}".format(exc))

                continue

            reply = self.sock.recvfrom(buffsize)[0]
            unpacker = self.unpacker
            unpacker.reset(reply)
            xid, verifier = unpacker.unpack_reply_header()

            if xid != self.last_xid:
                logger.error("BAD XID")
                continue
            break

        # Unpacker WDB ERROR STATUS
        chksum, repl_sz, wdb_err = self.unpacker.unpack_reply_param_wrapper()

        return chksum, repl_sz, wdb_err

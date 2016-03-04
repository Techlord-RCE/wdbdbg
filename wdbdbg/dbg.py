#! /usr/bin/env python
# coding: utf-8
#
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

import time
import threading
from collections import OrderedDict
from capstone import *
from core.wdbrpc import *

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Registers(OrderedDict):

    def __setitem__(self, key, value):
        if key in self:
            del(self[key])
        OrderedDict.__setitem__(self, key, value)

    def __str__(self):
        ret = ""
        for key, value in self.iteritems():
            ret += "{}\t=>\t0x{:08x}\n".format(key, value)

        return ret


class CrashInfo(object):

    def __init__(self, task_id, exception, exc_addr, registers, asm_dump):
        self.task_id = task_id
        self.registers = registers
        self.exception = exceptions[exception]
        self.exception_addr = exc_addr
        self.asm_dump = ""
        if asm_dump:
            # Use capstone to disassemble code where crash occurred
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            for instr in md.disasm(asm_dump, self.registers["PC"]):
                self.asm_dump += "0x{:08x}:\t{}\t{}\n".format(
                    instr.address, instr.mnemonic, instr.op_str
                )

    def __str__(self):
        report = "A crash occurred at address 0x{:08x}\n".format(self.task_id)
        report += "Exception raised: {} at address 0x{:08x}".format(self.exception, self.exception_addr)
        report += "\nRegisters states:\n"
        for key, value in self.registers.iteritems():
            report += "{}\t=>\t0x{:08x}\n".format(key, value)

        report += "\n" + "#" * 80 + "\n"
        pc = self.registers["PC"]
        if pc == 0:
            report += "Cannot disassemble code at address: 0x{:08x}.\n".format(pc)
            report += "Potential NULL pointer dereference.\n"
        else:
            report += "\nAssembly code at 0x{:08x}\n".format(pc)
            if self.asm_dump is not "":
                report += self.asm_dump
            else:
                report += "Unable to disassemble memory at PC.\n"

        report += "#" * 80 + "\n"

        return report

    def __repr__(self):
        return self.__str__()


class Dbg(object):
    def __init__(self, vxworks_version, tgt_addr):
        self.version = int(vxworks_version)
        self.target = str(tgt_addr)
        self.wdb_runtime = WdbRPC(self.target, 1)

        self.crashed = False
        self.stop = False
        self.connected = False
        self.task_id = 0
        self.exception = 0
        self.exception_address = 0
        self.registers = Registers([(elt, 0) for elt in X86_REGS])
        self.mem_dump = None
        self.crash_info = None

        self.monitor_thread = None

        if self.version < 6:
            self.notification = "\xee" * 8
        else:
            self.notification = "\xee" * 4

    def connect(self):
        if self.version < 6:
            self.wdb_runtime.call_procedure(WDB_TARGET_CONNECT, None, None)

        else:
            connection_string = "VxWorks debugger v0.1\x00"
            self.wdb_runtime.call_procedure(WDB_TARGET_CONNECT2, [2, 0, 0, 1, connection_string], None)

        self.connected = True

    def get_notification(self):
        """ Event loop.
        If target agent send a wdb notification, the debugger is alerted and send the ack (WDB_EVENT_GET) message
        :return: the notification data
        :rtype: str
        """
        notification = ""
        while True:
            ready, _, _ = select([self.wdb_runtime.sock], [], [], 0)
            if ready:
                notification = ready[0].recv(24)
                if self.notification in notification:
                    logger.debug("notification received")
                    break
                else:
                    continue
        return notification

    def __get_event_data(self):
        """ Parse event data for useful information.

        Depending on the version, the requests and replies differ
        :return: None
        :rtype: NoneType
        """
        if self.version < 6:
            parameters = None
            _, _, wdb_err = self.wdb_runtime.call_procedure(WDB_EVENT_GET, parameters, None)
            if wdb_err == WDB_OK:
                # evt_type = self.wdb_runtime.unpacker.unpack_uint()
                evt_count = self.wdb_runtime.unpacker.unpack_uint()
                evt_data = []
                for i in range(evt_count/2):
                    evt_data.append(self.wdb_runtime.unpacker.unpack_uint())

                self.task_id = evt_data[2]
                self.exception = evt_data[0]

            else:
                raise WdbRPCException("Error occurred while trying to get event data")

        else:
            parameters = [3, 0, 0, 4]
            _, _, wdb_err = self.wdb_runtime.call_procedure(WDB_EVENT_GET, parameters, None)

            if wdb_err == WDB_OK:
                evt_type = self.wdb_runtime.unpacker.unpack_uint()
                evt_count = self.wdb_runtime.unpacker.unpack_uint()
                evt_data = []
                if evt_type == 6:
                    # WDB Exception occurred
                    for i in range(evt_count):
                        evt_data.append(self.wdb_runtime.unpacker.unpack_uint())

                    self.task_id, self.exception, self.exception_address = evt_data[2], evt_data[7], evt_data[8]
                else:
                    # Unknown exception
                    raise WdbRPCException("Unhandled event")
            else:
                raise WdbRPCException("Error occurred while trying to get event data")

    def __get_registers(self):
        """ Dumps the registers info.

        :return: None
        :rtype: NoneType
        """
        if self.version < 6:
            reg_offset = WDB_RESP_HDR_SZ + 12
            parameters = [0, 3, self.task_id, 0, WDB_REGS_GET, 0]

        else:
            reg_offset = WDB_RESP_HDR_SZ + 16
            parameters = [3, 0, 0, 0, 0, 3, 1, 1, self.task_id, 0, 0, WDB_REGS_GET, 0]

        _, _, wdb_err = self.wdb_runtime.call_procedure(WDB_REGS_GET, parameters)

        if wdb_err == WDB_OK:
            data = self.wdb_runtime.unpacker.get_buffer()[reg_offset:]        # only reg data
            if data:
                regs = struct.unpack("<10I", data)                                      # 10 Registers
                for reg, value in zip(self.registers.keys(), regs):
                    self.registers[reg] = value
            else:
                WdbRPCException("Error occurred while trying to dump the registers")
        else:
            raise WdbRPCException("Error occurred while trying to dump the registers")

    def __get_memory_dump(self, num_bytes=100):
        """ Dumps memory around pc.
        :param num_bytes:
        :type num_bytes:
        :return:
        :rtype:
        """
        pc = self.registers["PC"]
        if pc == 0:
            # Cannot dump memory at address 0
            logger.debug("Cannot dump memory at address 0")
            self.mem_dump = ""

        else:
            if self.version < 6:
                mem_offset = WDB_RESP_HDR_SZ + 12
                parameters = [pc, num_bytes, 0]

            else:
                mem_offset = WDB_RESP_HDR_SZ + 16
                parameters = [2, 0, 0, 0, pc, num_bytes, 0]

            try:
                _, _, wdb_err = self.wdb_runtime.call_procedure(WDB_MEM_READ, parameters)
                if wdb_err == WDB_OK:
                    data = self.wdb_runtime.unpacker.get_buffer()[mem_offset:]
                    if data:
                        self.mem_dump = data
                else:
                    self.mem_dump = ""

            except Exception as exc:
                self.mem_dump = ""

    def monitor_thread_worker(self):
        """ Thread in charge of monitoring the target for incoming notification.

        Once notification received, get the event data, registers and memory dump if possible.
        :return: None
        :rtype: None
        """
        logger.debug("monitor thread starts")
        crash_notification = ""

        while crash_notification is "":
            crash_notification = self.get_notification()

        logger.debug("crash notification received")

        # Acknowledge event
        logger.debug("sending ack")
        self.__get_event_data()

        time.sleep(0.05)                    # Fix issue #1: VxWorks 5.x needs some time between requests
        if self.task_id:
            logger.debug("getting registers status")
            self.__get_registers()

        time.sleep(0.05)                    # Fix issue #1: VxWorks 5.x needs some time between requests
        if self.registers:
            logger.debug("dumping memory around pc")
            self.__get_memory_dump()

        self.crashed = True

    def begin_monitoring(self):
        logger.debug("Starting monitor thread")
        self.crashed = False
        self.stop = False
        self.monitor_thread = threading.Thread(target=self.monitor_thread_worker, name="debug_loop")
        self.monitor_thread.setDaemon(True)
        self.monitor_thread.start()

    def monitor(self):
        self.stop = True
        self.monitor_thread.join()
        crash = None
        crash_info = "WDB Monitor detected a crash in 0x{:08x}".format(self.task_id)

        if self.crashed:
            logger.info(crash_info)
            crash = CrashInfo(self.task_id, self.exception, self.exception_address, self.registers, self.mem_dump)

        self.crash_info = str(crash)
        return str(crash)

if __name__ == '__main__':
    dbg = Dbg(6, "192.168.102.89")
    # dbg = Dbg(5, "192.168.102.88")
    dbg.connect()
    dbg.begin_monitoring()
    crash_info = ""
    while not dbg.crashed:
        crash_info = dbg.monitor()

    print crash_info

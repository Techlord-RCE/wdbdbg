#! /usr/bin/env python
# coding: utf-8
#
# Author: Yannick Formaggio
# This python module is based on the sulley Unix process monitor.

import argparse
import sys
import time

# Sulley imports
try:
    from sulley import pedrpc

except ImportError as exc:
    pedrpc = None
    print("First make sure sulley framework is your PYTHONPATH!")
    sys.exit(-1)

# WdbDBG imports
from wdbdbg.dbg import *

logger = logging.getLogger("wdbdb.dbg")


class VxWorksProcMonitor(pedrpc.server):

    def __init__(self, host, port, crash_filename, target_version, target_address, level=logging.INFO):
        """
        @param host: IP address the servlet is bound to
        @type host: str
        @param port: Port the servlet is listening to
        @type port: int
        @param crash_filename: filename to record crash information
        @type crash_filename: str
        @param target_version: VxWorks target version
        @type target_version: int
        @param target_address: VxWorks target IP address
        @type target_address: str
        @param level: Debug logging level
        @type level: int
        @return: None
        @rtype: NoneType
        """

        # Initialize PED-RPC server
        pedrpc.server.__init__(self, host, port)
        self.crash_bin = crash_filename
        self.log_level = level
        self.dbg = None
        self.log = logging.getLogger("wdbdb.dbg")
        self.log.setLevel(level)
        self.log.info("Process monitor PED-RPC server initialized")
        self.log.info("Listening on {}:{}".format(host, port))
        self.log.info("Awaiting requests...")
        self.last_synopsis = None
        self.test_number = 0
        self.target_version = target_version
        self.target_address = target_address

    @staticmethod
    def alive():
        """ Always returns True. Useful for PED-RPC clients who want to check if PED-RPC is still alive
        @return: True
        @rtype: bool
        """
        return True

    def post_send(self):
        """ Routine called after the fuzzer transmits a test case and returns the status of the target.
        @return: True if target is active, False otherwise
        @rtype: bool
        """
        if self.dbg.crashed:
            self.last_synopsis = self.dbg.monitor()
            with open(self.crash_bin, "a") as crash_bin:
                crash_bin.write(self.last_synopsis)

        return not self.dbg.crashed

    def pre_send(self, test_number):
        """ Routine called before the fuzzer transmits a test case and ensure the debugger thread is operational.
        """
        if not self.dbg:
            self.start_debugger()
        self.test_number = test_number
        self.log.debug("pre_send({})".format(self.test_number))

    def start_debugger(self):
        """ Start up the process monitor and waits 5 seconds that the target is operational.
        @return: None
        @rtype:
        """
        self.log.info("starting target process monitoring")
        self.dbg = Dbg(self.target_version, self.target_address)
        self.dbg.connect()
        self.dbg.begin_monitoring()
        # Prevent blocking by spawning off another thread to wait for crash infos
        threading.Thread(target=self.dbg.monitor, name="crash event loop").start()
        self.log.info("Done. Target is up and running, give 5 seconds to settle in.")
        time.sleep(5)

    def get_crash_synopsis(self):
        """ Returns the last recorded crash synopsis
        @return: self.last_synopsys
        @rtype: str
        """
        return str(self.last_synopsis)


class VxWorksMonitor(object):

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(
            add_help=False,
            description="VxWorks WdbRPC process monitor",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            prog="vxworks_procmon"
        )

        mand = parser.add_argument_group('mandatory args')
        mand.add_argument('-c', '--crashbin', required=True, type=str,
                          dest='crashbin', help='File to record crash info to')
        mand.add_argument('-t', '--target-ip', required=True, type=str, dest='target', help='Target IP address')
        mand.add_argument("-v", "--version", required=True, type=int, dest="version", help="VxWorks target version")

        opt = parser.add_argument_group('optional arguments')
        opt.add_argument('-l', '--logging', type=int, default=10, choices=range(10, 60, 10),
                         help='Logging verbosity level')
        opt.add_argument('-p', '--port', type=int, default=26001,
                         dest='port', help='PED RPC port')

        return parser.parse_args()

    @classmethod
    def main(cls):
        args = cls.parse_args()
        # spawn the PED-RPC servlet
        try:
            servlet = VxWorksProcMonitor("0.0.0.0", args.port, args.crashbin, args.version, args.target,
                                         level=args.logging)
            servlet.serve_forever()

        except KeyboardInterrupt:
            print("User interruption.")
            return -1

        except Exception as exc:
            print("Error while starting RPC server: {}".format(exc))
            return -1

        return 0

if __name__ == '__main__':
    sys.exit(VxWorksMonitor.main())

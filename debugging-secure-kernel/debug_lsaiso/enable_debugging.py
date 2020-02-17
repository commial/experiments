import json
import struct

class FixRet(gdb.Breakpoint):
    def stop(self):
        print("[SkpsIsProcessDebuggingEnabled] Exit - Fix RAX")
        gdb.execute("set $rax = 1", to_string=True)
        # `self.delete` results in a gdb crash
        self.disable = True
        return False

class EnterProcessDebug(gdb.Breakpoint):
    def stop(self):
        print("[SkpsIsProcessDebuggingEnabled] Enter")
        rsp = int(gdb.parse_and_eval("$rsp")) & 0xFFFFFFFFFFFFFFFF
        inf = gdb.inferiors()[0]
        ret_addr = struct.unpack("<Q", inf.read_memory(rsp, 8).tobytes())[0]
        bp = FixRet("* %d" % ret_addr)
        bp.silent = True
        return False

class EnableIumDebug(gdb.Command):
    """Enable debugging through SkpsIsProcessDebuggingEnabled"""

    def __init__ (self):
        super(EnableIumDebug, self).__init__("enable_ium_debug", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if not check_addrspace():
            return

        va = FUNCTIONS["SkpsIsProcessDebuggingEnabled"]["va"] + base_va
        dpb = EnterProcessDebug("* %d" % va)
        dpb.silent = True

EnableIumDebug()

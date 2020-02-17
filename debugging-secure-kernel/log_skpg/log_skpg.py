import json
import struct

VA_TO_FUNC = {}

class DebugPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        global VA_TO_FUNC
        rip = int(gdb.parse_and_eval("$rip")) & 0xFFFFFFFFFFFFFFFF
        name = VA_TO_FUNC.get(rip)
        if name is not None:
            print("[%s]" % name)
            return False
        return True

class LogSkpg(gdb.Command):
    """Break on Skpg* functions"""

    def __init__ (self):
        super(LogSkpg, self).__init__("log_skpg", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global VA_TO_FUNC

        if not check_addrspace():
            return

        for func, info in FUNCTIONS.items():
            if not func.startswith("Skpg"):
                continue
            va = info["va"] + base_va
            dpb = DebugPrintingBreakpoint("* %d" % va)
            dpb.silent = True
            VA_TO_FUNC[va] = func

LogSkpg()

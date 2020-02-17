import json
import struct

SKNUMS = None

class SKCALL_print(gdb.Breakpoint):
    def stop(self):
        global SKNUMS
        arg = int(gdb.parse_and_eval("$rcx")) & 0xFFFFFFFFFFFFFFFF
        inf = gdb.inferiors()[0]
        data = inf.read_memory(arg, 6).tobytes()
        part1 = data[0]
        part2 = struct.unpack("<I", data[2:6])[0]

        # Special cases
        if part1 == 1:
            print("[IumInvokeSecureService] PrepareEnclaveCall")
            return False

        # Common cases
        value = part2
        name = SKNUMS.get("%s" % value)
        if name is not None:
            print("[IumInvokeSecureService] %s " % name)
        else:
            print("[IumInvokeSecureService] Unknown: 0x%x (0x%x)" % (value, part1))
        return False


class LogSecureCalls(gdb.Command):
    """Break on IumInvokeSecureService and outs the name of the corresponding Call"""

    def __init__ (self):
        super(LogSecureCalls, self).__init__("log_securecall", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global SKNUMS

        if not arg:
            print("log_securecall /path/to/securecall.json")
            return

        if not check_addrspace():
            return

        SKNUMS = json.load(open(arg))

        bp = SKCALL_print("* %d" % (FUNCTIONS["IumInvokeSecureService"]["va"] + base_va))
        bp.silent = True

LogSecureCalls()

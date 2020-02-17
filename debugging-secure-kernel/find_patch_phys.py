import json
import time

##### TO PATCH #####
JSON_FILE = "/home/user/etudes/lab-windows/secure_kernel/info.json" # From extract_ida.py
SECUREKERNEL_PATH = "/home/user/etudes/lab-windows/secure_kernel/securekernel.exe"
####################
FUNCTIONS = json.load(open(JSON_FILE, "rb"))

# Shared variables
base_va = None
sk_cr3 = None

# Utils
def turn_phys_mode_on():
    gdb.execute("maint packet Qqemu.PhyMemMode:1", to_string=True)

def turn_phys_mode_off():
    gdb.execute("maint packet Qqemu.PhyMemMode:0", to_string=True)

def check_addrspace():
    cur_cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
    if cur_cr3 != sk_cr3:
        print("Please launch this command in the context of the secure kernel")
        print("hint: hbreak *(0x%x)" % (base_va + FUNCTIONS["IumInvokeSecureService"]["va"]))
        return False
    return True


# Commands
class FindPatchIumEP(gdb.Command):
    """Find and patch a Ium secure call entry point in physical memory"""

    RAM_MAX_ADDR = 0xffffffff
    CHUNK = 0x10000

    def __init__ (self):
        super(FindPatchIumEP, self).__init__("find_patch_ium_ep", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        offset = FUNCTIONS["IumInvokeSecureService"]["offset"]
        to_find = open(SECUREKERNEL_PATH, "rb").read()[offset: offset + 200]

        print("Look for 'IumInvokeSecureService' in physical memory...")
        turn_phys_mode_on()
        inf = gdb.inferiors()[0]
        offset = None
        for i in range(0, self.RAM_MAX_ADDR, self.CHUNK):
            if (i % 0x1000000 == 0):
                print(hex(i))
            data = inf.read_memory(i, self.CHUNK).tobytes()
            try:
                offset_invokesk = data.index(to_find) + i
                print("Found at 0x%x!" % offset_invokesk)
                break
            except ValueError:
                continue

        print("Replace with infinite loop...")
        inf.write_memory(offset_invokesk, b"\xeb\xfe")
        turn_phys_mode_off()


class FixIumEP(gdb.Command):
    """Fix the Ium entry-point data, and note the current virtual address"""
    def __init__ (self):
        super(FixIumEP, self).__init__("fix_ium_ep", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global base_va, sk_cr3
        rip = int(gdb.parse_and_eval("$rip")) & 0xFFFFFFFFFFFFFFFF
        inf = gdb.inferiors()[0]
        if inf.read_memory(rip, 2).tobytes() != b"\xeb\xfe":
            print("Please call this function once IumInvokeSecureService loophole has been reached")
            return

        offset = FUNCTIONS["IumInvokeSecureService"]["offset"]
        orig = open(SECUREKERNEL_PATH, "rb").read()[offset: offset + 2]
        inf.write_memory(rip, orig)

        base_va = rip - FUNCTIONS["IumInvokeSecureService"]["va"]
        sk_cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
        print("Base VA: 0x%x" % base_va)

# Register commands
FindPatchIumEP()
FixIumEP()

import struct
import argparse
import sys
#fdesc = open("extracted/out.1076.luac", "rb")
#fdesc = open("extracted/out.635.luac", "rb")
#fdesc = open("extracted/out.222.luac", "rb")
parser = argparse.ArgumentParser("MpLua to lua-51 translator")
parser.add_argument("target", help="Target MpLua compiled script")
parser.add_argument("output", help="Output file")
options = parser.parse_args()

fdesc = open(options.target, "rb")

# Header + some info hardcoded (int size, endianess, etc.)
# MpEngine actually checks that these values are always the same
header = fdesc.read(12)
assert header == b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'


class LuaConst(object):
    "Stand for Lua constants"
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "<%s %s>" % (self.__class__, self.value)

class LuaConstNil(LuaConst):
    pass

class LuaConstByte(LuaConst):
    pass

class LuaConstNumber(LuaConst):
    pass

class LuaConstString(LuaConst):
    pass


class LuaFunc(object):
    "Converter"

    def read_byte(self):
        return struct.unpack("B", self.stream.read(1))[0]

    def read_int(self):
        return struct.unpack("<I", self.stream.read(4))[0]
    
    def __init__(self, stream):
        """
        @stream: I/O like object
        """
        self.stream = stream
        src_name = stream.read(4)
        assert src_name == b"\x00" * 4
        line_def = stream.read(4)
        assert line_def == b"\x00" * 4
        lastline_def = stream.read(4)
        assert lastline_def == b"\x00" * 4

        self.nb_upvalues = self.read_byte()
        self.nb_params = self.read_byte()
        self.is_vararg = self.read_byte()
        self.max_stacksize = self.read_byte()

        self.nb_instr = self.read_int()

        self.instrs = stream.read(4 * self.nb_instr)

        self.nb_const = self.read_int()

        self.consts = []
        i = 0
        for i in range(self.nb_const):
            cst_type = self.read_byte()
            if cst_type == 4:
                # String
                length = self.read_int()
                self.consts.append(LuaConstString(stream.read(length)))
            elif cst_type == 3:
                # Int
                self.consts.append(LuaConstNumber(struct.unpack("<q", stream.read(8))[0]))
            elif cst_type == 1:
                # Byte
                self.consts.append(LuaConstByte(self.read_byte()))
            elif cst_type == 0:
                # NIL
                self.consts.append(LuaConstNil(0))
            else:
                raise RuntimeError("Unimplemented")

        nb_func = self.read_int()

        self.funcs = []
        for i in range(nb_func):
            self.funcs.append(LuaFunc(stream))

        src_line_positions = self.read_int()
        assert src_line_positions == 0
        nb_locals = self.read_int()
        assert nb_locals == 0
        nb_upvalues = self.read_int()
        assert nb_upvalues == 0

    def export(self, root=False):
        """
        Returns the bytes of the newly created Lua precompiled script
        If @root is set, prepend a Lua header
        """
        out = []
        if root:
            out.append(b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x00')
        out.append(b"\x00" * 0x10)
        out.append(struct.pack("BBBB", self.nb_upvalues, self.nb_params, self.is_vararg, self.max_stacksize))
        out.append(struct.pack("<I", self.nb_instr))
        out.append(self.instrs)
        out.append(struct.pack("<I", self.nb_const))
        for cst in self.consts:
            if isinstance(cst, LuaConstNil):
                out.append(struct.pack("B", 0))
            elif isinstance(cst, LuaConstByte):
                out.append(struct.pack("BB", 1, cst.value))
            elif isinstance(cst, LuaConstNumber):
                out.append(struct.pack("<B", 3))
                
                # HACK-ISH
                # Convert int to double for decompiler
                out.append(struct.pack("<d", cst.value))
            else:
                assert isinstance(cst, LuaConstString)
                out.append(struct.pack("<BQ", 4, len(cst.value)))
                out.append(cst.value)

        out.append(struct.pack("<I", len(self.funcs)))
        for func in self.funcs:
            out.append(func.export(root=False))
        
        # No debug info
        out.append(struct.pack("<III", 0, 0, 0))

        return b"".join(out)


func = LuaFunc(fdesc)
export = func.export(root=True)
open(options.output, "wb").write(export)

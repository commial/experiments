import sys
from argparse import ArgumentParser
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core import parse_asm, asmblock

def patch_bytes_at(data_in, offset, patch):
    return data_in[:offset] + patch + data_in[offset + len(patch):]

parser = ArgumentParser("Patch a jump in a binary")
parser.add_argument("mpenginedll", help="Path to the mpengine.dll")
parser.add_argument("jump_offset_in_file", help="Offset of the jump in the file")
parser.add_argument("jump_VA", help="Virtual address of the jump")
parser.add_argument("target_VA", help="Target virtual address for the jump")
args = parser.parse_args()

# Bypass, in UfsHelpers::QueueVfo, the check before
# DcQueryConfigBool(MpDumpUnpackedObjects) to jump directly to DumpUnpackedFile

mpenginedll = options.mpenginedll

offset_base = int(args.jump_VA, 0)
offset_dest = int(args.target_VA, 0)

infile = int(args.jump_offset_in_file, 0)

# Assemble the JMP
loc_db = LocationDB()
mn_x86 = Machine("x86_32").mn
asmcfg = parse_asm.parse_txt(mn_x86, 32, '''
main:
    JMP dest
''', loc_db)

# Set 'main' and 'dest' loc_key's offset
loc_db.set_location_offset(loc_db.get_name_location("main"), offset_base)
loc_db.set_location_offset(loc_db.get_name_location("dest"), offset_dest)

# Spread information and resolve instructions offset
patches = asmblock.asm_resolve_final(mn_x86, asmcfg)
val = patches[offset_base]

data = patch_bytes_at(
    open(mpenginedll, "rb").read(),
    infile,
    val
)

open(mpenginedll, "wb").write(bytes(data))

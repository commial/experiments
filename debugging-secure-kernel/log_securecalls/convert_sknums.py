import json
import sys

SKNUMS = {}
for line in open(sys.argv[1]):
    name, value = line.split(b"=")
    value = int(value.replace(b" ", b"").replace(b"h", b""), 16)
    name = name.replace(b" ", b"")
    SKNUMS[value] = name

json.dump(SKNUMS, sys.argv[2])

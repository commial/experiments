from enum import Enum
import re
from argparse import ArgumentParser

def remove_version(name: str):
    """Remove version-like elements from string
    Yoda 1.2b -> Yoda
    Unpack Me 1.2.h -> Unpack Me
    Box_1.2.e -> Box
    """
    # Ugly and not that fool-proof
    last = name.split("_")[-1].split(" ")[-1]
    if re.match(r"\d+(\.\d+)*[a-z]*", last):
        return name.replace(last, "")
    return name

parser = ArgumentParser()
parser.add_argument("result_file", help="Path to the result file")
args = parser.parse_args()


# File format:
#
# [+] Target: Bleeding Rose Crypter 1.0/UnPackMe_Bleeding Rose Crypter 1.0.exe
# EngineScanCallback(): Scanning input
# EngineScanCallback(): Scanning input->(UPX)
# EngineScanCallback(): Threat VirTool:Win32/Vbinder identified.
# [*] Result:
# input.[00](upx).runp
# [+] Target: Hmimys Packer 1.2/KeyGen.exe
# EngineScanCallback(): Scanning input
# [*] Result:
# [+] Target: MZ0oPE 1.0.6b/UnPackMe_MZ0oPE 1.0.6b.exe
# ...

# Target name -> results
target2result = {}

class State(Enum):
    IN_RESULT = 0
    IN_OUTPUT = 1

state = State.IN_RESULT
target = None
for line in open(args.result_file, "r"):
    if line.startswith("[+] Target: "):
        assert state == State.IN_RESULT
        target = line.split("[+] Target: ")[1].strip()
        target2result[target] = []
        state = State.IN_OUTPUT
        continue
    if line.startswith("[*] Result:"):
        assert target is not None
        assert state is State.IN_OUTPUT
        state = State.IN_RESULT
        continue
    
    if state == State.IN_RESULT:
        assert target is not None
        target2result[target].append(line.strip())


# Family name -> targets
families = {}
for name in target2result:
    orig_name = name
    name = name.split("/")[0]
    if name.endswith(".exe"):
        name = name[:-4]
    family = remove_version(name)
    families.setdefault(family, []).append(orig_name)

for family in families:
    has_results = False
    all_unpacked = True
    for target in families[family]:
        if target2result.get(target):
            has_results = True
        else:
            all_unpacked = False 
    print(f"{family}: {len(families[family])} ({'+' if has_results else '-'}) {'(*)' if all_unpacked else ''}")
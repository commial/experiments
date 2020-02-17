import idaapi
import idc
import idautils
import json

functions = {}
for addr_func in idautils.Functions():
    if idc.hasUserName(idc.GetFlags(addr_func)):
        name = idc.GetFunctionName(addr_func)
        offset = idaapi.get_fileregion_offset(addr_func)
        functions[name] = {"offset": offset, "va": addr_func}

json.dump(functions, open("/tmp/out.json", "wb"))

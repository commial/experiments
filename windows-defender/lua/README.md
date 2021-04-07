# MpLua converter

This naive & hack-ish script converts a Lua precompiled-script from MpEngine VDM database to a version decompilable with [luadec](https://github.com/viruscamp/luadec).

## Usage

```shell
# Extract the target LUA compiled script from the VDM file
...
# Convert it
$ python3 parse.py extracted/out.1.luac /tmp/export.luac
# Decompile it
$ luadec/luadec /tmp/export.luac
cannot find blockend > 537 , pc = 536, f->sizecode = 538
cannot find blockend > 538 , pc = 537, f->sizecode = 538
-- Decompiled using luadec 2.2 rev: 895d923 for Lua 5.1 from https://github.com/viruscamp/luadec
-- Command line: /tmp/export.luac 

processing OP_JMP to } else { 
 at line 2649 in file decompile.c
 for lua files: /tmp/export2.luac
 at lua function 0 pc=509

-- params : ...
-- function num : 0
if not (mp.IsHipsRuleEnabled)("3b576869-a4ec-4529-8536-b80a7769e899") then
  return mp.CLEAN
end
if GetCtxOfficeProc() ~= "productivity" then
  return mp.CLEAN
end
...
```
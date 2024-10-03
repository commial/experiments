# ALPC Monitoring

ALPC is widely used in Windows (Vista and later) for inter-process communication.

By monitoring ALPC, one can gain insights into system activities, including monitoring COM and RPC calls.

To the best of my knowledge, there is currently no comprehensive tool available for effectively monitoring ALPC.

## Existing Resources

- **Unofficial ALPC Structures:** [SystemInformer ntlpcapi.h](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntlpcapi.h)
- **ALPCLogger:** Monitors ALPC using ETW. Unfortunately, it only logs metadata—i.e., who is communicating with whom—not the content or call stack.
    - Code: [ALPCLogger GitHub](https://github.com/zodiacon/ALPCLogger)
    - Blog Post: [Archived](https://web.archive.org/web/20170503073728/https://blogs.microsoft.co.il/pavely/2017/02/12/monitoring-alpc-messages/)
    - Enhanced Version with Process Support: [ProcMonX GitHub](https://github.com/zodiacon/ProcMonX)
- **HITB2014:** An attempt to monitor ALPC: [Slides](https://conference.hitb.org/hitbsecconf2014kul/materials/D2T1%20-%20Ben%20Nagy%20-%20ALPC%20Fuzzing%20Toolkit.pdf)
- **Ideas for Monitoring:** [Archived blog post](https://web.archive.org/web/20220524203931/http://www.zer0mem.sk/?p=542)

## Monitoring PoC

- **[monitor_alpc.js](monitor_alpc.js):** A JavaScript script for WinDBG in kernel debugging mode. This script:
    - Breaks on `NtAlpcSendWaitReceivePort` entry and exit
    - Logs the message and attempts (PoC only) to extract whether it appears to be NDR-encoded data (for RPC calls)
    - Adds context by retrieving the ALPC ports used, the direction, and the processes involved
    - Adds the call stack, where including public symbols helps identify the function names and provides additional context
    - Indents results to highlight recursive calls
    - Skips overly verbose processes, such as `MsMpEng`

This method works well on a single-core VM. The main issue is that it is relatively slow (~x100), as the breakpoint mechanism is time-consuming and triggered multiple times per second. However, it remains usable with some patience in a "start recording, perform the action, stop recording" sequence.

[record_rdp_administrator_to_preparingwindows.log](record_rdp_administrator_to_preparingwindows.log) is an example of such a record. It captures the connection of `Administrator:vagrant` on `VAGRANTVM` (`192.168.58.100`).

Despite the complexities of COM and RPC internals, one can observe interactions between `termsrv` (RDP service), `lsass` (security contexts), `smss` (Windows session handling), and others.

Even the messages displayed on the screen are transmitted through these ALPC calls:
```
...
  |  [SendWait] Start
  |  |  winlogon.exe(5624)
  |  |  PortHandle=394, SendMessage=2995869e780, ReceiveMessage=0
  |  |  Handle: 394 Port: LRPC-b4cb7c7affbc500b2a | winlogon.exe(5624) -> LogonUI.exe(2304)
  |  |  |  CALL req_id:2 method:7
  |  |  |  0000  00 00 00 00 00 00 00 00 01 00 00 00 02 00 00 00  ................
  |  |  |  0010  02 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00  ................
  |  |  |  0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  |  |  |  0030  A0 59 DB 3B 36 D7 44 4D 90 74 C1 EE 00 00 00 03   YÛ;6×DMtÁî....
  |  |  |  0040  2E 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  |  |  |  0050  2E 00 00 00 00 00 00 00 50 00 6C 00 65 00 61 00  ........P.l.e.a.
  |  |  |  0060  73 00 65 00 20 00 77 00 61 00 69 00 74 00 20 00  s.e...w.a.i.t...
  |  |  |  0070  66 00 6F 00 72 00 20 00 74 00 68 00 65 00 20 00  f.o.r...t.h.e...
  |  |  |  0080  57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00  W.i.n.d.o.w.s...
  |  |  |  0090  4D 00 6F 00 64 00 75 00 6C 00 65 00 73 00 20 00  M.o.d.u.l.e.s...
  |  |  |  00a0  49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 65 00  I.n.s.t.a.l.l.e.
  |  |  |  00b0  72 00 00 00 00 00 00 00                          r.......        
  |  |  |   # Child-SP          RetAddr               Call Site
  |  |  |  00 fffff687`e3f7ea88 fffff800`07de6c05     nt!NtAlpcSendWaitReceivePort
  |  |  |  01 fffff687`e3f7ea90 00007fff`220f0b24     nt!KiSystemServiceCopyEnd+0x25
  |  |  |  02 000000fb`0a97ea68 00007fff`1e8ac542     ntdll!NtAlpcSendWaitReceivePort+0x14
  |  |  |  03 000000fb`0a97ea70 00007fff`1e8a9a91     RPCRT4!LRPC_BASE_CCALL::DoSendReceive+0x112
  |  |  |  04 000000fb`0a97eb20 00007fff`1e959169     RPCRT4!LRPC_CCALL::SendReceive+0x51
  |  |  |  05 000000fb`0a97eb70 00007fff`1e957a51     RPCRT4!NdrpClientCall3+0xdf9
  |  |  |  06 000000fb`0a97ef20 00007ff7`1d939ee9     RPCRT4!NdrClientCall3+0xf1
  |  |  |  07 000000fb`0a97f2b0 00007ff7`1d939da5     winlogon!WluiDisplayStatus+0xf9
  |  |  |  08 000000fb`0a97f450 00007ff7`1d93f728     winlogon!WlDisplayStatus+0x2d
  |  |  |  09 000000fb`0a97f490 00007ff7`1d935c8a     winlogon!InternalNotifyExecute+0xa38
  |  |  |  0a 000000fb`0a97f910 00007ff7`1d92387b     winlogon!WLGeneric_NotifyCreateSession_Execute+0x26a
  |  |  |  0b 000000fb`0a97f9b0 00007fff`220bbb10     winlogon!StateMachineWorkerCallback+0x4b
  |  |  |  0c 000000fb`0a97f9e0 00007fff`22066964     ntdll!TppWorkpExecuteCallback+0x130
  |  |  |  0d 000000fb`0a97fa30 00007fff`20eb7974     ntdll!TppWorkerThread+0x644
  |  |  |  0e 000000fb`0a97fd20 00007fff`220aa2f1     KERNEL32!BaseThreadInitThunk+0x14
  |  |  |  0f 000000fb`0a97fd50 00000000`00000000     ntdll!RtlUserThreadStart+0x21
...
```

- **[alpc.d](alpc.d):** A DTrace script demonstrating:
    - The feasibility of monitoring without significantly impacting performance
    - The ability to inspect even unsupported structures with DTrace

This PoC resolves the names of the ports involved and the associated processes.

First, ensure that symbols are available; otherwise, you will encounter a cryptic "syntax error around `)`". Once that’s set up, the DTrace script can be executed:

```powershell
PS C:\Program Files\Dtrace> .\dtrace.exe -s C:\Users\User\Desktop\alpc.d
...
Process dwm.exe, EPROCESS: ffffdc8bf6ae0080, HANDLE: 478
[ALPC Port] [CoreMsgK]-{e8435d59-816a-11ef-8178-b154cf140bd4}
Owner: System (4)
Client: dwm.exe (8)

Process WindowsTermina, EPROCESS: ffffdc8bf5939080, HANDLE: 640
[ALPC Port] [CoreUI]-PID(4256)-TID(4328) 7b456aae-b05a-4d3a-83ae-e33a19d5113d
Owner: ctfmon.exe (4256)
Client: WindowsTermina (976)

Process ctfmon.exe, EPROCESS: ffffdc8bf2a10080, HANDLE: 364
[ALPC Port] [CoreUI]-PID(4256)-TID(4328) 7b456aae-b05a-4d3a-83ae-e33a19d5113d
Owner: ctfmon.exe (4256)
No client

Process dwm.exe, EPROCESS: ffffdc8bf6ae0080, HANDLE: 478
[ALPC Port] [CoreMsgK]-{e8435d59-816a-11ef-8178-b154cf140bd4}
Owner: System (4)
Client: dwm.exe (8)

Process ctfmon.exe, EPROCESS: ffffdc8bf2a10080, HANDLE: 364
[ALPC Port] [CoreUI]-PID(4256)-TID(4328) 7b456aae-b05a-4d3a-83ae-e33a19d5113d
Owner: ctfmon.exe (4256)
No client
...
```

- **TODO: Auto-Wrapping Driver**

Although this solution necessitates the debug mode, one could write a driver that wraps `NtAlpcSendWaitReceivePort` to replicate the functionality of `monitor_alpc.js`. By using an additional userland service, one could obtain the corresponding symbols and thus gain a clearer view of the interactions taking place.

With debug mode enabled, this approach should not trigger PatchGuard. HVCI should also be disabled.
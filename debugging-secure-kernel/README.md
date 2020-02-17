# Intro

PoC gdb debugging the Windows 10 secure kernel, with examples of use:
* Tracing secure calls
* Tracing `Skpg*` calls
* Debugging `LsaIso.exe` (Credential Guard)

At the time of writing, it works on a Win10 1903, Windows Server 2019 and Win10 January 2020 Insider preview (Build 19550).

# Setup

:warning: this PoC has been done on an Ubuntu 19.04. Bugs and working elements
are only relevant at the time of writing.

Requirements:
* QEMU-KVM: version from the package does not include the possibility to read /
  write physical memory (support for `qemu.PhyMemMode` packets). We'll then use the version
  from [the repository](https://github.com/qemu/qemu)
* Win10 image
* A kernel supporting some KVM extensions. The current `5.0.0-38` version
  crashes qemu while booting Win10 with VSM. For the experiments, the
  `4.15.0-1066-oem` is used (available from Ubuntu repository)
* Secure-boot, with OVMF. The Ubuntu version (from repository) does not include variables with preconfigured windows Key. The fedora version can be used (or the one in this repository)

Steps:
1. Get a working version of Win10 on QEMU-KVM
2. Extracts `securekernel.exe` from this installation. One can use qemu-nbd:
```
rmmod nbd
modprobe nbd max_part=16
qemu-nbd -c /dev/nbd0 drive.vdi
mount /dev/nbd0p1 /mnt
cp /mnt/.../System32/securekernel.exe /dest
qemu-nbd -d /dev/nbd0
```
3. Extracts a few interesting addresses from this binary. It can be done manually, or using an IDA script (`extract_ida.py`)
4. Run Win10 with QEMU-KVM, enabling secureboot, KVM. Some englightments can be added, but are not required. One can even disable the hypervisor advertising (`hypervisor=off`). Example of command:
```
qemu/x86_64-softmmu/qemu-system-x86_64 -snapshot -drive file=/path/to/win10.qcow2,format=qcow2,if=none,id=drive-sata0-0-0 -device ide-hd,bus=ide.0,drive=drive-sata0-0-0,id=sata0-0-0,bootindex=1 -cpu host,hv_time,kvm=off,hv_vendor_id=null,hypervisor=off -enable-kvm -m 4096  -global driver=cfi.pflash01,property=secure,value=on -net none -pflash /path/to/OVMF_CODE.secboot.fd -pflash /path/to/OVMF_VARS.secboot.copy.fd -machine pc-q35-3.1,smm=on  -global driver=cfi.pflash01,property=secure,value=on  -device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=pcie.0,multifunction=on,addr=0x2  -device pcie-root-port,port=0x11,chassis=2,id=pci.2,bus=pcie.0,addr=0x2.0x1  -device pcie-root-port,port=0x12,chassis=3,id=pci.3,bus=pcie.0,addr=0x2.0x2  -device pcie-root-port,port=0x13,chassis=4,id=pci.4,bus=pcie.0,addr=0x2.0x3  -device qemu-xhci,p2=15,p3=15,id=usb,bus=pci.2,addr=0x0 -s`
```
The `-s` is used to automatically starts the `gdb stub` on `127.0.0.1:1234`. One can start it at runtime using the qemu console (command `gdbserver`).

5. Once the Win10 correctly starts, ensure Virtual Based Security capabilities are enabled. Depending on the experiments, one can enable Device Guard (through the local console), HVCI (through the "Core memory protection"), ...

Once these steps have been done, one can now attach to the secure kernel.

First, once the VM is running, attach to it with `gdb`, disable gdb pagination and display the current instruction:
```
(gdb) target remote 127.1:1234
(gdb) set pagination off
(gdb) display /i $pc
```

The difficulty is now to retrieve the virtual address of the secure kernel. There are several way to do it:
* Inspect the memory, looking for VMCS structures
* Inspect the memory, looking for the securekernel, then rebuilding back Pagination tables and associated addresses
* Breaking early during the startup, in `hvloader`: the securekernel will report back its address
* Breaking in Hyper-V, looking for VTL transition (hint: handling of hypercalls 0x11 and 0x12)

This PoC is based on a more pragmatic / ulgy way to do it.

First, let's load the `find_patch_phys.py` script in gdb (after patching the
constants inside, like the `securekernel.exe` path):
```
(gdb) source path/to/find_patch_phys.py
```

Now, let's find `securekernel` in the physical memory, patching the
`IumInvokeSecureService` entry point with an infinite loop. This function is
called to perform "secure calls", and is at least called by the normal world
every second to perform "periodic" work.
```
(gdb) find_patch_ium_ep
Look for 'IumInvokeSecureService' in physical memory...
0x0
0x1000000
0x2000000
0x3000000
0x4000000
0x5000000
0x6000000
Found at 0x6c4a0b0!
Replace with infinite loop...
```

Once the memory has been patched, we let the VM continue for a while (a few seconds is enough):
```
(gdb) c
Continuing.
^C
Program received signal SIGINT, Interrupt.
0xfffff80608a130b0 in ?? ()
1: x/i $pc
=> 0xfffff80608a130b0:	jmp    0xfffff80608a130b0
```

We can check we actually ends on an infinite loop. If so, we note the virtual address, and fix the memory:
```
(gdb) fix_ium_ep
Base VA: 0xfffff804c8a00000
```

At this stage, we have the virtual address used by the secure kernel. Then, we
can break on it from anywhere using hardware breakpoints, or use software
breakpoints when we are in the secure kernel context (QEMU gdb stub can support
any of them).

If, while using a script, one need to get back in the context of the secure kernel, the following warning will be printed:
```
(gdb) my_command
Please launch this command in the context of the secure kernel
hint: hbreak *(0xfffff8040d0900b0)
```

One can do:
```
(gdb) hbreak *(0xfffff8040d0900b0)
Hardware assisted breakpoint 14 at 0xfffff8040d0900b0
(gdb) c
Continuing.

Breakpoint 14, 0xfffff8040d0900b0 in ?? ()
1: x/i $pc
=> 0xfffff8040d0900b0:	mov    %rbx,0x18(%rsp)
(gdb) del 14
```

# Examples

## Logging SECURE CALLs

We'll break on `IumInvokeSecureService` and inspect its argument to get the secure call number.
The translation is made thanks to the `_SKSECURESERVICE` enum, available in `ntoskernel.pdb`.

One can extract it with IDA or WinDbg, and convert it to a JSON file thanks to
the `log_securecalls/convert_sknum.py` script.

Then, we can import the script and run it:
```
(gdb) source log_securecalls/log_securecalls.py
(gdb) log_securecall /path/to/sknums.json
Breakpoint 15 at 0xfffff8040d0900b0
(gdb) c
Continuing.
[IumInvokeSecureService] SECURESERVICE_FAST_FLUSH_RANGE_LIST 
[IumInvokeSecureService] SECURESERVICE_FAST_FLUSH_RANGE_LIST 
[IumInvokeSecureService] SECURESERVICE_FAST_FLUSH_RANGE_LIST 
...
```

![IumInvokeSecureService](screen_ium.png?raw=true)

## Logging Hyperguard

Thanks to the support of many breakpoint, we'll break on all `securekernel.exe` functions starting with "Skpg".

To do so:
```
(gdb) source /path/to/log_skpg.py
(gdb) log_skpg
Breakpoint 19 at 0xfffff8040d0a99f8
Breakpoint 20 at 0xfffff8040d0f35d8
Breakpoint 21 at 0xfffff8040d0a6248
Breakpoint 22 at 0xfffff8040d0f3804
Breakpoint 23 at 0xfffff8040d07e1a0
Breakpoint 24 at 0xfffff8040d089518
Breakpoint 25 at 0xfffff8040d08938c
Breakpoint 26 at 0xfffff8040d07e6e4
Breakpoint 27 at 0xfffff8040d0a52f8
...
(gdb) c
Continuing.
[SkpgPeriodicEvent]
[SkpgPeriodicEvent]
[SkpgPeriodicEvent]
[SkpgPeriodicEvent]
```

![Skpg log](screen_skpg.png?raw=true)

## Debugging LsaIso

Ium binaries specifies if their are debuggable or not. When attaching to one of
this process, the secure kernel function `SkpsIsProcessDebuggingEnabled` is
called to retrieve if the debugging is enabled or not.

Here, we simply always return 1.

```
(gdb) source /path/to/enable_debugging.py
(gdb) enable_ium_debug
Breakpoint 1 at 0xfffff80608a7961c
(gdb) c
Continuing.
```

Now, we can attach to `LsaIso` in WinDbg and observes the patch in the gdb output:
```
[SkpsIsProcessDebuggingEnabled] Enter
Breakpoint 2 at 0xfffff80608a133e0
[SkpsIsProcessDebuggingEnabled] Exit - Fix RAX
```

![LsaIso](screen_lsaiso.png?raw=true)

# References

* Hyper-V debugging for beginners, from [@gerhart_x](https://twitter.com/gerhart_x) [Link](http://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html)
* BlackHat 2015: BATTLE OF SKM AND IUM: HOW WINDOWS 10 REWRITES OSARCHITECTURE, from Ionescu [Link](http://www.alex-ionescu.com/blackhat2015.pdf)
* BlackHat 2017: Fractured Backbone: Breaking Modern OS Defenses with Firmware Attacks, from Bulygin and al. [Link](https://www.blackhat.com/docs/us-17/wednesday/us-17-Bulygin-Fractured-Backbone-Breaking-Modern-OS-Defenses-With-Firmware-Attacks.pdf)
* [LiveCloudKd](https://github.com/comaeio/LiveCloudKd)
* [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/fr-fr/virtualization/hyper-v-on-windows/reference/tlfs)

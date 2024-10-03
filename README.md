# Experiments

Repository of various experiments / PoC.

* [debugging-secure-kernel](debugging-secure-kernel/): PoC gdb debugging the Windows 10 secure kernel, on top of QEMU KVM
* [dns](dns/): Experiments regarding DNS / Certificate transparency / Homoglyphs
* [Attack Surface Reduction](windows-defender/ASR): Demystifying Windows Attack Surface Reduction internals
* [VDM](windows-defender/VDM): Windows Defender's VDM Format (signatures database)
* [Primary Group ID](windows/random_things/primaryGroupID): Analysis of security checks made on `primaryGroupID` AD attribute changes
* [Unpacking with Windows Defender](windows-defender/unpacking): Re-using the unpackers built into Windows Defender
* [Firejail no-execve](firejail/no-exec): Illustration of an issue when filtering the `execve` syscall for a target binary
* [ALPC Monitoring](windows/alpc): Attempt to monitor ALPC calls, using WinDBG scripting and Dtrace

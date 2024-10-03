# Sec-comping execve

## Context

`firejail`, `systemd-exec`, and similar programs provide the ability to sandbox executables. This sandboxing includes the setup of `seccomp` filters to limit certain syscalls.

To apply these syscall limitations, these programs must call `seccomp` to install the filters before invoking `execve`. If the executable loader (executed after `execve`) requires syscalls that have been previously denied, the programs will be unable to load the executable.

Some strategies have been proposed to bypass this issue. For example, `firejail` [uses](https://github.com/netblue30/firejail/blob/master/src/firejail/fs_trace.c#L105) [a custom *ld preload library*](https://github.com/netblue30/firejail/blob/master/src/libpostexecseccomp/libpostexecseccomp.c) to install some filters at loading time, delaying their application until after the call to `execve`.

## The Problem

An attentive reader might ask: what if the *ld preload library* is not honored, for instance when a static executable is used?

Well, there is no magic. For instance, `firejail` will happily launch the executable without installing the `seccomp`'s `execve` filter.

By compiling [exec.c](./exec.c) (a `ls` wrapper) as both dynamic and static, one can test this behavior:
```bash
# Compile the executables
$ make exec
$ make exec-static
# Launch the dynamic version, seccomping execve
$ firejail --noprofile --shell=none --seccomp=execve ./exec
Seccomp list in: execve, check list: @default-keep, postlist: execve
Parent pid 6606, child pid 6607
Seccomp list in: execve, check list: @default-keep, postlist: execve
Post-exec seccomp protector enabled
Child process initialized in 10.66 ms
execve: Operation not permitted

Parent is shutting down, bye...
# Launch the static version, where even execve is forgiven, `ls` will be launched
$ firejail --noprofile --shell=none --seccomp=execve ./exec-static 
Seccomp list in: execve, check list: @default-keep, postlist: execve
Parent pid 6617, child pid 6618
Seccomp list in: execve, check list: @default-keep, postlist: execve
Post-exec seccomp protector enabled
Child process initialized in 10.52 ms
bin  boot  core  dev  etc  home  lib  lib32  lib64  lost+found  media  mnt  proc  root  run  sbin  sys  tmp  usr  var  vmlinuz

Parent is shutting down, bye...
```

For more information, this issue is explained in detail on the official repository [^firejail], including a similar problem related to `prctl` and additional issues concerning the use of a custom *ld preload library* (mainly the need to delay filtering of other syscalls, such as `mmap`, `open`, etc., which could be problematic).

## Discussing a Solution

To the best of my knowledge, there are no easy solutions:

- Removing the ability to seccomp `execve` in sandboxing wrappers like `firejail` in some cases, as this could mislead users into thinking that `execve` will be blocked when it is not. This resembles what `systemd-exec` mention in its documentation[^systemd]:
> Note that strict system call filters may impact execution and error handling code paths of the service invocation. Specifically, access to the execve() system call is required for the execution of the service binary — if it is blocked service invocation will necessarily fail

- Adding a possibility to delay the application of `seccomp` filters in the kernel.

This last possibility has been discussed on the kernel list[^kernel], with answers by people far more knowledgeable than I. Also, some workarounds using `ptrace` or `seccomp-fd` have been proposed.

[^firejail]: https://github.com/netblue30/firejail/issues/3685
[^kernel]: https://lore.kernel.org/all/202010281500.855B950FE@keescook/T/
[^systemd]: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
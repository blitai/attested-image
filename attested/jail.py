"""Last step before a job's programs run: give up root for good.

  jail.py <uid> [--root <folder>] <program> [args...]

With --root, first enters <folder> as the new root (the engine's, set up by
jobenv.sh), so that no program of it ever runs with privileges. Then clears
the capability sets, becomes <uid>, forbids regaining privileges and
installs a system call filter, then runs the program. Refuses to continue if
any of it did not take.
"""
import ctypes
import errno
import os
import struct
import sys

PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP = 24, 38, 22
PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 47, 4
SECCOMP_MODE_FILTER = 2
AUDIT_ARCH_X86_64 = 0xc000003e
RET_ALLOW, RET_ERRNO, RET_KILL = 0x7fff0000, 0x00050000, 0x80000000
LD_ABS, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06
NR, ARCH, ARG0 = 0, 4, 16
X32_BIT = 0x40000000
CLONE, CLONE3, SOCKET = 56, 435, 41
# Any flag that would make a new namespace.
CLONE_NEW = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x80
ALLOWED_FAMILIES = (1, 2, 10)   # AF_UNIX, AF_INET, AF_INET6: no vsock, netlink or raw packets
DENIED = (
    101,                          # ptrace
    155, 161, 165, 166,           # pivot_root, chroot, mount, umount2
    163, 167, 168, 169, 170, 171,  # acct, swapon, swapoff, reboot, sethostname, setdomainname
    172, 173, 174, 175, 176, 313,  # iopl, ioperm, create/init/delete/finit_module
    159, 164, 227, 305,           # adjtimex, settimeofday, clock_settime, clock_adjtime
    156, 179, 180, 212,           # _sysctl, quotactl, nfsservctl, lookup_dcookie
    246, 320,                     # kexec_load, kexec_file_load
    248, 249, 250,                # add_key, request_key, keyctl
    272, 308,                     # unshare, setns
    298, 321, 323,                # perf_event_open, bpf, userfaultfd
    303, 304,                     # name_to_handle_at, open_by_handle_at
    310, 311, 438,                # process_vm_readv/writev, pidfd_getfd
    425, 426, 427,                # io_uring
    428, 429, 430, 431, 432, 433, 442,  # the new mount API
)


def _ins(code, k, jt=0, jf=0):
    return struct.pack("HBBI", code, jt, jf, k)


def _deny(e):
    return _ins(RET, RET_ERRNO | e)


def filter_program():
    p = [_ins(LD_ABS, ARCH), _ins(JEQ, AUDIT_ARCH_X86_64, 1, 0), _ins(RET, RET_KILL),
         _ins(LD_ABS, NR), _ins(JGE, X32_BIT, 0, 1), _deny(errno.EPERM)]
    for nr in DENIED:
        p += [_ins(JEQ, nr, 0, 1), _deny(errno.EPERM)]
    # clone3 passes its flags behind a pointer: "not here" sends libc to clone.
    p += [_ins(JEQ, CLONE3, 0, 1), _deny(errno.ENOSYS)]
    p += [_ins(JEQ, CLONE, 0, 4), _ins(LD_ABS, ARG0), _ins(JSET, CLONE_NEW, 0, 1),
          _deny(errno.EPERM), _ins(RET, RET_ALLOW)]
    p += [_ins(JEQ, SOCKET, 0, 6), _ins(LD_ABS, ARG0), _ins(JEQ, ALLOWED_FAMILIES[0], 3, 0),
          _ins(JEQ, ALLOWED_FAMILIES[1], 2, 0), _ins(JEQ, ALLOWED_FAMILIES[2], 1, 0),
          _deny(errno.EAFNOSUPPORT), _ins(RET, RET_ALLOW)]
    p.append(_ins(RET, RET_ALLOW))
    return p


def _capabilities():
    with open("/proc/self/status") as f:
        return {k: int(v, 16) for k, v in (ln.split(":") for ln in f if ln.startswith("Cap"))}


def drop(uid):
    libc = ctypes.CDLL(None, use_errno=True)

    def call(*args):
        if libc.prctl(*[ctypes.c_ulong(a) for a in args]) != 0:
            raise OSError(ctypes.get_errno(), f"prctl {args[0]}")

    for cap in range(64):
        if libc.prctl(ctypes.c_ulong(PR_CAPBSET_DROP), ctypes.c_ulong(cap), 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
            raise OSError(ctypes.get_errno(), "capability bounding set")
    call(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
    header = struct.pack("Ii", 0x20080522, 0)   # _LINUX_CAPABILITY_VERSION_3, this process
    if libc.capset(header, bytes(24)) != 0:
        raise OSError(ctypes.get_errno(), "capset")
    call(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    program = b"".join(filter_program())
    buf = ctypes.create_string_buffer(program)
    fprog = struct.pack("HxxxxxxQ", len(program) // 8, ctypes.addressof(buf))
    fbuf = ctypes.create_string_buffer(fprog)
    if libc.prctl(ctypes.c_ulong(PR_SET_SECCOMP), ctypes.c_ulong(SECCOMP_MODE_FILTER), ctypes.c_void_p(ctypes.addressof(fbuf)), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp")

    caps = _capabilities()
    if os.getuid() != uid or os.geteuid() != uid or any(caps.values()):
        raise RuntimeError("still privileged")


def main():
    uid, args = int(sys.argv[1]), sys.argv[2:]
    if args[:1] == ["--root"]:
        os.chroot(args[1])
        os.chdir("/")
        args = args[2:]
    drop(uid)
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()

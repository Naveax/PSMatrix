from __future__ import annotations

import ctypes
import errno
import math
import os
import platform
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

try:
    import resource as _resource
except ImportError:  # Windows does not provide the POSIX resource module.
    _resource = None


# Linux Landlock constants from linux/landlock.h.
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_LL_EXECUTE = 1 << 0
_LL_WRITE_FILE = 1 << 1
_LL_READ_FILE = 1 << 2
_LL_READ_DIR = 1 << 3
_LL_REMOVE_DIR = 1 << 4
_LL_REMOVE_FILE = 1 << 5
_LL_MAKE_CHAR = 1 << 6
_LL_MAKE_DIR = 1 << 7
_LL_MAKE_REG = 1 << 8
_LL_MAKE_SOCK = 1 << 9
_LL_MAKE_FIFO = 1 << 10
_LL_MAKE_BLOCK = 1 << 11
_LL_MAKE_SYM = 1 << 12
_LL_REFER = 1 << 13
_LL_TRUNCATE = 1 << 14

_READ_RIGHTS = _LL_EXECUTE | _LL_READ_FILE | _LL_READ_DIR
_WRITE_V1_RIGHTS = (
    _LL_WRITE_FILE
    | _LL_REMOVE_DIR
    | _LL_REMOVE_FILE
    | _LL_MAKE_CHAR
    | _LL_MAKE_DIR
    | _LL_MAKE_REG
    | _LL_MAKE_SOCK
    | _LL_MAKE_FIFO
    | _LL_MAKE_BLOCK
    | _LL_MAKE_SYM
)

# prctl/seccomp constants.
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000

_MS_RDONLY = 1
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_NOEXEC = 8
_MS_BIND = 4096
_MS_REC = 16384
_MS_PRIVATE = 1 << 18

# Classic BPF constants.
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


@dataclass(frozen=True)
class SandboxLimits:
    wall_seconds: float = 60.0
    cpu_seconds: int = 60
    max_output_bytes: int = 10 * 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024
    max_workspace_bytes: int = 512 * 1024 * 1024
    max_memory_bytes: int = 1024 * 1024 * 1024
    max_processes: int = 128
    max_open_files: int = 512


@dataclass(frozen=True)
class SandboxCapabilities:
    platform: str
    landlock_abi: int
    seccomp_filter: bool
    privilege_drop: bool
    namespaces: bool
    chroot: bool
    notes: tuple[str, ...] = ()

    @property
    def filesystem_isolation(self) -> bool:
        return self.landlock_abi > 0

    @property
    def network_isolation(self) -> bool:
        return self.seccomp_filter

    @property
    def strong(self) -> bool:
        return (self.filesystem_isolation or self.chroot) and self.network_isolation

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["filesystem_isolation"] = self.filesystem_isolation
        payload["network_isolation"] = self.network_isolation
        payload["strong"] = self.strong
        return payload


@dataclass(frozen=True)
class SandboxPlan:
    backend: str
    workspace: Path
    capabilities: SandboxCapabilities
    limits: SandboxLimits
    network: str
    read_paths: tuple[Path, ...] = ()
    warnings: tuple[str, ...] = ()
    drop_uid: int | None = None
    drop_gid: int | None = None
    rootfs: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "workspace": str(self.workspace),
            "network": self.network,
            "limits": asdict(self.limits),
            "capabilities": self.capabilities.to_dict(),
            "warnings": list(self.warnings),
            "drop_uid": self.drop_uid,
            "drop_gid": self.drop_gid,
            "rootfs": str(self.rootfs) if self.rootfs else None,
        }


class SandboxUnavailable(RuntimeError):
    pass


def _effective_uid() -> int | None:
    getter = getattr(os, "geteuid", None)
    if getter is None:
        return None
    try:
        return int(getter())
    except OSError:
        return None


def _syscall_numbers() -> tuple[int, int, int] | None:
    machine = platform.machine().lower()
    # Landlock syscall numbers are currently aligned for x86_64 and arm64.
    if machine in {"x86_64", "amd64", "aarch64", "arm64"}:
        return (444, 445, 446)
    return None


def _landlock_abi() -> int:
    if platform.system() != "Linux":
        return 0
    numbers = _syscall_numbers()
    if numbers is None:
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        ctypes.c_long(numbers[0]),
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result < 0:
        return 0
    return int(result)


def _seccomp_supported() -> bool:
    if platform.system() != "Linux":
        return False
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
        return False
    try:
        actions = Path("/proc/sys/kernel/seccomp/actions_avail").read_text(
            encoding="utf-8"
        )
    except OSError:
        return False
    return "allow" in actions and "errno" in actions


def _namespace_probe() -> bool:
    # Do not mutate the current process. Presence of user namespaces is useful,
    # but mount/net namespaces may still be denied by the outer container.
    try:
        value = Path("/proc/sys/user/max_user_namespaces").read_text().strip()
        return int(value) > 0
    except (OSError, ValueError):
        return False


def _has_effective_capability(bit: int) -> bool:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("CapEff:"):
                value = int(line.split(":", 1)[1].strip(), 16)
                return bool(value & (1 << bit))
    except (OSError, ValueError):
        return False
    return False


def detect_capabilities() -> SandboxCapabilities:
    notes: list[str] = []
    system = platform.system()
    euid = _effective_uid()
    abi = _landlock_abi()
    seccomp = _seccomp_supported()
    if system != "Linux":
        notes.append("Strong local sandbox is implemented only on Linux")
    if system == "Linux" and abi == 0:
        notes.append("Landlock is unavailable; host filesystem reads/writes cannot be confined")
    if system == "Linux" and not seccomp:
        notes.append("seccomp filter is unavailable; IP networking cannot be blocked")
    chroot = (
        system == "Linux"
        and euid == 0
        and hasattr(os, "chroot")
        and hasattr(os, "unshare")
        and _has_effective_capability(21)  # CAP_SYS_ADMIN is required to bind-mount /proc.
    )
    if system == "Linux" and euid == 0 and not chroot:
        notes.append("chroot backend disabled because a private/bind-mounted /proc cannot be created")
    return SandboxCapabilities(
        platform=system.lower(),
        landlock_abi=abi,
        seccomp_filter=seccomp,
        privilege_drop=(hasattr(os, "setuid") and hasattr(os, "setgid")),
        namespaces=_namespace_probe(),
        chroot=chroot,
        notes=tuple(notes),
    )


def _existing_unique(paths: Iterable[Path]) -> tuple[Path, ...]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return tuple(result)


def default_read_paths(
    workspace: Path,
    executable: Path,
    harness_paths: Iterable[Path],
    env: dict[str, str],
) -> tuple[Path, ...]:
    candidates = [
        workspace,
        executable.parent,
        *(path.parent for path in harness_paths),
        Path("/bin"),
        Path("/sbin"),
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/usr/local"),
        Path("/opt"),
        Path("/etc"),
        Path("/usr/share/zoneinfo"),
        Path("/usr/share/locale"),
        Path("/dev/null"),
        Path("/dev/zero"),
        Path("/dev/random"),
        Path("/dev/urandom"),
        Path("/proc"),
        Path("/sys"),
    ]
    for key in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        value = env.get(key)
        if value:
            candidates.append(Path(value))
    for entry in env.get("PATH", "").split(os.pathsep):
        if entry:
            candidates.append(Path(entry))
    # Dynamic loaders and libc consult these individual files.
    for path in (
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/localtime",
    ):
        candidates.append(Path(path))
    return _existing_unique(candidates)


def build_plan(
    *,
    mode: str,
    workspace: Path,
    executable: Path,
    harness_paths: Iterable[Path],
    env: dict[str, str],
    limits: SandboxLimits,
    network: str = "none",
) -> SandboxPlan:
    capabilities = detect_capabilities()
    if mode not in {"auto", "strict", "copy", "direct"}:
        raise ValueError(f"Unsupported sandbox mode: {mode}")
    if network not in {"none", "host"}:
        raise ValueError(f"Unsupported network policy: {network}")

    if mode in {"copy", "direct"}:
        warning = (
            "Sandbox isolation explicitly disabled; only process timeout and output limits apply"
        )
        return SandboxPlan(
            backend=mode,
            workspace=workspace,
            capabilities=capabilities,
            limits=limits,
            network="host",
            warnings=(warning,),
        )

    has_filesystem_backend = capabilities.filesystem_isolation or capabilities.chroot
    missing: list[str] = []
    if not has_filesystem_backend:
        missing.append("Landlock or chroot filesystem isolation")
    if network == "none" and not capabilities.network_isolation:
        missing.append("seccomp network isolation")
    if missing:
        message = "Required sandbox primitives unavailable: " + ", ".join(missing)
        if mode == "strict":
            raise SandboxUnavailable(message)
        euid = _effective_uid()
        can_drop_privileges = capabilities.platform == "linux" and capabilities.privilege_drop
        fallback_uid = 65534 if can_drop_privileges and euid == 0 else None
        fallback_gid = 65534 if can_drop_privileges and euid == 0 else None
        return SandboxPlan(
            backend="guarded-copy",
            workspace=workspace,
            capabilities=capabilities,
            limits=limits,
            network="host" if not capabilities.network_isolation else network,
            warnings=(
                message,
                "Falling back to guarded process isolation; host filesystem reads are not confined",
            ),
            drop_uid=fallback_uid,
            drop_gid=fallback_gid,
        )

    drop_uid: int | None = None
    drop_gid: int | None = None
    rootfs: Path | None = None
    if capabilities.platform == "linux" and _effective_uid() == 0:
        drop_uid = 65534
        drop_gid = 65534

    backend = (
        "linux-landlock-seccomp"
        if capabilities.filesystem_isolation
        else "linux-chroot-seccomp"
    )
    return SandboxPlan(
        backend=backend,
        workspace=workspace,
        capabilities=capabilities,
        limits=limits,
        network=network,
        read_paths=default_read_paths(workspace, executable, harness_paths, env),
        drop_uid=drop_uid,
        drop_gid=drop_gid,
    )


def prepare_workspace_permissions(plan: SandboxPlan) -> None:
    if plan.drop_uid is None or plan.drop_gid is None:
        return
    for root, dirs, files in os.walk(plan.workspace, followlinks=False):
        root_path = Path(root)
        os.chown(root_path, plan.drop_uid, plan.drop_gid, follow_symlinks=False)
        for name in dirs:
            path = root_path / name
            if not path.is_symlink():
                os.chown(path, plan.drop_uid, plan.drop_gid, follow_symlinks=False)
        for name in files:
            path = root_path / name
            if not path.is_symlink():
                os.chown(path, plan.drop_uid, plan.drop_gid, follow_symlinks=False)


def _prctl(option: int, arg2: int | ctypes.c_void_p) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(option, arg2, 0, 0, 0)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _rights_for_abi(abi: int) -> int:
    rights = _READ_RIGHTS | _WRITE_V1_RIGHTS
    if abi >= 2:
        rights |= _LL_REFER
    if abi >= 3:
        rights |= _LL_TRUNCATE
    return rights


def _path_allowed_rights(path: Path, rights: int, writable: bool) -> int:
    mode = path.stat().st_mode
    if stat.S_ISDIR(mode):
        allowed = _READ_RIGHTS
        if writable:
            allowed |= rights & ~_READ_RIGHTS
        return allowed
    allowed = _LL_READ_FILE
    if mode & 0o111:
        allowed |= _LL_EXECUTE
    if writable:
        allowed |= _LL_WRITE_FILE
        if rights & _LL_TRUNCATE:
            allowed |= _LL_TRUNCATE
    return allowed


def _apply_landlock(plan: SandboxPlan) -> None:
    numbers = _syscall_numbers()
    if numbers is None or plan.capabilities.landlock_abi <= 0:
        raise SandboxUnavailable("Landlock syscall numbers unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    handled = _rights_for_abi(plan.capabilities.landlock_abi)
    attr = _LandlockRulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(
        ctypes.c_long(numbers[0]),
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        ctypes.c_uint(0),
    )
    if ruleset_fd < 0:
        code = ctypes.get_errno()
        raise OSError(code, f"landlock_create_ruleset: {os.strerror(code)}")

    path_fds: list[int] = []
    try:
        entries: list[tuple[Path, bool]] = [(path, False) for path in plan.read_paths]
        entries.append((plan.workspace.resolve(), True))
        # The workspace rule is intentionally last and grants the superset of rights.
        for path, writable in entries:
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue
            path_fds.append(fd)
            allowed = _path_allowed_rights(path, handled, writable)
            rule = _LandlockPathBeneathAttr(
                allowed_access=allowed,
                parent_fd=fd,
                reserved=0,
            )
            result = libc.syscall(
                ctypes.c_long(numbers[1]),
                ctypes.c_int(ruleset_fd),
                ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule),
                ctypes.c_uint(0),
            )
            if result < 0:
                code = ctypes.get_errno()
                raise OSError(code, f"landlock_add_rule({path}): {os.strerror(code)}")

        result = libc.syscall(
            ctypes.c_long(numbers[2]), ctypes.c_int(ruleset_fd), ctypes.c_uint(0)
        )
        if result < 0:
            code = ctypes.get_errno()
            raise OSError(code, f"landlock_restrict_self: {os.strerror(code)}")
    finally:
        for fd in path_fds:
            os.close(fd)
        os.close(ruleset_fd)


def _seccomp_arch_policy() -> tuple[int, int, set[int]]:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        audit_arch = 0xC000003E
        socket_nr = 41
        denied = {
            101,  # ptrace
            109,  # setpgid
            112,  # setsid
            155,  # pivot_root
            161,  # chroot
            165,  # mount
            166,  # umount2
            167, 168, 169,  # swapon, swapoff, reboot
            175, 176,  # init_module, delete_module
            246, 248, 249, 250,  # kexec_load and kernel keyring
            272,  # unshare
            303, 304,  # name/open_by_handle_at
            308,  # setns
            310, 311,  # process_vm_readv/writev
            313,  # finit_module
            321,  # bpf
        }
        return audit_arch, socket_nr, denied
    if machine in {"aarch64", "arm64"}:
        audit_arch = 0xC00000B7
        socket_nr = 198
        denied = {
            39, 40, 41,  # umount2, mount, pivot_root
            51,  # chroot
            97,  # unshare
            104, 105, 106,  # kexec/module operations
            117,  # ptrace
            142,  # reboot
            154, 157,  # setpgid, setsid
            217, 218, 219,  # kernel keyring
            224, 225,  # swapon, swapoff
            264, 265,  # name/open_by_handle_at
            268, 270, 271, 273,  # setns, process_vm, finit_module
            280,  # bpf
        }
        return audit_arch, socket_nr, denied
    raise SandboxUnavailable(f"seccomp policy unsupported on {machine}")


def _apply_seccomp_policy(*, block_ip_network: bool) -> None:
    audit_arch, socket_nr, denied_syscalls = _seccomp_arch_policy()
    specs: list[tuple[int, int, int, int]] = []

    # Reject a foreign syscall ABI; otherwise a 32-bit executable could use
    # syscall numbers not covered by this native-architecture policy.
    specs.append((_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 4))  # seccomp_data.arch
    specs.append((_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, audit_arch))
    specs.append((_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM))
    specs.append((_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 0))  # seccomp_data.nr

    for syscall_nr in sorted(denied_syscalls):
        specs.append((_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 1, syscall_nr))
        specs.append((_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM))

    if block_ip_network:
        # Allow AF_UNIX (1) for local runtime IPC, deny all other socket
        # domains. close_fds=True prevents reuse of inherited IP sockets.
        specs.append((_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 3, socket_nr))
        specs.append((_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 16))  # args[0]
        specs.append((_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, 1))
        specs.append((_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM))

    specs.append((_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW))
    instructions = (_SockFilter * len(specs))(*(_SockFilter(*item) for item in specs))
    program = _SockFprog(len=len(instructions), filter=instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(
        _PR_SET_SECCOMP,
        _SECCOMP_MODE_FILTER,
        ctypes.byref(program),
        0,
        0,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, f"seccomp filter: {os.strerror(code)}")


def _apply_limits(limits: SandboxLimits) -> None:
    if _resource is None:
        return
    cpu = max(1, int(math.ceil(limits.cpu_seconds)))
    _resource.setrlimit(_resource.RLIMIT_CPU, (cpu, cpu + 1))
    _resource.setrlimit(
        _resource.RLIMIT_FSIZE,
        (limits.max_file_bytes, limits.max_file_bytes),
    )
    _resource.setrlimit(
        _resource.RLIMIT_NOFILE,
        (limits.max_open_files, limits.max_open_files),
    )
    if hasattr(_resource, "RLIMIT_NPROC"):
        _resource.setrlimit(
            _resource.RLIMIT_NPROC,
            (limits.max_processes, limits.max_processes),
        )
    _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))


def _mount(
    source: str | None,
    target: str,
    filesystem: str | None,
    flags: int,
    data: str | None = None,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.mount(
        source.encode() if source is not None else None,
        target.encode(),
        filesystem.encode() if filesystem is not None else None,
        ctypes.c_ulong(flags),
        data.encode() if data is not None else None,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, f"mount({target}): {os.strerror(code)}")


def _setup_chroot_namespace(rootfs: Path) -> None:
    if not hasattr(os, "unshare"):
        raise SandboxUnavailable("Python does not expose os.unshare")
    namespace_flags = os.CLONE_NEWNS | os.CLONE_NEWNET | os.CLONE_NEWIPC | os.CLONE_NEWUTS
    os.unshare(namespace_flags)
    _mount(None, "/", None, _MS_REC | _MS_PRIVATE)
    root = str(rootfs)
    # Expose an explicit root mount to PowerShell/.NET drive enumeration and
    # mount a private procfs. Both mounts disappear with the child namespace.
    _mount(root, root, None, _MS_BIND | _MS_REC)
    proc = rootfs / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    _mount("proc", str(proc), "proc", _MS_NOSUID | _MS_NODEV | _MS_NOEXEC)
    os.chroot(rootfs)
    os.chdir("/workspace")


def make_preexec(plan: SandboxPlan) -> Callable[[], None] | None:
    if plan.backend in {"copy", "direct"}:
        return None
    if plan.capabilities.platform != "linux" or _resource is None:
        return None

    def _preexec() -> None:
        if plan.rootfs is not None:
            _setup_chroot_namespace(plan.rootfs)
        _apply_limits(plan.limits)
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
        if plan.backend == "linux-landlock-seccomp":
            _apply_landlock(plan)
        if plan.capabilities.seccomp_filter:
            _apply_seccomp_policy(block_ip_network=(plan.network == "none"))
        if plan.drop_gid is not None and plan.drop_uid is not None:
            try:
                os.setgroups([])
            except OSError:
                pass
            os.setgid(plan.drop_gid)
            os.setuid(plan.drop_uid)

    return _preexec


def _copy_or_link(source: Path | str, destination: Path | str) -> None:
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination, follow_symlinks=False)
    except OSError:
        shutil.copy2(source, destination, follow_symlinks=False)


def _copy_tree_linked(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        symlinks=True,
        copy_function=_copy_or_link,
    )
    for root, dirs, files in os.walk(destination, followlinks=False):
        root_path = Path(root)
        root_path.chmod(root_path.stat().st_mode | 0o755)
        for name in dirs:
            path = root_path / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o755)
        for name in files:
            path = root_path / name
            if not path.is_symlink():
                mode = path.stat().st_mode
                path.chmod(mode | (0o555 if mode & 0o111 else 0o444))


def _ldd_dependencies(binary: Path) -> set[Path]:
    try:
        completed = subprocess.run(
            ["ldd", str(binary)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    dependencies: set[Path] = set()
    for line in completed.stdout.splitlines():
        line = line.strip()
        if "=>" in line:
            candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0]
        elif line.startswith("/"):
            candidate = line.split(" ", 1)[0]
        else:
            continue
        path = Path(candidate)
        if path.is_file():
            dependencies.add(path)
    return dependencies


def _copy_absolute(source: Path, rootfs: Path) -> None:
    absolute = source if source.is_absolute() else source.absolute()
    resolved = absolute.resolve()
    destination = rootfs / str(absolute).lstrip("/")
    _copy_or_link(resolved, destination)


def _copy_runtime_dependencies(runtime_root: Path, rootfs: Path) -> None:
    dependencies: set[Path] = set()
    candidates = [runtime_root / "pwsh"]
    candidates.extend(runtime_root.glob("*.so"))
    for candidate in candidates:
        if candidate.is_file():
            dependencies.update(_ldd_dependencies(candidate))
    # Libraries loaded through dlopen are not always visible in ldd output.
    library_roots = [Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu")]
    dynamic_patterns = (
        "libicu*.so*",
        "libssl.so*",
        "libcrypto.so*",
        "libz.so*",
        "libgssapi_krb5.so*",
        "libkrb5*.so*",
        "libk5crypto.so*",
        "libcom_err.so*",
        "libkeyutils.so*",
        "libresolv.so*",
    )
    for root in library_roots:
        for pattern in dynamic_patterns:
            dependencies.update(path for path in root.glob(pattern) if path.is_file())
    loader = Path("/lib64/ld-linux-x86-64.so.2")
    if loader.exists():
        dependencies.add(loader)
    for dependency in sorted(dependencies):
        _copy_absolute(dependency, rootfs)


def _copy_path_if_exists(source: Path, rootfs: Path) -> None:
    if not source.exists():
        return
    destination = rootfs / str(source).lstrip("/")
    if source.is_dir():
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination, symlinks=True)
    elif source.is_file():
        _copy_or_link(source, destination)


def _create_device(path: Path, mode: int, device: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mknod(path, mode, device)
    except FileExistsError:
        pass
    except PermissionError:
        path.touch(exist_ok=True)
        path.chmod(mode & 0o777)


def materialize_chroot(
    plan: SandboxPlan,
    *,
    executable: Path,
    harness_paths: tuple[Path, ...],
    source_name: str,
) -> tuple[SandboxPlan, Path, str, tuple[str, ...]]:
    if plan.backend != "linux-chroot-seccomp":
        return (
            plan,
            plan.workspace,
            str(executable),
            tuple(str(path) for path in harness_paths),
        )

    staging = plan.workspace
    rootfs = staging / ".psmatrix-internal" / "rootfs"
    project = rootfs / "workspace"
    runtime_destination = rootfs / "opt" / "psmatrix" / "runtime"
    harness_destination = rootfs / "opt" / "psmatrix" / "harness"
    rootfs.mkdir(parents=True, exist_ok=True)
    project.mkdir(parents=True, exist_ok=True)

    for item in staging.iterdir():
        if item.name == ".psmatrix-internal":
            continue
        destination = project / item.name
        if item.is_dir():
            shutil.copytree(item, destination, symlinks=False)
        elif item.is_file() and not item.is_symlink():
            shutil.copy2(item, destination)

    _copy_tree_linked(executable.parent, runtime_destination)
    internal_source = staging / ".psmatrix-internal"
    internal_project = project / ".psmatrix-internal"
    for name in ("modules", "generated-tests", "hooks"):
        source = internal_source / name
        if source.is_dir():
            _copy_tree_linked(source, internal_project / name)
    for name in ("dependency-lock.json",):
        source = internal_source / name
        if source.is_file():
            internal_project.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, internal_project / name)
    harness_destination.mkdir(parents=True, exist_ok=True)
    child_harnesses: list[str] = []
    for harness in harness_paths:
        destination = harness_destination / harness.name
        shutil.copy2(harness, destination)
        destination.chmod(0o644)
        child_harnesses.append(f"/opt/psmatrix/harness/{harness.name}")
    _copy_runtime_dependencies(executable.parent, rootfs)

    for path in (
        Path("/etc/passwd"),
        Path("/etc/group"),
        Path("/etc/nsswitch.conf"),
        Path("/etc/hosts"),
        Path("/etc/resolv.conf"),
        Path("/etc/localtime"),
        Path("/etc/ssl"),
        Path("/usr/share/zoneinfo"),
        Path("/usr/share/locale"),
    ):
        _copy_path_if_exists(path, rootfs)

    _create_device(rootfs / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
    _create_device(rootfs / "dev/zero", stat.S_IFCHR | 0o666, os.makedev(1, 5))
    _create_device(rootfs / "dev/random", stat.S_IFCHR | 0o666, os.makedev(1, 8))
    _create_device(rootfs / "dev/urandom", stat.S_IFCHR | 0o666, os.makedev(1, 9))
    proc_self = rootfs / "proc/self"
    proc_self.mkdir(parents=True, exist_ok=True)
    try:
        (proc_self / "exe").symlink_to("/opt/psmatrix/runtime/pwsh")
    except FileExistsError:
        pass

    updated = SandboxPlan(
        backend=plan.backend,
        workspace=project,
        capabilities=plan.capabilities,
        limits=plan.limits,
        network=plan.network,
        read_paths=(),
        warnings=plan.warnings,
        drop_uid=plan.drop_uid,
        drop_gid=plan.drop_gid,
        rootfs=rootfs,
    )
    prepare_workspace_permissions(updated)
    return (updated, project, "/opt/psmatrix/runtime/pwsh", tuple(child_harnesses))


def stage_execution_assets(
    workspace: Path,
    executable: Path,
    harness_paths: tuple[Path, ...],
) -> tuple[Path, tuple[Path, ...]]:
    """Stage immutable runtime and harness assets inside the run directory."""
    internal = workspace / ".psmatrix-internal"
    runtime = internal / "runtime"
    harness_root = internal / "harness"
    _copy_tree_linked(executable.parent, runtime)
    harness_root.mkdir(parents=True, exist_ok=True)
    staged: list[Path] = []
    for harness in harness_paths:
        destination = harness_root / harness.name
        shutil.copy2(harness, destination)
        destination.chmod(0o644)
        staged.append(destination)
    return runtime / executable.name, tuple(staged)

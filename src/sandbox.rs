use std::path::Path;

pub(crate) fn backend() -> &'static str {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        "Linux Landlock + seccomp"
    }
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        "no supported Linux sandbox backend"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "no native sandbox backend"
    }
}

pub(crate) fn apply(root: &Path) -> Result<(), String> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        linux::apply(root)
    }
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        let _ = root;
        Err("the Linux sandbox supports only x86_64 and AArch64".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err("this platform has no implemented OS sandbox".into())
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::{
        fs::{self, File},
        mem::size_of,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        path::Path,
    };

    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
    const LANDLOCK_ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;
    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const LANDLOCK_REQUIRED_ABI: libc::c_int = 4;

    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_SET_SECCOMP: libc::c_int = 22;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: libc::c_int,
    }

    pub(super) fn apply(requested_root: &Path) -> Result<(), String> {
        reject_unsafe_output_descriptors()?;
        close_inherited_fds()
            .map_err(|error| format!("cannot close inherited file handles: {error}"))?;
        let root = fs::canonicalize(requested_root)
            .map_err(|error| format!("cannot resolve scan root for sandboxing: {error}"))?;
        let root_handle = File::open(&root)
            .map_err(|error| format!("cannot open scan root for sandboxing: {error}"))?;

        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi < 0 {
            return Err(format!(
                "cannot query Landlock support: {}",
                std::io::Error::last_os_error()
            ));
        }
        if abi < LANDLOCK_REQUIRED_ABI as libc::c_long {
            return Err(format!(
                "Landlock ABI {abi} is unavailable or below required ABI {LANDLOCK_REQUIRED_ABI}"
            ));
        }

        let mut handled_access_fs = fs_access_rights(abi as libc::c_int);
        if abi >= 5 {
            handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }
        if abi >= 9 {
            handled_access_fs |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
        }
        let ruleset_attr = RulesetAttr {
            handled_access_fs,
            handled_access_net: LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
            scoped: 0,
        };
        let ruleset = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &ruleset_attr,
                size_of::<RulesetAttr>(),
                0_u32,
            )
        };
        if ruleset < 0 {
            return Err(format!(
                "cannot create Landlock ruleset: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset as libc::c_int) };

        let root_rule = PathBeneathAttr {
            allowed_access: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            parent_fd: root_handle.as_raw_fd(),
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &root_rule,
                0_u32,
            )
        };
        if result < 0 {
            return Err(format!(
                "cannot allow read-only access to scan root in Landlock: {}",
                std::io::Error::last_os_error()
            ));
        }

        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            return Err(format!(
                "cannot set no_new_privs before sandboxing: {}",
                std::io::Error::last_os_error()
            ));
        }
        let result =
            unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0_u32) };
        if result < 0 {
            return Err(format!(
                "cannot enforce Landlock ruleset: {}",
                std::io::Error::last_os_error()
            ));
        }

        install_seccomp().map_err(|error| format!("cannot enforce seccomp filter: {error}"))
    }

    fn reject_unsafe_output_descriptors() -> Result<(), String> {
        let mut rejected = false;
        let mut failure = None;
        for descriptor in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                rejected = true;
                failure.get_or_insert_with(|| format!("cannot inspect output descriptor: {error}"));
                if unsafe { libc::close(descriptor) } < 0 {
                    let close_error = std::io::Error::last_os_error();
                    if close_error.raw_os_error() != Some(libc::EBADF) {
                        failure.get_or_insert_with(|| {
                            format!("cannot close an unverified output descriptor: {close_error}")
                        });
                    }
                }
                continue;
            }
            let metadata = unsafe { metadata.assume_init() };
            let file_type = metadata.st_mode & libc::S_IFMT;
            let unsafe_kind = file_type == libc::S_IFSOCK || file_type == libc::S_IFBLK;
            let writable_file = if file_type == libc::S_IFREG {
                let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
                if flags < 0 {
                    true
                } else {
                    flags & libc::O_ACCMODE != libc::O_RDONLY
                }
            } else {
                false
            };
            if unsafe_kind || writable_file {
                rejected = true;
                if unsafe { libc::close(descriptor) } < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EBADF) {
                        failure.get_or_insert_with(|| {
                            format!("cannot close an unsafe output descriptor: {error}")
                        });
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if rejected {
            return Err(
                "the Linux sandbox cannot preserve writable regular-file, block-device, or socket stdout/stderr; use a pipe or explicitly pass --no-sandbox".into(),
            );
        }
        Ok(())
    }

    fn close_inherited_fds() -> std::io::Result<()> {
        if unsafe { libc::close(libc::STDIN_FILENO) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        }
        if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn fs_access_rights(abi: libc::c_int) -> u64 {
        let mut rights = LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if abi >= 2 {
            rights |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        rights
    }

    fn install_seccomp() -> std::io::Result<()> {
        let mut filter = vec![
            statement(
                libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
                4,
            ),
            jump_equal(audit_arch(), 1, 0),
            statement(
                libc::BPF_RET as u16 | libc::BPF_K as u16,
                SECCOMP_RET_KILL_PROCESS,
            ),
            statement(
                libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
                0,
            ),
        ];

        #[cfg(target_arch = "x86_64")]
        {
            filter.push(libc::sock_filter {
                code: libc::BPF_JMP as u16 | libc::BPF_JSET as u16 | libc::BPF_K as u16,
                jt: 0,
                jf: 1,
                k: 0x4000_0000,
            });
            filter.push(statement(
                libc::BPF_RET as u16 | libc::BPF_K as u16,
                SECCOMP_RET_KILL_PROCESS,
            ));
            filter.push(statement(
                libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
                0,
            ));
        }

        for (syscall, errno) in blocked_syscalls() {
            filter.push(jump_equal(syscall as u32, 0, 1));
            filter.push(statement(
                libc::BPF_RET as u16 | libc::BPF_K as u16,
                SECCOMP_RET_ERRNO | errno as u32,
            ));
        }
        filter.extend(process_clone_filter());
        filter.extend(executable_memory_filter());
        filter.push(statement(
            libc::BPF_RET as u16 | libc::BPF_K as u16,
            SECCOMP_RET_ALLOW,
        ));

        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        if unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &mut program as *mut libc::sock_fprog,
                0,
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn statement(code: u16, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k: value,
        }
    }

    fn jump_equal(value: u32, if_equal: u8, if_not_equal: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: libc::BPF_JMP as u16 | libc::BPF_JEQ as u16 | libc::BPF_K as u16,
            jt: if_equal,
            jf: if_not_equal,
            k: value,
        }
    }

    fn jump_set(value: u32, if_set: u8, if_unset: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: libc::BPF_JMP as u16 | libc::BPF_JSET as u16 | libc::BPF_K as u16,
            jt: if_set,
            jf: if_unset,
            k: value,
        }
    }

    fn process_clone_filter() -> [libc::sock_filter; 5] {
        let thread_flags = (libc::CLONE_VM | libc::CLONE_THREAD) as u32;
        [
            // Let the scanner's worker threads use clone(2), but reject process-like clones.
            jump_equal(libc::SYS_clone as u32, 0, 4),
            statement(
                libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
                16,
            ),
            statement(
                libc::BPF_ALU as u16 | libc::BPF_AND as u16 | libc::BPF_K as u16,
                thread_flags,
            ),
            jump_equal(thread_flags, 1, 0),
            statement(
                libc::BPF_RET as u16 | libc::BPF_K as u16,
                SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ),
        ]
    }

    fn executable_memory_filter() -> Vec<libc::sock_filter> {
        let mut filter = Vec::new();
        for syscall in [libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_pkey_mprotect] {
            filter.push(jump_equal(syscall as u32, 0, 3));
            filter.push(statement(
                libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
                32,
            ));
            filter.push(jump_set(libc::PROT_EXEC as u32, 0, 1));
            filter.push(statement(
                libc::BPF_RET as u16 | libc::BPF_K as u16,
                SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ));
        }
        filter
    }

    #[cfg(target_arch = "x86_64")]
    fn audit_arch() -> u32 {
        0xc000_003e // AUDIT_ARCH_X86_64
    }

    #[cfg(target_arch = "aarch64")]
    fn audit_arch() -> u32 {
        0xc000_00b7 // AUDIT_ARCH_AARCH64
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn audit_arch() -> u32 {
        0
    }

    fn blocked_syscalls() -> Vec<(libc::c_long, libc::c_int)> {
        let mut syscalls = [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_ptrace,
            libc::SYS_shmat,
            libc::SYS_personality,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ]
        .into_iter()
        .map(|syscall| (syscall, libc::EPERM))
        .collect::<Vec<_>>();
        // ENOSYS makes libc fall back to thread-only clone(2), which is filtered below.
        syscalls.push((libc::SYS_clone3, libc::ENOSYS));
        #[cfg(target_arch = "x86_64")]
        syscalls.extend([
            (libc::SYS_fork, libc::EPERM),
            (libc::SYS_vfork, libc::EPERM),
        ]);
        syscalls
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::apply;
    use std::{
        ffi::CString,
        fs::{self, OpenOptions},
        os::fd::AsRawFd,
        os::unix::fs::symlink,
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    const ROOT_ENV: &str = "PREFLIGHTX_SANDBOX_TEST_ROOT";
    const OUTSIDE_ENV: &str = "PREFLIGHTX_SANDBOX_TEST_OUTSIDE";
    const FD_ENV: &str = "PREFLIGHTX_SANDBOX_TEST_FD";
    #[test]
    fn landlock_and_seccomp_confine_a_child_process() {
        if let (Some(root), Some(outside), Some(fd)) = (
            std::env::var_os(ROOT_ENV).map(PathBuf::from),
            std::env::var_os(OUTSIDE_ENV).map(PathBuf::from),
            std::env::var(FD_ENV)
                .ok()
                .and_then(|value| value.parse().ok()),
        ) {
            sandbox_probe(&root, &outside, fd);
            return;
        }

        let base = std::env::temp_dir().join(format!(
            "preflightx-sandbox-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("target");
        let outside = base.join("outside.txt");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("read.txt"), b"synthetic inert fixture").unwrap();
        fs::write(&outside, b"outside sentinel").unwrap();
        symlink(&outside, root.join("outside-link.txt")).unwrap();
        let inherited = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&outside)
            .unwrap();
        let fd_flags = unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFD) };
        assert!(fd_flags >= 0);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    inherited.as_raw_fd(),
                    libc::F_SETFD,
                    fd_flags & !libc::FD_CLOEXEC,
                )
            },
            0
        );

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::tests::landlock_and_seccomp_confine_a_child_process",
                "--nocapture",
            ])
            .env(ROOT_ENV, &root)
            .env(OUTSIDE_ENV, &outside)
            .env(FD_ENV, inherited.as_raw_fd().to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "sandbox probe failed ({:?}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&outside).unwrap(), b"outside sentinel");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        drop(inherited);
        fs::remove_dir_all(base).unwrap();
    }

    fn sandbox_probe(root: &std::path::Path, outside: &std::path::Path, inherited_fd: i32) {
        apply(root).unwrap();
        assert_eq!(
            fs::read(root.join("read.txt")).unwrap(),
            b"synthetic inert fixture"
        );
        assert_eq!(unsafe { libc::fcntl(inherited_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        assert!(fs::read(outside).is_err());
        assert!(fs::read(root.join("outside-link.txt")).is_err());
        assert!(fs::write(root.join("target-write.txt"), b"blocked").is_err());
        assert!(fs::write(outside, b"blocked").is_err());
        assert_eq!(unsafe { libc::prctl(21, 0, 0, 0, 0) }, 2); // PR_GET_SECCOMP
        assert_eq!(unsafe { libc::prctl(39, 0, 0, 0, 0) }, 1); // PR_GET_NO_NEW_PRIVS

        let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert_eq!(socket, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );

        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    memory,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            },
            libc::MAP_FAILED
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(unsafe { libc::munmap(memory, 4096) }, 0);

        assert_eq!(
            unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0_u64) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS)
        );
        assert_eq!(std::thread::spawn(|| 42).join().unwrap(), 42);
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::SIGCHLD,
                    std::ptr::null::<libc::c_void>(),
                    0,
                    0,
                    0,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );

        let nonexistent = CString::new("/preflightx-target-must-not-exist").unwrap();
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_execve,
                    nonexistent.as_ptr(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
}

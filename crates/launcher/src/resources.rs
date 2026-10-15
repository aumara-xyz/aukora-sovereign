// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

pub(crate) fn install_file_size_limit(bytes: u64) -> Result<(), Refusal> {
    let limit = libc::rlimit {
        rlim_cur: bytes as libc::rlim_t,
        rlim_max: bytes as libc::rlim_t,
    };
    // SAFETY: limit is initialized storage for the setrlimit ABI.
    if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) } != 0 {
        return Err(Refusal::io("launcher:rlimits"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn antibody_guest_write_past_fsize_fails_with_efbig() {
        // EFBIG; set both limits in a child so the owner process stays unrestricted.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("launcher-fsize-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        // SAFETY: the child uses only syscalls and exits without inherited Rust destructors.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: SIG_IGN is a valid disposition; EFBIG can then be observed instead of termination.
            unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
            let limit_ok = install_file_size_limit(1024).is_ok();
            let byte = b'x';
            // SAFETY: file is open and byte is readable; this attempts one byte beyond the configured limit.
            let written =
                unsafe { libc::pwrite(file.as_raw_fd(), (&byte as *const u8).cast(), 1, 1024) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            // SAFETY: this child skips inherited destructors after recording its syscall result.
            unsafe {
                libc::_exit(i32::from(
                    !(limit_ok && written == -1 && errno == Some(libc::EFBIG)),
                ))
            };
        }
        let mut status = 0;
        // SAFETY: status is writable and pid is this test's child.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        drop(file);
        std::fs::remove_file(path).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "guest write did not return EFBIG"
        );
    }
}

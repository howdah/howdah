//! Request ids must differ across forked PHP workers. php-fpm (and Apache
//! prefork) start Howdah in a parent process and fork workers from it, so
//! every worker begins with the same request counter and the same hash keys;
//! the lab caught three FPM workers logging the same id. The id therefore
//! mixes in the process id and the clock.
//!
//! One test function: it forks, which must not race other tests' threads.

use howdah_core::log::new_request_id;

#[test]
fn ids_differ_between_parent_and_forked_child() {
    let _warm = new_request_id(); // the counter and keys exist before the fork
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // Child: one id, written raw to the pipe, then exit without
        // running the test harness's teardown.
        let id = new_request_id();
        unsafe {
            libc::write(fds[1], id.as_ptr().cast(), id.len());
            libc::_exit(0);
        }
    }
    let mine = new_request_id();
    unsafe { libc::close(fds[1]) };
    let mut buf = [0u8; 128];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(n > 0, "child wrote no id");
    let child = std::str::from_utf8(&buf[..n as usize]).unwrap();
    assert_ne!(child, mine, "a forked worker repeats the parent's request id");
    assert!(child.len() <= 64 && child.bytes().all(|b| b.is_ascii_hexdigit()));
}

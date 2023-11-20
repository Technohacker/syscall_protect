// SPDX-License-Identifier: GPL-2.0
//! Kernel-level syscall policy enforcer

use kernel::{
    prelude::*,
    procfs::{ProcDirectory, ProcFile},
    task::Task,
};

mod syscall_names;

module! {
    type: SyscallProtect,
    name: "syscall_protect",
    author: "Kevin Kuriakose",
    description: "Kernel-level syscall policy enforcer",
    license: "GPL",
}

struct SyscallProtect {
    _procfs_root: ProcDirectory,

    _start_entry: Pin<Box<ProcFile>>,
}

unsafe impl Send for SyscallProtect {}
unsafe impl Sync for SyscallProtect {}

impl kernel::Module for SyscallProtect {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("syscall_protect starting up...\n");

        let procfs_root = ProcDirectory::new(kernel::c_str!("syscall_protect"), None);
        let start_entry = ProcFile::new(kernel::c_str!("start"), Some(&procfs_root))
            .with_write(Self::start_write);

        Ok(SyscallProtect {
            _procfs_root: procfs_root,

            _start_entry: start_entry,
        })
    }
}

impl SyscallProtect {
    fn start_write(_buf: &[u8]) -> Option<Error> {
        let current: &Task = kernel::current!();

        pr_info!("Enforcement requested for PID: {}", current.pid());
        // Policy file loaded here

        current.register_seccomp_callback((), Self::scg_step);

        None
    }

    fn scg_step(_ctx: &mut (), syscall_num: i32) -> bool {
        syscall_names::print_syscall(syscall_num as u32);

        true
    }
}

impl Drop for SyscallProtect {
    fn drop(&mut self) {
        pr_info!("syscall_protect shutting down...\n");
    }
}

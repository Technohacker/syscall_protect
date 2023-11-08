// SPDX-License-Identifier: GPL-2.0

//! Rust out-of-tree sample

use kernel::{prelude::*, types::Opaque};

module! {
    type: SyscallProtect,
    name: "syscall_protect",
    author: "Kevin Kuriakose",
    description: "Kernel-level syscall policy enforcer",
    license: "GPL",
}

struct SyscallProtect {
    procfs_root: Opaque<*mut kernel::bindings::proc_dir_entry>,
}

unsafe impl Send for SyscallProtect {}
unsafe impl Sync for SyscallProtect {}

impl kernel::Module for SyscallProtect {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("syscall_protect starting up...\n");

        unsafe {
            Ok(SyscallProtect {
                procfs_root: Opaque::new(kernel::bindings::proc_create(
                    kernel::c_str!("syscall_protect").as_char_ptr(),
                    0644,
                    core::ptr::null_mut(),
                    core::ptr::null(),
                ))
            })
        }
    }
}

impl Drop for SyscallProtect {
    fn drop(&mut self) {
        pr_info!("syscall_protect shutting down...\n");
        unsafe {
            kernel::bindings::proc_remove(*self.procfs_root.get());
        }
    }
}
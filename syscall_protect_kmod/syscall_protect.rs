// SPDX-License-Identifier: GPL-2.0
//! Kernel-level syscall policy enforcer

use kernel::{
    prelude::*,
    procfs::{ProcDirectory, ProcFile},
    task::Task,
};

use crate::state_machine::StateMachine;

mod state_machine;
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
    fn bytes_to_usize(buf: &[u8]) -> usize {
        let mut num = [0u8; 8];
        num.copy_from_slice(buf);

        usize::from_le_bytes(num)
    }

    fn start_write(buf: &[u8]) -> Option<Error> {
        let current: &Task = kernel::current!();

        pr_info!("Enforcement requested for PID: {}", current.pid());
        // Policy file loaded here

        let num_states = Self::bytes_to_usize(&buf[0..8]);
        let mut state_machine = StateMachine::new(num_states);

        // 1 usize for the number of states, 3 usizes for the src, edge, dest
        let state_count = (buf.len() - 8) / (8 * 3);

        for i in 0..state_count {
            // first usize + (curr state * 3 * usize)
            let byte_start = 8 + 24 * i;
            let (src, edge, dest) = (
                Self::bytes_to_usize(&buf[(byte_start + 0 * 8)..(byte_start + 1 * 8)]),
                Self::bytes_to_usize(&buf[(byte_start + 1 * 8)..(byte_start + 2 * 8)]),
                Self::bytes_to_usize(&buf[(byte_start + 2 * 8)..(byte_start + 3 * 8)]),
            );

            let res = state_machine.add_edge(src, edge, dest);
            if let Err(error) = res {
                pr_err!("Error adding state machine edge: {error}\n");
                return Some(EINVAL);
            }
        }

        current.register_seccomp_callback(state_machine, Self::scg_step);

        None
    }

    fn scg_step(machine: &mut StateMachine, syscall_num: i32) -> bool {
        let syscall_num = syscall_num as u32;

        syscall_names::print_syscall(syscall_num);
        if machine.is_active() {
            machine.step(syscall_num)
        } else {
            if syscall_num == kernel::bindings::__NR_execve {
                machine.activate();
            }

            true
        }
    }
}

impl Drop for SyscallProtect {
    fn drop(&mut self) {
        pr_info!("syscall_protect shutting down...\n");
    }
}

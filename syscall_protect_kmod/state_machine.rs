use core::result::Result::Ok;

use kernel::prelude::*;

pub(crate) enum EdgeType {
    Wildcard,
    Epsilon,
    Syscall(u32),
}

impl EdgeType {
    pub(crate) fn from_policy_int(n: usize) -> Result<Self, &'static str> {
        const EPSILON: usize = 1 << 32;
        const WILDCARD: usize = 1 << 33;

        let high = n >> 32;
        let low = n & 0b1111_1111_1111_1111;

        if high == 0 {
            Ok(Self::Syscall(low as u32))
        } else if n & EPSILON != 0 {
            Ok(Self::Epsilon)
        } else if n & WILDCARD != 0 {
            Ok(Self::Wildcard)
        } else {
            Err("Invalid bit pattern for edge")
        }
    }
}

pub(crate) struct StateMachine {
    state_machine_active: bool,

    current_wavefront: Vec<usize>,
    states: Vec<Vec<(EdgeType, usize)>>,
}

impl StateMachine {
    pub(crate) fn new(num_states: usize) -> Self {
        let mut states = Vec::try_with_capacity(num_states).expect("OOM?");

        for _ in 0..num_states {
            states.try_push(Vec::new()).expect("OOM?");
        }

        Self {
            state_machine_active: false,
            current_wavefront: Vec::new(),
            states,
        }
    }

    pub(crate) fn add_edge(&mut self, src: usize, edge: usize, dest: usize) -> Result<(), &'static str> {
        if src >= self.states.len() || dest >= self.states.len() {
            return Err("Source or destination exceeded state count");
        }

        self.states[src].try_push((EdgeType::from_policy_int(edge)?, dest)).expect("OOM?");

        Ok(())
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state_machine_active
    }

    pub(crate) fn activate(&mut self) {
        assert!(!self.state_machine_active, "Tried to activate an already active state machine");

        self.current_wavefront = self.wavefront(&[0]);
        self.state_machine_active = true;
    }

    pub(crate) fn step(&mut self, syscall_num: u32) -> bool {
        let mut next_states = Vec::new();

        for current in &self.current_wavefront {
            for (edge, dest) in &self.states[*current] {
                match edge {
                    // Epsilons are dealt with in wavefront()
                    EdgeType::Epsilon => {},
                    // Wildcards accept any syscall
                    EdgeType::Wildcard => {
                        // pr_warn!("Syscall matched a wildcard\n");
                        next_states.try_push(*dest).expect("OOM?");
                    },
                    EdgeType::Syscall(num) => if *num == syscall_num {
                        next_states.try_push(*dest).expect("OOM?");
                    },
                }
            }
        }

        self.current_wavefront = self.wavefront(&next_states);

        // Only allow it if the new wavefront is not empty
        !self.current_wavefront.is_empty()
    }

    fn wavefront(&self, states: &[usize]) -> Vec<usize> {
        let mut covered = Vec::new();

        // Prepare the bitmaps for covering
        for _ in 0..((self.states.len() / 64) + 1) {
            covered.try_push(0u64).expect("OOM?");
        }
        // Mark all starting states as covered

        let mut wavefront = Vec::new();
        let mut in_progress = Vec::new();
        let mut next_front = Vec::new();

        // Start with our initial states
        in_progress.try_extend_from_slice(states).expect("OOM?");

        while !in_progress.is_empty() {
            for state in &in_progress {
                let index = state / 64;
                let bit = state % 64;

                // Check if we've covered this
                if (covered[index] & (1 << bit)) != 0 {
                    // Covered, ignore the node
                } else {
                    // Mark it covered
                    covered[index] |= 1 << bit;

                    // Add all its epsilon neighbours
                    for (edge, dest) in &self.states[*state] {
                        if matches!(edge, EdgeType::Epsilon) {
                            next_front.try_push(*dest).expect("OOM?");
                        }
                    }
                }
            }

            // Extend the final wavefront
            wavefront.try_extend_from_slice(&in_progress).expect("OOM?");
            // Start processing the front we've made
            in_progress = next_front;
            // Prepare a new front
            next_front = Vec::new();
        }

        wavefront
    }
}

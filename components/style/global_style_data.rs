/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Global style data

use crate::context::StyleSystemOptions;
#[cfg(feature = "gecko")]
use crate::gecko_bindings::bindings;
use crate::parallel::STYLE_THREAD_STACK_SIZE_KB;
use crate::shared_lock::SharedRwLock;
use crate::thread_state;
use parking_lot::{RwLock, RwLockReadGuard};
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Global style data
pub struct GlobalStyleData {
    /// Shared RWLock for CSSOM objects
    pub shared_lock: SharedRwLock,

    /// Global style system options determined by env vars.
    pub options: StyleSystemOptions,
}

/// Global thread pool.
pub struct StyleThreadPool {
    /// How many threads parallel styling can use. If not using a thread pool, this is set to `None`.
    pub num_threads: Option<usize>,

    /// The parallel styling thread pool.
    ///
    /// For leak-checking purposes, we want to terminate the thread-pool, which
    /// waits for all the async jobs to complete. Thus the RwLock.
    style_thread_pool: RwLock<Option<rayon::ThreadPool>>,
}

fn thread_name(index: usize) -> String {
    format!("Style#{}", index)
}

// A counter so that we can wait for shutdown of all threads. See
// StyleThreadPool::shutdown.
static ALIVE_WORKER_THREADS: AtomicUsize = AtomicUsize::new(0);

fn thread_startup(_index: usize) {
    ALIVE_WORKER_THREADS.fetch_add(1, Ordering::Relaxed);
    thread_state::initialize_layout_worker_thread();
    #[cfg(feature = "gecko")]
    unsafe {
        use std::ffi::CString;

        bindings::Gecko_SetJemallocThreadLocalArena(true);
        let name = thread_name(_index);
        let name = CString::new(name).unwrap();
        // Gecko_RegisterProfilerThread copies the passed name here.
        bindings::Gecko_RegisterProfilerThread(name.as_ptr());
    }
}

fn thread_shutdown(_: usize) {
    #[cfg(feature = "gecko")]
    unsafe {
        bindings::Gecko_UnregisterProfilerThread();
        bindings::Gecko_SetJemallocThreadLocalArena(false);
    }
    ALIVE_WORKER_THREADS.fetch_sub(1, Ordering::Relaxed);
}

impl StyleThreadPool {
    /// Shuts down the thread pool, waiting for all work to complete.
    pub fn shutdown() {
        if ALIVE_WORKER_THREADS.load(Ordering::Relaxed) == 0 {
            return;
        }
        {
            // Drop the pool.
            let _ = STYLE_THREAD_POOL.style_thread_pool.write().take();
        }
        // Spin until all our threads are done. This will usually be pretty
        // fast, as on shutdown there should be basically no threads left
        // running.
        //
        // This still _technically_ doesn't give us the guarantee of TLS
        // destructors running on the worker threads. For that we'd need help
        // from rayon to properly join the threads.
        //
        // See https://github.com/rayon-rs/rayon/issues/688
        //
        // So we instead intentionally leak TLS stuff (see BLOOM_KEY and co) for
        // now until that's fixed.
        while ALIVE_WORKER_THREADS.load(Ordering::Relaxed) != 0 {
            std::thread::yield_now();
        }
    }

    /// Returns a reference to the thread pool.
    ///
    /// We only really want to give read-only access to the pool, except
    /// for shutdown().
    pub fn pool(&self) -> RwLockReadGuard<Option<rayon::ThreadPool>> {
        self.style_thread_pool.read()
    }
}

lazy_static! {
    /// Global thread pool
    pub static ref STYLE_THREAD_POOL: StyleThreadPool = {
        StyleThreadPool {
            num_threads: None,
            style_thread_pool: RwLock::new(None),
        }
    };

    /// Global style data
    pub static ref GLOBAL_STYLE_DATA: GlobalStyleData = GlobalStyleData {
        shared_lock: SharedRwLock::new_leaked(),
        options: StyleSystemOptions::default(),
    };
}

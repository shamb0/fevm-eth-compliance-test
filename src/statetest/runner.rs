use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indicatif::ProgressBar;
use tracing::{error, info, trace};

use super::executor;
use crate::common::Error;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ExecStatus {
    Ok,
    Ko,
    Skip,
}

pub trait Runner {
    fn update_exe_status(&self, exec_status: ExecStatus, path_tag: String, status: String);
    fn print_summary(&self);
    fn update_elapsed_duration(&self, elapsed_time: Duration);
}

#[derive(Clone)]
struct RunnerStatus {
    ok_list: HashMap<String, Vec<String>>,
    ko_list: HashMap<String, Vec<String>>,
    skip_list: HashMap<String, Vec<String>>,
    elapsed: Duration,
}

#[derive(Clone)]
struct RunnerCore {
    exe_status: Arc<Mutex<RunnerStatus>>,
}

impl RunnerCore {
    pub fn new() -> Self {
        RunnerCore {
            exe_status: Arc::new(Mutex::new(RunnerStatus {
                ok_list: HashMap::new(),
                ko_list: HashMap::new(),
                skip_list: HashMap::new(),
                elapsed: Duration::ZERO,
            })),
        }
    }

    pub fn get_total_elapsed_duration(&self) -> Duration {
        let total_duration = if let Ok(runner_stats) = self.exe_status.lock() {
            runner_stats.elapsed
        } else {
            Duration::ZERO
        };

        total_duration
    }
}

impl Runner for RunnerCore {
    fn update_exe_status(&self, exec_status: ExecStatus, path_tag: String, status: String) {
        if let Ok(mut runner_stats) = self.exe_status.lock() {
            let update_list = match exec_status {
                ExecStatus::Ok => &mut runner_stats.ok_list,
                ExecStatus::Ko => &mut runner_stats.ko_list,
                ExecStatus::Skip => &mut runner_stats.skip_list,
            };

            update_list
                .entry(path_tag)
                .and_modify(|status_list| status_list.push(status.clone()))
                .or_insert_with(|| vec![status]);
        }
    }

    fn update_elapsed_duration(&self, elapsed_time: Duration) {
        if let Ok(mut runner_stats) = self.exe_status.lock() {
            runner_stats.elapsed += elapsed_time;
        }
    }

    fn print_summary(&self) {
        if let Ok(runner_stats) = self.exe_status.lock() {
            println!("=== Start ===");
            println!("=== OK Status ===");
            if runner_stats.ok_list.is_empty() {
                println!("None");
            } else {
                println!("Count :: {:#?}", runner_stats.ok_list.len());
                println!("{:#?}", &runner_stats.ok_list);
            }

            println!("=== KO Status ===");
            if runner_stats.ko_list.is_empty() {
                println!("None");
            } else {
                println!("Count :: {:#?}", runner_stats.ko_list.len());
                println!("{:#?}", &runner_stats.ko_list);
            }

            println!("=== SKIP Status ===");
            if runner_stats.skip_list.is_empty() {
                println!("None");
            } else {
                println!("Count :: {:#?}", runner_stats.skip_list.len());
                println!("{:#?}", &runner_stats.skip_list);
            }
            println!("=== End ===");
        }
    }
}

pub fn run(test_files: Vec<PathBuf>, num_threads: usize) -> Result<(), Error> {
    let endjob = Arc::new(AtomicBool::new(false));
    let console_bar = Arc::new(ProgressBar::new(test_files.len() as u64));
    let mut joins: Vec<std::thread::JoinHandle<Result<(), Error>>> = Vec::new();
    let queue = Arc::new(Mutex::new((0, test_files.clone())));
    let top_runner = RunnerCore::new();

    let num_threads = if num_threads > num_cpus::get() {
        num_cpus::get()
    } else {
        num_threads
    };

    for _ in 0..num_threads {
        let queue = queue.clone();
        let endjob = endjob.clone();
        let console_bar = console_bar.clone();
        let top_runner = top_runner.clone();

        joins.push(
            std::thread::Builder::new()
                .stack_size(50 * 1024 * 1024)
                .spawn(move || loop {
                    let (index, test_path) = {
                        let mut queue = queue.lock().unwrap();
                        if queue.1.len() <= queue.0 {
                            return Ok(());
                        }
                        let test_path = queue.1[queue.0].clone();
                        queue.0 += 1;
                        (queue.0 - 1, test_path)
                    };

                    if endjob.load(Ordering::SeqCst) {
                        return Ok(());
                    }

                    trace!("Calling testfile => {:#?}", test_path);

                    if let Err(err) = executor::execute_test_suit(top_runner.clone(), &test_path) {
                        endjob.store(true, Ordering::SeqCst);
                        error!(
                            "Test Failed => [{:#?}] path:{:#?} err:{:#?}",
                            index, test_path, err
                        );
                        return Err(err);
                    }

                    trace!("TestDone => {:#?}", test_path);
                    console_bar.inc(1);
                })
                .unwrap(),
        );
    }

    for handler in joins {
        handler.join().map_err(|_| Error::SystemFailure)??;
    }

    console_bar.finish();

    info!(
        "Finished Processing of {:#?} Files in Time:{:#?}",
        test_files.len(),
        top_runner.get_total_elapsed_duration(),
    );

    top_runner.print_summary();

    Ok(())
}

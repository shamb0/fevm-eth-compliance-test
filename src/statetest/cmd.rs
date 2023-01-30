use std::env::var;
use std::path::{Path, PathBuf};

use structopt::StructOpt;
use tracing::info;

use super::runner::run;
use crate::common::{system_find_all_json_tests, Error};

#[derive(StructOpt, Debug)]
pub struct Cmd {
    #[structopt(short = "j", long, default_value = "1")]
    num_threads: usize,
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let path =
            var("VECTOR").unwrap_or_else(|_| "test-vectors/tests/GeneralStateTests".to_owned());
        let path = Path::new(path.as_str()).to_path_buf();

        let test_files: Vec<PathBuf> = if path.is_file() {
            vec![path.clone()]
        } else {
            system_find_all_json_tests(path.as_path())
        };

        if test_files.is_empty() {
            info!(
                "Cmd Exiting, no valid test files in the Path :: {:#?}",
                path,
            );
        } else {
            info!(
                "Start running tests on: Path :: {:#?}, Total Files :: {:#?}",
                path,
                test_files.len(),
            );

            run(test_files, self.num_threads)?;
        }

        Ok(())
    }
}

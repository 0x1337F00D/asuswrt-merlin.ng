//! The `-S PROG` hook.
//!
//! On the router `PROG` is `/sbin/ntpd_synced`, a symlink to `rc` whose
//! `ntpd_synced_main()` reacts only to `argc == 2 && argv[1] == "step"`. This
//! test uses a recording shell script instead, so it asserts the exact
//! argument vector and environment without needing the firmware.

use ntp::clock::ScriptAction;
use ntp::script::{run, Environment};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Makes every scratch directory unique even when tests run in parallel.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Recorder {
    directory: PathBuf,
    script: PathBuf,
    output: PathBuf,
}

impl Recorder {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ntp-script-hook-{}-{name}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).expect("scratch directory");
        let script = directory.join("ntpd_synced");
        let output = directory.join("record");
        let mut file = fs::File::create(&script).expect("script");
        // Records argc, every argument and the four exported variables.
        writeln!(
            file,
            "#!/bin/sh\n\
             {{\n\
             echo \"argc=$#\"\n\
             for argument in \"$@\"; do echo \"arg=$argument\"; done\n\
             echo \"stratum=$stratum\"\n\
             echo \"freq_drift_ppm=$freq_drift_ppm\"\n\
             echo \"poll_interval=$poll_interval\"\n\
             echo \"offset=$offset\"\n\
             }} > \"{}\"",
            output.display()
        )
        .expect("write script");
        drop(file);
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        Self {
            directory,
            script,
            output,
        }
    }

    fn wait(&self) -> String {
        // The daemon deliberately does not wait for the hook, so the test does.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(contents) = fs::read_to_string(&self.output) {
                if contents.contains("offset=") {
                    return contents;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the hook never wrote {}", self.output.display());
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn environment() -> Environment {
    Environment {
        stratum: 3,
        freq_drift_ppm: -17,
        poll_interval: 64,
        offset: -1.5,
    }
}

#[test]
fn runs_the_hook_with_exactly_one_argument_and_the_four_variables() {
    let recorder = Recorder::new("step");
    run(&recorder.script, ScriptAction::Step, &environment()).expect("spawns");
    let recorded = recorder.wait();
    // rc's ntpd_synced_main() acts only on argc == 2 with argv[1] == "step".
    assert!(recorded.contains("argc=1\n"), "{recorded}");
    assert!(recorded.contains("arg=step\n"), "{recorded}");
    assert!(recorded.contains("stratum=3\n"), "{recorded}");
    assert!(recorded.contains("freq_drift_ppm=-17\n"), "{recorded}");
    assert!(recorded.contains("poll_interval=64\n"), "{recorded}");
    // busybox exported the offset with "%f", which is six decimals.
    assert!(recorded.contains("offset=-1.500000\n"), "{recorded}");
}

#[test]
fn every_action_word_reaches_the_hook_verbatim() {
    for (action, expected) in [
        (ScriptAction::Step, "step"),
        (ScriptAction::Stratum, "stratum"),
        (ScriptAction::Periodic, "periodic"),
        (ScriptAction::Unsync, "unsync"),
    ] {
        assert_eq!(action.as_str(), expected);
        let recorder = Recorder::new(expected);
        run(&recorder.script, action, &environment()).expect("spawns");
        let recorded = recorder.wait();
        assert!(
            recorded.contains(&format!("arg={expected}\n")),
            "{recorded}"
        );
        assert!(recorded.contains("argc=1\n"), "{recorded}");
    }
}

#[test]
fn a_missing_hook_is_reported_rather_than_ignored() {
    let missing = Path::new("/nonexistent/ntpd_synced");
    assert!(run(missing, ScriptAction::Step, &environment()).is_err());
}

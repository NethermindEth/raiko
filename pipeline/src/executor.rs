use anyhow::bail;
use regex::Regex;
use std::io::BufRead;
use std::path::Path;
use std::{
    io::BufReader,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    panic,
};

#[derive(Debug)]
pub struct Executor {
    pub cmd: Command,
    pub artifacts: Vec<PathBuf>,
    pub test: bool,
}

impl Executor {
    pub fn execute(mut self) -> anyhow::Result<Self> {
        println!("[DEBUG] Starting execute with command: {:?}", self.cmd);
        
        // Spawn the child process with enhanced error handling
        let child = match self
            .cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn() {
                Ok(child) => child,
                Err(e) => {
                    println!("[DEBUG] Failed to spawn child process: {:?}", e);
                    return Err(anyhow::anyhow!("Couldn't spawn child process: {}", e));
                }
            };

        let stdout = match child.stdout.take() {
            Some(stdout) => BufReader::new(stdout),
            None => {
                println!("[DEBUG] Failed to capture stdout");
                return Err(anyhow::anyhow!("Couldn't take stdout of child"));
            }
        };
        
        let stderr = match child.stderr.take() {
            Some(stderr) => BufReader::new(stderr),
            None => {
                println!("[DEBUG] Failed to capture stderr");
                return Err(anyhow::anyhow!("Couldn't take stderr of child"));
            }
        };

        // Use catch_unwind to debug potential panics in the stdout thread
        let stdout_handle = thread::spawn(move || {
            let result = panic::catch_unwind(|| {
                for line in stdout.lines().enumerate().map(|(index, line)| {
                    match line {
                        Ok(l) => l,
                        Err(e) => {
                            println!("[DEBUG] Error reading stdout at line {}: {:?}", index, e);
                            format!("Error reading line: {}", e)
                        }
                    }
                }) {
                    println!("[docker] {line}");
                }
            });
            
            if let Err(e) = result {
                println!("[DEBUG] Panic in stdout thread: {:?}", e);
            }
        });

        // Process stderr with better error handling
        let process_stderr = || -> anyhow::Result<()> {
            for line_result in stderr.lines().enumerate() {
                let (index, line) = line_result;
                let line = match line {
                    Ok(l) => l,
                    Err(e) => {
                        println!("[DEBUG] Error reading stderr at line {}: {:?}", index, e);
                        return Err(anyhow::anyhow!("Couldn't get stderr line {}: {}", index, e));
                    }
                };
                
                println!("[zkvm-stdout] {line}");

                if self.test && line.contains("Executable unittests") {
                    println!("[DEBUG] Found test line: {}", line);
                    if let Some(test) = extract_path(&line) {
                        println!("[DEBUG] Extracted path: {:?}", test);
                        let artifact = self
                            .artifacts
                            .iter_mut()
                            .find(|a| file_name(&test).contains(&file_name(a).replace('-', "_")));
                            
                        match artifact {
                            Some(a) => {
                                println!("[DEBUG] Matched artifact: {:?}", a);
                                *a = test;
                            },
                            None => {
                                println!("[DEBUG] Failed to find test artifact for {:?}", test);
                                return Err(anyhow::anyhow!("Failed to find test artifact"));
                            }
                        }
                    }
                }
            }
            Ok(())
        };

        // Catch any panics in stderr processing
        let stderr_result = panic::catch_unwind(process_stderr);
        if let Err(e) = stderr_result {
            println!("[DEBUG] Panic in stderr processing: {:?}", e);
            return Err(anyhow::anyhow!("Panic while processing stderr"));
        } else if let Ok(Err(e)) = stderr_result {
            println!("[DEBUG] Error in stderr processing: {:?}", e);
            return Err(e);
        }

        // Wait for the stdout thread to complete
        match stdout_handle.join() {
            Ok(_) => println!("[DEBUG] Stdout thread completed successfully"),
            Err(e) => {
                println!("[DEBUG] Error joining stdout thread: {:?}", e);
                return Err(anyhow::anyhow!("Couldn't wait for stdout handle to finish"));
            }
        }

        // Wait for the child process to complete
        let result = match child.wait() {
            Ok(r) => r,
            Err(e) => {
                println!("[DEBUG] Error waiting for child process: {:?}", e);
                return Err(anyhow::anyhow!("Error waiting for child process: {}", e));
            }
        };
        
        if !result.success() {
            println!("[DEBUG] Child process exited with non-zero code: {:?}", result.code());
            // Error message is already printed by cargo
            std::process::exit(result.code().unwrap_or(1))
        }
        
        println!("[DEBUG] Execute completed successfully");
        Ok(self)
    }

    #[cfg(feature = "sp1")]
    pub fn sp1_placement(&self, dest: &str) -> anyhow::Result<()> {
        use sp1_sdk::{CpuProver, HashableKey, Prover};
        use std::fs;

        let root = crate::ROOT_DIR.get().expect("No reference to ROOT_DIR");
        let dest = PathBuf::from(dest);

        if !dest.exists() {
            fs::create_dir_all(&dest).expect("Couldn't create destination directories");
        }

        for src in &self.artifacts {
            let mut name = file_name(src);
            if self.test {
                name = format!(
                    "test-{}",
                    name.split('-').next().expect("Couldn't get test name")
                );
            }

            fs::copy(
                root.join(src.to_str().expect("File name is not valid UTF-8")),
                &dest.join(&name.replace('_', "-")),
            )?;

            println!("Write elf from\n {src:?}\nto\n {dest:?}");
            let elf = std::fs::read(&dest.join(&name.replace('_', "-")))?;
            let prover = CpuProver::new();
            let key_pair = prover.setup(&elf);
            println!("sp1 elf vk bn256 is: {}", key_pair.1.bytes32());
            println!(
                "sp1 elf vk hash_bytes is: {}",
                hex::encode(key_pair.1.hash_bytes())
            );
        }

        Ok(())
    }

    #[cfg(feature = "risc0")]
    pub fn risc0_placement(&self, dest: &str) -> anyhow::Result<()> {
        use crate::risc0_util::GuestListEntry;
        use std::{fs, io::Write};

        let root = crate::ROOT_DIR.get().expect("No reference to ROOT_DIR");
        let dest_dir = PathBuf::from(dest);
        if !dest_dir.exists() {
            fs::create_dir_all(&dest_dir).expect("Couldn't create destination directories");
        }

        for src in &self.artifacts {
            let mut name = file_name(src);

            if self.test {
                name = format!(
                    "test-{}",
                    name.split('-').next().expect("Couldn't get test name")
                );
            }

            let mut dest_file =
                fs::File::create(&dest_dir.join(&format!("{}.rs", name.replace('-', "_"))))
                    .expect("Couldn't create destination file");

            let guest = GuestListEntry::build(
                &name,
                root.join(src).to_str().expect("Path is not valid UTF-8"),
            )
            .expect("Couldn't build the guest list entry");

            dest_file.write_all(
                guest
                    .codegen_consts(
                        &std::fs::canonicalize(&dest_dir)
                            .expect("Couldn't canonicalize the destination path"),
                    )
                    .as_bytes(),
            )?;

            println!("Write from\n {src:?}\nto\n {dest_file:?}");
        }

        Ok(())
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .expect("no filename in path")
        .to_str()
        .expect("filename is non unicode")
        .to_owned()
}

fn extract_path(line: &str) -> Option<PathBuf> {
    let re = Regex::new(r"\(([^)]+)\)").expect("Couldn't create regex");
    re.captures(line)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .map(PathBuf::from)
}

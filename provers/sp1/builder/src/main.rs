use raiko_pipeline::{
    parse_metadata, rerun_if_changed, CommandBuilder, GuestMetadata, Metadata, Pipeline,
};
use std::{env, path::PathBuf};

fn main() {
    let pipeline = Sp1Pipeline::new("provers/sp1/guest", "release");
    pipeline.bins(
        &["sp1-aggregation", "sp1-batch", "sp1-shasta-aggregation"],
        "provers/sp1/guest/elf",
    );
    #[cfg(feature = "test")]
    pipeline.tests(&["sp1-batch"], "provers/sp1/guest/elf");
}

pub struct Sp1Pipeline {
    pub meta: Metadata,
    pub profile: String,
}

impl Pipeline for Sp1Pipeline {
    fn new(root: &str, profile: &str) -> Self {
        raiko_pipeline::ROOT_DIR.get_or_init(|| PathBuf::from(root));
        Sp1Pipeline {
            meta: parse_metadata(root),
            profile: profile.to_string(),
        }
    }

    fn builder(&self) -> CommandBuilder {
        let home_dir = env::var("HOME").expect("HOME environment variable not set");
        let gcc_path = format!("{home_dir}/.risc0/cpp/bin/riscv32-unknown-elf-gcc");
        CommandBuilder::new(&self.meta, "riscv32im-succinct-zkvm-elf", "succinct")
            .rust_flags(&[
                "passes=lower-atomic",
                "link-arg=-Ttext=0x00200800",
                "panic=abort",
            ])
            .rust_cfgs(&["getrandom_backend=\"unsupported\""])
            .cc_compiler("gcc".into())
            .c_flags(&[
                &gcc_path,
                "-march=rv32im",
                "-mstrict-align",
                "-falign-functions=2",
            ])
            .custom_args(&["--ignore-rust-version"])
    }

    fn bins(&self, names: &[&str], dest: &str) {
        rerun_if_changed(&[]);
        let bins = self.meta.get_bins(names);
        let builder = self.builder();
        let executor = builder.build_command(&self.profile, &bins);
        println!(
            "executor: \n   ${:?}\ntargets: \n   {:?}",
            executor.cmd, executor.artifacts
        );
        if executor.artifacts.is_empty() {
            panic!("No artifacts to build");
        }
        executor
            .execute()
            .expect("Execution failed")
            .sp1_placement(dest)
            .expect("Failed to export Sp1 artifacts");
    }

    fn tests(&self, names: &[&str], dest: &str) {
        rerun_if_changed(&[]);
        let tests = self.meta.get_tests(names);
        let builder = self.builder();
        let executor = builder.test_command(&self.profile, &tests);
        println!(
            "executor: \n   ${:?}\ntargets: \n   {:?}",
            executor.cmd, executor.artifacts
        );
        if executor.artifacts.is_empty() {
            panic!("No artifacts to build");
        }
        executor
            .execute()
            .expect("Execution failed")
            .sp1_placement(dest)
            .expect("Failed to export Sp1 artifacts");
    }
}

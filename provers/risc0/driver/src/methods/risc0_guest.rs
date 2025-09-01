pub const RISC0_GUEST_ELF: &[u8] =
    include_bytes!("../../../guest/target/riscv32im-risc0-zkvm-elf/release/risc0-guest.bin");
pub const RISC0_GUEST_ID: [u32; 8] = [
    3700761592, 1686243428, 978362957, 681274911, 951300450, 1516747008, 2700866012, 2784723022,
];

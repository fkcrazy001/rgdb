use nix::sys::personality;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    // 检查当前 personality 是否已经禁用了 ASLR
    let persona = personality::get().expect("Failed to get personality");
    if !persona.contains(personality::Persona::ADDR_NO_RANDOMIZE) {
        println!("ASLR is enabled. Re-executing with ADDR_NO_RANDOMIZE...");

        // 设置禁用 ASLR 的标志
        personality::set(persona | personality::Persona::ADDR_NO_RANDOMIZE)
            .expect("Failed to set personality");

        // 重新执行自身，由于 exec 会保留环境变量和 PID，且新的进程映像将遵循新的 personality
        let err = Command::new(std::env::current_exe().unwrap())
            .args(std::env::args().skip(1))
            .exec();

        panic!("Failed to re-exec: {}", err);
    }

    // 此时 ASLR 已被禁用，地址应该是固定的
    let main_addr = main as *const () as usize;
    println!("Target program started (ASLR disabled).");
    println!("Main function address: 0x{:x}", main_addr);

    let mut counter = 0;
    loop {
        println!(
            "Loop iteration {}, main address: 0x{:x}",
            counter, main_addr
        );
        counter += 1;
        std::thread::sleep(std::time::Duration::from_secs(2));
        if counter > 5 {
            break;
        }
    }
}

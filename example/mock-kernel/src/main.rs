use rcore_lkm::manager::*;
use rcore_lkm::structs::*;
use std::fs::File;
use std::io::Read;

fn main() {
    env_logger::init();

    let x = mock_kernel::add as usize;

    let mut buf = String::new();
    let mut symbol = File::open("symbol").unwrap();
    symbol.read_to_string(&mut buf).unwrap();
    let symbols = parse_kernel_symbols(&buf);

    let mut mm = ModuleManager::new(ProviderImpl);
    mm.add_kernel_symbols(symbols);

    let mut module_buf = Vec::new();
    let mut module = File::open(
        "../kernel-module/target/debug/kernel_module.ko",
    )
    .unwrap();
    module.read_to_end(&mut module_buf).unwrap();

    mm.init_module(&module_buf, "").unwrap();
}

struct ProviderImpl;

impl Provider for ProviderImpl {
    fn map(&mut self, len: usize) -> Result<Box<VSpace>, &'static str> {
        use core::ptr::null_mut;
        use libc::*;
        let ptr = unsafe {
            mmap(
                null_mut(),
                len,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, null_mut());
        println!("mmap at {:#?}", ptr);
        Ok(Box::new(VSpaceImpl(ptr as usize)))
    }
}

struct VSpaceImpl(usize);

impl VSpace for VSpaceImpl {
    fn start(&self) -> usize {
        self.0
    }
    fn add_area(&mut self, _start_addr: usize, _end_addr: usize, _flags: &Flags) {}
}

/// Parse kernel symbols from 'nm kernel.elf' output string
pub fn parse_kernel_symbols<'a>(s: &'a str) -> impl Iterator<Item = ModuleSymbol> + 'a {
    s.lines().filter_map(|l| {
        if l.chars().nth(0).unwrap() == ' ' {
            return None;
        }
        let mut words = l.split_whitespace();
        let address = words.next().unwrap();
        let _stype = words.next().unwrap();
        let name = words.next().unwrap();
        Some(ModuleSymbol {
            name: String::from(name),
            loc: usize::from_str_radix(address, 16).unwrap(),
        })
    })
}

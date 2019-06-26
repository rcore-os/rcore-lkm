use self::ErrorKind::*;
use super::const_reloc as loader;
use super::structs::*;
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::*;
use core::mem::transmute;
use spin::Mutex;
use xmas_elf::sections::SectionData::{self, DynSymbolTable64, Undefined, Dynamic64};
use xmas_elf::symbol_table::{DynEntry64, Entry};
use xmas_elf::dynamic::Dynamic;
use xmas_elf::{header, program::Type, ElfFile};

/// `ModuleManager` is the core part of LKM.
/// It does these jobs:
/// - load preset(API) symbols
/// - manage module loading dependency and linking modules.
pub struct ModuleManager {
    stub_symbols: BTreeMap<String, ModuleSymbol>,
    loaded_modules: Vec<Box<LoadedModule>>,
    provider: Box<Provider>,
}

/// Provider for `ModuleManager`
pub trait Provider: Send {
    fn map(&mut self, len: usize) -> Result<Box<VSpace>, &'static str>;
}

impl ModuleManager {
    pub fn new(provider: impl Provider + 'static) -> Self {
        ModuleManager {
            stub_symbols: BTreeMap::new(),
            loaded_modules: Vec::new(),
            provider: Box::new(provider),
        }
    }

    pub fn add_kernel_symbols(&mut self, symbols: impl Iterator<Item = ModuleSymbol>) {
        for symbol in symbols {
            self.stub_symbols.insert(symbol.name.clone(), symbol);
        }
    }

    pub fn resolve_symbol(&self, symbol: &str) -> Option<usize> {
        self.find_symbol_in_deps(symbol, 0)
    }
    fn find_symbol_in_deps(&self, symbol: &str, this_module: usize) -> Option<usize> {
        if symbol == "THIS_MODULE" {
            return Some(this_module);
        }
        if let Some(sym) = self.stub_symbols.get(symbol) {
            return Some(sym.loc);
        }

        for km in self.loaded_modules.iter().rev() {
            for sym in km.exported_symbols.iter() {
                if (&sym.name) == symbol {
                    return Some(sym.loc);
                }
            }
        }
        debug!("[LKM] symbol not found: {}", symbol);
        None
    }

    fn find_module(&mut self, name: &str) -> Option<&mut Box<LoadedModule>> {
        self.loaded_modules.iter_mut().find(|m| m.info.name == name)
    }

    pub fn init_module(&mut self, module_image: &[u8], _param_values: &str) -> LKMResult<()> {
        let elf =
            ElfFile::new(module_image).map_err(|_| Error::new(Invalid, "failed to read elf"))?;

        // check 64 bit
        let is32 = match elf.header.pt2 {
            header::HeaderPt2::Header32(_) => true,
            header::HeaderPt2::Header64(_) => false,
        };
        if is32 {
            return Err(Error::new(NoExec, "32-bit elf is not supported"));
        }

        // check type
        match elf.header.pt2.type_().as_type() {
            header::Type::SharedObject => {}
            _ => {
                return Err(Error::new(
                    NoExec,
                    "a kernel module must be some shared object",
                ))
            }
        }

        // check and get LKM info
        let minfo = elf.module_info()?;

        info!(
            "[LKM] loading module {} version {} api_version {}",
            minfo.name, minfo.version, minfo.api_version
        );

        // check name
        if self.find_module(&minfo.name).is_some() {
            return Err(Error::new(
                Exist,
                format!(
                    "another instance of module {} (api version {}) has been loaded!",
                    minfo.name, minfo.api_version
                ),
            ));
        }

        // check dependencies
        for dependent in minfo.dependent_modules.iter() {
            let module = self
                .find_module(&dependent.name)
                .ok_or(Error::new(NoExec, "dependent module not found"))?;
            if module.info.api_version != dependent.api_version {
                return Err(Error::new(
                    NoExec,
                    format!(
                        "dependent module {} found but with a different api version {}",
                        module.info.name, module.info.api_version
                    ),
                ));
            }
        }
        // increase reference count of dependent modules
        for dependent in minfo.dependent_modules.iter() {
            let module = self.find_module(&dependent.name).unwrap();
            module.used_counts += 1;
        }

        let map_len = elf.map_len();
        // We first map a huge piece. This requires the kernel model to be dense and not abusing vaddr.
        let mut vspace = self
            .provider
            .map(map_len)
            .map_err(|_| Error::new(NoMem, "valloc failed"))?;
        let base = vspace.start();

        //loaded_minfo.mem_start=base as usize;
        //loaded_minfo.mem_size=(map_len/PAGE_SIZE) as usize;
        //if map_len%PAGE_SIZE>0{
        //    loaded_minfo.mem_size+=1;
        //}
        for ph in elf.program_iter() {
            if ph
                .get_type()
                .map_err(|_| Error::new(NoExec, "program header error"))?
                == Type::Load
            {
                let prog_start_addr = base + (ph.virtual_addr() as usize);
                let prog_end_addr = prog_start_addr + (ph.mem_size() as usize);
                let offset = ph.offset() as usize;
                let flags = ph.flags();
                vspace.add_area(prog_start_addr, prog_end_addr, &flags);
                //self.vallocator.map_pages(prog_start_addr, prog_end_addr, &attr);
                //No need to flush TLB.
                let target = unsafe {
                    ::core::slice::from_raw_parts_mut(
                        prog_start_addr as *mut u8,
                        ph.mem_size() as usize,
                    )
                };
                let file_size = ph.file_size() as usize;
                if file_size > 0 {
                    target[..file_size].copy_from_slice(&elf.input[offset..offset + file_size]);
                }
                target[file_size..].iter_mut().for_each(|x| *x = 0);
            }
        }

        let mut loaded_minfo = Box::new(LoadedModule {
            info: minfo,
            exported_symbols: Vec::new(),
            used_counts: 0,
            using_counts: Arc::new(ModuleRef {}),
            vspace,
            lock: Mutex::new(()),
            state: ModuleState::Ready,
        });
        info!(
            "[LKM] module load done at {}, now need to do the relocation job.",
            base
        );

        info!("[LKM] relocating three sections");
        let this_module = &(*loaded_minfo) as *const _ as usize;
        elf.relocate_symbols(
            base,
            |name| self.find_symbol_in_deps(name, this_module),
            |addr, value| unsafe {
                (addr as *mut usize).write(value);
            },
        )?;
        info!("[LKM] relocation done. adding module to manager and call init_module");
        let mut lkm_entry: usize = 0;
        for exported in loaded_minfo.info.exported_symbols.iter() {
            for sym in elf.dynsym()? {
                let name = sym
                    .get_name(&elf)
                    .map_err(|_| Error::new(NoExec, "load symbol name error"))?;
                if exported == name {
                    let exported_symbol = ModuleSymbol {
                        name: exported.clone(),
                        loc: base + (sym.value() as usize),
                    };

                    if exported == "init_module" {
                        lkm_entry = base + (sym.value() as usize);
                    } else {
                        loaded_minfo.exported_symbols.push(exported_symbol);
                    }
                }
            }
        }
        // Now everything is done, and the entry can be safely plugged into the vector.
        self.loaded_modules.push(loaded_minfo);
        if lkm_entry == 0 {
            return Err(Error::new(
                NoExec,
                "this module does not have init_module()",
            ));
        }

        // get init & fini address
        let mut init = None;
        let mut fini = None;
        for entry in elf.dynamic()? {
            use xmas_elf::dynamic::Tag::*;
            match entry.get_tag()? {
                Init => init = Some(entry.get_ptr()? as usize),
                Fini => fini = Some(entry.get_ptr()? as usize),
                _ => {}
            }
        }
        debug!("[LKM] init = {:x?}, fini = {:x?}", init, fini);

        unsafe {
            // if let Some(init) = init {
            //     let init_fn: unsafe extern "C" fn() = transmute(base + init);
            //     debug!("[LKM] calling init at {:?}", init_fn);
            //     init_fn();
            // }
            let init_module: unsafe extern "C" fn() = transmute(lkm_entry);
            debug!("[LKM] calling init_module at {:?}", init_module);
            k();
            init_module();
            #[inline(never)]
            #[no_mangle]
            fn k() {}
        }
        Ok(())
    }

    pub fn delete_module(&mut self, name: &str, _flags: u32) -> LKMResult<()> {
        info!("[LKM] now you can plug out a kernel module!");
        let module = self
            .find_module(name)
            .ok_or(Error::new(NoEnt, "module not found"))?;

        let mod_lock = module.lock.lock();
        if module.used_counts > 0 {
            return Err(Error::new(Again, "some module depends on this module"));
        }
        if Arc::strong_count(&module.using_counts) > 0 {
            return Err(Error::new(Again, "there are references to the module"));
        }
        let mut cleanup_func: usize = 0;
        for entry in module.exported_symbols.iter() {
            if (&(entry.name)) == "cleanup_module" {
                cleanup_func = entry.loc;
                break;
            }
        }
        if cleanup_func > 0 {
            unsafe {
                module.state = ModuleState::Unloading;
                let cleanup_module: unsafe extern "C" fn() = transmute(cleanup_func);
                cleanup_module();
            }
        } else {
            return Err(Error::new(Busy, "you cannot plug this module out"));
        }
        drop(mod_lock);

        // remove module
        self.loaded_modules.retain(|m| m.info.name != name);
        info!("[LKM] Remove module {:?} done!", name);
        Ok(())
    }
}

/// Helper functions for ELF
trait ElfExt {
    /// Calculate length of LOAD sections to map
    fn map_len(&self) -> usize;

    /// Get dynamic symbol entries from '.dynsym' section
    fn dynsym(&self) -> LKMResult<&[DynEntry64]>;

    /// Get dynamic entries from '.dynamic' section
    fn dynamic(&self) -> LKMResult<&[Dynamic<u64>]>;

    /// Parse LKM info from '.rcore-lkm' section
    fn module_info(&self) -> LKMResult<ModuleInfo>;

    /// Relocate all symbols.
    fn relocate_symbols(
        &self,
        base: usize,
        query_symbol_location: impl Fn(&str) -> Option<usize>,
        write_ptr: impl Fn(usize, usize),
    ) -> LKMResult<()>;
}

impl ElfExt for ElfFile<'_> {
    fn map_len(&self) -> usize {
        let mut max_addr: usize = 0;
        let mut min_addr: usize = ::core::usize::MAX;
        let mut off_start: usize = 0;
        for ph in self.program_iter() {
            if ph.get_type().unwrap() == Type::Load {
                if (ph.virtual_addr() as usize) < min_addr {
                    min_addr = ph.virtual_addr() as usize;
                    off_start = ph.offset() as usize;
                }
                if (ph.virtual_addr() + ph.mem_size()) as usize > max_addr {
                    max_addr = (ph.virtual_addr() + ph.mem_size()) as usize;
                }
            }
        }
        fn page_align_down(addr: usize) -> usize {
            addr / PAGE_SIZE * PAGE_SIZE
        }
        fn page_align_up(addr: usize) -> usize {
            (addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
        }
        max_addr = page_align_up(max_addr);
        min_addr = page_align_down(min_addr);
        off_start = page_align_down(off_start);
        max_addr - min_addr + off_start
    }

    fn dynsym(&self) -> LKMResult<&[DynEntry64]> {
        match self
            .find_section_by_name(".dynsym")
            .ok_or(".dynsym not found")?
            .get_data(self)
            .map_err(|_| "corrupted .dynsym")?
        {
            DynSymbolTable64(dsym) => Ok(dsym),
            _ => Err(Error::from("bad .dynsym")),
        }
    }

    fn dynamic(&self) -> LKMResult<&[Dynamic<u64>]> {
        match self
            .find_section_by_name(".dynamic")
            .ok_or(".dynamic not found")?
            .get_data(self)
            .map_err(|_| "corrupted .dynamic")?
        {
            Dynamic64(e) => Ok(e),
            _ => Err(Error::from("bad .dynamic")),
        }
    }

    fn module_info(&self) -> LKMResult<ModuleInfo> {
        let info_content = match self
            .find_section_by_name(".rcore-lkm")
            .ok_or("rcore-lkm metadata not found")?
            .get_data(self)
            .map_err(|_| "load rcore-lkm error")?
        {
            Undefined(c) => core::str::from_utf8(c).map_err(|_| "info content is not utf8")?,
            _ => return Err(Error::from("metadata section type wrong")),
        };
        let minfo = ModuleInfo::parse(info_content).ok_or("parse info error")?;
        Ok(minfo)
    }

    fn relocate_symbols(
        &self,
        base: usize,
        query_symbol_location: impl Fn(&str) -> Option<usize>,
        write_ptr: impl Fn(usize, usize),
    ) -> LKMResult<()> {
        let dynsym = self.dynsym()?;

        // define a closure to relocate one symbol
        let relocate_symbol =
            |sti: usize, offset: usize, addend: usize, itype: usize| -> LKMResult<()> {
                if sti == 0 {
                    return Ok(());
                }
                let dynsym = &dynsym[sti];
                let sym_val = if dynsym.shndx() == 0 {
                    let name = dynsym.get_name(self)?;
                    query_symbol_location(name).ok_or(format!("symbol not found: {}", name))?
                } else {
                    base + dynsym.value() as usize
                };
                match itype as usize {
                    loader::REL_NONE => {}
                    loader::REL_OFFSET32 => return Err(Error::from("REL_OFFSET32 detected")),
                    loader::REL_SYMBOLIC | loader::REL_GOT | loader::REL_PLT => {
                        write_ptr(base + offset, sym_val + addend);
                    }
                    loader::REL_RELATIVE => {
                        write_ptr(base + offset, base + addend);
                    }
                    _ => {
                        return Err(Error::from(format!(
                            "unsupported relocation type: {}",
                            itype
                        )))
                    }
                }
                Ok(())
            };

        // for each REL & RELA section ...
        for section in self.section_iter() {
            match section.get_data(self)? {
                SectionData::Rela64(rela_items) => {
                    debug!("[LKM] relocating section: {:?}", section);
                    for item in rela_items.iter() {
                        relocate_symbol(
                            item.get_symbol_table_index() as usize,
                            item.get_offset() as usize,
                            item.get_addend() as usize,
                            item.get_type() as usize,
                        )?;
                    }
                }
                SectionData::Rel64(rel_items) => {
                    debug!("[LKM] relocating section: {:?}", section);
                    for item in rel_items.iter() {
                        relocate_symbol(
                            item.get_symbol_table_index() as usize,
                            item.get_offset() as usize,
                            0,
                            item.get_type() as usize,
                        )?;
                    }
                }
                _ => continue,
            }
        }
        Ok(())
    }
}

const PAGE_SIZE: usize = 1 << 12;

// error handling

pub type LKMResult<T> = Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub reason: String,
}

#[derive(Debug)]
pub enum ErrorKind {
    NoEnt = 2,
    NoExec = 8,
    Again = 11,
    NoMem = 12,
    Busy = 16,
    Exist = 17,
    Invalid = 22,
}

impl Error {
    fn new(kind: ErrorKind, reason: impl Into<String>) -> Self {
        Error {
            kind,
            reason: reason.into(),
        }
    }
}

impl<S: Into<String>> From<S> for Error {
    fn from(reason: S) -> Self {
        Error::new(NoExec, reason)
    }
}

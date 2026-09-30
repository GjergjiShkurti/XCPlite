//--------------------------------------------------------------------------------------------------------------------------------------------------
// Module dwarf
// Read ELF files and extract debug information
// Taken from Github repository a2ltool by DanielT

use indexmap::IndexMap;
use std::ffi::OsStr;
use std::ops::Index;
use std::{collections::HashMap, fs::File};

type SliceType<'a> = EndianSlice<'a, RunTimeEndian>;

use object::read::ObjectSection;
use object::{Endianness, Object};

use gimli::{Abbreviations, DebuggingInformationEntry, Dwarf, UnitHeader};
use gimli::{EndianSlice, RunTimeEndian};

use crate::elf_reader::debuginfo::cfa::{CfaInfo, get_cfa_from_object};
use crate::elf_reader::debuginfo::{DbgDataType, DebugData, TypeInfo, VarInfo};

mod attributes;
use attributes::{get_abstract_origin_attribute, get_attr_value, get_location_attribute, get_name_attribute, get_specification_attribute, get_typeref_attribute};

mod typereader;

pub(crate) struct UnitList<'a> {
    list: Vec<(UnitHeader<SliceType<'a>>, gimli::Abbreviations)>,
}

struct DebugDataReader<'elffile> {
    dwarf: Dwarf<EndianSlice<'elffile, RunTimeEndian>>,
    verbose: usize,
    units: UnitList<'elffile>,
    unit_names: Vec<Option<String>>,
    endian: Endianness,
    sections: HashMap<String, (u64, u64)>,
    cfa_info: Vec<CfaInfo>,
    epk_string: Option<String>,
    epk_addr: u64,
    xcp_meta_data: Option<(u64, Vec<u8>)>, // (section_base_addr, raw_bytes)
    mci_meta_data: Option<Vec<u8>>,        // raw bytes of the mci_meta section (mc-instrument calibration metadata)
    mci_app_name: Option<String>,          // the application's own name, from the mci_app section
    mci_meas_data: Option<(u64, Vec<u8>)>, // (section_base_addr, raw_bytes) of mci_meas (mc-instrument measurement descriptors)
    mci_layout_data: Option<Vec<u8>>,      // raw bytes of mci_layout: how to parse an mci_meas record on this ABI
    rodata_data: Option<(u64, Vec<u8>)>,   // (section_base_addr, raw_bytes) of .rodata, used to resolve string pointers held in mci_meas
    is_little_endian: bool,
}

// load the debug info from an elf file
pub(crate) fn load_elf_dwarf(filename: &OsStr, verbose: usize, unit_idx_limit: usize) -> Result<DebugData, String> {
    log::debug!("load_elf_dwarf: {}", filename.to_string_lossy());

    // open the file and mmap its content
    let filedata = load_filedata(filename)?;

    // load the elf file using the object crate
    let elffile = load_elf_file(&filename.to_string_lossy(), &filedata, verbose)?;

    // verify that the elf file contains DWARF debug info
    if !elffile.sections().any(|section| section.name() == Ok(".debug_info")) {
        log::error!("DWARF .debug_info section not found");
        return Err(format!(
            "Error: {} does not contain DWARF2+ debug info. The section .debug_info is missing.",
            filename.to_string_lossy()
        ));
    }

    // load the DWARF sections from the elf file
    let dwarf = load_dwarf_sections(&elffile)?;

    // verify that the dwarf data is valid
    if !verify_dwarf_compile_units(&dwarf) {
        return Err(format!(
            "Error: {} does not contain DWARF2+ debug info - zero compile units contain debug info.",
            filename.to_string_lossy()
        ));
    }

    // get the elf sections for DebugDataReader
    let sections = get_elf_sections(&elffile);

    // read the EPK string and address from the xcp_epk ELF section
    let epk_section = elffile.section_by_name("xcp_epk");
    let epk_addr: u64 = epk_section.as_ref().map_or(0, |s| s.address());
    let epk_string: Option<String> = epk_section
        .and_then(|s| s.data().ok())
        .and_then(|data| std::ffi::CStr::from_bytes_until_nul(data).ok())
        .map(|cs| cs.to_string_lossy().into_owned());
    if let Some(ref epk) = epk_string {
        log::info!("EPK string read from xcp_epk section: '{}' at address 0x{:08X}", epk, epk_addr);
    }

    // read the xcp_meta section raw bytes for metadata (XCP_UNIT / XCP_LIMITS annotations)
    let xcp_meta_section = elffile.section_by_name("xcp_meta");
    let xcp_meta_data: Option<(u64, Vec<u8>)> = xcp_meta_section.and_then(|s| {
        let addr = s.address();
        s.data().ok().map(|data| (addr, data.to_vec()))
    });
    if let Some((addr, ref data)) = xcp_meta_data {
        log::info!("XCP metadata section (xcp_meta) found at address 0x{:08X}, {} bytes", addr, data.len());
    } else {
        log::debug!("XCP metadata section (xcp_meta) not found in ELF file");
    }
    // read the mci_meta section raw bytes: mc-instrument's calibration field metadata, a packed
    // array of self-describing records rather than named objects, so no address lookup is needed
    let mci_meta_data: Option<Vec<u8>> = elffile.section_by_name("mci_meta").and_then(|s| s.data().ok()).map(|data| data.to_vec());
    if let Some(ref data) = mci_meta_data {
        log::info!("mc-instrument calibration metadata section (mci_meta) found, {} bytes", data.len());
    } else {
        log::debug!("mc-instrument calibration metadata section (mci_meta) not found in ELF file");
    }
    // read the mci_app section: the application's own name, as characters. The runtime A2L route
    // takes it from the same Cfg the server is started with; without this the offline route had
    // nothing to call the project but a placeholder.
    let mci_app_name: Option<String> = elffile
        .section_by_name("mci_app")
        .and_then(|s| s.data().ok())
        .map(|data| String::from_utf8_lossy(data).trim_end_matches('\0').trim().to_string())
        .filter(|name| !name.is_empty());
    if let Some(ref name) = mci_app_name {
        log::info!("mc-instrument application name section (mci_app) found: '{}'", name);
    } else {
        log::debug!("mc-instrument application name section (mci_app) not found in ELF file");
    }
    // read the mci_meas section: mc-instrument's measurement descriptors (a packed array of
    // MeasMeta records). Keep the section base address; the records hold absolute pointers into
    // .rodata for their name/comment/unit strings (and, from layout version 2, their event name),
    // so the reader needs .rodata too to resolve them.
    let mci_meas_data: Option<(u64, Vec<u8>)> = elffile.section_by_name("mci_meas").and_then(|s| {
        let addr = s.address();
        s.data().ok().map(|data| (addr, data.to_vec()))
    });
    if let Some((addr, ref data)) = mci_meas_data {
        log::info!("mc-instrument measurement descriptor section (mci_meas) found at address 0x{:08X}, {} bytes", addr, data.len());
    } else {
        log::debug!("mc-instrument measurement descriptor section (mci_meas) not found in ELF file");
    }
    // read the mci_layout section: a single MeasLayout record (mc_meas_abi.hpp) telling this reader the
    // record stride and every field offset for THIS binary's ABI. MeasMeta holds pointers, so its
    // layout moves with the word size -- and not only by the pointer width, since `double` aligns
    // to 4 on i386 and to 8 on ARM32. Absent (older binaries) means the historical LP64 layout.
    let mci_layout_data: Option<Vec<u8>> = elffile.section_by_name("mci_layout").and_then(|s| s.data().ok()).map(|d| d.to_vec());
    if let Some(ref data) = mci_layout_data {
        log::info!("mc-instrument layout section (mci_layout) found, {} bytes", data.len());
    } else {
        log::debug!("mc-instrument layout section (mci_layout) not found; assuming the historical 64-bit MeasMeta layout");
    }
    // .rodata backs the string literals the mci_meas descriptors point at; captured here so those
    // name/comment/unit/event pointers can be dereferenced offline without applying relocations
    let rodata_data: Option<(u64, Vec<u8>)> = elffile.section_by_name(".rodata").and_then(|s| {
        let addr = s.address();
        s.data().ok().map(|data| (addr, data.to_vec()))
    });

    let is_little_endian = elffile.endianness() == Endianness::Little;

    // get CFA information for DebugDataReader
    let mut cfa_info = Vec::new();
    let res = get_cfa_from_object(&elffile, &mut cfa_info, verbose, unit_idx_limit);
    match res {
        Ok(cfa) => {
            if cfa > 0 {
                log::info!("CFA data found in {cfa} functions");
            } else {
                log::warn!("CFA data not found");
            }
        }
        Err(err) => {
            log::error!("CFA parser error: {err}");
        }
    }

    // create the debug data reader
    log::debug!("Creating debug data reader");
    let dbg_reader = DebugDataReader {
        dwarf,
        verbose,
        units: UnitList::new(),
        unit_names: Vec::new(),
        endian: elffile.endianness(),
        sections,
        cfa_info,
        epk_string,
        epk_addr,
        xcp_meta_data,
        mci_meta_data,
        mci_app_name,
        mci_meas_data,
        mci_layout_data,
        rodata_data,
        is_little_endian,
    };
    log::debug!("Reading debug info entries");
    Ok(dbg_reader.read_debug_info_entries(unit_idx_limit))
}

// open a file and mmap its content
fn load_filedata(filename: &OsStr) -> Result<memmap2::Mmap, String> {
    let file = match File::open(filename) {
        Ok(file) => file,
        Err(error) => {
            return Err(format!("Error: could not open file {}: {error}", filename.to_string_lossy()));
        }
    };

    match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => Ok(mmap),
        Err(err) => Err(format!("Error: Failed to map file '{}': {err}", filename.to_string_lossy())),
    }
}

// read the headers and sections of an elf/object file
fn load_elf_file<'data>(filename: &str, filedata: &'data [u8], verbose: usize) -> Result<object::read::File<'data>, String> {
    log::debug!("load_elf_file: {}", filename);
    match object::File::parse(filedata) {
        Ok(object_file) => {
            if verbose >= 1 {
                println!("\nParsed object file file: {}", filename);
                println!("ELF file format: {:?}", object_file.format());
                println!("Architecture: {:?}", object_file.architecture());
                println!("Endianness: {:?}", object_file.endianness());
                println!("\nSections:");
                for section in object_file.sections() {
                    let kind = section.kind();
                    println!(
                        "  Name: {:<20} Addr: 0x{:08x} Size: {} bytes Kind: {:?} ",
                        section.name().unwrap_or("<unknown>"),
                        section.address(),
                        section.size(),
                        kind
                    );
                }
                println!("\n");
            }

            Ok(object_file)
        }
        Err(err) => Err(format!("Error: Failed to parse file '{filename}': {err}")),
    }
}

fn get_elf_sections(elffile: &object::read::File) -> HashMap<String, (u64, u64)> {
    log::debug!("get_elf_sections: Creating ELF sections map for debug data (only size!=0 and addr!=0)");
    let mut map = HashMap::new();
    for section in elffile.sections() {
        let addr = section.address();
        let size = section.size();
        if addr != 0
            && size != 0
            && let Ok(name) = section.name()
        {
            map.insert(name.to_string(), (addr, addr + size));
            log::trace!("elf section: {} addr={addr:x}, size={size:x}", name);
        }
    }

    map
}

// load the DWARF debug info from the .debug_<xyz> sections
fn load_dwarf_sections<'data>(elffile: &object::read::File<'data>) -> Result<gimli::Dwarf<SliceType<'data>>, String> {
    log::debug!("load_dwarf_sections");
    // Dwarf::load takes two closures / functions and uses them to load all the required debug sections
    let loader = |section: gimli::SectionId| get_file_section_reader(elffile, section.name());
    gimli::Dwarf::load(loader)
}

// verify that the dwarf data is valid
fn verify_dwarf_compile_units(dwarf: &gimli::Dwarf<SliceType>) -> bool {
    let mut units_iter = dwarf.debug_info.units();
    let mut units_count = 0;
    while let Ok(Some(_)) = units_iter.next() {
        units_count += 1;
    }

    log::info!("DWARF compile units: {}", units_count);
    units_count > 0
}

// get a section from the elf file.
// returns a slice referencing the section data if it exists, or an empty slice otherwise
fn get_file_section_reader<'data>(elffile: &object::read::File<'data>, section_name: &str) -> Result<SliceType<'data>, String> {
    if let Some(dbginfo) = elffile.section_by_name(section_name) {
        match dbginfo.data() {
            Ok(val) => Ok(EndianSlice::new(val, get_endian(elffile))),
            Err(e) => Err(e.to_string()),
        }
    } else {
        Ok(EndianSlice::new(&[], get_endian(elffile)))
    }
}

// get the endianity of the elf file
fn get_endian(elffile: &object::read::File) -> RunTimeEndian {
    if elffile.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big }
}

impl DebugDataReader<'_> {
    // read the debug information entries in the DWARF data to get all the global variables and their types
    fn read_debug_info_entries(mut self, unit_idx_limit: usize) -> DebugData {
        let variables = self.load_variables(unit_idx_limit);
        let (types, typenames) = self.load_types(&variables);
        let varname_list: Vec<&String> = variables.keys().collect();
        let demangled_names = demangle_cpp_varnames(&varname_list);
        let mut unit_names = Vec::new();
        std::mem::swap(&mut unit_names, &mut self.unit_names);
        DebugData {
            variables,
            types,
            typenames,
            demangled_names,
            unit_names,
            sections: self.sections,
            cfa_info: self.cfa_info,
            epk_string: self.epk_string,
            epk_addr: self.epk_addr,
            xcp_meta_data: self.xcp_meta_data,
            mci_meta_data: self.mci_meta_data,
            mci_app_name: self.mci_app_name,
            mci_meas_data: self.mci_meas_data,
            mci_layout_data: self.mci_layout_data,
            rodata_data: self.rodata_data,
            is_little_endian: self.is_little_endian,
        }
    }

    // load all variables from the dwarf data
    fn load_variables(&mut self, unit_idx_limit: usize) -> IndexMap<String, Vec<VarInfo>> {
        let mut variables = IndexMap::<String, Vec<VarInfo>>::new();

        let mut iter = self.dwarf.debug_info.units();
        while let Ok(Some(unit)) = iter.next() {
            // get the abbreviations for the unit
            let Ok(abbreviations) = unit.abbreviations(&self.dwarf.debug_abbrev) else {
                if self.verbose > 0 {
                    let offset = unit.offset().as_debug_info_offset().unwrap_or(gimli::DebugInfoOffset(0)).0;
                    log::warn!("Error: Failed to get abbreviations for unit @{offset:x}");
                }
                continue;
            };

            // store the unit for later reference
            self.units.add(unit, abbreviations);
            let unit_idx = self.units.list.len() - 1;
            if unit_idx > unit_idx_limit {
                break;
            }
            let (unit, abbreviations) = &self.units[unit_idx];

            // The root of the tree inside of a unit is always a DW_TAG_compile_unit or DW_TAG_partial_unit.
            // The global variables are among the immediate children of the unit; static variables
            // in functions are declared inside of DW_TAG_subprogram[/DW_TAG_lexical_block]*.
            // We can easily find all of them by using depth-first traversal of the tree
            let mut entries_cursor = unit.entries(abbreviations);
            if let Ok(Some((_, entry))) = entries_cursor.next_dfs()
                && (entry.tag() == gimli::constants::DW_TAG_compile_unit || entry.tag() == gimli::constants::DW_TAG_partial_unit)
            {
                // @@@@ warn if unit name is missing
                let unit_name = match get_name_attribute(entry, &self.dwarf, unit) {
                    Ok(name) => {
                        log::trace!("unit name: {}", &name);
                        Some(name)
                    }
                    Err(e) => {
                        log::warn!("Failed to get unit name: {}", e);
                        None
                    }
                };
                self.unit_names.push(unit_name);
            }

            // traverse all entries in depth-first order
            let mut depth = 0;
            let mut context: Vec<(gimli::DwTag, Option<String>)> = Vec::new();
            // Where each variable DIE of this unit ended up, so that a later definition DIE can
            // find the declaration it completes. Unit-relative offsets, so it is per unit.
            let mut declared: HashMap<gimli::UnitOffset, (String, usize)> = HashMap::new();
            // Definitions whose declaration had not been read when they were (issue 42): the
            // declaration's offset, the name and where the definition was put. gcc writes the
            // declaration first, which the merge below relies on, but DWARF does not require that
            // order; these are merged once the whole unit is read.
            let mut forward: Vec<(gimli::UnitOffset, String, usize)> = Vec::new();
            while let Ok(Some((depth_delta, entry))) = entries_cursor.next_dfs() {
                depth += depth_delta;
                debug_assert!(depth >= 1);
                context.truncate((depth - 1) as usize);
                let tag = entry.tag();
                // It's essential to only get those names that might actually be needed.
                // Getting all names unconditionally doubled the runtime of the program
                // as a result of countless useless string allocations and deallocations.
                if tag == gimli::constants::DW_TAG_namespace || tag == gimli::constants::DW_TAG_subprogram {
                    context.push((tag, get_name_attribute(entry, &self.dwarf, unit).ok()));
                } else {
                    context.push((tag, None));
                }
                debug_assert_eq!(depth as usize, context.len());

                if entry.tag() == gimli::constants::DW_TAG_variable {
                    // A definition DIE carrying DW_AT_specification is the *same* variable as the
                    // declaration it points at, not a second one. gcc splits a variable declared
                    // inside a namespace exactly that way: the declaration sits in the
                    // DW_TAG_namespace chain and carries the namespaces, the definition sits at
                    // compilation-unit level and carries the address. Pushing both reports one
                    // variable twice -- once with its namespaces and no address, once with an
                    // address and no namespaces -- and callers that expect one entry per name
                    // (register_segments, and the segment ordering that follows it) see two.
                    let specification = match get_attr_value(entry, gimli::constants::DW_AT_specification) {
                        Some(gimli::AttributeValue::UnitRef(offset)) => Some(offset),
                        _ => None,
                    };
                    let entry_offset = entry.offset();
                    // Get variable information
                    match self.get_variable(entry, unit, abbreviations) {
                        Ok((name, typeref, address)) => {
                            let merged = match specification.and_then(|offset| declared.get(&offset)) {
                                Some((declared_name, index)) => variables
                                    .get_mut(declared_name.as_str())
                                    .and_then(|infos| infos.get_mut(*index))
                                    .map(|info| {
                                        // Take what the declaration could not carry, and keep what
                                        // only it knows: the namespaces it was written in.
                                        if info.address.1 == 0 {
                                            info.address = address;
                                        }
                                    })
                                    .is_some(),
                                None => false,
                            };
                            if !merged {
                                let (function, namespaces) = get_varinfo_from_context(&context);
                                let infos = variables.entry(name.clone()).or_default();
                                if let Some(offset) = specification {
                                    forward.push((offset, name.clone(), infos.len()));
                                }
                                declared.insert(entry_offset, (name, infos.len()));
                                infos.push(VarInfo {
                                    address, // may be 0 for local variables
                                    typeref,
                                    unit_idx,
                                    function,
                                    namespaces,
                                });
                            }
                        }
                        Err(errmsg) => {
                            if self.verbose > 0 {
                                let offset = entry.offset().to_debug_info_offset(unit).unwrap_or(gimli::DebugInfoOffset(0)).0;
                                log::warn!("Error loading variable @{offset:x}: {errmsg}");
                            }
                        }
                    }
                }
            }

            // The second pass: each forward definition gives its address to the declaration it
            // completes, which keeps the namespaces only it knows, and is then removed -- after all
            // of them are merged, so that the positions `declared` recorded stay valid until then.
            let mut absorbed: HashMap<String, Vec<usize>> = HashMap::new();
            for (offset, name, index) in forward {
                let Some((declared_name, declared_index)) = declared.get(&offset) else {
                    continue;
                };
                if *declared_name != name || *declared_index == index {
                    continue;
                }
                let Some(infos) = variables.get_mut(name.as_str()) else {
                    continue;
                };
                let address = infos[index].address;
                if infos[*declared_index].address.1 == 0 {
                    infos[*declared_index].address = address;
                }
                absorbed.entry(name).or_default().push(index);
            }
            for (name, mut indices) in absorbed {
                indices.sort_unstable();
                if let Some(infos) = variables.get_mut(name.as_str()) {
                    for index in indices.into_iter().rev() {
                        infos.remove(index);
                    }
                }
            }
        }

        variables
    }

    // Return global variable information
    // an entry of the type DW_TAG_variable only describes a global variable if there is a name, a type and an address
    // this function tries to get all three and returns them
    // returns None if the entry does not describe a global variable
    /*
        fn get_global_variable(
            &self,
            entry: &DebuggingInformationEntry<SliceType, usize>,
            unit: &UnitHeader<SliceType>,
            abbrev: &gimli::Abbreviations,
        ) -> Result<Option<(String, usize, u64)>, String> {
            match get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1) {
                Some((addr_ext, addr)) => {
                    // if debugging information entry A has a DW_AT_specification or DW_AT_abstract_origin attribute
                    // pointing to another debugging information entry B, any attributes of B are considered to be part of A.
                    if let Some(specification_entry) = get_specification_attribute(entry, unit, abbrev) {
                        // the entry refers to a specification, which contains the name and type reference
                        let name = get_name_attribute(&specification_entry, &self.dwarf, unit)?;
                        let typeref = get_typeref_attribute(&specification_entry, unit)?;
                        Ok(Some((name, typeref, addr)))
                    } else if let Some(abstract_origin_entry) = get_abstract_origin_attribute(entry, unit, abbrev) {
                        // the entry refers to an abstract origin, which should also be considered when getting the name and type ref
                        let name = get_name_attribute(entry, &self.dwarf, unit).or_else(|_| get_name_attribute(&abstract_origin_entry, &self.dwarf, unit))?;
                        let typeref = get_typeref_attribute(entry, unit).or_else(|_| get_typeref_attribute(&abstract_origin_entry, unit))?;
                        Ok(Some((name, typeref, addr)))
                    } else {
                        // usual case: there is no specification or abstract origin and all info is part of this entry
                        let name = get_name_attribute(entry, &self.dwarf, unit)?;
                        let typeref = get_typeref_attribute(entry, unit)?;
                        Ok(Some((name, typeref, addr)))
                    }
                }
                None => {
                    // it's a local variable, skip, no error
                    Ok(None)
                }
            }
        }
    */

    // @@@@ xcp_client: Get all variables, including local variables
    // Return variable information
    // returns name, type reference and address
    // address may be 0 if a local variable is requested
    fn get_variable(
        &self,
        entry: &DebuggingInformationEntry<SliceType, usize>,
        unit: &UnitHeader<SliceType>,
        abbrev: &gimli::Abbreviations,
    ) -> Result<(String, usize, (u8, u64)), String> {
        // if debugging information entry A has a DW_AT_specification or DW_AT_abstract_origin attribute
        // pointing to another debugging information entry B, any attributes of B are considered to be part of A.
        if let Some(specification_entry) = get_specification_attribute(entry, unit, abbrev) {
            // the entry refers to a specification, which contains the name and type reference
            let name = get_name_attribute(&specification_entry, &self.dwarf, unit)?;
            log::debug!("get_variable '{}':", name);
            let typeref = get_typeref_attribute(&specification_entry, unit)?;
            let address = get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1).unwrap_or((0u8, 0u64));
            if address.0 >= 0x80 {
                log::debug!("  {} is a register, tls or has unknown location", name);
            } else if address.1 == 0 {
                log::debug!("  {} has no address", name);
            }
            Ok((name, typeref, address))
        } else if let Some(abstract_origin_entry) = get_abstract_origin_attribute(entry, unit, abbrev) {
            // the entry refers to an abstract origin, which should also be considered when getting the name and type ref
            let name = get_name_attribute(entry, &self.dwarf, unit).or_else(|_| get_name_attribute(&abstract_origin_entry, &self.dwarf, unit))?;
            log::debug!("'{}':", name);
            let typeref = get_typeref_attribute(entry, unit).or_else(|_| get_typeref_attribute(&abstract_origin_entry, unit))?;
            let address = get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1).unwrap_or((0u8, 0u64));
            if address.0 >= 0x80 {
                log::debug!("  {} is a register, tls or has unknown location", name);
            } else if address.1 == 0 {
                log::debug!("  {} has no address", name);
            }
            Ok((name, typeref, address))
        } else {
            // usual case: there is no specification or abstract origin and all info is part of this entry
            let name = get_name_attribute(entry, &self.dwarf, unit)?;
            log::debug!("'{}':", name);
            let typeref = get_typeref_attribute(entry, unit)?;
            let address = get_location_attribute(self, entry, unit.encoding(), &self.units.list.len() - 1).unwrap_or((0u8, 0u64));
            if address.0 >= 0x80 {
                log::debug!("  {} is a register, tls or has unknown location", name);
            } else if address.1 == 0 {
                log::debug!(". {} has no address", name);
            }
            Ok((name, typeref, address))
        }
    }
}

fn get_varinfo_from_context(context: &[(gimli::DwTag, Option<String>)]) -> (Option<String>, Vec<String>) {
    let function = context
        .iter()
        .rev()
        .find(|(tag, _)| *tag == gimli::constants::DW_TAG_subprogram)
        .and_then(|(_, name)| name.clone());
    let namespaces: Vec<String> = context
        .iter()
        .rev()
        .filter_map(|(tag, ns)| (*tag == gimli::constants::DW_TAG_namespace).then(|| ns.clone()).flatten())
        .collect();
    (function, namespaces)
}

fn demangle_cpp_varnames(input: &[&String]) -> HashMap<String, String> {
    let mut demangled_symbols = HashMap::<String, String>::new();
    let demangle_opts = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
    for varname in input {
        // some really simple strings can be processed by the demangler, e.g "c" -> "const", which is wrong here.
        // by only processing symbols that start with _Z (variables in classes/namespaces) this problem is avoided
        if varname.starts_with("_Z")
            && let Ok(sym) = cpp_demangle::Symbol::new(*varname)
        {
            // exclude useless demangled names like "typeinfo for std::type_info" or "{vtable(std::type_info)}"
            if let Ok(demangled) = sym.demangle(&demangle_opts)
                && !demangled.contains(' ')
                && !demangled.starts_with("{vtable")
            {
                demangled_symbols.insert(demangled, (*varname).clone());
            }
        }
    }

    demangled_symbols
}

// UnitList holds a list of all UnitHeaders in the Dwarf data for convenient access
impl<'a> UnitList<'a> {
    fn new() -> Self {
        Self { list: Vec::new() }
    }

    fn add(&mut self, unit: UnitHeader<SliceType<'a>>, abbrev: Abbreviations) {
        self.list.push((unit, abbrev));
    }

    fn get_unit(&self, itemoffset: usize) -> Option<usize> {
        for (idx, (unit, _)) in self.list.iter().enumerate() {
            let unitoffset = unit.offset().as_debug_info_offset().unwrap().0;
            if unitoffset < itemoffset && unitoffset + unit.length_including_self() > itemoffset {
                return Some(idx);
            }
        }

        None
    }
}

impl<'a> Index<usize> for UnitList<'a> {
    type Output = (UnitHeader<SliceType<'a>>, gimli::Abbreviations);

    fn index(&self, idx: usize) -> &Self::Output {
        &self.list[idx]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static ELF_FILE_NAMES: [&str; 1] = ["fixtures/no_a2l_demo.out"];

    #[test]
    fn test_load_data() {
        for filename in ELF_FILE_NAMES {
            let debugdata = DebugData::load_dwarf(OsStr::new(filename), 1, 0).unwrap();
            assert_eq!(debugdata.variables.len(), 28);
            assert!(debugdata.variables.get("counter").is_some());

            for (_, varinfo) in &debugdata.variables {
                assert!(debugdata.types.contains_key(&varinfo[0].typeref));
            }

            let varinfo = debugdata.variables.get("params").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Struct { .. },
                    ..
                }
            ));

            /*
            if let TypeInfo {
                datatype: DbgDataType::Class { inheritance, members, .. },
                ..
            } = typeinfo
            {
                assert!(inheritance.contains_key("base1"));
                assert!(inheritance.contains_key("base2"));
                assert!(matches!(
                    members.get("ss"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Sint16,
                            ..
                        },
                        _
                    ))
                ));
                assert!(matches!(
                    members.get("base1_var"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Sint32,
                            ..
                        },
                        _
                    ))
                ));
                assert!(matches!(
                    members.get("base2var"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Sint32,
                            ..
                        },
                        _
                    ))
                ));
            }

            let varinfo = debugdata.variables.get("class2").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Class { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("class3").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Class { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("class4").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Class { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("staticvar").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Sint32,
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("structvar").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Struct { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("bitfield").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Struct { .. },
                    ..
                }
            ));
            if let TypeInfo {
                datatype: DbgDataType::Struct { members, .. },
                ..
            } = typeinfo
            {
                assert!(matches!(
                    members.get("var"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 0, bit_size: 5, .. },
                            ..
                        },
                        0
                    ))
                ));
                assert!(matches!(
                    members.get("var2"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 5, bit_size: 5, .. },
                            ..
                        },
                        0
                    ))
                ));
                assert!(matches!(
                    members.get("var3"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 0, bit_size: 23, .. },
                            ..
                        },
                        4
                    ))
                ));
                assert!(matches!(
                    members.get("var4"),
                    Some((
                        TypeInfo {
                            datatype: DbgDataType::Bitfield { bit_offset: 23, bit_size: 1, .. },
                            ..
                        },
                        4
                    ))
                ));
            }
            let varinfo = debugdata.variables.get("enum_var1").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Enum { .. },
                    ..
                }
            ));
            let varinfo = debugdata.variables.get("enum_var2").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Enum { .. },
                    ..
                }
            ));
            let varinfo = debugdata.variables.get("enum_var3").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            assert!(matches!(
                typeinfo,
                TypeInfo {
                    datatype: DbgDataType::Enum { .. },
                    ..
                }
            ));

            let varinfo = debugdata.variables.get("var_array").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            let DbgDataType::Array { size, dim, arraytype, .. } = &typeinfo.datatype else {
                panic!("Expected array type, got {:?}", typeinfo.datatype);
            };
            assert_eq!(*size, 33);
            assert_eq!(dim.len(), 1);
            assert_eq!(dim[0], 33);
            assert!(matches!(arraytype.datatype, DbgDataType::Uint8));

            let varinfo = debugdata.variables.get("var_multidim").unwrap();
            let typeinfo = debugdata.types.get(&varinfo[0].typeref).unwrap();
            let DbgDataType::Array { dim, arraytype, .. } = &typeinfo.datatype else {
                panic!("Expected array type, got {:?}", typeinfo.datatype);
            };
            assert_eq!(dim.len(), 3);
            assert_eq!(dim, &[10, 3, 7]);
            assert!(matches!(arraytype.datatype, DbgDataType::Float));
            */
        }
    }
}

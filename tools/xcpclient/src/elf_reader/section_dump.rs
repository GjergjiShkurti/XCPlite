//--------------------------------------------------------------------------------------------------------------------------------------------------
// Module section_dump
// Print the xcp_ and mci_ sections of an ELF file as tables: what xcplite and mc-instrument put into a binary for the offline A2L generator,
// decoded with the generator's own record parsers wherever it has one, so the dump shows what the generator reads.
//
// The ELF is read with `object` alone, never its DWARF: a binary built without debug information dumps as well as one built with it, and a
// large one does not pay for debug information the dump does not use.
//
// Pointers are read as the loaded image holds them, with the dynamic relocations applied. In a shared library a pointer to a function the
// library exports -- the type thunks of mci_flds and mci_insts -- is 0 in the file, and only its relocation names the target.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt::Write as _;
use std::io::Write as _;

use object::read::elf::FileHeader;
use object::{Object, ObjectKind, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationFlags, RelocationKind, RelocationTarget, SectionFlags, SymbolKind};

use super::{
    CalTableKind, MCI_APP_BIND_LEN, MCI_APP_DESC_LEN, MCI_APP_ENDPOINT_END, MCI_APP_NAME_LEN, MCI_APP_NO_SERVER, MCI_APP_RECORD_LEN, MCI_APP_SERVER, MCI_INSTANCE_POINTERS,
    MCI_META_RECORD_LEN, XCP_EVENT_RECORD_SIZE, parse_cal_meta_record, parse_cal_table_records, parse_event_records, parse_instance_records, parse_mci_records,
    parse_server_protocol, read_cstr_at, read_cstr_bounded, read_target_ptr,
};

/// Print every xcp_ and mci_ section of the ELF file at `path`, one table per section. Section by section rather than all at
/// once, so that a warning a record parser logs lands next to the section it is about. `verbose` > 0 adds each section's bytes.
pub fn dump_sections(path: &str, verbose: usize) -> Result<(), Box<dyn Error>> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let image = Image::parse(&data).map_err(|e| format!("'{path}': {e}"))?;
    let sections = image.sections();
    // Each section is decoded as it is printed, so the parsers' warnings come out in place
    let printed = std::iter::once(image.summary(path, sections.len()))
        .chain(sections.iter().map(|section| image.dump(section, verbose)))
        .try_for_each(|text| std::io::stdout().write_all(text.as_bytes()));
    match printed {
        // A reader that stops early, as `| head` does, closes the pipe: the dump ends there, and that is no error
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(format!("cannot print the dump: {e}").into()),
        _ => Ok(()),
    }
}

/// The order the sections are printed in: the application, its events and measurements, then its calibration. A section this
/// list does not name follows, in file order.
const SECTION_ORDER: [&str; 13] = [
    "mci_app",
    "xcp_proto",
    "xcp_epk",
    "xcp_evts",
    "mci_layout",
    "mci_meas",
    "xcp_meta",
    "xcp_cals",
    "mci_cals",
    "mci_insts",
    "mci_flds",
    "mci_meta",
    "mci_tbls",
];

/// The size of a `tXcpCalSegDescriptor`, which cal.h pads to 32 bytes on every target: name, address and index pointers, then
/// the size and the type as 16-bit words.
const XCP_CALSEG_RECORD_SIZE: usize = 32;

/// How many bytes of a section the dump shows when it cannot decode it and `verbose` is 0.
const HEX_DUMP_LIMIT: usize = 256;

/// How many symbols below an address `symbol_at` looks at for one that spans it.
const SPAN_SEARCH: usize = 16;

/// A defined symbol of the ELF.
struct Symbol {
    addr: u64,
    size: u64,
    name: String,
    /// An object or a function, rather than a label or a symbol of unknown type: the better name for an address.
    typed: bool,
}

/// One xcp_ or mci_ section: where it is, and its bytes as the loaded image holds them.
struct SectionView {
    name: String,
    addr: u64,
    bytes: Vec<u8>,
    /// How many of its pointers the dynamic relocations set to something else than the file holds
    relocated: usize,
}

/// The ELF as the loader sees it: its sections' contents with the dynamic relocations applied, and its symbols by address.
struct Image<'d> {
    file: object::File<'d>,
    little_endian: bool,
    ptr_size: u8,
    /// e_machine: decides which relocation type is the relative one, and how a 32-bit target aligns a double
    machine: u16,
    /// The allocated sections that hold contents in the file, by address
    contents: Vec<(u64, &'d [u8])>,
    /// The pointer value a dynamic relocation writes at an address
    relocated: BTreeMap<u64, u64>,
    /// The symbol a dynamic relocation points an address at, when the ELF does not define that symbol itself
    imports: HashMap<u64, String>,
    /// Defined symbols, by address
    symbols: Vec<Symbol>,
}

impl<'d> Image<'d> {
    fn parse(data: &'d [u8]) -> Result<Image<'d>, String> {
        let file = object::File::parse(data).map_err(|e| format!("not an object file this reader can parse: {e}"))?;
        if file.format() != object::BinaryFormat::Elf {
            return Err(format!("a {:?} file: xcp_ and mci_ sections are ELF sections", file.format()));
        }
        if file.kind() == ObjectKind::Relocatable {
            return Err("a relocatable object: its sections hold no addresses until it is linked; dump the executable or shared library it is linked into".into());
        }
        let machine = match &file {
            object::File::Elf32(elf) => elf.elf_header().e_machine(elf.endian()),
            object::File::Elf64(elf) => elf.elf_header().e_machine(elf.endian()),
            _ => 0,
        };
        let little_endian = file.is_little_endian();
        let ptr_size: u8 = if file.is_64() { 8 } else { 4 };

        let mut contents: Vec<(u64, &'d [u8])> = file
            .sections()
            .filter(|s| matches!(s.flags(), SectionFlags::Elf { sh_flags } if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0))
            .filter_map(|s| s.data().ok().filter(|d| !d.is_empty()).map(|d| (s.address(), d)))
            .collect();
        contents.sort_by_key(|(addr, _)| *addr);

        let mut symbols: Vec<Symbol> = file
            .symbols()
            .chain(file.dynamic_symbols())
            .filter(|s| !s.is_undefined() && s.address() != 0 && matches!(s.kind(), SymbolKind::Data | SymbolKind::Text | SymbolKind::Unknown))
            .filter_map(|s| {
                let name = s.name().ok()?;
                // Linker-made section bounds and ARM mapping symbols name a place, not an object
                if name.is_empty() || name.starts_with("__start_") || name.starts_with("__stop_") || name.starts_with('$') {
                    return None;
                }
                Some(Symbol {
                    addr: s.address(),
                    size: s.size(),
                    name: name.to_string(),
                    typed: matches!(s.kind(), SymbolKind::Data | SymbolKind::Text),
                })
            })
            .collect();
        symbols.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.name.cmp(&b.name)));
        symbols.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);

        let mut image = Image {
            file,
            little_endian,
            ptr_size,
            machine,
            contents,
            relocated: BTreeMap::new(),
            imports: HashMap::new(),
            symbols,
        };
        image.apply_dynamic_relocations();
        Ok(image)
    }

    /// Record what the dynamic relocations put into pointer-sized places: a relative one the load address plus its addend, which
    /// for an image linked at 0 is the addend; an absolute one its symbol's address plus the addend, or, for a symbol another
    /// module defines, the symbol's name.
    fn apply_dynamic_relocations(&mut self) {
        let Some(relocations) = self.file.dynamic_relocations() else {
            return;
        };
        let dynamic_symbols = self.file.dynamic_symbol_table();
        let mut relocated = BTreeMap::new();
        let mut imports = HashMap::new();
        for (at, relocation) in relocations {
            let RelocationFlags::Elf { r_type } = relocation.flags() else {
                continue;
            };
            // A REL relocation keeps its addend in the place it relocates
            let addend = if relocation.has_implicit_addend() {
                match self.file_pointer(at) {
                    Some(in_place) => in_place,
                    None => continue,
                }
            } else {
                relocation.addend() as u64
            };
            if is_relative_relocation(self.machine, r_type) {
                relocated.insert(at, addend);
            } else if relocation.kind() == RelocationKind::Absolute && relocation.size() == self.ptr_size * 8 {
                match relocation.target() {
                    RelocationTarget::Symbol(index) => {
                        let Some(symbol) = dynamic_symbols.as_ref().and_then(|table| table.symbol_by_index(index).ok()) else {
                            continue;
                        };
                        if symbol.is_undefined() {
                            imports.insert(at, demangle(symbol.name().unwrap_or("?")));
                        } else {
                            relocated.insert(at, symbol.address().wrapping_add(addend));
                        }
                    }
                    RelocationTarget::Absolute => {
                        relocated.insert(at, addend);
                    }
                    _ => {}
                }
            }
        }
        self.relocated = relocated;
        self.imports = imports;
    }

    /// The allocated section contents `addr` lies in: its start address and its bytes.
    fn contents_at(&self, addr: u64) -> Option<(u64, &'d [u8])> {
        let i = self.contents.partition_point(|(start, _)| *start <= addr);
        let (start, bytes) = *self.contents.get(i.checked_sub(1)?)?;
        (addr - start < bytes.len() as u64).then_some((start, bytes))
    }

    /// The pointer the file holds at `addr`, before any relocation.
    fn file_pointer(&self, addr: u64) -> Option<u64> {
        let (start, bytes) = self.contents_at(addr)?;
        read_target_ptr(bytes, usize::try_from(addr - start).ok()?, self.ptr_size, self.little_endian)
    }

    /// The C string at `addr`, read as the generator reads one (`read_cstr_at`): None where the image holds none, or no UTF-8.
    fn text_at(&self, addr: u64) -> Option<String> {
        let (start, bytes) = self.contents_at(addr)?;
        read_cstr_at(bytes, usize::try_from(addr - start).ok()?)
    }

    /// The name of what is at `addr`: the symbol that starts there, or the one that spans it, with the offset into it.
    fn symbol_at(&self, addr: u64) -> Option<String> {
        let first = self.symbols.partition_point(|s| s.addr < addr);
        let exact = self.symbols[first..].iter().take_while(|s| s.addr == addr);
        if let Some(best) = exact.max_by_key(|s| (s.typed, s.size > 0)) {
            return Some(demangle(&best.name));
        }
        // The object that spans an address starts just below it: looking further would cost a walk of every symbol for an address
        // no object spans
        self.symbols[..first]
            .iter()
            .rev()
            .take(SPAN_SEARCH)
            .find(|s| s.size > 0 && addr - s.addr < s.size)
            .map(|s| format!("{}+0x{:X}", demangle(&s.name), addr - s.addr))
    }

    /// A pointer field at `at` holding `value`: what it points at.
    fn pointer(&self, at: u64, value: u64) -> String {
        if let Some(name) = self.imports.get(&at) {
            return format!("{name} (imported)");
        }
        if value == 0 {
            return "-".into();
        }
        self.symbol_at(value).unwrap_or_else(|| format!("0x{value:X}"))
    }

    /// A string pointer field at `at` holding `value`: the text it points at.
    fn text(&self, at: u64, value: u64) -> String {
        if let Some(name) = self.imports.get(&at) {
            return format!("{name} (imported)");
        }
        if value == 0 {
            return "-".into();
        }
        match self.text_at(value) {
            Some(text) if text.is_empty() => "\"\"".into(),
            Some(text) => printable(&text),
            None => format!("0x{value:X} (no text there)"),
        }
    }

    /// A type thunk field at `at` holding `value` (FieldMeta's owner and nested, InstanceMeta's type): the type it describes.
    fn type_thunk(&self, at: u64, value: u64) -> String {
        type_of_thunk(&self.pointer(at, value))
    }

    /// The xcp_ and mci_ sections, in SECTION_ORDER, with their contents as the loaded image holds them.
    fn sections(&self) -> Vec<SectionView> {
        let mut sections: Vec<(usize, usize, SectionView)> = self
            .file
            .sections()
            .filter_map(|section| {
                let name = section.name().ok()?;
                if !name.starts_with("xcp_") && !name.starts_with("mci_") {
                    return None;
                }
                let mut bytes = section.data().unwrap_or_default().to_vec();
                let relocated = apply_relocations(&mut bytes, section.address(), &self.relocated, self.ptr_size, self.little_endian);
                let rank = SECTION_ORDER.iter().position(|known| *known == name).unwrap_or(SECTION_ORDER.len());
                Some((
                    rank,
                    section.index().0,
                    SectionView {
                        name: name.to_string(),
                        addr: section.address(),
                        bytes,
                        relocated,
                    },
                ))
            })
            .collect();
        sections.sort_by_key(|(rank, index, _)| (*rank, *index));
        sections.into_iter().map(|(_, _, section)| section).collect()
    }

    fn summary(&self, path: &str, sections: usize) -> String {
        let kind = match self.file.kind() {
            ObjectKind::Executable => "executable",
            // An executable names its program interpreter, a shared library does not
            ObjectKind::Dynamic if self.file.section_by_name(".interp").is_some() => "position independent executable",
            ObjectKind::Dynamic => "shared library",
            _ => "ELF file",
        };
        let what = match sections {
            0 => "no xcp_ or mci_ section".to_string(),
            1 => "1 xcp_ or mci_ section".to_string(),
            n => format!("{n} xcp_ and mci_ sections"),
        };
        format!(
            "{path}: {}-bit {} endian {:?} {kind}, {what}\n",
            self.ptr_size * 8,
            if self.little_endian { "little" } else { "big" },
            self.file.architecture()
        )
    }

    /// One section: a line saying where it is, then its records as a table, or its bytes when it cannot be decoded.
    fn dump(&self, section: &SectionView, verbose: usize) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "\n{}  0x{:X}  {} bytes", section.name, section.addr, section.bytes.len());
        let decoded = match section.name.as_str() {
            "mci_app" => self.app(section, &mut out),
            "xcp_proto" => self.proto(section, &mut out),
            "xcp_epk" => epk(section, &mut out),
            "xcp_evts" => self.events(section, &mut out),
            "mci_layout" => self.layout(section, &mut out),
            "mci_meas" => self.measurements(section, &mut out),
            "xcp_meta" => self.meta(section, &mut out),
            "xcp_cals" => self.calsegs(section, &mut out),
            "mci_cals" => self.calseg_markers(section, &mut out),
            "mci_insts" => self.instances(section, &mut out),
            "mci_flds" => self.fields(section, &mut out),
            "mci_meta" => self.cal_meta(section, &mut out),
            "mci_tbls" => self.tables(section, &mut out),
            _ => Err("no decoder for this section".into()),
        };
        match decoded {
            Err(reason) => {
                let _ = writeln!(out, "  {reason}");
                hex_dump(&mut out, section.addr, &section.bytes, if verbose > 0 { usize::MAX } else { HEX_DUMP_LIMIT });
            }
            Ok(()) if verbose > 0 => hex_dump(&mut out, section.addr, &section.bytes, usize::MAX),
            Ok(()) => {}
        }
        if section.relocated > 0 {
            let _ = writeln!(
                out,
                "  {} set by dynamic relocations: the file itself holds another value there",
                count(section.relocated, "pointer")
            );
        }
        out
    }

    fn u16_at(&self, bytes: &[u8], at: usize) -> u16 {
        let raw = [bytes[at], bytes[at + 1]];
        if self.little_endian { u16::from_le_bytes(raw) } else { u16::from_be_bytes(raw) }
    }

    fn f64_at(&self, bytes: &[u8], at: usize) -> f64 {
        let raw: [u8; 8] = bytes[at..at + 8].try_into().unwrap();
        if self.little_endian { f64::from_le_bytes(raw) } else { f64::from_be_bytes(raw) }
    }

    fn ptr_at(&self, bytes: &[u8], at: usize) -> u64 {
        read_target_ptr(bytes, at, self.ptr_size, self.little_endian).unwrap_or(0)
    }

    /// mci_app: the application record, `mci::AppMeta` (mc_meas_abi.hpp).
    fn app(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let d = &section.bytes;
        if ![MCI_APP_NAME_LEN, MCI_APP_ENDPOINT_END, MCI_APP_RECORD_LEN].contains(&d.len()) {
            return Err(format!(
                "not an application record: AppMeta is {MCI_APP_RECORD_LEN} bytes, {MCI_APP_ENDPOINT_END} or {MCI_APP_NAME_LEN} in older builds"
            ));
        }
        let _ = writeln!(out, "  the application record (AppMeta), as MC_APP states it");
        let mut table = Table::new(&["field", "value"]);
        table.row(["name".into(), field_text(&read_cstr_bounded(d, 0, MCI_APP_NAME_LEN).unwrap_or_default())]);
        if d.len() >= MCI_APP_ENDPOINT_END {
            let bind = read_cstr_bounded(d, MCI_APP_NAME_LEN, MCI_APP_BIND_LEN).unwrap_or_default();
            let at = MCI_APP_NAME_LEN + MCI_APP_BIND_LEN;
            table.row(["bind".into(), if bind.is_empty() { "\"\" (every interface)".into() } else { printable(&bind) }]);
            table.row(["port".into(), self.u16_at(d, at).to_string()]);
            table.row(["transport".into(), if d[at + 2] != 0 { "TCP" } else { "UDP" }.into()]);
            let endpoint = match d[at + 3] {
                MCI_APP_SERVER => "an XCP server".to_string(),
                MCI_APP_NO_SERVER => "no XCP server (the device is the transport)".to_string(),
                other => format!("unknown kind {other}"),
            };
            table.row(["endpoint".into(), endpoint]);
        }
        if d.len() == MCI_APP_RECORD_LEN {
            table.row([
                "description".into(),
                field_text(&read_cstr_bounded(d, MCI_APP_ENDPOINT_END, MCI_APP_DESC_LEN).unwrap_or_default()),
            ]);
        }
        table.render(out);
        if d.len() < MCI_APP_RECORD_LEN {
            let _ = writeln!(
                out,
                "  an older record: built before MC_APP recorded {}",
                if d.len() == MCI_APP_NAME_LEN { "its endpoint" } else { "its description" }
            );
        }
        Ok(())
    }

    /// xcp_proto: what the server answers to CONNECT, GET_DAQ_RESOLUTION_INFO and GET_DAQ_PROCESSOR_INFO (`parse_server_protocol`).
    fn proto(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let d = &section.bytes;
        if d.len() < 8 || !d.len().is_multiple_of(2) {
            return Err(parse_server_protocol(d, self.little_endian).err().unwrap_or_default());
        }
        let parsed = parse_server_protocol(d, self.little_endian);
        let server = parsed.as_ref().ok();
        let _ = writeln!(out, "  the server's protocol parameters, as the A2L states them");
        let mut table = Table::new(&["word", "field", "value"]);
        for (i, word) in d.chunks_exact(2).enumerate() {
            let value = self.u16_at(word, 0);
            let (field, shown) = match i {
                0 => ("MAX_CTO", value.to_string()),
                1 => ("MAX_DTO", value.to_string()),
                2 => (
                    "TIMESTAMP_MODE",
                    match server.map(|s| s.timestamp_supported()) {
                        Some(Ok(supported)) => format!("0x{value:02X} (TIMESTAMP_SUPPORTED {supported})"),
                        _ => format!("0x{value:02X}"),
                    },
                ),
                3 => ("TIMESTAMP_TICKS", value.to_string()),
                4 => (
                    "identification",
                    match server.and_then(|s| s.ident_keyword()) {
                        Some(keyword) => format!("0x{value:04X} (IDENTIFICATION_FIELD_TYPE_{keyword})"),
                        None => format!("0x{value:04X} (states no identification field type)"),
                    },
                ),
                _ => ("-", format!("0x{value:04X}")),
            };
            table.row([i.to_string(), field.into(), shown]);
        }
        table.render(out);
        if let Err(e) = parsed {
            let _ = writeln!(out, "  the A2L generator refuses this record: {e}");
        }
        Ok(())
    }

    /// xcp_evts: one `tXcpEventDescriptor` per event (`parse_event_records`).
    fn events(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let records = parse_event_records(&section.bytes, section.addr, self.ptr_size, self.little_endian)?;
        let _ = writeln!(
            out,
            "  {} (tXcpEventDescriptor, {XCP_EVENT_RECORD_SIZE} bytes each), in section order: the order XcpInit creates the events in",
            count(records.len(), "event descriptor")
        );
        let mut table = Table::new(&["#", "name", "cycle", "priority", "descriptor"]);
        for (i, record) in records.iter().enumerate() {
            let priority = section.bytes[i * XCP_EVENT_RECORD_SIZE + self.ptr_size as usize + 4];
            table.row([
                i.to_string(),
                self.text(record.addr, record.name_ptr),
                cycle(record.cycle_time_ns),
                priority.to_string(),
                self.symbol_at(record.addr).unwrap_or_else(|| "-".into()),
            ]);
        }
        table.render(out);
        Ok(())
    }

    /// mci_layout: the `mci::MeasLayout` record that says how to read mci_meas.
    fn layout(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let d = &section.bytes;
        if d.len() < 20 {
            return Err(format!("{} bytes, too short for a MeasLayout record (20 bytes, 24 from version 2)", d.len()));
        }
        let version = d[3];
        let mut names = vec!["name", "type", "x_dim", "flags", "comment", "unit", "min", "max"];
        if version >= 2 && d.len() >= 24 {
            names.extend(["event", "addr"]);
        }
        let offsets: Vec<String> = names.iter().enumerate().map(|(i, name)| format!("{name} {}", self.u16_at(d, 4 + 2 * i))).collect();
        let _ = writeln!(out, "  how to read the mci_meas records (MeasLayout)");
        let mut table = Table::new(&["field", "value"]);
        table.row(["record size".into(), self.u16_at(d, 0).to_string()]);
        table.row(["pointer size".into(), d[2].to_string()]);
        table.row(["version".into(), version.to_string()]);
        table.row(["field offsets".into(), offsets.join(", ")]);
        table.render(out);
        Ok(())
    }

    /// mci_meas: one `mci::MeasMeta` per measured object (`parse_mci_records`), read with the layout mci_layout gives.
    fn measurements(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let layout = self.file.section_by_name("mci_layout").and_then(|s| s.data().ok());
        let text_at = |addr: u64| self.text_at(addr);
        let records = parse_mci_records(&section.bytes, layout, self.little_endian, &text_at).map_err(|e| e.to_string())?;
        if records.is_empty() {
            if section.bytes.is_empty() {
                let _ = writeln!(out, "  no measurement descriptors");
                return Ok(());
            }
            return Err("the A2L generator reads no record from this section; its warning above says why".into());
        }
        let _ = writeln!(
            out,
            "  {} (MeasMeta, {} bytes each, laid out as {}); a signal is <event>.<name>",
            count(records.len(), "measurement descriptor"),
            section.bytes.len() / records.len(),
            if layout.is_some() {
                "mci_layout says"
            } else {
                "the historical 64-bit layout, there being no mci_layout"
            }
        );
        let mut table = Table::new(&["#", "event", "name", "type", "dim", "unit", "min", "max", "address", "comment"]);
        for (i, record) in records.iter().enumerate() {
            let (min, max) = limits(record.min, record.max);
            let address = match record.addr {
                None => "identifier".to_string(),
                Some(addr) => match self.symbol_at(u64::from(addr)) {
                    Some(name) => format!("0x{addr:08X} {name}"),
                    None => format!("0x{addr:08X}"),
                },
            };
            table.row([
                i.to_string(),
                field_text(&record.event),
                printable(&record.name),
                type_name(record.ty),
                record.x_dim.to_string(),
                field_text(&record.unit),
                min,
                max,
                address,
                field_text(&record.comment),
            ]);
        }
        table.render(out);
        note_limits(out, records.iter().map(|r| (r.min, r.max)));
        Ok(())
    }

    /// xcp_meta: xcplite's named metadata objects, `xcp_meta__<kind>__<name>` (XCP_UNIT, XCP_COMMENT, XCP_LIMITS), read as the
    /// generator's register_metadata reads them. The name is the only thing that says what an object is, so this needs the
    /// symbol table: the generator takes the names from the debug information instead.
    fn meta(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let end = section.addr + section.bytes.len() as u64;
        let mut objects: Vec<(&Symbol, String)> = Vec::new();
        for symbol in self.symbols.iter().filter(|s| s.addr >= section.addr && s.addr < end) {
            let name = demangle(&symbol.name);
            if !objects.iter().any(|(s, n)| s.addr == symbol.addr && *n == name) {
                objects.push((symbol, name));
            }
        }
        if objects.is_empty() {
            return Err("no symbol names the objects in this section (a stripped binary?), and only its name says what an object is".into());
        }
        #[derive(Default)]
        struct Entry {
            unit: Option<String>,
            comment: Option<String>,
            min: Option<f64>,
            max: Option<f64>,
        }
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
        let mut unknown: Vec<String> = Vec::new();
        for (symbol, name) in &objects {
            let offset = (symbol.addr - section.addr) as usize;
            let Some((kind, path)) = meta_object_name(name) else {
                unknown.push(format!("{name}: not an xcp_meta__<kind>__<name> object"));
                continue;
            };
            let entry = entries.entry(path).or_default();
            match kind.as_str() {
                "unit" => entry.unit = read_cstr_at(&section.bytes, offset),
                "comment" => entry.comment = read_cstr_at(&section.bytes, offset),
                "min" if offset + 8 <= section.bytes.len() => entry.min = Some(self.f64_at(&section.bytes, offset)),
                "max" if offset + 8 <= section.bytes.len() => entry.max = Some(self.f64_at(&section.bytes, offset)),
                _ => unknown.push(format!("{name}: a kind '{kind}' the generator does not read")),
            }
        }
        let _ = writeln!(
            out,
            "  {} for {} (xcp_meta__<kind>__<name>; __ in a name is a '.')",
            count(objects.len(), "metadata object"),
            count(entries.len(), "name")
        );
        let mut table = Table::new(&["name", "unit", "min", "max", "comment"]);
        for (path, entry) in &entries {
            let limit = |v: Option<f64>| v.map_or_else(|| "-".to_string(), number);
            table.row([
                printable(path),
                entry.unit.as_deref().map_or_else(|| "-".to_string(), field_text),
                limit(entry.min),
                limit(entry.max),
                entry.comment.as_deref().map_or_else(|| "-".to_string(), field_text),
            ]);
        }
        table.render(out);
        for line in unknown {
            let _ = writeln!(out, "  {line}");
        }
        Ok(())
    }

    /// xcp_cals: one `tXcpCalSegDescriptor` per segment or block xcplite creates from the section.
    fn calsegs(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let d = &section.bytes;
        if !d.len().is_multiple_of(XCP_CALSEG_RECORD_SIZE) {
            return Err(format!("not a whole number of {XCP_CALSEG_RECORD_SIZE}-byte tXcpCalSegDescriptor records"));
        }
        let p = self.ptr_size as usize;
        let _ = writeln!(
            out,
            "  {} (tXcpCalSegDescriptor, {XCP_CALSEG_RECORD_SIZE} bytes each)",
            count(d.len() / XCP_CALSEG_RECORD_SIZE, "calibration segment descriptor")
        );
        let mut table = Table::new(&["#", "name", "default page", "size", "type", "index slot"]);
        for (i, record) in d.chunks_exact(XCP_CALSEG_RECORD_SIZE).enumerate() {
            let at = section.addr + (i * XCP_CALSEG_RECORD_SIZE) as u64;
            let kind = match self.u16_at(record, 3 * p + 2) {
                0x8001 => "segment".to_string(),
                0x8002 => "block".to_string(),
                other => format!("0x{other:04X}"),
            };
            table.row([
                i.to_string(),
                self.text(at, self.ptr_at(record, 0)),
                self.pointer(at + p as u64, self.ptr_at(record, p)),
                self.u16_at(record, 3 * p).to_string(),
                kind,
                self.pointer(at + 2 * p as u64, self.ptr_at(record, 2 * p)),
            ]);
        }
        table.render(out);
        Ok(())
    }

    /// mci_cals: mc-instrument's segment markers, `calseg__<name>`, each its name as characters. The application numbers its
    /// segments by the markers' address order.
    fn calseg_markers(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let mut table = Table::new(&["#", "address", "name", "marker"]);
        let mut markers = 0;
        let mut offset = 0;
        while offset < section.bytes.len() {
            let len = section.bytes[offset..].iter().position(|&b| b == 0).unwrap_or(section.bytes.len() - offset);
            if len > 0 {
                let addr = section.addr + offset as u64;
                let name = String::from_utf8_lossy(&section.bytes[offset..offset + len]);
                table.row([
                    markers.to_string(),
                    format!("0x{addr:X}"),
                    printable(&name),
                    self.symbol_at(addr).unwrap_or_else(|| "-".into()),
                ]);
                markers += 1;
            }
            offset += len + 1;
        }
        let _ = writeln!(
            out,
            "  {}, in address order: the order the segments are numbered in",
            count(markers, "calibration segment marker")
        );
        table.render(out);
        Ok(())
    }

    /// mci_insts: one `mci::InstanceMeta` per calibration segment instance (`parse_instance_records`).
    fn instances(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let records = parse_instance_records(&section.bytes, self.ptr_size, self.little_endian)?;
        let p = self.ptr_size as usize;
        let size = MCI_INSTANCE_POINTERS * p;
        let _ = writeln!(out, "  {} (InstanceMeta, {size} bytes each)", count(records.len(), "calibration segment instance"));
        let mut table = Table::new(&["#", "name", "label", "type", "page", "index slot", "marker"]);
        for (i, (record, bytes)) in records.iter().zip(section.bytes.chunks_exact(size)).enumerate() {
            let at = |n: usize| section.addr + (i * size + n * p) as u64;
            table.row([
                i.to_string(),
                self.text(at(0), record.name_ptr),
                self.text(at(1), self.ptr_at(bytes, p)),
                self.type_thunk(at(2), self.ptr_at(bytes, 2 * p)),
                self.pointer(at(3), self.ptr_at(bytes, 3 * p)),
                self.pointer(at(4), self.ptr_at(bytes, 4 * p)),
                self.pointer(at(5), record.marker),
            ]);
        }
        table.render(out);
        Ok(())
    }

    /// mci_flds: one `mci::FieldMeta` per field of a declared type, the metadata the runtime A2L route registers.
    fn fields(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        // i386 is the 32-bit ABI that aligns a double to 4 inside a struct; the others this runs on align it to 8
        let double_align = if self.ptr_size == 4 && self.machine == object::elf::EM_386 { 4 } else { 8 };
        let layout = FieldMetaLayout::new(self.ptr_size as usize, double_align);
        let d = &section.bytes;
        if !d.len().is_multiple_of(layout.stride) {
            return Err(format!("not a whole number of {}-byte FieldMeta records", layout.stride));
        }
        let _ = writeln!(
            out,
            "  {} (FieldMeta, {} bytes each), in link order",
            count(d.len() / layout.stride, "field descriptor"),
            layout.stride
        );
        let mut table = Table::new(&["#", "owner", "field", "nested", "label", "unit", "min", "max", "x axis", "y axis", "comment"]);
        let mut limits_seen = Vec::new();
        for (i, record) in d.chunks_exact(layout.stride).enumerate() {
            let base = section.addr + (i * layout.stride) as u64;
            let ptr = |offset: usize| (base + offset as u64, self.ptr_at(record, offset));
            let text = |offset: usize| {
                let (at, value) = ptr(offset);
                self.text(at, value)
            };
            let (owner_at, owner) = ptr(layout.owner);
            let (nested_at, nested) = ptr(layout.nested);
            let (min, max) = (self.f64_at(record, layout.min), self.f64_at(record, layout.max));
            limits_seen.push((min, max));
            let (min, max) = limits(min, max);
            table.row([
                i.to_string(),
                self.type_thunk(owner_at, owner),
                text(layout.name),
                self.type_thunk(nested_at, nested),
                text(layout.label),
                text(layout.unit),
                min,
                max,
                text(layout.x_axis),
                text(layout.y_axis),
                text(layout.comment),
            ]);
        }
        table.render(out);
        note_limits(out, limits_seen.into_iter());
        Ok(())
    }

    /// mci_meta: one `mci::CalMeta` per calibration field that states a unit, a comment or limits (`parse_cal_meta_record`).
    fn cal_meta(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let d = &section.bytes;
        if !d.len().is_multiple_of(MCI_META_RECORD_LEN) {
            return Err(format!("not a whole number of {MCI_META_RECORD_LEN}-byte CalMeta records"));
        }
        let _ = writeln!(
            out,
            "  {} (CalMeta, {MCI_META_RECORD_LEN} bytes each)",
            count(d.len() / MCI_META_RECORD_LEN, "calibration field metadata record")
        );
        let mut table = Table::new(&["#", "owner", "field", "unit", "min", "max", "comment"]);
        let mut limits_seen = Vec::new();
        for (i, record) in d.chunks_exact(MCI_META_RECORD_LEN).enumerate() {
            match parse_cal_meta_record(record, self.little_endian) {
                Some(meta) => {
                    limits_seen.push((meta.min, meta.max));
                    let (min, max) = limits(meta.min, meta.max);
                    table.row([
                        i.to_string(),
                        field_text(&meta.owner),
                        field_text(&meta.field),
                        field_text(&meta.unit),
                        min,
                        max,
                        field_text(&meta.comment),
                    ]);
                }
                None => table.row([i.to_string(), "(a text that is not UTF-8)".into(), "".into(), "".into(), "".into(), "".into(), "".into()]),
            }
        }
        table.render(out);
        note_limits(out, limits_seen.into_iter());
        Ok(())
    }

    /// mci_tbls: one `mci::TableMeta` per curve, map and axis (`parse_cal_table_records`).
    fn tables(&self, section: &SectionView, out: &mut String) -> Result<(), String> {
        let records = parse_cal_table_records(&section.bytes, self.little_endian)?;
        let _ = writeln!(out, "  {} (TableMeta)", count(records.len(), "table record"));
        let mut table = Table::new(&["#", "owner", "field", "kind", "x", "y", "x axis", "y axis", "unit", "min", "max", "comment"]);
        for (i, record) in records.iter().enumerate() {
            let kind = match record.kind() {
                Ok(CalTableKind::Axis) => "AXIS_PTS",
                Ok(CalTableKind::Curve) => "CURVE",
                Ok(CalTableKind::Map) => "MAP",
                Ok(CalTableKind::Value) => "VALUE",
                Err(_) => "no valid shape",
            };
            let axis = |name: &str| if name.is_empty() { "fixed".to_string() } else { printable(name) };
            let (min, max) = limits(record.meta.min, record.meta.max);
            table.row([
                i.to_string(),
                field_text(&record.meta.owner),
                field_text(&record.meta.field),
                kind.into(),
                record.x_dim.to_string(),
                record.y_dim.to_string(),
                axis(&record.x_axis),
                axis(&record.y_axis),
                field_text(&record.meta.unit),
                min,
                max,
                field_text(&record.meta.comment),
            ]);
        }
        table.render(out);
        note_limits(out, records.iter().map(|r| (r.meta.min, r.meta.max)));
        Ok(())
    }
}

/// xcp_epk: the EPK, a C string.
fn epk(section: &SectionView, out: &mut String) -> Result<(), String> {
    let text = read_cstr_at(&section.bytes, 0).ok_or("no UTF-8 C string")?;
    let _ = writeln!(out, "  the EPK, the software version string the A2L and the server state");
    let mut table = Table::new(&["field", "value"]);
    table.row(["text".into(), field_text(&text)]);
    table.render(out);
    Ok(())
}

/// Field offsets of an `mci::FieldMeta` (mc.hpp) for a pointer size and a double alignment, and the stride its objects are
/// laid out at: each is placed aligned(8) in mci_flds.
#[derive(Debug, PartialEq)]
struct FieldMetaLayout {
    owner: usize,
    nested: usize,
    name: usize,
    label: usize,
    comment: usize,
    unit: usize,
    min: usize,
    max: usize,
    x_axis: usize,
    y_axis: usize,
    layout: usize,
    stride: usize,
}

impl FieldMetaLayout {
    fn new(ptr: usize, double_align: usize) -> FieldMetaLayout {
        let min = (6 * ptr).next_multiple_of(double_align);
        let x_axis = (min + 16).next_multiple_of(ptr);
        let layout = x_axis + 2 * ptr;
        let size = (layout + ptr).next_multiple_of(ptr.max(double_align));
        FieldMetaLayout {
            owner: 0,
            nested: ptr,
            name: 2 * ptr,
            label: 3 * ptr,
            comment: 4 * ptr,
            unit: 5 * ptr,
            min,
            max: min + 8,
            x_axis,
            y_axis: x_axis + ptr,
            layout,
            stride: size.next_multiple_of(8),
        }
    }
}

/// Write `relocated`'s pointer values into the bytes of a section at `base`; how many of them change what the bytes held.
fn apply_relocations(bytes: &mut [u8], base: u64, relocated: &BTreeMap<u64, u64>, ptr_size: u8, little_endian: bool) -> usize {
    let width = ptr_size as usize;
    let mut changed = 0;
    for (&at, &value) in relocated.range(base..base.saturating_add(bytes.len() as u64)) {
        let offset = (at - base) as usize;
        let Some(place) = bytes.get_mut(offset..offset + width) else {
            continue;
        };
        let encoded = match (width, little_endian) {
            (8, true) => value.to_le_bytes().to_vec(),
            (8, false) => value.to_be_bytes().to_vec(),
            (_, true) => (value as u32).to_le_bytes().to_vec(),
            (_, false) => (value as u32).to_be_bytes().to_vec(),
        };
        if place != encoded.as_slice() {
            place.copy_from_slice(&encoded);
            changed += 1;
        }
    }
    changed
}

/// Whether an ELF relocation type is the machine's relative one: the load address plus the addend.
fn is_relative_relocation(machine: u16, r_type: u32) -> bool {
    use object::elf::*;
    matches!(
        (machine, r_type),
        (EM_X86_64, R_X86_64_RELATIVE)
            | (EM_386, R_386_RELATIVE)
            | (EM_AARCH64, R_AARCH64_RELATIVE)
            | (EM_ARM, R_ARM_RELATIVE)
            | (EM_RISCV, R_RISCV_RELATIVE)
            | (EM_PPC, R_PPC_RELATIVE)
            | (EM_PPC64, R_PPC64_RELATIVE)
    )
}

/// A C++ symbol name as source spells it, without parameters; any other name as it is.
fn demangle(name: &str) -> String {
    if name.starts_with("_Z")
        && let Ok(symbol) = cpp_demangle::Symbol::new(name)
        && let Ok(plain) = symbol.demangle(&cpp_demangle::DemangleOptions::new().no_params().no_return_type())
    {
        return plain;
    }
    name.to_string()
}

/// The type a type thunk describes: `X` for `mci::TypeBase<X, (mci::TypeKind)0>::mci_owner`, with a measurement type marked,
/// and any other function by its name.
fn type_of_thunk(function: &str) -> String {
    const OPEN: &str = "mci::TypeBase<";
    const KIND: &str = ", (mci::TypeKind)";
    if let Some(start) = function.find(OPEN)
        && let Some(kind_at) = function.rfind(KIND)
        && kind_at > start
        && function.ends_with(">::mci_owner")
    {
        let name = &function[start + OPEN.len()..kind_at];
        return match &function[kind_at + KIND.len()..function.len() - ">::mci_owner".len()] {
            "1" => format!("{name} (measurement)"),
            _ => name.to_string(),
        };
    }
    function.to_string()
}

/// The kind and the dotted name of an xcp_meta object, from its symbol: `xcp_meta__unit__params__delay_us` is the unit of
/// `params.delay_us`. A static in a function is `<function>::xcp_meta__...`, and a local one can carry a `.<n>` suffix.
fn meta_object_name(symbol: &str) -> Option<(String, String)> {
    let leaf = symbol.rsplit("::").next()?;
    let leaf = match leaf.rsplit_once('.') {
        Some((stem, suffix)) if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) => stem,
        _ => leaf,
    };
    let (kind, name) = leaf.strip_prefix("xcp_meta__")?.split_once("__")?;
    Some((kind.to_string(), name.replace("__", ".")))
}

/// The A2L data type of an A2L type id (tA2lTypeId: magnitude the byte size, sign the signedness, -9 and -10 float and double).
fn type_name(id: i8) -> String {
    match id {
        1 => "UBYTE",
        2 => "UWORD",
        4 => "ULONG",
        8 => "A_UINT64",
        -1 => "SBYTE",
        -2 => "SWORD",
        -4 => "SLONG",
        -8 => "A_INT64",
        -9 => "FLOAT32_IEEE",
        -10 => "FLOAT64_IEEE",
        other => return format!("type id {other}"),
    }
    .to_string()
}

/// `n` and a noun, plural unless `n` is 1.
fn count(n: usize, noun: &str) -> String {
    if n == 1 { format!("1 {noun}") } else { format!("{n} {noun}s") }
}

/// A cycle time in nanoseconds, in the largest unit that states it exactly.
fn cycle(ns: u32) -> String {
    match ns {
        0 => "0 (sporadic)".to_string(),
        ns if ns % 1_000_000_000 == 0 => format!("{} s", ns / 1_000_000_000),
        ns if ns % 1_000_000 == 0 => format!("{} ms", ns / 1_000_000),
        ns if ns % 1_000 == 0 => format!("{} us", ns / 1_000),
        ns => format!("{ns} ns"),
    }
}

/// A limit, as short as states it exactly: integral values in full up to 1e10, others past that or below 1e-4 as exponents.
fn number(value: f64) -> String {
    let magnitude = value.abs();
    if value.fract() == 0.0 && magnitude < 1e10 {
        format!("{value}")
    } else if magnitude >= 1e10 || (magnitude < 1e-4 && value != 0.0) {
        format!("{value:e}")
    } else {
        format!("{value}")
    }
}

/// A min and max pair as stored, where both 0 is the convention for no limits given: then both print as "-".
fn limits(min: f64, max: f64) -> (String, String) {
    if min == 0.0 && max == 0.0 {
        ("-".into(), "-".into())
    } else {
        (number(min), number(max))
    }
}

/// Under a table with limits, what "-" stands for, when a row uses it.
fn note_limits(out: &mut String, mut limits: impl Iterator<Item = (f64, f64)>) {
    if limits.any(|(min, max)| min == 0.0 && max == 0.0) {
        let _ = writeln!(out, "  min and max -: none given (both stored as 0), so the type's range applies");
    }
}

/// A text for a table cell: control characters escaped, so one record stays one line.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A fixed-width text field for a table cell, "-" when empty: these records state nothing by leaving a field empty.
fn field_text(text: &str) -> String {
    if text.is_empty() { "-".into() } else { printable(text) }
}

/// `bytes` from address `base` as hex and characters, 16 to a line, the first `limit` of them.
fn hex_dump(out: &mut String, base: u64, bytes: &[u8], limit: usize) {
    for (i, line) in bytes.chunks(16).take(limit.div_ceil(16)).enumerate() {
        let hex: Vec<String> = line.chunks(4).map(|word| word.iter().map(|b| format!("{b:02x}")).collect()).collect();
        let text: String = line.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
        let _ = writeln!(out, "  0x{:08x}  {:<35}  {text}", base + (i * 16) as u64, hex.join(" "));
    }
    if bytes.len() > limit {
        let _ = writeln!(out, "  ... {} more bytes (--verbose 1 shows them all)", bytes.len() - limit);
    }
}

/// Rows of cells printed in columns under a header, each column as wide as its widest cell.
struct Table {
    header: Vec<&'static str>,
    rows: Vec<Vec<String>>,
}

impl Table {
    fn new(header: &[&'static str]) -> Table {
        Table {
            header: header.to_vec(),
            rows: Vec::new(),
        }
    }

    fn row<const N: usize>(&mut self, cells: [String; N]) {
        debug_assert_eq!(N, self.header.len());
        self.rows.push(cells.into());
    }

    fn render(&self, out: &mut String) {
        let widths: Vec<usize> = (0..self.header.len())
            .map(|c| self.rows.iter().map(|row| row[c].chars().count()).chain([self.header[c].len()]).max().unwrap_or(0))
            .collect();
        let rules: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        render_line(out, &widths, self.header.iter().copied());
        render_line(out, &widths, rules.iter().map(String::as_str));
        for row in &self.rows {
            render_line(out, &widths, row.iter().map(String::as_str));
        }
    }
}

/// One line of a table: two spaces in, two between columns, none at the end.
fn render_line<'a>(out: &mut String, widths: &[usize], cells: impl Iterator<Item = &'a str>) {
    let mut text = String::from(" ");
    for (cell, width) in cells.zip(widths.iter().copied()) {
        let _ = write!(text, " {cell:<width$} ");
    }
    out.push_str(text.trim_end());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    const XCPLITE_ELF: &str = "../../examples/no_a2l_demo/CANape/no_a2l_demo.elf";

    #[test]
    fn a_relocation_writes_its_pointer_and_counts_a_change() {
        let mut relocated = BTreeMap::new();
        relocated.insert(0x1000, 0x2345); // differs from the bytes: written and counted
        relocated.insert(0x1008, 0x0807_0605_0403_0201); // already there: not counted
        relocated.insert(0x1010, 0x9999); // past the section: ignored
        let mut bytes = vec![0u8; 16];
        bytes[8..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(apply_relocations(&mut bytes, 0x1000, &relocated, 8, true), 1);
        assert_eq!(&bytes[..8], &0x2345u64.to_le_bytes());
        assert_eq!(&bytes[8..], &[1, 2, 3, 4, 5, 6, 7, 8]);

        // a 32-bit big-endian target, and a place cut off by the end of the section
        let mut relocated = BTreeMap::new();
        relocated.insert(0x2000, 0x1234_5678);
        relocated.insert(0x2006, 0x1);
        let mut bytes = vec![0u8; 8];
        assert_eq!(apply_relocations(&mut bytes, 0x2000, &relocated, 4, false), 1);
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
    }

    #[test]
    fn field_meta_is_laid_out_per_abi() {
        // LP64: six pointers, two doubles, three pointers -- 88 bytes
        let lp64 = FieldMetaLayout::new(8, 8);
        assert_eq!((lp64.min, lp64.max, lp64.x_axis, lp64.y_axis, lp64.layout, lp64.stride), (48, 56, 64, 72, 80, 88));
        // i386 aligns a double to 4: 52 bytes, placed 8-aligned, so 56 apart
        let i386 = FieldMetaLayout::new(4, 4);
        assert_eq!((i386.min, i386.max, i386.x_axis, i386.y_axis, i386.layout, i386.stride), (24, 32, 40, 44, 48, 56));
        // a 32-bit ABI that aligns a double to 8: 56 bytes
        let arm = FieldMetaLayout::new(4, 8);
        assert_eq!((arm.min, arm.stride), (24, 56));
    }

    #[test]
    fn a_type_thunk_names_its_type() {
        assert_eq!(type_of_thunk("mci::TypeBase<KernelParamsType, (mci::TypeKind)0>::mci_owner"), "KernelParamsType");
        assert_eq!(type_of_thunk("mci::TypeBase<ns::Grid<int, 3>, (mci::TypeKind)0>::mci_owner"), "ns::Grid<int, 3>");
        assert_eq!(type_of_thunk("mci::TypeBase<Sample, (mci::TypeKind)1>::mci_owner"), "Sample (measurement)");
        // anything else is shown as it is
        assert_eq!(type_of_thunk("mci_page_of_KernelParams"), "mci_page_of_KernelParams");
        assert_eq!(type_of_thunk("-"), "-");
    }

    #[test]
    fn demangling_drops_the_parameters() {
        assert_eq!(
            demangle("_ZN3mci8TypeBaseI16KernelParamsTypeLNS_8TypeKindE0EE9mci_ownerEv"),
            "mci::TypeBase<KernelParamsType, (mci::TypeKind)0>::mci_owner"
        );
        assert_eq!(demangle("_ZL29xcp_meta__max__sample_rate_hz"), "xcp_meta__max__sample_rate_hz");
        assert_eq!(demangle("calseg__epk"), "calseg__epk");
    }

    #[test]
    fn an_xcp_meta_object_name_gives_its_kind_and_name() {
        assert_eq!(meta_object_name("xcp_meta__unit__counter"), Some(("unit".into(), "counter".into())));
        assert_eq!(meta_object_name("xcp_meta__min__params__delay_us"), Some(("min".into(), "params.delay_us".into())));
        // a static in a function, and a local static's suffix
        assert_eq!(meta_object_name("main::xcp_meta__comment__speed"), Some(("comment".into(), "speed".into())));
        assert_eq!(meta_object_name("xcp_meta__max__speed.0"), Some(("max".into(), "speed".into())));
        assert_eq!(meta_object_name("xcp_meta__unit"), None);
        assert_eq!(meta_object_name("gXcpData"), None);
    }

    #[test]
    fn values_print_as_short_as_states_them() {
        assert_eq!(cycle(0), "0 (sporadic)");
        assert_eq!(cycle(10_000_000), "10 ms");
        assert_eq!(cycle(2_000_000_000), "2 s");
        assert_eq!(cycle(250_000), "250 us");
        assert_eq!(cycle(1_500), "1500 ns");
        assert_eq!(number(4294967295.0), "4294967295");
        assert_eq!(number(-1e12), "-1e12");
        assert_eq!(number(0.25), "0.25");
        assert_eq!(number(1e-6), "1e-6");
        assert_eq!(limits(0.0, 0.0), ("-".to_string(), "-".to_string()));
        assert_eq!(limits(0.0, 100.0), ("0".to_string(), "100".to_string()));
        assert_eq!(type_name(-9), "FLOAT32_IEEE");
        assert_eq!(type_name(3), "type id 3");
        assert_eq!(printable("a\tb\nc\u{1}"), "a\\tb\\nc\\u{1}");
    }

    #[test]
    fn a_table_aligns_its_columns() {
        let mut table = Table::new(&["#", "name", "comment"]);
        table.row(["0".into(), "mainloop".into(), "the main loop".into()]);
        table.row(["10".into(), "x".into(), "".into()]);
        let mut out = String::new();
        table.render(&mut out);
        assert_eq!(out, "  #   name      comment\n  --  --------  -------------\n  0   mainloop  the main loop\n  10  x\n");
    }

    #[test]
    fn the_sections_of_an_xcplite_elf_are_decoded() {
        // An aarch64 PIE: its pointers are dynamically relocated, and this linker also wrote them into the file
        let data = std::fs::read(XCPLITE_ELF).unwrap();
        let image = Image::parse(&data).unwrap();
        let sections = image.sections();
        let names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["xcp_epk", "xcp_evts", "xcp_cals"]);
        let dumps: Vec<String> = sections.iter().map(|s| image.dump(s, 0)).collect();
        assert!(dumps[0].contains("  text   V101\n"), "{}", dumps[0]);
        // the event names are behind relocated pointers
        assert!(dumps[1].contains("4 event descriptors"), "{}", dumps[1]);
        for name in ["task", "foo", "bar", "mainloop"] {
            assert!(dumps[1].contains(&format!("  {name}  ")), "{name}: {}", dumps[1]);
        }
        // This xcplite predates the index pointer of tXcpCalSegDescriptor: 24-byte records, which are shown as bytes
        assert!(dumps[2].contains("not a whole number of 32-byte tXcpCalSegDescriptor records"), "{}", dumps[2]);
        assert!(dumps[2].contains("  0x00030270  104d0100 00000000 c84c0100 00000000  .M.......L......\n"), "{}", dumps[2]);
    }
}

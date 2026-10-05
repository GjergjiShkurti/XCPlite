//--------------------------------------------------------------------------------------------------------------------------------------------------
// Module elf_reader
// Read ELF files and extract debug information

#![allow(clippy::collapsible_else_if)]

use indexmap::IndexMap;
use regex::Regex;
use std::error::Error;
use std::ffi::OsStr;
use std::net::Ipv4Addr;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use xcp_registry::{McAddress, McDimType, McEvent, McObjectType, McSupportData, McValueType, Registry, RegistryError};

/*
Which information can be detected from ELF/DWARF:
- Events:
    name, compilation unit, function name and CFA offset, but index is unknown
- Memory segment name, type (naming convention name = reference page), address, length, but number is unknown
- Variables:
    variable name, typename, absolute address, frame offset, compilation unit, function name, namespace
    static variables in functions get the correct event
    local variables on stack get the correct CFA
    name, type, compilation unit, namespace, location (register or stack)
- Types:
    typedefs, structs, enums
    basic types: int8/16/32/64, uint8/16/32/64, float, double
    arrays 1D and 2D
    pointers (as ulong or ulonglong)

    Key benefits:
    - Instance names get prefixed with function name if local stack or static variables
    - All instances get the correct fixed event id, if there is one in their scope, otherwise default event id is 0
    - Event compilation unit, function and CFA is detected to enable local variable access

    Todo:
    - test arrays and nested structs

    - No DW_AT_location means optimized away

Detect TLS Variables:

TLS Variables:
Check for missing DW_AT_location + thread-local context
Look for variables referencing .tdata/.tbss sections
Parse DW_TAG_variable with TLS-specific location expressions
DW_OP_form_tls_address, etc


Tools:
dwarfdump --debug-info <filename>
dwarfdump --debug-info --name <varname> <filename>
objdump -h  <filename>
objdump --syms <filename>

Limitations:
- With -o1 most stack variables are in registers, have to be manually spilled to stack or captured
- Segment numbers and event index are not constant expressions, need to be read by XCP (current solution) or from the binary persistence file from the target

Possible future improvements:
- Thread load addressing mode
- C++ support,  this addressing support, namespaces
- Measurement of variables and function parameters in registers
- Just in time compilation of variable access expressions



*/

// Dwarf reader
// This module contains modified code adapted from https://github.com/DanielT/a2ltool
// Original code licensed under MIT/Apache-2.0
// Copyright (c) DanielT
mod debuginfo;
use debuginfo::{DbgDataType, DebugData, TypeInfo, VarInfo};

//use crate::xcp_client::xcp;

//------------------------------------------------------------------------
//  ELF reader and A2L creator

pub(crate) struct ElfReader {
    pub(crate) debug_data: DebugData,
}

impl ElfReader {
    /// The application's own name, as MC_APP declared it, or None when the ELF does not carry
    /// one. Used for the A2L's PROJECT and MODULE, which otherwise fall back to a placeholder
    /// that is the same for every application and so cannot tell two of them apart.
    pub fn app_name(&self) -> Option<&str> {
        self.debug_data.mci_app_name.as_deref()
    }

    /// Added to upstream (VsCANape issue 186). The A2L's PROJECT description: MC_APP's `.desc`,
    /// escaped as every text of an mc-instrument record is (`a2l_text`). "" when the ELF has no
    /// mci_app section; an error for a record from before it held one, as for the endpoint.
    pub fn project_description(&self) -> Result<String, Box<dyn Error>> {
        let Some(data) = self.mci_app_record()? else {
            return Ok(String::new());
        };
        let desc = &data[MCI_APP_ENDPOINT_END..MCI_APP_RECORD_LEN];
        let end = desc.iter().position(|&b| b == 0).unwrap_or(desc.len());
        Ok(a2l_text(&String::from_utf8_lossy(&desc[..end])))
    }

    /// The mci_app record, checked to be one of today's: None when the ELF has none.
    fn mci_app_record(&self) -> Result<Option<&[u8]>, Box<dyn Error>> {
        let Some(data) = self.debug_data.mci_app_data.as_ref() else {
            return Ok(None);
        };
        if data.len() == MCI_APP_NAME_LEN {
            return Err(format!(
                "the ELF's mci_app record names the application ('{}') but not where it listens: it was built before MC_APP recorded .bind, .port and .tcp there. \
                 Rebuild it, so that its offline A2L states the application's own endpoint",
                self.app_name().unwrap_or("")
            )
            .into());
        }
        if data.len() == MCI_APP_ENDPOINT_END {
            return Err(format!(
                "the ELF's mci_app record has no description: '{}' was built before MC_APP recorded .desc there. Rebuild it, so that its offline A2L carries its description",
                self.app_name().unwrap_or("")
            )
            .into());
        }
        if data.len() != MCI_APP_RECORD_LEN {
            return Err(format!(
                "the mci_app section holds {} bytes, which is not one application record of {MCI_APP_RECORD_LEN}: an application has one MC_APP",
                data.len()
            )
            .into());
        }
        Ok(Some(data))
    }

    /// Where the application's XCP server listens, as its MC_APP states it in the mci_app record
    /// (AppMeta in mc_meas_abi.hpp: name[64], bind[16], port u16 in the target's byte order, tcp u8,
    /// endpoint u8, desc[128]). None when the ELF has no mci_app section -- no MC_APP, so no server
    /// of mc-instrument's to describe.
    ///
    /// The offline A2L's transport block used to come from the command line alone, and the build
    /// rule passed 127.0.0.1, its own port and TCP for every application (issues 158, 225). An unset
    /// `.bind` and "0.0.0.0" are every interface, which 127.0.0.1 reaches; anything else is the one
    /// address the server listens on. A record that predates the endpoint -- the name alone, 64
    /// bytes -- is an error rather than a reason to fall back on the command line: that fallback is
    /// the guess this replaces.
    pub fn app_endpoint(&self) -> Result<Option<AppEndpoint>, Box<dyn Error>> {
        let Some(data) = self.mci_app_record()? else {
            return Ok(None);
        };
        let bind_bytes = &data[MCI_APP_NAME_LEN..MCI_APP_NAME_LEN + MCI_APP_BIND_LEN];
        let bind_end = bind_bytes.iter().position(|&b| b == 0).unwrap_or(bind_bytes.len());
        let bind = String::from_utf8_lossy(&bind_bytes[..bind_end]).to_string();
        let at = MCI_APP_NAME_LEN + MCI_APP_BIND_LEN;
        let port_bytes: [u8; 2] = data[at..at + 2].try_into().unwrap();
        let port = if self.debug_data.is_little_endian { u16::from_le_bytes(port_bytes) } else { u16::from_be_bytes(port_bytes) };
        let tcp = data[at + 2] != 0;
        match data[at + 3] {
            MCI_APP_NO_SERVER => Ok(Some(AppEndpoint::NoServer)),
            MCI_APP_SERVER => {
                let addr = if bind.is_empty() || bind == "0.0.0.0" {
                    Ipv4Addr::LOCALHOST
                } else {
                    bind.parse::<Ipv4Addr>()
                        .map_err(|_| format!("MC_APP's .bind \"{bind}\" in the mci_app record is not a dotted IPv4 address, and the application stops at startup on it"))?
                };
                Ok(Some(AppEndpoint::Server { addr, port, tcp, bind }))
            }
            other => Err(format!("the mci_app record says endpoint kind {other}, which this reader does not know").into()),
        }
    }

    /// What the xcplite server linked into the ELF answers to CONNECT and GET_DAQ_RESOLUTION_INFO,
    /// from the record xcplite.c places in the xcp_proto section: MAX_CTO, MAX_DTO, TIMESTAMP_MODE
    /// and TIMESTAMP_TICKS, four u16 in the target's byte order. None when the ELF has no such
    /// section -- no xcplite, or one from before the record existed. A record the A2L cannot state
    /// is an error rather than a value guessed past.
    pub fn server_protocol(&self) -> Result<Option<ServerProtocol>, Box<dyn Error>> {
        let Some(data) = self.debug_data.xcp_proto_data.as_ref() else {
            return Ok(None);
        };
        if data.len() < 8 {
            return Err(format!(
                "the xcp_proto section holds {} bytes, short of the 8 of MAX_CTO, MAX_DTO, TIMESTAMP_MODE and TIMESTAMP_TICKS",
                data.len()
            )
            .into());
        }
        let is_le = self.debug_data.is_little_endian;
        let rd_u16 = |o: usize| -> u16 {
            let a: [u8; 2] = data[o..o + 2].try_into().unwrap();
            if is_le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) }
        };
        let server = ServerProtocol {
            max_cto: rd_u16(0),
            max_dto: rd_u16(2),
            timestamp_mode: rd_u16(4),
            timestamp_ticks: rd_u16(6),
        };
        // CONNECT answers MAX_CTO in one byte, and the AML declares it a uchar
        if server.max_cto > 0xFF {
            return Err(format!("the xcp_proto section states a MAX_CTO of {}, which CONNECT cannot answer in one byte", server.max_cto).into());
        }
        if let Err(e) = server.timestamp_supported() {
            return Err(format!(
                "the xcp_proto section states TIMESTAMP_MODE 0x{:X}, with a {} the A2L has no name for",
                server.timestamp_mode, e
            )
            .into());
        }
        Ok(Some(server))
    }

    // Load debug information from the ELF file
    pub fn new(file_name: &str, verbose: usize, unit_idx_limit: usize) -> Option<ElfReader> {
        info!("Loading debug information from ELF file: {}", file_name);
        let debug_data = DebugData::load_dwarf(OsStr::new(file_name), verbose, unit_idx_limit);
        match debug_data {
            Ok(debug_data) => Some(ElfReader { debug_data }),
            Err(e) => {
                error!("Failed to load debug info from '{}': {}", file_name, e);
                None
            }
        }
    }

    // Get the McValueType for a given TypeInfo, which can be a basic type, pointer or array
    fn get_value_type(&self, reg: &mut Registry, type_info: &TypeInfo, object_type: McObjectType) -> McValueType {
        let type_size = type_info.get_size();
        match &type_info.datatype {
            DbgDataType::Uint8 => McValueType::Ubyte,
            DbgDataType::Uint16 => McValueType::Uword,
            DbgDataType::Uint32 => McValueType::Ulong,
            DbgDataType::Uint64 => McValueType::Ulonglong,
            DbgDataType::Sint8 => McValueType::Sbyte,
            DbgDataType::Sint16 => McValueType::Sword,
            DbgDataType::Sint32 => McValueType::Slong,
            DbgDataType::Sint64 => McValueType::Slonglong,
            DbgDataType::Float => McValueType::Float32Ieee,
            DbgDataType::Double => McValueType::Float64Ieee,
            DbgDataType::Struct { size, members } => {
                if let Some(type_name) = &type_info.name {
                    // Register the typedef struct for the value type typedef
                    if let Some(name) = type_info.name.as_ref() {
                        let _ = self.register_struct(reg, object_type, name.clone(), *size as usize, members);
                    }
                    McValueType::new_typedef(type_name.clone())
                } else {
                    warn!("Struct type without name in get_field_type");
                    McValueType::Ubyte
                }
            }
            DbgDataType::Enum { size, signed, enumerators } => McValueType::from_integer_size(*size as usize, *signed),

            DbgDataType::TypeRef(typeref, size) => {
                if let Some(typeinfo) = self.debug_data.types.get(typeref) {
                    self.get_value_type(reg, typeinfo, object_type)
                } else {
                    error!("TypeRef {} to unknown in get_field_type", typeref);
                    McValueType::Ubyte
                }
            }

            DbgDataType::Pointer(pointee, size) => {
                if *size == 4 {
                    McValueType::Ulong
                } else if *size == 8 {
                    McValueType::Ulonglong
                } else {
                    warn!("Unsupported pointer size {} in get_field_type", size);
                    McValueType::Ulonglong
                }
            }

            // These type are not a supported value type
            // DbgDataType::Bitfield | DbgDataType::Pointer | DbgDataType::FuncPtr | DbgDataType::Class | DbgDataType::Union | DbgDataType::Enum  | DbgDataType::Other =>
            _ => {
                warn!("Unsupported type in get_field_type: {:?}", &type_info.datatype);
                //assert!(false, "Unsupported type in get_field_type: {:?}", &type_info.datatype);
                McValueType::Ubyte
            }
        }
    }

    // Get the dimension type for a variable, which is used to determine the number of elements and dimensions for arrays
    fn get_dim_type(&self, reg: &mut Registry, type_info: &TypeInfo, object_type: McObjectType) -> McDimType {
        let type_size = type_info.get_size();
        match &type_info.datatype {
            DbgDataType::Array { arraytype, dim, stride, size } => {
                assert!(dim.len() != 0);
                let elem_type = self.get_value_type(reg, arraytype, object_type);
                if dim.len() > 2 {
                    warn!("Only 1D and 2D arrays supported, got {}D", dim.len());
                    McDimType::new(McValueType::Ubyte, 1, 1)
                } else if dim.len() == 1 {
                    McDimType::new(elem_type, dim[0] as u16, 1)
                } else {
                    McDimType::new(elem_type, dim[0] as u16, dim[1] as u16)
                }
            }
            _ => McDimType::new(self.get_value_type(reg, type_info, object_type), 1, 1),
        }
    }

    // Register a struct type in the registry, including its members
    fn register_struct(
        &self,
        reg: &mut Registry,
        object_type: McObjectType,
        type_name: String,
        size: usize,
        members: &IndexMap<String, (TypeInfo, u64)>,
    ) -> Result<(), Box<dyn Error>> {
        let typedef = reg.add_typedef(type_name.clone(), size)?;
        for (field_name, (type_info, field_offset)) in members {
            let field_dim_type = self.get_dim_type(reg, type_info, object_type);
            let field_mc_support_data = McSupportData::new(object_type);
            reg.add_typedef_field(&type_name, field_name.clone(), field_dim_type, field_mc_support_data, (*field_offset).try_into().unwrap())?;
        }
        Ok(())
    }

    // Find the addressing mode marker variable (naming convention "XCPLITE__<signature>") and return the signature, if found
    pub fn get_target_signature(&self) -> Option<&str> {
        // Iterate over variables and look for XCPlite addressing mode marker
        for (var_name, var_infos) in &self.debug_data.variables {
            if !var_name.starts_with("XCPLITE__") {
                continue;
            }
            if let Some(signature) = var_name.strip_prefix("XCPLITE__") {
                return Some(signature);
            }
        }
        return None;
    }

    /// Register the EPK string and the address a master must read it from.
    ///
    /// The A2L's `ADDR_EPK` is a *protocol* address, not the ELF address of the string. A master
    /// that verifies the A2L against the ECU (CANape does, on going online) issues
    /// `SET_MTA(ADDR_EPK)` + `UPLOAD`, and xcplite serves the EPK from exactly one place:
    ///
    ///   * with an EPK calibration segment and `XCP_ADDR_EXT_SEG == 0` -- what mc-instrument builds
    ///     -- segment 0 offset 0, i.e. `XcpAddrEncodeSegIndex(0, 0)` = `0x80000000`;
    ///   * otherwise the reserved absolute address `0xFFFFFF00`, which `XcpSetMta` special-cases.
    ///
    /// Writing the ELF address instead is what the runtime A2L never did and this route always did.
    /// The consequence is not subtle and it is not visible to our own kernel pipeline, which never
    /// reads the EPK: CANape sends `SET_MTA addrext=0 addr=<elf addr>`, xcplite finds an address
    /// below 0x80000000 on the segment extension, warns that it is "converting to ABS addressing
    /// mode", reads whatever that offset means from the module base, and answers `ERR 0x24`
    /// (access denied). CANape reports "Error message from ECU! The memory location is not
    /// accessible (UPLOAD,24H)" and refuses to switch the device online. The application is
    /// perfectly measurable and completely unusable.
    ///
    /// See `xcplite.c:626` and `xcp_cfg.h:238-266`.
    pub fn register_epk_addr_info(&self, reg: &mut Registry, segment_relative: bool, verbose: usize) {
        info!("===============================================================");
        if self.debug_data.epk_addr > 0 {
            let epk = self.debug_data.epk_string.clone().unwrap_or_else(|| "<unknown>".to_string());
            // XCP_ADDR_EPK for the two addressing schemes this reader can be given. The EPK
            // segment always has index 0 (`register_segments` forces it), so the offset is 0.
            const XCP_ADDR_EPK_SEG: u32 = 0x8000_0000;
            const XCP_ADDR_EPK_ABS: u32 = 0xFFFF_FF00;
            let epk_addr = if segment_relative { XCP_ADDR_EPK_SEG } else { XCP_ADDR_EPK_ABS };
            info!("EPK string: '{}'", epk);
            info!(
                "EPK section is at 0x{:08X} in the ELF; ADDR_EPK is the protocol address 0x{:08X}, which is where xcplite serves it",
                self.debug_data.epk_addr, epk_addr
            );
            reg.application.set_version(epk, epk_addr);
        } else {
            warn!("EPK segment memory section not found in ELF file");
        }
    }

    // Register segments from segment creation markers (calseg__name) found in the code
    pub fn register_segments(&self, reg: &mut Registry, seg_relative: bool, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");
        info!(
            "Registering segment information {}:",
            if !seg_relative { "(absolute addressing mode)" } else { "(relative addressing mode)" }
        );

        // Step 1
        // Iterate over all variables and look for segment definition markers, which are created by the CalSegCreate or CalBlkCreate macros
        // Naming convention is "calseg__<name>" or "calblk__<name>"
        // Sort the vector by address to ensure the segments are processed in the order they are defined in the code
        // Index in the vector is now the segment number
        let mut seg_definitions: Vec<(String, &Vec<VarInfo>, u64, Option<u8>)> = Vec::new();
        for (var_name, var_infos) in &self.debug_data.variables {
            let is_calseg = var_name.starts_with("calseg__");
            let is_calblk = var_name.starts_with("calblk__");
            if is_calseg || is_calblk {
                let (seg_name, seg_number) = if is_calseg {
                    (var_name.strip_prefix("calseg__").unwrap_or(var_name), Some(0))
                } else {
                    (var_name.strip_prefix("calblk__").unwrap_or(var_name), None)
                };
                // One marker, one segment. Where the debug info still reports the same marker
                // more than once, take the entry that has an address rather than the first:
                // a marker without one contributes 0, and segment numbers come from sorting on
                // this address, so a 0 would silently renumber every segment after it. Asserting
                // here used to abort the whole A2L generation over debug info that is perfectly
                // legal -- a hard stop on a valid program is never the right answer for a
                // generator.
                let var_info = var_infos.iter().find(|info| info.address.1 != 0).unwrap_or(&var_infos[0]);
                // Added to upstream (issue 144): two markers of one name in different namespaces are
                // two segments -- `one::Params` and `two::Params` -- that xcplite, which keys
                // segments by name, makes one, and that the A2L could only name alike. The second
                // reads the first one's page, or is never created. mc-instrument refuses to start such
                // an application, so no A2L is written for it either. Markers in one namespace stay
                // one segment, as xcplite has them: its own CalSegDecl in a header defines one per
                // file that includes it.
                if let Some(other) = var_infos.iter().find(|info| info.address.1 != 0 && info.namespaces != var_info.namespaces) {
                    let qualified = |info: &VarInfo| {
                        let mut path: Vec<&str> = info.namespaces.iter().rev().map(String::as_str).collect();
                        path.push(seg_name);
                        path.join("::")
                    };
                    return Err(format!(
                        "two calibration segments are both named '{seg_name}' ({} and {}): xcplite and the A2L would see one segment. \
                         Rename one; no A2L is written",
                        qualified(var_info),
                        qualified(other)
                    )
                    .into());
                }
                let mut seg_descr_addr = var_info.address.1;
                if seg_name == "epk" {
                    // EPK segment is a special case, it has always index = 0
                    seg_descr_addr = 0;
                } else if seg_descr_addr == 0 {
                    log::warn!(
                        "Calibration segment marker '{var_name}' has no address in the debug info. Segment numbering is taken \
                         from marker addresses, so this segment may be numbered wrongly. Declare the marker with external \
                         linkage so the compiler emits a location for it."
                    );
                }
                seg_definitions.push((seg_name.to_string(), var_infos, seg_descr_addr, seg_number));
            }
        }
        seg_definitions.sort_by_key(|x| x.2);
        // Calculate the segment numbers for calseg, calblk doues not have a number
        let mut seg_number: u8 = 0;
        for i in 0..seg_definitions.len() {
            if let Some(0) = seg_definitions[i].3 {
                seg_definitions[i].3 = Some(seg_number);
                seg_number += 1;
            }
        }

        // Print the found segment definition markers
        if verbose >= 1 {
            info!("Found {} segment definition marker variables:", seg_definitions.len());
            for (seg_index, (var_name, var_infos, var_address, seg_number)) in seg_definitions.iter().enumerate() {
                info!("{}: '{}' - number={:?}, addr={:08X}'", seg_index, var_name, seg_number, var_address);
                if verbose >= 2 {
                    let var_info = &var_infos[0];
                    let function_name = if let Some(f) = var_info.function.as_ref() { f.as_str() } else { "" };
                    let unit_idx = var_info.unit_idx;
                    let unit_name = if let Some(name) = self.debug_data.make_simple_unit_name(unit_idx) {
                        name
                    } else {
                        format!("{unit_idx}")
                    };
                    info!("  found in {}:'{}'", unit_name, function_name);
                }
            }
        }

        // A segment that does not fit xcplite's build-time room is not created by the application,
        // so it is left out here too (CalsegRoom). The numbers above assumed every segment exists;
        // `next_number` hands them out to the segments that do, as the application numbers them.
        let mut room = self.calseg_room(seg_relative);
        if room.is_none() && !seg_definitions.is_empty() {
            warn!(
                "xcplite's calibration limits (gXcpData.cal_seg_list) are not in this binary's debug info: every calibration segment \
                 goes into the A2L, including one the application may have had no room for"
            );
        }
        let mut next_number: u8 = 0;

        // Step 2
        // Iterate over the segment definitions and register the segments in the registry
        for (seg_index, (seg_name, var_infos, var_address, seg_number)) in seg_definitions.iter().enumerate() {
            let var_info = &var_infos[0];
            let seg_length: u16;
            let seg_addr: u64;

            // Special case for EPK segment, which does not have a reference page variable, but the segment address and length may be stored in the debug data from the EPK section
            if seg_name == "epk" {
                if let Some(epk_str) = self.debug_data.epk_string.as_ref() {
                    seg_length = epk_str.len().try_into().expect("EPK string length exceeds 64K");
                    seg_addr = self.debug_data.epk_addr;
                } else {
                    error!("No EPK segment memory section in ELF file, segment '{}' skipped", seg_name);
                    continue; // skip this variable
                }
            }
            // Not epk segment
            else {
                // Lookup the reference page variable (by naming convention: same as segment name!) information
                // This may be ambigous, so we use some heuristics to select the right variable
                // @@@@ TODO use the commandline compilation unit filter here
                let seg_var_info = if let Some(x) = self.debug_data.variables.get(seg_name) {
                    let mut valid_candidates: Vec<_> = x.iter().filter(|var_info| var_info.address.0 == 0 && var_info.address.1 != 0).collect();
                    // Changed from upstream (issue 143). A segment declared with mc-instrument's
                    // MC_CALSEG has its page in namespace mci_pages, inside the namespaces of its
                    // calseg__<name> marker, which pins it however many other variables share the
                    // name. The name alone did not: any static of that name in the segment's file --
                    // `static int Alpha;` in a function -- left more than one candidate, and the
                    // segment was skipped. Upstream's same-unit tie-break stays for a page declared
                    // any other way.
                    if let Some(page) = mci_page(&valid_candidates, var_infos) {
                        valid_candidates = vec![page];
                    } else if valid_candidates.len() > 1 {
                        let same_unit_candidates: Vec<_> = valid_candidates.iter().copied().filter(|candidate| candidate.unit_idx == var_info.unit_idx).collect();
                        if same_unit_candidates.len() == 1 {
                            valid_candidates = same_unit_candidates;
                        }
                    }
                    if valid_candidates.len() != 1 {
                        error!(
                            "Calibration segment reference page variable '{}' has {} usable definitions, expected 1 ({} total DWARF entries)",
                            seg_name,
                            valid_candidates.len(),
                            x.len()
                        );
                        if verbose >= 1 {
                            for candidate in x {
                                let unit_name = self.debug_data.make_simple_unit_name(candidate.unit_idx).unwrap_or_else(|| candidate.unit_idx.to_string());
                                let function_name = candidate.function.as_deref().unwrap_or("<global>");
                                info!(
                                    "  candidate in {}:'{}', addr_class={}, addr=0x{:08X}",
                                    unit_name, function_name, candidate.address.0, candidate.address.1
                                );
                            }
                        }
                        // Changed from upstream (issue 143): an error, not a skip. The application
                        // creates this segment whether or not its page can be found here, and
                        // segments are numbered and addressed by position, so leaving it out gave
                        // every later segment the address of the one before it at run time -- an
                        // A2L that writes to the wrong segment, from a run that exited 0.
                        return Err(format!(
                            "calibration segment '{seg_name}': its reference page cannot be told apart from {} variables of that name, \
                             so no A2L is written (rerun with -v for the candidates)",
                            valid_candidates.len()
                        )
                        .into());
                    }
                    valid_candidates[0]
                } else {
                    // Changed from upstream (issue 143), for the reason above.
                    return Err(format!("calibration segment '{seg_name}': no reference page variable of that name, so no A2L is written").into());
                };

                // Determine segment length
                seg_length = {
                    if let Some(type_info) = self.debug_data.types.get(&seg_var_info.typeref) {
                        info!(
                            "Calibration segment '{}' type information found, type={}, size = {}",
                            seg_name,
                            type_info.name.as_ref().map_or("<unnamed>", |s| s.as_str()),
                            type_info.get_size()
                        );
                        if verbose >= 2 {
                            info!("  type = {}", type_info);
                        }
                        type_info.get_size().try_into().expect("segment size exceeds 64K")
                    } else {
                        error!("Could not determine length type for segment {}", seg_name);
                        0
                    }
                };

                // Determine segment address
                // @@@@ TODO: handle signed relative encoding
                seg_addr = seg_var_info.address.1;
                if !(seg_length > 0 && seg_addr > 0 && seg_var_info.address.0 == 0) {
                    // Changed from upstream (issue 143): an error, not a skip, as for a page that
                    // cannot be found above.
                    return Err(format!(
                        "calibration segment '{seg_name}': its reference page has an invalid address {seg_addr:#x} or size {seg_length:#x}, \
                         so no A2L is written"
                    )
                    .into());
                }

                info!(
                    "Calibration segment '{}' default page variable found in debug data: Address = {:#x}, Size = {:#x}",
                    seg_name, seg_addr, seg_length
                );
            } // not EPK segment

            // Find the segment by name in the registry
            if let Some(reg_seg) = reg.cal_seg_list.find_cal_seg(seg_name) {
                info!("Calibration segment '{}' {}:0x{:08X} found in registry", seg_name, reg_seg.addr_ext, reg_seg.addr);
                // Segment relative addressing mode
                if reg_seg.addr == 0x80000000 + ((reg_seg.index as u32) << 16) {
                    info!("  with segment relative addressing");
                    // Check if length matches
                    if reg_seg.size == seg_length as u32 {
                        reg_seg.set_mem_addr(seg_addr);
                        info!("  matches existing registry entry");
                    } else {
                        warn!("Calibration segment '{}' length does not match existing registry entry", seg_name);
                    }
                }
                // Segment absolute addressing mode
                else {
                    // Check if address and length match
                    if reg_seg.addr as u64 != seg_addr {
                        warn!(
                            "Calibration segment '{}' address does not match existing registry entry, reg = {:08X} vs. {:08X}",
                            seg_name, reg_seg.addr, seg_addr
                        );
                    } else if reg_seg.size != seg_length as u32 {
                        warn!(
                            "Calibration segment '{}' length does not match existing registry entry, reg = {} vs. {}",
                            seg_name, reg_seg.size, seg_length
                        );
                    } else {
                        info!("Calibration segment '{}' matches existing registry entry", seg_name);
                    }
                } // absolute addressing mode
            }
            // already existing
            //
            // If not existing, create the segment
            // Use segment relative or absolute addressing mode
            else {
                info!("Calibration segment '{}' not yet defined in registry", seg_name);

                if let Some(room) = room.as_mut()
                    && let Err(why) = room.admit(seg_name, seg_length)
                {
                    warn!(
                        "Calibration segment '{}' is left out of the A2L: {}. The application has no room for it either, runs without it, and \
                         says so at startup",
                        seg_name, why
                    );
                    continue;
                }
                let number = seg_number.map(|_| {
                    next_number += 1;
                    next_number - 1
                });

                if seg_relative {
                    // Add in segment relative addressing mode
                    let res = reg.cal_seg_list.add_cal_seg(seg_name.to_string(), number, seg_length as u32);
                    if let Err(e) = res {
                        error!("Failed to add calibration segment '{}': {}", seg_name, e);
                        continue;
                    }
                } else {
                    // Absolute addressing mode
                    if seg_addr >= 0xFFFFFFFF {
                        error!(
                            "Calibration segment '{}' has 64 bit address {:#x}, which does not fit the 32 bit XCP address range",
                            seg_name, seg_addr
                        );
                        continue; // skip 
                    }
                    if seg_index >= 255 {
                        error!("Too many calibration segments, segment index {} does not fit in u8 for segment '{}'", seg_index, seg_name);
                        continue; // skip
                    }
                    if seg_length == 0 {
                        error!("Calibration segment '{}' has zero length, skipped", seg_name);
                        continue; // skip
                    }
                    let res = reg
                        .cal_seg_list
                        .add_cal_seg_by_addr(seg_name.to_string(), number, 0, seg_addr as u32, seg_length as u32);
                    if let Err(e) = res {
                        error!("Failed to add calibration segment '{}': {}", seg_name, e);
                        continue;
                    }
                }

                // Set memory address for later lookup of potential calibration variables in this segment
                let new_seg = reg.cal_seg_list.find_cal_seg(seg_name).unwrap();
                new_seg.set_mem_addr(seg_addr);

                info!(
                    "Created segment {}: '{}':  addr = 0x{:08X}, size = {}, mem_addr = 0x{:08X}",
                    seg_index, seg_name, new_seg.addr, new_seg.size, new_seg.mem_addr
                );
            } // not already existing
        } // for
        Ok(())
    }

    // Register events from event creation markers (evt__name) in the code
    pub fn register_events(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");

        info!("Registering event information:");

        // Get the address of the XCP event descriptor memory section
        let xcp_event_section_addr = self.debug_data.get_event_section_addr();

        // An event name belongs to one MEASURE. Each site defines its own evt__<name> record in
        // xcp_evts, so a name defined at two addresses there is two sites -- one event with one DAQ
        // list, triggered from two places, which the running application also refuses. Counted by
        // address, not by DWARF definition: an inline function's MEASURE is one site however many
        // units include it (the linker keeps one COMDAT copy, and the other units' definitions point
        // at it or, for a discarded copy, at no address in the section).
        let evt_section = self.debug_data.sections.get("xcp_evts").copied();
        let mut duplicate_events: Vec<String> = Vec::new();
        for (var_name, var_infos) in &self.debug_data.variables {
            let Some(evt_name) = var_name.strip_prefix("evt__") else {
                continue;
            };
            let Some((start, end)) = evt_section else {
                break;
            };
            // One place per distinct record address: the first definition found at it.
            let mut sites: std::collections::BTreeMap<u64, &VarInfo> = std::collections::BTreeMap::new();
            for v in var_infos.iter().filter(|v| v.address.1 >= start && v.address.1 < end) {
                sites.entry(v.address.1).or_insert(v);
            }
            if sites.len() > 1 {
                let places: Vec<String> = sites
                    .values()
                    .map(|v| {
                        let unit = self.debug_data.make_simple_unit_name(v.unit_idx).unwrap_or_else(|| format!("{}", v.unit_idx));
                        format!("{}:{}", unit, v.function.as_deref().unwrap_or("?"))
                    })
                    .collect();
                duplicate_events.push(format!("'{}' ({} sites: {})", evt_name, sites.len(), places.join(", ")));
            }
        }
        if !duplicate_events.is_empty() {
            duplicate_events.sort();
            return Err(format!(
                "event name used by more than one MEASURE: {}. An event belongs to one call site -- two would share one \
                 DAQ list and trigger it from two places. Give each MEASURE an event name of its own. A MEASURE in a \
                 `static` function in a header is one site per file that includes it: move that function into one .cpp file.",
                duplicate_events.join("; ")
            )
            .into());
        }

        // Iterate over variables
        for (var_name, var_infos) in &self.debug_data.variables {
            // Skip standard library variables and system/compiler internals (__<name>)s
            // Skip global XCP variables (gXCP.. and gA2L..)
            if var_name.starts_with("__") || var_name.starts_with("gXcp") || var_name.starts_with("gA2l") {
                continue;
            }

            // Event definitions (by markers from DaqCreateEvent macro)
            // (thread local) static evt__<name>, name is event name
            if var_name.starts_with("evt__") {
                // remove the "evt__" prefix
                let evt_name = var_name.strip_prefix("evt__").unwrap_or("unnamed");
                let evt_unit_idx = var_infos[0].unit_idx;
                let evt_unit_name = if let Some(name) = self.debug_data.make_simple_unit_name(evt_unit_idx) {
                    name
                } else {
                    format!("{evt_unit_idx}")
                };

                let evt_function = if let Some(f) = var_infos[0].function.as_ref() { f.as_str() } else { "" };
                info!(
                    "Event definition for event '{}' found in {}:{}, addr = {:#x}",
                    evt_name, evt_unit_name, evt_function, var_infos[0].address.1
                );
                // Find the event already exists in the registry
                if let Some(_evt) = reg.event_list.find_event(evt_name, 0) {
                    continue; // event already exists
                }
                // Create a new event and try to determine the event number from the event memory section
                else {
                    if xcp_event_section_addr > 0 {
                        let event_id: u16 = ((var_infos[0].address.1 - xcp_event_section_addr) / 16) as u16; // @@@@ size of tXcpEventDescriptor hardcoded
                        reg.event_list.add_event(McEvent::new(evt_name.to_string(), 0, event_id, 0)).unwrap();
                        info!("New event '{}' found: event id = {}", evt_name, event_id);
                        continue; // event id has to be fixed later, for now we just create it with a unique id based on the address of the event marker variable
                    } else {
                        reg.event_list.add_event(McEvent::new(evt_name.to_string(), 0, 0xFFFF, 0)).unwrap();
                        warn!("New event '{}' found, created with undefined event id 0xFFFF", evt_name);
                    }
                }
            }
        }
        Ok(())
    }

    // Find event triggers in the code and register their location (compilation unit, function, CFA offset)
    pub fn register_event_locations(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");

        info!("Registering event locations:");

        // Iterate over variables
        for (var_name, var_infos) in &self.debug_data.variables {
            // Skip standard library variables and system/compiler internals (__<name>)s
            // Skip global XCP variables (gXCP.. and gA2L..)
            if var_name.starts_with("__") || var_name.starts_with("gXcp") || var_name.starts_with("gA2l") {
                continue;
            }

            // trg__<event_name> (thread local static, name is event name)
            // Event definitions (thread local static variables)
            if var_name.starts_with("trg__") {
                // More than one definition is one MEASURE in an inline function, described once per
                // unit that includes it: two sites with one event name were refused by
                // register_events. The copy the linker kept is the one with an address.
                let var_info = var_infos.iter().find(|v| v.address.1 != 0).unwrap_or(&var_infos[0]);

                // Get the event name from format  "trg__<tag>__<eventname>" prefix
                let s = var_name.strip_prefix("trg__").unwrap_or("unnamed");
                let mut parts = s.split("__");
                let evt_mode = parts.next().unwrap_or("");
                let evt_name = parts.next().unwrap_or("");

                let evt_unit_idx = var_info.unit_idx;
                let evt_unit_name = if let Some(name) = self.debug_data.make_simple_unit_name(evt_unit_idx) {
                    name
                } else {
                    format!("{evt_unit_idx}")
                };
                let evt_function = if let Some(f) = var_info.function.as_ref() { f.as_str() } else { "" };
                info!(
                    "  Event {} trigger found in {}:{}, address resolver mode {}",
                    evt_name, evt_unit_name, evt_function, evt_mode
                );

                // Find the event in the registry
                if let Some(_evt) = reg.event_list.find_event(evt_name, 0) {
                    // Try to lookup the canonical stack frame address offset from the function name
                    let mut evt_cfa: i32 = 0;
                    for cfa_info in self.debug_data.cfa_info.iter() {
                        if cfa_info.unit_idx == evt_unit_idx && cfa_info.function == evt_function {
                            if let Some(x) = cfa_info.cfa_offset {
                                evt_cfa = x as i32;
                            } else {
                                warn!("Could not determine CFA offset for function '{}'", evt_function);
                            }
                            break;
                        }
                    }

                    if verbose >= 1 {
                        info!("  Event '{}' trigger in function '{}', cfa = {}", evt_name, evt_function, evt_cfa);
                    }

                    // Store the unit and function name and canonical stack frame address offset for this event trigger
                    match reg.event_list.set_event_location(evt_name, evt_unit_idx, evt_function, evt_cfa) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Failed to set event location for event '{}': {}", evt_name, e);
                        }
                    }
                } else {
                    error!("Event '{}' for trigger not found in registry", evt_name);
                }
                continue; // skip this variable
            }
        }
        Ok(())
    }

    pub fn register_variables(
        &self,
        reg: &mut Registry,
        seg_relative: bool,
        verbose: usize,
        unit_idx_limit: usize,
        name_filter: &str,
        unit_filter: &str,
        id_addressing: bool,
    ) -> Result<(), Box<dyn Error>> {
        // Load debug information from the ELF file
        info!("===============================================================");
        info!("Registering variables:");

        // Compile name filter regex if specified
        let name_regex: Option<Regex> = if name_filter.is_empty() {
            None
        } else {
            match Regex::new(name_filter) {
                Ok(re) => {
                    info!("Variable name filter: '{}'", name_filter);
                    Some(re)
                }
                Err(e) => {
                    return Err(format!("Invalid --elf-var-filter regex '{}': {}", name_filter, e).into());
                }
            }
        };

        // The reference pages of the declared calibration segments and blocks. The compilation
        // unit filter narrows the sweep of *incidental* variables -- without it the A2L also
        // describes the XCP server's own internals -- but a declared segment is not incidental:
        // register_segments has already created it, and its objects are what the A2L is being
        // generated for. Filtering its page out left the segment in the registry with no
        // INSTANCE and no TYPEDEF_STRUCTURE behind it, so the A2L came out with every
        // measurement, no calibration at all, and a dangling SUB_GROUP -- reported as a warning
        // on a run that still exited successfully. A calibration block (calblk__<name>) is the
        // same declaration through the block API, and its page is found by the same name.
        let calseg_pages: std::collections::HashSet<String> = self
            .debug_data
            .variables
            .keys()
            .filter_map(|marker| marker.strip_prefix("calseg__").or_else(|| marker.strip_prefix("calblk__")))
            .filter(|name| *name != "epk")
            .map(str::to_string)
            .collect();

        // Compile compilation unit filter regex if specified
        let unit_regex: Option<Regex> = if unit_filter.is_empty() {
            None
        } else {
            match Regex::new(unit_filter) {
                Ok(re) => {
                    info!("Compilation unit filter: '{}'", unit_filter);
                    Some(re)
                }
                Err(e) => {
                    return Err(format!("Invalid --elf-unit-filter regex '{}': {}", unit_filter, e).into());
                }
            }
        };

        // Iterate over variables
        for (var_name, var_infos) in &self.debug_data.variables {
            // Skip standard library variables and system/compiler internals (__<name>)s
            // Skip global XCP variables (gXCP.. and gA2L..) and special marker variables (calseg__, evt__, trg__, xcp_meta__)
            if var_name.starts_with("__")
                || var_name.starts_with("gXcp")
                || var_name.starts_with("gA2l")
                || var_name.starts_with("calseg__")
                || var_name.starts_with("calblk__")
                || var_name.starts_with("evt__")
                || var_name.starts_with("trg__")
                || var_name.starts_with("xcp_meta__")
            {
                continue;
            }

            // Apply name filter
            if let Some(ref re) = name_regex {
                if !re.is_match(var_name) {
                    continue;
                }
            }

            if var_infos.is_empty() {
                warn!("Variable '{}' has no variable info", var_name);
            }

            let mut a2l_name = var_name.to_string();
            let mut xcp_event_id = 0; // default event id is 0, async event in transmit thread

            // Under identifier addressing a captured variable is not measured from here either (see
            // the check on each instance below), so its event is not looked up, nor warned about.
            if id_addressing && var_name.starts_with("daq__") {
                continue;
            }

            // daq__<event_name>__<var_name> (local scope static variables)
            // Check for captured variables with format "daq__<event_name>__<var_name>"
            if var_name.starts_with("daq__") {
                // remove the "daq__" prefix
                let new_name = var_name.strip_prefix("daq__").unwrap_or(var_name);
                // get event name and variable name
                let mut parts = new_name.split("__");
                let event_name = parts.next().unwrap_or("");
                let var_name = parts.next().unwrap_or("");
                // Find the event in the registry
                if let Some(id) = reg.event_list.find_event(event_name, 0) {
                    xcp_event_id = id.id;
                    if event_name.len() > 0 {
                        a2l_name = format!("{}.{}", event_name, var_name);
                    } else {
                        a2l_name = var_name.to_string();
                    }
                } else {
                    warn!("Event '{}' for captured variable '{}' not found in registry", event_name, var_name);
                    continue; // skip this variable
                }
            }

            // Count variables with this name in compilation unit 0
            let count = var_infos.iter().filter(|v| v.unit_idx <= unit_idx_limit).count();

            // Process all variable with this name in different scopes and namespaces
            for var_info in var_infos {
                // @@@@ TODO: Create only variables from specified compilation unit
                if var_info.unit_idx > unit_idx_limit {
                    continue;
                }

                // Apply compilation unit filter, except to a calibration segment's or block's page
                if let Some(ref re) = unit_regex
                    && !calseg_pages.contains(var_name)
                {
                    let cu_name = self.debug_data.make_simple_unit_name(var_info.unit_idx).unwrap_or_else(|| format!("{}", var_info.unit_idx));
                    if !re.is_match(&cu_name) {
                        continue;
                    }
                }

                // Identifier addressing (issue 51). Every measurement comes from the mci_meas
                // records (register_mci_measurements), so this sweep contributes calibration
                // characteristics only: variables at an absolute address inside a segment's page.
                // Anything else is dropped here, before the event lookup and the frame-offset
                // arithmetic below, which warned -- "Variable 'counter' skipped, has offset ... does not
                // fit" -- about locals that are measured all the same, through their identifiers. A
                // swept measurement would also have duplicated one under an absolute address and taken
                // in the library's own globals.
                if id_addressing
                    && (var_info.address.0 != 0 || var_info.address.1 == 0 || reg.cal_seg_list.find_cal_seg_by_mem_address(var_info.address.1).is_none())
                {
                    continue;
                }

                let var_function = if let Some(f) = var_info.function.as_ref() { f.as_str() } else { "" };

                // Address encoder
                let mem_addr_ext: u8 = var_info.address.0;
                let mem_addr: u64 = if mem_addr_ext == 0 {
                    // Encode absolute addressing mode
                    if var_info.address.1 == 0 {
                        debug!("Variable '{}' in function '{}' skipped, no address", var_name, var_function);
                        continue; // skip this variable
                    } else if var_info.address.1 >= 0xFFFFFFFF {
                        warn!(
                            "Variable '{}' skipped, has 64 bit address {:#x}, which does not fit the 32 bit XCP address range",
                            var_name, var_info.address.1
                        );
                        continue; // skip this variable
                    } else {
                        // find an event triggered in this function
                        if let Some(event) = reg.event_list.find_event_by_location(var_info.unit_idx, var_function) {
                            xcp_event_id = event.id;
                            info!("Variable '{}' is local to function '{}', using event id = {}", var_name, var_function, xcp_event_id);
                        } else {
                            debug!("Variable '{}' is local to function '{}', but no event found", var_name, var_function);
                        }
                        // multiple variables with this name, prefix with function name
                        if count > 1 {
                            if var_function.len() > 0 {
                                a2l_name = format!("{}.{}", var_function, var_name);
                            } else {
                                a2l_name = var_name.to_string();
                            }
                        }
                        var_info.address.1
                    }
                }
                // Encode relative addressing mode
                else if mem_addr_ext == 2 {
                    // Find an event id for this local variable
                    if let Some(event) = reg.event_list.find_event_by_location(var_info.unit_idx, var_function) {
                        // Set the event id for this function
                        // Prefix the variable with the function name
                        xcp_event_id = event.id;
                        let cfa: i64 = event.cfa as i64;
                        if var_function.len() > 0 {
                            a2l_name = format!("{}.{}", var_function, var_name);
                        } else {
                            a2l_name = var_name.to_string();
                        }
                        debug!(
                            "Variable '{}' is local to function '{}', using event id = {}, dwarf_offset = {} cfa = {}",
                            var_name,
                            var_function,
                            xcp_event_id,
                            (var_info.address.1 as i64 - 0x80000000) as i64,
                            cfa
                        );

                        // @@@@ TODO: Create functions instead of constants for relative address encoding
                        // Encode dyn addressing mode A2L/XCP address from offset and event id
                        let offset: i64 = var_info.address.1 as i64 - 0x80000000 + cfa;
                        if offset < -(McAddress::XCP_ADDR_EXT_DYN_OFFSET_OFFSET as i64)
                            || offset > (McAddress::XCP_ADDR_EXT_DYN_OFFSET_MASK as i64 - McAddress::XCP_ADDR_EXT_DYN_OFFSET_OFFSET as i64)
                        {
                            warn!(
                                "Variable '{}' skipped, has offset {} which does not fit the XCP dynamic addressing mode range",
                                var_name, offset
                            );
                            continue; // skip this variable
                        }

                        (((offset + McAddress::XCP_ADDR_EXT_DYN_OFFSET_OFFSET as i64) as u64) & McAddress::XCP_ADDR_EXT_DYN_OFFSET_MASK as u64)
                            | ((event.id as u64) << McAddress::XCP_ADDR_EXT_DYN_OFFSET_BITS)
                    } else {
                        debug!("Variable '{}' skipped, could not find event for dyn addressing mode", var_name);
                        continue; // skip this variable
                    }
                }
                // @@@@ TODO: Handle other address extensions
                else {
                    debug!("Variable '{}' skipped, has unsupported address extension {:#x}", var_name, mem_addr_ext);
                    continue; // skip this variable
                };

                // Check if the absolute address is in a calibration segment or block
                // For segments with segment relative and absolute addressing mode, we always need to check with the memory address of the segment, not the a2l address
                let seg_name = reg.cal_seg_list.find_cal_seg_by_mem_address(mem_addr);
                let (object_type, mc_addr) = if let Some(seg_name) = seg_name {
                    let seg = reg.cal_seg_list.find_cal_seg(&seg_name).unwrap();
                    let offset: u16 = (mem_addr - seg.mem_addr).try_into().unwrap();
                    // Address extension of characteristics in memory segments is always 0, hardcoded here
                    // @@@@ NOTE: This might change in the future
                    (McObjectType::Characteristic, McAddress::new_a2l(seg.addr + offset as u32, 0))
                } else {
                    // Create a McAddress with event id, mem_addr is relative or absolute
                    // @@@@ TODO: Not implemented dependency on target addressing scheme
                    // Address extension might be 0, 1, 2 depending on the target addressing scheme
                    let addr_ext = if seg_relative && mem_addr_ext == 0 {
                        1 // set to absolute addressing mode
                    } else {
                        mem_addr_ext
                    };
                    (McObjectType::Measurement, McAddress::new_a2l_with_event(xcp_event_id, mem_addr as u32, addr_ext))
                };

                // Register measurement variable if possible
                if let Some(type_info) = self.debug_data.types.get(&var_info.typeref) {
                    // Register supported variable types in the registry
                    let type_size = type_info.get_size();
                    let type_name = &type_info.name;
                    match &type_info.datatype {
                        DbgDataType::Uint8
                        | DbgDataType::Uint16
                        | DbgDataType::Uint32
                        | DbgDataType::Uint64
                        | DbgDataType::Sint8
                        | DbgDataType::Sint16
                        | DbgDataType::Sint32
                        | DbgDataType::Sint64
                        | DbgDataType::Float
                        | DbgDataType::Double
                        | DbgDataType::Array { .. }
                        | DbgDataType::Struct { .. } => {
                            info!(
                                "Add {} for {}: addr = {}:0x{:08x}",
                                if object_type == McObjectType::Characteristic { "characteristic" } else { "measurement" },
                                a2l_name,
                                mem_addr_ext,
                                mem_addr
                            );
                            if verbose >= 2 {
                                info!("{}", type_info);
                            }
                            let dim_type = self.get_dim_type(reg, type_info, object_type);
                            let res = reg.instance_list.add_instance(a2l_name.clone(), dim_type, McSupportData::new(object_type), mc_addr);
                            match res {
                                Ok(_) => {
                                    if verbose >= 1 {
                                        info!(
                                            "  Registered variable '{}' with type '{}', size = {}, event id = {}",
                                            a2l_name,
                                            type_name.as_ref().unwrap_or(&"<unnamed>".to_string()),
                                            type_size,
                                            xcp_event_id
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to register variable '{}': {}", a2l_name, e);
                                }
                            }
                        }
                        _ => {
                            warn!("Variable '{}' has unsupported type: {}", var_name, type_info);
                        }
                    }
                } else {
                    warn!("TypeRef {} of variable '{}' not found in debug info", var_info.typeref, var_name);
                }
            }
        } // var_infos
        Ok(())
    }

    /// Read XCP_UNIT / XCP_LIMITS / XCP_COMMENT metadata from the xcp_meta ELF section
    /// and apply them to already-registered instances in the registry.
    /// Must be called after register_variables.
    pub fn register_metadata(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        info!("===============================================================");
        info!("Registering metadata from xcp_meta section:");

        let (meta_base_addr, meta_data) = match &self.debug_data.xcp_meta_data {
            Some(data) => data,
            None => {
                info!("No xcp_meta section found, skipping metadata registration");
                return Ok(());
            }
        };
        let meta_end = meta_base_addr + meta_data.len() as u64;
        let is_le = self.debug_data.is_little_endian;

        for (var_name, var_infos) in &self.debug_data.variables {
            // Only process metadata variables: xcp_meta__<kind>__<base_name>
            let Some(rest) = var_name.strip_prefix("xcp_meta__") else {
                continue;
            };
            let Some((kind, base_name)) = rest.split_once("__") else {
                warn!("Unexpected xcp_meta__ variable name format: '{}'", var_name);
                continue;
            };

            if var_infos.is_empty() {
                continue;
            }
            let var_addr = var_infos[0].address.1;
            if var_addr < *meta_base_addr || var_addr >= meta_end {
                warn!("Metadata variable '{}' address 0x{:08X} is outside xcp_meta section", var_name, var_addr);
                continue;
            }

            let offset = (var_addr - meta_base_addr) as usize;

            // Decode base_name: __ is the path separator, e.g. "params__delay_us" means
            // instance "params", field "delay_us".  Replace all __ with . to get the dot path.
            let dot_path = base_name.replace("__", ".");

            // Path A — typedef field metadata (instance + dot-separated field path)
            // Applies when base_name contains __, i.e. it encodes a struct field reference.
            // Uses set_instance_field_support_data which walks the typedef tree.
            let field_applied = if dot_path.contains('.') {
                let (instance_name, field_path) = dot_path.split_once('.').unwrap();
                apply_field_metadata(reg, var_name, kind, instance_name, field_path, meta_data, offset, is_le, verbose)
            } else {
                false
            };

            // Path B — direct instance metadata (simple variable or flattened typedef)
            // Matches instances whose A2L name equals dot_path or ends with ".{dot_path}".
            // dot_path already has . separators so it matches both "delay_us" and "params.delay_us".
            let escaped = dot_path.replace('.', "\\.");
            let pattern = format!(r"^(.*\.)?{}$", escaped);
            let names: Vec<String> = reg.instance_list.find_instances_regex(&pattern, McObjectType::Unspecified, None);
            for name in &names {
                if let Some(inst) = reg.instance_list.get_instance_mut(name, None) {
                    apply_instance_metadata(inst, kind, meta_data, offset, is_le);
                    if verbose >= 1 {
                        info!("  Metadata {} applied to instance '{}'", var_name, name);
                    }
                }
            }

            if !field_applied && names.is_empty() {
                debug!("Metadata '{}': no matching registry entry for '{}'", var_name, dot_path);
            }
        }

        Ok(())
    }

    /// True when the ELF carries mc-instrument measurement descriptors (the mci_meas section):
    /// identifier-addressed on xcplite, or with absolute addresses from a backend that supplies
    /// them (VX1000). In that case the DWARF measurement sweep in register_variables is suppressed
    /// and the measurements are produced by register_mci_measurements instead.
    pub fn has_id_addressing(&self) -> bool {
        self.debug_data.mci_meas_data.is_some()
    }

    /// Register the measurements the mci_meas ELF section describes: identifier-addressed, or at
    /// an absolute address where the backend supplied one (layout version 2).
    ///
    /// Each MeasMeta record (mc-instrument's mc_meas_abi.hpp) is parsed with the layout the
    /// binary's mci_layout record gives, because it moves with the target ABI (below). Without
    /// that record the historical LP64 layout is assumed: 56 bytes, name ptr @0, tA2lTypeId @8,
    /// x_dim @10, flags @12, comment ptr @16, unit ptr @24, min @32, max @40, id-slot ptr @48;
    /// version 2 appends the owning event's name ptr and the absolute address.
    /// The string pointers are absolute virtual addresses into .rodata (our binaries are
    /// linked at base 0, so the stored value is the string's vaddr and no relocation needs to be
    /// applied). Identifiers are NOT read from the binary: they are the 1-based position of each
    /// A2L name, `<event>.<name>`, in the byte-wise sorted set of names -- exactly how
    /// register_measurements() assigns them at runtime (identifier-addressing spec §3). Reproducing
    /// that sort here is what makes the offline A2L agree with a runtime A2L on every id. A name
    /// that occurs twice is refused, as the application refuses it.
    pub fn register_mci_measurements(&self, reg: &mut Registry, segment_relative: bool, verbose: usize) -> Result<(), Box<dyn Error>> {
        let Some((_base, data)) = self.debug_data.mci_meas_data.as_ref() else {
            return Ok(());
        };
        info!("===============================================================");
        info!("Registering identifier-addressed measurements from mci_meas section:");

        let is_le = self.debug_data.is_little_endian;
        let rd_u16_at = |b: &[u8], o: usize| -> u16 {
            let a: [u8; 2] = b[o..o + 2].try_into().unwrap();
            if is_le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) }
        };

        // How to parse a record. mc.hpp emits a MeasLayout into mci_layout precisely so this is
        // read rather than assumed: MeasMeta holds pointers, so its stride and field offsets move
        // with the target ABI, and every VX1000 target is 32-bit. Binaries built before that
        // section existed are all LP64, so their historical layout is the fallback.
        struct Layout {
            rec: usize,
            ptr: usize,
            o_name: usize,
            o_type: usize,
            o_x_dim: usize,
            o_comment: usize,
            o_unit: usize,
            o_min: usize,
            o_max: usize,
            // Layout version 2. `None` on a v1 binary, where every object is identifier-addressed.
            o_event: Option<usize>,
            o_addr: Option<usize>,
        }
        const LP64: Layout = Layout {
            rec: 56,
            ptr: 8,
            o_name: 0,
            o_type: 8,
            o_x_dim: 10,
            o_comment: 16,
            o_unit: 24,
            o_min: 32,
            o_max: 40,
            o_event: None,
            o_addr: None,
        };

        let lay = match self.debug_data.mci_layout_data.as_ref() {
            Some(b) if b.len() >= 20 => {
                let ver = b[3];
                if ver > 2 {
                    warn!("mci_layout version {} is newer than this reader understands (2); parsing the fields version 2 defines and ignoring the rest", ver);
                }
                // v2 appended o_event and o_addr, so every v1 offset is still where it was.
                let has_v2 = ver >= 2 && b.len() >= 24;
                let l = Layout {
                    rec: rd_u16_at(b, 0) as usize,
                    ptr: b[2] as usize,
                    o_name: rd_u16_at(b, 4) as usize,
                    o_type: rd_u16_at(b, 6) as usize,
                    o_x_dim: rd_u16_at(b, 8) as usize,
                    o_comment: rd_u16_at(b, 12) as usize,
                    o_unit: rd_u16_at(b, 14) as usize,
                    o_min: rd_u16_at(b, 16) as usize,
                    o_max: rd_u16_at(b, 18) as usize,
                    o_event: if has_v2 { Some(rd_u16_at(b, 20) as usize) } else { None },
                    o_addr: if has_v2 { Some(rd_u16_at(b, 22) as usize) } else { None },
                };
                info!("mci_meas layout from mci_layout: {}-byte records, {}-bit pointers", l.rec, l.ptr * 8);
                l
            }
            Some(b) => {
                warn!("mci_layout section is {} bytes, too short for a MeasLayout record; assuming the 64-bit layout", b.len());
                LP64
            }
            None => LP64,
        };

        if lay.rec == 0 || lay.ptr == 0 || (lay.ptr != 4 && lay.ptr != 8) {
            warn!("mci_layout describes {}-byte records with {}-byte pointers, which is not parseable; skipping mci_meas", lay.rec, lay.ptr);
            return Ok(());
        }
        // Every field the reader is about to slice has to lie inside a record. Without this a
        // layout claiming, say, 16-byte records with min at offset 32 passes the chunk-length
        // check and then panics in rd_f64 with a backtrace instead of a diagnostic.
        let fits = |offset: usize, width: usize| offset + width <= lay.rec;
        // o_event and o_addr are Options because v1 records do not have them, but when they are
        // present they are sliced exactly like the v1 fields (rd_ptr below), so they are checked
        // exactly like them. Leaving them out let a v2 layout over v1-sized records -- a stale
        // object file relinked against a newer mci_layout -- reach rd_ptr and panic.
        let bad = [
            ("name", Some(lay.o_name), lay.ptr),
            ("type", Some(lay.o_type), 1),
            ("x_dim", Some(lay.o_x_dim), 2),
            ("comment", Some(lay.o_comment), lay.ptr),
            ("unit", Some(lay.o_unit), lay.ptr),
            ("min", Some(lay.o_min), 8),
            ("max", Some(lay.o_max), 8),
            ("event", lay.o_event, lay.ptr),
            ("addr", lay.o_addr, lay.ptr),
        ]
        .into_iter()
        .filter_map(|(name, offset, width)| offset.map(|o| (name, o, width)))
        .find(|(_, offset, width)| !fits(*offset, *width));
        if let Some((field, offset, width)) = bad {
            warn!(
                "mci_layout puts '{}' at offset {} ({} bytes) in a {}-byte record, which does not fit; skipping mci_meas",
                field, offset, width, lay.rec
            );
            return Ok(());
        }

        if data.len() % lay.rec != 0 {
            // Not a warning to carry on from: if the stride disagrees, every field read after
            // the first record lands in the middle of another one, so the measurements this
            // would emit are fabricated rather than merely incomplete.
            warn!(
                "mci_meas section is {} bytes, not a multiple of the {}-byte record stride -- mc.hpp MeasMeta layout and this reader disagree; skipping mci_meas rather than emitting fabricated signals",
                data.len(),
                lay.rec
            );
            return Ok(());
        }

        // A pointer field, widened to u64 so the rest of the reader is word-size agnostic.
        let rd_ptr = |b: &[u8], o: usize| -> u64 {
            if lay.ptr == 8 {
                let a: [u8; 8] = b[o..o + 8].try_into().unwrap();
                if is_le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) }
            } else {
                let a: [u8; 4] = b[o..o + 4].try_into().unwrap();
                (if is_le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }) as u64
            }
        };
        let rd_u16 = |b: &[u8], o: usize| -> u16 { rd_u16_at(b, o) };
        let rd_f64 = |b: &[u8], o: usize| -> f64 {
            let a: [u8; 8] = b[o..o + 8].try_into().unwrap();
            if is_le { f64::from_le_bytes(a) } else { f64::from_be_bytes(a) }
        };

        struct MeasRec {
            name: String,
            ty: i8,
            x_dim: u16,
            comment: String,
            unit: String,
            min: f64,
            max: f64,
            /// Absolute address, when the backend supplied one. `Some` switches this object from
            /// identifier addressing to a plain address in the A2L -- what the VX1000 backend
            /// needs, because the device samples ECU memory from outside the CPU and cannot ask
            /// the application to resolve an identifier at trigger time.
            addr: Option<u32>,
            /// Owning event's name, on both addressing modes: it is the object's event binding in
            /// the A2L whether or not `addr` is set. Under identifier addressing that binding is
            /// metadata rather than something the address implies (spec §7), but it still decides
            /// which event the object is armed on -- see the event_id lookup below.
            event: String,
        }

        let mut recs: Vec<MeasRec> = Vec::new();
        for (i, chunk) in data.chunks(lay.rec).enumerate() {
            if chunk.len() < lay.rec {
                break;
            }
            let name_ptr = rd_ptr(chunk, lay.o_name);
            let ty = chunk[lay.o_type] as i8;
            let x_dim = rd_u16(chunk, lay.o_x_dim);
            let comment_ptr = rd_ptr(chunk, lay.o_comment);
            let unit_ptr = rd_ptr(chunk, lay.o_unit);
            let min = rd_f64(chunk, lay.o_min);
            let max = rd_f64(chunk, lay.o_max);
            let addr = lay.o_addr.map(|o| rd_ptr(chunk, o)).filter(|a| *a != 0).map(|a| a as u32);
            let event = lay
                .o_event
                .map(|o| rd_ptr(chunk, o))
                .and_then(|p| self.read_rodata_cstr(p))
                .unwrap_or_default();

            // Identifiers are the 1-based position in the sorted, de-duplicated name list, and
            // the application derives them the same way from *every* descriptor. Dropping a
            // record here would shift every alphabetically-later identifier by one, so the A2L
            // would say `spectrum` is 7 while the application resolves 8 -- the kernel would arm
            // 7, xcplite would resolve it happily, and the user would get another variable's
            // bytes as plausible-looking numbers. An A2L that cannot reproduce the runtime's
            // assignment is worse than no A2L, so this is fatal rather than a skip.
            let Some(name) = self.read_rodata_cstr(name_ptr) else {
                return Err(format!(
                    "mci_meas record {} has an unresolvable name pointer 0x{:08X}. Identifiers are \
                     positional, so skipping it would renumber every later signal and the A2L would \
                     describe the wrong variables.",
                    i, name_ptr
                )
                .into());
            };
            if name.is_empty() {
                return Err(format!(
                    "mci_meas record {} has an empty name; identifiers are positional, so it cannot \
                     be skipped without renumbering every later signal.",
                    i
                )
                .into());
            }
            let comment = self.read_rodata_cstr(comment_ptr).unwrap_or_default();
            let unit = self.read_rodata_cstr(unit_ptr).unwrap_or_default();
            recs.push(MeasRec { name, ty, x_dim, comment, unit, min, max, addr, event });
        }

        // Each record's A2L name: `<event>.<name>`, or the bare name for a record built outside any
        // MEASURE -- the rule mc-instrument's a2l_name() applies at runtime. A name alone does not say
        // which object it is: two functions each measuring a local `speed`, or one global measured by
        // two events, used to become one A2L object, so one of the objects went unmeasured. With the
        // event in the name every entry is its own signal on its own event.
        let qualified: Vec<String> = recs
            .iter()
            .map(|r| if r.event.is_empty() { r.name.clone() } else { format!("{}.{}", r.event, r.name) })
            .collect();

        // Deterministic identifiers: 1-based position in the byte-wise sorted name list (spec §3).
        // strcmp on the C strings is a byte comparison, which is exactly the Ord that sorting Rust
        // Strings gives for these ASCII identifiers.
        let mut order: Vec<usize> = (0..recs.len()).collect();
        order.sort_unstable_by(|&x, &y| qualified[x].cmp(&qualified[y]));

        // A name sorted next to itself is two entries of one MEASURE: one A2L object for two
        // objects, which the running application refuses to start with. An A2L for it would describe
        // one of them under both names, so it is refused here too, naming every repeat.
        let mut repeats: Vec<String> = Vec::new();
        for w in order.windows(2) {
            if qualified[w[0]] == qualified[w[1]] {
                let r = &recs[w[1]];
                let what = if r.event.is_empty() {
                    format!("'{}' is named twice outside any MEASURE", r.name)
                } else {
                    format!("MEASURE({}, ...) lists '{}' twice", r.event, r.name)
                };
                if repeats.last() != Some(&what) {
                    repeats.push(what);
                }
            }
        }
        if !repeats.is_empty() {
            return Err(format!(
                "measurement entries that share a name: {}. One signal cannot stand for two objects: measure each \
                 object once, or give one a .name of its own.",
                repeats.join("; ")
            )
            .into());
        }
        let names: Vec<&str> = order.iter().map(|&i| qualified[i].as_str()).collect();
        // identifier 0 is reserved (invalid), so ids are 1-based.
        let id_of = |name: &str| -> u32 { (names.binary_search(&name).unwrap() as u32) + 1 };

        // The identifier occupies the high 16 bits of the address field, so it has a ceiling, and
        // exceeding it does not overflow into nothing -- `id << 16` drops the top bits and two
        // distinct objects come out with the same ECU_ADDRESS. The A2L then describes one variable
        // and the application resolves the other, with every value plausible. Refuse instead: the
        // ceiling is a property of the addressing mode, not of this binary, and a user who hits it
        // needs to hear the number.
        //
        // The application-side numbering (mc-instrument's register_measurements) degrades instead:
        // the objects under the ceiling still measure and the ones past it are named on stderr and
        // dropped. Deliberate, on both sides. A running application has somewhere to put that
        // message and a reason to keep going; an A2L that silently omits signals is worse than no
        // A2L, because nothing downstream can tell the difference. If either side is revisited
        // they both move: the identifier rule is the contract between them.
        if names.len() > XCP_ID_MAX as usize {
            return Err(format!(
                "{} distinct measurement names, but identifier addressing can only address {} \
                 (the identifier is the high {} bits of a 32 bit address field, the low bits being \
                 a byte offset into the object). Measure fewer objects, or raise \
                 XCP_ID_OFFSET_BITS on both sides of the seam.",
                names.len(),
                XCP_ID_MAX,
                32 - XCP_ID_OFFSET_BITS
            )
            .into());
        }

        let mut count = 0usize;
        for (r, name) in recs.iter().zip(qualified.iter()) {
            let id = id_of(name);
            let value_type = a2l_type_to_value_type(r.ty);
            let dim_type = McDimType::new(value_type, r.x_dim.max(1), 1);
            // Match sig_min/sig_max in mc_meas_abi.hpp: the descriptor stores (0.0, 0.0) when
            // neither bound was given, and that resolves to the type's own range. The range must be
            // xcplite's (A2lGetTypeMin/Max, mirrored by type_min/type_max in mc_meas_abi.hpp: +-1e12
            // for float/double/int64), NOT the registry's own get_min/get_max (+-1e32), so the
            // offline limits equal the runtime ones.
            let (min, max) = if r.min == 0.0 && r.max == 0.0 {
                (Some(a2l_type_min(r.ty)), Some(a2l_type_max(r.ty)))
            } else {
                (Some(r.min), Some(r.max))
            };
            let mut sd = McSupportData::new(McObjectType::Measurement).set_min(min).set_max(max);
            if !r.comment.is_empty() {
                sd = sd.set_comment(a2l_text(&r.comment));
            }
            if !r.unit.is_empty() {
                sd = sd.set_unit(a2l_text(&r.unit));
            }
            // Two addressing modes, chosen per record by whether the backend supplied an address.
            //
            // Absolute (VX1000): the descriptor carries the object's real address, so it goes into
            // ECU_ADDRESS with the target's absolute extension (abs_addr_ext below) and the object
            // is bound to its owning event by name.
            // The VX samples ECU memory from outside the CPU, so there is nobody to resolve an
            // identifier at trigger time and the address has to be in the A2L.
            //
            // Identifier (xcplite): the identifier travels in ECU_ADDRESS with extension
            // XCP_ADDR_EXT_ID (0x7F). The event association still matters -- it is what the
            // generator turns into per-event DAQ lists and a non-zero EventId, and it is the one
            // event whose trigger carries this identifier's address: a MEASURE passes its own
            // entries' addresses when it triggers its event, and xcplite refuses to start a DAQ
            // list that samples the identifier on any other (XcpCheckIdEvents). Binding every
            // identifier to event 0 (as this used to) left the 2nd..nth event arming nothing at
            // all: its signals were put on event 0's list instead, at the wrong rate, on a
            // trigger that does not carry their addresses.
            let event_id = match reg.event_list.find_event(&r.event, 0) {
                Some(e) => e.id,
                None => {
                    // Event 0 either way, but said out loud either way too. The warning used to be
                    // conditional on the name being non-empty, which silenced the case that needs
                    // it most: a descriptor with no event at all is bound to whichever event
                    // happens to be 0, whose trigger does not carry its address.
                    if r.event.is_empty() {
                        warn!("measurement '{}' names no event; binding it to event 0", r.name);
                    } else {
                        warn!(
                            "measurement '{}' names event '{}', which is not in the ELF's event section; binding it to event 0",
                            r.name, r.event
                        );
                    }
                    0
                }
            };
            // Absolute addresses carry the target's absolute extension, which is not always 0:
            // under a segment-relative target (XCPLITE__CASDD) extension 0 *is* the calibration
            // segment and absolute is 1. register_variables makes the same choice at line ~867;
            // hardcoding 0 here emitted MEASUREMENTs pointing into the calibration page while
            // every other object in the same A2L used 1.
            let abs_addr_ext = if segment_relative { 1 } else { 0 };
            let addr = match r.addr {
                Some(a) => McAddress::new_a2l_with_event(event_id, a, abs_addr_ext),
                // The identifier occupies the high 16 bits and the low 16 are a byte offset into
                // the object (0 for the whole object). The field is split so that address
                // arithmetic works: a master selecting one array element sends ECU_ADDRESS +
                // i*elemsize, and an object wider than one ODT entry is armed as chunks at
                // ECU_ADDRESS + k*248. With the whole word spent on the identifier those landed
                // on unrelated objects. Mirrors XcpAddrEncodeId in xcplite's inc/xcp_id_addr.h.
                None => McAddress::new_a2l_with_event(event_id, id << XCP_ID_OFFSET_BITS, XCP_ADDR_EXT_ID),
            };
            match reg.instance_list.add_instance(name.clone(), dim_type, sd, addr) {
                Ok(_) => {
                    count += 1;
                    if verbose >= 1 {
                        info!("  measurement '{}' id={} type={:?} dim={}", name, id, value_type, r.x_dim.max(1));
                    }
                }
                Err(e) => error!("Failed to register measurement '{}': {}", name, e),
            }
        }
        info!("Registered {} identifier-addressed measurement(s) from mci_meas", count);
        Ok(())
    }

    /// Dereference a string pointer stored in a mci_meas descriptor. The pointer is an absolute
    /// virtual address into .rodata (base 0 for our PIE binaries); it is resolved against the
    /// captured .rodata bytes. Returns None for a null pointer or an address outside .rodata.
    fn read_rodata_cstr(&self, vaddr: u64) -> Option<String> {
        if vaddr == 0 {
            return None;
        }
        let (base, data) = self.debug_data.rodata_data.as_ref()?;
        if vaddr < *base {
            return None;
        }
        let off = (vaddr - *base) as usize;
        read_cstr_at(data, off)
    }
}

/// The reference page mc-instrument's MC_CALSEG defines for the segment whose calseg__<name>
/// marker is `markers`: among `candidates`, the one variable in namespace `mci_pages` nested in the
/// marker's own namespaces (both lists innermost first). Nothing for a page declared any other way,
/// or when two would match.
fn mci_page<'a>(candidates: &[&'a VarInfo], markers: &[VarInfo]) -> Option<&'a VarInfo> {
    let marker = markers.iter().find(|m| m.address.1 != 0)?;
    let matches = |c: &&&VarInfo| c.namespaces.len() == marker.namespaces.len() + 1 && c.namespaces[0] == "mci_pages" && c.namespaces[1..] == marker.namespaces[..];
    let mut pages = candidates.iter().filter(matches);
    let page = pages.next()?;
    if pages.next().is_some() {
        return None;
    }
    Some(page)
}

/// What is left of xcplite's room for calibration segments, spent the way XcpCreateCalSeg_
/// (cal.c) spends it. Segments and blocks are created in marker address order, and each takes one
/// slot of the segment list and `header + pages * size` bytes of the calibration memory pool, the
/// size rounded up to XCP_CALPAGE_ALIGNMENT. One that does not fit is not created, and the
/// application runs without it (mc-instrument says so at startup), so the A2L must not describe
/// it either -- nor give it the number and the address the application gives the next one.
///
/// The limits come from the binary (ElfReader::calseg_room). The costs are xcplite's constants,
/// kept here by hand: XCP_CALSEG_HEADER_SIZE and XCP_CALPAGE_ALIGNMENT (cal.h), and the EPK
/// segment's size, XCP_EPK_MAX_LENGTH + 1 whatever the EPK string is (XcpInit, xcplite.c). The
/// fixtures 141 and 142 in test-review-regressions/xcplite run segments to the last byte and the
/// last slot on both routes, so a constant that drifts fails there.
struct CalsegRoom {
    slots: u64,
    bytes: u64,
    pages: u64,
}

const XCP_CALSEG_HEADER_SIZE: u64 = 64;
const XCP_CALPAGE_ALIGNMENT: u64 = 8;
const XCP_EPK_SEGMENT_SIZE: u64 = 31 + 1;

impl CalsegRoom {
    /// Take a segment's slot and memory, or say why it does not fit.
    fn admit(&mut self, name: &str, size: u16) -> Result<(), String> {
        let size = if name == "epk" { XCP_EPK_SEGMENT_SIZE } else { size as u64 };
        let aligned = size.div_ceil(XCP_CALPAGE_ALIGNMENT) * XCP_CALPAGE_ALIGNMENT;
        let cost = XCP_CALSEG_HEADER_SIZE + self.pages * aligned;
        if cost > self.bytes {
            return Err(format!(
                "it needs {} bytes of xcplite's calibration memory and the segments before it left {} (raise OPTION_CAL_MEM_SIZE; \
                 MCI_CAL_MEM_SIZE in mc-instrument's CMake)",
                cost, self.bytes
            ));
        }
        // xcplite allocates before it takes a slot, so a segment refused for want of a slot has
        // spent its memory as well. That changes nothing: every later one is refused alike.
        self.bytes -= cost;
        if self.slots == 0 {
            return Err("xcplite's list of calibration segments is full (raise OPTION_CAL_SEGMENT_COUNT; MCI_CAL_SEGMENT_COUNT in mc-instrument's CMake)".to_string());
        }
        self.slots -= 1;
        Ok(())
    }
}

/// The address extension of an identifier-addressed object: ECU_ADDRESS_EXTENSION 0x7F. Must equal
/// XCP_ADDR_EXT_ID in xcplite's inc/xcp_id_addr.h, which A2lSetIdAddrMode writes on the runtime
/// route and the server's identifier branches test.
///
/// One value in every addressing scheme. Identifiers used to travel on the application extension,
/// XCP_ADDR_EXT_APP, which is 0x80 under XCPLITE__CASDD and 0x01 under AXSDD and CXSDD, and this
/// constant was 0x80 whatever scheme the ELF named -- right for what mc-instrument builds, wrong for
/// a binary built in another scheme, whose every WRITE_DAQ the server would then reject (issue 253).
const XCP_ADDR_EXT_ID: u8 = 0x7F;

/// Added to upstream (issue 223): refuses a measurement whose full name is a calibration
/// object's.
///
/// AXIS_PTS, BLOB, CHARACTERISTIC, INSTANCE and MEASUREMENT names are one namespace in an A2L, and
/// an INSTANCE's component paths are in it too: `INSTANCE Pump PumpType` with a component `duty` is
/// `Pump.duty` to every reader. `MC_CALSEG(PumpType, Pump)` with that field, measured by
/// `MEASURE(Pump, ..., MC(duty))`, gave `MEASUREMENT Pump.duty` beside it, and the generator and
/// the extension then found two objects under one name. mc-instrument refuses to start such an
/// application, so no A2L is written for it either, as for two segments of one name. Only a whole
/// name collides: an event may be named like a segment.
pub fn check_measurement_names(reg: &Registry) -> Result<(), Box<dyn Error>> {
    // Every calibration object's full name, and the object it belongs to.
    let mut calibration: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    fn components(reg: &Registry, typedef: &str, prefix: &str, owner: &str, out: &mut std::collections::HashMap<String, String>, depth: usize) {
        let Some(typedef) = reg.typedef_list.find_typedef(typedef) else { return };
        if depth > 16 {
            return; // a type that contains itself; the cap is cheaper than proving it cannot
        }
        for field in &typedef.fields {
            let path = format!("{prefix}.{}", field.get_name());
            if let Some(nested) = field.get_typedef_name() {
                components(reg, nested, &path, owner, out, depth + 1);
            }
            out.entry(path).or_insert_with(|| format!("a component of {owner}"));
        }
    }
    for instance in &reg.instance_list {
        if instance.is_measurement_object() {
            continue;
        }
        let name = instance.get_unique_name(reg).to_string();
        let kind = if instance.get_typedef_name().is_some() {
            "INSTANCE"
        } else if instance.is_axis() {
            "AXIS_PTS"
        } else {
            "CHARACTERISTIC"
        };
        let owner = format!("{kind} '{name}'");
        if let Some(typedef) = instance.get_typedef_name() {
            components(reg, typedef, &name, &owner, &mut calibration, 0);
        }
        calibration.insert(name, owner);
    }
    let clashes: Vec<String> = (&reg.instance_list)
        .into_iter()
        .filter(|instance| instance.is_measurement_object())
        .filter_map(|instance| {
            let name = instance.get_unique_name(reg);
            calibration.get(name.as_ref()).map(|owner| format!("MEASUREMENT '{name}' has the full name of {owner}"))
        })
        .collect();
    if clashes.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}. AXIS_PTS, BLOB, CHARACTERISTIC, INSTANCE and MEASUREMENT names are one A2L namespace, an INSTANCE's component paths included, \
         so a reader would find two objects under one name. Give the measured entry a .name of its own, or rename its event; no A2L is written",
        clashes.join("; ")
    )
    .into())
}

/// Added to upstream (issue 258): one token of an A2L text, and where it starts in the text.
///
/// A quoted string is one token, its quotes included, by A2L's rules: inside it `\"` and `""` are a
/// quote and `\\` a backslash, so none of them ends it. Outside one, `/* ... */` and `//` to the end
/// of the line are comments, which are no token (issue 294). Any other token runs to white space, a
/// quote or a comment. The passes below find a measurement's block and read its keywords from these,
/// so that a description or a unit holding `/end MEASUREMENT` or `ECU_ADDRESS_EXTENSION 1` decides
/// nothing: a quoted token is never equal to a keyword. Nor does a comment, whatever it holds:
/// xcp_registry writes the function each event triggers in into one, and a quote in that name --
/// `step<'\"'>`, an explicit specialization -- opened a string that turned every later quote round.
struct A2lToken<'a> {
    start: usize,
    text: &'a str,
}

impl A2lToken<'_> {
    fn end(&self) -> usize {
        self.start + self.text.len()
    }
    fn quoted(&self) -> bool {
        self.text.starts_with('"')
    }
}

/// Whether a comment starts at `at` in `bytes`: `/*` or `//`.
fn a2l_comment_at(bytes: &[u8], at: usize) -> bool {
    bytes[at] == b'/' && matches!(bytes.get(at + 1), Some(b'*' | b'/'))
}

/// The tokens of an A2L text. A string or a block comment still open at the end of the text runs to
/// its end.
fn a2l_tokens(text: &str) -> Vec<A2lToken<'_>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if a2l_comment_at(bytes, at) {
            at = if bytes[at + 1] == b'*' {
                // The `*` that opens it does not close it: `/*/` is still open, as a2lfile reads it.
                text[at + 2..].find("*/").map_or(bytes.len(), |end| at + 2 + end + 2)
            } else {
                text[at..].find('\n').map_or(bytes.len(), |end| at + end)
            };
            continue;
        }
        let start = at;
        if bytes[at] == b'"' {
            at += 1;
            while at < bytes.len() {
                match bytes[at] {
                    b'\\' => at += 2,
                    b'"' if bytes.get(at + 1) == Some(&b'"') => at += 2,
                    b'"' => {
                        at += 1;
                        break;
                    }
                    _ => at += 1,
                }
            }
            at = at.min(bytes.len());
        } else {
            while at < bytes.len() && !bytes[at].is_ascii_whitespace() && bytes[at] != b'"' && !a2l_comment_at(bytes, at) {
                at += 1;
            }
        }
        // Every token ends after an ASCII byte or at the end of the text, so this is a char boundary.
        tokens.push(A2lToken { start, text: &text[start..at] });
    }
    tokens
}

/// The MEASUREMENT blocks among `tokens`, each from its `/begin MEASUREMENT` to its `/end MEASUREMENT`.
fn a2l_measurements<'t, 'a>(tokens: &'t [A2lToken<'a>]) -> Vec<&'t [A2lToken<'a>]> {
    let mut blocks = Vec::new();
    let mut open = None;
    for (at, pair) in tokens.windows(2).enumerate() {
        match (pair[0].text, pair[1].text) {
            ("/begin", "MEASUREMENT") => open = Some(at),
            ("/end", "MEASUREMENT") => {
                if let Some(start) = open.take() {
                    blocks.push(&tokens[start..at + 2]);
                }
            }
            _ => {}
        }
    }
    blocks
}

/// The ECU_ADDRESS_EXTENSION a measurement block states, decimal or 0x hex.
fn a2l_address_extension(block: &[A2lToken]) -> Option<u8> {
    let at = block.iter().position(|t| t.text == "ECU_ADDRESS_EXTENSION")?;
    let v = block.get(at + 1)?.text;
    if let Some(hex) = v.strip_prefix("0x") {
        u8::from_str_radix(hex, 16).ok()
    } else {
        v.parse::<u8>().ok()
    }
}

/// `text` with each of `edits` -- a byte range and what replaces it, in order and not overlapping.
fn a2l_splice(text: &str, edits: &[(std::ops::Range<usize>, String)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (range, with) in edits {
        out.push_str(&text[at..range.start]);
        out.push_str(with);
        at = range.end;
    }
    out.push_str(&text[at..]);
    out
}

/// Rewrite, in the A2L at `path`, the event list of every identifier-addressed measurement
/// (ECU_ADDRESS_EXTENSION XCP_ADDR_EXT_ID) from `VARIABLE ... DEFAULT_EVENT_LIST EVENT n` to
/// `FIXED_EVENT_LIST EVENT n`: its identifier may only be sampled on that event (issue 140).
/// Measurements on other extensions, which any event can sample, keep what xcp_registry wrote.
///
/// The block, its extension and its event list are read from the A2L's tokens, outside quoted
/// strings (issue 258), as fix_identifier_read_write reads them.
pub fn fix_identifier_event_lists(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    // `DAQ_EVENT VARIABLE /begin DEFAULT_EVENT_LIST EVENT n /end DEFAULT_EVENT_LIST /end DAQ_EVENT`,
    // where None is the event's number.
    const VARIABLE: [Option<&str>; 10] = [
        Some("DAQ_EVENT"),
        Some("VARIABLE"),
        Some("/begin"),
        Some("DEFAULT_EVENT_LIST"),
        Some("EVENT"),
        None,
        Some("/end"),
        Some("DEFAULT_EVENT_LIST"),
        Some("/end"),
        Some("DAQ_EVENT"),
    ];
    let text = std::fs::read_to_string(path)?;
    let tokens = a2l_tokens(&text);
    let mut edits = Vec::new();
    for block in a2l_measurements(&tokens) {
        if a2l_address_extension(block) != Some(XCP_ADDR_EXT_ID) {
            continue;
        }
        let list = block.windows(VARIABLE.len()).find(|w| {
            w.iter().zip(VARIABLE).all(|(t, want)| match want {
                Some(keyword) => t.text == keyword,
                None => !t.quoted(),
            })
        });
        if let Some(list) = list {
            edits.push((list[0].start..list[9].end(), format!("DAQ_EVENT FIXED_EVENT_LIST EVENT {} /end DAQ_EVENT", list[5].text)));
        }
    }
    if !edits.is_empty() {
        std::fs::write(path, a2l_splice(&text, &edits).as_bytes())?;
        info!("{} identifier-addressed measurement(s) written with FIXED_EVENT_LIST", edits.len());
    }
    Ok(())
}

/// Take READ_WRITE off, in the A2L at `path`, every identifier-addressed measurement (ECU_ADDRESS_EXTENSION
/// XCP_ADDR_EXT_ID). xcp_registry gives READ_WRITE to every A2L-addressed object, but the server
/// refuses a write to an identifier -- a measurement has no reference page and no consistent-write
/// discipline (issue 18) -- so a tool offered writes that fail (issue 230). The runtime route
/// writes no READ_WRITE for them. A measurement on another extension, an absolute one a write
/// reaches, keeps what xcp_registry wrote.
///
/// The block, the extension and the keyword are read from the A2L's tokens, outside quoted strings
/// (issue 258), so a description or a unit that mentions any of them is left as it is and decides
/// nothing.
pub fn fix_identifier_read_write(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    let tokens = a2l_tokens(&text);
    let mut edits = Vec::new();
    let mut fixed = 0usize;
    for block in a2l_measurements(&tokens) {
        if a2l_address_extension(block) != Some(XCP_ADDR_EXT_ID) {
            continue;
        }
        let before = edits.len();
        // The keyword and the white space before it, as xcp_registry writes ` READ_WRITE`.
        for pair in block.windows(2).filter(|pair| pair[1].text == "READ_WRITE") {
            edits.push((pair[0].end()..pair[1].end(), String::new()));
        }
        if edits.len() > before {
            fixed += 1;
        }
    }
    if fixed > 0 {
        std::fs::write(path, a2l_splice(&text, &edits).as_bytes())?;
        info!("{} identifier-addressed measurement(s) written without READ_WRITE", fixed);
    }
    Ok(())
}

/// The size of the mci_app record before it held the endpoint -- the name alone -- before it held
/// the description (issue 186), and since.
const MCI_APP_NAME_LEN: usize = 64;
const MCI_APP_BIND_LEN: usize = 16;
const MCI_APP_ENDPOINT_END: usize = MCI_APP_NAME_LEN + MCI_APP_BIND_LEN + 4;
const MCI_APP_DESC_LEN: usize = 128;
const MCI_APP_RECORD_LEN: usize = MCI_APP_ENDPOINT_END + MCI_APP_DESC_LEN;
/// AppMeta::endpoint: the application runs no XCP server (the VX1000 backend), or it runs one.
const MCI_APP_NO_SERVER: u8 = 0;
const MCI_APP_SERVER: u8 = 1;

/// What an mc-instrument application's mci_app record says about its XCP endpoint (issue 225).
pub enum AppEndpoint {
    /// It serves XCP at `addr`:`port` over TCP or UDP; `bind` is `.bind` as written, "" when unset.
    /// The offline A2L's transport block is this.
    Server { addr: Ipv4Addr, port: u16, tcp: bool, bind: String },
    /// It serves none -- the VX1000 backend, whose device is the transport -- so the command
    /// line's endpoint stands.
    NoServer,
}

/// What an xcplite server answers to CONNECT (MAX_CTO, MAX_DTO) and to GET_DAQ_RESOLUTION_INFO
/// (TIMESTAMP_MODE, TIMESTAMP_TICKS), as the record in its xcp_proto section states it. xcplite.c
/// builds the record from the definitions both commands answer with.
pub struct ServerProtocol {
    pub max_cto: u16,
    pub max_dto: u16,
    pub timestamp_mode: u16,
    pub timestamp_ticks: u16,
}

impl ServerProtocol {
    /// The body of TIMESTAMP_SUPPORTED, in XCP_104.aml's terms: the ticks, the size, the unit, and
    /// TIMESTAMP_FIXED when the server always sends a timestamp. Err for a code the AML has no name for.
    fn timestamp_supported(&self) -> Result<String, String> {
        const UNITS: [&str; 13] = [
            "UNIT_1NS",
            "UNIT_10NS",
            "UNIT_100NS",
            "UNIT_1US",
            "UNIT_10US",
            "UNIT_100US",
            "UNIT_1MS",
            "UNIT_10MS",
            "UNIT_100MS",
            "UNIT_1S",
            "UNIT_1PS",
            "UNIT_10PS",
            "UNIT_100PS",
        ];
        let size = match self.timestamp_mode & 0x07 {
            0 => "NO_TIME_STAMP",
            1 => "SIZE_BYTE",
            2 => "SIZE_WORD",
            4 => "SIZE_DWORD",
            code => return Err(format!("timestamp size code {code}")),
        };
        let unit = UNITS
            .get(usize::from(self.timestamp_mode >> 4))
            .ok_or_else(|| format!("timestamp unit code {}", self.timestamp_mode >> 4))?;
        let fixed = if self.timestamp_mode & 0x08 != 0 { " TIMESTAMP_FIXED" } else { "" };
        Ok(format!("0x{:X} {size} {unit}{fixed}", self.timestamp_ticks))
    }
}

/// Rewrite, in the A2L at `path`, what xcp_registry states about the server -- MAX_CTO and MAX_DTO
/// in PROTOCOL_LAYER, and TIMESTAMP_SUPPORTED -- with what the server answers (issue 224).
/// xcp_registry writes the same literals for every server: 252, 1468, and ticks of 1 us.
///
/// Both blocks are found among the A2L's tokens, outside quoted strings and comments, as the
/// identifier passes find a measurement (issues 258, 294). Patterns over the whole text counted a
/// measurement's description holding `/begin TIMESTAMP_SUPPORTED` as a second block, and the A2L
/// was refused (issue 314).
pub fn fix_protocol_layer(path: &std::path::Path, server: &ServerProtocol) -> Result<(), Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    let tokens = a2l_tokens(&text);
    // Where each `/begin <name>` block's body starts: the token after its name.
    let bodies = |name: &str| -> Vec<usize> {
        tokens
            .windows(2)
            .enumerate()
            .filter(|(_, pair)| pair[0].text == "/begin" && pair[1].text == name)
            .map(|(at, _)| at + 2)
            .collect()
    };
    let (layers, stamps) = (bodies("PROTOCOL_LAYER"), bodies("TIMESTAMP_SUPPORTED"));
    if layers.len() != 1 || stamps.len() != 1 {
        return Err(format!(
            "{} has {} PROTOCOL_LAYER and {} TIMESTAMP_SUPPORTED, not the one of each the server's MAX_CTO, MAX_DTO and timestamp go into",
            path.display(),
            layers.len(),
            stamps.len()
        )
        .into());
    }
    // PROTOCOL_LAYER's parameters: the version and the timeouts T1..T7, then MAX_CTO and MAX_DTO.
    let layer = &tokens[layers[0]..];
    let (Some(cto), Some(dto)) = (layer.get(8).filter(|t| !t.quoted()), layer.get(9).filter(|t| !t.quoted())) else {
        return Err(format!("{}'s PROTOCOL_LAYER has no MAX_CTO and MAX_DTO after its version and seven timeouts", path.display()).into());
    };
    // TIMESTAMP_SUPPORTED's body: every token before its `/end TIMESTAMP_SUPPORTED`.
    let stamp = &tokens[stamps[0]..];
    let end = stamp.windows(2).position(|pair| pair[0].text == "/end" && pair[1].text == "TIMESTAMP_SUPPORTED");
    let Some(end) = end.filter(|&end| end > 0 && !stamp[..end].iter().any(|t| t.text == "/begin" || t.text == "/end")) else {
        return Err(format!("{}'s TIMESTAMP_SUPPORTED is empty or not closed", path.display()).into());
    };
    let timestamp = server.timestamp_supported()?;
    let mut edits = vec![
        (cto.start..cto.end(), server.max_cto.to_string()),
        (dto.start..dto.end(), server.max_dto.to_string()),
        (stamp[0].start..stamp[end - 1].end(), timestamp.clone()),
    ];
    edits.sort_by_key(|(range, _)| range.start);
    std::fs::write(path, a2l_splice(&text, &edits).as_bytes())?;
    info!(
        "PROTOCOL_LAYER and TIMESTAMP_SUPPORTED written as the server answers: MAX_CTO {}, MAX_DTO {}, timestamp {}",
        server.max_cto, server.max_dto, timestamp
    );
    Ok(())
}

/// Added to upstream (issue 276): the XCP IF_DATA description every A2L xcp_registry writes
/// includes by name, `/include "XCP_104.aml"` -- this crate's copy, xcplite's own, compiled in, so
/// that a prebuilt xcpclient needs no file beside it.
const XCP_104_AML: &str = include_str!("../../XCP_104.aml");

/// Added to upstream (issue 276): put the XCP_104.aml the A2L at `a2l_path` includes beside it,
/// before the A2L is written.
///
/// a2lfile resolves the include beside the A2L, and else in the working directory, and so does
/// every other reader: xcp_registry's check of the A2L it has just written, CANape, the kernel. With
/// nothing there the check failed on IncludeFileError, said so, and xcpclient went on with an A2L no
/// reader could load where it lay. An XCP_104.aml already beside it is kept: it may be a tool's own,
/// and the A2L reaches it either way. One that is not this one is said to differ.
pub fn write_aml_beside(a2l_path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let aml = a2l_path.with_file_name("XCP_104.aml");
    match std::fs::read(&aml) {
        Ok(found) if found == XCP_104_AML.as_bytes() => {}
        Ok(_) => warn!(
            "{} is kept as it is, and differs from the XCP_104.aml this xcpclient was built with, which the A2L's IF_DATA is written for",
            aml.display()
        ),
        Err(_) => {
            std::fs::write(&aml, XCP_104_AML).map_err(|e| format!("cannot write {}, which the A2L includes: {}", aml.display(), e))?;
            info!("Wrote {}, which the A2L includes", aml.display());
        }
    }
    Ok(())
}

/// How many low bits of the address field are a byte offset into the object the identifier names.
/// Must equal XCP_ID_OFFSET_BITS in xcplite's inc/xcp_id_addr.h -- the server decodes what this
/// encodes. That header is the single definition (xcp_cfg.h and xcplib.h both include it); this
/// Rust mirror is the one copy that still has to be kept by hand, which is why it names the file.
const XCP_ID_OFFSET_BITS: u32 = 16;

/// The largest identifier the field can hold, = XCP_ID_MAX in xcplite's inc/xcp_id_addr.h.
const XCP_ID_MAX: u32 = u32::MAX >> XCP_ID_OFFSET_BITS;

/// Byte size of an A2L type id. The magnitude *is* the size for the integers (see
/// mc_meas_abi.hpp); the two float ids sit past them and carry their own.
fn a2l_type_size(t: i8) -> u32 {
    match t {
        -9 => 4,
        -10 => 8,
        other => u32::from(other.unsigned_abs()),
    }
}

/// Map an A2L type id (tA2lTypeId in a2l.h: for the integers magnitude = byte size and sign =
/// signedness; -9 and -10 are float and double) to the registry value type. mc-instrument
/// measures `bool` as UINT8, so it arrives here as +1.
fn a2l_type_to_value_type(t: i8) -> McValueType {
    match t {
        1 => McValueType::Ubyte,
        2 => McValueType::Uword,
        4 => McValueType::Ulong,
        8 => McValueType::Ulonglong,
        -1 => McValueType::Sbyte,
        -2 => McValueType::Sword,
        -4 => McValueType::Slong,
        -8 => McValueType::Slonglong,
        -9 => McValueType::Float32Ieee,
        -10 => McValueType::Float64Ieee,
        other => {
            warn!("mci_meas: unknown A2L type id {}, defaulting to UBYTE", other);
            McValueType::Ubyte
        }
    }
}

/// Type lower bound for an unset measurement limit, mirroring xcplite's A2lGetTypeMin (and its C++
/// copy type_min() in mc_meas_abi.hpp): signed integers use their own minimum, int64/float/double clamp to
/// -1e12, unsigned integers start at 0. Kept equal to the runtime so the offline A2L agrees.
fn a2l_type_min(t: i8) -> f64 {
    match t {
        -1 => -128.0,
        -2 => -32768.0,
        -4 => -2147483648.0,
        -8 | -9 | -10 => -1e12,
        _ => 0.0,
    }
}

/// Type upper bound for an unset measurement limit, mirroring xcplite's A2lGetTypeMax / type_max()
/// in mc_meas_abi.hpp: exact maxima for 8/16/32-bit integers, and 1e12 for int64/uint64/float/double.
fn a2l_type_max(t: i8) -> f64 {
    match t {
        -1 => 127.0,
        -2 => 32767.0,
        -4 => 2147483647.0,
        1 => 255.0,
        2 => 65535.0,
        4 => 4294967295.0,
        _ => 1e12,
    }
}

// Read a null-terminated UTF-8 string from a byte slice at a given offset
fn read_cstr_at(data: &[u8], offset: usize) -> Option<String> {
    read_cstr_bounded(data, offset, usize::MAX)
}

/// Read a null-terminated UTF-8 string from a *fixed-width* field: the scan for the terminator
/// stops at the end of the field, not at the next NUL anywhere in the section.
///
/// Every string in an `mci_meta` record is a fixed-width buffer laid end to end with the next one.
/// Scanning past the width made an unterminated field swallow the fields that follow it -- a full
/// 64-byte owner came back as owner+field+unit+comment, and a full 128-byte comment ran into the
/// raw f64 min/max bytes, failed UTF-8 and dropped the whole record. mc_meas_abi.hpp's `chars<N>` always
/// terminates today, so this was latent; the reader is the side that must not trust the section.
fn read_cstr_bounded(data: &[u8], offset: usize, len: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let limit = data.len().min(offset.saturating_add(len));
    let field = &data[offset..limit];
    let end = offset + field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8(data[offset..end].to_vec()).ok()
}

// Path A helper: apply metadata to a typedef field via set_instance_field_support_data.
// Returns true if the metadata was successfully applied.
fn apply_field_metadata(
    reg: &mut Registry,
    var_name: &str,
    kind: &str,
    instance_name: &str,
    field_path: &str,
    meta_data: &[u8],
    offset: usize,
    is_le: bool,
    verbose: usize,
) -> bool {
    let support_data = match kind {
        "unit" | "comment" => {
            let Some(value) = read_cstr_at(meta_data, offset) else {
                warn!("Failed to read string for metadata variable '{}'", var_name);
                return false;
            };
            let sd = McSupportData::new(McObjectType::Unspecified);
            if kind == "unit" { sd.set_unit(value) } else { sd.set_comment(value) }
        }
        "min" | "max" => {
            if offset + 8 > meta_data.len() {
                warn!("Not enough bytes for f64 at offset {} in xcp_meta for '{}'", offset, var_name);
                return false;
            }
            let bytes: [u8; 8] = meta_data[offset..offset + 8].try_into().unwrap();
            let value = if is_le { f64::from_le_bytes(bytes) } else { f64::from_be_bytes(bytes) };
            let sd = McSupportData::new(McObjectType::Unspecified);
            if kind == "min" { sd.set_min(Some(value)) } else { sd.set_max(Some(value)) }
        }
        _ => {
            warn!("Unknown metadata kind '{}' in variable '{}'", kind, var_name);
            return false;
        }
    };

    match reg.set_instance_field_support_data(instance_name, field_path, support_data) {
        Ok(()) => {
            if verbose >= 1 {
                info!("  Metadata {} applied to typedef field '{}.{}'", var_name, instance_name, field_path);
            }
            true
        }
        Err(RegistryError::NotFound(_)) => false, // no such instance or field — not an error, Path B will try
        Err(e) => {
            warn!("Metadata '{}': set_instance_field_support_data failed: {}", var_name, e);
            false
        }
    }
}

// Path B helper: apply metadata directly to an McInstance's mc_support_data.
fn apply_instance_metadata(inst: &mut xcp_registry::McInstance, kind: &str, meta_data: &[u8], offset: usize, is_le: bool) {
    match kind {
        "unit" | "comment" => {
            if let Some(value) = read_cstr_at(meta_data, offset) {
                if kind == "unit" {
                    inst.mc_support_data.update_unit(value);
                } else {
                    inst.mc_support_data.update_comment(value);
                }
            }
        }
        "min" | "max" => {
            if offset + 8 <= meta_data.len() {
                let bytes: [u8; 8] = meta_data[offset..offset + 8].try_into().unwrap();
                let value = if is_le { f64::from_le_bytes(bytes) } else { f64::from_be_bytes(bytes) };
                if kind == "min" {
                    inst.mc_support_data.update_min(Some(value));
                } else {
                    inst.mc_support_data.update_max(Some(value));
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// mc-instrument calibration field metadata (mci_meta section)
//
// A field macro like MC_F64(gain, .unit = "V", .min = 0.0) expands *inside* a class body, so it
// cannot emit xcp_meta__<kind>__<path> objects the way the measurement macros do: an inline static
// data member has vague linkage, lands in a COMDAT flavour of its section, and gcc refuses to mix
// that with the plain objects already in xcp_meta ("causes a section type conflict"). Nor could such
// an object name its owner -- the preprocessor cannot paste the enclosing type into an identifier.
//
// So mc-instrument writes self-describing records into a section of its own instead. Each names the
// declaring *type*; the segments that instantiate it are found here, from the calseg__<name> markers
// register_segments already relies on.

/// `text` as it has to stand between an A2L string's quotes: every `"`, `\`, newline, carriage return
/// and tab escaped, as `\"`, `\\` (issue 222), `\n`, `\r` and `\t` (issue 256) -- escapes a2lfile
/// reads, and so does canape-kernel-config's generator.
///
/// xcp_registry's writer puts what it is given between quotes as it is (`"{comment}"`), so a `"` in
/// a comment, a unit or a segment description ended the string early and a `\` began an escape, and
/// a newline split the object's line, which the generator then refused to read: the A2L said
/// something other than the source. The text of an mc-instrument record is the user's, written as
/// they mean it, so it is escaped here, where it is handed to the registry -- the writer itself is
/// upstream's (issue 251). Any other control character is written as it is: an A2L string has no
/// escape for one, a2lfile's own writer writes it as it is too, and neither a2lfile nor the generator
/// ends a string or a line at it. Nothing after this cuts a string short, so there is no room to
/// count the escapes against: the record's own width capped the text before it was escaped.
fn a2l_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let escape = match c {
            '"' | '\\' => Some(c),
            '\n' => Some('n'),
            '\r' => Some('r'),
            '\t' => Some('t'),
            _ => None,
        };
        match escape {
            Some(e) => {
                out.push('\\');
                out.push(e);
            }
            None => out.push(c),
        }
    }
    out
}

/// Byte layout of one `mci::CalMeta`, fixed by mc-instrument's static_asserts (mc.hpp).
const MCI_META_OWNER_LEN: usize = 64;
const MCI_META_FIELD_LEN: usize = 64;
const MCI_META_UNIT_LEN: usize = 32;
const MCI_META_COMMENT_LEN: usize = 128;
const MCI_META_RECORD_LEN: usize = MCI_META_OWNER_LEN + MCI_META_FIELD_LEN + MCI_META_UNIT_LEN + MCI_META_COMMENT_LEN + 16;

struct CalMetaRecord {
    owner: String,
    field: String,
    unit: String,
    comment: String,
    min: f64,
    max: f64,
}

impl CalMetaRecord {
    /// Nothing stated is the common case -- a field with no metadata still gets a record, because
    /// the macro cannot see which initialisers were given. Both limits zero is mc-instrument's (and
    /// xcplite's) "none given", so such a record is dropped rather than turned into a per-field A2L
    /// typedef that says no more than the shared one it would replace.
    fn is_empty(&self) -> bool {
        self.unit.is_empty() && self.comment.is_empty() && self.min == 0.0 && self.max == 0.0
    }

    fn support_data(&self) -> McSupportData {
        let mut sd = McSupportData::new(McObjectType::Characteristic);
        if !self.unit.is_empty() {
            sd = sd.set_unit(a2l_text(&self.unit));
        }
        if !self.comment.is_empty() {
            sd = sd.set_comment(a2l_text(&self.comment));
        }
        if !(self.min == 0.0 && self.max == 0.0) {
            sd = sd.set_min(Some(self.min)).set_max(Some(self.max));
        }
        sd
    }
}

/// One record, or nothing if the slice is short or the strings are not UTF-8.
fn parse_cal_meta_record(bytes: &[u8], is_le: bool) -> Option<CalMetaRecord> {
    if bytes.len() < MCI_META_RECORD_LEN {
        return None;
    }
    let mut at = 0;
    let mut take = |len: usize| -> Option<String> {
        let s = read_cstr_bounded(bytes, at, len)?;
        at += len;
        Some(s)
    };
    let owner = take(MCI_META_OWNER_LEN)?;
    let field = take(MCI_META_FIELD_LEN)?;
    let unit = take(MCI_META_UNIT_LEN)?;
    let comment = take(MCI_META_COMMENT_LEN)?;
    let read_f64 = |offset: usize| -> f64 {
        let raw: [u8; 8] = bytes[offset..offset + 8].try_into().unwrap();
        if is_le { f64::from_le_bytes(raw) } else { f64::from_be_bytes(raw) }
    };
    Some(CalMetaRecord {
        owner,
        field,
        unit,
        comment,
        min: read_f64(at),
        max: read_f64(at + 8),
    })
}

impl ElfReader {
    /// Read mc-instrument's calibration field metadata from the `mci_meta` section and apply it to
    /// the segments whose type declares each field. Must be called after `register_segments` and
    /// `register_variables`, whichever route built the objects.
    pub fn register_cal_metadata(&self, reg: &mut Registry, verbose: usize) -> Result<(), Box<dyn Error>> {
        let Some(meta_data) = self.debug_data.mci_meta_data.as_ref() else {
            return Ok(());
        };
        if meta_data.is_empty() {
            return Ok(());
        }
        info!("===============================================================");
        info!("Registering mc-instrument calibration metadata from mci_meta section:");

        let segments = self.calseg_roots();
        if segments.is_empty() {
            warn!("mci_meta section present but no calibration segment markers were found; metadata not applied");
            return Ok(());
        }

        // Where inside a segment a struct of a given type sits depends on the segment and the type
        // alone, and every field of that type asks the same question: each segment's tree is
        // walked once per declaring type, not once per record.
        let mut prefixes_of: std::collections::HashMap<(usize, String), Vec<String>> = std::collections::HashMap::new();

        let is_le = self.debug_data.is_little_endian;
        for chunk in meta_data.chunks(MCI_META_RECORD_LEN) {
            let Some(record) = parse_cal_meta_record(chunk, is_le) else {
                // Two different failures share this None. A short chunk is the end of the
                // section and there is nothing after it; anything else is one bad record, and
                // breaking there silently discarded the metadata of every field declared after
                // it.
                if chunk.len() < MCI_META_RECORD_LEN {
                    warn!(
                        "Trailing {} bytes in mci_meta are not a whole record; mc.hpp and this reader disagree on the layout",
                        chunk.len()
                    );
                    break;
                }
                warn!("an mci_meta record could not be decoded (non-UTF-8 text?); skipping it and continuing");
                continue;
            };
            if record.is_empty() {
                continue;
            }
            // A record with no field name describes the type itself, not a field of it. It goes
            // on the INSTANCE of every segment of that type -- which is the only place an A2L
            // will take it: TYPEDEF_STRUCTURE's description is written as "" by the registry's
            // A2L writer with no way to set it.
            if record.field.is_empty() {
                for (segment, root) in &segments {
                    if root.name.as_deref() != Some(record.owner.as_str()) {
                        continue;
                    }
                    if let Some(inst) = reg.instance_list.get_instance_mut(segment, None) {
                        inst.mc_support_data.update_comment(a2l_text(&record.comment));
                        if verbose >= 1 {
                            info!("  Description applied to segment instance '{}': '{}'", segment, record.comment);
                        }
                    }
                }
                continue;
            }
            let mut applied = 0;
            for (index, (segment, root)) in segments.iter().enumerate() {
                // Where inside this segment a struct of the declaring type sits. Usually nowhere
                // or at the root; a nested MC_STRUCT puts it one or more members down, and the
                // field's A2L path then carries that prefix.
                let prefixes = prefixes_of.entry((index, record.owner.clone())).or_insert_with(|| self.paths_to_type(root, &record.owner));
                for prefix in prefixes.iter() {
                    self.apply_cal_metadata(reg, segment, &format!("{}{}", prefix, record.field), &record, verbose);
                    applied += 1;
                }
            }
            // Not an error. MC_MEASTYPE declares fields no calibration segment ever holds, and a
            // type can be declared and never instantiated.
            if applied == 0 {
                debug!("Calibration metadata for '{}.{}': no segment holds that type", record.owner, record.field);
            }
        }
        Ok(())
    }

    /// Apply one record to one segment, on whichever of the two shapes the A2L has.
    ///
    /// A segment written as a real typedef is an INSTANCE of a TYPEDEF_STRUCTURE, so the field is a
    /// component of that typedef; a flattened one is a set of instances named `<segment>.<field>`.
    /// The default is flattened, but the mode is the application's, not ours, so both are tried.
    fn apply_cal_metadata(&self, reg: &mut Registry, segment: &str, field_path: &str, record: &CalMetaRecord, verbose: usize) {
        match reg.set_instance_field_support_data(segment, field_path, record.support_data()) {
            Ok(()) => {
                if verbose >= 1 {
                    info!("  Metadata applied to typedef field '{}.{}'", segment, field_path);
                }
                return;
            }
            Err(RegistryError::NotFound(_)) => {} // not a typedef instance, or no such field: try flattened
            Err(e) => {
                warn!("Calibration metadata '{}.{}': {}", segment, field_path, e);
                return;
            }
        }

        let flat = format!("{}.{}", segment, field_path);
        if let Some(inst) = reg.instance_list.get_instance_mut(&flat, None) {
            if !record.unit.is_empty() {
                inst.mc_support_data.update_unit(a2l_text(&record.unit));
            }
            if !record.comment.is_empty() {
                inst.mc_support_data.update_comment(a2l_text(&record.comment));
            }
            if !(record.min == 0.0 && record.max == 0.0) {
                inst.mc_support_data.update_min(Some(record.min));
                inst.mc_support_data.update_max(Some(record.max));
            }
            if verbose >= 1 {
                info!("  Metadata applied to instance '{}'", flat);
            }
        } else {
            // warn!, not debug!. A record names a field the segment does not have, which is
            // always a defect whatever caused it -- a truncated name in the record, a field
            // renamed on one side of the seam, a stale object file. At debug! the default
            // verbosity said nothing at all, so the unit, comment and limits simply went
            // missing from the A2L with no line anywhere to explain it.
            warn!("Calibration metadata '{}': no typedef field and no instance of that name, so its unit, comment and limits are not in the A2L", flat);
        }
    }

    /// Every calibration segment, with the type of its reference page.
    ///
    /// The same two steps register_segments takes: the marker `calseg__<name>` gives the segment
    /// name, and the reference page variable of that same name gives the type.
    fn calseg_roots(&self) -> Vec<(String, &TypeInfo)> {
        let mut roots = Vec::new();
        for var_name in self.debug_data.variables.keys() {
            let Some(seg_name) = var_name.strip_prefix("calseg__") else {
                continue;
            };
            if seg_name == "epk" {
                continue;
            }
            let root = self
                .debug_data
                .variables
                .get(seg_name)
                .and_then(|infos| infos.iter().find(|info| info.address.0 == 0 && info.address.1 != 0))
                .and_then(|info| self.debug_data.types.get(&info.typeref));
            match root {
                Some(type_info) => roots.push((seg_name.to_string(), type_info)),
                None => warn!("Calibration segment '{}': no reference page variable with a type; metadata not applied", seg_name),
            }
        }
        roots
    }
}

/// Depth cap rather than a visited set: a calibration struct is a POD tree, so it cannot be
/// cyclic, and a cap keeps a chain of type references from being followed forever.
const MCI_MAX_NESTING: usize = 8;

impl ElfReader {
    /// The dotted member paths inside `root` at which a struct named `owner` sits, each ending in
    /// a `.` so a field name appends directly. The empty string when `root` is that type itself.
    ///
    /// Read out of DWARF rather than out of mci_meta: the section says which *type* declares a
    /// field, and the struct tree is what turns that into the path a tool knows the field by. A
    /// field of a nested MC_STRUCT is `<segment>.<outer>.<inner>` in the A2L, and nothing in the
    /// record itself could know the `<outer>` -- one nested type may sit inside several others,
    /// as PidGains sits in both `speed` and `torque`.
    fn paths_to_type(&self, root: &TypeInfo, owner: &str) -> Vec<String> {
        let mut found = Vec::new();
        self.walk_for_type(root, owner, String::new(), &mut found, 0);
        found
    }

    fn walk_for_type(&self, node: &TypeInfo, owner: &str, prefix: String, found: &mut Vec<String>, depth: usize) {
        // Only the first level of a struct is expanded in place; below that a member is a
        // TypeRef into the type map, so the name and the members are both on the other side of
        // it. Walking without resolving finds a nested type one level down and never deeper.
        let Some(node) = self.resolve_type(node) else {
            return;
        };
        if node.name.as_deref() == Some(owner) {
            found.push(prefix.clone());
            // No early return: a struct may hold another of the same type further down, and both
            // are real places the field exists.
        }
        if depth >= MCI_MAX_NESTING {
            return;
        }
        let members = match &node.datatype {
            DbgDataType::Struct { members, .. } | DbgDataType::Class { members, .. } | DbgDataType::Union { members, .. } => members,
            _ => return,
        };
        for (name, (member, _offset)) in members {
            self.walk_for_type(member, owner, format!("{}{}.", prefix, name), found, depth + 1);
        }
    }

    /// xcplite's room for calibration segments in this binary, or nothing when the debug info does
    /// not show it. Both limits are build options (OPTION_CAL_SEGMENT_COUNT, OPTION_CAL_MEM_SIZE),
    /// so they are read from what xcplite was compiled with rather than assumed: the lengths of
    /// the arrays gXcpData.cal_seg_list.offset and gXcpData.cal_seg_list.cal_mem.pool.
    fn calseg_room(&self, seg_relative: bool) -> Option<CalsegRoom> {
        let member = |node: &TypeInfo, name: &str| -> Option<TypeInfo> {
            let node = self.resolve_type(node)?;
            match &node.datatype {
                DbgDataType::Struct { members, .. } | DbgDataType::Union { members, .. } | DbgDataType::Class { members, .. } => {
                    members.get(name).and_then(|(member, _)| self.resolve_type(member)).cloned()
                }
                _ => None,
            }
        };
        let length = |node: &TypeInfo| -> Option<u64> {
            match &node.datatype {
                DbgDataType::Array { dim, .. } if dim.len() == 1 => Some(dim[0]),
                _ => None,
            }
        };
        let var = self.debug_data.variables.get("gXcpData")?.iter().find(|v| v.address.1 != 0)?;
        let data = self.debug_data.types.get(&var.typeref)?;
        let list = member(data, "cal_seg_list")?;
        let slots = length(&member(&list, "offset")?)?;
        let bytes = length(&member(&member(&list, "cal_mem")?, "pool")?)?;
        Some(CalsegRoom {
            // XcpRegisterCalSeg_ refuses an index of XCP_MAX_CALSEG_COUNT - 1 or more, so the last
            // slot is never used; the EPK segment takes the first.
            slots: slots.saturating_sub(1),
            bytes,
            // cal.h keeps a copy of the default page in the segment in segment relative addressing
            // (CALSEG_PAGE_COUNT 4), and points at the application's in absolute addressing (3).
            pages: if seg_relative { 4 } else { 3 },
        })
    }

    /// A type with its TypeRef indirections followed, or nothing when one dangles.
    fn resolve_type<'a>(&'a self, node: &'a TypeInfo) -> Option<&'a TypeInfo> {
        let mut current = node;
        for _ in 0..MCI_MAX_NESTING {
            let DbgDataType::TypeRef(offset, _) = current.datatype else {
                return Some(current);
            };
            current = self.debug_data.types.get(&offset)?;
        }
        None
    }
}

/// Added to upstream (issue 258): A2L's string rules, which the offline A2L reaches only in part --
/// our writer escapes a quote as `\"`, never as `""`.
#[cfg(test)]
mod a2l_token_tests {
    use super::*;

    fn texts(text: &str) -> Vec<&str> {
        a2l_tokens(text).iter().map(|t| t.text).collect()
    }

    #[test]
    fn a_string_is_one_token_whatever_it_holds() {
        assert_eq!(
            texts(r#"/begin MEASUREMENT m "a \"q\" /end MEASUREMENT" UBYTE"#),
            ["/begin", "MEASUREMENT", "m", r#""a \"q\" /end MEASUREMENT""#, "UBYTE"]
        );
        assert_eq!(texts(r#""say ""/end MEASUREMENT"" here" X"#), [r#""say ""/end MEASUREMENT"" here""#, "X"]);
        assert_eq!(texts(r#""C:\\" ECU_ADDRESS_EXTENSION 1"#), [r#""C:\\""#, "ECU_ADDRESS_EXTENSION", "1"]);
        assert_eq!(texts(r#""" X "open"#), [r#""""#, "X", r#""open"#]);
    }

    /// Added to upstream (issue 294): a comment is no token, and a quote in one opens no string.
    #[test]
    fn a_comment_is_skipped_whatever_it_holds() {
        assert_eq!(
            texts("/* function = step<'\\\"'>, CFA = 16 */ /begin EVENT \"e\" 0 /end EVENT"),
            ["/begin", "EVENT", "\"e\"", "0", "/end", "EVENT"]
        );
        assert_eq!(texts("A // a \"line /end MEASUREMENT\nB"), ["A", "B"]);
        assert_eq!(texts("A/*x*/B C//y"), ["A", "B", "C"]);
        assert_eq!(texts(r#""/* in a string */" "// too""#), [r#""/* in a string */""#, r#""// too""#]);
        assert_eq!(texts("A /**/ B /*/ C */ D"), ["A", "B", "D"]);
        assert_eq!(texts("A /* never closed \" B"), ["A"]);
        assert_eq!(texts("/begin /include x"), ["/begin", "/include", "x"]);
    }

    #[test]
    fn a_quote_in_a_comment_moves_no_block() {
        let text = "/* function = step<'\\\"'> */ /begin MEASUREMENT m \"c\" ULONG ECU_ADDRESS_EXTENSION 127 READ_WRITE /end MEASUREMENT";
        let tokens = a2l_tokens(text);
        let blocks = a2l_measurements(&tokens);
        assert_eq!(blocks.len(), 1);
        assert_eq!(a2l_address_extension(blocks[0]), Some(XCP_ADDR_EXT_ID));
        assert!(blocks[0].iter().any(|t| t.text == "READ_WRITE"));
    }

    /// Added to upstream (issue 314): the server's values go into the real blocks, and a description
    /// naming them is neither counted nor changed.
    #[test]
    fn the_protocol_layer_is_found_outside_strings() {
        let named = r#""/begin PROTOCOL_LAYER 0x0104 1 2 3 4 5 6 7 8 9 /end PROTOCOL_LAYER, /begin TIMESTAMP_SUPPORTED 0x1 SIZE_DWORD UNIT_1US /end TIMESTAMP_SUPPORTED""#;
        let text = format!(
            "/begin MEASUREMENT m {named} ULONG /end MEASUREMENT /* /begin PROTOCOL_LAYER */\n\
             /begin PROTOCOL_LAYER\n  0x0104 1000 2000 0 0 0 0 0 252 1468 BYTE_ORDER_MSB_LAST\n/end PROTOCOL_LAYER\n\
             /begin TIMESTAMP_SUPPORTED\n  0x1 SIZE_DWORD UNIT_1US\n/end TIMESTAMP_SUPPORTED\n"
        );
        let path = std::env::temp_dir().join(format!("xcpclient_314_{}.a2l", std::process::id()));
        std::fs::write(&path, &text).unwrap();
        let server = ServerProtocol { max_cto: 248, max_dto: 1024, timestamp_mode: 0x04 | 0x08, timestamp_ticks: 1 };
        let fixed = fix_protocol_layer(&path, &server).map(|_| std::fs::read_to_string(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let fixed = fixed.unwrap();
        assert!(fixed.contains(named));
        assert!(fixed.contains("0x0104 1000 2000 0 0 0 0 0 248 1024 BYTE_ORDER_MSB_LAST"));
        assert!(fixed.contains("/begin TIMESTAMP_SUPPORTED\n  0x1 SIZE_DWORD UNIT_1NS TIMESTAMP_FIXED\n/end TIMESTAMP_SUPPORTED"));
    }

    #[test]
    fn a_block_and_its_extension_are_read_outside_strings() {
        let text = r#"/begin MEASUREMENT m "ends at /end MEASUREMENT, says ECU_ADDRESS_EXTENSION 1" ULONG ECU_ADDRESS_EXTENSION 0x7F READ_WRITE /end MEASUREMENT"#;
        let tokens = a2l_tokens(text);
        let blocks = a2l_measurements(&tokens);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].last().map(|t| t.end()), Some(text.len()));
        assert_eq!(a2l_address_extension(blocks[0]), Some(XCP_ADDR_EXT_ID));
    }
}

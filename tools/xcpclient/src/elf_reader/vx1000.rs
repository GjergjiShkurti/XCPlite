//--------------------------------------------------------------------------------------------------------------------------------------------------
// mc-instrument's VX1000 backend, as the ELF holds it
//
// A firmware measured by a VX1000 (mc-instrument's mc_vx.h and mc_vx.hpp, and their runtime mc_vx.c) links no XCP server of its own: the
// VX1000 is the server, and the firmware describes itself to it at startup. Its records say more than an xcplite application's:
//
// - MC_APP's VX1000 options, in the application record: the VX1000 Timing Bundle (.timing_active, .timing_cores), the VX1000's own values
//   (.vx_monitor_active), whether mc_vx.c can set a channel's mode in the driver's release, and the driver's channel count.
// - A marker and a flags byte in each event record's reserved bytes: a multi-buffer event (MC_MULTIBUF), a Timing Bundle template.
// - How the events are numbered, which mc_vx.c does the same way: the records in section order, each named record that is no template and
//   whose name is new the next channel from 0; with the bundle on, its OS event per traced core, then its runnable event per core.
// - The Timing Bundle's templates, which mc_vx.c always holds: two event records and a trace word on each, which stand for the events
//   OsTaskInfo_C<n> and OsRunInfo_C<n> and the words VX1000If_Os_Trace[n] and VX1000If_Rte_Trace[n] of every traced core n.
//
// All of it is read only in an ELF that does not link xcplite: there the records are this backend's own.

use std::collections::{HashMap, HashSet};
use std::error::Error;

use object::{Object, ObjectSymbol};
use xcp_registry::Registry;

use super::vx_a2l::{TraceKind, TraceWord, Tracing, VxA2l, trace_name_tables};
use super::{ElfReader, MCI_APP_CHANNEL_COUNT, MCI_APP_RECORD_LEN, MCI_APP_TIMING_ACTIVE, MCI_APP_TIMING_CORES, MCI_APP_VX_MONITOR, MCI_APP_W1_KNOWN, MciRecord, a2l_type_size};

/// MC_APP's VX1000 options, and what MC_APP adds to them, as the application record states them (mc_vx.h, mci_app_meta).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct VxOptions {
    /// .timing_active: the Timing Bundle's events and trace words are mc-instrument's
    pub(crate) timing_active: bool,
    /// .timing_cores: how many cores the bundle traces; 0, left out, is one
    pub(crate) timing_cores: u8,
    /// .vx_monitor_active: the VX1000's own values go into the A2L
    pub(crate) vx_monitor_active: bool,
    /// mc_vx.c can set a channel's mode in the VX1000 driver's release (MCI_VX_W1_KNOWN)
    pub(crate) w1_known: bool,
    /// VX1000_OLDA_ACTIVE_EVT_CNT_MAX where MC_APP expands: the driver's channel count
    pub(crate) channel_count: u16,
}

impl VxOptions {
    /// The cores the Timing Bundle traces, as MC_APP states them
    pub(crate) fn cores(&self) -> u16 {
        u16::from(self.timing_cores.max(1))
    }
}

/// The channels mc-instrument numbers at most, 0 to 30. With no per-channel rows in its configuration the VX1000 driver handles channels 0 to
/// 30 alike, and channel 31 is the VX1000's own. Up to 31 channels the driver keeps the channel modes in four words of RAM, which mc_vx.c
/// writes for a multi-buffer event; above 31 they are a table in flash, which it cannot.
pub(crate) const MAX_CHANNELS: u16 = 31;

/// True when an application record asks for the Timing Bundle: the debug information reader reads the bundle's enumerators only then.
pub(crate) fn timing_requested(mci_app: Option<&[u8]>) -> bool {
    mci_app.is_some_and(|record| record.len() == MCI_APP_RECORD_LEN && record[MCI_APP_TIMING_ACTIVE] != 0)
}

/// The VX1000 options of a whole application record. A switch that is neither 0 nor 1 is a record this reader does not lay out as its writer
/// did, and is refused rather than read as on.
pub(crate) fn parse_vx_options(record: &[u8], little_endian: bool) -> Result<VxOptions, String> {
    debug_assert_eq!(record.len(), MCI_APP_RECORD_LEN);
    let switch = |at: usize, what: &str| match record[at] {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!(
            "the mci_app record holds {other} for {what}, where 0 or 1 belongs: it is not laid out as this xcpclient reads it. \
             Rebuild with the mc-instrument headers this xcpclient belongs with; no A2L is written"
        )),
    };
    let count = [record[MCI_APP_CHANNEL_COUNT], record[MCI_APP_CHANNEL_COUNT + 1]];
    Ok(VxOptions {
        timing_active: switch(MCI_APP_TIMING_ACTIVE, ".timing_active")?,
        timing_cores: record[MCI_APP_TIMING_CORES],
        vx_monitor_active: switch(MCI_APP_VX_MONITOR, ".vx_monitor_active")?,
        w1_known: switch(MCI_APP_W1_KNOWN, "whether mc_vx.c knows the VX1000 driver's release")?,
        channel_count: if little_endian { u16::from_le_bytes(count) } else { u16::from_be_bytes(count) },
    })
}

//------------------------------------------------------------------------
// Event records

/// The marker mc-instrument's VX1000 headers write into an event record's first reserved byte; the flags byte follows it.
pub(crate) const EVENT_MARKER: u8 = 0xC6;
/// The marker of a record that fixed its own channel, which the headers wrote before mc-instrument numbered the events
pub(crate) const EVENT_MARKER_FIXED: u8 = 0xC5;
/// A flag: the event's channel is multi-buffer (MC_MULTIBUF)
pub(crate) const EVENT_MULTIBUF: u8 = 0x01;
/// A flag: a Timing Bundle template, which stands for one event per traced core and is no event of its own
pub(crate) const EVENT_TEMPLATE: u8 = 0x02;

/// The flags of a VX1000 firmware's event record, from the first two of its reserved bytes, `marker` and `flags`: none without the marker. A
/// record that fixes its channel, from the headers before the numbering, is refused, and so is a marker or a flag this reader does not know.
pub(crate) fn event_flags(name: &str, marker: u8, flags: u8) -> Result<u8, String> {
    match marker {
        0 => Ok(0),
        EVENT_MARKER if flags & !(EVENT_MULTIBUF | EVENT_TEMPLATE) == 0 => Ok(flags),
        EVENT_MARKER => Err(format!(
            "event '{name}': its record's flags are 0x{flags:02X}, with a flag this reader does not know (0x01 multi-buffer, 0x02 Timing Bundle \
             template): rebuild with the mc-instrument headers this xcpclient belongs with; no A2L is written"
        )),
        EVENT_MARKER_FIXED => Err(format!(
            "event '{name}': its record fixes a channel (MEASURE_CHANNEL or MC_EVENT), which mc-instrument no longer does: it numbers the events \
             itself. Rebuild with the current headers; no A2L is written"
        )),
        other => Err(format!(
            "event '{name}': its record's reserved bytes start with 0x{other:02X}, which is no marker this reader knows (0x{EVENT_MARKER:02X}): \
             rebuild with the current headers; no A2L is written"
        )),
    }
}

/// One record of the xcp_evts section, as the numbering sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventSlot<'a> {
    /// A record without a name: a null name pointer
    Unnamed,
    /// An event
    Event(&'a str),
    /// A Timing Bundle template
    Template(&'a str),
}

/// The channel of each record, in section order: none for a record without a name, for a template, and for a name already numbered (its
/// first record keeps it); the next channel from 0 for every other. mc_vx.c numbers the events the same way, and an xcplite server numbers
/// them by their position in the section, which is the same where the section holds no such record.
pub(crate) fn number_events(slots: &[EventSlot]) -> Result<Vec<Option<u16>>, String> {
    let mut numbered: HashSet<&str> = HashSet::new();
    let mut next: usize = 0;
    let mut channels = Vec::with_capacity(slots.len());
    for slot in slots {
        let channel = match slot {
            EventSlot::Event(name) if numbered.insert(name) => {
                let channel = u16::try_from(next).map_err(|_| format!("event '{name}' would be event {next}, past the 16 bit event numbers"))?;
                next += 1;
                Some(channel)
            }
            _ => None,
        };
        channels.push(channel);
    }
    Ok(channels)
}

/// Refuse more events than the channels mc-instrument numbers (`MAX_CHANNELS`, and no more than the driver's channel count), and an event
/// whose channel mc_vx.c is to make multi-buffer while the driver keeps its modes where mc_vx.c cannot set them. `events` are the firmware's
/// events in channel order, `multibuf` those of them flagged MC_MULTIBUF, `bundle` the Timing Bundle's events, which are multi-buffer too.
pub(crate) fn check_channel_count(options: &VxOptions, events: &[&str], multibuf: &[&str], bundle: &[(String, u16)]) -> Result<(), String> {
    let usable = options.channel_count.min(MAX_CHANNELS);
    let total = events.len() + bundle.len();
    if total > usize::from(usable) {
        let of_the_bundle = if bundle.is_empty() {
            String::new()
        } else {
            format!(" and {} of the Timing Bundle (two per traced core)", bundle.len())
        };
        return Err(format!(
            "{total} events need a channel each, {} of the firmware{of_the_bundle}, but the firmware has {usable}: its VX1000 driver is built with \
             VX1000_OLDA_ACTIVE_EVT_CNT_MAX {}, and mc-instrument numbers at most {MAX_CHANNELS} channels, 0 to 30, which the driver handles without \
             a row of its own in VX1000_cfg.h. Measure on fewer events; no A2L is written",
            events.len(),
            options.channel_count
        ));
    }
    if options.channel_count > MAX_CHANNELS && (!multibuf.is_empty() || !bundle.is_empty()) {
        let mut named: Vec<String> = multibuf.iter().map(|name| format!("'{name}'")).collect();
        if !bundle.is_empty() {
            named.push("the Timing Bundle's".to_string());
        }
        return Err(format!(
            "the firmware has multi-buffer events ({}), but its VX1000 driver is built with VX1000_OLDA_ACTIVE_EVT_CNT_MAX {}: above {MAX_CHANNELS} \
             the driver keeps the channel modes in a table in flash, which mc_vx.c cannot set, and the events would stay single-buffer. Build the \
             driver with {MAX_CHANNELS} channels or fewer; no A2L is written",
            named.join(", "),
            options.channel_count
        ));
    }
    Ok(())
}

/// What a firmware's event named `name` clashes with, while MC_APP switches on what xcpclient adds to the A2L under that name: with the
/// Timing Bundle the group Tracing and the bundle's events, with the VX1000's own values the groups VX1000, BaseModule and Serial. An event
/// is a group of its own name in the A2L, and the bundle's are events as well. None for a name that is free.
pub(crate) fn reserved_event_name(name: &str, options: &VxOptions) -> Option<String> {
    if options.timing_active {
        if name == "Tracing" {
            return Some("the A2L group Tracing, which xcpclient adds for the Timing Bundle while MC_APP sets .timing_active".to_string());
        }
        for template in BUNDLE_TEMPLATES {
            if let Some(core) = name.strip_prefix(template).and_then(|rest| rest.strip_prefix("_C"))
                && !core.is_empty()
                && core.bytes().all(|b| b.is_ascii_digit())
            {
                return Some(format!(
                    "the Timing Bundle's event of core {core}, which xcpclient adds, whatever the core count, while MC_APP sets .timing_active"
                ));
            }
        }
    }
    if options.vx_monitor_active && matches!(name, "VX1000" | "BaseModule" | "Serial") {
        return Some(format!(
            "the A2L group {name}, which xcpclient adds for the VX1000's own values while MC_APP sets .vx_monitor_active"
        ));
    }
    None
}

//------------------------------------------------------------------------
// The Timing Bundle

/// The bundle's templates, the OS event's and the runnable event's, in the order their per-core events are numbered.
pub(crate) const BUNDLE_TEMPLATES: [&str; 2] = ["OsTaskInfo", "OsRunInfo"];
/// The bundle's trace arrays, one word per traced core, which the template's trace words stand for: the OS trace and the runnable trace.
pub(crate) const BUNDLE_TRACES: [&str; 2] = ["VX1000If_Os_Trace", "VX1000If_Rte_Trace"];
/// mc_vx.c's channel arrays, which the bundle's hooks raise their events through, one 16-bit entry per core it can trace.
pub(crate) const BUNDLE_CHANNEL_ARRAYS: [&str; 2] = ["mci_vx_timing_os_channel", "mci_vx_timing_rte_channel"];

/// The event a template stands for on core `core`: the suffix also with one core, so that adding a core renames nothing.
pub(crate) fn bundle_event(template: &str, core: u16) -> String {
    format!("{template}_C{core}")
}

/// The bundle's events and their channels, after the firmware's `first` channels: the OS event of each core, then the runnable event of each.
pub(crate) fn bundle_events(first: u16, cores: u16) -> Vec<(String, u16)> {
    let mut events = Vec::with_capacity(BUNDLE_TEMPLATES.len() * usize::from(cores));
    for (t, template) in (0u16..).zip(BUNDLE_TEMPLATES) {
        for core in 0..cores {
            events.push((bundle_event(template, core), first + t * cores + core));
        }
    }
    events
}

/// The Timing Bundle, switched on and checked: the cores it traces and its two trace words.
#[derive(Debug, Clone)]
pub(crate) struct TimingBundle {
    pub(crate) cores: u16,
    /// The record of the OS word and of the runnable word, each on its template, at the address of core 0's word
    pub(crate) words: [MciRecord; 2],
}

/// The records as the A2L describes them: a record on a Timing Bundle template, one of `templates`, stands for one word per core when the
/// bundle is on -- core n's at the address of core 0's plus n words, on core n's own event -- and for none when it is off.
pub(crate) fn expand_bundle_records(records: Vec<MciRecord>, templates: &[String], bundle: Option<&TimingBundle>) -> Vec<MciRecord> {
    let mut expanded = Vec::with_capacity(records.len());
    for record in records {
        if !templates.contains(&record.event) {
            expanded.push(record);
            continue;
        }
        let Some(bundle) = bundle else {
            continue;
        };
        let stride = a2l_type_size(record.ty);
        for core in 0..bundle.cores {
            expanded.push(MciRecord {
                event: bundle_event(&record.event, core),
                addr: record.addr.map(|addr| addr + u32::from(core) * stride),
                ..record.clone()
            });
        }
    }
    expanded
}

impl ElfReader {
    /// MC_APP's VX1000 options, as the application record states them. None in an ELF that links xcplite, whose record carries them only
    /// because one MC_APP builds on both backends, and in one without an application record.
    pub(crate) fn vx_options(&self) -> Result<Option<VxOptions>, Box<dyn Error>> {
        if self.is_xcplite_target() {
            return Ok(None);
        }
        let Some(record) = self.mci_app_record()? else {
            return Ok(None);
        };
        Ok(Some(parse_vx_options(record, self.debug_data.is_little_endian)?))
    }

    /// The Timing Bundle, when MC_APP switches it on in a VX1000 firmware. Refused when the driver's release is one mc_vx.c cannot set a
    /// multi-buffer channel in, when the bundle is not linked, when it traces another number of cores than `.timing_cores` says, and when
    /// mc_vx.c has room for fewer: each would be an A2L whose bundle events are never raised, or not multi-buffer.
    pub(crate) fn timing_bundle(&self) -> Result<Option<TimingBundle>, Box<dyn Error>> {
        let Some(options) = self.vx_options()? else {
            return Ok(None);
        };
        if !options.timing_active {
            return Ok(None);
        }
        if !options.w1_known {
            return Err(
                "MC_APP sets .timing_active, but the firmware's VX1000 driver is a release mc_vx.c cannot set a channel's mode in \
                 (MCI_VX_W1_KNOWN is 0 where MC_APP expands): the Timing Bundle's events would not be multi-buffer, and would lose \
                 samples. Build with a driver release mc_vx.c knows, or drop .timing_active; no A2L is written"
                    .into(),
            );
        }

        let templates = self.event_templates()?;
        let records = self.raw_mci_records()?.unwrap_or_default();
        let mut words = Vec::with_capacity(BUNDLE_TEMPLATES.len());
        for template in BUNDLE_TEMPLATES {
            if !templates.iter().any(|t| t == template) {
                return Err(format!(
                    "MC_APP sets .timing_active, but the ELF has no Timing Bundle template {template} in its xcp_evts section: the firmware's mc_vx.c \
                     is older than its headers. Rebuild with the mc_vx.c of those headers; no A2L is written"
                )
                .into());
            }
            let on: Vec<&MciRecord> = records.iter().filter(|r| r.event == template).collect();
            let [word] = on.as_slice() else {
                return Err(format!(
                    "the Timing Bundle template {template} has {} trace words in the mci_meas section, where mc_vx.c writes one; no A2L is written",
                    on.len()
                )
                .into());
            };
            if a2l_type_size(word.ty) != 4 || word.ty < 0 || word.x_dim > 1 {
                return Err(format!(
                    "the Timing Bundle's trace word {template}.{} is not one uint32 in its mci_meas record, as mc_vx.c writes it; no A2L is written",
                    word.name
                )
                .into());
            }
            words.push((*word).clone());
        }

        let names: Vec<&str> = BUNDLE_TRACES.iter().chain(BUNDLE_CHANNEL_ARRAYS.iter()).copied().collect();
        let symbols = defined_symbols(&self.path, &names)?;
        let size_of = |name: &str| symbols.get(name).map(|(_, size)| *size).filter(|size| *size > 0);
        let unlinked: Vec<&str> = BUNDLE_TRACES.iter().copied().filter(|name| size_of(name).is_none()).collect();
        if !unlinked.is_empty() || words.iter().any(|word| word.addr.is_none()) {
            let missing = if unlinked.is_empty() { BUNDLE_TRACES.to_vec() } else { unlinked };
            return Err(format!(
                "MC_APP sets .timing_active, but the VX1000 Timing Bundle is not linked: the ELF defines no {}. Link the bundle, or drop \
                 .timing_active; no A2L is written",
                missing.join(" and no ")
            )
            .into());
        }
        let cores = options.cores();
        for (word, array) in words.iter().zip(BUNDLE_TRACES) {
            let (at, size) = symbols[array];
            let addr = word.addr.map(u64::from).unwrap_or_default();
            if addr != at {
                return Err(format!(
                    "the Timing Bundle's trace word {}.{} is at 0x{addr:08X} in its mci_meas record, and {array} at 0x{at:08X} in the symbol table: \
                     they are one variable to mc_vx.c; no A2L is written",
                    word.event, word.name
                )
                .into());
            }
            if size % 4 != 0 || size / 4 != u64::from(cores) {
                return Err(format!(
                    "MC_APP's .timing_cores says the Timing Bundle traces {cores} core{}{}, but {array} holds {} bytes, {}: set .timing_cores to \
                     the bundle's VX1000IF_TRACE_NUM_CORES; no A2L is written",
                    if cores == 1 { "" } else { "s" },
                    if options.timing_cores == 0 { " (it is left out, which is one)" } else { "" },
                    size,
                    if size % 4 == 0 {
                        format!("one 32-bit word per core for {} cores", size / 4)
                    } else {
                        "no whole number of 32-bit words".to_string()
                    }
                )
                .into());
            }
        }
        let room = BUNDLE_CHANNEL_ARRAYS.iter().map(|array| size_of(array).map(|size| size / 2)).collect::<Option<Vec<u64>>>();
        let Some(room) = room.and_then(|room| room.into_iter().min()) else {
            return Err(format!(
                "MC_APP sets .timing_active, but the ELF defines no {}: its mc_vx.c is older than its headers. Rebuild with the mc_vx.c of those \
                 headers; no A2L is written",
                BUNDLE_CHANNEL_ARRAYS.join(" or ")
            )
            .into());
        };
        if u64::from(cores) > room {
            return Err(format!(
                "MC_APP's .timing_cores is {cores}, but mc_vx.c traces at most {room} cores: its channel arrays ({}) hold {room} entries. MC_SYNC \
                 leaves the Timing Bundle out for this firmware; no A2L is written",
                BUNDLE_CHANNEL_ARRAYS.join(", ")
            )
            .into());
        }
        let [os, rte]: [MciRecord; 2] = words.try_into().expect("one word per template");
        Ok(Some(TimingBundle { cores, words: [os, rte] }))
    }

    /// What a VX1000 firmware's MC_APP adds to its A2L once xcp_registry has written it (vx_a2l.rs, write_vx_a2l), with the channels `reg`
    /// gave the Timing Bundle's events. None when MC_APP switches nothing on, and in an ELF that links xcplite. The trace's names come from the
    /// debug information; a table that it does not give is said, and left out.
    pub(crate) fn vx_a2l(&self, reg: &Registry) -> Result<Option<VxA2l>, Box<dyn Error>> {
        let Some(options) = self.vx_options()? else {
            return Ok(None);
        };
        let tracing = match self.timing_bundle()? {
            None => None,
            Some(bundle) => {
                let mut words = Vec::with_capacity(2 * usize::from(bundle.cores));
                for (kind, record) in [TraceKind::Os, TraceKind::Runnable].into_iter().zip(&bundle.words) {
                    let addr = record.addr.expect("timing_bundle refuses a trace word without an address");
                    for core in 0..bundle.cores {
                        let event = bundle_event(&record.event, core);
                        let channel = reg
                            .event_list
                            .find_event(&event, 0)
                            .map(|e| e.id)
                            .ok_or_else(|| format!("the Timing Bundle's event {event} is not registered"))?;
                        words.push(TraceWord {
                            kind,
                            event,
                            channel,
                            name: record.name.clone(),
                            addr: addr + 4 * u32::from(core),
                        });
                    }
                }
                let (threads, runnables, warnings) = trace_name_tables(self.debug_data.trace_enumerators.as_ref());
                for warning in warnings {
                    log::warn!("{warning}");
                }
                Some(Tracing {
                    little_endian: self.debug_data.is_little_endian,
                    words,
                    threads,
                    runnables,
                })
            }
        };
        if tracing.is_none() && !options.vx_monitor_active {
            return Ok(None);
        }
        Ok(Some(VxA2l {
            tracing,
            vx_monitor: options.vx_monitor_active,
        }))
    }
}

/// The address and the size of each of `names` that the ELF at `path` defines in its symbol table. A name a weak reference leaves undefined
/// is not among them.
fn defined_symbols(path: &str, names: &[&str]) -> Result<HashMap<String, (u64, u64)>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open '{path}' for its symbol table: {e}"))?;
    // Safety: the file is mapped read-only for the duration of this function, as the debug information reader maps it
    let data = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| format!("cannot map '{path}' for its symbol table: {e}"))?;
    let elf = object::File::parse(&*data).map_err(|e| format!("cannot read the symbol table of '{path}': {e}"))?;
    let mut found = HashMap::new();
    for symbol in elf.symbols() {
        if symbol.is_undefined() {
            continue;
        }
        if let Ok(name) = symbol.name()
            && names.contains(&name)
        {
            found.insert(name.to_string(), (symbol.address(), symbol.size()));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcp_registry::Registry;

    fn record(timing: u8, cores: u8, monitor: u8, known: u8, count: u16, little_endian: bool) -> Vec<u8> {
        let mut record = vec![0u8; MCI_APP_RECORD_LEN];
        record[..7].copy_from_slice(b"VXdemo\0");
        record[MCI_APP_TIMING_ACTIVE] = timing;
        record[MCI_APP_TIMING_CORES] = cores;
        record[MCI_APP_VX_MONITOR] = monitor;
        record[MCI_APP_W1_KNOWN] = known;
        let count = if little_endian { count.to_le_bytes() } else { count.to_be_bytes() };
        record[MCI_APP_CHANNEL_COUNT..MCI_APP_CHANNEL_COUNT + 2].copy_from_slice(&count);
        record
    }

    #[test]
    fn the_vx1000_options_are_read_by_offset_in_either_byte_order() {
        assert_eq!((MCI_APP_TIMING_ACTIVE, MCI_APP_CHANNEL_COUNT, MCI_APP_RECORD_LEN), (212, 216, 218));
        for little_endian in [true, false] {
            let options = parse_vx_options(&record(1, 2, 1, 1, 31, little_endian), little_endian).unwrap();
            assert_eq!(
                options,
                VxOptions {
                    timing_active: true,
                    timing_cores: 2,
                    vx_monitor_active: true,
                    w1_known: true,
                    channel_count: 31
                },
                "little endian {little_endian}"
            );
            assert_eq!(options.cores(), 2);
        }
        // everything off, and .timing_cores left out, which is one core
        let options = parse_vx_options(&record(0, 0, 0, 0, 0, true), true).unwrap();
        assert_eq!(options, VxOptions::default());
        assert_eq!(options.cores(), 1);
        // a switch that is neither 0 nor 1 is a record laid out otherwise
        let error = parse_vx_options(&record(2, 1, 0, 1, 31, true), true).unwrap_err();
        assert!(error.contains("holds 2 for .timing_active"), "{error}");
        assert!(parse_vx_options(&record(1, 1, 7, 1, 31, true), true).unwrap_err().contains(".vx_monitor_active"));
    }

    #[test]
    fn only_a_whole_record_with_timing_active_asks_for_the_bundle() {
        assert!(timing_requested(Some(&record(1, 1, 0, 1, 31, true))));
        assert!(!timing_requested(Some(&record(0, 1, 1, 1, 31, true))));
        assert!(!timing_requested(Some(&record(1, 1, 0, 1, 31, true)[..212])));
        assert!(!timing_requested(None));
    }

    #[test]
    fn an_event_records_marker_gives_its_flags_and_an_old_or_unknown_one_is_refused() {
        assert_eq!(event_flags("Frame", 0, 0), Ok(0));
        assert_eq!(event_flags("Frame", EVENT_MARKER, 0), Ok(0));
        assert_eq!(event_flags("Frame", EVENT_MARKER, EVENT_MULTIBUF), Ok(EVENT_MULTIBUF));
        assert_eq!(event_flags("OsTaskInfo", EVENT_MARKER, EVENT_MULTIBUF | EVENT_TEMPLATE), Ok(0x03));
        let error = event_flags("Frame", EVENT_MARKER_FIXED, 5).unwrap_err();
        assert!(
            error.contains("event 'Frame': its record fixes a channel") && error.contains("Rebuild with the current headers"),
            "{error}"
        );
        let error = event_flags("Frame", 0x7E, 0).unwrap_err();
        assert!(error.contains("0x7E, which is no marker this reader knows (0xC6)"), "{error}");
        let error = event_flags("Frame", EVENT_MARKER, 0x04).unwrap_err();
        assert!(error.contains("flags are 0x04, with a flag this reader does not know"), "{error}");
    }

    #[test]
    fn events_are_numbered_in_section_order_without_templates_names_already_numbered_and_unnamed_records() {
        use EventSlot::*;
        assert_eq!(number_events(&[Event("a"), Event("b"), Event("c")]), Ok(vec![Some(0), Some(1), Some(2)]));
        assert_eq!(
            number_events(&[
                Template("OsTaskInfo"),
                Event("Init"),
                Unnamed,
                Event("Frame"),
                Event("Init"),
                Template("OsRunInfo"),
                Event("Sound")
            ]),
            Ok(vec![None, Some(0), None, Some(1), None, None, Some(2)])
        );
        assert_eq!(number_events(&[]), Ok(vec![]));
    }

    #[test]
    fn the_bundles_events_follow_the_firmwares_os_events_of_every_core_first() {
        assert_eq!(bundle_events(6, 1), [("OsTaskInfo_C0".to_string(), 6), ("OsRunInfo_C0".to_string(), 7)]);
        let names: Vec<(String, u16)> = bundle_events(2, 3);
        assert_eq!(
            names,
            [
                ("OsTaskInfo_C0", 2),
                ("OsTaskInfo_C1", 3),
                ("OsTaskInfo_C2", 4),
                ("OsRunInfo_C0", 5),
                ("OsRunInfo_C1", 6),
                ("OsRunInfo_C2", 7)
            ]
            .map(|(name, channel)| (name.to_string(), channel))
        );
        assert!(bundle_events(0, 0).is_empty());
    }

    fn options(count: u16, timing: bool, monitor: bool) -> VxOptions {
        VxOptions {
            timing_active: timing,
            timing_cores: 1,
            vx_monitor_active: monitor,
            w1_known: true,
            channel_count: count,
        }
    }

    #[test]
    fn more_events_than_usable_channels_are_refused() {
        let events: Vec<String> = (0..31).map(|i| format!("e{i}")).collect();
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        // 31 channels, 0 to 30, all taken: fine; one more, or the bundle's two, is refused
        assert_eq!(check_channel_count(&options(31, false, false), &events, &[], &[]), Ok(()));
        let error = check_channel_count(&options(31, true, false), &events, &[], &bundle_events(31, 1)).unwrap_err();
        assert!(error.starts_with("33 events need a channel each, 31 of the firmware and 2 of the Timing Bundle"), "{error}");
        assert!(error.contains("but the firmware has 31") && error.contains("no A2L is written"), "{error}");
        // a driver with fewer channels has fewer; one with more still has 31 for mc-instrument
        let error = check_channel_count(&options(8, false, false), &events[..9], &[], &[]).unwrap_err();
        assert!(error.starts_with("9 events need a channel each, 9 of the firmware, but the firmware has 8"), "{error}");
        assert_eq!(check_channel_count(&options(64, false, false), &events, &[], &[]), Ok(()));
        assert!(check_channel_count(&options(64, false, false), &[&events[..], &["e31"]].concat(), &[], &[]).is_err());
        // the VX1000's own events take no channel of the firmware's
        assert_eq!(check_channel_count(&options(0, false, true), &[], &[], &[]), Ok(()));
    }

    #[test]
    fn a_multi_buffer_event_with_more_than_31_driver_channels_is_refused() {
        let error = check_channel_count(&options(64, false, false), &["Frame", "Sound"], &["Frame"], &[]).unwrap_err();
        assert!(
            error.starts_with("the firmware has multi-buffer events ('Frame'), but") && error.contains("VX1000_OLDA_ACTIVE_EVT_CNT_MAX 64"),
            "{error}"
        );
        let error = check_channel_count(&options(64, true, false), &["Frame"], &["Frame"], &bundle_events(1, 1)).unwrap_err();
        assert!(error.starts_with("the firmware has multi-buffer events ('Frame', the Timing Bundle's), but"), "{error}");
        assert_eq!(check_channel_count(&options(31, true, false), &["Frame"], &["Frame"], &bundle_events(1, 1)), Ok(()));
    }

    #[test]
    fn an_event_may_not_be_named_like_what_a_switched_on_feature_adds() {
        let timing = options(31, true, false);
        let monitor = options(31, false, true);
        let neither = options(31, false, false);
        for name in ["Tracing", "OsTaskInfo_C0", "OsRunInfo_C0", "OsTaskInfo_C3", "OsRunInfo_C12"] {
            assert!(reserved_event_name(name, &timing).is_some(), "{name}");
            assert_eq!(reserved_event_name(name, &monitor), None, "{name}");
        }
        for name in ["VX1000", "BaseModule", "Serial"] {
            assert!(reserved_event_name(name, &monitor).unwrap().contains(&format!("the A2L group {name}")), "{name}");
            assert_eq!(reserved_event_name(name, &timing), None, "{name}");
        }
        for name in ["OsTaskInfo_C", "OsTaskInfo_Cx", "OsTaskInfo_C0a", "Tracing2", "Frame", "VX1000x"] {
            assert_eq!(reserved_event_name(name, &timing), None, "{name}");
            assert_eq!(reserved_event_name(name, &monitor), None, "{name}");
        }
        assert_eq!(reserved_event_name("Tracing", &neither), None);
        assert!(reserved_event_name("OsRunInfo_C0", &timing).unwrap().contains("event of core 0"));
    }

    /// The stand-in VX1000 firmware (fixtures/vx_bundle): MC_APP with the Timing Bundle on two cores and the VX1000's own values, the
    /// events Init and Frame (multi-buffer), the bundle's templates, entries measured in place and one copied, and the bundle's enums in
    /// two units.
    const VX_BUNDLE: &str = "fixtures/vx_bundle/vx_bundle.out";

    fn stand_in() -> ElfReader {
        ElfReader::new(VX_BUNDLE, 0, usize::MAX).expect("the stand-in VX1000 firmware loads")
    }

    #[test]
    fn the_trace_enumerators_are_each_name_once_with_every_value_a_unit_gives_it() {
        let elf = stand_in();
        let found = elf.debug_data.trace_enumerators.as_ref().expect("its MC_APP sets .timing_active, so the pass runs");
        // app.c and bundle.c each have a copy of trace.h's anonymous enums: one value each
        for (name, value) in [
            ("VX1000IF_OS_TASK_MAIN", 0),
            ("VX1000IF_OS_TASK_IDLE", 1),
            ("VX1000IF_OS_TASK_COUNT", 2),
            ("VX1000IF_OS_ISR_TICK", 2),
            ("VX1000IF_OS_ISR_CAN0_RX", 3),
            ("VX1000IF_OS_THREAD_COUNT", 4),
            ("VX1000IF_RTE_R_STEP", 1),
            ("VX1000IF_RTE_R_LOG", 2),
            ("VX1000IF_RTE_R_END_", 3),
        ] {
            assert_eq!(found.get(name).map(Vec::as_slice), Some(&[value][..]), "{name}");
        }
        // and the two units give one name two values
        assert_eq!(found["VX1000IF_OS_XCP_EVENT"], [20, 21]);
        assert_eq!(found.len(), 10, "{found:?}");
        // the names it gives the trace
        let (threads, runnables, warnings) = trace_name_tables(Some(found));
        assert_eq!(
            threads.unwrap(),
            [(0, "MAIN"), (1, "IDLE"), (2, "ISR_TICK"), (3, "ISR_CAN0_RX")].map(|(v, n)| (v, n.to_string()))
        );
        assert_eq!(runnables.unwrap(), [(0, "Return"), (1, "R_STEP"), (2, "R_LOG")].map(|(v, n)| (v, n.to_string())));
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn an_elf_whose_mc_app_does_not_ask_for_the_bundle_has_no_trace_enumerators() {
        let elf = ElfReader::new("../../examples/no_a2l_demo/CANape/no_a2l_demo.elf", 0, usize::MAX).expect("the xcplite example ELF loads");
        assert!(elf.debug_data.trace_enumerators.is_none());
    }

    #[test]
    fn the_stand_in_firmwares_bundle_is_checked_and_its_words_expanded_per_core() {
        let elf = stand_in();
        let options = elf.vx_options().unwrap().unwrap();
        assert_eq!(
            options,
            VxOptions {
                timing_active: true,
                timing_cores: 2,
                vx_monitor_active: true,
                w1_known: true,
                channel_count: 31
            }
        );
        let bundle = elf.timing_bundle().unwrap().unwrap();
        assert_eq!(bundle.cores, 2);
        assert_eq!((bundle.words[0].event.as_str(), bundle.words[0].name.as_str()), ("OsTaskInfo", "Os_Trace"));
        assert_eq!((bundle.words[1].event.as_str(), bundle.words[1].name.as_str()), ("OsRunInfo", "Rte_Trace"));
        let records = elf.mci_records().unwrap().unwrap();
        let names: Vec<String> = records.iter().map(|r| format!("{}.{}", r.event, r.name)).collect();
        assert_eq!(
            names,
            [
                "Frame.Health",
                "Frame.Ammo_Bullets",
                "Frame.PlayerX",
                "Frame.Speed",
                "OsTaskInfo_C0.Os_Trace",
                "OsTaskInfo_C1.Os_Trace",
                "OsRunInfo_C0.Rte_Trace",
                "OsRunInfo_C1.Rte_Trace"
            ]
        );
        let os = bundle.words[0].addr.unwrap();
        assert_eq!(records[4].addr, Some(os));
        assert_eq!(records[5].addr, Some(os + 4));
        assert_eq!(super::super::MciAddressing::of(Some(&records), &[]), super::super::MciAddressing::Absolute);
    }

    #[test]
    fn the_stand_in_firmwares_events_are_numbered_with_the_bundles_after_them() {
        let elf = stand_in();
        let mut reg = Registry::new();
        elf.register_events(&mut reg, 0).unwrap();
        let events: Vec<(String, u16)> = (&reg.event_list).into_iter().map(|e| (e.get_name().to_string(), e.get_id())).collect();
        assert_eq!(
            events,
            [
                ("Init", 0),
                ("Frame", 1),
                ("OsTaskInfo_C0", 2),
                ("OsTaskInfo_C1", 3),
                ("OsRunInfo_C0", 4),
                ("OsRunInfo_C1", 5)
            ]
            .map(|(name, id)| (name.to_string(), id))
        );
        // and what the A2L gets added: each core's words on its events, decoded with the names of the debug information
        let vx = elf.vx_a2l(&reg).unwrap().unwrap();
        assert!(vx.vx_monitor);
        let tracing = vx.tracing.unwrap();
        assert!(tracing.little_endian);
        let words: Vec<(TraceKind, &str, u16)> = tracing.words.iter().map(|w| (w.kind, w.event.as_str(), w.channel)).collect();
        assert_eq!(
            words,
            [
                (TraceKind::Os, "OsTaskInfo_C0", 2),
                (TraceKind::Os, "OsTaskInfo_C1", 3),
                (TraceKind::Runnable, "OsRunInfo_C0", 4),
                (TraceKind::Runnable, "OsRunInfo_C1", 5)
            ]
        );
        assert_eq!(tracing.words[1].addr, tracing.words[0].addr + 4);
        assert_eq!(tracing.threads.unwrap().len(), 4);
        assert_eq!(tracing.runnables.unwrap().len(), 3);
    }

    #[test]
    fn the_sweep_leaves_out_a_global_a_record_covers_whole_and_keeps_one_it_covers_in_part() {
        let elf = stand_in();
        let mut reg = Registry::new();
        elf.register_events(&mut reg, 0).unwrap();
        let mci = elf.mci_records().unwrap();
        let cal = elf.mci_cal_records().unwrap();
        elf.register_variables(&mut reg, false, 0, usize::MAX, "", "", mci.as_deref(), &cal).unwrap();
        let swept: Vec<String> = (&reg.instance_list).into_iter().map(|i| i.get_name().to_string()).collect();
        // Frame.Health is Health where it is, all of it: no second object
        assert!(!swept.iter().any(|name| name == "Health"), "{swept:?}");
        // Frame.Ammo_Bullets is one element of Ammo, Frame.PlayerX the first member of Player: each variable is swept as a whole
        assert!(swept.iter().any(|name| name == "Ammo") && swept.iter().any(|name| name == "Player"), "{swept:?}");
        // Frame.Speed is copied into its shadow: the variable is left out by its name, as before
        assert!(!swept.iter().any(|name| name == "Speed"), "{swept:?}");
    }

    fn word(name: &str, event: &str, addr: u32) -> MciRecord {
        MciRecord {
            name: name.into(),
            ty: 4,
            x_dim: 1,
            comment: "c".into(),
            unit: String::new(),
            min: 0.0,
            max: 0.0,
            addr: Some(addr),
            event: event.into(),
        }
    }

    #[test]
    fn a_template_word_stands_for_one_word_per_core_or_for_none() {
        let records = vec![
            word("Health", "DoomFrame", 0x7000_0010),
            word("Os_Trace", "OsTaskInfo", 0x900C_D884),
            word("Rte_Trace", "OsRunInfo", 0x900C_D880),
        ];
        let templates = vec!["OsTaskInfo".to_string(), "OsRunInfo".to_string()];
        let bundle = TimingBundle {
            cores: 2,
            words: [records[1].clone(), records[2].clone()],
        };
        let expanded = expand_bundle_records(records.clone(), &templates, Some(&bundle));
        let got: Vec<(String, String, Option<u32>)> = expanded.iter().map(|r| (r.event.clone(), r.name.clone(), r.addr)).collect();
        assert_eq!(
            got,
            [
                ("DoomFrame", "Health", 0x7000_0010),
                ("OsTaskInfo_C0", "Os_Trace", 0x900C_D884),
                ("OsTaskInfo_C1", "Os_Trace", 0x900C_D888),
                ("OsRunInfo_C0", "Rte_Trace", 0x900C_D880),
                ("OsRunInfo_C1", "Rte_Trace", 0x900C_D884),
            ]
            .map(|(event, name, addr)| (event.to_string(), name.to_string(), Some(addr)))
        );
        assert!(expanded.iter().all(|r| r.comment == "c" && r.ty == 4));
        // the bundle off: its words are no record
        let off = expand_bundle_records(records, &templates, None);
        assert_eq!(off.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["Health"]);
    }
}

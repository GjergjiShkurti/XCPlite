//--------------------------------------------------------------------------------------------------------------------------------------------------
// What xcpclient adds to the A2L of a VX1000 firmware once xcp_registry has written it
//
// xcp_registry's writer has no way to add a group, a type that is no struct of the program, or an object that is not in the ELF, so what a
// VX1000 firmware's MC_APP switches on goes into the A2L text after the writer, as xcpclient's other corrections there do:
//
// - With .timing_active, the VX1000 Timing Bundle's: a ROOT group Tracing that holds the bundle's event groups, which leave the group
//   Measurements, and each trace word decoded, as the bundle's A2L parts for CANape decode it: a structure laid over the word (from thread,
//   from reason, to thread, to reason; runnable, core), the two tables of reasons the bundle's trace format fixes, and the names of the
//   threads and of the runnables, from the bundle's enumerators in the debug information.
// - With .vx_monitor_active, the VX1000's own values: its base module's temperature, its counters of lost events and of retries on the
//   target interface, and its console, on the VX1000's own events, in a ROOT group VX1000.
//
// Each object is on one line, which is how the kernel configuration generator reads them, and a structure's components on lines of their own.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::ops::Range;

use super::debuginfo::TraceEnumerators;
use super::{A2lToken, a2l_splice, a2l_tokens};

/// What a VX1000 firmware's MC_APP adds to its A2L (ElfReader::vx_a2l), which write_vx_a2l writes.
#[derive(Debug, Clone, PartialEq)]
pub struct VxA2l {
    /// The Timing Bundle's group and its decoded trace words, with .timing_active
    pub(crate) tracing: Option<Tracing>,
    /// The VX1000's own values, with .vx_monitor_active
    pub(crate) vx_monitor: bool,
}

/// The Timing Bundle's trace words, as the A2L decodes them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Tracing {
    /// The target's byte order, which decides where in a trace word each of its bytes is
    pub(crate) little_endian: bool,
    /// Every traced core's OS word, then every core's runnable word
    pub(crate) words: Vec<TraceWord>,
    /// The names of the threads (TaskInfo) and of the runnables (RunnableInfo): None where the debug information does not give them, and
    /// the trace then shows the IDs as numbers
    pub(crate) threads: Option<NameTable>,
    pub(crate) runnables: Option<NameTable>,
}

/// A name table of the trace: each value with its name, by value.
pub(crate) type NameTable = Vec<(i64, String)>;

/// Which of the bundle's two words: the OS trace or the runnable trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraceKind {
    Os,
    Runnable,
}

/// One trace word of one core: the measurement `<event>.<name>`, which the INSTANCE `<event>.<name>_Info` decodes on the same event.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TraceWord {
    pub(crate) kind: TraceKind,
    pub(crate) event: String,
    pub(crate) channel: u16,
    pub(crate) name: String,
    pub(crate) addr: u32,
}

impl TraceWord {
    fn instance(&self) -> String {
        format!("{}.{}_Info", self.event, self.name)
    }
}

//------------------------------------------------------------------------
// The trace's names, from the debug information

/// The names of the threads and of the runnables, from the bundle's enumerators (debuginfo, trace_enums.rs), and a warning for each table
/// that is left out. VX1000IF_OS_TASK_<name> names a thread <name>, VX1000IF_OS_ISR_<name> a thread ISR_<name>, VX1000IF_RTE_R_<name> a
/// runnable R_<name>, and 0 is the return from a runnable. The enumerators that count, the ones ending in _COUNT or _END_, name nothing.
///
/// A table is left out when the debug information has none of its enumerators, when one of its names has two values -- units that saw the
/// bundle's header differently -- and when two of its names have one value: the trace then shows that table's IDs as numbers.
pub(crate) fn trace_name_tables(enumerators: Option<&TraceEnumerators>) -> (Option<NameTable>, Option<NameTable>, Vec<String>) {
    let mut threads: Vec<(&str, &[i64], String)> = Vec::new();
    let mut runnables: Vec<(&str, &[i64], String)> = Vec::new();
    for (enumerator, values) in enumerators.into_iter().flatten() {
        if enumerator.ends_with("_COUNT") || enumerator.ends_with("_END_") {
            continue;
        }
        if let Some(task) = enumerator.strip_prefix("VX1000IF_OS_TASK_") {
            threads.push((enumerator, values, task.to_string()));
        } else if let Some(isr) = enumerator.strip_prefix("VX1000IF_OS_").filter(|rest| rest.starts_with("ISR_")) {
            threads.push((enumerator, values, isr.to_string()));
        } else if let Some(runnable) = enumerator.strip_prefix("VX1000IF_RTE_").filter(|rest| rest.starts_with("R_")) {
            runnables.push((enumerator, values, runnable.to_string()));
        }
    }
    let mut warnings = Vec::new();
    let mut table = |entries: Vec<(&str, &[i64], String)>, fixed: &[(i64, &str)], prefixes: &str, trace: &str, what: &str, table: &str| match name_table(entries, fixed, prefixes) {
        Ok(names) => Some(names),
        Err(why) => {
            warnings.push(format!(
                "{why}: the A2L decodes the {trace} trace without the {what} names ({table}), and shows {what} IDs as numbers"
            ));
            None
        }
    };
    let threads = table(threads, &[], "VX1000IF_OS_TASK_ or VX1000IF_OS_ISR_", "OS", "thread", "TaskInfo");
    let runnables = table(runnables, &[(0, "Return")], "VX1000IF_RTE_R_", "runnable", "runnable", "RunnableInfo");
    (threads, runnables, warnings)
}

/// One name table, by value: `entries` are the enumerators with their values and the names they give, `fixed` the names the trace format
/// gives.
fn name_table(entries: Vec<(&str, &[i64], String)>, fixed: &[(i64, &str)], prefixes: &str) -> Result<NameTable, String> {
    if entries.is_empty() {
        return Err(format!("The debug information has no enumerator {prefixes}<name> of the VX1000 Timing Bundle"));
    }
    let mut by_value: BTreeMap<i64, String> = fixed.iter().map(|(value, name)| (*value, name.to_string())).collect();
    for (enumerator, values, name) in entries {
        let [value] = values else {
            let values: Vec<String> = values.iter().map(i64::to_string).collect();
            return Err(format!(
                "The enumerator {enumerator} has the values {} in different units, which saw the bundle's header differently",
                values.join(" and ")
            ));
        };
        if let Some(other) = by_value.insert(*value, name.clone()) {
            return Err(format!(
                "The names {other} and {name} have the same value, {value}, in the VX1000 Timing Bundle's enumerators"
            ));
        }
    }
    Ok(by_value.into_iter().collect())
}

//------------------------------------------------------------------------
// The A2L text

/// The reasons a thread is switched from, which the bundle's trace format fixes (its A2L part for CANape, Part_OS.a2l)
const FROM_REASONS: [(i64, &str); 5] = [(1, "Termination"), (2, "IsrEnd"), (4, "WaitEvent"), (8, "WaitSemaphore"), (16, "Preemption")];

/// The reasons a thread is switched to, and the trace's events
const TO_REASONS: [(i64, &str); 16] = [
    (1, "Activation"),
    (2, "IsrStart"),
    (4, "SetEvent"),
    (8, "GotSemaphore"),
    (16, "Resume"),
    (32, "Cleanup"),
    (64, "Event_TaskActivate"),
    (65, "Event_SetEvent"),
    (66, "Event_Release"),
    (67, "Event_NoWait"),
    (68, "Event_ActivationLimit"),
    (69, "Event_EnableInterrupts"),
    (70, "Event_DisableInterrupts"),
    (71, "Event_SpinlockGot"),
    (72, "Event_SpinlockRequest"),
    (73, "Event_SpinlockRelease"),
];

/// A verbal table and the conversion that names it, of one name each.
fn verbal_table(name: &str, description: &str, pairs: &[(i64, String)]) -> String {
    let mut vtab = format!("/begin COMPU_VTAB {name} \"{description}\" TAB_VERB {}", pairs.len());
    for (value, label) in pairs {
        vtab.push_str(&format!(" {value} \"{label}\""));
    }
    format!("{vtab} DEFAULT_VALUE \"\" /end COMPU_VTAB\n/begin COMPU_METHOD {name} \"{description}\" TAB_VERB \"%3.0\" \"\" COMPU_TAB_REF {name} /end COMPU_METHOD\n")
}

/// The A2L that decodes the Timing Bundle's trace words, and its group Tracing.
fn tracing_text(tracing: &Tracing) -> String {
    let fixed = |pairs: &[(i64, &str)]| -> Vec<(i64, String)> { pairs.iter().map(|(value, name)| (*value, name.to_string())).collect() };
    let mut text = String::from("\n/* The VX1000 Timing Bundle's trace words, decoded (MC_APP's .timing_active) */\n");
    text.push_str(&verbal_table("OsTraceFromReason", "OS trace: reason of the thread switched from", &fixed(&FROM_REASONS)));
    text.push_str(&verbal_table("OsTraceToReason", "OS trace: reason of the thread switched to / event", &fixed(&TO_REASONS)));
    if let Some(threads) = &tracing.threads {
        text.push_str(&verbal_table("TaskInfo", "Task/Isr info", threads));
    }
    if let Some(runnables) = &tracing.runnables {
        text.push_str(&verbal_table("RunnableInfo", "Runnable info", runnables));
    }
    let conversion = |names: &Option<NameTable>, table: &'static str| if names.is_some() { table } else { "NO_COMPU_METHOD" };
    for (name, description, datatype, conversion, max) in [
        ("VX1000If_Trace_Raw", "trace value (raw)", "ULONG", "NO_COMPU_METHOD", 4294967295u64),
        ("VX1000If_Trace_Thread", "OS trace: thread ID", "UBYTE", conversion(&tracing.threads, "TaskInfo"), 255),
        (
            "VX1000If_Trace_FromReason",
            "OS trace: reason of the thread switched from",
            "UBYTE",
            "OsTraceFromReason",
            255,
        ),
        (
            "VX1000If_Trace_ToReason",
            "OS trace: reason of the thread switched to / event",
            "UBYTE",
            "OsTraceToReason",
            255,
        ),
        (
            "VX1000If_Trace_Runnable",
            "RTE trace: runnable ID (0 = return)",
            "UBYTE",
            conversion(&tracing.runnables, "RunnableInfo"),
            255,
        ),
        ("VX1000If_Trace_Core", "RTE trace: core", "UBYTE", "NO_COMPU_METHOD", 255),
    ] {
        text.push_str(&format!(
            "/begin TYPEDEF_MEASUREMENT {name} \"{description}\" {datatype} {conversion} 0 0 0 {max} /end TYPEDEF_MEASUREMENT\n"
        ));
    }
    // A byte of a 32-bit word, from its least significant (0) up: where it is in memory on the target
    let byte = |significance: u8| if tracing.little_endian { significance } else { 3 - significance };
    for (name, description, components) in [
        (
            "VX1000If_Os_Trace_Info",
            "VX1000If_Os_Trace: FromThreadId << 24 | FromReason << 16 | ToThreadId << 8 | ToReason",
            vec![
                ("Raw", "VX1000If_Trace_Raw", 0),
                ("FromThread", "VX1000If_Trace_Thread", byte(3)),
                ("FromReason", "VX1000If_Trace_FromReason", byte(2)),
                ("ToThread", "VX1000If_Trace_Thread", byte(1)),
                ("ToReason", "VX1000If_Trace_ToReason", byte(0)),
            ],
        ),
        (
            "VX1000If_Rte_Trace_Info",
            "VX1000If_Rte_Trace: RunnableId << 8 | CoreId",
            vec![
                ("Raw", "VX1000If_Trace_Raw", 0),
                ("Runnable", "VX1000If_Trace_Runnable", byte(1)),
                ("Core", "VX1000If_Trace_Core", byte(0)),
            ],
        ),
    ] {
        text.push_str(&format!("/begin TYPEDEF_STRUCTURE {name} \"{description}\" 4\n"));
        for (component, typedef, offset) in components {
            text.push_str(&format!("\t/begin STRUCTURE_COMPONENT {component} {typedef} {offset} /end STRUCTURE_COMPONENT\n"));
        }
        text.push_str("/end TYPEDEF_STRUCTURE\n");
    }
    for word in &tracing.words {
        let typedef = match word.kind {
            TraceKind::Os => "VX1000If_Os_Trace_Info",
            TraceKind::Runnable => "VX1000If_Rte_Trace_Info",
        };
        text.push_str(&format!(
            "/begin INSTANCE {} \"{}.{} as a structure (raw value and fields with names)\" {typedef} 0x{:X} ECU_ADDRESS_EXTENSION 0 \
             /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT {} /end DAQ_EVENT /end IF_DATA /end INSTANCE\n",
            word.instance(),
            word.event,
            word.name,
            word.addr,
            word.channel
        ));
    }
    let mut groups = Vec::new();
    for word in &tracing.words {
        if !groups.contains(&word.event.as_str()) {
            groups.push(word.event.as_str());
        }
    }
    text.push_str(&format!(
        "/begin GROUP Tracing \"VX1000 Timing Bundle: OS trace and runnable trace of each traced core\" ROOT /begin SUB_GROUP {} /end SUB_GROUP /end GROUP\n",
        groups.join(" ")
    ));
    text
}

/// The VX1000's own events, in the DAQ block: the base module's (0x8000, 10 ms) and the console's (0x8100).
const VX_MONITOR_EVENTS: [&str; 2] = [
    "/begin EVENT \"EVENT_VX1000_BASEMODULE\" \"EVENT_BM\" 0x8000 DAQ 0xFF 10 6 0 /end EVENT",
    "/begin EVENT \"EVENT_VX1000_VXCONSOLE\" \"EVENT_VC\" 0x8100 DAQ 0xFF 0 6 0 /end EVENT",
];

/// The VX1000's own values, at address extension 0xFD, the VX1000's own memory: its base module's temperature (raw / 128, in °C), its count
/// of lost events (OLDA overruns), its count of retries on the target interface, and its console, a text of 128 characters. The console has
/// xcplite's record layout U8, which holds the same bytes as the layout of CANape's own part for the VX1000.
const VX_MONITOR_TEXT: &str = "
/* The VX1000's own values (MC_APP's .vx_monitor_active) */
/begin COMPU_METHOD VX1000.BM.mon.bmTemperature.CONVERSION \"BaseModule temperature conversion\" RAT_FUNC \"%3.1\" \"\u{b0}C\" COEFFS 0 128 0 0 0 1 /end COMPU_METHOD
/begin MEASUREMENT VX1000.BM.mon.bmTemperature \"Temperature inside the Base Module\" SWORD VX1000.BM.mon.bmTemperature.CONVERSION 0 2 -50 100 ECU_ADDRESS 0x91000232 ECU_ADDRESS_EXTENSION 0xFD FORMAT \"%.15\" /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x8000 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT
/begin MEASUREMENT VX1000.BM.mon.serial.niosOldaOverruns \"Number of OLDA Overruns (lost XCP events)\" ULONG NO_COMPU_METHOD 0 0 0 4294967295 BYTE_ORDER MSB_LAST ECU_ADDRESS 0x91000220 ECU_ADDRESS_EXTENSION 0xFD FORMAT \"%.15\" /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x8000 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT
/begin MEASUREMENT VX1000.BM.mon.serial.targetIfRetryCounter \"Target Interface Access Retry Counter\" ULONG NO_COMPU_METHOD 0 0 0 4294967295 BYTE_ORDER MSB_LAST ECU_ADDRESS 0x91000228 ECU_ADDRESS_EXTENSION 0xFD FORMAT \"%.15\" /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x8000 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT
/begin CHARACTERISTIC VX1000.BM.monFW.VXconsole \"VXconsole Messages\" ASCII 0x93000000 U8 0 NO_COMPU_METHOD 0 255 ECU_ADDRESS_EXTENSION 0xFD EXTENDED_LIMITS 0 255 NUMBER 128 /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x8100 /end DAQ_EVENT /end IF_DATA /end CHARACTERISTIC
/begin GROUP VX1000 \"VX1000 Internal Signals\" ROOT /begin SUB_GROUP BaseModule /end SUB_GROUP /end GROUP
/begin GROUP BaseModule \"VX1060, VX113x, VX1161.3x internal Measurements\" /begin REF_CHARACTERISTIC VX1000.BM.monFW.VXconsole /end REF_CHARACTERISTIC /begin REF_MEASUREMENT VX1000.BM.mon.bmTemperature /end REF_MEASUREMENT /begin SUB_GROUP Serial /end SUB_GROUP /end GROUP
/begin GROUP Serial \"\" /begin REF_MEASUREMENT VX1000.BM.mon.serial.niosOldaOverruns VX1000.BM.mon.serial.targetIfRetryCounter /end REF_MEASUREMENT /end GROUP
";

//------------------------------------------------------------------------
// The edit

/// Add what `vx` says to the A2L at `path`, which xcp_registry has written, then check that the A2L loads, as the writer checks the one it
/// writes. One that cannot be made or does not load is an error, and the caller does not leave it behind.
pub fn write_vx_a2l(path: &std::path::Path, vx: &VxA2l) -> Result<(), Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    let text = vx_a2l_text(&text, vx).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::write(path, text.as_bytes())?;
    let warnings = xcp_registry::Registry::new()
        .check_a2l(&path)
        .map_err(|e| format!("{} does not load once the VX1000 additions are in it: {e}", path.display()))?;
    log::info!(
        "Added to the A2L:{}{} ({warnings} warnings from the A2L check)",
        if vx.tracing.is_some() {
            " the Timing Bundle's group Tracing and its decoded trace words;"
        } else {
            ""
        },
        if vx.vx_monitor { " the VX1000's own values, in the group VX1000;" } else { "" }
    );
    Ok(())
}

/// The A2L `text` with what `vx` says added: Err when the text has not exactly one place for each addition, or already names what it adds.
pub(crate) fn vx_a2l_text(text: &str, vx: &VxA2l) -> Result<String, String> {
    let tokens = a2l_tokens(text);
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut added = String::new();

    let module_end = only(&pairs(&tokens, "/end", "MODULE"), "/end MODULE")?;

    if let Some(tracing) = &vx.tracing {
        // The bundle's event groups leave the group Measurements for the group Tracing, and each gets its words' INSTANCEs.
        let mut events: Vec<&str> = Vec::new();
        for word in &tracing.words {
            if !events.contains(&word.event.as_str()) {
                events.push(word.event.as_str());
            }
        }
        let measurements = group(&tokens, "Measurements")?;
        let list = block(&tokens, measurements.clone(), "SUB_GROUP").ok_or("the group Measurements has no SUB_GROUP")?;
        for event in &events {
            let at = (list.start..list.end)
                .find(|&i| tokens[i].text == *event)
                .ok_or_else(|| format!("the group Measurements has no sub-group {event}"))?;
            edits.push((tokens[at - 1].end()..tokens[at].end(), String::new()));
        }
        for event in &events {
            let range = group(&tokens, event)?;
            let refs = block(&tokens, range, "REF_MEASUREMENT").ok_or_else(|| format!("the group {event} has no REF_MEASUREMENT"))?;
            let instances: String = tracing.words.iter().filter(|w| w.event == *event).map(|w| format!(" {}", w.instance())).collect();
            edits.push((tokens[refs.end - 1].end()..tokens[refs.end - 1].end(), instances));
        }
        added.push_str(&tracing_text(tracing));
    }

    if vx.vx_monitor {
        // The VX1000's own events go behind the others in the DAQ block, whose count of event channels counts them too.
        let daq_end = only(&pairs(&tokens, "/end", "DAQ"), "/end DAQ")?;
        let daq_begin = only(&pairs(&tokens, "/begin", "DAQ"), "/begin DAQ")?;
        let daq = daq_begin..daq_end;
        let events = pairs(&tokens, "/begin", "EVENT").into_iter().filter(|i| daq.contains(i)).count();
        let dynamic = daq.clone().find(|&i| tokens[i].text == "DYNAMIC").ok_or("the DAQ block is not DYNAMIC")?;
        let count = tokens
            .get(dynamic + 2)
            .filter(|t| daq.contains(&(dynamic + 2)) && t.text.parse::<u64>().is_ok())
            .ok_or("the DAQ block states no MAX_EVENT_CHANNEL")?;
        edits.push((count.start..count.end(), (events + VX_MONITOR_EVENTS.len()).to_string()));
        let at = match pairs(&tokens, "/end", "EVENT").into_iter().rfind(|i| daq.contains(i)) {
            Some(last) => tokens[last + 1].end(),
            None => tokens[daq_end].start,
        };
        let lines: String = VX_MONITOR_EVENTS.iter().map(|event| format!("\n\t\t\t{event}")).collect();
        edits.push((at..at, if at == tokens[daq_end].start { format!("{}\n\t\t", lines.trim_start()) } else { lines }));
        added.push_str(VX_MONITOR_TEXT);
    }

    if edits.is_empty() && added.is_empty() {
        return Ok(text.to_string());
    }

    // Nothing added may take a name the A2L has: two objects of one name, two groups, two events are no A2L a reader can trust.
    let inserted: String = edits.iter().map(|(_, with)| with.as_str()).chain([added.as_str()]).collect::<Vec<_>>().join("\n");
    let have = declared_names(&tokens);
    let mut taken: Vec<String> = declared_names(&a2l_tokens(&inserted))
        .into_iter()
        .filter(|name| have.contains(name))
        .map(|(kind, name)| format!("{kind} {name}"))
        .collect();
    if !taken.is_empty() {
        taken.sort();
        return Err(format!(
            "it already has {}, which xcpclient adds for what MC_APP switches on (.timing_active, .vx_monitor_active): rename the firmware's own; \
             no A2L is written",
            taken.join(", ")
        ));
    }

    let end = tokens[module_end].start;
    edits.push((end..end, format!("{}\n", added.trim_start_matches('\n'))));
    edits.sort_by_key(|(range, _)| range.start);
    Ok(a2l_splice(text, &edits))
}

/// The positions of the token pairs `first second`.
fn pairs(tokens: &[A2lToken], first: &str, second: &str) -> Vec<usize> {
    tokens
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[0].text == first && pair[1].text == second)
        .map(|(at, _)| at)
        .collect()
}

/// The one position among `positions` of `what`, or why there is not one.
fn only(positions: &[usize], what: &str) -> Result<usize, String> {
    match positions {
        [at] => Ok(*at),
        _ => Err(format!(
            "it has {} of {what}, where xcpclient expects the one xcp_registry writes, to add what MC_APP switches on",
            positions.len()
        )),
    }
}

/// The tokens of the one `/begin GROUP <name> ... /end GROUP`: from its /begin to the /end, without it.
fn group(tokens: &[A2lToken], name: &str) -> Result<Range<usize>, String> {
    let begins: Vec<usize> = pairs(tokens, "/begin", "GROUP")
        .into_iter()
        .filter(|&at| tokens.get(at + 2).is_some_and(|t| t.text == name))
        .collect();
    let [begin] = begins.as_slice() else {
        return Err(format!("it has {} groups {name}, where xcpclient expects the one xcp_registry writes", begins.len()));
    };
    let end = pairs(tokens, "/end", "GROUP")
        .into_iter()
        .find(|&at| at > *begin)
        .ok_or_else(|| format!("the group {name} has no /end GROUP"))?;
    Ok(*begin..end)
}

/// The tokens inside the block `/begin <keyword> ... /end <keyword>` within `range`: from the first after its keyword to the last before its
/// /end.
fn block(tokens: &[A2lToken], range: Range<usize>, keyword: &str) -> Option<Range<usize>> {
    let begin = (range.start..range.end).find(|&i| tokens[i].text == "/begin" && tokens.get(i + 1).is_some_and(|t| t.text == keyword))?;
    let end = (begin..range.end).find(|&i| tokens[i].text == "/end" && tokens.get(i + 1).is_some_and(|t| t.text == keyword))?;
    Some(begin + 2..end)
}

/// The names the A2L `tokens` declare, each with the kind of names it is one of: objects (MEASUREMENT, CHARACTERISTIC, AXIS_PTS, BLOB,
/// INSTANCE), types, conversions, conversion tables, groups and events are each one namespace.
fn declared_names(tokens: &[A2lToken]) -> HashSet<(&'static str, String)> {
    let mut names = HashSet::new();
    for pair in tokens.windows(3).filter(|w| w[0].text == "/begin") {
        let kind = match pair[1].text {
            "MEASUREMENT" | "CHARACTERISTIC" | "AXIS_PTS" | "BLOB" | "INSTANCE" => "an object",
            "TYPEDEF_MEASUREMENT" | "TYPEDEF_CHARACTERISTIC" | "TYPEDEF_AXIS" | "TYPEDEF_STRUCTURE" | "TYPEDEF_BLOB" => "a type",
            "COMPU_METHOD" => "a COMPU_METHOD",
            "COMPU_TAB" | "COMPU_VTAB" | "COMPU_VTAB_RANGE" => "a conversion table",
            "GROUP" => "a GROUP",
            "EVENT" => "an EVENT",
            _ => continue,
        };
        let name = pair[2].text;
        let name = name.strip_prefix('"').and_then(|n| n.strip_suffix('"')).unwrap_or(name);
        names.insert((kind, name.to_string()));
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What xcp_registry writes, cut down to what the additions touch: the DAQ block with its events, the groups, the module's end.
    fn registry_a2l(events: &[(&str, u16)], signals: &[(&str, &str)]) -> String {
        let mut text = String::from("/begin PROJECT p \"\"\n/begin MODULE m \"\"\n/begin IF_DATA XCP\n\t\t/begin DAQ\n            DYNAMIC 0 ");
        text.push_str(&format!(
            "{} 0 OPTIMISATION_TYPE_DEFAULT ADDRESS_EXTENSION_FREE IDENTIFICATION_FIELD_TYPE_RELATIVE_BYTE GRANULARITY_ODT_ENTRY_SIZE_DAQ_BYTE 0xF8 OVERLOAD_INDICATION_PID\n",
            events.len()
        ));
        text.push_str("            /begin TIMESTAMP_SUPPORTED\n                0x1 SIZE_DWORD UNIT_1US\n            /end TIMESTAMP_SUPPORTED\n            \n");
        for (name, id) in events {
            text.push_str(&format!("\t\t\t/begin EVENT \"{name}\" \"{name}\" {id} DAQ 0xFF 0 0 0 CONSISTENCY DAQ /end EVENT\n"));
        }
        text.push_str("\n\t\t/end DAQ\n\n/end IF_DATA\n\n");
        for (event, signal) in signals {
            text.push_str(&format!(
                "/begin MEASUREMENT {event}.{signal} \"\" ULONG IDENTITY 0 0 0 4294967295 ECU_ADDRESS 0x900CD884 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT\n"
            ));
        }
        let names: Vec<&str> = events.iter().map(|(name, _)| *name).collect();
        text.push_str(&format!(
            "\n/begin GROUP Measurements \"\" ROOT /begin SUB_GROUP {} /end SUB_GROUP /end GROUP\n",
            names.join(" ")
        ));
        for name in names {
            let refs: String = signals
                .iter()
                .filter(|(event, _)| *event == name)
                .map(|(event, signal)| format!(" {event}.{signal}"))
                .collect();
            text.push_str(&format!("/begin GROUP {name} \"\" /begin REF_MEASUREMENT{refs} /end REF_MEASUREMENT /end GROUP\n"));
        }
        text.push_str("\n/* Characteristic and Axis Groups */\n\n/end MODULE\n/end PROJECT\n");
        text
    }

    fn doom_tracing(little_endian: bool, threads: Option<NameTable>) -> Tracing {
        Tracing {
            little_endian,
            words: vec![
                TraceWord {
                    kind: TraceKind::Os,
                    event: "OsTaskInfo_C0".into(),
                    channel: 6,
                    name: "Os_Trace".into(),
                    addr: 0x900C_D884,
                },
                TraceWord {
                    kind: TraceKind::Runnable,
                    event: "OsRunInfo_C0".into(),
                    channel: 7,
                    name: "Rte_Trace".into(),
                    addr: 0x900C_D880,
                },
            ],
            threads,
            runnables: Some(vec![(0, "Return".into()), (1, "R_DOOM_TICS".into())]),
        }
    }

    fn doom_a2l() -> String {
        registry_a2l(
            &[("DoomInit", 0), ("DoomFrame", 1), ("OsTaskInfo_C0", 6), ("OsRunInfo_C0", 7)],
            &[("DoomFrame", "Health"), ("OsTaskInfo_C0", "Os_Trace"), ("OsRunInfo_C0", "Rte_Trace")],
        )
    }

    fn line_of<'a>(text: &'a str, start: &str) -> &'a str {
        text.lines()
            .find(|line| line.starts_with(start))
            .unwrap_or_else(|| panic!("no line starts with {start}:\n{text}"))
    }

    #[test]
    fn the_bundles_event_groups_move_to_tracing_with_their_decoded_words() {
        let tracing = doom_tracing(true, Some(vec![(0, "DOOM".into()), (5, "ISR_CAN0_RX".into())]));
        let text = vx_a2l_text(
            &doom_a2l(),
            &VxA2l {
                tracing: Some(tracing),
                vx_monitor: false,
            },
        )
        .unwrap();
        assert_eq!(
            line_of(&text, "/begin GROUP Measurements"),
            "/begin GROUP Measurements \"\" ROOT /begin SUB_GROUP DoomInit DoomFrame /end SUB_GROUP /end GROUP"
        );
        assert_eq!(
            line_of(&text, "/begin GROUP Tracing"),
            "/begin GROUP Tracing \"VX1000 Timing Bundle: OS trace and runnable trace of each traced core\" ROOT /begin SUB_GROUP OsTaskInfo_C0 OsRunInfo_C0 /end SUB_GROUP /end GROUP"
        );
        assert_eq!(
            line_of(&text, "/begin GROUP OsTaskInfo_C0"),
            "/begin GROUP OsTaskInfo_C0 \"\" /begin REF_MEASUREMENT OsTaskInfo_C0.Os_Trace OsTaskInfo_C0.Os_Trace_Info /end REF_MEASUREMENT /end GROUP"
        );
        assert_eq!(
            line_of(&text, "/begin INSTANCE OsTaskInfo_C0.Os_Trace_Info"),
            "/begin INSTANCE OsTaskInfo_C0.Os_Trace_Info \"OsTaskInfo_C0.Os_Trace as a structure (raw value and fields with names)\" VX1000If_Os_Trace_Info \
             0x900CD884 ECU_ADDRESS_EXTENSION 0 /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 6 /end DAQ_EVENT /end IF_DATA /end INSTANCE"
        );
        assert!(text.contains(
            "/begin INSTANCE OsRunInfo_C0.Rte_Trace_Info \"OsRunInfo_C0.Rte_Trace as a structure (raw value and fields with names)\" VX1000If_Rte_Trace_Info 0x900CD880"
        ));
        assert_eq!(
            line_of(&text, "/begin COMPU_VTAB TaskInfo"),
            "/begin COMPU_VTAB TaskInfo \"Task/Isr info\" TAB_VERB 2 0 \"DOOM\" 5 \"ISR_CAN0_RX\" DEFAULT_VALUE \"\" /end COMPU_VTAB"
        );
        assert_eq!(
            line_of(&text, "/begin COMPU_METHOD TaskInfo"),
            "/begin COMPU_METHOD TaskInfo \"Task/Isr info\" TAB_VERB \"%3.0\" \"\" COMPU_TAB_REF TaskInfo /end COMPU_METHOD"
        );
        assert!(line_of(&text, "/begin COMPU_VTAB OsTraceToReason").contains("TAB_VERB 16 1 \"Activation\" 2 \"IsrStart\""));
        assert!(line_of(&text, "/begin COMPU_VTAB OsTraceFromReason").contains("TAB_VERB 5 1 \"Termination\""));
        assert!(text.contains("/begin TYPEDEF_MEASUREMENT VX1000If_Trace_Thread \"OS trace: thread ID\" UBYTE TaskInfo 0 0 0 255 /end TYPEDEF_MEASUREMENT\n"));
        // little endian: FromThread is the word's top byte, at offset 3
        assert!(text.contains(
            "/begin TYPEDEF_STRUCTURE VX1000If_Os_Trace_Info \"VX1000If_Os_Trace: FromThreadId << 24 | FromReason << 16 | ToThreadId << 8 | ToReason\" 4\n\
             \t/begin STRUCTURE_COMPONENT Raw VX1000If_Trace_Raw 0 /end STRUCTURE_COMPONENT\n\
             \t/begin STRUCTURE_COMPONENT FromThread VX1000If_Trace_Thread 3 /end STRUCTURE_COMPONENT\n\
             \t/begin STRUCTURE_COMPONENT FromReason VX1000If_Trace_FromReason 2 /end STRUCTURE_COMPONENT\n\
             \t/begin STRUCTURE_COMPONENT ToThread VX1000If_Trace_Thread 1 /end STRUCTURE_COMPONENT\n\
             \t/begin STRUCTURE_COMPONENT ToReason VX1000If_Trace_ToReason 0 /end STRUCTURE_COMPONENT\n\
             /end TYPEDEF_STRUCTURE\n"
        ));
        assert!(text.contains("\t/begin STRUCTURE_COMPONENT Runnable VX1000If_Trace_Runnable 1 /end STRUCTURE_COMPONENT\n\t/begin STRUCTURE_COMPONENT Core VX1000If_Trace_Core 0 /end STRUCTURE_COMPONENT\n"));
        // everything added sits before the module's end, the group Tracing last, and nothing of the VX1000 block is there
        assert!(
            text.contains("OsTaskInfo_C0 OsRunInfo_C0 /end SUB_GROUP /end GROUP\n\n/end MODULE\n/end PROJECT\n"),
            "{text}"
        );
        assert!(text.contains("/* Characteristic and Axis Groups */\n\n/* The VX1000 Timing Bundle's trace words, decoded (MC_APP's .timing_active) */\n"));
        assert!(!text.contains("VX1000.BM") && !text.contains("0x8000"));
    }

    #[test]
    fn a_big_endian_target_has_the_words_bytes_the_other_way_round() {
        let text = vx_a2l_text(
            &doom_a2l(),
            &VxA2l {
                tracing: Some(doom_tracing(false, None)),
                vx_monitor: false,
            },
        )
        .unwrap();
        assert!(text.contains("\t/begin STRUCTURE_COMPONENT FromThread VX1000If_Trace_Thread 0 /end STRUCTURE_COMPONENT\n"));
        assert!(text.contains("\t/begin STRUCTURE_COMPONENT ToReason VX1000If_Trace_ToReason 3 /end STRUCTURE_COMPONENT\n"));
        assert!(text.contains("\t/begin STRUCTURE_COMPONENT Runnable VX1000If_Trace_Runnable 2 /end STRUCTURE_COMPONENT\n"));
        assert!(text.contains("\t/begin STRUCTURE_COMPONENT Core VX1000If_Trace_Core 3 /end STRUCTURE_COMPONENT\n"));
        // without the thread names, thread IDs are numbers; the runnable names stay
        assert!(!text.contains("COMPU_VTAB TaskInfo") && !text.contains("COMPU_METHOD TaskInfo"));
        assert!(text.contains("/begin TYPEDEF_MEASUREMENT VX1000If_Trace_Thread \"OS trace: thread ID\" UBYTE NO_COMPU_METHOD 0 0 0 255"));
        assert!(text.contains("/begin TYPEDEF_MEASUREMENT VX1000If_Trace_Runnable \"RTE trace: runnable ID (0 = return)\" UBYTE RunnableInfo 0 0 0 255"));
    }

    #[test]
    fn every_core_has_its_own_events_and_words() {
        let mut tracing = doom_tracing(true, None);
        tracing.words = vec![
            TraceWord {
                kind: TraceKind::Os,
                event: "OsTaskInfo_C0".into(),
                channel: 2,
                name: "Os_Trace".into(),
                addr: 0x100,
            },
            TraceWord {
                kind: TraceKind::Os,
                event: "OsTaskInfo_C1".into(),
                channel: 3,
                name: "Os_Trace".into(),
                addr: 0x104,
            },
            TraceWord {
                kind: TraceKind::Runnable,
                event: "OsRunInfo_C0".into(),
                channel: 4,
                name: "Rte_Trace".into(),
                addr: 0x200,
            },
            TraceWord {
                kind: TraceKind::Runnable,
                event: "OsRunInfo_C1".into(),
                channel: 5,
                name: "Rte_Trace".into(),
                addr: 0x204,
            },
        ];
        let a2l = registry_a2l(
            &[
                ("Frame", 0),
                ("Sound", 1),
                ("OsTaskInfo_C0", 2),
                ("OsTaskInfo_C1", 3),
                ("OsRunInfo_C0", 4),
                ("OsRunInfo_C1", 5),
            ],
            &[],
        );
        let text = vx_a2l_text(
            &a2l,
            &VxA2l {
                tracing: Some(tracing),
                vx_monitor: false,
            },
        )
        .unwrap();
        assert!(text.contains("/begin SUB_GROUP Frame Sound /end SUB_GROUP"));
        assert!(text.contains("ROOT /begin SUB_GROUP OsTaskInfo_C0 OsTaskInfo_C1 OsRunInfo_C0 OsRunInfo_C1 /end SUB_GROUP"));
        assert!(text.contains("/begin INSTANCE OsTaskInfo_C1.Os_Trace_Info \"OsTaskInfo_C1.Os_Trace as a structure (raw value and fields with names)\" VX1000If_Os_Trace_Info 0x104 ECU_ADDRESS_EXTENSION 0 /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 3 /end DAQ_EVENT"));
        assert!(text.contains("/begin GROUP OsRunInfo_C1 \"\" /begin REF_MEASUREMENT OsRunInfo_C1.Rte_Trace_Info /end REF_MEASUREMENT /end GROUP"));
        // the decoding is there once, however many cores
        assert_eq!(text.matches("/begin TYPEDEF_STRUCTURE VX1000If_Os_Trace_Info").count(), 1);
    }

    #[test]
    fn the_vx1000s_own_values_are_one_object_a_line_on_its_own_events() {
        let text = vx_a2l_text(&doom_a2l(), &VxA2l { tracing: None, vx_monitor: true }).unwrap();
        // the events behind the firmware's, and the DAQ block counts them
        assert!(text.contains(
            "/begin EVENT \"OsRunInfo_C0\" \"OsRunInfo_C0\" 7 DAQ 0xFF 0 0 0 CONSISTENCY DAQ /end EVENT\n\
             \t\t\t/begin EVENT \"EVENT_VX1000_BASEMODULE\" \"EVENT_BM\" 0x8000 DAQ 0xFF 10 6 0 /end EVENT\n\
             \t\t\t/begin EVENT \"EVENT_VX1000_VXCONSOLE\" \"EVENT_VC\" 0x8100 DAQ 0xFF 0 6 0 /end EVENT\n\n\t\t/end DAQ"
        ));
        assert!(text.contains("DYNAMIC 0 6 0 OPTIMISATION_TYPE_DEFAULT"));
        // each object on one line
        for (start, end) in [
            ("/begin MEASUREMENT VX1000.BM.mon.bmTemperature ", "/end MEASUREMENT"),
            ("/begin MEASUREMENT VX1000.BM.mon.serial.niosOldaOverruns ", "/end MEASUREMENT"),
            ("/begin MEASUREMENT VX1000.BM.mon.serial.targetIfRetryCounter ", "/end MEASUREMENT"),
            ("/begin CHARACTERISTIC VX1000.BM.monFW.VXconsole ", "/end CHARACTERISTIC"),
            ("/begin COMPU_METHOD VX1000.BM.mon.bmTemperature.CONVERSION ", "/end COMPU_METHOD"),
            ("/begin GROUP VX1000 ", "/end GROUP"),
            ("/begin GROUP BaseModule ", "/end GROUP"),
            ("/begin GROUP Serial ", "/end GROUP"),
        ] {
            assert!(line_of(&text, start).ends_with(end), "{start}");
        }
        assert_eq!(
            line_of(&text, "/begin CHARACTERISTIC VX1000.BM.monFW.VXconsole"),
            "/begin CHARACTERISTIC VX1000.BM.monFW.VXconsole \"VXconsole Messages\" ASCII 0x93000000 U8 0 NO_COMPU_METHOD 0 255 ECU_ADDRESS_EXTENSION 0xFD \
             EXTENDED_LIMITS 0 255 NUMBER 128 /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x8100 /end DAQ_EVENT /end IF_DATA /end CHARACTERISTIC"
        );
        assert!(line_of(&text, "/begin MEASUREMENT VX1000.BM.mon.bmTemperature").contains(
            "SWORD VX1000.BM.mon.bmTemperature.CONVERSION 0 2 -50 100 ECU_ADDRESS 0x91000232 ECU_ADDRESS_EXTENSION 0xFD FORMAT \"%.15\" /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x8000"
        ));
        assert!(line_of(&text, "/begin COMPU_METHOD VX1000.BM.mon.bmTemperature.CONVERSION").contains("RAT_FUNC \"%3.1\" \"\u{b0}C\" COEFFS 0 128 0 0 0 1"));
        assert!(line_of(&text, "/begin GROUP VX1000 ").contains("ROOT /begin SUB_GROUP BaseModule /end SUB_GROUP"));
        // the firmware's groups as they were, and nothing of the Timing Bundle
        assert!(text.contains("/begin SUB_GROUP DoomInit DoomFrame OsTaskInfo_C0 OsRunInfo_C0 /end SUB_GROUP"));
        assert!(!text.contains("Tracing") && !text.contains("TYPEDEF_STRUCTURE"));
    }

    #[test]
    fn both_at_once_and_neither() {
        let both = vx_a2l_text(
            &doom_a2l(),
            &VxA2l {
                tracing: Some(doom_tracing(true, None)),
                vx_monitor: true,
            },
        )
        .unwrap();
        assert!(both.find("/begin GROUP Tracing").unwrap() < both.find("/begin GROUP VX1000 ").unwrap());
        assert!(both.contains("DYNAMIC 0 6 0"));
        assert_eq!(vx_a2l_text(&doom_a2l(), &VxA2l { tracing: None, vx_monitor: false }).unwrap(), doom_a2l());
    }

    #[test]
    fn a_name_the_a2l_already_has_is_refused() {
        // a calibration object's value table named like the trace's thread names
        let a2l = doom_a2l().replace(
            "\n/end MODULE",
            "\n/begin COMPU_METHOD TaskInfo \"\" TAB_VERB \"%.0\" \"\" COMPU_TAB_REF TaskInfo.table /end COMPU_METHOD\n/end MODULE",
        );
        let tracing = doom_tracing(true, Some(vec![(0, "DOOM".into())]));
        let error = vx_a2l_text(
            &a2l,
            &VxA2l {
                tracing: Some(tracing.clone()),
                vx_monitor: false,
            },
        )
        .unwrap_err();
        assert!(error.starts_with("it already has a COMPU_METHOD TaskInfo, which xcpclient adds"), "{error}");
        // without the thread names there is no clash
        assert!(
            vx_a2l_text(
                &a2l,
                &VxA2l {
                    tracing: Some(doom_tracing(true, None)),
                    vx_monitor: false
                }
            )
            .is_ok()
        );
        // an event of the VX1000's own name
        let a2l = registry_a2l(&[("EVENT_VX1000_VXCONSOLE", 0)], &[]);
        let error = vx_a2l_text(&a2l, &VxA2l { tracing: None, vx_monitor: true }).unwrap_err();
        assert!(error.contains("an EVENT EVENT_VX1000_VXCONSOLE"), "{error}");
    }

    #[test]
    fn an_a2l_without_the_places_the_additions_go_is_refused() {
        // no group for the bundle's event
        let a2l = registry_a2l(&[("DoomInit", 0)], &[]);
        let error = vx_a2l_text(
            &a2l,
            &VxA2l {
                tracing: Some(doom_tracing(true, None)),
                vx_monitor: false,
            },
        )
        .unwrap_err();
        assert!(error.contains("the group Measurements has no sub-group OsTaskInfo_C0"), "{error}");
        // no DAQ block
        let error = vx_a2l_text("/begin MODULE m \"\"\n/end MODULE\n", &VxA2l { tracing: None, vx_monitor: true }).unwrap_err();
        assert!(error.contains("it has 0 of /end DAQ"), "{error}");
    }

    fn enumerators(list: &[(&str, &[i64])]) -> TraceEnumerators {
        list.iter().map(|(name, values)| (name.to_string(), values.to_vec())).collect()
    }

    #[test]
    fn the_names_are_the_enumerators_without_their_prefixes_and_counts() {
        let found = enumerators(&[
            ("VX1000IF_OS_TASK_DOOM", &[0]),
            ("VX1000IF_OS_TASK_BG_10MS", &[1]),
            ("VX1000IF_OS_TASK_COUNT", &[2]),
            ("VX1000IF_OS_ISR_CAN0_RX", &[2]),
            ("VX1000IF_OS_ISR_OS_TICK", &[3]),
            ("VX1000IF_OS_THREAD_COUNT", &[4]),
            ("VX1000IF_RTE_R_DOOM_TICS", &[1]),
            ("VX1000IF_RTE_R_SOUND", &[2]),
            ("VX1000IF_RTE_R_END_", &[3]),
            ("VX1000IF_OS_XCP_EVENT", &[20]),
        ]);
        let (threads, runnables, warnings) = trace_name_tables(Some(&found));
        assert_eq!(
            threads.unwrap(),
            [(0, "DOOM"), (1, "BG_10MS"), (2, "ISR_CAN0_RX"), (3, "ISR_OS_TICK")].map(|(v, n)| (v, n.to_string()))
        );
        assert_eq!(runnables.unwrap(), [(0, "Return"), (1, "R_DOOM_TICS"), (2, "R_SOUND")].map(|(v, n)| (v, n.to_string())));
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_table_without_its_enumerators_or_with_a_name_of_two_values_is_left_out_and_said() {
        // no enumerator at all: both left out, each said
        let (threads, runnables, warnings) = trace_name_tables(Some(&TraceEnumerators::new()));
        assert_eq!((threads, runnables), (None, None));
        assert_eq!(warnings.len(), 2);
        assert!(
            warnings[0].starts_with("The debug information has no enumerator VX1000IF_OS_TASK_ or VX1000IF_OS_ISR_<name>"),
            "{}",
            warnings[0]
        );
        assert!(
            warnings[0].ends_with("the A2L decodes the OS trace without the thread names (TaskInfo), and shows thread IDs as numbers"),
            "{}",
            warnings[0]
        );
        assert!(warnings[1].contains("VX1000IF_RTE_R_<name>") && warnings[1].contains("(RunnableInfo)"), "{}", warnings[1]);
        assert_eq!(trace_name_tables(None).2.len(), 2);
        // a name with two values leaves its table out, and the other stays
        let found = enumerators(&[("VX1000IF_OS_TASK_DOOM", &[0, 1]), ("VX1000IF_RTE_R_DOOM_TICS", &[1])]);
        let (threads, runnables, warnings) = trace_name_tables(Some(&found));
        assert_eq!(threads, None);
        assert_eq!(runnables.unwrap().len(), 2);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].starts_with("The enumerator VX1000IF_OS_TASK_DOOM has the values 0 and 1 in different units"),
            "{}",
            warnings[0]
        );
        // two names of one value, a runnable of value 0 among them
        let found = enumerators(&[("VX1000IF_OS_TASK_DOOM", &[0]), ("VX1000IF_RTE_R_DOOM_TICS", &[0])]);
        let (_, runnables, warnings) = trace_name_tables(Some(&found));
        assert_eq!(runnables, None);
        assert!(warnings[0].starts_with("The names Return and R_DOOM_TICS have the same value, 0"), "{}", warnings[0]);
    }
}

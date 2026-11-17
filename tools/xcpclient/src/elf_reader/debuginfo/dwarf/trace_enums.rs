//--------------------------------------------------------------------------------------------------------------------------------------------------
// The enumerators of the VX1000 Timing Bundle's trace IDs
//
// The bundle numbers the threads (tasks and interrupts) and the runnables it traces with enums in its header, VX1000If_Trace.h:
// VX1000IF_OS_TASK_<name>, VX1000IF_OS_ISR_<name> and VX1000IF_RTE_R_<name>. The trace words carry those numbers, and their names make
// a trace readable. The type reader cannot see them: it loads the types some variable uses, and these enums have no name and no
// variable of their type. Every unit that includes the header has a copy of its own.
//
// This pass walks the enumerators of every unit the reader has opened and keeps the ones with the bundle's prefixes, each name once,
// with every value a unit gave it: two values for one name are a header that units saw differently, and the caller says so. It runs only
// for a firmware that links no xcplite and whose mc-instrument application record switches the bundle on (MC_APP's .timing_active): every
// other ELF pays nothing for it.

use std::collections::BTreeMap;

use indexmap::IndexMap;

use super::attributes::{get_const_value_attribute, get_name_attribute};
use super::{DebugDataReader, VarInfo};

/// The prefixes of the enumerators the pass keeps: the bundle's thread IDs and its runnable IDs.
pub(crate) const TRACE_ENUM_PREFIXES: [&str; 2] = ["VX1000IF_OS_", "VX1000IF_RTE_"];

/// Enumerator name -> the values the units give it, each once, in the order the units are read.
pub(crate) type TraceEnumerators = BTreeMap<String, Vec<i64>>;

impl DebugDataReader<'_> {
    /// The trace enumerators of every opened unit, or None when the pass does not run (`wanted`); `variables` are the ones the reader
    /// has loaded.
    pub(crate) fn load_trace_enumerators(&self, variables: &IndexMap<String, Vec<VarInfo>>) -> Option<TraceEnumerators> {
        if !wanted(self.mci_app_data.as_deref(), variables.keys()) {
            return None;
        }
        let mut found = TraceEnumerators::new();
        for (unit, abbreviations) in &self.units.list {
            let mut entries = unit.entries(abbreviations);
            while let Ok(Some((_, entry))) = entries.next_dfs() {
                // An enumerator is always the child of an enumeration type, wherever that type is declared
                if entry.tag() != gimli::constants::DW_TAG_enumerator {
                    continue;
                }
                let Ok(name) = get_name_attribute(entry, &self.dwarf, unit) else {
                    continue;
                };
                if !TRACE_ENUM_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
                    continue;
                }
                let Some(value) = get_const_value_attribute(entry) else {
                    log::warn!("The enumerator {name} has no value in the debug information; it is left out of the trace's names");
                    continue;
                };
                keep_enumerator(&mut found, name, value);
            }
        }
        Some(found)
    }
}

/// Whether the pass runs: for a firmware that links no xcplite -- no `XCPLITE__<signature>` among its `variables`, the test the rest of the
/// reader makes -- and whose application record `mci_app` switches the Timing Bundle on. An xcplite application's record may carry the
/// switch, since one MC_APP builds on both backends, and the bundle is no xcplite's.
fn wanted<'a>(mci_app: Option<&[u8]>, mut variables: impl Iterator<Item = &'a String>) -> bool {
    crate::elf_reader::timing_requested(mci_app) && !variables.any(|name| name.starts_with("XCPLITE__"))
}

/// Keep `name` with `value`: a name once, each of its values once.
pub(crate) fn keep_enumerator(found: &mut TraceEnumerators, name: String, value: i64) {
    let values = found.entry(name).or_default();
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pass_runs_for_a_firmware_without_xcplite_whose_record_asks_for_the_bundle() {
        let mut record = vec![0u8; 218];
        record[212] = 1;
        let firmware = ["main".to_string(), "VX1000If_Os_Trace".to_string()];
        let xcplite = ["main".to_string(), "XCPLITE__CASDD".to_string()];
        assert!(wanted(Some(&record), firmware.iter()));
        assert!(!wanted(Some(&record), xcplite.iter()), "the bundle is no xcplite's, whatever its MC_APP says");
        record[212] = 0;
        assert!(!wanted(Some(&record), firmware.iter()));
        assert!(!wanted(None, firmware.iter()));
    }

    #[test]
    fn a_name_is_kept_once_with_each_of_its_values() {
        let mut found = TraceEnumerators::new();
        // the same anonymous enum in three units, and one name a fourth unit gives another value
        for _ in 0..3 {
            keep_enumerator(&mut found, "VX1000IF_OS_TASK_DOOM".into(), 0);
            keep_enumerator(&mut found, "VX1000IF_OS_TASK_SOUND".into(), 1);
        }
        keep_enumerator(&mut found, "VX1000IF_OS_TASK_SOUND".into(), 2);
        assert_eq!(found.len(), 2);
        assert_eq!(found["VX1000IF_OS_TASK_DOOM"], [0]);
        assert_eq!(found["VX1000IF_OS_TASK_SOUND"], [1, 2]);
    }
}

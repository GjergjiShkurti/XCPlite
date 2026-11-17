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
// for an ELF whose mc-instrument application record switches the bundle on (MC_APP's .timing_active), so every other ELF pays nothing.

use std::collections::BTreeMap;

use super::DebugDataReader;
use super::attributes::{get_const_value_attribute, get_name_attribute};

/// The prefixes of the enumerators the pass keeps: the bundle's thread IDs and its runnable IDs.
pub(crate) const TRACE_ENUM_PREFIXES: [&str; 2] = ["VX1000IF_OS_", "VX1000IF_RTE_"];

/// Enumerator name -> the values the units give it, each once, in the order the units are read.
pub(crate) type TraceEnumerators = BTreeMap<String, Vec<i64>>;

impl DebugDataReader<'_> {
    /// The trace enumerators of every opened unit, or None when the application record does not switch the bundle on.
    pub(crate) fn load_trace_enumerators(&self) -> Option<TraceEnumerators> {
        if !crate::elf_reader::timing_requested(self.mci_app_data.as_deref()) {
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

# xcpclient

XCP test client implementation in Rust

Used for integration testing and for uploading or generating A2L files.  
Partial XCP implementation with hard-coded protocol settings for XCPlite.  

## How offline A2L generation works

xcpclient generates A2L files from ELF/DWARF debug information written into the firmware by
the XCPlite instrumentation macros — no runtime A2L code is needed in the application.

**Three sources of information** are combined:

1. **`.xcp_evts` ELF section** — the XCPlite macros (`DaqCreateEvent`, `DaqCreateAndTriggerEvent`)
   emit a `tXcpEventDescriptor` constant per event into this named section. xcpclient iterates
   it to discover every event defined in the firmware, including name, cycle time, and priority.

2. **`.xcp_cals` ELF section** — `CalSegDecl` emits a `tXcpCalSegDescriptor` constant per
   calibration segment into this section, containing the segment name, address of the default
   page, and its size. xcpclient uses this to discover all calibration segments.

3. **DWARF debug info** — every trigger macro also emits a named static variable (e.g.
   `trg__AAS__eventname`) whose DWARF lexical scope covers the same local variables as the
   trigger point. xcpclient walks the DWARF to find these anchor variables, reads the
   addressing mode from their name, and associates all in-scope local variables with the
   corresponding event as measurements.

**Preconditions in the application code:**
- Use the XCPlite macros (`DaqCreateEvent`, `DaqTriggerEvent`, `CalSegDecl`, …),
  never the raw C API — only macros emit the ELF markers.
- Build with debug info (`-g` / `Debug` or `RelWithDebInfo`).
- Mark local measurement variables `volatile` so the compiler keeps them on the stack frame
  and DWARF location expressions remain valid in optimized builds.

For the full technical specification — ELF section layouts, the `trg__` anchor naming
convention, and the `AddrExt` encoding — see
[docs/TECHNICAL.md — Offline A2L Generation](../../docs/TECHNICAL.md#offline-a2l-generation--elfdwarf-internals).

### Event cycle times

Every `EVENT` of an offline A2L states the cycle time of its `xcp_evts` record: the
`cycle_time_ns` field of the 16-byte `tXcpEventDescriptor`, read from the ELF in the target's
byte order (100 000 000 ns is `100 6`, 100 ms). A record with 0 is a sporadic event (`0 0`).
Events made with `DaqCreateEventExt` therefore carry their cycle in the offline A2L as they do
in the runtime one.

### What the server answers

The writer xcpclient uses states the same `PROTOCOL_LAYER` sizes (252, 1468), timestamp
(1 us, fixed) and `IDENTIFICATION_FIELD_TYPE_RELATIVE_BYTE` for every server. xcpclient
replaces them with the values of the ELF's `xcp_proto` record (layout in
[docs/TECHNICAL.md](../../docs/TECHNICAL.md#xcp_proto-section--what-the-server-answers)).
The identification field type comes from word 4 of a version 2 record. Without it, an XCPlite
ELF gets `RELATIVE_WORD_ALIGNED`, the 4-byte header XCPlite sends, and the A2L keeps its text with
a warning if it has not exactly one DAQ block to write it into. Any other ELF without word 4 keeps
`RELATIVE_BYTE`. A value from the record that has no single place in the A2L deletes the A2L and
fails the run.

### ELFs that do not link XCPlite

An ELF without an `XCPLITE__<signature>` variable is a target that is not XCPlite — for
example a VX1000 application instrumented with mc-instrument's `mc_vx.hpp`. Some A2L facts
then follow the target rather than XCPlite's server:

- **`ADDR_EPK`** is the ELF address of the `xcp_epk` section. XCPlite serves its EPK from a
  protocol address (`0x80000000` or `0xFFFFFF00`); a VX1000 reads target memory as it is.
  xcpclient warns when the image does not hold the section at that address (it is not in the
  file contents of a `PT_LOAD` segment with `p_vaddr == p_paddr`, for example data copied to
  RAM at startup): keep the EPK `const`, so it stays in flash. An address past 32 bits, or no
  `xcp_epk` section, gives an A2L without an EPK.
- **The DWARF variable sweep** depends on mc-instrument's measurement records (`mci_meas`).
  When a record has no address (identifier addressing, XCPlite), the records are the
  measurements and the sweep adds calibration characteristics only. When every record has an
  absolute address (`mc_vx.hpp`), the sweep also adds the plain globals in the same run. It
  leaves out a variable that a `MEASURE` already measures as `<event>.<name>`: a record's name,
  or `X` of a shadow `__mci_sh_X`. `--elf-var-filter` and `--elf-unit-filter` narrow the sweep
  as usual. A swept measurement on a target that is not XCPlite has no `IF_DATA` (no event),
  so the master selects the event that samples it. An ELF without `mci_meas` is swept as before.
- **The `xcp_proto` record is required** for an ELF whose `mci_meas` records all have absolute
  addresses (`mc_vx.hpp`). Without it the A2L would state xcp_registry's MAX_CTO 252, MAX_DTO 1468,
  fixed timestamps and `RELATIVE_BYTE`, none of which a VX1000 does, and a master loses the
  samples without an error. xcpclient then fails with a message and writes no A2L. Rebuild the
  application with a `mc_vx.hpp` that writes the record, or pass `--allow-registry-protocol` to
  get the A2L with a warning. Any other ELF without the record is not affected.

### Log levels and `--print-features`

At log level 2 (warnings), a run prints only what needs a decision: a type that went wrong, a
record that does not fit, an ELF that is not fully usable. The facts of a normal run are at level
3: the A2L path, an overwritten A2L, no `XCPLITE__` signature (the ELF is not an XCPlite target),
no CFA data, and one count of the globals left out because the A2L cannot state their type (enum,
pointer, class). Level 4 lists those globals by name.

`--print-features` prints the names of what this build does, one per line, and exits with status
0 without reading anything: for the A2L `a2l-epk-elf-address`, `a2l-loclistx`,
`a2l-sweep-absolute`, `a2l-event-cycle`, `a2l-ident-field` and `a2l-require-proto`, and
`check-epk` for the EPK check below. A tool that
needs one asks for the list. A build from before the option exits with a usage error, which means
the same as a name that is missing. `--version` names the commit the build is from (issue 214),
not what it does; `--print-features` does.

Pointer members of a structure type are `ULONG` or `ULONGLONG` by the target's address size. They
were typed from the wrong field of the debug information, so a 32-bit target got `ULONGLONG`.

### `--check-epk`: does the device run the build the A2L describes?

```
xcpclient --check-epk --tcp --dest-addr 192.168.0.10:5555 --a2l app.a2l
xcpclient --check-epk --udp --dest-addr 127.0.0.1 --elf app.elf
```

The EPK is the text a build puts in its image and its A2L states (`MOD_PAR`: `EPK "..."`,
`ADDR_EPK`). `--check-epk` connects (TCP or UDP), reads the device's EPK and compares it with the
ELF's (`--elf`: the text and the address that the A2L of that ELF states) or else the A2L's
(`--a2l`). The read is an upload of the text's length from `ADDR_EPK` with address extension 0,
which is what a master does when it goes online. Where the A2L has no `ADDR_EPK`, or the device
refuses the upload, it asks `GET_ID` type 5. The connection is CONNECT only, with no DAQ setup, so
a server whose DAQ xcpclient cannot use (a VX1000) can also be checked. It prints one line and
exits:

| exit | line |
|---|---|
| 0 | `EPK match: "<epk>" at 0x<ADDR_EPK>` (or `by GET_ID`) |
| 2 | `EPK mismatch: the device has "<text>", the A2L has "<epk>" (at 0x<ADDR_EPK>)` |
| 1 | an error: no EPK in the ELF or the A2L, no connection in 5 s, nothing read |

A device byte that is not printable ASCII shows as `\xNN` (erased flash reads `\xFF\xFF...`). An
upload reads exactly the expected length, as a master does, so a device text that only continues
the expected one is not seen. The CANape Kernel does not check the EPK, and a device flashed with
another build then measures plausible values from the wrong addresses. Run the check before a
measurement.




XCP client v2.1.x for testing XCP servers and managing A2L and HEX files.

This tool can:
- Connect to XCP on Ethernet servers via TCP or UDP and show information about the XCP protocol and the target ECU
- Upload A2L or ELF files from XCP servers (GET_ID command)
- Create A2L files from ELF/DWARF debug information including event and memory segment information obtained from the XCP server or from an ELF file
- Create A2L file templates for from a XCPlite ELF/DWARF
- Fix A2L files with event and memory segment information from the XCP server
- Read and write calibration variables (CAL)
- Upload (from target) and download (to target) binary files (Intel-HEX) with calibration segment data
- List available measurement variables and parameters with regex patterns
- Test data acquisition (DAQ)
- Execute test sequences


Usage: xcpclient [OPTIONS]

Options:
      --log-level <LOG_LEVEL>
          Log level (Off=0, Error=1, Warn=2, Info=3, Debug=4, Trace=5) [default: 3]

      --verbose <VERBOSE>
          Verbose output Enables additional output when reading ELF files and creating A2L files
            
      --dest-addr <DEST_ADDR>
          XCP server address (IP address or IP:port). If port is omitted, uses --port parameter [default: 127.0.0.1]

      --port <PORT>
          XCP server port number (used when --dest-addr doesn't include port) [default: 5555]

      --bind-addr <BIND_ADDR>
          Bind address (IP address or IP:port). If port is omitted, system assigns an available port [default: 0.0.0.0]

      --tcp
          Use TCP for XCP communication..

      --udp
          Use UDP for XCP communication

      --connect-mode <CONNECT_MODE>
          XCP connect mode

      --offline
          Force offline mode (no network communication), communication parameters are used to create A2L file

      --a2l <A2L>
          Specify and overide the name of the A2L file name. If not specified, The A2L file name is read from the XCP server
          
      --upload-a2l
          Upload A2L file from XCP server. Requires that the XCP server supports GET_ID A2L upload

      --create-a2l
          Build an A2L file template from XCP server information about events and memory segments. Requires that the XCP server supports the GET_EVENT_INFO and GET_SEGMENT_INFO commands. Insert all visible measurement and calibration variables from ELF file if specified with --elf or --upload-elf

      --create-a2l-template
          Build a minimal A2L template from XCP server event and memory segment information only. No variables or types are registered; the result is a skeleton A2L file. Requires that the XCP server supports the GET_EVENT_INFO and GET_SEGMENT_INFO commands

      --fix-a2l
          Update the given A2L file with XCP server information about events and memory segments. Requires that the XCP server supports the GET_EVENT_INFO and GET_SEGMENT_INFO commands

      --upload-elf
          Upload ELF file from XCP server. Requires that the XCP server supports proprietary GET_ID ELF upload command

      --elf <ELF>
          Specify the name of an ELF file, create an A2L file from ELF debug information. If connected to a XCP server, events and memory segments will be extracted from the XCP server

      --elf-unit-limit <ELF_UNIT_LIMIT>
          Parse only compilations units <= n

      --elf-var-filter <ELF_VAR_FILTER>
          Regex pattern to filter variable names when registering from an ELF file.
          Only variables whose names match the pattern are included in the A2L output.
          If not specified (or empty), all variables are registered.
          Example: --elf-var-filter "counter.*"

      --elf-unit-filter <ELF_UNIT_FILTER>
          Regex pattern to filter variables by their compilation unit (source file) name.
          Only variables defined in compilation units whose name matches are included in the A2L output.
          If not specified (or empty), variables from all compilation units are registered.
          Example: --elf-cu-filter "my_module.*"

      --bin <BIN>
          Specify the pathname of a binary file (Intel-HEX) for calibration parameter segment data

      --upload-bin
          Upload all calibration segments working page data from target and store into a binary file. Requires that the XCP server supports GET_ID A2L upload

      --download-bin
          Download all calibration segments working page data in a binary file to the target

      --list-mea <LIST_MEA>
          Lists all specified measurement variables (regex) found in the A2L file

      --mea <MEA>...
          Specify variable names for DAQ measurement (list), may be list of names separated by space or single regular expressions (e.g. ".*")

      --time <TIME>
          Time limit measurement duration to n s. 0 means infinite

      --csv <CSV>
          Save measurement data to a CSV file. If not specified, data is printed to the console. CSV format: time_ns,daq,name,value  (one row per measurement sample)

      --list-cal <LIST_CAL>
          Lists all specified calibration variables (regex) found in the A2L file
          
      --cal <NAME> <VALUE>
          Set calibration variable to a value (format: "variable_name value")

      --test
          --test Execute a test sequence on the XCP server

      --print-features
          Print one line per feature this build has (A2L facts, device checks), then exit

      --check-epk
          Compare the device's EPK with the ELF's (--elf) or else the A2L's (--a2l), then exit

      --allow-registry-protocol
          Create the A2L of a VX1000 ELF that has no xcp_proto record anyway

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version


## Build and Install

```bash
cd tools/xcpclient
cargo install --path .
```

## Examples

### List all calibration or measurement variables

```bash
xcpclient --dest-addr 192.168.0.206 --udp --list-cal .
xcpclient --dest-addr 192.168.0.206 --udp --list-mea .
```

### Set a calibration variable

Set variable counter_max to 1000
```bash
xcpclient --dest-addr 192.168.0.206 --port 5555 --tcp --cal counter_max 1000
```

### Measure variables

Measure everything from uploaded A2L file for 5 seconds with detailed log to terminal:  

```bash
xcpclient --dest-addr=127.0.0.1  --udp --upload-a2l --mea ".*" --time 5 --verbose 2
```

With A2L file given:  

```bash
xcpclient --dest-addr=192.168.0.206  --tcp --a2l hello_xcp.a2l  --mea ".*" 
```

With ELF file given, creates an A2L file from the ELF file and XCP server information about events and memory segments, then measures the specified variable:  

```bash
xcpclient --udp --elf build/hello_xcp --mea "counter" --verbose 2
```


### Upload the A2L file to be used from the target

```bash
xcpclient --dest-addr=192.168.0.206:5555 --tcp --upload-a2l   
```

### Create an A2L file for a target from ELF without on target A2L generation support

Ccreate an A2L file from the ELF file (and optional XCP server information about events and memory segments), then save the A2L file as hello_xcp.a2l:
```bash

# offline
xcpclient --offline --elf examples/no_a2l_demo/CANape/no_a2l_demo.elf --a2l examples/no_a2l_demo/CANape/no_a2l_demo_template.a2l --create-a2l-template 
xcpclient --offline --elf examples/no_a2l_demo/CANape/no_a2l_demo.elf --a2l examples/no_a2l_demo/CANape/no_a2l_demo.a2l --create-a2l

# online with XCP server information about events and memory segments
xcpclient --dest-addr=192.168.0.206:5555 --udp  --create-a2l --elf no_a2l_demo.elf --a2l no_a2l_demo.a2l 
```

Upload the ELF file into hello_xcp.elf and create an A2L file from the ELF file and XCP server information about events and memory segments, then save the A2L file as hello_xcp.a2l:
```bash
xcpclient --dest-addr=192.168.0.206:5555 --udp --create-a2l --upload-elf --elf hello_xcp.elf --a2l hello_xcp.a2l 
```

### Upload an Intel-HEX file with the current calibration data

```bash
xcpclient --upload-bin test.hex
```


#### Demo

```bash

# A2l from no_a2l_demo.out
cargo r --  --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l   --offline  


cargo r --  --dest-addr 192.168.0.206 --udp --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l 

cargo r --  --dest-addr 192.168.0.206  --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l --list-mea 'counter'

cargo r --  --dest-addr 192.168.0.206  --elf no_a2l_demo.out --elf-unit-limit 1000 --log-level 3  --create-a2l --a2l no_a2l_demo.a2l --mea 'counter'  --time 5 --verbose 2

```
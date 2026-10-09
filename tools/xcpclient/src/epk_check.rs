//-----------------------------------------------------------------------------
// epk_check.rs -- `--check-epk`: is the device running the build the ELF or the A2L describes?
//
// Added to upstream (issue 375). The EPK is the text a build puts in its image and its A2L states
// (MOD_PAR EPK, ADDR_EPK). A master that reads the device at ADDR_EPK and finds another text knows
// that the A2L's addresses belong to another build. The CANape Kernel does not make this check, so
// a device flashed with an older build measures plausible values from the wrong addresses. This
// makes the check on its own: one line, exit status 0 (match), 2 (mismatch) or 1 (error).
//-----------------------------------------------------------------------------

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use parking_lot::Mutex;

use crate::elf_reader::ElfReader;
use crate::xcp_client::{OdtEntry, XcpClient, XcpDaqDecoder, XcpTextDecoder, xcp::IDT_ASAM_EPK};

/// The device holds the expected EPK
pub const EXIT_MATCH: i32 = 0;
/// The check could not be made: no EPK to compare, no connection, nothing read
pub const EXIT_ERROR: i32 = 1;
/// The device holds another EPK
pub const EXIT_MISMATCH: i32 = 2;

/// How long the connection may take. A TCP connect to a host that does not answer waits for the
/// operating system's limit (about 20 s on Windows), and a caller runs the check before it starts
/// a measurement.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The EPK to compare the device with, and where it comes from
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedEpk {
    pub text: String,
    /// ADDR_EPK; None when the A2L or the ELF states none, and the device is asked with GET_ID
    pub addr: Option<u32>,
    /// "ELF" or "A2L", for the result line
    pub source: &'static str,
}

/// Where the device's EPK was read
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    /// SET_MTA + UPLOAD at ADDR_EPK, address extension 0: what a master does on going online
    Address(u32),
    /// GET_ID type 5 (ASAM EPK)
    GetId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Match,
    /// The device's text, made printable
    Mismatch(String),
}

/// Compare the bytes read from the device with the expected EPK. An upload reads exactly as many
/// bytes as the expected text has, as a master does, so a device text that only continues the
/// expected one is not seen. GET_ID answers the whole text. NUL bytes at the end (padding of the
/// section) are not part of the text.
pub fn compare(expected: &str, device: &[u8]) -> Verdict {
    let mut end = device.len();
    while end > 0 && device[end - 1] == 0 {
        end -= 1;
    }
    let device = &device[..end];
    if device == expected.as_bytes() {
        Verdict::Match
    } else {
        Verdict::Mismatch(printable(device))
    }
}

/// The device's bytes as text for the result line: up to the first NUL, with every byte that is
/// not printable ASCII as `\xNN` (an erased flash reads `\xFF\xFF...`) and `"` and `\` escaped.
pub fn printable(bytes: &[u8]) -> String {
    let bytes = match bytes.iter().position(|&b| b == 0) {
        Some(n) => &bytes[..n],
        None => bytes,
    };
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\\x{:02X}", b)),
        }
    }
    s
}

/// The one line the check prints
pub fn verdict_line(expected: &ExpectedEpk, verdict: &Verdict, from: ReadFrom) -> String {
    let at = match from {
        ReadFrom::Address(addr) => format!("at 0x{:08X}", addr),
        ReadFrom::GetId => "by GET_ID".to_string(),
    };
    match verdict {
        Verdict::Match => format!("EPK match: \"{}\" {}", printable(expected.text.as_bytes()), at),
        Verdict::Mismatch(device) => format!(
            "EPK mismatch: the device has \"{}\", the {} has \"{}\" ({})",
            device,
            expected.source,
            printable(expected.text.as_bytes()),
            at
        ),
    }
}

//-----------------------------------------------------------------------------
// The EPK an A2L states

/// The EPK text and ADDR_EPK of the A2L's MOD_PAR, None when it states no EPK text. The A2L is
/// read as tokens, so a MOD_PAR on one line and comments are no different from the usual layout.
pub fn epk_from_a2l(a2l: &str) -> Option<(String, Option<u32>)> {
    let tokens = tokenize(a2l);
    let start = tokens
        .windows(2)
        .position(|w| w[0] == Token::Word("/begin".into()) && w[1] == Token::Word("MOD_PAR".into()))?;
    let mut text = None;
    let mut addr = None;
    let mut i = start + 2;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Word(w) if w == "/end" && tokens.get(i + 1) == Some(&Token::Word("MOD_PAR".into())) => break,
            Token::Word(w) if w == "EPK" && text.is_none() => {
                if let Some(Token::Str(s)) = tokens.get(i + 1) {
                    text = Some(s.clone());
                    i += 1;
                }
            }
            Token::Word(w) if w == "ADDR_EPK" && addr.is_none() => {
                if let Some(Token::Word(n)) = tokens.get(i + 1) {
                    addr = parse_number(n);
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    text.filter(|t| !t.is_empty()).map(|t| (t, addr))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Str(String),
}

// A2L tokens: words, and strings in double quotes (\" and "" are a quote); /* */ and // comments
fn tokenize(a2l: &str) -> Vec<Token> {
    let c: Vec<char> = a2l.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if c[i].is_whitespace() {
            i += 1;
        } else if c[i] == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i < c.len() && !(c[i] == '*' && c.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else if c[i] == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if c[i] == '"' {
            let mut s = String::new();
            i += 1;
            while i < c.len() {
                if c[i] == '\\' && i + 1 < c.len() {
                    s.push(c[i + 1]);
                    i += 2;
                } else if c[i] == '"' && c.get(i + 1) == Some(&'"') {
                    s.push('"');
                    i += 2;
                } else if c[i] == '"' {
                    i += 1;
                    break;
                } else {
                    s.push(c[i]);
                    i += 1;
                }
            }
            tokens.push(Token::Str(s));
        } else {
            let begin = i;
            while i < c.len() && !c[i].is_whitespace() && c[i] != '"' {
                i += 1;
            }
            tokens.push(Token::Word(c[begin..i].iter().collect()));
        }
    }
    tokens
}

fn parse_number(n: &str) -> Option<u32> {
    match n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => n.parse().ok(),
    }
}

//-----------------------------------------------------------------------------
// The check

/// The EPK to compare with: the ELF's when `elf` is given, else the A2L's
pub fn expected_epk(elf: &str, a2l: &str, elf_unit_limit: usize) -> Result<ExpectedEpk, Box<dyn Error>> {
    if !elf.is_empty() {
        let reader = ElfReader::new(elf, 0, elf_unit_limit).ok_or(format!("Failed to read ELF file '{}'", elf))?;
        let (text, addr) = reader
            .epk()
            .ok_or(format!("The ELF '{}' has no EPK (no xcp_epk section, or no text in it): nothing to compare", elf))?;
        return Ok(ExpectedEpk { text, addr, source: "ELF" });
    }
    if !a2l.is_empty() {
        let bytes = std::fs::read(a2l).map_err(|e| format!("Could not read the A2L '{}': {}", a2l, e))?;
        let (text, addr) = epk_from_a2l(&String::from_utf8_lossy(&bytes)).ok_or(format!("The A2L '{}' states no EPK in MOD_PAR: nothing to compare", a2l))?;
        return Ok(ExpectedEpk { text, addr, source: "A2L" });
    }
    Err("--check-epk needs the ELF (--elf) or the A2L (--a2l) to compare the device with".into())
}

// The check reads memory and receives no DAQ data and no text it would show
struct NoDaq;
impl XcpDaqDecoder for NoDaq {
    fn decode(&mut self, _lost: u32, _data: &[u8]) {}
    fn start(&mut self, _odt_entries: Vec<Vec<OdtEntry>>, _timestamp_raw64: u64) {}
    fn set_daq_properties(&mut self, _timestamp_resolution: u64, _daq_header_size: u8) {}
}
struct NoText;
impl XcpTextDecoder for NoText {
    fn decode(&self, _data: &[u8]) {}
}

/// Connect, read the device's EPK and compare it with `expected`. The read is an upload of the
/// text's length from ADDR_EPK (address extension 0), as a master does on going online; where the
/// A2L has no ADDR_EPK, or the device refuses the upload, it is GET_ID type 5.
pub async fn check_epk(
    expected: &ExpectedEpk,
    protocol: &'static str,
    dest_addr: SocketAddr,
    local_addr: SocketAddr,
    connect_mode: u8,
) -> Result<(Verdict, ReadFrom), Box<dyn Error>> {
    if protocol != "TCP" && protocol != "UDP" {
        return Err(format!("--check-epk connects over TCP or UDP, not {}", protocol).into());
    }
    let mut client = XcpClient::new(protocol, dest_addr, local_addr, 0);
    match tokio::time::timeout(CONNECT_TIMEOUT, client.connect_memory_access(connect_mode, Arc::new(Mutex::new(NoDaq)), NoText)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("Could not connect to the XCP server at {}: {}", dest_addr, e).into()),
        Err(_) => return Err(format!("Could not connect to the XCP server at {}: no answer in {} s", dest_addr, CONNECT_TIMEOUT.as_secs()).into()),
    }
    let result = read_and_compare(&mut client, expected).await;
    let _ = client.disconnect().await;
    result
}

async fn read_and_compare(client: &mut XcpClient, expected: &ExpectedEpk) -> Result<(Verdict, ReadFrom), Box<dyn Error>> {
    let len = u32::try_from(expected.text.len()).map_err(|_| "The EPK is too long")?;
    if let Some(addr) = expected.addr {
        let upload = async {
            client.set_mta(0, addr).await?;
            client.upload_memory_block(len).await
        };
        match upload.await {
            Ok(bytes) => return Ok((compare(&expected.text, &bytes), ReadFrom::Address(addr))),
            Err(e) => warn!("The device refused the upload of {} bytes from ADDR_EPK 0x{:08X} ({}): asking with GET_ID", len, addr, e),
        }
    }
    let (size, text) = client
        .get_id(IDT_ASAM_EPK)
        .await
        .map_err(|e| format!("The device answered neither an upload from ADDR_EPK nor GET_ID EPK: {}", e))?;
    let bytes = match text {
        Some(text) => text.into_bytes(),
        None => client.upload_memory_block(size).await?,
    };
    Ok((compare(&expected.text, &bytes), ReadFrom::GetId))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(text: &str, addr: Option<u32>, source: &'static str) -> ExpectedEpk {
        ExpectedEpk { text: text.into(), addr, source }
    }

    #[test]
    fn the_same_text_matches() {
        assert_eq!(compare("000.001.000", b"000.001.000"), Verdict::Match);
    }

    #[test]
    fn nul_padding_after_the_text_matches() {
        // GET_ID of a padded section, or a text read with its NUL
        assert_eq!(compare("v1", b"v1\0\0\0"), Verdict::Match);
    }

    #[test]
    fn another_text_is_a_mismatch_with_the_device_text() {
        assert_eq!(compare("Oct  2 2026 13:05:54", b"Oct  2 2026 11:41:07"), Verdict::Mismatch("Oct  2 2026 11:41:07".into()));
    }

    #[test]
    fn a_shorter_device_text_is_a_mismatch() {
        assert_eq!(compare("abc", b"ab"), Verdict::Mismatch("ab".into()));
        assert_eq!(compare("abc", b"ab\0"), Verdict::Mismatch("ab".into()));
    }

    #[test]
    fn erased_flash_is_a_mismatch_that_shows_the_bytes() {
        assert_eq!(compare("ab", &[0xFF, 0xFF]), Verdict::Mismatch("\\xFF\\xFF".into()));
    }

    #[test]
    fn an_empty_answer_is_a_mismatch() {
        assert_eq!(compare("ab", b""), Verdict::Mismatch(String::new()));
        assert_eq!(compare("ab", b"\0\0"), Verdict::Mismatch(String::new()));
    }

    #[test]
    fn printable_stops_at_nul_and_escapes() {
        assert_eq!(printable(b"a\"b\\c\x01\0rest"), "a\\\"b\\\\c\\x01");
    }

    #[test]
    fn the_result_lines() {
        let elf = expected("abc", Some(0x0801_B960), "ELF");
        assert_eq!(verdict_line(&elf, &Verdict::Match, ReadFrom::Address(0x0801_B960)), "EPK match: \"abc\" at 0x0801B960");
        assert_eq!(
            verdict_line(&elf, &Verdict::Mismatch("abd".into()), ReadFrom::Address(0x0801_B960)),
            "EPK mismatch: the device has \"abd\", the ELF has \"abc\" (at 0x0801B960)"
        );
        let a2l = expected("abc", None, "A2L");
        assert_eq!(
            verdict_line(&a2l, &Verdict::Mismatch("x".into()), ReadFrom::GetId),
            "EPK mismatch: the device has \"x\", the A2L has \"abc\" (by GET_ID)"
        );
    }

    #[test]
    fn the_a2l_epk_and_address_come_from_mod_par() {
        let a2l = r#"
/begin PROJECT p ""
  /begin MODULE m ""
    /begin MOD_PAR "comment"
      EPK "Oct  2 2026 13:05:54"
      ADDR_EPK 0x0801B960
      /begin MEMORY_SEGMENT epk "" DATA FLASH INTERN 0x80000000 32 -1 -1 -1 -1 -1 /end MEMORY_SEGMENT
    /end MOD_PAR
  /end MODULE
/end PROJECT
"#;
        assert_eq!(epk_from_a2l(a2l), Some(("Oct  2 2026 13:05:54".into(), Some(0x0801_B960))));
    }

    #[test]
    fn a_mod_par_on_one_line_with_comments_is_read() {
        let a2l = r#"/* EPK "not this" */ /begin MOD_PAR "" // EPK "nor this"
        ADDR_EPK 4294967040 EPK "v\"1" /end MOD_PAR"#;
        assert_eq!(epk_from_a2l(a2l), Some(("v\"1".into(), Some(0xFFFF_FF00))));
    }

    #[test]
    fn an_epk_outside_mod_par_is_not_the_epk() {
        assert_eq!(epk_from_a2l(r#"/begin MOD_PAR "" ADDR_EPK 0x10 /end MOD_PAR EPK "late""#), None);
        assert_eq!(epk_from_a2l(r#"/begin MODULE m "" /end MODULE"#), None);
    }

    #[test]
    fn an_epk_without_an_address_is_asked_by_get_id() {
        assert_eq!(epk_from_a2l(r#"/begin MOD_PAR "" EPK "abc" /end MOD_PAR"#), Some(("abc".into(), None)));
    }

    #[test]
    fn an_empty_epk_is_no_epk() {
        assert_eq!(epk_from_a2l(r#"/begin MOD_PAR "" EPK "" ADDR_EPK 0x10 /end MOD_PAR"#), None);
    }

    #[test]
    fn check_epk_needs_an_elf_or_an_a2l() {
        assert!(expected_epk("", "", usize::MAX).is_err());
    }
}

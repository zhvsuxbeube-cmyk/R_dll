/*
 * Copyright 2014 Stas'M Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Rust port of IniFile.h / IniFile.cpp
 */

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Maximum length for string fields — matches MAX_STRING_LEN in the C++ code.
pub const MAX_STRING_LEN: usize = 255;

// ---------------------------------------------------------------------------
// Output value types (mirror the C++ structs exactly)
// ---------------------------------------------------------------------------

/// Mirrors INI_VAR_STRING.
#[derive(Clone, Default)]
pub struct IniVarString {
    pub name: String,
    pub value: String,
}

/// Mirrors INI_VAR_DWORD.
/// On x64 the fields are u64; on x86 they are u32.
/// We always use u64 internally for simplicity — callers that only need a
/// DWORD will cast / truncate, which is identical to the C++ behaviour.
#[derive(Clone, Default)]
pub struct IniVarDword {
    pub name: String,
    /// Parsed as decimal (strtol base 10 / _strtoi64 base 10)
    pub value_dec: u64,
    /// Parsed as hexadecimal (strtol base 16 / _strtoi64 base 16)
    pub value_hex: u64,
}

/// Mirrors INI_VAR_BYTEARRAY.
/// The C++ struct holds `char Value[MAX_STRING_LEN]` and `BYTE ArraySize`.
/// Here we store the already-decoded bytes directly.
#[derive(Clone, Default)]
pub struct IniVarByteArray {
    pub name: String,
    /// Decoded bytes (at most 16, same as C++ `if (ValueLen > 32) ValueLen = 32`)
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal representation
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct IniSectionVariable {
    name: String,
    value: String,
}

#[derive(Clone, Default)]
struct IniSection {
    name: String,
    variables: Vec<IniSectionVariable>,
}

// ---------------------------------------------------------------------------
// IniFile
// ---------------------------------------------------------------------------

/// Mirrors the INI_FILE C++ class.
pub struct IniFile {
    sections: Vec<IniSection>,
}

impl IniFile {
    // -----------------------------------------------------------------------
    // Construction — mirrors INI_FILE::INI_FILE(wchar_t *FilePath)
    // -----------------------------------------------------------------------

    /// Open and parse an INI file.  Returns `None` when the file cannot be
    /// opened or read (matches the silent-failure behaviour of the C++
    /// constructor).
    pub fn open(path: &[u16]) -> Option<Self> {
        use winapi::um::fileapi::{CreateFileW, GetFileSize, ReadFile, INVALID_FILE_SIZE, OPEN_EXISTING};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ};

        // Ensure NUL-terminated
        let mut path_nul: Vec<u16> = path.to_vec();
        if path_nul.last().copied() != Some(0) {
            path_nul.push(0);
        }

        let hfile = unsafe {
            CreateFileW(
                path_nul.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                core::ptr::null_mut(),
            )
        };
        if hfile == INVALID_HANDLE_VALUE {
            return None;
        }

        let file_size = unsafe { GetFileSize(hfile, core::ptr::null_mut()) };
        if file_size == INVALID_FILE_SIZE || file_size == 0 {
            unsafe { CloseHandle(hfile) };
            return None;
        }

        let mut raw: Vec<u8> = vec![0u8; file_size as usize];
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                hfile,
                raw.as_mut_ptr() as *mut _,
                file_size,
                &mut bytes_read,
                core::ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(hfile) };
        if ok == 0 {
            return None;
        }
        raw.truncate(bytes_read as usize);

        let sections = Self::parse(&raw);
        Some(IniFile { sections })
    }

    // -----------------------------------------------------------------------
    // Parsing — mirrors CreateStringsMap() + Parse()
    // -----------------------------------------------------------------------

    /// Split raw bytes on \r\n (same as CreateStringsMap + Parse in C++).
    fn parse(raw: &[u8]) -> Vec<IniSection> {
        // Split into lines exactly like the C++ string-map does:
        // a new line starts after each \r\n pair.
        let lines: Vec<&[u8]> = raw.split(|&b| b == b'\n')
            .map(|l| if l.last() == Some(&b'\r') { &l[..l.len()-1] } else { l })
            .collect();

        let mut sections: Vec<IniSection> = Vec::new();
        let mut current_section: Option<usize> = None;

        for line_bytes in &lines {
            // Decode as ASCII / Latin-1 (the INI file is ASCII)
            let line: String = line_bytes.iter().map(|&b| b as char).collect();
            let line = Self::str_trim(&line);

            if line.starts_with(';') || line.is_empty() {
                continue; // comment or blank
            }

            // Section header: [SectionName]
            if line.starts_with('[') && line.ends_with(']') {
                let sect_name = &line[1..line.len()-1];
                sections.push(IniSection {
                    name: String::from(sect_name),
                    variables: Vec::new(),
                });
                current_section = Some(sections.len() - 1);
                continue;
            }

            // Variable: Name=Value
            if Self::is_variable(&line) {
                if let Some(idx) = current_section {
                    if let Some(var) = Self::fill_variable(&line) {
                        sections[idx].variables.push(var);
                    }
                }
            }
        }

        sections
    }

    /// Mirrors StrTrim — trims leading and trailing spaces / tabs.
    fn str_trim(s: &str) -> String {
        String::from(s.trim_matches(|c| c == ' ' || c == '\t'))
    }

    /// Mirrors IsVariable — returns true if the line contains an unquoted '='.
    fn is_variable(s: &str) -> bool {
        let mut in_quotes = false;
        for c in s.chars() {
            if c == '"' || c == '\'' {
                in_quotes = !in_quotes;
            }
            if c == '=' && !in_quotes {
                return true;
            }
        }
        false
    }

    /// Mirrors FillVariable — splits on the first unquoted '=' and trims both sides.
    fn fill_variable(s: &str) -> Option<IniSectionVariable> {
        let mut in_quotes = false;
        for (i, c) in s.char_indices() {
            if c == '"' || c == '\'' {
                in_quotes = !in_quotes;
            }
            if c == '=' && !in_quotes {
                let name = Self::str_trim(&s[..i]);
                let value = Self::str_trim(&s[i+1..]);
                return Some(IniSectionVariable { name, value });
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Section lookup — mirrors GetSection
    // -----------------------------------------------------------------------

    fn get_section(&self, name: &str) -> Option<&IniSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    fn get_variable_raw(&self, section: &str, var_name: &str) -> Option<IniSectionVariable> {
        let sect = self.get_section(section)?;
        let var = sect.variables.iter().find(|v| v.name == var_name)?;
        Some(var.clone())
    }

    // -----------------------------------------------------------------------
    // Public API — char block (mirrors the C++ char overloads)
    // -----------------------------------------------------------------------

    /// Mirrors SectionExists(char*)
    pub fn section_exists(&self, section: &str) -> bool {
        self.get_section(section).is_some()
    }

    /// Mirrors VariableExists(char*, char*)
    pub fn variable_exists(&self, section: &str, var_name: &str) -> bool {
        self.get_variable_raw(section, var_name).is_some()
    }

    /// Mirrors GetVariableInSection(…, INI_VAR_STRING*)
    pub fn get_string(&self, section: &str, var_name: &str) -> Option<IniVarString> {
        let raw = self.get_variable_raw(section, var_name)?;
        Some(IniVarString {
            name: raw.name,
            value: raw.value,
        })
    }

    /// Mirrors GetVariableInSection(…, INI_VAR_DWORD*)
    /// Parses as both decimal and hexadecimal just like the C++ code.
    pub fn get_dword(&self, section: &str, var_name: &str) -> Option<IniVarDword> {
        let raw = self.get_variable_raw(section, var_name)?;
        let value_dec = u64::from_str_radix(raw.value.trim(), 10).unwrap_or(0);
        let value_hex = u64::from_str_radix(raw.value.trim(), 16).unwrap_or(0);
        Some(IniVarDword {
            name: raw.name,
            value_dec,
            value_hex,
        })
    }

    /// Mirrors GetVariableInSection(…, bool*)
    /// Returns the decimal integer interpreted as a bool (nonzero = true).
    pub fn get_bool(&self, section: &str, var_name: &str) -> Option<bool> {
        let raw = self.get_variable_raw(section, var_name)?;
        let n = i64::from_str_radix(raw.value.trim(), 10).unwrap_or(0);
        Some(n != 0)
    }

    /// Mirrors GetVariableInSection(…, INI_VAR_BYTEARRAY*)
    ///
    /// The C++ implementation:
    ///   - Requires even-length hex string
    ///   - Caps at 32 hex chars (16 bytes) for security
    ///   - Parses uppercase hex only (A-F; lowercase is unhandled in the
    ///     original switch-case, so we do the same — only uppercase)
    pub fn get_bytearray(&self, section: &str, var_name: &str) -> Option<IniVarByteArray> {
        let raw = self.get_variable_raw(section, var_name)?;

        let hex_str = &raw.value;
        let mut value_len = hex_str.len();

        if value_len % 2 != 0 {
            return None; // C++ returns false
        }

        // Cap at 32 hex digits (16 bytes) — security measure from C++ code
        if value_len > 32 {
            value_len = 32;
        }

        let hex_chars: Vec<char> = hex_str.chars().collect();
        let num_bytes = value_len / 2;
        let mut bytes = vec![0u8; num_bytes];

        for i in (0..value_len).step_by(2) {
            let hi = Self::hex_nibble(hex_chars[i]);
            let lo = Self::hex_nibble(hex_chars[i + 1]);
            bytes[i / 2] = (hi << 4) | lo;
        }

        Some(IniVarByteArray {
            name: raw.name,
            value: bytes,
        })
    }

    /// Decode one uppercase hex nibble — matches the C++ switch statement
    /// exactly (only handles '0'-'9' and 'A'-'F', unrecognised → 0).
    fn hex_nibble(c: char) -> u8 {
        match c {
            '0' => 0,
            '1' => 1,
            '2' => 2,
            '3' => 3,
            '4' => 4,
            '5' => 5,
            '6' => 6,
            '7' => 7,
            '8' => 8,
            '9' => 9,
            'A' => 10,
            'B' => 11,
            'C' => 12,
            'D' => 13,
            'E' => 14,
            'F' => 15,
            _ => 0,
        }
    }

    // -----------------------------------------------------------------------
    // wchar_t trampolines — mirrors the wchar_t overloads in the C++ code.
    // In Rust we receive wide strings (slices of u16) and convert to &str.
    // -----------------------------------------------------------------------

    /// Convert a NUL-terminated (or not) wide-char slice to a Rust String.
    pub fn wide_to_string(wide: &[u16]) -> String {
        let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..end])
    }

    pub fn section_exists_wide(&self, section: &[u16]) -> bool {
        self.section_exists(&Self::wide_to_string(section))
    }

    pub fn variable_exists_wide(&self, section: &[u16], var_name: &[u16]) -> bool {
        self.variable_exists(
            &Self::wide_to_string(section),
            &Self::wide_to_string(var_name),
        )
    }

    pub fn get_string_wide(&self, section: &[u16], var_name: &[u16]) -> Option<IniVarString> {
        self.get_string(
            &Self::wide_to_string(section),
            &Self::wide_to_string(var_name),
        )
    }

    pub fn get_dword_wide(&self, section: &[u16], var_name: &[u16]) -> Option<IniVarDword> {
        self.get_dword(
            &Self::wide_to_string(section),
            &Self::wide_to_string(var_name),
        )
    }

    pub fn get_bool_wide(&self, section: &[u16], var_name: &[u16]) -> Option<bool> {
        self.get_bool(
            &Self::wide_to_string(section),
            &Self::wide_to_string(var_name),
        )
    }

    pub fn get_bytearray_wide(
        &self,
        section: &[u16],
        var_name: &[u16],
    ) -> Option<IniVarByteArray> {
        self.get_bytearray(
            &Self::wide_to_string(section),
            &Self::wide_to_string(var_name),
        )
    }
}

//! `reg`: offline Windows registry hive (`regf`) parser — enough to drive `secretsdump` over `SAM`,
//! `SYSTEM`, and `SECURITY` hives (`impacket/winregistry.py`).
//!
//! Parses the base block, walks named-key (`nk`) nodes through subkey lists (`lf`/`lh`/`li`/`ri`),
//! reads a key's class name (where the SYSTEM `Lsa` bootkey nibbles live) and its values (`vk` cells,
//! inline or out-of-line data). All offsets are relative to the first hive bin at file offset 0x1000.

use impacket_core::CoreError;

const HBIN_BASE: usize = 0x1000;

/// A parsed `regf` hive backed by its raw bytes.
pub struct Hive<'a> {
    data: &'a [u8],
    root_offset: u32,
}

/// A named key (`nk`) node.
#[derive(Debug, Clone)]
pub struct Nk {
    pub name: String,
    pub subkey_count: u32,
    pub subkeys_list_offset: u32,
    pub value_count: u32,
    pub values_list_offset: u32,
    pub class_offset: u32,
    pub class_length: u16,
}

/// A value (`vk`) entry.
#[derive(Debug, Clone)]
pub struct Vk {
    pub name: String,
    pub data_type: u32,
    pub data: Vec<u8>,
}

fn rd_u16(b: &[u8], o: usize) -> Result<u16, CoreError> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(CoreError::BufferUnderflow { needed: o + 2, available: b.len() })
}
fn rd_u32(b: &[u8], o: usize) -> Result<u32, CoreError> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(CoreError::BufferUnderflow { needed: o + 4, available: b.len() })
}

/// Decodes a key/value name: Latin-1 when the ASCII-name flag is set, else UTF-16LE.
fn decode_name(bytes: &[u8], ascii: bool) -> String {
    if ascii {
        bytes.iter().map(|&b| b as char).collect()
    } else {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

impl<'a> Hive<'a> {
    /// Validates the `regf` base block and captures the root cell offset.
    pub fn new(data: &'a [u8]) -> Result<Self, CoreError> {
        if data.len() < HBIN_BASE || &data[0..4] != b"regf" {
            return Err(CoreError::ProtocolError("not a regf hive".into()));
        }
        let root_offset = rd_u32(data, 0x24)?;
        Ok(Self { data, root_offset })
    }

    /// Returns a cell's data slice (the bytes after the 4-byte signed size word).
    fn cell(&self, rel_offset: u32) -> Result<&'a [u8], CoreError> {
        let abs = HBIN_BASE + rel_offset as usize;
        let raw_size = rd_u32(self.data, abs)? as i32;
        let size = raw_size.unsigned_abs() as usize;
        if size < 4 {
            return Err(CoreError::ProtocolError("regf cell size < 4".into()));
        }
        self.data
            .get(abs + 4..abs + size)
            .ok_or(CoreError::BufferUnderflow { needed: abs + size, available: self.data.len() })
    }

    fn parse_nk(&self, rel_offset: u32) -> Result<Nk, CoreError> {
        let c = self.cell(rel_offset)?;
        if c.len() < 0x4C || &c[0..2] != b"nk" {
            return Err(CoreError::ProtocolError("not an nk cell".into()));
        }
        let flags = rd_u16(c, 0x02)?;
        let subkey_count = rd_u32(c, 0x14)?;
        let subkeys_list_offset = rd_u32(c, 0x1C)?;
        let value_count = rd_u32(c, 0x24)?;
        let values_list_offset = rd_u32(c, 0x28)?;
        let class_offset = rd_u32(c, 0x30)?;
        let name_len = rd_u16(c, 0x48)? as usize;
        let class_length = rd_u16(c, 0x4A)?;
        let name_bytes = c
            .get(0x4C..0x4C + name_len)
            .ok_or(CoreError::BufferUnderflow { needed: 0x4C + name_len, available: c.len() })?;
        let name = decode_name(name_bytes, flags & 0x0020 != 0);
        Ok(Nk {
            name,
            subkey_count,
            subkeys_list_offset,
            value_count,
            values_list_offset,
            class_offset,
            class_length,
        })
    }

    pub fn root(&self) -> Result<Nk, CoreError> {
        self.parse_nk(self.root_offset)
    }

    /// Collects the offsets of all subkeys referenced by a subkey list cell (`lf`/`lh`/`li`/`ri`).
    fn subkey_offsets(&self, list_offset: u32, out: &mut Vec<u32>) -> Result<(), CoreError> {
        if list_offset == 0xFFFF_FFFF || list_offset == 0 {
            return Ok(());
        }
        let c = self.cell(list_offset)?;
        if c.len() < 4 {
            return Ok(());
        }
        let sig = &c[0..2];
        let count = rd_u16(c, 0x02)? as usize;
        match sig {
            b"lf" | b"lh" => {
                for i in 0..count {
                    let base = 4 + i * 8;
                    out.push(rd_u32(c, base)?);
                }
            }
            b"li" => {
                for i in 0..count {
                    out.push(rd_u32(c, 4 + i * 4)?);
                }
            }
            b"ri" => {
                for i in 0..count {
                    let sub = rd_u32(c, 4 + i * 4)?;
                    self.subkey_offsets(sub, out)?;
                }
            }
            _ => return Err(CoreError::ProtocolError("unknown subkey list signature".into())),
        }
        Ok(())
    }

    /// Lists a key's immediate subkeys.
    pub fn subkeys(&self, nk: &Nk) -> Result<Vec<Nk>, CoreError> {
        let mut offs = Vec::new();
        self.subkey_offsets(nk.subkeys_list_offset, &mut offs)?;
        let mut out = Vec::with_capacity(offs.len());
        for o in offs {
            if let Ok(child) = self.parse_nk(o) {
                out.push(child);
            }
        }
        Ok(out)
    }

    /// Finds a direct child subkey by name (case-insensitive).
    pub fn find_subkey(&self, nk: &Nk, name: &str) -> Result<Option<Nk>, CoreError> {
        for child in self.subkeys(nk)? {
            if child.name.eq_ignore_ascii_case(name) {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    /// Navigates a key path from the given start node (e.g. `["Control", "Lsa", "JD"]`).
    pub fn navigate(&self, start: &Nk, path: &[&str]) -> Result<Option<Nk>, CoreError> {
        let mut cur = start.clone();
        for part in path {
            match self.find_subkey(&cur, part)? {
                Some(next) => cur = next,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// Reads a key's class-name string (UTF-16LE). SYSTEM `Lsa\{JD,Skew1,GBG,Data}` store bootkey
    /// nibbles here.
    pub fn class_name(&self, nk: &Nk) -> Result<String, CoreError> {
        if nk.class_length == 0 || nk.class_offset == 0xFFFF_FFFF {
            return Ok(String::new());
        }
        let c = self.cell(nk.class_offset)?;
        let bytes = c
            .get(0..nk.class_length as usize)
            .ok_or(CoreError::BufferUnderflow { needed: nk.class_length as usize, available: c.len() })?;
        Ok(decode_name(bytes, false))
    }

    /// Reads all values of a key.
    pub fn values(&self, nk: &Nk) -> Result<Vec<Vk>, CoreError> {
        if nk.value_count == 0 || nk.values_list_offset == 0xFFFF_FFFF {
            return Ok(Vec::new());
        }
        let list = self.cell(nk.values_list_offset)?;
        let mut out = Vec::with_capacity(nk.value_count as usize);
        for i in 0..nk.value_count as usize {
            let vk_off = rd_u32(list, i * 4)?;
            if let Ok(vk) = self.parse_vk(vk_off) {
                out.push(vk);
            }
        }
        Ok(out)
    }

    /// Reads a single named value of a key (case-insensitive; `""` = the default value).
    pub fn get_value(&self, nk: &Nk, name: &str) -> Result<Option<Vk>, CoreError> {
        for v in self.values(nk)? {
            if v.name.eq_ignore_ascii_case(name) {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    fn parse_vk(&self, rel_offset: u32) -> Result<Vk, CoreError> {
        let c = self.cell(rel_offset)?;
        if c.len() < 0x14 || &c[0..2] != b"vk" {
            return Err(CoreError::ProtocolError("not a vk cell".into()));
        }
        let name_len = rd_u16(c, 0x02)? as usize;
        let data_len_raw = rd_u32(c, 0x04)?;
        let data_offset = rd_u32(c, 0x08)?;
        let data_type = rd_u32(c, 0x0C)?;
        let flags = rd_u16(c, 0x10)?;
        let name_bytes = c.get(0x14..0x14 + name_len).unwrap_or(&[]);
        let name = decode_name(name_bytes, flags & 0x0001 != 0);

        let inline = data_len_raw & 0x8000_0000 != 0;
        let data_len = (data_len_raw & 0x7FFF_FFFF) as usize;
        let data = if inline {
            // Data (<= 4 bytes) stored directly in the data_offset field.
            data_offset.to_le_bytes()[..data_len.min(4)].to_vec()
        } else if data_len == 0 {
            Vec::new()
        } else {
            let cell = self.cell(data_offset)?;
            cell.get(0..data_len)
                .ok_or(CoreError::BufferUnderflow { needed: data_len, available: cell.len() })?
                .to_vec()
        };
        Ok(Vk { name, data_type, data })
    }

    /// Returns the absolute byte offset and length of a value's data payload within the hive byte slice.
    pub fn get_value_data_location(
        &self,
        nk: &Nk,
        name: &str,
    ) -> Result<Option<(usize, usize)>, CoreError> {
        if nk.value_count == 0 || nk.values_list_offset == 0xFFFF_FFFF {
            return Ok(None);
        }
        let list = self.cell(nk.values_list_offset)?;
        for i in 0..nk.value_count as usize {
            let vk_off = rd_u32(list, i * 4)?;
            let c = self.cell(vk_off)?;
            if c.len() < 0x14 || &c[0..2] != b"vk" {
                continue;
            }
            let name_len = rd_u16(c, 0x02)? as usize;
            let data_len_raw = rd_u32(c, 0x04)?;
            let data_offset = rd_u32(c, 0x08)?;
            let flags = rd_u16(c, 0x10)?;
            let name_bytes = c.get(0x14..0x14 + name_len).unwrap_or(&[]);
            let v_name = decode_name(name_bytes, flags & 0x0001 != 0);
            if v_name.eq_ignore_ascii_case(name) {
                let inline = data_len_raw & 0x8000_0000 != 0;
                let data_len = (data_len_raw & 0x7FFF_FFFF) as usize;
                if inline {
                    let abs = HBIN_BASE + vk_off as usize + 4 + 8;
                    return Ok(Some((abs, data_len.min(4))));
                } else if data_len == 0 {
                    return Ok(Some((0, 0)));
                } else {
                    let abs = HBIN_BASE + data_offset as usize + 4;
                    return Ok(Some((abs, data_len)));
                }
            }
        }
        Ok(None)
    }
}

/// Updates the Windows registry base block XOR checksum at offset `0x1FC` (`MS-RRP`).
pub fn update_hive_checksum(hive_bytes: &mut [u8]) {
    if hive_bytes.len() < 0x200 || &hive_bytes[0..4] != b"regf" {
        return;
    }
    let mut sum: u32 = 0;
    for chunk in hive_bytes[0..0x1FC].chunks_exact(4) {
        sum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    hive_bytes[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid hive: root key "ROOT" with one subkey "Sub" (class "DEADBEEF") that holds
    /// one REG_BINARY value "Val" = [0xDE,0xAD]. Exercises base block, nk, lf, vk (out-of-line), class.
    fn build_hive() -> Vec<u8> {
        // Layout within the hbin (offsets relative to 0x1000):
        //   0x00: root nk
        //   0x80: subkey nk ("Sub")
        //   0x100: lf list (1 entry -> 0x80)
        //   0x140: class cell ("DEADBEEF" utf16)
        //   0x180: value-list cell (1 u32 -> 0x1C0)
        //   0x1C0: vk cell ("Val")
        //   0x200: value data cell ([0xDE,0xAD])
        let mut hbin = vec![0u8; 0x400];

        let put_u32 = |h: &mut [u8], at: usize, v: u32| h[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put_u16 = |h: &mut [u8], at: usize, v: u16| h[at..at + 2].copy_from_slice(&v.to_le_bytes());
        let put_i32 = |h: &mut [u8], at: usize, v: i32| h[at..at + 4].copy_from_slice(&v.to_le_bytes());

        // root nk @0x00
        put_i32(&mut hbin, 0x00, -0x60);
        hbin[0x04..0x06].copy_from_slice(b"nk");
        put_u16(&mut hbin, 0x06, 0x0020); // KEY_COMP_NAME (ASCII name)
        put_u32(&mut hbin, 0x04 + 0x14, 1); // subkey_count
        put_u32(&mut hbin, 0x04 + 0x1C, 0x100); // subkeys_list_offset -> lf
        put_u32(&mut hbin, 0x04 + 0x24, 0); // value_count
        put_u32(&mut hbin, 0x04 + 0x28, 0xFFFF_FFFF); // values_list_offset
        put_u32(&mut hbin, 0x04 + 0x30, 0xFFFF_FFFF); // class_offset
        put_u16(&mut hbin, 0x04 + 0x48, 4); // name_len
        put_u16(&mut hbin, 0x04 + 0x4A, 0); // class_len
        hbin[0x04 + 0x4C..0x04 + 0x4C + 4].copy_from_slice(b"ROOT");

        // subkey nk @0x80 ("Sub", class "DEADBEEF")
        put_i32(&mut hbin, 0x80, -0x60);
        hbin[0x84..0x86].copy_from_slice(b"nk");
        put_u16(&mut hbin, 0x86, 0x0020);
        put_u32(&mut hbin, 0x84 + 0x14, 0); // subkey_count
        put_u32(&mut hbin, 0x84 + 0x1C, 0xFFFF_FFFF);
        put_u32(&mut hbin, 0x84 + 0x24, 1); // value_count
        put_u32(&mut hbin, 0x84 + 0x28, 0x180); // values_list_offset
        put_u32(&mut hbin, 0x84 + 0x30, 0x140); // class_offset
        put_u16(&mut hbin, 0x84 + 0x48, 3); // name_len "Sub"
        put_u16(&mut hbin, 0x84 + 0x4A, 16); // class_len = 8 utf16 units * 2
        hbin[0x84 + 0x4C..0x84 + 0x4C + 3].copy_from_slice(b"Sub");

        // lf list @0x100
        put_i32(&mut hbin, 0x100, -0x18);
        hbin[0x104..0x106].copy_from_slice(b"lf");
        put_u16(&mut hbin, 0x106, 1); // count
        put_u32(&mut hbin, 0x108, 0x80); // entry offset -> subkey nk
        put_u32(&mut hbin, 0x10C, 0); // hash

        // class cell @0x140 ("DEADBEEF" utf16le)
        put_i32(&mut hbin, 0x140, -0x18);
        for (i, ch) in "DEADBEEF".encode_utf16().enumerate() {
            hbin[0x144 + i * 2..0x144 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }

        // value-list @0x180 (1 u32 -> 0x1C0)
        put_i32(&mut hbin, 0x180, -0x08);
        put_u32(&mut hbin, 0x184, 0x1C0);

        // vk @0x1C0 ("Val", REG_BINARY, data @0x200 len 2)
        put_i32(&mut hbin, 0x1C0, -0x20);
        hbin[0x1C4..0x1C6].copy_from_slice(b"vk");
        put_u16(&mut hbin, 0x1C6, 3); // name_len "Val"
        put_u32(&mut hbin, 0x1C8, 2); // data_len
        put_u32(&mut hbin, 0x1CC, 0x200); // data_offset
        put_u32(&mut hbin, 0x1D0, 3); // REG_BINARY
        put_u16(&mut hbin, 0x1D4, 0x0001); // ASCII name
        hbin[0x1D8..0x1D8 + 3].copy_from_slice(b"Val");

        // data cell @0x200
        put_i32(&mut hbin, 0x200, -0x08);
        hbin[0x204] = 0xDE;
        hbin[0x205] = 0xAD;

        // Assemble: 0x1000 base block (root offset @0x24 = 0) + hbin.
        let mut file = vec![0u8; 0x1000];
        file[0..4].copy_from_slice(b"regf");
        file[0x24..0x28].copy_from_slice(&0u32.to_le_bytes()); // root cell offset = 0
        file.extend_from_slice(&hbin);
        file
    }

    #[test]
    fn test_regf_navigate_class_and_value() {
        let data = build_hive();
        let hive = Hive::new(&data).unwrap();
        let root = hive.root().unwrap();
        assert_eq!(root.name, "ROOT");
        assert_eq!(root.subkey_count, 1);

        let sub = hive.find_subkey(&root, "sub").unwrap().unwrap();
        assert_eq!(sub.name, "Sub");
        assert_eq!(hive.class_name(&sub).unwrap(), "DEADBEEF");

        let v = hive.get_value(&sub, "VAL").unwrap().unwrap();
        assert_eq!(v.data_type, 3);
        assert_eq!(v.data, vec![0xDE, 0xAD]);

        assert!(hive.navigate(&root, &["Sub"]).unwrap().is_some());
        assert!(hive.navigate(&root, &["Nope"]).unwrap().is_none());
    }
}

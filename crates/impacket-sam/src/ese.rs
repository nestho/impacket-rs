//! Pure-Rust Extensible Storage Engine (ESENT / JET Blue) offline database parser.
//!
//! Implements offline reading of Microsoft Active Directory databases (`NTDS.dit`)
//! and Windows search / exchange catalog databases without native Windows DLLs.
//!
//! Reference:
//! - Joachim Metz, "Extensible Storage Engine (ESE) Database File (EDB) Format"
//! - Microsoft [MS-ESE] specifications

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use impacket_core::CoreError;

pub const ESE_SIGNATURE: u32 = 0x89ab_cdef;

// Page flags
pub const FLAGS_ROOT: u32 = 0x0001;
pub const FLAGS_LEAF: u32 = 0x0002;
pub const FLAGS_PARENT: u32 = 0x0004;
pub const FLAGS_EMPTY: u32 = 0x0008;
pub const FLAGS_SPACE_TREE: u32 = 0x0020;
pub const FLAGS_INDEX: u32 = 0x0040;
pub const FLAGS_LONG_VALUE: u32 = 0x0080;

// Tag flags
pub const TAG_UNKNOWN: u16 = 0x0001;
pub const TAG_DEFUNCT: u16 = 0x0002;
pub const TAG_COMMON: u16 = 0x0004;

// Catalog Types
pub const CATALOG_TYPE_TABLE: u16 = 1;
pub const CATALOG_TYPE_COLUMN: u16 = 2;
pub const CATALOG_TYPE_INDEX: u16 = 3;
pub const CATALOG_TYPE_LONG_VALUE: u16 = 4;
pub const CATALOG_TYPE_CALLBACK: u16 = 5;

// Column Types (JET_coltyp)
pub const JET_COLTYP_NIL: u32 = 0;
pub const JET_COLTYP_BIT: u32 = 1;
pub const JET_COLTYP_UNSIGNED_BYTE: u32 = 2;
pub const JET_COLTYP_SHORT: u32 = 3;
pub const JET_COLTYP_LONG: u32 = 4;
pub const JET_COLTYP_CURRENCY: u32 = 5;
pub const JET_COLTYP_IEEESINGLE: u32 = 6;
pub const JET_COLTYP_IEEEDOUBLE: u32 = 7;
pub const JET_COLTYP_DATETIME: u32 = 8;
pub const JET_COLTYP_BINARY: u32 = 9;
pub const JET_COLTYP_TEXT: u32 = 10;
pub const JET_COLTYP_LONG_BINARY: u32 = 11;
pub const JET_COLTYP_LONG_TEXT: u32 = 12;
pub const JET_COLTYP_SLV: u32 = 13;
pub const JET_COLTYP_UNSIGNED_LONG: u32 = 14;
pub const JET_COLTYP_LONGLONG: u32 = 15;
pub const JET_COLTYP_GUID: u32 = 16;
pub const JET_COLTYP_UNSIGNED_SHORT: u32 = 17;

// Tagged Data Type Flags
pub const TAGGED_DATA_TYPE_VARIABLE_SIZE: u8 = 1;
pub const TAGGED_DATA_TYPE_COMPRESSED: u8 = 2;
pub const TAGGED_DATA_TYPE_STORED: u8 = 4;
pub const TAGGED_DATA_TYPE_MULTI_VALUE: u8 = 8;

pub const CATALOG_PAGE_NUMBER: u32 = 4;
pub const CATALOG_BACKUP_PAGE_NUMBER: u32 = 24;

/// Parsed ESE Database header (Page 0).
#[derive(Debug, Clone)]
pub struct EseDbHeader {
    pub checksum: u32,
    pub signature: u32,
    pub version: u32,
    pub file_type: u32,
    pub db_time: u64,
    pub db_state: u32,
    pub file_format_revision: u32,
    pub page_size: usize,
}

impl EseDbHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() < 224 {
            return Err(CoreError::ProtocolError("ESE DB header too small".into()));
        }
        let signature = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if signature != ESE_SIGNATURE {
            return Err(CoreError::ProtocolError(format!(
                "invalid ESE signature 0x{:08x}, expected 0x{:08x}",
                signature, ESE_SIGNATURE
            )));
        }
        let checksum = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let file_type = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let db_time = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let db_state = u32::from_le_bytes(buf[52..56].try_into().unwrap());

        let file_format_revision = u32::from_le_bytes(buf[216..220].try_into().unwrap());
        let mut page_size = u32::from_le_bytes(buf[220..224].try_into().unwrap()) as usize;
        if page_size == 0 {
            page_size = 4096;
        }

        Ok(Self {
            checksum,
            signature,
            version,
            file_type,
            db_time,
            db_state,
            file_format_revision,
            page_size,
        })
    }
}

/// Parsed page header for an ESE database page.
#[derive(Debug, Clone)]
pub struct EsePageHeader {
    pub checksum: u64,
    pub last_modification_time: u64,
    pub previous_page_number: u32,
    pub next_page_number: u32,
    pub father_data_page: u32,
    pub available_data_size: u16,
    pub available_uncommitted_data_size: u16,
    pub first_available_data_offset: u16,
    pub first_available_page_tag: u16,
    pub page_flags: u32,
    pub header_size: usize,
    pub tag_count: usize,
    pub tag_reserved: usize,
    pub first_data_tag: usize,
}

impl EsePageHeader {
    pub fn parse(buf: &[u8], version: u32, revision: u32, page_size: usize) -> Result<Self, CoreError> {
        let is_old = (version < 0x620) || (version == 0x620 && revision < 0x0b);
        let is_vista = version == 0x620 && revision < 0x11;
        let is_win7_modern = !is_old && !is_vista;

        let (checksum, common_offset) = if is_old || is_vista {
            let cs = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as u64;
            (cs, 8usize)
        } else {
            let cs = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            (cs, 8usize)
        };

        if buf.len() < common_offset + 32 {
            return Err(CoreError::ProtocolError("page buffer too small for header".into()));
        }

        let p = &buf[common_offset..];
        let last_modification_time = u64::from_le_bytes(p[0..8].try_into().unwrap());
        let previous_page_number = u32::from_le_bytes(p[8..12].try_into().unwrap());
        let next_page_number = u32::from_le_bytes(p[12..16].try_into().unwrap());
        let father_data_page = u32::from_le_bytes(p[16..20].try_into().unwrap());
        let available_data_size = u16::from_le_bytes(p[20..22].try_into().unwrap());
        let available_uncommitted_data_size = u16::from_le_bytes(p[22..24].try_into().unwrap());
        let first_available_data_offset = u16::from_le_bytes(p[24..26].try_into().unwrap());
        let first_available_page_tag = u16::from_le_bytes(p[26..28].try_into().unwrap());
        let page_flags = u32::from_le_bytes(p[28..32].try_into().unwrap());

        let mut header_size = common_offset + 32;
        if is_win7_modern && page_size > 8192 {
            header_size += 40;
        }

        let (tag_count, tag_reserved) = if version == 0x620 && revision >= 0x11 && page_size > 8192 {
            let reserved = (first_available_page_tag >> 12) as usize;
            let count = (first_available_page_tag & 0x0fff) as usize;
            (count, if reserved == 0 { 1 } else { reserved })
        } else {
            (first_available_page_tag as usize, 1usize)
        };
        let first_data_tag = std::cmp::min(tag_reserved, tag_count);

        Ok(Self {
            checksum,
            last_modification_time,
            previous_page_number,
            next_page_number,
            father_data_page,
            available_data_size,
            available_uncommitted_data_size,
            first_available_data_offset,
            first_available_page_tag,
            page_flags,
            header_size,
            tag_count,
            tag_reserved,
            first_data_tag,
        })
    }
}

/// Decoded tag data item from an ESE page.
#[derive(Debug, Clone)]
pub struct EseTag {
    pub flags: u16,
    pub offset: usize,
    pub size: usize,
    pub data: Vec<u8>,
}

/// Catalog entry describing a table column.
#[derive(Debug, Clone)]
pub struct EseColumn {
    pub name: String,
    pub identifier: u32,
    pub column_type: u32,
    pub space_usage: usize,
    pub column_flags: u32,
    pub code_page: u32,
}

/// Catalog entry describing a table.
#[derive(Debug, Clone)]
pub struct EseTableDef {
    pub name: String,
    pub father_data_page_number: u32,
    pub columns: BTreeMap<String, EseColumn>,
    pub columns_by_id: BTreeMap<u32, EseColumn>,
}

/// Value stored in an ESE database record column.
#[derive(Debug, Clone, PartialEq)]
pub enum EseValue {
    Nil,
    Bit(bool),
    Byte(u8),
    Short(i16),
    UShort(u16),
    Long(i32),
    ULong(u32),
    LongLong(i64),
    DateTime(u64),
    Guid([u8; 16]),
    Text(String),
    Binary(Vec<u8>),
}

impl EseValue {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            EseValue::Binary(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            EseValue::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            EseValue::ULong(v) => Some(*v),
            EseValue::Long(v) => Some(*v as u32),
            EseValue::UShort(v) => Some(*v as u32),
            EseValue::Byte(v) => Some(*v as u32),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            EseValue::DateTime(v) => Some(*v),
            EseValue::LongLong(v) => Some(*v as u64),
            EseValue::ULong(v) => Some(*v as u64),
            _ => None,
        }
    }
}

/// A parsed record row mapping column name to value.
pub type EseRecord = BTreeMap<String, EseValue>;

/// ESE Database reader.
pub struct EseDatabase<R> {
    reader: R,
    header: EseDbHeader,
    tables: BTreeMap<String, EseTableDef>,
}

impl<R: Read + Seek> EseDatabase<R> {
    pub fn open(mut reader: R) -> Result<Self, CoreError> {
        reader.seek(SeekFrom::Start(0))?;
        let mut header_buf = [0u8; 4096];
        reader.read_exact(&mut header_buf)?;
        let header = EseDbHeader::parse(&header_buf)?;

        let mut db = Self {
            reader,
            header,
            tables: BTreeMap::new(),
        };

        db.parse_catalog(CATALOG_PAGE_NUMBER)?;
        Ok(db)
    }

    pub fn header(&self) -> &EseDbHeader {
        &self.header
    }

    pub fn tables(&self) -> &BTreeMap<String, EseTableDef> {
        &self.tables
    }

    pub fn get_table(&self, name: &str) -> Option<&EseTableDef> {
        self.tables.get(name)
    }

    pub fn read_page(&mut self, page_num: u32) -> Result<(EsePageHeader, Vec<u8>), CoreError> {
        let offset = ((page_num as u64) + 1) * (self.header.page_size as u64);
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; self.header.page_size];
        self.reader.read_exact(&mut buf)?;
        let hdr = EsePageHeader::parse(
            &buf,
            self.header.version,
            self.header.file_format_revision,
            self.header.page_size,
        )?;
        Ok((hdr, buf))
    }

    pub fn read_page_tags(&self, hdr: &EsePageHeader, page_buf: &[u8]) -> Vec<EseTag> {
        let mut tags = Vec::with_capacity(hdr.tag_count);
        let base_offset = hdr.header_size;
        let is_modern = self.header.version == 0x620
            && self.header.file_format_revision >= 17
            && self.header.page_size > 8192;

        let tag_array_start = page_buf.len() - 4 * hdr.tag_count;

        for i in 0..hdr.tag_count {
            let offset = tag_array_start + i * 4;
            if offset + 4 > page_buf.len() {
                break;
            }
            let raw_tag = &page_buf[offset..offset + 4];
            let raw0 = u16::from_le_bytes([raw_tag[0], raw_tag[1]]);
            let raw1 = u16::from_le_bytes([raw_tag[2], raw_tag[3]]);

            let (value_size, value_offset, tag_flags) = if is_modern {
                let size = (raw0 & 0x7fff) as usize;
                let off = (raw1 & 0x7fff) as usize;
                (size, off, 0u16)
            } else {
                let size = (raw0 & 0x1fff) as usize;
                let flags = (raw1 & 0xe000) >> 13;
                let off = (raw1 & 0x1fff) as usize;
                (size, off, flags)
            };

            let data_start = base_offset + value_offset;
            let data_end = (data_start + value_size).min(page_buf.len());
            let mut data = if data_start < page_buf.len() {
                page_buf[data_start..data_end].to_vec()
            } else {
                Vec::new()
            };

            let final_flags = if is_modern && data.len() > 1 {
                let f = (data[1] >> 5) as u16;
                data[1] &= 0x1f;
                f
            } else {
                tag_flags
            };

            tags.push(EseTag {
                flags: final_flags,
                offset: value_offset,
                size: value_size,
                data,
            });
        }
        tags
    }

    fn parse_catalog(&mut self, page_num: u32) -> Result<(), CoreError> {
        let (hdr, buf) = self.read_page(page_num)?;
        let tags = self.read_page_tags(&hdr, &buf);

        if (hdr.page_flags & FLAGS_LEAF) != 0 {
            // Leaf page: parse catalog items
            let mut current_table: Option<String> = None;

            for tag_idx in hdr.first_data_tag..hdr.tag_count {
                if tag_idx >= tags.len() {
                    break;
                }
                let tag = &tags[tag_idx];
                let entry_data = Self::extract_leaf_entry_data(tag.flags, &tag.data);
                if entry_data.len() < 16 {
                    continue;
                }

                let last_var = entry_data[1];
                let var_offset = u16::from_le_bytes([entry_data[2], entry_data[3]]) as usize;
                let num_entries = if last_var > 127 { (last_var - 127) as usize } else { last_var as usize };

                if var_offset + 2 > entry_data.len() {
                    continue;
                }
                let item_len = u16::from_le_bytes([entry_data[var_offset], entry_data[var_offset + 1]]) as usize;
                let name_start = var_offset + 2 * num_entries;
                let name_end = (name_start + item_len).min(entry_data.len());
                let item_name = if name_start < entry_data.len() {
                    String::from_utf8_lossy(&entry_data[name_start..name_end]).to_string()
                } else {
                    continue;
                };

                // Fixed catalog metadata is at offset 4
                let catalog_data = &entry_data[4..];
                if catalog_data.len() < 10 {
                    continue;
                }
                let cat_type = u16::from_le_bytes([catalog_data[4], catalog_data[5]]);
                let identifier = u32::from_le_bytes(catalog_data[6..10].try_into().unwrap());

                match cat_type {
                    CATALOG_TYPE_TABLE => {
                        let fdp_number = if catalog_data.len() >= 14 {
                            u32::from_le_bytes(catalog_data[10..14].try_into().unwrap())
                        } else {
                            0
                        };
                        let tdef = EseTableDef {
                            name: item_name.clone(),
                            father_data_page_number: fdp_number,
                            columns: BTreeMap::new(),
                            columns_by_id: BTreeMap::new(),
                        };
                        self.tables.insert(item_name.clone(), tdef);
                        current_table = Some(item_name);
                    }
                    CATALOG_TYPE_COLUMN => {
                        if let Some(tname) = &current_table {
                            if let Some(table) = self.tables.get_mut(tname) {
                                let col_type = if catalog_data.len() >= 14 {
                                    u32::from_le_bytes(catalog_data[10..14].try_into().unwrap())
                                } else {
                                    0
                                };
                                let space_usage = if catalog_data.len() >= 18 {
                                    u32::from_le_bytes(catalog_data[14..18].try_into().unwrap()) as usize
                                } else {
                                    0
                                };
                                let col_flags = if catalog_data.len() >= 22 {
                                    u32::from_le_bytes(catalog_data[18..22].try_into().unwrap())
                                } else {
                                    0
                                };
                                let code_page = if catalog_data.len() >= 26 {
                                    u32::from_le_bytes(catalog_data[22..26].try_into().unwrap())
                                } else {
                                    0
                                };

                                let col = EseColumn {
                                    name: item_name.clone(),
                                    identifier,
                                    column_type: col_type,
                                    space_usage,
                                    column_flags: col_flags,
                                    code_page,
                                };
                                table.columns_by_id.insert(identifier, col.clone());
                                table.columns.insert(item_name, col);
                            }
                        }
                    }
                    _ => {}
                }
            }
        } else {
            // Branch page: recurse into children
            for tag_idx in hdr.first_data_tag..hdr.tag_count {
                if tag_idx >= tags.len() {
                    break;
                }
                let tag = &tags[tag_idx];
                if let Some(child_page) = Self::extract_branch_child(tag.flags, &tag.data) {
                    if child_page != 0 {
                        let _ = self.parse_catalog(child_page);
                    }
                }
            }
        }

        Ok(())
    }

    fn extract_leaf_entry_data<'a>(flags: u16, data: &'a [u8]) -> &'a [u8] {
        let mut cursor = 0;
        if (flags & TAG_COMMON) != 0 && data.len() >= 2 {
            cursor += 2;
        }
        if cursor + 2 > data.len() {
            return &[];
        }
        let local_key_size = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2 + local_key_size;
        if cursor < data.len() {
            &data[cursor..]
        } else {
            &[]
        }
    }

    fn extract_branch_child(flags: u16, data: &[u8]) -> Option<u32> {
        let mut cursor = 0;
        if (flags & TAG_COMMON) != 0 && data.len() >= 2 {
            cursor += 2;
        }
        if cursor + 2 > data.len() {
            return None;
        }
        let local_key_size = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2 + local_key_size;
        if cursor + 4 <= data.len() {
            Some(u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Read all rows of a specified table by name.
    pub fn read_table_records(&mut self, table_name: &str) -> Result<Vec<EseRecord>, CoreError> {
        let table_def = match self.tables.get(table_name) {
            Some(t) => t.clone(),
            None => {
                return Err(CoreError::ProtocolError(format!(
                    "table {} not found in catalog",
                    table_name
                )))
            }
        };

        // Navigate to the leftmost leaf page of the table B-tree
        let mut page_num = table_def.father_data_page_number;
        let mut visited = std::collections::BTreeSet::new();

        loop {
            if visited.contains(&page_num) || page_num == 0 {
                break;
            }
            visited.insert(page_num);

            let (hdr, buf) = self.read_page(page_num)?;
            if (hdr.page_flags & FLAGS_LEAF) != 0 {
                break;
            }
            let tags = self.read_page_tags(&hdr, &buf);
            let mut next_child = None;
            for tag_idx in hdr.first_data_tag..hdr.tag_count {
                if tag_idx < tags.len() {
                    if let Some(child) = Self::extract_branch_child(tags[tag_idx].flags, &tags[tag_idx].data) {
                        if child != 0 {
                            next_child = Some(child);
                            break;
                        }
                    }
                }
            }
            match next_child {
                Some(c) => page_num = c,
                None => break,
            }
        }

        // Now iterate sequentially through leaf pages using next_page_number
        let mut records = Vec::new();
        let mut current_page = page_num;
        let mut visited_leafs = std::collections::BTreeSet::new();

        while current_page != 0 && !visited_leafs.contains(&current_page) {
            visited_leafs.insert(current_page);
            let (hdr, buf) = self.read_page(current_page)?;
            let tags = self.read_page_tags(&hdr, &buf);

            if (hdr.page_flags & FLAGS_LEAF) != 0 {
                for tag_idx in hdr.first_data_tag..hdr.tag_count {
                    if tag_idx < tags.len() {
                        let entry_data = Self::extract_leaf_entry_data(tags[tag_idx].flags, &tags[tag_idx].data);
                        if let Some(record) = Self::decode_record(&table_def, entry_data, self.header.page_size) {
                            records.push(record);
                        }
                    }
                }
            }

            current_page = hdr.next_page_number;
        }

        Ok(records)
    }

    /// Decode raw entry data of a record into structured column values.
    pub fn decode_record(table: &EseTableDef, tag: &[u8], page_size: usize) -> Option<EseRecord> {
        if tag.len() < 4 {
            return None;
        }

        let last_fixed = tag[0] as u32;
        let last_var = tag[1] as u32;
        let var_offset = u16::from_le_bytes([tag[2], tag[3]]) as usize;

        let mut fixed_offset = 4usize;
        let mut var_bytes_processed = if last_var > 127 { (last_var - 127) as usize * 2 } else { 0 };
        let mut prev_item_len = 0usize;

        // Parse tagged items if present
        let mut tagged_items: BTreeMap<u32, (usize, usize, bool)> = BTreeMap::new();
        let tag_len = tag.len();
        if (var_offset + var_bytes_processed) < tag_len {
            let mut idx = var_offset + var_bytes_processed;
            if idx + 4 <= tag_len {
                let first_tagged_offset = (u16::from_le_bytes([tag[idx + 2], tag[idx + 3]]) & 0x3fff) as usize
                    + var_offset + var_bytes_processed;
                let mut offsets = Vec::new();

                while idx + 4 <= tag_len && idx < first_tagged_offset {
                    let tid = u16::from_le_bytes([tag[idx], tag[idx + 1]]) as u32;
                    let raw_off = u16::from_le_bytes([tag[idx + 2], tag[idx + 3]]);
                    let toff = (raw_off & 0x3fff) as usize;
                    let flags_present = (raw_off & 0x4000) != 0 || page_size > 8192;
                    offsets.push((tid, toff, flags_present));
                    idx += 4;
                }

                for i in 0..offsets.len() {
                    let (tid, toff, f_pres) = offsets[i];
                    let tlen = if i + 1 < offsets.len() {
                        offsets[i + 1].1.saturating_sub(toff)
                    } else {
                        tag_len.saturating_sub(var_offset + var_bytes_processed + toff)
                    };
                    tagged_items.insert(tid, (toff, tlen, f_pres));
                }
            }
        }

        let mut record = EseRecord::new();

        for (col_name, col) in &table.columns {
            let id = col.identifier;

            if id <= last_fixed {
                // Fixed size column
                if fixed_offset + col.space_usage <= tag.len() {
                    let raw = &tag[fixed_offset..fixed_offset + col.space_usage];
                    record.insert(col_name.clone(), Self::unpack_value(col, raw));
                    fixed_offset += col.space_usage;
                } else {
                    record.insert(col_name.clone(), EseValue::Nil);
                }
            } else if id > 127 && id <= last_var {
                // Variable size column
                let var_idx = (id - 127 - 1) as usize;
                let entry_off = var_offset + var_idx * 2;
                if entry_off + 2 <= tag.len() {
                    let raw_len = u16::from_le_bytes([tag[entry_off], tag[entry_off + 1]]);
                    if (raw_len & 0x8000) != 0 {
                        // Empty / null item
                        record.insert(col_name.clone(), EseValue::Nil);
                    } else {
                        let item_len = raw_len as usize;
                        let val_len = item_len.saturating_sub(prev_item_len);
                        let val_start = var_offset + var_bytes_processed;
                        let val_end = (val_start + val_len).min(tag.len());
                        if val_start < tag.len() {
                            let raw = &tag[val_start..val_end];
                            record.insert(col_name.clone(), Self::unpack_value(col, raw));
                        } else {
                            record.insert(col_name.clone(), EseValue::Nil);
                        }
                        var_bytes_processed += val_len;
                        prev_item_len = item_len;
                    }
                } else {
                    record.insert(col_name.clone(), EseValue::Nil);
                }
            } else if id > 255 {
                // Tagged column
                if let Some(&(toff, tlen, f_pres)) = tagged_items.get(&id) {
                    let mut item_start = var_offset + var_bytes_processed + toff;
                    let mut item_size = tlen;
                    if f_pres && item_start < tag.len() {
                        let _item_flag = tag[item_start];
                        item_start += 1;
                        item_size = item_size.saturating_sub(1);
                    }
                    let item_end = (item_start + item_size).min(tag.len());
                    if item_start < tag.len() {
                        let raw = &tag[item_start..item_end];
                        record.insert(col_name.clone(), Self::unpack_value(col, raw));
                    } else {
                        record.insert(col_name.clone(), EseValue::Nil);
                    }
                } else {
                    record.insert(col_name.clone(), EseValue::Nil);
                }
            } else {
                record.insert(col_name.clone(), EseValue::Nil);
            }
        }

        Some(record)
    }

    fn unpack_value(col: &EseColumn, raw: &[u8]) -> EseValue {
        match col.column_type {
            JET_COLTYP_BIT => EseValue::Bit(!raw.is_empty() && raw[0] != 0),
            JET_COLTYP_UNSIGNED_BYTE => EseValue::Byte(if !raw.is_empty() { raw[0] } else { 0 }),
            JET_COLTYP_SHORT => {
                if raw.len() >= 2 {
                    EseValue::Short(i16::from_le_bytes([raw[0], raw[1]]))
                } else {
                    EseValue::Short(0)
                }
            }
            JET_COLTYP_UNSIGNED_SHORT => {
                if raw.len() >= 2 {
                    EseValue::UShort(u16::from_le_bytes([raw[0], raw[1]]))
                } else {
                    EseValue::UShort(0)
                }
            }
            JET_COLTYP_LONG => {
                if raw.len() >= 4 {
                    EseValue::Long(i32::from_le_bytes(raw[0..4].try_into().unwrap()))
                } else {
                    EseValue::Long(0)
                }
            }
            JET_COLTYP_UNSIGNED_LONG => {
                if raw.len() >= 4 {
                    EseValue::ULong(u32::from_le_bytes(raw[0..4].try_into().unwrap()))
                } else {
                    EseValue::ULong(0)
                }
            }
            JET_COLTYP_LONGLONG | JET_COLTYP_CURRENCY => {
                if raw.len() >= 8 {
                    EseValue::LongLong(i64::from_le_bytes(raw[0..8].try_into().unwrap()))
                } else {
                    EseValue::LongLong(0)
                }
            }
            JET_COLTYP_DATETIME => {
                if raw.len() >= 8 {
                    EseValue::DateTime(u64::from_le_bytes(raw[0..8].try_into().unwrap()))
                } else {
                    EseValue::DateTime(0)
                }
            }
            JET_COLTYP_GUID => {
                let mut g = [0u8; 16];
                let take = raw.len().min(16);
                g[..take].copy_from_slice(&raw[..take]);
                EseValue::Guid(g)
            }
            JET_COLTYP_TEXT | JET_COLTYP_LONG_TEXT => {
                if col.code_page == 1200 {
                    // UTF-16LE
                    let u16s: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    EseValue::Text(String::from_utf16_lossy(&u16s))
                } else {
                    EseValue::Text(String::from_utf8_lossy(raw).to_string())
                }
            }
            _ => EseValue::Binary(raw.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ese_header_parse_valid() {
        let mut buf = vec![0u8; 4096];
        // Signature at offset 4: 0x89abcdef
        buf[4..8].copy_from_slice(&ESE_SIGNATURE.to_le_bytes());
        buf[8..12].copy_from_slice(&0x620u32.to_le_bytes()); // version
        buf[52..56].copy_from_slice(&3u32.to_le_bytes()); // CleanShutdown
        buf[216..220].copy_from_slice(&0x14u32.to_le_bytes()); // revision
        buf[220..224].copy_from_slice(&8192u32.to_le_bytes()); // page_size

        let hdr = EseDbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.signature, ESE_SIGNATURE);
        assert_eq!(hdr.version, 0x620);
        assert_eq!(hdr.file_format_revision, 0x14);
        assert_eq!(hdr.page_size, 8192);
        assert_eq!(hdr.db_state, 3);
    }

    #[test]
    fn test_ese_header_invalid_signature() {
        let buf = vec![0u8; 4096];
        assert!(EseDbHeader::parse(&buf).is_err());
    }

    #[test]
    fn test_ese_record_decoding_fixed_and_tagged() {
        let mut table = EseTableDef {
            name: "test_table".into(),
            father_data_page_number: 10,
            columns: BTreeMap::new(),
            columns_by_id: BTreeMap::new(),
        };

        let col_fixed = EseColumn {
            name: "id".into(),
            identifier: 1,
            column_type: JET_COLTYP_UNSIGNED_LONG,
            space_usage: 4,
            column_flags: 0,
            code_page: 0,
        };
        let col_tagged = EseColumn {
            name: "username".into(),
            identifier: 256,
            column_type: JET_COLTYP_TEXT,
            space_usage: 0,
            column_flags: 0,
            code_page: 1200, // UTF-16LE
        };

        table.columns_by_id.insert(1, col_fixed.clone());
        table.columns.insert("id".into(), col_fixed);
        table.columns_by_id.insert(256, col_tagged.clone());
        table.columns.insert("username".into(), col_tagged);

        // Build synthetic tag payload
        // LastFixedSize = 1, LastVariableDataType = 127, VariableSizeOffset = 8
        let mut tag = Vec::new();
        tag.push(1u8); // LastFixedSize = 1
        tag.push(127u8); // LastVariableDataType = 127 (no variable columns)
        tag.extend_from_slice(&8u16.to_le_bytes()); // VariableSizeOffset = 8

        // Fixed data: ID 1 = 4 bytes (value = 1001)
        tag.extend_from_slice(&1001u32.to_le_bytes()); // offset 4..8

        // VariableSizeOffset = 8.
        // Tagged entries array:
        // Tagged ID 256 = [256u16, tagged_offset=4 | 0x4000]
        let tagged_entry_id = 256u16;
        let tagged_offset = 4u16 | 0x4000; // flags present
        tag.extend_from_slice(&tagged_entry_id.to_le_bytes());
        tag.extend_from_slice(&tagged_offset.to_le_bytes());

        // Value data at offset 4 after tagged array (8 + 4 = 12):
        // flag byte = 0
        tag.push(0u8);
        // UTF-16LE "Admin"
        let s: Vec<u8> = "Admin".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        tag.extend_from_slice(&s);

        let rec = EseDatabase::<std::io::Cursor<Vec<u8>>>::decode_record(&table, &tag, 8192).unwrap();
        assert_eq!(rec.get("id"), Some(&EseValue::ULong(1001)));
        assert_eq!(rec.get("username"), Some(&EseValue::Text("Admin".into())));
    }
}

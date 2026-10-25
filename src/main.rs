use clap::Parser;
use serde_json::Value::Null;
use serde_json::{Map, Value, json};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ops::Deref;
use std::path::PathBuf;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fmt, println, unreachable, writeln};

use mysql_ibdinspect::read_sdi_info_from_disk;

use binlog::data0fil::{
    KnownLogEventType, LogEventType, get_fixed_column_size, ColumnTypes
};

use binlog::page::{
    BINLOG_MAGIC, BINLOG_MAGIC_SIZE, EVENT_LEN_OFFSET, EVENT_TYPE_OFFSET, FLAGS_OFFSET,
    LOG_EVENT_HEADER_LEN, LOG_POS_OFFSET, ROWS_HEADER_LEN_V2, SERVER_ID_OFFSET, ST_SERVER_VER_LEN,
    TABLE_MAP_HEADER_LEN,
};

const PAGE_SIZE: u16 = 2 << 13;

#[allow(dead_code)]
#[derive(Debug)]
enum BinError {
    InvalidValue(&'static str),
    DoesNotExist,
}

static mut DD_CACHE: Option<Map<String, Value>> = None;
static mut TABLE_MAP: Option<TableMapEventOwned> = None;
static mut DATA_DIR: Option<String> = None;
static VERBOSE: AtomicBool = AtomicBool::new(false);

fn read_data_dir() -> Result<&'static str, BinError> {
    unsafe {
        let data_dir = addr_of!(DATA_DIR);
        match (*data_dir).as_ref() {
            Some(dir) => Ok(dir),
            None => Err(BinError::InvalidValue("Table map uninitialized")),
        }
    }
}

fn set_data_dir(data_dir: String) -> Option<BinError> {
    // let ddir = data_dir.clone().as_str();
    unsafe {
        *addr_of_mut!(DATA_DIR) = Some(data_dir);
        None
    }
}

fn read_global_dd_cache(key: &str) -> Result<&'static Value, BinError> {
    unsafe {
        let dd_cache = addr_of!(DD_CACHE);
        let mut key = key.to_string();
        key.pop();

        if let Some(dd_c) = (*dd_cache).as_ref() {
            match dd_c.get(&key) {
                Some(val) => return Ok(val),
                None => return Err(BinError::DoesNotExist),
            };
        }

        return Err(BinError::InvalidValue("Data Dictionary is uninitializeddd"));
    }
}

fn update_global_dd_cache(key: String, val: Value) -> Option<BinError> {
    unsafe {
        let dd_cache = addr_of_mut!(DD_CACHE);
        let mut key = key;
        key.pop();

        match (*dd_cache).as_mut() {
            Some(dd) => {
                dd.insert(key, val);
            }
            None => {
                let mut temp = Map::new();
                temp.insert(key, val);
                *addr_of_mut!(DD_CACHE) = Some(temp);
            }
        }

        None
    }
}

fn read_global_table_map() -> Result<TableMapEventOwned, BinError> {
    unsafe {
        let table_map = addr_of!(TABLE_MAP);
        match (*table_map).as_ref() {
            Some(tmap) => Ok(tmap.clone()),
            None => Err(BinError::InvalidValue("Table map uninitialized")),
        }
    }
}

fn update_global_table_map(tmap: TableMapEventOwned) -> Option<BinError> {
    unsafe {
        *addr_of_mut!(TABLE_MAP) = Some(tmap);
        None
    }
}

fn default_path() -> String {
    ".".to_string()
}

macro_rules! vbinprintln {
    ($($arg:tt)*) => {
        if VERBOSE.load(Ordering::Relaxed) {
            println!($($arg)*);
        }
    };
}

macro_rules! vbinwriteln {
    ($dst:expr, $($arg:tt)*) => {
        if VERBOSE.load(Ordering::Relaxed) {
            writeln!($dst, $($arg)*).unwrap();
        }
    };
}

#[derive(Debug, Parser)]
struct Args {
    /// Path to the binlog file (binlog.xxxxxx file)
    #[arg(short = 'b', long)]
    binlog: PathBuf,
    /// path to directory containing .ibd data files, used for parsing row events
    #[arg(short = 'd', long, default_value = default_path())]
    data_files_dir: PathBuf,
    /// Level of output
    #[arg(short, long)]
    verbose: bool,
}

pub struct Cursor<'a> {
    data: &'a [u8],
    max_size: usize,
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            max_size: data.len(),
        }
    }

    fn jump(&mut self, bytes: usize) -> &'a [u8] {
        assert!(bytes > self.pos, "We can only jump forward");
        assert!(
            bytes < self.max_size,
            "Jump position exceeds maximum buffer length"
        );

        self.pos = bytes;
        &self.data[bytes..]
    }

    fn num_unread(&self) -> usize {
        self.max_size - self.pos
    }

    fn read_more(&self) -> bool {
        self.pos < self.max_size
    }

    fn read(&mut self, len: usize) -> &'a [u8] {
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        out
    }

    fn read_u8(&mut self) -> u8 {
        let v = self.data[self.pos];
        self.pos += 1;
        v
    }

    fn read_u16_le(&mut self) -> u16 {
        let bytes = self.read(2);
        u16::from_le_bytes(bytes.try_into().unwrap())
    }

    fn read_u32_le(&mut self) -> u32 {
        let bytes = self.read(4);
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    fn read_u64_le(&mut self) -> u64 {
        let bytes = self.read(8);
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
}

pub fn read_from_1(buf: &[u8]) -> u8 {
    let temp: [u8; 1] = buf[..1]
        .try_into()
        .expect("Unable to coarse to 1 bytes array");
    u8::from_le_bytes(temp)
}

pub fn read_from_2(buf: &[u8]) -> u16 {
    let temp: [u8; 2] = buf[..2]
        .try_into()
        .expect("Unable to coarse to 2 bytes array");
    u16::from_le_bytes(temp)
}

pub fn read_from_3(buf: &[u8]) -> u32 {
    let temp: [u8; 4] = buf[..4]
        .try_into()
        .expect("Unable to coarse to 4 bytes array");
    u32::from_le_bytes(temp) & 0x00FFFFFF
}

pub fn read_from_4(buf: &[u8]) -> u32 {
    let temp: [u8; 4] = buf[..4]
        .try_into()
        .expect("Unable to coarse to 4 bytes array");
    u32::from_le_bytes(temp)
}

pub fn read_from_8(buf: &[u8]) -> u64 {
    let temp: [u8; 8] = buf[..]
        .try_into()
        .expect("Unable to coarse to 4 bytes array");
    u64::from_le_bytes(temp)
}

fn read_page(page_number: u32, file_path: &PathBuf, buf: &mut [u8]) -> usize {
    let mut file = File::open(file_path).expect("Failed to open file");

    file.seek(SeekFrom::Start(PAGE_SIZE as u64 * page_number as u64))
        .expect("Failed to seek to start");

    file.read(buf).expect("Unable to read file block")
}

fn get_blob_length(in_buf: &[u8], packlength_arg: u32) -> u32 {
    let length = match packlength_arg {
        1 => in_buf[0] as u32,
        2 => read_from_2(in_buf) as u32,
        3 => read_from_3(in_buf),
        4 => read_from_4(in_buf),
        _ => panic!("Invalid packlength_arg value"),
    };
    length
}

pub fn unpack_blob(in_buf: &[u8], out_buf: &mut Vec<u8>, param_data: u32) -> u32 {
    // Field_blob::unpack
    let master_packlength = if param_data > 0 { param_data & 0xFF } else { 0 };
    let blob_length = get_blob_length(in_buf, master_packlength);
    out_buf.extend_from_slice(
        &in_buf[master_packlength as usize..(master_packlength + blob_length) as usize],
    );
    return master_packlength + blob_length;
}

// Attempt to render UTF-8 safely
fn fmt_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            // fallback to hex representation
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("")
        }
    }
}

#[derive(Default, Debug)]
pub struct LogEventHeader {
    type_code: u8,
    flags: u16,
    when: u32,
    unmasked_server_id: u32,
    data_written: u32,
    log_pos: u32,
}

impl LogEventHeader {
    pub fn get_type_code(&self) -> u8 {
        self.type_code
    }
}

#[derive(Debug)]
pub struct FormatDescriptionEvent {
    created: u32,
    binlog_version: u16,
    server_version: [u8; ST_SERVER_VER_LEN as usize],
    common_header_len: u8,
    post_header_len: Vec<u8>,
    _server_version_split: [u8; 3],
    number_of_event_types: u8,
}

impl fmt::Display for FormatDescriptionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert fixed server_version buffer to readable string
        let server_version = {
            let end = self
                .server_version
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(self.server_version.len());

            match std::str::from_utf8(&self.server_version[..end]) {
                Ok(s) => s.to_string(),
                Err(_) => self.server_version[..end]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(""),
            }
        };

        vbinwriteln!(f, "FormatDescriptionEvent {{");
        vbinwriteln!(f, "  created: {},", self.created);
        vbinwriteln!(f, "  binlog_version: {},", self.binlog_version);
        vbinwriteln!(f, "  server_version: \"{}\",", server_version);
        vbinwriteln!(f, "  common_header_len: {},", self.common_header_len);
        vbinwriteln!(
            f,
            "  number_of_event_types: {},",
            self.number_of_event_types
        );
        vbinwriteln!(f, "  post_header_len: {:?},", self.post_header_len);
        vbinwriteln!(f, "}}");
        Ok(())
    }
}

impl FormatDescriptionEvent {
    pub fn parse_format_description_event(data: &[u8]) -> Result<Self, ParseError> {
        let mut cur = Cursor::new(data);
        let mut fde = FormatDescriptionEvent::default();
        fde.binlog_version = cur.read_u16_le();
        fde.server_version
            .copy_from_slice(cur.read(ST_SERVER_VER_LEN as usize));
        fde.created = cur.read_u32_le();
        fde.common_header_len = cur.read_u8();
        fde.number_of_event_types = cur.num_unread() as u8;
        fde.post_header_len = cur.read(fde.number_of_event_types as usize).to_vec();
        Ok(fde)
    }
}

impl Default for FormatDescriptionEvent {
    fn default() -> Self {
        FormatDescriptionEvent {
            created: 0,
            binlog_version: 0,
            server_version: [0u8; ST_SERVER_VER_LEN as usize],
            common_header_len: 0,
            post_header_len: Vec::new(),
            _server_version_split: [0u8; 3],
            number_of_event_types: 0,
        }
    }
}

fn event_handler(
    event_type: LogEventType,
    data: &[u8],
    fde: &mut FormatDescriptionEvent,
    event_header: &LogEventHeader,
) {
    match event_type {
        LogEventType::Known(event) => match event {
            KnownLogEventType::UnknownEvent => {}
            KnownLogEventType::StartEventV3 => {}
            KnownLogEventType::QueryEvent => {}
            KnownLogEventType::StopEvent => {}
            KnownLogEventType::RotateEvent => {}
            KnownLogEventType::IntvarEvent => {}
            KnownLogEventType::SlaveEvent => {}
            KnownLogEventType::AppendBlockEvent => {}
            KnownLogEventType::DeleteFileEvent => {}
            KnownLogEventType::RandEvent => {}
            KnownLogEventType::UserVarEvent => {}
            KnownLogEventType::FormatDescriptionEvent => {
                match FormatDescriptionEvent::parse_format_description_event(data) {
                    Ok(ev) => {
                        vbinprintln!("{}", ev);
                    }
                    Err(e) => {
                        eprintln!("FormatDescriptionEvent parse error: {}", e)
                    }
                }
            }
            KnownLogEventType::XidEvent => {}
            KnownLogEventType::BeginLoadQueryEvent => {}
            KnownLogEventType::ExecuteLoadQueryEvent => {}
            KnownLogEventType::TableMapEvent => {
                match TableMapEvent::parse_table_map_event(data, fde) {
                    Ok(_) => {
                        let ev = read_global_table_map().unwrap();
                        vbinprintln!("{}", ev);
                    }
                    Err(e) => {
                        eprintln!("TableMapEvent parse error: {}", e)
                    }
                }
            }
            KnownLogEventType::ObsoleteWriteRowsEventV1 => {}
            KnownLogEventType::ObsoleteUpdateRowsEventV1 => {}
            KnownLogEventType::ObsoleteDeleteRowsEventV1 => {}
            KnownLogEventType::IncidentEvent => {}
            KnownLogEventType::HeartbeatLogEvent => {}
            KnownLogEventType::IgnorableLogEvent => {}
            KnownLogEventType::RowsQueryLogEvent => {}
            KnownLogEventType::WriteRowsEvent => {
                match WriteRowsEvent::new(data, fde, event_header) {
                    Ok(ev) => {
                        println!("{}", ev);
                    }
                    Err(e) => {
                        eprintln!("WriteRowsEvent parse error: {}", e)
                    }
                }
            }
            KnownLogEventType::UpdateRowsEvent => {
                match UpdateRowsEvent::new(data, fde, event_header) {
                    Ok(ev) => {
                        println!("{}", ev);
                    }
                    Err(e) => {
                        eprintln!("UpdateRowsEvent parse error: {}", e)
                    }
                }
            }
            KnownLogEventType::DeleteRowsEvent => {
                match DeleteRowsEvent::new(data, fde, event_header) {
                    Ok(ev) => {
                        println!("{}", ev);
                    }
                    Err(e) => {
                        eprintln!("DeleteRowsEvent parse error: {}", e)
                    }
                }
            }
            KnownLogEventType::GtidLogEvent => {}
            KnownLogEventType::AnonymousGtidLogEvent => {}
            KnownLogEventType::PreviousGtidsLogEvent => {}
            KnownLogEventType::TransactionContextEvent => {}
            KnownLogEventType::ViewChangeEvent => {}
            KnownLogEventType::XaPrepareLogEvent => {}
            KnownLogEventType::PartialUpdateRowsEvent => {}
            KnownLogEventType::TransactionPayloadEvent => {}
            KnownLogEventType::HeartbeatLogEventV2 => {}
            KnownLogEventType::GtidTaggedLogEvent => {}
            KnownLogEventType::EnumEndEvent => {}
        },

        LogEventType::Unknown(code) => {
            eprintln!("Unknown binlog event type: {}", code);
        }
    }
}

fn _print_event(event_type: LogEventType) {
    match event_type {
        LogEventType::Known(event) => {
            println!("Event: {}", event);
        }
        LogEventType::Unknown(code) => {
            println!("Unknown binlog event type: {}", code);
        }
    }
}

/// Read packed integer. Similar to net_field_length_ll in pack.c
fn read_parse_packed_int(cur: &mut Cursor) -> Option<u64> {
    let first = cur.read_u8();

    match first {
        0x00..=0xFA => Some(first as u64),
        0xFB => None, // NULL
        0xFC => {
            let val = cur.read_u16_le() as u64;
            Some(val)
        }
        0xFD => {
            let input = cur.read(3);
            let val = (input[0] as u64) | ((input[1] as u64) << 8) | ((input[2] as u64) << 16);
            Some(val)
        }

        0xFE => {
            let val = cur.read_u64_le();
            Some(val)
        }

        _ => unreachable!(),
    }
}

#[derive(Debug)]
pub enum ParseError {
    /// Input buffer ended before expected
    UnexpectedEof,

    /// A field had an invalid or unsupported value
    InvalidValue(&'static str),

    /// A length field did not match available data
    LengthMismatch { expected: usize, actual: usize },

    /// Invalid UTF-8 when decoding strings
    Utf8Error(std::str::Utf8Error),

    /// Catch-all for malformed events
    Malformed(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedEof => {
                write!(f, "unexpected end of input")
            }
            ParseError::InvalidValue(field) => {
                write!(f, "invalid value in field: {}", field)
            }
            ParseError::LengthMismatch { expected, actual } => {
                write!(f, "length mismatch (expected {}, got {})", expected, actual)
            }
            ParseError::Utf8Error(e) => {
                write!(f, "utf8 error: {}", e)
            }
            ParseError::Malformed(msg) => {
                write!(f, "malformed event: {}", msg)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TableMapEvent<'a> {
    flags: u16,
    table_id: u64,
    dblen: u64,
    tbllen: u64,
    col_cnt: u64,
    field_metadata_size: u64,
    opt_metadata_len: usize,
    tblname: &'a [u8],
    dbname: &'a [u8],
    col_types: &'a [u8],
    field_metadata: &'a [u8],
    null_bits: &'a [u8],
    opt_metadata: &'a [u8],
}

#[derive(Debug, Clone)]
struct TableMapEventOwned {
    flags: u16,
    table_id: u64,
    dblen: u64,
    tbllen: u64,
    col_cnt: u64,
    field_metadata_size: u64,
    opt_metadata_len: usize,
    tblname: Vec<u8>,
    dbname: Vec<u8>,
    col_types: Vec<u8>,
    field_metadata: Vec<u8>,
    null_bits: Vec<u8>,
    opt_metadata: Vec<u8>,
}

impl fmt::Display for TableMapEventOwned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Attempt to render UTF-8 safely
        fn fmt_bytes(bytes: &[u8]) -> String {
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    // fallback to hex representation
                    bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("")
                }
            }
        }

        vbinwriteln!(f, "TableMapEvent {{");
        vbinwriteln!(f, "  flags: {},", self.flags);
        vbinwriteln!(f, "  dblen: {},", self.dblen);
        vbinwriteln!(f, "  tbllen: {},", self.tbllen);
        vbinwriteln!(f, "  table_id: {},", self.table_id);
        vbinwriteln!(f, "  database: \"{}\",", fmt_bytes(&self.dbname));
        vbinwriteln!(f, "  table: \"{}\",", fmt_bytes(&self.tblname));
        vbinwriteln!(f, "  col_types: \"{}\",", fmt_bytes(&self.col_types));
        vbinwriteln!(f, "  column_count: {},", self.col_cnt);
        vbinwriteln!(f, "  field_metadata_size: {},", self.field_metadata_size);
        vbinwriteln!(
            f,
            "  field_metadata: \"{:?}\",",
            &self.field_metadata // fmt_bytes(&self.field_metadata)
        );
        vbinwriteln!(f, "  null_bits: \"{}\",", fmt_bytes(&self.null_bits));
        vbinwriteln!(f, "  opt_metadata: \"{}\",", fmt_bytes(&self.opt_metadata));
        vbinwriteln!(f, "  optional_metadata_length: {},", self.opt_metadata_len);
        vbinwriteln!(f, "}}");
        // write!(f, "")
        Ok(())
    }
}

impl<'a> From<TableMapEvent<'a>> for TableMapEventOwned {
    fn from(e: TableMapEvent<'a>) -> Self {
        Self {
            flags: e.flags,
            table_id: e.table_id,
            dblen: e.dblen,
            tbllen: e.tbllen,
            col_cnt: e.col_cnt,
            field_metadata_size: e.field_metadata_size,
            opt_metadata_len: e.opt_metadata_len,
            tblname: e.tblname.to_vec(),
            dbname: e.dbname.to_vec(),
            col_types: e.col_types.to_vec(),
            field_metadata: e.field_metadata.to_vec(),
            null_bits: e.null_bits.to_vec(),
            opt_metadata: e.opt_metadata.to_vec(),
        }
    }
}

impl<'a> TableMapEvent<'a> {
    pub fn parse_table_map_event(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
    ) -> Result<(), ParseError> {
        let table_id: u64;
        let flags: u16;
        let dblen: u64;
        let tbllen: u64;
        let tblname: &[u8];
        let dbname: &[u8];
        let col_types: &[u8];
        let mut field_metadata_size: u64 = 0;
        let field_metadata: &[u8];
        let null_bits: &[u8];
        let col_cnt: u64;

        // Optional metadata details
        let opt_metadata_len: usize;
        let opt_metadata: &[u8];

        // Get a cursor to move within the buffer
        let mut cur = Cursor::new(data);
        if fde.post_header_len[KnownLogEventType::TableMapEvent as usize - 1] == 6 {
            /* Master is of an intermediate source tree before 5.1.4. Id is 4 bytes */
            table_id = read_from_4(cur.read(4)) as u64;
        } else {
            assert_eq!(
                fde.post_header_len[KnownLogEventType::TableMapEvent as usize - 1] as u32,
                TABLE_MAP_HEADER_LEN
            );
            // Read next 6 bytes
            let buf = cur.read(6);
            table_id = buf[0] as u64
                | (buf[1] as u64) << 8
                | (buf[2] as u64) << 16
                | (buf[3] as u64) << 24
                | (buf[4] as u64) << 32
                | (buf[5] as u64) << 40;
        }

        flags = cur.read_u16_le();
        dblen = read_parse_packed_int(&mut cur)
            .expect("Unable to parse database length from packed int");
        dbname = cur.read(dblen as usize);
        // Skip null c-style terminator \0
        cur.read(1);

        tbllen = read_parse_packed_int(&mut cur)
            .expect("Unable to parse database length from packed int");
        tblname = cur.read(tbllen as usize);
        // Skip null c-style terminator \0
        cur.read(1);

        col_cnt =
            read_parse_packed_int(&mut cur).expect("Unable to parse column count from packed int");
        col_types = cur.read(col_cnt as usize);

        if cur.read_more() {
            field_metadata_size = read_parse_packed_int(&mut cur)
                .expect("Unable to parse field meatadata size from packed int");
            if field_metadata_size > (col_cnt * 4) {
                panic!("Invalid field meatadata size");
            }
            let num_null_bytes = (col_cnt + 7) / 8;
            field_metadata = cur.read(field_metadata_size as usize);
            null_bits = cur.read(num_null_bytes as usize);
        } else {
            field_metadata = cur.read(0);
            null_bits = cur.read(0);
        }

        opt_metadata_len = cur.num_unread();
        if opt_metadata_len > 0 {
            opt_metadata = cur.read(opt_metadata_len);
        } else {
            opt_metadata = cur.read(0);
        }

        let ev = TableMapEvent {
            flags,
            table_id,
            dblen,
            tbllen,
            col_cnt,
            field_metadata_size,
            tblname,
            dbname,
            col_types,
            field_metadata,
            null_bits,
            opt_metadata_len,
            opt_metadata,
        };

        update_global_table_map(ev.into());

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RowsEvent<'a> {
    flags: u16, // Flags for row-level events
    var_header_len: u16,
    n_bits_len: u32, // value determined by (m_width + 7) / 8
    table_id: u64,
    width: u64, // The width of the columns bitmap
    columns_before_image: &'a [u8],
    columns_after_image: &'a [u8],
    row: &'a [u8],
}

impl<'a> RowsEvent<'a> {
    pub fn parse_rows_event(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
        event_header: &LogEventHeader,
    ) -> Result<Self, ParseError> {
        let table_id: u64;
        let flags: u16;
        let width: u64;
        let n_bits_len: u32;
        let columns_before_image: &[u8];
        let columns_after_image: &[u8];
        let row: &[u8];
        let var_header_len: u16 = 0; // Placeholder, as it's not explicitly used in parsing but is part of the event structure
        let post_header_len = fde.post_header_len[KnownLogEventType::WriteRowsEvent as usize - 1];

        // Get a cursor to move within the buffer
        let mut cur = Cursor::new(data);
        if post_header_len == 6 {
            /* Master is of an intermediate source tree before 5.1.4. Id is 4 bytes */
            table_id = read_from_4(cur.read(4)) as u64;
        } else {
            // Read next 6 bytes
            let buf = cur.read(6);
            table_id = buf[0] as u64
                | (buf[1] as u64) << 8
                | (buf[2] as u64) << 16
                | (buf[3] as u64) << 24
                | (buf[4] as u64) << 32
                | (buf[5] as u64) << 40;
        }
        let table_map = read_global_table_map().unwrap();
        assert!(
            table_map.table_id == table_id,
            "Table ID mismatch between WriteRowsEvent and TableMapEvent"
        );
        flags = cur.read_u16_le();

        // Post-header length for V2 events is 10
        if post_header_len as u32 == ROWS_HEADER_LEN_V2 {
            let extra_data_len = cur.read_u16_le() as usize; // Reads bytes 8..10 (value 2)

            // Only advance if there are extra bytes beyond the length prefix itself
            if extra_data_len > 2 {
                cur.read(extra_data_len - 2);
            }
        }

        // We expect the post-header length to be 10 bytes, and if it's not, we have an unsupported format.
        assert_eq!(post_header_len as u32, ROWS_HEADER_LEN_V2);

        width = read_parse_packed_int(&mut cur).expect("Unable to parse width from packed int");
        assert!(
            table_map.col_cnt == width,
            "Column count mismatch between RowsEvent and TableMapEvent"
        );
        assert_ne!(width, 0, "Width must be greater than 0");

        n_bits_len = (width + 7) as u32 / 8;
        columns_before_image = cur.read(n_bits_len as usize);

        // UpdateRowsEvent and PartialUpdateRowsEvent
        if event_header.get_type_code() == 31 || event_header.get_type_code() == 39 {
            columns_after_image = cur.read(n_bits_len as usize);
        } else {
            columns_after_image = columns_before_image.as_ref();
        }

        row = cur.read(cur.num_unread());

        Ok(RowsEvent {
            flags,
            var_header_len,
            n_bits_len,
            table_id,
            width,
            columns_before_image,
            columns_after_image,
            row,
        })
    }

    fn table_columns(&self, table_map: &TableMapEventOwned) -> Option<Vec<Value>> {
        // let table_map = read_global_table_map().unwrap();
        let t_name = &table_map.tblname;
        vbinprintln!(
            "Reading SDI information from table data file: {:?}",
            String::from_utf8_lossy(t_name)
        );
        let mut columns: Vec<Value> = Vec::new();
        let sdi_info: &Value;
        match read_global_dd_cache(
            String::from_utf8(t_name.to_vec())
                .expect("Invalid UTF-8 sequence")
                .as_str(),
        ) {
            Ok(dd) => sdi_info = dd,
            Err(e) => {
                vbinprintln!("Table information not found in dd cache: {:?}", e);
                let mut file_path = PathBuf::from(read_data_dir().unwrap())
                    .join(String::from_utf8_lossy(&table_map.dbname).as_ref())
                    .join(String::from_utf8_lossy(&table_map.tblname).as_ref());
                file_path.set_extension("ibd");
                vbinprintln!("Reading SDI information from table data file: {:?}", file_path);

                let buf = [0u8; PAGE_SIZE as usize];
                let mut file = File::open(file_path).expect("Failed to open file");
                let sdi = serde_json::to_value(read_sdi_info_from_disk(&mut file, buf)).unwrap();
                update_global_dd_cache(
                    String::from_utf8(t_name.to_vec()).expect("Invalid UTF-8 sequence"),
                    sdi,
                );
                sdi_info = read_global_dd_cache(
                    String::from_utf8(t_name.to_vec())
                        .expect("Invalid UTF-8 sequence")
                        .as_str(),
                )
                .unwrap();
            }
        }

        // Retrieve columns from SDI data
        for rec in sdi_info.as_array().unwrap() {
            if let Some(Value::Object(dd_object)) = rec.get("dd_object") {
                if let Some(obj_type) = rec.get("dd_object_type") {
                    if obj_type == "Table" {
                        if let Some(Value::Array(cols)) = dd_object.get("columns") {
                            columns = cols.clone();
                            break;
                        }
                    }
                }
            }
        }
        Some(columns)
    }

    fn handle_field_types(&self, off: &mut u32, meta_i: &mut usize) -> Map<String, Value> {
        let table_map = read_global_table_map().unwrap();
        let columns: Vec<Value> = self
            .table_columns(&table_map)
            .expect("Missing columns info");
        let null_bit_mask = &self.row[*off as usize..(*off + self.n_bits_len) as usize];
        *off += self.n_bits_len;

        let mut out_data: Map<String, Value> = Map::new();
        for i in 0..table_map.col_cnt {
            let byte_idx = i / 8;
            let bit_idx = i % 8;

            let col: &Map<String, Value> = columns[i as usize]
                .as_object()
                .expect("Error parsing column information from SDI");

            let fixed_col_size = get_fixed_column_size(ColumnTypes::from(
                col["type"].as_u64().unwrap_or(u64::MAX) as u32,
            ));

            assert!(
                self.row[*off as usize..].len() as u32 > 0,
                "Record buffer is empty"
            );

            if (null_bit_mask[byte_idx as usize] & (1 << bit_idx)) != 0 {
                out_data.insert(
                    col["name"].as_str().unwrap_or("unknown").to_string(),
                    json!(Null),
                );
                continue;
            }

            // We are only handling fixed size columns and varchar/string type columns
            if fixed_col_size < u32::MAX {
                // FIX: Assumes integer only(4 bytes). Should change
                let field = &&self.row[*off as usize..(*off + fixed_col_size) as usize];
                out_data.insert(
                    col["name"].as_str().unwrap_or("unknown").to_string(),
                    json!(read_from_4(field)),
                );
                *off += fixed_col_size;
            } else {
                let column = ColumnTypes::from(col["type"].as_u64().unwrap_or(u64::MAX) as u32);
                match column {
                    ColumnTypes::BLOB => {
                        // See Field_blob::unpack
                        // Pack length is stored in a single byte. See mysql Table_map_event
                        let param_data = read_from_1(&table_map.field_metadata[*meta_i..]);
                        *meta_i += 1;
                        let in_buf = &&self.row[*off as usize..];
                        let mut out_buf = Vec::new();
                        let length = unpack_blob(in_buf, &mut out_buf, param_data as u32);
                        out_data.insert(
                            col["name"].as_str().unwrap_or("unknown").to_string(),
                            json!(String::from_utf8_lossy(&out_buf)),
                        );
                        *off += length;
                    }
                    ColumnTypes::VARCHAR | ColumnTypes::STRING => {
                        // See Field_string::unpack
                        // Pack length is stored in a two bytes. See mysql Table_map_event
                        let param_data = read_from_2(&table_map.field_metadata[*meta_i..]);
                        let from_length =
                            (((param_data >> 4) & 0x300) ^ 0x300) + (param_data & 0x00ff);
                        *meta_i += 2;
                        if from_length > 255 {
                            let len = read_from_2(&&self.row[*off as usize..]);
                            *off += 2;
                            let field = &&self.row[(*off) as usize..(*off + len as u32) as usize];
                            out_data.insert(
                                col["name"].as_str().unwrap_or("unknown").to_string(),
                                json!(String::from_utf8_lossy(field)),
                            );
                            *off += len as u32;
                        } else {
                            let len = read_from_1(&&self.row[*off as usize..]);
                            *off += 1;
                            let field = &&self.row[(*off) as usize..(*off + len as u32) as usize];
                            out_data.insert(
                                col["name"].as_str().unwrap_or("unknown").to_string(),
                                json!(String::from_utf8_lossy(field)),
                            );
                            *off += len as u32;
                        }
                    }
                    _ => {
                        panic!("Unsupported column type: {:?}", column);
                    }
                }
            }
        }
        out_data
    }

    fn to_json(&self) -> Map<String, Value> {
        let mut ret_data = Map::new();
        if VERBOSE.load(Ordering::Relaxed) {
            ret_data.insert("flags".to_string(), Value::Number(self.flags.into()));
            ret_data.insert(
                "var_header_len".to_string(),
                Value::Number(self.var_header_len.into()),
            );
            ret_data.insert(
                "n_bits_len".to_string(),
                Value::Number(self.n_bits_len.into()),
            );
            ret_data.insert("table_id".to_string(), Value::Number(self.table_id.into()));
            ret_data.insert("width".to_string(), Value::Number(self.width.into()));
            ret_data.insert(
                "columns_before_image".to_string(),
                Value::String(fmt_bytes(self.columns_before_image)),
            );
            ret_data.insert(
                "columns_after_image".to_string(),
                Value::String(fmt_bytes(self.columns_after_image)),
            );
        }

        ret_data
    }
}

struct WriteRowsEvent<'a> {
    rows_event: RowsEvent<'a>,
}

impl<'a> Deref for WriteRowsEvent<'a> {
    type Target = RowsEvent<'a>;

    fn deref(&self) -> &Self::Target {
        &self.rows_event
    }
}

impl<'a> WriteRowsEvent<'a> {
    pub fn new(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
        event_header: &LogEventHeader,
    ) -> Result<Self, ParseError> {
        let rows_event = RowsEvent::parse_rows_event(data, fde, event_header)?;
        Ok(WriteRowsEvent { rows_event })
    }

    fn parse_fields(&self) -> Map<String, Value> {
        // Offset through the row data
        let mut off = 0;
        // Offset through the table metadata
        let mut meta_i: usize = 0;
        self.handle_field_types(&mut off, &mut meta_i)
    }
}

impl<'a> fmt::Display for WriteRowsEvent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ret_data = self.to_json();

        let out_data = self.parse_fields();
        ret_data.insert("row".to_string(), Value::Object(out_data));

        writeln!(
            f,
            "WriteRowsEvent: {}",
            serde_json::to_string_pretty(&ret_data).expect("Error")
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct UpdateRowsEvent<'a> {
    rows_event: RowsEvent<'a>,
}

impl<'a> Deref for UpdateRowsEvent<'a> {
    type Target = RowsEvent<'a>;

    fn deref(&self) -> &Self::Target {
        &self.rows_event
    }
}

impl<'a> UpdateRowsEvent<'a> {
    pub fn new(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
        event_header: &LogEventHeader,
    ) -> Result<Self, ParseError> {
        let rows_event = RowsEvent::parse_rows_event(data, fde, event_header)?;
        Ok(UpdateRowsEvent { rows_event })
    }

    fn parse_fields(&self) -> Map<String, Value> {
        // Offset through the row data
        let mut off = 0;
        // Offset through the table metadata
        let mut meta_i: usize = 0;
        let mut out_data: Map<String, Value> = Map::new();
        let names = ["before_image", "after_image"];
        // Loop twice to capture before and after images
        for k in 0..2 {
            let row_data = self.handle_field_types(&mut off, &mut meta_i);

            out_data.insert(names[k as usize].to_string(), Value::Object(row_data));
            meta_i = 0; // Reset meta index for the next image
        }
        out_data
    }
}

impl<'a> fmt::Display for UpdateRowsEvent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ret_data = self.to_json();

        let out_data = self.parse_fields();
        ret_data.insert("row".to_string(), Value::Object(out_data));

        writeln!(
            f,
            "UpdateRowsEvent: {}",
            serde_json::to_string_pretty(&ret_data).expect("Error")
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct DeleteRowsEvent<'a> {
    rows_event: RowsEvent<'a>,
}

impl<'a> Deref for DeleteRowsEvent<'a> {
    type Target = RowsEvent<'a>;

    fn deref(&self) -> &Self::Target {
        &self.rows_event
    }
}

impl<'a> DeleteRowsEvent<'a> {
    pub fn new(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
        event_header: &LogEventHeader,
    ) -> Result<Self, ParseError> {
        let rows_event = RowsEvent::parse_rows_event(data, fde, event_header)?;
        Ok(DeleteRowsEvent { rows_event })
    }

    fn parse_fields(&self) -> Map<String, Value> {
        // Offset through the row data
        let mut off = 0;
        // Offset through the table metadata
        let mut meta_i: usize = 0;
        self.handle_field_types(&mut off, &mut meta_i)
    }
}

impl<'a> fmt::Display for DeleteRowsEvent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ret_data = self.to_json();

        let out_data = self.parse_fields();
        ret_data.insert("row".to_string(), Value::Object(out_data));

        writeln!(
            f,
            "DeleteRowsEvent: {}",
            serde_json::to_string_pretty(&ret_data).expect("Error")
        )?;
        Ok(())
    }
}

fn main() {
    let mut args = Args::parse();
    let buf = &mut [0u8; PAGE_SIZE as usize];
    let mut pos;

    let data_dir = args
        .data_files_dir
        .to_str()
        .expect("Error reading data dir");
    if data_dir == "." || data_dir == " " {
        eprintln!(
            "Data directory containing table data files(<tablename>.ibd) does not exist. Defaulting to Linux path /var/lib/mysql"
        );
        args.data_files_dir = PathBuf::from("/var/lib/mysql");
    }

    VERBOSE.store(args.verbose, Ordering::Relaxed);

    let data_dir = String::from(args.data_files_dir.clone().to_string_lossy());
    vbinprintln!("Data directory: {}", data_dir);
    set_data_dir(data_dir);

    let nr = read_page(0, &args.binlog, buf);

    let mut event_header = LogEventHeader::default();

    let mut cur = Cursor::new(buf);
    assert_eq!(
        BINLOG_MAGIC,
        cur.read(BINLOG_MAGIC_SIZE as usize),
        "Binlog magic number must match on disk value. Corruption or unsupported format detected"
    );

    let data_buf = &buf[BINLOG_MAGIC_SIZE as usize..];
    event_header.type_code = read_from_1(&data_buf[EVENT_TYPE_OFFSET as usize..]);

    event_header.flags = read_from_2(&data_buf[FLAGS_OFFSET as usize..]);
    event_header.when = read_from_4(data_buf);
    event_header.unmasked_server_id = read_from_4(&data_buf[SERVER_ID_OFFSET as usize..]);
    event_header.data_written = read_from_4(&data_buf[EVENT_LEN_OFFSET as usize..]);
    event_header.log_pos = read_from_4(&data_buf[LOG_POS_OFFSET as usize..]);
    pos = event_header.log_pos;

    vbinprintln!("Event Log Header: {:?}", event_header);
    cur.jump((BINLOG_MAGIC_SIZE + LOG_EVENT_HEADER_LEN) as usize);

    let mut fde = match FormatDescriptionEvent::parse_format_description_event(
        &buf[(BINLOG_MAGIC_SIZE + LOG_EVENT_HEADER_LEN) as usize..event_header.log_pos as usize],
    ) {
        Ok(fde_) => fde_,
        Err(e) => {
            panic!("FormatDescriptionEvent parse error: {}", e);
        }
    };
    vbinprintln!("{}", fde);
    cur.jump(event_header.log_pos as usize);

    while pos < nr as u32 {
        let data_buf = cur.read(LOG_EVENT_HEADER_LEN as usize);
        build_event_header(&mut event_header, data_buf);
        let event =
            LogEventType::try_from(event_header.type_code).expect("Error parsing raw event type");

        if event_header.log_pos < PAGE_SIZE as u32 {
            event_handler(
                event,
                &buf[(pos + LOG_EVENT_HEADER_LEN) as usize..event_header.log_pos as usize],
                &mut fde,
                &event_header,
            );
        } else {
            event_handler(
                event,
                &buf[(pos + LOG_EVENT_HEADER_LEN) as usize..],
                &mut fde,
                &event_header,
            );
        }
        pos = event_header.log_pos;

        if pos < PAGE_SIZE as u32 {
            cur.jump(pos as usize);
        }
    }
}

pub fn build_event_header(event_header: &mut LogEventHeader, data_buf: &[u8]) {
    event_header.type_code = read_from_1(&data_buf[EVENT_TYPE_OFFSET as usize..]);

    event_header.flags = read_from_2(&data_buf[FLAGS_OFFSET as usize..]);
    event_header.when = read_from_4(data_buf);
    event_header.unmasked_server_id = read_from_4(&data_buf[SERVER_ID_OFFSET as usize..]);
    event_header.data_written = read_from_4(&data_buf[EVENT_LEN_OFFSET as usize..]);
    event_header.log_pos = read_from_4(&data_buf[LOG_POS_OFFSET as usize..]);
}

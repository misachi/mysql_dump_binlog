use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use clap::Parser;

const PAGE_SIZE: u16 = 2 << 13;

/*
   Event header offsets; these point to places inside the fixed header.
*/
const EVENT_TYPE_OFFSET: u32 = 4;
const SERVER_ID_OFFSET: u32 = 5;
const EVENT_LEN_OFFSET: u32 = 9;
const LOG_POS_OFFSET: u32 = 13;
const FLAGS_OFFSET: u32 = 17;

/* The length of the array server_version */
const ST_SERVER_VER_LEN: u32 = 50;

/** start event post-header (for v3 and v4) */
// const _ST_BINLOG_VER_OFFSET: u32 = 0;
// const ST_SERVER_VER_OFFSET: u32 = 2;
// const ST_CREATED_OFFSET: u32 = ST_SERVER_VER_OFFSET + ST_SERVER_VER_LEN;
// const ST_COMMON_HEADER_LEN_OFFSET: u32 = ST_CREATED_OFFSET + 4;

const LOG_EVENT_HEADER_LEN: u32 = 19; /* the fixed header length */

const _LOG_EVENT_TYPES: u32 = 42;

/* 4 bytes which all binlogs should begin with */
const BINLOG_MAGIC_SIZE: u32 = 4;
const BINLOG_MAGIC: [u8; BINLOG_MAGIC_SIZE as usize] = [0xfe, 0x62, 0x69, 0x6e];

// #######
/**
  The lengths for the fixed data part of each event.
  This is a const that provides post-header lengths for all events.
*/
// where 3.23, 4.x and 5.0 agree
const _QUERY_HEADER_MINIMAL_LEN: u32 = 4 + 4 + 1 + 2;

// where 5.0 differs: 2 for length of N-bytes vars.
const _QUERY_HEADER_LEN: u32 = _QUERY_HEADER_MINIMAL_LEN + 2;

const _STOP_HEADER_LEN: u32 = 0;

const _START_V3_HEADER_LEN: u32 = 2 + ST_SERVER_VER_LEN + 4;

// this is FROZEN (the Rotate post-header is frozen)
const _ROTATE_HEADER_LEN: u32 = 8;

const _INTVAR_HEADER_LEN: u32 = 0;
const _APPEND_BLOCK_HEADER_LEN: u32 = 4;
const _DELETE_FILE_HEADER_LEN: u32 = 4;
const _RAND_HEADER_LEN: u32 = 0;
const _USER_VAR_HEADER_LEN: u32 = 0;

const _FORMAT_DESCRIPTION_HEADER_LEN: u32 = _START_V3_HEADER_LEN + 1 + _LOG_EVENT_TYPES;

const _XID_HEADER_LEN: u32 = 0;

const _BEGIN_LOAD_QUERY_HEADER_LEN: u32 = _APPEND_BLOCK_HEADER_LEN;

const _ROWS_HEADER_LEN_V1: u32 = 8;
const TABLE_MAP_HEADER_LEN: u32 = 8;

const _EXECUTE_LOAD_QUERY_EXTRA_HEADER_LEN: u32 = 4 + 4 + 4 + 1;

const _EXECUTE_LOAD_QUERY_HEADER_LEN: u32 =
    _QUERY_HEADER_LEN + _EXECUTE_LOAD_QUERY_EXTRA_HEADER_LEN;

const _INCIDENT_HEADER_LEN: u32 = 2;
const _HEARTBEAT_HEADER_LEN: u32 = 0;
const _IGNORABLE_HEADER_LEN: u32 = 0;
const ROWS_HEADER_LEN_V2: u32 = 10;
const _TRANSACTION_CONTEXT_HEADER_LEN: u32 = 18;
const _VIEW_CHANGE_HEADER_LEN: u32 = 52;
const _XA_PREPARE_HEADER_LEN: u32 = 0;
const _TRANSACTION_PAYLOAD_HEADER_LEN: u32 = 0;
// ######

fn default_path() -> String {
    ".".to_string()
}

#[derive(Debug, Parser)]
// #[command(version)]
struct Args {
    /// Path to the binlog file (binlog.xxxxxx file)
    #[arg(short = 'b', long)]
    binlog: PathBuf,
    #[arg(short = 'd', long, default_value = default_path())]
    data_files_dir: PathBuf, // path to directory containing .ibd data files, used for parsing row events
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownLogEventType {
    /// Every time you add a type, you must assign it a number explicitly.
    UnknownEvent = 0,

    /// Deprecated since MySQL 8.0.2. Placeholder only.
    StartEventV3 = 1,

    QueryEvent = 2,
    StopEvent = 3,
    RotateEvent = 4,
    IntvarEvent = 5,

    SlaveEvent = 7,

    AppendBlockEvent = 9,
    DeleteFileEvent = 11,

    RandEvent = 13,
    UserVarEvent = 14,
    FormatDescriptionEvent = 15,
    XidEvent = 16,
    BeginLoadQueryEvent = 17,
    ExecuteLoadQueryEvent = 18,

    TableMapEvent = 19,

    /// Obsolete V1 row events (5.1.16 → 5.6, rejected since 8.4.0)
    ObsoleteWriteRowsEventV1 = 23,
    ObsoleteUpdateRowsEventV1 = 24,
    ObsoleteDeleteRowsEventV1 = 25,

    /// Something out of the ordinary happened on the master
    IncidentEvent = 26,

    /// Heartbeat event sent by master during idle time
    HeartbeatLogEvent = 27,

    /// Ignorable data event
    IgnorableLogEvent = 28,
    RowsQueryLogEvent = 29,

    /// Version 2 row events
    WriteRowsEvent = 30,
    UpdateRowsEvent = 31,
    DeleteRowsEvent = 32,

    GtidLogEvent = 33,
    AnonymousGtidLogEvent = 34,
    PreviousGtidsLogEvent = 35,
    TransactionContextEvent = 36,
    ViewChangeEvent = 37,

    /// Prepared XA transaction terminal event similar to Xid
    XaPrepareLogEvent = 38,

    /// Extension of UPDATE_ROWS_EVENT allowing partial values
    PartialUpdateRowsEvent = 39,

    TransactionPayloadEvent = 40,
    HeartbeatLogEventV2 = 41,
    GtidTaggedLogEvent = 42,

    /// End marker
    EnumEndEvent,
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

impl fmt::Display for KnownLogEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            KnownLogEventType::UnknownEvent => "UnknownEvent",
            KnownLogEventType::StartEventV3 => "StartEventV3",
            KnownLogEventType::QueryEvent => "QueryEvent",
            KnownLogEventType::StopEvent => "StopEvent",
            KnownLogEventType::RotateEvent => "RotateEvent",
            KnownLogEventType::IntvarEvent => "IntvarEvent",
            KnownLogEventType::SlaveEvent => "SlaveEvent",
            KnownLogEventType::AppendBlockEvent => "AppendBlockEvent",
            KnownLogEventType::DeleteFileEvent => "DeleteFileEvent",
            KnownLogEventType::RandEvent => "RandEvent",
            KnownLogEventType::UserVarEvent => "UserVarEvent",
            KnownLogEventType::FormatDescriptionEvent => "FormatDescriptionEvent",
            KnownLogEventType::XidEvent => "XidEvent",
            KnownLogEventType::BeginLoadQueryEvent => "BeginLoadQueryEvent",
            KnownLogEventType::ExecuteLoadQueryEvent => "ExecuteLoadQueryEvent",
            KnownLogEventType::TableMapEvent => "TableMapEvent",
            KnownLogEventType::ObsoleteWriteRowsEventV1 => "ObsoleteWriteRowsEventV1",
            KnownLogEventType::ObsoleteUpdateRowsEventV1 => "ObsoleteUpdateRowsEventV1",
            KnownLogEventType::ObsoleteDeleteRowsEventV1 => "ObsoleteDeleteRowsEventV1",
            KnownLogEventType::IncidentEvent => "IncidentEvent",
            KnownLogEventType::HeartbeatLogEvent => "HeartbeatLogEvent",
            KnownLogEventType::IgnorableLogEvent => "IgnorableLogEvent",
            KnownLogEventType::RowsQueryLogEvent => "RowsQueryLogEvent",
            KnownLogEventType::WriteRowsEvent => "WriteRowsEvent",
            KnownLogEventType::UpdateRowsEvent => "UpdateRowsEvent",
            KnownLogEventType::DeleteRowsEvent => "DeleteRowsEvent",
            KnownLogEventType::GtidLogEvent => "GtidLogEvent",
            KnownLogEventType::AnonymousGtidLogEvent => "AnonymousGtidLogEvent",
            KnownLogEventType::PreviousGtidsLogEvent => "PreviousGtidsLogEvent",
            KnownLogEventType::TransactionContextEvent => "TransactionContextEvent",
            KnownLogEventType::ViewChangeEvent => "ViewChangeEvent",
            KnownLogEventType::XaPrepareLogEvent => "XaPrepareLogEvent",
            KnownLogEventType::PartialUpdateRowsEvent => "PartialUpdateRowsEvent",
            KnownLogEventType::TransactionPayloadEvent => "TransactionPayloadEvent",
            KnownLogEventType::HeartbeatLogEventV2 => "HeartbeatLogEventV2",
            KnownLogEventType::GtidTaggedLogEvent => "GtidTaggedLogEvent",
            KnownLogEventType::EnumEndEvent => "EnumEndEvent",
        };

        write!(f, "{}", name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogEventType {
    Known(KnownLogEventType),
    Unknown(u8),
}

impl From<u8> for LogEventType {
    fn from(value: u8) -> Self {
        let known = match value {
            0 => Some(KnownLogEventType::UnknownEvent),
            1 => Some(KnownLogEventType::StartEventV3),
            2 => Some(KnownLogEventType::QueryEvent),
            3 => Some(KnownLogEventType::StopEvent),
            4 => Some(KnownLogEventType::RotateEvent),
            5 => Some(KnownLogEventType::IntvarEvent),
            7 => Some(KnownLogEventType::SlaveEvent),
            9 => Some(KnownLogEventType::AppendBlockEvent),
            11 => Some(KnownLogEventType::DeleteFileEvent),
            13 => Some(KnownLogEventType::RandEvent),
            14 => Some(KnownLogEventType::UserVarEvent),
            15 => Some(KnownLogEventType::FormatDescriptionEvent),
            16 => Some(KnownLogEventType::XidEvent),
            17 => Some(KnownLogEventType::BeginLoadQueryEvent),
            18 => Some(KnownLogEventType::ExecuteLoadQueryEvent),
            19 => Some(KnownLogEventType::TableMapEvent),
            23 => Some(KnownLogEventType::ObsoleteWriteRowsEventV1),
            24 => Some(KnownLogEventType::ObsoleteUpdateRowsEventV1),
            25 => Some(KnownLogEventType::ObsoleteDeleteRowsEventV1),
            26 => Some(KnownLogEventType::IncidentEvent),
            27 => Some(KnownLogEventType::HeartbeatLogEvent),
            28 => Some(KnownLogEventType::IgnorableLogEvent),
            29 => Some(KnownLogEventType::RowsQueryLogEvent),
            30 => Some(KnownLogEventType::WriteRowsEvent),
            31 => Some(KnownLogEventType::UpdateRowsEvent),
            32 => Some(KnownLogEventType::DeleteRowsEvent),
            33 => Some(KnownLogEventType::GtidLogEvent),
            34 => Some(KnownLogEventType::AnonymousGtidLogEvent),
            35 => Some(KnownLogEventType::PreviousGtidsLogEvent),
            36 => Some(KnownLogEventType::TransactionContextEvent),
            37 => Some(KnownLogEventType::ViewChangeEvent),
            38 => Some(KnownLogEventType::XaPrepareLogEvent),
            39 => Some(KnownLogEventType::PartialUpdateRowsEvent),
            40 => Some(KnownLogEventType::TransactionPayloadEvent),
            41 => Some(KnownLogEventType::HeartbeatLogEventV2),
            42 => Some(KnownLogEventType::GtidTaggedLogEvent),
            _ => None,
        };

        match known {
            Some(k) => LogEventType::Known(k),
            None => LogEventType::Unknown(value),
        }
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

fn read_page(page_number: u32, file_path: &PathBuf, buf: &mut [u8]) {
    let mut file = File::open(file_path).expect("Failed to open file");

    file.seek(SeekFrom::Start(PAGE_SIZE as u64 * page_number as u64))
        .expect("Failed to seek to start");

    file.read_exact(buf).expect("Unable to read file block");
}

#[derive(Default, Debug)]
struct LogEventHeader {
    type_code: u8,
    flags: u16,
    when: u32,
    unmasked_server_id: u32,
    data_written: u32,
    log_pos: u32,
}

impl LogEventHeader {}

#[derive(Debug)]
struct FormatDescriptionEvent {
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

        writeln!(f, "FormatDescriptionEvent {{")?;
        writeln!(f, "  created: {},", self.created)?;
        writeln!(f, "  binlog_version: {},", self.binlog_version)?;
        writeln!(f, "  server_version: \"{}\",", server_version)?;
        writeln!(f, "  common_header_len: {},", self.common_header_len)?;
        writeln!(
            f,
            "  number_of_event_types: {},",
            self.number_of_event_types
        )?;
        writeln!(f, "  post_header_len: {:?},", self.post_header_len)?;
        write!(f, "}}")
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

fn event_handler(event_type: LogEventType, data: &[u8], fde: &mut FormatDescriptionEvent) {
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
                        println!("{}", ev);
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
                    Ok(ev) => {
                        println!("{}", ev);
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
                match WriteRowsEvent::parse_write_rows_event(data, fde) {
                    Ok(ev) => {
                        println!("{}", ev);
                    }
                    Err(e) => {
                        eprintln!("WriteRowsEvent parse error: {}", e)
                    }
                }
            }
            KnownLogEventType::UpdateRowsEvent => {}
            KnownLogEventType::DeleteRowsEvent => {}
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

impl<'a> fmt::Display for TableMapEvent<'a> {
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

        writeln!(f, "TableMapEvent {{")?;
        writeln!(f, "  flags: {},", self.flags)?;
        writeln!(f, "  dblen: {},", self.dblen)?;
        writeln!(f, "  tbllen: {},", self.tbllen)?;
        writeln!(f, "  table_id: {},", self.table_id)?;
        writeln!(f, "  database: \"{}\",", fmt_bytes(self.dbname))?;
        writeln!(f, "  table: \"{}\",", fmt_bytes(self.tblname))?;
        writeln!(f, "  col_types: \"{}\",", fmt_bytes(self.col_types))?;
        writeln!(f, "  column_count: {},", self.col_cnt)?;
        writeln!(f, "  field_metadata_size: {},", self.field_metadata_size)?;
        writeln!(f, "  field_metadata: \"{}\",", fmt_bytes(self.field_metadata))?;
        writeln!(f, "  null_bits: \"{}\",", fmt_bytes(self.null_bits))?;
        writeln!(f, "  opt_metadata: \"{}\",", fmt_bytes(self.opt_metadata))?;
        writeln!(f, "  optional_metadata_length: {},", self.opt_metadata_len)?;
        write!(f, "}}")
    }
}

impl<'a> TableMapEvent<'a> {
    pub fn parse_table_map_event(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
    ) -> Result<Self, ParseError> {
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
        dblen = read_parse_packed_int(&mut cur).expect("Unable to parse database length from packed int");
        dbname = cur.read(dblen as usize + 1);
        tbllen =
            read_parse_packed_int(&mut cur).expect("Unable to parse database length from packed int");
        tblname = cur.read(tbllen as usize + 1);

        col_cnt = read_parse_packed_int(&mut cur).expect("Unable to parse column count from packed int");
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

        Ok(TableMapEvent {
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
        })
    }
}

struct WriteRowsEvent<'a> {
    flags: u16, /// Flags for row-level events
    var_header_len: u16,
    n_bits_len: u32, /// value determined by (m_width + 7) / 8
    table_id: u64,
    width: u64, /// The width of the columns bitmap
    columns_before_image: &'a [u8],
    columns_after_image: &'a [u8],
    row: &'a [u8],
}

impl<'a> WriteRowsEvent<'a> {
    pub fn parse_write_rows_event(
        data: &'a [u8],
        fde: &FormatDescriptionEvent,
    ) -> Result<Self, ParseError> {
        let table_id: u64;
        let flags: u16;
        let width: u64;
        let n_bits_len: u32;
        let columns_before_image: &[u8];
        let columns_after_image: &[u8];
        let row: &[u8];
        let var_header_len: u16 = 0; // Placeholder, as it's not explicitly used in parsing but is part of the event structure

        // Get a cursor to move within the buffer
        let mut cur = Cursor::new(data);
        if fde.post_header_len[KnownLogEventType::WriteRowsEvent as usize - 1] == 6 {
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
        flags = cur.read_u16_le();

        // We expect the post-header length to be 10 bytes, and if it's not, we have an unsupported format.
        assert_eq!(fde.post_header_len[KnownLogEventType::WriteRowsEvent as usize - 1] as u32, ROWS_HEADER_LEN_V2);

        width = read_parse_packed_int(&mut cur).expect("Unable to parse width from packed int");
        assert_ne!(width, 0, "Width must be greater than 0");

        n_bits_len = (width + 7) as u32 / 8;
        columns_before_image = cur.read(n_bits_len as usize);

        columns_after_image = columns_before_image.as_ref();
        row = cur.read(cur.num_unread());
        Ok(WriteRowsEvent {
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
}

impl<'a> fmt::Display for WriteRowsEvent<'a> {
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

        writeln!(f, "WriteRowsEvent {{")?;
        writeln!(f, "  flags: {},", self.flags)?;
        writeln!(f, "  var_header_len: {},", self.var_header_len)?;
        writeln!(f, "  n_bits_len: {},", self.n_bits_len)?;
        writeln!(f, "  table_id: {},", self.table_id)?;
        writeln!(f, "  width: {},", self.width)?;
        writeln!(f, "  columns_before_image: \"{}\",", fmt_bytes(self.columns_before_image))?;
        writeln!(f, "  columns_after_image: \"{}\",", fmt_bytes(self.columns_after_image))?;
        writeln!(f, "  row: \"{}\",", String::from_utf8_lossy(self.row))?;
        write!(f, "}}")
    }
}

fn main() {
    let args = Args::parse();
    let buf = &mut [0u8; PAGE_SIZE as usize];
    let mut pos;

    read_page(0, &args.binlog, buf);

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

    println!("Event Log Header: {:?}", event_header);
    cur.jump((BINLOG_MAGIC_SIZE + LOG_EVENT_HEADER_LEN) as usize);

    let mut fde = match FormatDescriptionEvent::parse_format_description_event(
        &buf[(BINLOG_MAGIC_SIZE + LOG_EVENT_HEADER_LEN) as usize..event_header.log_pos as usize],
    ) {
        Ok(fde_) => fde_,
        Err(e) => {
            panic!("FormatDescriptionEvent parse error: {}", e)
        }
    };
    println!("{}", fde);
    cur.jump(event_header.log_pos as usize);

    while pos < PAGE_SIZE as u32 {
        let data_buf = cur.read(LOG_EVENT_HEADER_LEN as usize);
        event_header.type_code = read_from_1(&data_buf[EVENT_TYPE_OFFSET as usize..]);

        event_header.flags = read_from_2(&data_buf[FLAGS_OFFSET as usize..]);
        event_header.when = read_from_4(data_buf);
        event_header.unmasked_server_id = read_from_4(&data_buf[SERVER_ID_OFFSET as usize..]);
        event_header.data_written = read_from_4(&data_buf[EVENT_LEN_OFFSET as usize..]);
        event_header.log_pos = read_from_4(&data_buf[LOG_POS_OFFSET as usize..]);

        let event =
            LogEventType::try_from(event_header.type_code).expect("Error parsing raw event type");

        if event_header.log_pos < PAGE_SIZE as u32 {
            event_handler(
                event,
                &buf[(pos + LOG_EVENT_HEADER_LEN) as usize..event_header.log_pos as usize],
                &mut fde,
            );
        } else {
            event_handler(
                event,
                &buf[(pos + LOG_EVENT_HEADER_LEN) as usize..],
                &mut fde,
            );
        }
        pos = event_header.log_pos;

        if pos < PAGE_SIZE as u32 {
            cur.jump(pos as usize);
        }
    }

}

/*
   Event header offsets; these point to places inside the fixed header.
*/
pub const EVENT_TYPE_OFFSET: u32 = 4;
pub const SERVER_ID_OFFSET: u32 = 5;
pub const EVENT_LEN_OFFSET: u32 = 9;
pub const LOG_POS_OFFSET: u32 = 13;
pub const FLAGS_OFFSET: u32 = 17;

/* The length of the array server_version */
pub const ST_SERVER_VER_LEN: u32 = 50;

/** start event post-header (for v3 and v4) */
// const _ST_BINLOG_VER_OFFSET: u32 = 0;
// const ST_SERVER_VER_OFFSET: u32 = 2;
// const ST_CREATED_OFFSET: u32 = ST_SERVER_VER_OFFSET + ST_SERVER_VER_LEN;
// const ST_COMMON_HEADER_LEN_OFFSET: u32 = ST_CREATED_OFFSET + 4;

pub const LOG_EVENT_HEADER_LEN: u32 = 19; /* the fixed header length */

const _LOG_EVENT_TYPES: u32 = 42;

/* 4 bytes which all binlogs should begin with */
pub const BINLOG_MAGIC_SIZE: u32 = 4;
pub const BINLOG_MAGIC: [u8; BINLOG_MAGIC_SIZE as usize] = [0xfe, 0x62, 0x69, 0x6e];

// #######
/**
  The lengths for the fixed data part of each event.
  This is a constt that provides post-header lengths for all events.
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
pub const TABLE_MAP_HEADER_LEN: u32 = 8;

const _EXECUTE_LOAD_QUERY_EXTRA_HEADER_LEN: u32 = 4 + 4 + 4 + 1;

const _EXECUTE_LOAD_QUERY_HEADER_LEN: u32 =
    _QUERY_HEADER_LEN + _EXECUTE_LOAD_QUERY_EXTRA_HEADER_LEN;

const _INCIDENT_HEADER_LEN: u32 = 2;
const _HEARTBEAT_HEADER_LEN: u32 = 0;
const _IGNORABLE_HEADER_LEN: u32 = 0;
pub const ROWS_HEADER_LEN_V2: u32 = 10;
const _TRANSACTION_CONTEXT_HEADER_LEN: u32 = 18;
const _VIEW_CHANGE_HEADER_LEN: u32 = 52;
const _XA_PREPARE_HEADER_LEN: u32 = 0;
const _TRANSACTION_PAYLOAD_HEADER_LEN: u32 = 0;
// ######
use std::fmt;

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum ColumnTypes {
    DECIMAL = 1, // This is 1 > than MYSQL_TYPE_DECIMAL
    TINY = 2,
    SHORT = 3,
    LONG = 4,
    FLOAT = 5,
    DOUBLE = 6,
    TypeNull = 7,
    TIMESTAMP = 8,
    LONGLONG = 9,
    INT24 = 10,
    DATE = 11,
    TIME = 12,
    DATETIME = 13,
    YEAR = 14,
    NEWDATE = 15,
    VARCHAR = 16,
    BIT = 17,
    TIMESTAMP2 = 18,
    DATETIME2 = 19,
    TIME2 = 20,
    NEWDECIMAL = 21,
    ENUM = 22,
    SET = 23,
    TinyBlob = 24,
    MediumBlob = 25,
    LongBlob = 26,
    BLOB = 27,
    VarString = 28,
    STRING = 29,
    GEOMETRY = 30,
    JSON = 31,
    VECTOR = 32,
}

impl From<u32> for ColumnTypes {
    fn from(value: u32) -> Self {
        match value {
            1 => ColumnTypes::DECIMAL,
            2 => ColumnTypes::TINY,
            3 => ColumnTypes::SHORT,
            4 => ColumnTypes::LONG,
            5 => ColumnTypes::FLOAT,
            6 => ColumnTypes::DOUBLE,
            7 => ColumnTypes::TypeNull,
            8 => ColumnTypes::TIMESTAMP,
            9 => ColumnTypes::LONGLONG,
            10 => ColumnTypes::INT24,
            11 => ColumnTypes::DATE,
            12 => ColumnTypes::TIME,
            13 => ColumnTypes::DATETIME,
            14 => ColumnTypes::YEAR,
            15 => ColumnTypes::NEWDATE,
            16 => ColumnTypes::VARCHAR,
            17 => ColumnTypes::BIT,
            18 => ColumnTypes::TIMESTAMP2,
            19 => ColumnTypes::DATETIME2,
            20 => ColumnTypes::TIME2,
            21 => ColumnTypes::NEWDECIMAL,
            22 => ColumnTypes::ENUM,
            23 => ColumnTypes::SET,
            24 => ColumnTypes::TinyBlob,
            25 => ColumnTypes::MediumBlob,
            26 => ColumnTypes::LongBlob,
            27 => ColumnTypes::BLOB,
            28 => ColumnTypes::VarString,
            29 => ColumnTypes::STRING,
            30 => ColumnTypes::GEOMETRY,
            31 => ColumnTypes::JSON,
            32 => ColumnTypes::VECTOR,
            _ => panic!("Unknown column type: {}", value),
        }
    }
}

pub fn get_fixed_column_size(col_type: ColumnTypes) -> u32 {
    match col_type {
        ColumnTypes::TINY => 1,
        ColumnTypes::SHORT => 2,
        ColumnTypes::LONG => 4,
        ColumnTypes::FLOAT => 4,
        ColumnTypes::DOUBLE => 8,
        ColumnTypes::TypeNull => 0,
        ColumnTypes::TIMESTAMP => 4,
        ColumnTypes::LONGLONG => 8,
        ColumnTypes::INT24 => 3,
        // Recheck these
        ColumnTypes::DATE => 3,
        ColumnTypes::TIME => 3,
        ColumnTypes::DATETIME => 8,
        ColumnTypes::YEAR => 1,
        ColumnTypes::NEWDATE => 3,
        _ => u32::MAX, // Variable length
    }
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

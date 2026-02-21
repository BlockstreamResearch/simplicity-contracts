use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value as JsonValue;
use wallet_abi_transport::wa_relay::{WalletAbiRelayDirection, WalletAbiRelayRole};

const INIT_MIGRATION_SQL: &str = include_str!("migrations/0001_init.sql");

#[derive(Debug, Clone, Serialize)]
pub struct PairingRecord {
    pub pairing_id: String,
    pub origin: String,
    pub request_id: String,
    pub network: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: String,
    pub web_connected_at_ms: Option<u64>,
    pub phone_connected_at_ms: Option<u64>,
    pub closed_at_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageRecord {
    pub id: i64,
    pub pairing_id: String,
    pub direction: WalletAbiRelayDirection,
    pub msg_id: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub created_at_ms: u64,
    pub acked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub id: i64,
    pub pairing_id: String,
    pub event_type: String,
    pub detail_json: JsonValue,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairingSnapshot {
    pub pairing: PairingRecord,
    pub messages: Vec<MessageRecord>,
    pub events: Vec<EventRecord>,
}

#[derive(Debug, Clone)]
pub struct CreatePairingInput {
    pub pairing_id: String,
    pub origin: String,
    pub request_id: String,
    pub network: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: String,
}

#[derive(Debug, Clone, Copy)]
pub struct MessageCounts {
    pub web_to_phone: u64,
    pub phone_to_web: u64,
}

#[derive(Debug, Clone)]
pub struct InsertMessageInput {
    pub pairing_id: String,
    pub direction: WalletAbiRelayDirection,
    pub msg_id: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SqliteStore {
    db_path: PathBuf,
}

impl SqliteStore {
    pub fn new(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create database parent dir '{}'",
                    parent.display()
                )
            })?;
        }

        let conn = Connection::open(&db_path)
            .with_context(|| format!("failed to open sqlite database '{}'", db_path.display()))?;
        conn.execute_batch(INIT_MIGRATION_SQL)
            .context("failed to apply initial sqlite migration")?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .context("failed to enable foreign keys")?;

        Ok(Self { db_path })
    }

    fn connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path).with_context(|| {
            format!(
                "failed to open sqlite database '{}'",
                self.db_path.display()
            )
        })?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .context("failed to enable foreign keys")?;
        Ok(conn)
    }

    pub fn create_pairing(&self, input: &CreatePairingInput) -> Result<PairingRecord> {
        let conn = self.connection()?;

        conn.execute(
            "INSERT INTO pairings (
                pairing_id, origin, request_id, network,
                created_at_ms, expires_at_ms, state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                input.pairing_id,
                input.origin,
                input.request_id,
                input.network,
                to_i64(input.created_at_ms)?,
                to_i64(input.expires_at_ms)?,
                input.state
            ],
        )
        .context("failed to insert pairing")?;

        self.get_pairing(&input.pairing_id)?
            .ok_or_else(|| anyhow!("inserted pairing but failed to fetch it back"))
    }

    pub fn get_pairing(&self, pairing_id: &str) -> Result<Option<PairingRecord>> {
        let conn = self.connection()?;

        let mut stmt = conn.prepare(
            "SELECT
                pairing_id, origin, request_id, network,
                created_at_ms, expires_at_ms, state,
                web_connected_at_ms, phone_connected_at_ms,
                closed_at_ms, last_error
             FROM pairings
             WHERE pairing_id = ?1",
        )?;

        stmt.query_row(params![pairing_id], row_to_pairing)
            .optional()
            .context("failed to fetch pairing")
    }

    pub fn set_state(
        &self,
        pairing_id: &str,
        state: &str,
        closed_at_ms: Option<u64>,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.connection()?;

        conn.execute(
            "UPDATE pairings
             SET state = ?2,
                 closed_at_ms = COALESCE(?3, closed_at_ms),
                 last_error = ?4
             WHERE pairing_id = ?1",
            params![
                pairing_id,
                state,
                opt_i64(closed_at_ms)?,
                last_error.map(ToString::to_string)
            ],
        )
        .with_context(|| format!("failed to update state for pairing '{pairing_id}'"))?;

        Ok(())
    }

    pub fn set_last_error(&self, pairing_id: &str, last_error: Option<&str>) -> Result<()> {
        let conn = self.connection()?;

        conn.execute(
            "UPDATE pairings
             SET last_error = ?2
             WHERE pairing_id = ?1",
            params![pairing_id, last_error.map(ToString::to_string)],
        )
        .with_context(|| format!("failed to update last_error for pairing '{pairing_id}'"))?;

        Ok(())
    }

    pub fn mark_peer_connected(
        &self,
        pairing_id: &str,
        role: WalletAbiRelayRole,
        connected_at_ms: u64,
    ) -> Result<()> {
        let conn = self.connection()?;
        let value = to_i64(connected_at_ms)?;

        let sql = match role {
            WalletAbiRelayRole::Web => {
                "UPDATE pairings SET web_connected_at_ms = ?2 WHERE pairing_id = ?1"
            }
            WalletAbiRelayRole::Phone => {
                "UPDATE pairings SET phone_connected_at_ms = ?2 WHERE pairing_id = ?1"
            }
        };

        conn.execute(sql, params![pairing_id, value])
            .with_context(|| format!("failed to mark peer connected for pairing '{pairing_id}'"))?;

        Ok(())
    }

    pub fn insert_message(&self, input: &InsertMessageInput) -> Result<MessageRecord> {
        let conn = self.connection()?;

        conn.execute(
            "INSERT INTO messages (
                pairing_id, direction, msg_id, nonce_b64,
                ciphertext_b64, created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                input.pairing_id,
                direction_to_string(input.direction),
                input.msg_id,
                input.nonce_b64,
                input.ciphertext_b64,
                to_i64(input.created_at_ms)?
            ],
        )
        .with_context(|| format!("failed to insert message '{}'", input.msg_id))?;

        let id = conn.last_insert_rowid();

        Ok(MessageRecord {
            id,
            pairing_id: input.pairing_id.clone(),
            direction: input.direction,
            msg_id: input.msg_id.clone(),
            nonce_b64: input.nonce_b64.clone(),
            ciphertext_b64: input.ciphertext_b64.clone(),
            created_at_ms: input.created_at_ms,
            acked_at_ms: None,
        })
    }

    pub fn mark_message_acked(
        &self,
        pairing_id: &str,
        msg_id: &str,
        acked_at_ms: u64,
    ) -> Result<()> {
        let conn = self.connection()?;

        conn.execute(
            "UPDATE messages
             SET acked_at_ms = ?3
             WHERE pairing_id = ?1 AND msg_id = ?2",
            params![pairing_id, msg_id, to_i64(acked_at_ms)?],
        )
        .with_context(|| format!("failed to ack msg '{msg_id}' for pairing '{pairing_id}'"))?;

        Ok(())
    }

    pub fn message_counts(&self, pairing_id: &str) -> Result<MessageCounts> {
        let conn = self.connection()?;

        let web_to_phone: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE pairing_id = ?1 AND direction = 'web_to_phone'",
                params![pairing_id],
                |row| row.get(0),
            )
            .context("failed to count web_to_phone messages")?;

        let phone_to_web: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE pairing_id = ?1 AND direction = 'phone_to_web'",
                params![pairing_id],
                |row| row.get(0),
            )
            .context("failed to count phone_to_web messages")?;

        Ok(MessageCounts {
            web_to_phone: u64::try_from(web_to_phone).context("web_to_phone count overflow")?,
            phone_to_web: u64::try_from(phone_to_web).context("phone_to_web count overflow")?,
        })
    }

    pub fn messages_by_direction(
        &self,
        pairing_id: &str,
        direction: WalletAbiRelayDirection,
    ) -> Result<Vec<MessageRecord>> {
        let conn = self.connection()?;

        let mut stmt = conn.prepare(
            "SELECT
                id, pairing_id, direction, msg_id,
                nonce_b64, ciphertext_b64,
                created_at_ms, acked_at_ms
             FROM messages
             WHERE pairing_id = ?1 AND direction = ?2
             ORDER BY id ASC",
        )?;

        let rows = stmt.query_map(
            params![pairing_id, direction_to_string(direction)],
            row_to_message,
        )?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to fetch messages by direction")
    }

    pub fn add_event(
        &self,
        pairing_id: &str,
        event_type: &str,
        detail_json: &JsonValue,
        created_at_ms: u64,
    ) -> Result<()> {
        let conn = self.connection()?;

        conn.execute(
            "INSERT INTO events (pairing_id, event_type, detail_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                pairing_id,
                event_type,
                serde_json::to_string(detail_json).context("failed to serialize event details")?,
                to_i64(created_at_ms)?
            ],
        )
        .with_context(|| format!("failed to insert event '{event_type}'"))?;

        Ok(())
    }

    pub fn pairing_snapshot(&self, pairing_id: &str) -> Result<Option<PairingSnapshot>> {
        let pairing = match self.get_pairing(pairing_id)? {
            Some(value) => value,
            None => return Ok(None),
        };

        let conn = self.connection()?;

        let mut message_stmt = conn.prepare(
            "SELECT
                id, pairing_id, direction, msg_id,
                nonce_b64, ciphertext_b64,
                created_at_ms, acked_at_ms
             FROM messages
             WHERE pairing_id = ?1
             ORDER BY id ASC",
        )?;

        let messages = message_stmt
            .query_map(params![pairing_id], row_to_message)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to read pairing messages")?;

        let mut event_stmt = conn.prepare(
            "SELECT
                id, pairing_id, event_type, detail_json, created_at_ms
             FROM events
             WHERE pairing_id = ?1
             ORDER BY id ASC",
        )?;

        let events = event_stmt
            .query_map(params![pairing_id], row_to_event)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to read pairing events")?;

        Ok(Some(PairingSnapshot {
            pairing,
            messages,
            events,
        }))
    }

    pub fn expire_pairings(&self, now_ms: u64) -> Result<Vec<String>> {
        let conn = self.connection()?;

        let mut stmt = conn.prepare(
            "SELECT pairing_id
             FROM pairings
             WHERE expires_at_ms < ?1
               AND state NOT IN ('closed', 'expired')",
        )?;

        let expired_ids = stmt
            .query_map(params![to_i64(now_ms)?], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to query expired pairings")?;

        if expired_ids.is_empty() {
            return Ok(expired_ids);
        }

        conn.execute(
            "UPDATE pairings
             SET state = 'expired', closed_at_ms = ?1
             WHERE expires_at_ms < ?1
               AND state NOT IN ('closed', 'expired')",
            params![to_i64(now_ms)?],
        )
        .context("failed to mark pairings as expired")?;

        Ok(expired_ids)
    }

    pub fn prune_events(&self, older_than_ms: u64) -> Result<usize> {
        let conn = self.connection()?;

        let deleted = conn
            .execute(
                "DELETE FROM events WHERE created_at_ms < ?1",
                params![to_i64(older_than_ms)?],
            )
            .context("failed to prune old events")?;

        Ok(deleted)
    }
}

fn row_to_pairing(row: &rusqlite::Row<'_>) -> rusqlite::Result<PairingRecord> {
    Ok(PairingRecord {
        pairing_id: row.get(0)?,
        origin: row.get(1)?,
        request_id: row.get(2)?,
        network: row.get(3)?,
        created_at_ms: row.get::<_, u64>(4)?,
        expires_at_ms: row.get::<_, u64>(5)?,
        state: row.get(6)?,
        web_connected_at_ms: row.get(7)?,
        phone_connected_at_ms: row.get(8)?,
        closed_at_ms: row.get(9)?,
        last_error: row.get(10)?,
    })
}

fn row_to_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRecord> {
    let direction_raw: String = row.get(2)?;

    Ok(MessageRecord {
        id: row.get(0)?,
        pairing_id: row.get(1)?,
        direction: parse_direction(&direction_raw)?,
        msg_id: row.get(3)?,
        nonce_b64: row.get(4)?,
        ciphertext_b64: row.get(5)?,
        created_at_ms: row.get::<_, u64>(6)?,
        acked_at_ms: row.get(7)?,
    })
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRecord> {
    let detail_json_text: String = row.get(3)?;
    let detail_json = serde_json::from_str(&detail_json_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;

    Ok(EventRecord {
        id: row.get(0)?,
        pairing_id: row.get(1)?,
        event_type: row.get(2)?,
        detail_json,
        created_at_ms: row.get::<_, u64>(4)?,
    })
}

fn parse_direction(raw: &str) -> rusqlite::Result<WalletAbiRelayDirection> {
    match raw {
        "web_to_phone" => Ok(WalletAbiRelayDirection::WebToPhone),
        "phone_to_web" => Ok(WalletAbiRelayDirection::PhoneToWeb),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid stored direction '{raw}'"),
            )),
        )),
    }
}

const fn direction_to_string(direction: WalletAbiRelayDirection) -> &'static str {
    match direction {
        WalletAbiRelayDirection::WebToPhone => "web_to_phone",
        WalletAbiRelayDirection::PhoneToWeb => "phone_to_web",
    }
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).context("u64 timestamp does not fit into i64")
}

fn opt_i64(value: Option<u64>) -> Result<Option<i64>> {
    value.map(to_i64).transpose()
}

pub fn is_sqlite_unique_violation(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<rusqlite::Error>()
        .and_then(|err| match err {
            rusqlite::Error::SqliteFailure(code, _) => Some(code.extended_code),
            _ => None,
        })
        == Some(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
}

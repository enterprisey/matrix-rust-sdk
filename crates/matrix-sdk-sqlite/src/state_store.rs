use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use deadpool_sqlite::{Object as SqliteConn, Pool as SqlitePool, Runtime};
use matrix_sdk_base::{
    media::MediaRequest,
    store::{Result as StoreResult, StoreError as StateStoreError},
    RoomInfo, StateStore,
};
use matrix_sdk_store_encryption::StoreCipher;
use ruma::{
    events::{
        receipt::ReceiptType, AnyGlobalAccountDataEvent, AnyRoomAccountDataEvent,
        GlobalAccountDataEventType, RoomAccountDataEventType,
    },
    serde::Raw,
    OwnedUserId,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::fs;
use tracing::{debug, error};

use crate::{
    get_or_create_store_cipher,
    utils::{Key, SqliteObjectExt},
    OpenStoreError, SqliteObjectStoreExt,
};

#[derive(Debug)]
enum Error {
    Store(StateStoreError),
    Sqlite(rusqlite::Error),
    Pool(deadpool_sqlite::PoolError),
}

impl From<StateStoreError> for Error {
    fn from(value: StateStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<deadpool_sqlite::PoolError> for Error {
    fn from(value: deadpool_sqlite::PoolError) -> Self {
        Self::Pool(value)
    }
}

impl From<Error> for StateStoreError {
    fn from(value: Error) -> Self {
        match value {
            Error::Store(c) => c,
            Error::Sqlite(b) => StateStoreError::backend(b),
            Error::Pool(b) => StateStoreError::backend(b),
        }
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// A sqlite based cryptostore.
#[derive(Clone)]
pub struct SqliteStateStore {
    store_cipher: Option<Arc<StoreCipher>>,
    path: Option<PathBuf>,
    pool: SqlitePool,
}

impl fmt::Debug for SqliteStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            f.debug_struct("SqliteStateStore").field("path", &path).finish()
        } else {
            f.debug_struct("SqliteStateStore").field("path", &"memory store").finish()
        }
    }
}

impl SqliteStateStore {
    /// Open the sqlite-based crypto store at the given path using the given
    /// passphrase to encrypt private data.
    pub async fn open(
        path: impl AsRef<Path>,
        passphrase: Option<&str>,
    ) -> Result<Self, OpenStoreError> {
        let path = path.as_ref();
        fs::create_dir_all(path).await.map_err(StateStoreError::from)?;
        let cfg = deadpool_sqlite::Config::new(path.join("matrix-sdk-crypto.sqlite3"));
        let pool = cfg.create_pool(Runtime::Tokio1)?;

        Self::open_with_pool(pool, passphrase).await
    }

    /// Create a sqlite-based crypto store using the given sqlite database pool.
    /// The given passphrase will be used to encrypt private data.
    pub async fn open_with_pool(
        pool: SqlitePool,
        passphrase: Option<&str>,
    ) -> Result<Self, OpenStoreError> {
        let conn = pool.get().await.map_err(StateStoreError::backend)?;
        run_migrations(&conn).await.map_err(StateStoreError::from)?;
        let store_cipher = match passphrase {
            Some(p) => Some(Arc::new(get_or_create_store_cipher(p, &conn).await?)),
            None => None,
        };

        Ok(Self { store_cipher, path: None, pool })
    }

    fn serialize_value(&self, value: &impl Serialize) -> Result<Vec<u8>, StateStoreError> {
        let serialized = rmp_serde::to_vec_named(value).map_err(StateStoreError::backend)?;

        if let Some(key) = &self.store_cipher {
            let encrypted = key.encrypt_value_data(serialized).map_err(StateStoreError::backend)?;
            rmp_serde::to_vec_named(&encrypted).map_err(StateStoreError::backend)
        } else {
            Ok(serialized)
        }
    }

    fn deserialize_value<T: DeserializeOwned>(&self, value: &[u8]) -> Result<T, StateStoreError> {
        if let Some(key) = &self.store_cipher {
            let encrypted = rmp_serde::from_slice(value).map_err(StateStoreError::backend)?;
            let decrypted = key.decrypt_value_data(encrypted).map_err(StateStoreError::backend)?;

            rmp_serde::from_slice(&decrypted).map_err(StateStoreError::backend)
        } else {
            rmp_serde::from_slice(value).map_err(StateStoreError::backend)
        }
    }

    fn encode_key(&self, table_name: &str, key: impl AsRef<[u8]>) -> Key {
        let bytes = key.as_ref();
        if let Some(store_cipher) = &self.store_cipher {
            Key::Hashed(store_cipher.hash_key(table_name, bytes))
        } else {
            Key::Plain(bytes.to_owned())
        }
    }

    async fn acquire(&self) -> Result<deadpool_sqlite::Object> {
        Ok(self.pool.get().await?)
    }
}

const DATABASE_VERSION: u8 = 1;

async fn run_migrations(conn: &SqliteConn) -> Result<()> {
    let kv_exists = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'kv'",
            (),
            |row| row.get::<_, u32>(0),
        )
        .await?
        > 0;

    let version = if kv_exists {
        match conn.get_kv("version").await?.as_deref() {
            Some([v]) => *v,
            Some(_) => {
                error!("version database field has multiple bytes");
                return Ok(());
            }
            None => {
                error!("version database field is missing");
                return Ok(());
            }
        }
    } else {
        0
    };

    if version == 0 {
        debug!("Creating database");
    } else if version < DATABASE_VERSION {
        debug!(version, new_version = DATABASE_VERSION, "Upgrading database");
    }

    if version < 1 {
        // First turn on WAL mode, this can't be done in the transaction, it fails with
        // the error message: "cannot change into wal mode from within a transaction".
        conn.execute_batch("PRAGMA journal_mode = wal;").await?;
        conn.with_transaction(|txn| txn.execute_batch(include_str!("../migrations/001_init.sql")))
            .await?;
    }

    conn.set_kv("version", vec![DATABASE_VERSION]).await?;

    Ok(())
}

#[async_trait]
impl StateStore for SqliteStateStore {
    async fn save_filter(&self, filter_name: &str, filter_id: &str) -> StoreResult<()> {
        todo!()
    }

    async fn save_changes(&self, changes: &matrix_sdk_base::StateChanges) -> StoreResult<()> {
        todo!()
    }

    async fn get_filter(&self, filter_name: &str) -> StoreResult<Option<String>> {
        todo!()
    }

    async fn get_sync_token(&self) -> StoreResult<Option<String>> {
        todo!()
    }

    async fn get_presence_event(
        &self,
        user_id: &ruma::UserId,
    ) -> StoreResult<Option<Raw<ruma::events::presence::PresenceEvent>>> {
        todo!()
    }

    async fn get_state_event(
        &self,
        room_id: &ruma::RoomId,
        event_type: ruma::events::StateEventType,
        state_key: &str,
    ) -> StoreResult<Option<Raw<ruma::events::AnySyncStateEvent>>> {
        todo!()
    }

    async fn get_state_events(
        &self,
        room_id: &ruma::RoomId,
        event_type: ruma::events::StateEventType,
    ) -> StoreResult<Vec<Raw<ruma::events::AnySyncStateEvent>>> {
        todo!()
    }

    async fn get_profile(
        &self,
        room_id: &ruma::RoomId,
        user_id: &ruma::UserId,
    ) -> StoreResult<Option<matrix_sdk_base::MinimalRoomMemberEvent>> {
        todo!()
    }

    async fn get_member_event(
        &self,
        room_id: &ruma::RoomId,
        state_key: &ruma::UserId,
    ) -> StoreResult<Option<matrix_sdk_base::deserialized_responses::RawMemberEvent>> {
        todo!()
    }

    async fn get_user_ids(&self, room_id: &ruma::RoomId) -> StoreResult<Vec<OwnedUserId>> {
        todo!()
    }

    async fn get_invited_user_ids(&self, room_id: &ruma::RoomId) -> StoreResult<Vec<OwnedUserId>> {
        todo!()
    }

    async fn get_joined_user_ids(&self, room_id: &ruma::RoomId) -> StoreResult<Vec<OwnedUserId>> {
        todo!()
    }

    async fn get_room_infos(&self) -> StoreResult<Vec<RoomInfo>> {
        todo!()
    }

    async fn get_stripped_room_infos(&self) -> StoreResult<Vec<RoomInfo>> {
        todo!()
    }

    async fn get_users_with_display_name(
        &self,
        room_id: &ruma::RoomId,
        display_name: &str,
    ) -> StoreResult<BTreeSet<OwnedUserId>> {
        todo!()
    }

    async fn get_account_data_event(
        &self,
        event_type: GlobalAccountDataEventType,
    ) -> StoreResult<Option<Raw<AnyGlobalAccountDataEvent>>> {
        todo!()
    }

    async fn get_room_account_data_event(
        &self,
        room_id: &ruma::RoomId,
        event_type: RoomAccountDataEventType,
    ) -> StoreResult<Option<Raw<AnyRoomAccountDataEvent>>> {
        todo!()
    }

    async fn get_user_room_receipt_event(
        &self,
        room_id: &ruma::RoomId,
        receipt_type: ReceiptType,
        user_id: &ruma::UserId,
    ) -> StoreResult<Option<(ruma::OwnedEventId, ruma::events::receipt::Receipt)>> {
        todo!()
    }

    async fn get_event_room_receipt_events(
        &self,
        room_id: &ruma::RoomId,
        receipt_type: ReceiptType,
        event_id: &ruma::EventId,
    ) -> StoreResult<Vec<(OwnedUserId, ruma::events::receipt::Receipt)>> {
        todo!()
    }

    async fn get_custom_value(&self, key: &[u8]) -> StoreResult<Option<Vec<u8>>> {
        todo!()
    }

    async fn set_custom_value(&self, key: &[u8], value: Vec<u8>) -> StoreResult<Option<Vec<u8>>> {
        todo!()
    }

    async fn add_media_content(&self, request: &MediaRequest, content: Vec<u8>) -> StoreResult<()> {
        todo!()
    }

    async fn get_media_content(&self, request: &MediaRequest) -> StoreResult<Option<Vec<u8>>> {
        todo!()
    }

    async fn remove_media_content(&self, request: &MediaRequest) -> StoreResult<()> {
        todo!()
    }

    async fn remove_media_content_for_uri(&self, uri: &ruma::MxcUri) -> StoreResult<()> {
        todo!()
    }

    async fn remove_room(&self, room_id: &ruma::RoomId) -> StoreResult<()> {
        todo!()
    }
}

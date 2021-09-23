// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code, missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use matrix_sdk_common::{locks::RwLock, uuid::Uuid};
use ruma::{api::client::r0::backup::RoomKeyBackup, RoomId};
use tracing::{debug, info, warn};

use crate::{
    olm::{Account, InboundGroupSession},
    store::{BackupKeys, Changes, RoomKeyCounts, Store},
    CryptoStoreError, KeysBackupRequest, OutgoingRequest,
};

mod keys;

pub use keys::{DecodeError, MegolmV1BackupKey, PickledRecoveryKey, RecoveryKey};

/// TODO
#[derive(Debug, Clone)]
pub struct BackupMachine {
    account: Account,
    store: Store,
    backup_key: Arc<RwLock<Option<MegolmV1BackupKey>>>,
    pending_backup: Arc<RwLock<Option<PendingBackup>>>,
}

#[derive(Debug, Clone)]
struct PendingBackup {
    request_id: Uuid,
    request: KeysBackupRequest,
    sessions: BTreeMap<RoomId, BTreeMap<String, BTreeSet<String>>>,
}

impl PendingBackup {
    fn session_was_part_of_the_backup(&self, session: &InboundGroupSession) -> bool {
        self.sessions
            .get(session.room_id())
            .and_then(|r| r.get(session.sender_key()).map(|s| s.contains(session.session_id())))
            .unwrap_or(false)
    }
}

impl From<PendingBackup> for OutgoingRequest {
    fn from(b: PendingBackup) -> Self {
        OutgoingRequest { request_id: b.request_id, request: Arc::new(b.request.into()) }.into()
    }
}

impl BackupMachine {
    const BACKUP_BATCH_SIZE: usize = 100;

    pub(crate) fn new(
        account: Account,
        store: Store,
        backup_key: Option<MegolmV1BackupKey>,
    ) -> Self {
        Self {
            account,
            store,
            backup_key: RwLock::new(backup_key).into(),
            pending_backup: RwLock::new(None).into(),
        }
    }

    /// TODO
    pub async fn enable_backup(&self, key: MegolmV1BackupKey) -> Result<(), CryptoStoreError> {
        if key.backup_version().is_some() {
            *self.backup_key.write().await = Some(key.clone());
            info!(backup_key =? key, "Activated a backup");
        } else {
            warn!(backup_key =? key, "Tried to activate a backup without having the backup key uploaded");
        }

        Ok(())
    }

    /// TODO
    pub async fn room_key_counts(&self) -> Result<RoomKeyCounts, CryptoStoreError> {
        self.store.inbound_group_session_counts().await
    }

    /// TODO
    pub async fn disable_backup(&self) -> Result<(), CryptoStoreError> {
        self.backup_key.write().await.take();
        self.pending_backup.write().await.take();

        self.store.reset_backup_state().await?;

        Ok(())
    }

    /// TODO
    pub async fn save_recovery_key(
        &self,
        recovery_key: Option<RecoveryKey>,
        version: Option<String>,
    ) -> Result<(), CryptoStoreError> {
        let mut changes = Changes::default();

        changes.recovery_key = recovery_key;
        changes.backup_version = version;

        self.store.save_changes(changes).await
    }

    /// TODO
    pub async fn get_backup_keys(&self) -> Result<BackupKeys, CryptoStoreError> {
        self.store.load_backup_keys().await
    }

    /// TODO
    pub async fn backup(&self) -> Result<Option<OutgoingRequest>, CryptoStoreError> {
        if let Some(request) = &*self.pending_backup.read().await {
            Ok(Some(request.clone().into()))
        } else {
            let request = self.backup_helper().await?;
            *self.pending_backup.write().await = request.clone();

            Ok(request.map(|r| r.into()))
        }
    }

    pub(crate) async fn mark_request_as_sent(
        &self,
        request_id: Uuid,
    ) -> Result<(), CryptoStoreError> {
        let mut request = self.pending_backup.write().await;

        if let Some(r) = &*request {
            if r.request_id == request_id {
                let sessions: Vec<_> = self
                    .store
                    .get_inbound_group_sessions()
                    .await?
                    .into_iter()
                    .filter(|s| r.session_was_part_of_the_backup(s))
                    .collect();

                for session in &sessions {
                    session.mark_as_backed_up()
                }

                debug!(sessions =? r.sessions, "Marking inbound group sessions as backed up",);

                let changes = Changes { inbound_group_sessions: sessions, ..Default::default() };
                self.store.save_changes(changes).await?;

                *request = None;
            } else {
                warn!(
                    expected = r.request_id.to_string().as_str(),
                    got = request_id.to_string().as_str(),
                    "Tried to mark a pending backup as sent but the request id didn't match"
                )
            }
        } else {
            warn!(
                request_id = request_id.to_string().as_str(),
                "Tried to mark a pending backup as sent but there isn't a backup pending"
            );
        }

        Ok(())
    }

    async fn backup_helper(&self) -> Result<Option<PendingBackup>, CryptoStoreError> {
        if let Some(backup_key) = &*self.backup_key.read().await {
            if let Some(version) = backup_key.backup_version() {
                let sessions = self.store.inbound_group_sessions_for_backup().await?;

                if !sessions.is_empty() {
                    let key_count = sessions.len();
                    let (backup, session_record) = Self::backup_keys(sessions, backup_key).await;

                    let request = PendingBackup {
                        request_id: Uuid::new_v4(),
                        request: KeysBackupRequest { version, rooms: backup },
                        sessions: session_record,
                    };

                    info!(key_count = key_count, backup_key =? backup_key, "Backed up room keys");

                    Ok(Some(request))
                } else {
                    debug!(backup_key =? backup_key, "No room keys need to be backed up");
                    Ok(None)
                }
            } else {
                info!("Trying to backup room keys but the backup key wasn't uploaded");
                Ok(None)
            }
        } else {
            info!("Trying to backup room keys but no backup key was found");
            Ok(None)
        }
    }

    /// Backup all the non-backed up room keys we know about
    async fn backup_keys(
        sessions: Vec<InboundGroupSession>,
        backup_key: &MegolmV1BackupKey,
    ) -> (BTreeMap<RoomId, RoomKeyBackup>, BTreeMap<RoomId, BTreeMap<String, BTreeSet<String>>>)
    {
        let mut backup: BTreeMap<RoomId, RoomKeyBackup> = BTreeMap::new();
        let mut session_record: BTreeMap<RoomId, BTreeMap<String, BTreeSet<String>>> =
            BTreeMap::new();

        for session in sessions.into_iter().take(Self::BACKUP_BATCH_SIZE) {
            let room_id = session.room_id().to_owned();
            let session_id = session.session_id().to_owned();
            let sender_key = session.sender_key().to_owned();
            let session = backup_key.encrypt(session).await;

            session_record
                .entry(room_id.clone())
                .or_default()
                .entry(sender_key)
                .or_default()
                .insert(session_id.clone());

            backup
                .entry(room_id)
                .or_insert_with(|| RoomKeyBackup::new(BTreeMap::new()))
                .sessions
                .insert(session_id, session);
        }

        (backup, session_record)
    }
}

#[cfg(test)]
mod test {}
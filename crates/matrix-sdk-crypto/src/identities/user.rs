// Copyright 2020 The Matrix.org Foundation C.I.C.
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

use std::{
    collections::btree_map::Iter,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ruma::{
    api::client::keys::upload_signatures::v3::Request as SignatureUploadRequest,
    encryption::KeyUsage,
    events::{
        key::verification::VerificationMethod, room::message::KeyVerificationRequestEventContent,
    },
    DeviceKeyId, EventId, OwnedDeviceId, OwnedDeviceKeyId, RoomId, UserId,
};
use serde::{Deserialize, Serialize};
use tracing::error;
use vodozemac::Ed25519PublicKey;

use super::{atomic_bool_deserializer, atomic_bool_serializer};
use crate::{
    error::SignatureError,
    olm::VerifyJson,
    store::{Changes, IdentityChanges},
    types::{CrossSigningKey, DeviceKeys, Signatures, SigningKey, SigningKeys},
    verification::VerificationMachine,
    CryptoStoreError, OutgoingVerificationRequest, ReadOnlyDevice, VerificationRequest,
};

/// Enum over the different user identity types we can have.
#[derive(Debug, Clone)]
pub enum UserIdentities {
    /// Our own user identity.
    Own(OwnUserIdentity),
    /// An identity belonging to another user.
    Other(UserIdentity),
}

impl UserIdentities {
    /// Destructure the enum into an `OwnUserIdentity` if it's of the correct
    /// type.
    pub fn own(self) -> Option<OwnUserIdentity> {
        match self {
            Self::Own(i) => Some(i),
            _ => None,
        }
    }

    /// Destructure the enum into an `UserIdentity` if it's of the correct
    /// type.
    pub fn other(self) -> Option<UserIdentity> {
        match self {
            Self::Other(i) => Some(i),
            _ => None,
        }
    }
}

impl From<OwnUserIdentity> for UserIdentities {
    fn from(i: OwnUserIdentity) -> Self {
        Self::Own(i)
    }
}

impl From<UserIdentity> for UserIdentities {
    fn from(i: UserIdentity) -> Self {
        Self::Other(i)
    }
}

/// Struct representing a cross signing identity of a user.
///
/// This is the user identity of a user that is our own. Other users will
/// only contain a master key and a self signing key, meaning that only device
/// signatures can be checked with this identity.
///
/// This struct wraps a read-only version of the struct and allows verifications
/// to be requested to verify our own device with the user identity.
#[derive(Debug, Clone)]
pub struct OwnUserIdentity {
    pub(crate) inner: ReadOnlyOwnUserIdentity,
    pub(crate) verification_machine: VerificationMachine,
}

impl Deref for OwnUserIdentity {
    type Target = ReadOnlyOwnUserIdentity;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl OwnUserIdentity {
    /// Mark our user identity as verified.
    ///
    /// This will mark the identity locally as verified and sign it with our own
    /// device.
    ///
    /// Returns a signature upload request that needs to be sent out.
    pub async fn verify(&self) -> Result<SignatureUploadRequest, SignatureError> {
        self.mark_as_verified();

        let changes = Changes {
            identities: IdentityChanges { changed: vec![self.inner.clone().into()], new: vec![] },
            ..Default::default()
        };

        if let Err(e) = self.verification_machine.store.save_changes(changes).await {
            error!(error = ?e, "Couldn't store our own user identity after marking it as verified");
        }

        self.verification_machine.store.account.sign_master_key(self.master_key.clone()).await
    }

    /// Send a verification request to our other devices.
    pub async fn request_verification(
        &self,
    ) -> Result<(VerificationRequest, OutgoingVerificationRequest), CryptoStoreError> {
        self.request_verification_helper(None).await
    }

    /// Send a verification request to our other devices while specifying our
    /// supported methods.
    ///
    /// # Arguments
    ///
    /// * `methods` - The verification methods that we're supporting.
    pub async fn request_verification_with_methods(
        &self,
        methods: Vec<VerificationMethod>,
    ) -> Result<(VerificationRequest, OutgoingVerificationRequest), CryptoStoreError> {
        self.request_verification_helper(Some(methods)).await
    }

    /// Does our user identity trust our own device, i.e. have we signed  our
    /// own device keys with our self-signing key.
    pub async fn trusts_our_own_device(&self) -> Result<bool, CryptoStoreError> {
        Ok(if let Some(signatures) = self.verification_machine.store.device_signatures().await? {
            let mut device_keys = self.verification_machine.store.account.device_keys().await;
            device_keys.signatures = signatures;

            self.inner.self_signing_key().verify_device_keys(&device_keys).is_ok()
        } else {
            false
        })
    }

    async fn request_verification_helper(
        &self,
        methods: Option<Vec<VerificationMethod>>,
    ) -> Result<(VerificationRequest, OutgoingVerificationRequest), CryptoStoreError> {
        let devices: Vec<OwnedDeviceId> = self
            .verification_machine
            .store
            .get_user_devices(self.user_id())
            .await?
            .into_keys()
            .filter(|d| &**d != self.verification_machine.own_device_id())
            .collect();

        Ok(self
            .verification_machine
            .request_to_device_verification(self.user_id(), devices, methods)
            .await)
    }
}

/// Struct representing a cross signing identity of a user.
///
/// This is the user identity of a user that isn't our own. Other users will
/// only contain a master key and a self signing key, meaning that only device
/// signatures can be checked with this identity.
///
/// This struct wraps a read-only version of the struct and allows verifications
/// to be requested to verify our own device with the user identity.
#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub(crate) inner: ReadOnlyUserIdentity,
    pub(crate) own_identity: Option<ReadOnlyOwnUserIdentity>,
    pub(crate) verification_machine: VerificationMachine,
}

impl Deref for UserIdentity {
    type Target = ReadOnlyUserIdentity;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl UserIdentity {
    /// Is this user identity verified.
    pub fn is_verified(&self) -> bool {
        self.own_identity
            .as_ref()
            .map(|o| o.is_identity_signed(&self.inner).is_ok())
            .unwrap_or(false)
    }

    /// Manually verify this user.
    ///
    /// This method will attempt to sign the user identity using our private
    /// cross signing key.
    ///
    /// This method fails if we don't have the private part of our user-signing
    /// key.
    ///
    /// Returns a request that needs to be sent out for the user to be marked
    /// as verified.
    pub async fn verify(&self) -> Result<SignatureUploadRequest, SignatureError> {
        if self.user_id() != self.verification_machine.own_user_id() {
            Ok(self
                .verification_machine
                .store
                .private_identity
                .lock()
                .await
                .sign_user(&self.inner)
                .await?)
        } else {
            Err(SignatureError::UserIdMismatch)
        }
    }

    /// Create a `VerificationRequest` object after the verification request
    /// content has been sent out.
    pub async fn request_verification(
        &self,
        room_id: &RoomId,
        request_event_id: &EventId,
        methods: Option<Vec<VerificationMethod>>,
    ) -> VerificationRequest {
        self.verification_machine
            .request_verification(&self.inner, room_id, request_event_id, methods)
            .await
    }

    /// Send a verification request to the given user.
    ///
    /// The returned content needs to be sent out into a DM room with the given
    /// user.
    ///
    /// After the content has been sent out a `VerificationRequest` can be
    /// started with the [`request_verification()`] method.
    ///
    /// [`request_verification()`]: #method.request_verification
    pub async fn verification_request_content(
        &self,
        methods: Option<Vec<VerificationMethod>>,
    ) -> KeyVerificationRequestEventContent {
        VerificationRequest::request(
            self.verification_machine.own_user_id(),
            self.verification_machine.own_device_id(),
            self.user_id(),
            methods,
        )
    }
}

/// Wrapper for a cross signing key marking it as the master key.
///
/// Master keys are used to sign other cross signing keys, the self signing and
/// user signing keys of an user will be signed by their master key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "CrossSigningKey")]
pub struct MasterPubkey(Arc<CrossSigningKey>);

macro_rules! impl_partial_eq {
    ($key_type: ty) => {
        impl PartialEq for $key_type {
            /// The `PartialEq` implementation compares the user ID, the usage and the
            /// key material, ignoring signatures.
            ///
            /// The usage could be safely ignored since the type guarantees it has the
            /// correct usage by construction -- it is impossible to construct a
            /// value of a particular key type with an incorrect usage. However, we
            /// check it anyway, to codify the notion that the same key material
            /// with a different usage results in a logically different key.
            ///
            /// The signatures are provided by other devices and don't alter the
            /// identity of the key itself.
            fn eq(&self, other: &Self) -> bool {
                self.user_id() == other.user_id()
                    && self.keys() == other.keys()
                    && self.usage() == other.usage()
            }
        }
        impl Eq for $key_type {}
    };
}

impl_partial_eq!(MasterPubkey);
impl_partial_eq!(SelfSigningPubkey);
impl_partial_eq!(UserSigningPubkey);

/// Wrapper for a cross signing key marking it as a self signing key.
///
/// Self signing keys are used to sign the user's own devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "CrossSigningKey")]
pub struct SelfSigningPubkey(Arc<CrossSigningKey>);

/// Wrapper for a cross signing key marking it as a user signing key.
///
/// User signing keys are used to sign the master keys of other users.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "CrossSigningKey")]
pub struct UserSigningPubkey(Arc<CrossSigningKey>);

impl TryFrom<CrossSigningKey> for MasterPubkey {
    type Error = serde_json::Error;

    fn try_from(key: CrossSigningKey) -> Result<Self, Self::Error> {
        if key.usage.contains(&KeyUsage::Master) && key.usage.len() == 1 {
            Ok(Self(key.into()))
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected cross signing key usage {} was not found",
                KeyUsage::Master
            )))
        }
    }
}

impl TryFrom<CrossSigningKey> for SelfSigningPubkey {
    type Error = serde_json::Error;

    fn try_from(key: CrossSigningKey) -> Result<Self, Self::Error> {
        if key.usage.contains(&KeyUsage::SelfSigning) && key.usage.len() == 1 {
            Ok(Self(key.into()))
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected cross signing key usage {} was not found",
                KeyUsage::SelfSigning
            )))
        }
    }
}

impl TryFrom<CrossSigningKey> for UserSigningPubkey {
    type Error = serde_json::Error;

    fn try_from(key: CrossSigningKey) -> Result<Self, Self::Error> {
        if key.usage.contains(&KeyUsage::UserSigning) && key.usage.len() == 1 {
            Ok(Self(key.into()))
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected cross signing key usage {} was not found",
                KeyUsage::UserSigning
            )))
        }
    }
}

impl AsRef<CrossSigningKey> for MasterPubkey {
    fn as_ref(&self) -> &CrossSigningKey {
        &self.0
    }
}

impl AsRef<CrossSigningKey> for SelfSigningPubkey {
    fn as_ref(&self) -> &CrossSigningKey {
        &self.0
    }
}

impl AsRef<CrossSigningKey> for UserSigningPubkey {
    fn as_ref(&self) -> &CrossSigningKey {
        &self.0
    }
}

impl<'a> From<&'a SelfSigningPubkey> for CrossSigningSubKeys<'a> {
    fn from(key: &'a SelfSigningPubkey) -> Self {
        CrossSigningSubKeys::SelfSigning(key)
    }
}

impl<'a> From<&'a UserSigningPubkey> for CrossSigningSubKeys<'a> {
    fn from(key: &'a UserSigningPubkey) -> Self {
        CrossSigningSubKeys::UserSigning(key)
    }
}

/// Enum over the cross signing sub-keys.
pub(crate) enum CrossSigningSubKeys<'a> {
    /// The self signing subkey.
    SelfSigning(&'a SelfSigningPubkey),
    /// The user signing subkey.
    UserSigning(&'a UserSigningPubkey),
}

impl<'a> CrossSigningSubKeys<'a> {
    /// Get the id of the user that owns this cross signing subkey.
    fn user_id(&self) -> &UserId {
        match self {
            CrossSigningSubKeys::SelfSigning(key) => &key.0.user_id,
            CrossSigningSubKeys::UserSigning(key) => &key.0.user_id,
        }
    }

    /// Get the `CrossSigningKey` from an sub-keys enum
    pub(crate) fn cross_signing_key(&self) -> &CrossSigningKey {
        match self {
            CrossSigningSubKeys::SelfSigning(key) => &key.0,
            CrossSigningSubKeys::UserSigning(key) => &key.0,
        }
    }
}

impl MasterPubkey {
    /// Get the user id of the master key's owner.
    pub fn user_id(&self) -> &UserId {
        &self.0.user_id
    }

    /// Get the keys map of containing the master keys.
    pub fn keys(&self) -> &SigningKeys<OwnedDeviceKeyId> {
        &self.0.keys
    }

    /// Get the list of `KeyUsage` that is set for this key.
    pub fn usage(&self) -> &[KeyUsage] {
        &self.0.usage
    }

    /// Get the signatures map of this cross signing key.
    pub fn signatures(&self) -> &Signatures {
        &self.0.signatures
    }

    /// Get the master key with the given key id.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The id of the key that should be fetched.
    pub fn get_key(&self, key_id: &DeviceKeyId) -> Option<&SigningKey> {
        self.0.keys.get(key_id)
    }

    /// Get the first available master key.
    ///
    /// There's usually only a single master key so this will usually fetch the
    /// only key.
    pub fn get_first_key(&self) -> Option<Ed25519PublicKey> {
        self.0.get_first_key_and_id().map(|(_, k)| k)
    }

    /// Check if the given JSON is signed by this master key.
    ///
    /// This method should only be used if an object's signature needs to be
    /// checked multiple times, and you'd like to avoid performing the
    /// canonicalization step each time.
    ///
    /// **Note**: Use this method with caution, the `canonical_json` needs to be
    /// correctly canonicalized and make sure that the object you are checking
    /// the signature for is allowed to be signed by a master key.
    #[cfg(any(feature = "backups_v1", test))]
    pub(crate) fn has_signed_raw(
        &self,
        signatures: &Signatures,
        canonical_json: &str,
    ) -> Result<(), SignatureError> {
        if let Some((key_id, key)) = self.0.get_first_key_and_id() {
            key.verify_canonicalized_json(&self.0.user_id, key_id, signatures, canonical_json)
        } else {
            Err(SignatureError::UnsupportedAlgorithm)
        }
    }

    /// Check if the given cross signing sub-key is signed by the master key.
    ///
    /// # Arguments
    ///
    /// * `subkey` - The subkey that should be checked for a valid signature.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn verify_subkey<'a>(
        &self,
        subkey: impl Into<CrossSigningSubKeys<'a>>,
    ) -> Result<(), SignatureError> {
        let subkey: CrossSigningSubKeys<'_> = subkey.into();

        if self.0.user_id != subkey.user_id() {
            return Err(SignatureError::UserIdMismatch);
        }

        if let Some((key_id, key)) = self.0.get_first_key_and_id() {
            key.verify_json(&self.0.user_id, key_id, subkey.cross_signing_key())
        } else {
            Err(SignatureError::UnsupportedAlgorithm)
        }
    }
}

impl<'a> IntoIterator for &'a MasterPubkey {
    type Item = (&'a OwnedDeviceKeyId, &'a SigningKey);
    type IntoIter = Iter<'a, OwnedDeviceKeyId, SigningKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys().iter()
    }
}

impl UserSigningPubkey {
    /// Get the user id of the user signing key's owner.
    pub fn user_id(&self) -> &UserId {
        &self.0.user_id
    }

    /// Get the list of `KeyUsage` that is set for this key.
    pub fn usage(&self) -> &[KeyUsage] {
        &self.0.usage
    }

    /// Get the keys map of containing the user signing keys.
    pub fn keys(&self) -> &SigningKeys<OwnedDeviceKeyId> {
        &self.0.keys
    }

    /// Check if the given master key is signed by this user signing key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key that should be checked for a valid
    /// signature.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn verify_master_key(
        &self,
        master_key: &MasterPubkey,
    ) -> Result<(), SignatureError> {
        if let Some((key_id, key)) = self.0.get_first_key_and_id() {
            key.verify_json(&self.0.user_id, key_id, master_key.0.as_ref())
        } else {
            Err(SignatureError::UnsupportedAlgorithm)
        }
    }
}

impl<'a> IntoIterator for &'a UserSigningPubkey {
    type Item = (&'a OwnedDeviceKeyId, &'a SigningKey);
    type IntoIter = Iter<'a, OwnedDeviceKeyId, SigningKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys().iter()
    }
}

impl SelfSigningPubkey {
    /// Get the user id of the self signing key's owner.
    pub fn user_id(&self) -> &UserId {
        &self.0.user_id
    }

    /// Get the keys map of containing the self signing keys.
    pub fn keys(&self) -> &SigningKeys<OwnedDeviceKeyId> {
        &self.0.keys
    }

    /// Get the list of `KeyUsage` that is set for this key.
    pub fn usage(&self) -> &[KeyUsage] {
        &self.0.usage
    }

    fn verify_device_keys(&self, device_keys: &DeviceKeys) -> Result<(), SignatureError> {
        if let Some((key_id, key)) = self.0.get_first_key_and_id() {
            key.verify_json(&self.0.user_id, key_id, device_keys)
        } else {
            Err(SignatureError::UnsupportedAlgorithm)
        }
    }

    /// Check if the given device is signed by this self signing key.
    ///
    /// # Arguments
    ///
    /// * `device` - The device that should be checked for a valid signature.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn verify_device(&self, device: &ReadOnlyDevice) -> Result<(), SignatureError> {
        self.verify_device_keys(device.as_device_keys())
    }
}

impl<'a> IntoIterator for &'a SelfSigningPubkey {
    type Item = (&'a OwnedDeviceKeyId, &'a SigningKey);
    type IntoIter = Iter<'a, OwnedDeviceKeyId, SigningKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys().iter()
    }
}

/// Enum over the different user identity types we can have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadOnlyUserIdentities {
    /// Our own user identity.
    Own(ReadOnlyOwnUserIdentity),
    /// Identities of other users.
    Other(ReadOnlyUserIdentity),
}

impl From<ReadOnlyOwnUserIdentity> for ReadOnlyUserIdentities {
    fn from(identity: ReadOnlyOwnUserIdentity) -> Self {
        ReadOnlyUserIdentities::Own(identity)
    }
}

impl From<ReadOnlyUserIdentity> for ReadOnlyUserIdentities {
    fn from(identity: ReadOnlyUserIdentity) -> Self {
        ReadOnlyUserIdentities::Other(identity)
    }
}

impl ReadOnlyUserIdentities {
    /// The unique user id of this identity.
    pub fn user_id(&self) -> &UserId {
        match self {
            ReadOnlyUserIdentities::Own(i) => i.user_id(),
            ReadOnlyUserIdentities::Other(i) => i.user_id(),
        }
    }

    /// Get the master key of the identity.
    pub fn master_key(&self) -> &MasterPubkey {
        match self {
            ReadOnlyUserIdentities::Own(i) => i.master_key(),
            ReadOnlyUserIdentities::Other(i) => i.master_key(),
        }
    }

    /// Get the self-signing key of the identity.
    pub fn self_signing_key(&self) -> &SelfSigningPubkey {
        match self {
            ReadOnlyUserIdentities::Own(i) => &i.self_signing_key,
            ReadOnlyUserIdentities::Other(i) => &i.self_signing_key,
        }
    }

    /// Get the user-signing key of the identity, this is only present for our
    /// own user identity..
    pub fn user_signing_key(&self) -> Option<&UserSigningPubkey> {
        match self {
            ReadOnlyUserIdentities::Own(i) => Some(&i.user_signing_key),
            ReadOnlyUserIdentities::Other(_) => None,
        }
    }

    /// Destructure the enum into an `ReadOnlyOwnUserIdentity` if it's of the
    /// correct type.
    pub fn own(&self) -> Option<&ReadOnlyOwnUserIdentity> {
        match self {
            ReadOnlyUserIdentities::Own(i) => Some(i),
            _ => None,
        }
    }

    pub(crate) fn into_own(self) -> Option<ReadOnlyOwnUserIdentity> {
        match self {
            ReadOnlyUserIdentities::Own(i) => Some(i),
            _ => None,
        }
    }

    /// Destructure the enum into an `UserIdentity` if it's of the correct
    /// type.
    pub fn other(&self) -> Option<&ReadOnlyUserIdentity> {
        match self {
            ReadOnlyUserIdentities::Other(i) => Some(i),
            _ => None,
        }
    }
}

impl PartialEq for ReadOnlyUserIdentities {
    fn eq(&self, other: &ReadOnlyUserIdentities) -> bool {
        self.user_id() == other.user_id()
    }
}

/// Struct representing a cross signing identity of a user.
///
/// This is the user identity of a user that isn't our own. Other users will
/// only contain a master key and a self signing key, meaning that only device
/// signatures can be checked with this identity.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadOnlyUserIdentity {
    user_id: Arc<UserId>,
    pub(crate) master_key: MasterPubkey,
    self_signing_key: SelfSigningPubkey,
}

impl ReadOnlyUserIdentity {
    /// Create a new user identity with the given master and self signing key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key of the user identity.
    ///
    /// * `self signing key` - The self signing key of user identity.
    ///
    /// Returns a `SignatureError` if the self signing key fails to be correctly
    /// verified by the given master key.
    pub(crate) fn new(
        master_key: MasterPubkey,
        self_signing_key: SelfSigningPubkey,
    ) -> Result<Self, SignatureError> {
        master_key.verify_subkey(&self_signing_key)?;

        Ok(Self { user_id: (*master_key.0.user_id).into(), master_key, self_signing_key })
    }

    #[cfg(test)]
    pub(crate) async fn from_private(identity: &crate::olm::PrivateCrossSigningIdentity) -> Self {
        let master_key = identity.master_key.lock().await.as_ref().unwrap().public_key.clone();
        let self_signing_key =
            identity.self_signing_key.lock().await.as_ref().unwrap().public_key.clone();

        Self { user_id: identity.user_id().into(), master_key, self_signing_key }
    }

    /// Get the user id of this identity.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Get the public master key of the identity.
    pub fn master_key(&self) -> &MasterPubkey {
        &self.master_key
    }

    /// Get the public self-signing key of the identity.
    pub fn self_signing_key(&self) -> &SelfSigningPubkey {
        &self.self_signing_key
    }

    /// Update the identity with a new master key and self signing key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The new master key of the user identity.
    ///
    /// * `self_signing_key` - The new self signing key of user identity.
    ///
    /// Returns a `SignatureError` if we failed to update the identity.
    pub(crate) fn update(
        &mut self,
        master_key: MasterPubkey,
        self_signing_key: SelfSigningPubkey,
    ) -> Result<(), SignatureError> {
        master_key.verify_subkey(&self_signing_key)?;

        self.master_key = master_key;
        self.self_signing_key = self_signing_key;

        Ok(())
    }

    /// Check if the given device has been signed by this identity.
    ///
    /// The user_id of the user identity and the user_id of the device need to
    /// match for the signature check to succeed as we don't trust users to sign
    /// devices of other users.
    ///
    /// # Arguments
    ///
    /// * `device` - The device that should be checked for a valid signature.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn is_device_signed(&self, device: &ReadOnlyDevice) -> Result<(), SignatureError> {
        if self.user_id() != device.user_id() {
            return Err(SignatureError::UserIdMismatch);
        }

        self.self_signing_key.verify_device(device)
    }
}

/// Struct representing a cross signing identity of our own user.
///
/// This is the user identity of our own user. This user identity will contain a
/// master key, self signing key as well as a user signing key.
///
/// This identity can verify other identities as well as devices belonging to
/// the identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadOnlyOwnUserIdentity {
    user_id: Arc<UserId>,
    master_key: MasterPubkey,
    self_signing_key: SelfSigningPubkey,
    user_signing_key: UserSigningPubkey,
    #[serde(
        serialize_with = "atomic_bool_serializer",
        deserialize_with = "atomic_bool_deserializer"
    )]
    verified: Arc<AtomicBool>,
}

impl ReadOnlyOwnUserIdentity {
    /// Create a new own user identity with the given master, self signing, and
    /// user signing key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key of the user identity.
    ///
    /// * `self_signing_key` - The self signing key of user identity.
    ///
    /// * `user_signing_key` - The user signing key of user identity.
    ///
    /// Returns a `SignatureError` if the self signing key fails to be correctly
    /// verified by the given master key.
    pub(crate) fn new(
        master_key: MasterPubkey,
        self_signing_key: SelfSigningPubkey,
        user_signing_key: UserSigningPubkey,
    ) -> Result<Self, SignatureError> {
        master_key.verify_subkey(&self_signing_key)?;
        master_key.verify_subkey(&user_signing_key)?;

        Ok(Self {
            user_id: (*master_key.0.user_id).into(),
            master_key,
            self_signing_key,
            user_signing_key,
            verified: Arc::new(AtomicBool::new(false)),
        })
    }

    #[cfg(test)]
    pub(crate) async fn from_private(identity: &crate::olm::PrivateCrossSigningIdentity) -> Self {
        let master_key = identity.master_key.lock().await.as_ref().unwrap().public_key.clone();
        let self_signing_key =
            identity.self_signing_key.lock().await.as_ref().unwrap().public_key.clone();
        let user_signing_key =
            identity.user_signing_key.lock().await.as_ref().unwrap().public_key.clone();

        Self {
            user_id: identity.user_id().into(),
            master_key,
            self_signing_key,
            user_signing_key,
            verified: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the user id of this identity.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Get the public master key of the identity.
    pub fn master_key(&self) -> &MasterPubkey {
        &self.master_key
    }

    /// Get the public self-signing key of the identity.
    pub fn self_signing_key(&self) -> &SelfSigningPubkey {
        &self.self_signing_key
    }

    /// Get the public user-signing key of the identity.
    pub fn user_signing_key(&self) -> &UserSigningPubkey {
        &self.user_signing_key
    }

    /// Check if the given identity has been signed by this identity.
    ///
    /// # Arguments
    ///
    /// * `identity` - The identity of another user that we want to check if
    /// it's has been signed.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn is_identity_signed(
        &self,
        identity: &ReadOnlyUserIdentity,
    ) -> Result<(), SignatureError> {
        self.user_signing_key.verify_master_key(&identity.master_key)
    }

    /// Check if the given device has been signed by this identity.
    ///
    /// Only devices of our own user should be checked with this method, if a
    /// device of a different user is given the signature check will always fail
    /// even if a valid signature exists.
    ///
    /// # Arguments
    ///
    /// * `device` - The device that should be checked for a valid signature.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn is_device_signed(&self, device: &ReadOnlyDevice) -> Result<(), SignatureError> {
        if self.user_id() != device.user_id() {
            return Err(SignatureError::UserIdMismatch);
        }

        self.self_signing_key.verify_device(device)
    }

    /// Mark our identity as verified.
    pub fn mark_as_verified(&self) {
        self.verified.store(true, Ordering::SeqCst)
    }

    /// Check if our identity is verified.
    pub fn is_verified(&self) -> bool {
        self.verified.load(Ordering::SeqCst)
    }

    /// Update the identity with a new master key and self signing key.
    ///
    /// Note: This will reset the verification state if the master keys differ.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The new master key of the user identity.
    ///
    /// * `self_signing_key` - The new self signing key of user identity.
    ///
    /// * `user_signing_key` - The new user signing key of user identity.
    ///
    /// Returns a `SignatureError` if we failed to update the identity.
    pub(crate) fn update(
        &mut self,
        master_key: MasterPubkey,
        self_signing_key: SelfSigningPubkey,
        user_signing_key: UserSigningPubkey,
    ) -> Result<(), SignatureError> {
        master_key.verify_subkey(&self_signing_key)?;
        master_key.verify_subkey(&user_signing_key)?;

        self.self_signing_key = self_signing_key;
        self.user_signing_key = user_signing_key;

        if self.master_key != master_key {
            self.verified.store(false, Ordering::SeqCst);
        }

        self.master_key = master_key;

        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
pub(crate) mod testing {
    //! Testing Facilities
    #![allow(dead_code)]
    use ruma::{api::client::keys::get_keys::v3::Response as KeyQueryResponse, user_id};

    use super::{ReadOnlyOwnUserIdentity, ReadOnlyUserIdentity};
    #[cfg(test)]
    use crate::{identities::manager::testing::other_user_id, olm::PrivateCrossSigningIdentity};
    use crate::{
        identities::{
            manager::testing::{other_key_query, own_key_query},
            ReadOnlyDevice,
        },
        types::CrossSigningKey,
    };

    /// Generate test devices from KeyQueryResponse
    pub fn device(response: &KeyQueryResponse) -> (ReadOnlyDevice, ReadOnlyDevice) {
        let mut devices = response.device_keys.values().next().unwrap().values();
        let first =
            ReadOnlyDevice::try_from(&devices.next().unwrap().deserialize_as().unwrap()).unwrap();
        let second =
            ReadOnlyDevice::try_from(&devices.next().unwrap().deserialize_as().unwrap()).unwrap();
        (first, second)
    }

    /// Generate ReadOnlyOwnUserIdentity from KeyQueryResponse for testing
    pub fn own_identity(response: &KeyQueryResponse) -> ReadOnlyOwnUserIdentity {
        let user_id = user_id!("@example:localhost");

        let master_key: CrossSigningKey =
            response.master_keys.get(user_id).unwrap().deserialize_as().unwrap();
        let user_signing: CrossSigningKey =
            response.user_signing_keys.get(user_id).unwrap().deserialize_as().unwrap();
        let self_signing: CrossSigningKey =
            response.self_signing_keys.get(user_id).unwrap().deserialize_as().unwrap();

        ReadOnlyOwnUserIdentity::new(
            master_key.try_into().unwrap(),
            self_signing.try_into().unwrap(),
            user_signing.try_into().unwrap(),
        )
        .unwrap()
    }

    /// Generate default own identity for tests
    pub fn get_own_identity() -> ReadOnlyOwnUserIdentity {
        own_identity(&own_key_query())
    }

    /// Generate default other "own" identity for tests
    #[cfg(test)]
    pub async fn get_other_own_identity() -> ReadOnlyOwnUserIdentity {
        let private_identity = PrivateCrossSigningIdentity::new(other_user_id().into()).await;
        ReadOnlyOwnUserIdentity::from_private(&private_identity).await
    }

    /// Generate default other identify for tests
    pub fn get_other_identity() -> ReadOnlyUserIdentity {
        let user_id = user_id!("@example2:localhost");
        let response = other_key_query();

        let master_key: CrossSigningKey =
            response.master_keys.get(user_id).unwrap().deserialize_as().unwrap();
        let self_signing: CrossSigningKey =
            response.self_signing_keys.get(user_id).unwrap().deserialize_as().unwrap();

        ReadOnlyUserIdentity::new(master_key.try_into().unwrap(), self_signing.try_into().unwrap())
            .unwrap()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use matrix_sdk_common::locks::Mutex;
    use matrix_sdk_test::async_test;
    use ruma::{encryption::KeyUsage, user_id, DeviceKeyId};
    use serde_json::{json, Value};
    use vodozemac::Ed25519Signature;

    use super::{
        testing::{device, get_other_identity, get_own_identity},
        ReadOnlyOwnUserIdentity, ReadOnlyUserIdentities,
    };
    use crate::{
        identities::{
            manager::testing::{own_key_query, own_key_query_with_user_id},
            user::testing::get_other_own_identity,
            Device, MasterPubkey, SelfSigningPubkey, UserSigningPubkey,
        },
        olm::{PrivateCrossSigningIdentity, ReadOnlyAccount},
        store::MemoryStore,
        types::CrossSigningKey,
        verification::VerificationMachine,
    };

    #[test]
    fn own_identity_create() {
        let user_id = user_id!("@example:localhost");
        let response = own_key_query();

        let master_key: CrossSigningKey =
            response.master_keys.get(user_id).unwrap().deserialize_as().unwrap();
        let user_signing: CrossSigningKey =
            response.user_signing_keys.get(user_id).unwrap().deserialize_as().unwrap();
        let self_signing: CrossSigningKey =
            response.self_signing_keys.get(user_id).unwrap().deserialize_as().unwrap();

        ReadOnlyOwnUserIdentity::new(
            master_key.try_into().unwrap(),
            self_signing.try_into().unwrap(),
            user_signing.try_into().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn other_identity_create() {
        get_other_identity();
    }

    #[test]
    fn own_identity_check_signatures() {
        let response = own_key_query();
        let identity = get_own_identity();
        let (first, second) = device(&response);

        identity.is_device_signed(&first).unwrap_err();
        identity.is_device_signed(&second).unwrap();

        let private_identity =
            Arc::new(Mutex::new(PrivateCrossSigningIdentity::empty(second.user_id())));
        let verification_machine = VerificationMachine::new(
            ReadOnlyAccount::new(second.user_id(), second.device_id()),
            private_identity,
            Arc::new(MemoryStore::new()),
        );

        let first = Device {
            inner: first,
            verification_machine: verification_machine.clone(),
            own_identity: Some(identity.clone()),
            device_owner_identity: Some(ReadOnlyUserIdentities::Own(identity.clone())),
        };

        let second = Device {
            inner: second,
            verification_machine,
            own_identity: Some(identity.clone()),
            device_owner_identity: Some(ReadOnlyUserIdentities::Own(identity.clone())),
        };

        assert!(!second.is_locally_trusted());
        assert!(!second.is_cross_signing_trusted());

        assert!(!first.is_locally_trusted());
        assert!(!first.is_cross_signing_trusted());

        identity.mark_as_verified();
        assert!(second.is_verified());
        assert!(!first.is_verified());
    }

    #[async_test]
    async fn own_device_with_private_identity() {
        let response = own_key_query();
        let (_, device) = device(&response);

        let account = ReadOnlyAccount::new(device.user_id(), device.device_id());
        let (identity, _, _) = PrivateCrossSigningIdentity::with_account(&account).await;

        let id = Arc::new(Mutex::new(identity.clone()));

        let verification_machine = VerificationMachine::new(
            ReadOnlyAccount::new(device.user_id(), device.device_id()),
            id.clone(),
            Arc::new(MemoryStore::new()),
        );

        let public_identity = identity.to_public_identity().await.unwrap();

        let mut device = Device {
            inner: device,
            verification_machine: verification_machine.clone(),
            own_identity: Some(public_identity.clone()),
            device_owner_identity: Some(public_identity.clone().into()),
        };

        assert!(!device.is_verified());

        let mut device_keys = device.as_device_keys().to_owned();

        identity.sign_device_keys(&mut device_keys).await.unwrap();
        device.inner.update_device(&device_keys).expect("Couldn't update newly signed device keys");
        assert!(device.is_verified());
    }

    /// Test that `CrossSigningKey` instances without a correct `usage` cannot
    /// be deserialized into high-level structs representing the MSK, SSK
    /// and USK.
    #[test]
    fn cannot_instantiate_keys_with_incorrect_usage() {
        let user_id = user_id!("@example:localhost");
        let response = own_key_query();

        let master_key = response.master_keys.get(user_id).unwrap();
        let mut master_key_json: Value = master_key.deserialize_as().unwrap();
        let self_signing_key = response.self_signing_keys.get(user_id).unwrap();
        let mut self_signing_key_json: Value = self_signing_key.deserialize_as().unwrap();
        let user_signing_key = response.user_signing_keys.get(user_id).unwrap();
        let mut user_signing_key_json: Value = user_signing_key.deserialize_as().unwrap();

        // Delete the usages.
        let usage = master_key_json.get_mut("usage").unwrap();
        *usage = json!([]);
        let usage = self_signing_key_json.get_mut("usage").unwrap();
        *usage = json!([]);
        let usage = user_signing_key_json.get_mut("usage").unwrap();
        *usage = json!([]);

        // It should now be impossible to deserialize the keys into their corresponding
        // high-level cross-signing key structs.
        assert_matches!(serde_json::from_value::<MasterPubkey>(master_key_json.clone()), Err(_));
        assert_matches!(
            serde_json::from_value::<SelfSigningPubkey>(self_signing_key_json.clone()),
            Err(_)
        );
        assert_matches!(
            serde_json::from_value::<UserSigningPubkey>(user_signing_key_json.clone()),
            Err(_)
        );

        // Add additional usages.
        let usage = master_key_json.get_mut("usage").unwrap();
        *usage = json!(["master", "user_signing"]);
        let usage = self_signing_key_json.get_mut("usage").unwrap();
        *usage = json!(["self_signing", "user_signing"]);
        let usage = user_signing_key_json.get_mut("usage").unwrap();
        *usage = json!(["user_signing", "self_signing"]);

        // It should still be impossible to deserialize the keys into their
        // corresponding high-level cross-signing key structs.
        assert_matches!(serde_json::from_value::<MasterPubkey>(master_key_json.clone()), Err(_));
        assert_matches!(
            serde_json::from_value::<SelfSigningPubkey>(self_signing_key_json.clone()),
            Err(_)
        );
        assert_matches!(
            serde_json::from_value::<UserSigningPubkey>(user_signing_key_json.clone()),
            Err(_)
        );
    }

    #[async_test]
    async fn partial_eq_cross_signing_keys() {
        macro_rules! test_partial_eq {
            ($key_type:ident, $key_field:ident, $field:ident, $usage:expr) => {
                let user_id = user_id!("@example:localhost");
                let response = own_key_query();
                let raw = response.$field.get(user_id).unwrap();
                let key: $key_type = raw.deserialize_as().unwrap();

                // A different key is naturally not the same as our key.
                let other_identity = get_other_own_identity().await;
                let other_key = other_identity.$key_field;
                assert_ne!(key, other_key);

                // However, not even our own key material with another user ID is the same.
                let other_user_id = user_id!("@example2:localhost");
                let other_response = own_key_query_with_user_id(&other_user_id);
                let other_raw = other_response.$field.get(other_user_id).unwrap();
                let other_key: $key_type = other_raw.deserialize_as().unwrap();
                assert_ne!(key, other_key);

                // Now let's add another signature to our key.
                let signature = Ed25519Signature::from_base64(
                    "mia28GKixFzOWKJ0h7Bdrdy2fjxiHCsst1qpe467FbW85H61UlshtKBoAXfTLlVfi0FX+/noJ8B3noQPnY+9Cg"
                ).expect("The signature can always be decoded");
                let mut other_key: CrossSigningKey = raw.deserialize_as().unwrap();
                other_key.signatures.add_signature(
                    user_id.to_owned(),
                    DeviceKeyId::from_parts(ruma::DeviceKeyAlgorithm::Ed25519, "DEVICEID".into()),
                    signature,
                );
                let other_key = other_key.try_into().unwrap();

                // Additional signatures are fine, adding more does not change the key's identity.
                assert_eq!(key, other_key);

                // However changing the usage results in a different key.
                let mut other_key: CrossSigningKey = raw.deserialize_as().unwrap();
                other_key.usage.push($usage);
                let other_key = $key_type { 0: other_key.into() };
                assert_ne!(key, other_key);
            };
        }

        // The last argument is deliberately some usage which is *not* correct for the
        // type.
        test_partial_eq!(MasterPubkey, master_key, master_keys, KeyUsage::SelfSigning);
        test_partial_eq!(SelfSigningPubkey, self_signing_key, self_signing_keys, KeyUsage::Master);
        test_partial_eq!(UserSigningPubkey, user_signing_key, user_signing_keys, KeyUsage::Master);
    }
}

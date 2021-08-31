/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020-2021 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/encrypt/encryptor-v2.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *   Support ChaCha20-Ploy1305, GCK, encrypted Interest, multiple access managers.
 *   Add setGckLatestInterestLifetime.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.cpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

#include <stdexcept>
#include <sstream>
#include "../c/util/ndn_memory.h"
#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/lite/security/rsa-public-key-lite.hpp>
#include <ndn-ind/lite/encrypt/algo/aes-algorithm-lite.hpp>
#include <ndn-ind/lite/encrypt/algo/chacha20-algorithm-lite.hpp>
#include <ndn-ind/encrypt/encrypted-content.hpp>
#include <ndn-ind/encrypt/encryptor-v2.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn::func_lib;

INIT_LOGGER("ndn.EncryptorV2");

namespace ndn {

ndn_ind_dll const std::chrono::nanoseconds RETRY_DELAY_AFTER_NACK = std::chrono::seconds(1);
ndn_ind_dll const std::chrono::nanoseconds RETRY_DELAY_KEK_RETRIEVAL = std::chrono::minutes(1);
ndn_ind_dll const std::chrono::nanoseconds DEFAULT_CK_FRESHNESS_PERIOD = std::chrono::hours(1);

void
EncryptorV2::encrypt
  (const ptr_lib::shared_ptr<Interest>& interest,
   const OnEncryptInterestSuccess& onSuccess,
   const EncryptError::OnError& onError, WireFormat& wireFormat)
{
  if (interest->getName().findParametersSha256Digest() != -1) {
    onError(EncryptError::ErrorCode::EncryptionFailure,
      std::string("The Interest name already has a ParametersSha256Digest component: ") +
      interest->getName().toUri());
    return;
  }

  encrypt
    (interest->getApplicationParameters(),
     interest->getName().wireEncode(wireFormat),
     [=](const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent) {
       interest->setApplicationParameters(encryptedContent->wireEncodeV2());
       interest->appendParametersDigestToName();
       onSuccess(interest, encryptedContent);
     },
     onError);
}

EncryptorV2::Impl::Impl
  (const Name& accessPrefix, const Name& ckPrefix,
   const SigningInfo& ckDataSigningInfo, const EncryptError::OnError& onError,
   Validator* validator, KeyChain* keyChain, Face* face,
   ndn_EncryptAlgorithmType algorithmType)
: credentialsKey_(0), validator_(validator),
  onError_(onError), keyChain_(keyChain), face_(face), algorithmType_(algorithmType),
  iKeyManagerLastEncryption_(-1)
{
  keyManagers_.push_back(ptr_lib::make_shared<KeyManager>
    (this, accessPrefix, ckPrefix, ckDataSigningInfo));
}

EncryptorV2::Impl::KeyManager::KeyManager
  (Impl* parent, const Name& accessPrefix, const Name& ckPrefix,
   const SigningInfo& ckDataSigningInfo)
: parent_(parent), accessPrefix_(accessPrefix), ckPrefix_(ckPrefix),
  ckDataSigningInfo_(ckDataSigningInfo),
  isKekRetrievalInProgress_(false), kekPendingInterestId_(0),
  isGckRetrievalInProgress_(false), gckPendingInterestId_(0),
  accessManagerIsResponding_(false)
{
  if (parent->algorithmType_ == ndn_EncryptAlgorithmType_ChaCha20Poly1305)
    ckBits_.resize(ndn_CHACHA20_KEY_LENGTH);
  else if (parent->algorithmType_ == ndn_EncryptAlgorithmType_AesCbc)
    ckBits_.resize(AES_KEY_SIZE);
  else
    throw std::runtime_error("EncryptorV2: Unsupported encryption algorithm type");
}

EncryptorV2::Impl::Impl
  (const Name* accessPrefixes, size_t nAccessPrefixes, const EncryptError::OnError& onError,
   PibKey* credentialsKey, Validator* validator, KeyChain* keyChain, Face* face,
   ndn_EncryptAlgorithmType algorithmType)
: onError_(onError), credentialsKey_(credentialsKey), validator_(validator),
  keyChain_(keyChain), face_(face), algorithmType_(algorithmType),
  iKeyManagerLastEncryption_(-1)
{
  for (size_t i = 0; i < nAccessPrefixes; ++i)
    keyManagers_.push_back(ptr_lib::make_shared<KeyManager>(this, accessPrefixes[i]));
}

EncryptorV2::Impl::KeyManager::KeyManager(Impl* parent, const Name& accessPrefix)
: parent_(parent), accessPrefix_(accessPrefix),
  isKekRetrievalInProgress_(false), ckRegisteredPrefixId_(0),
  kekPendingInterestId_(0), isGckRetrievalInProgress_(false),
  gckPendingInterestId_(0), accessManagerIsResponding_(false)
{
  if (parent->algorithmType_ == ndn_EncryptAlgorithmType_ChaCha20Poly1305)
    ckBits_.resize(ndn_CHACHA20_KEY_LENGTH);
  else if (parent->algorithmType_ == ndn_EncryptAlgorithmType_AesCbc)
    ckBits_.resize(AES_KEY_SIZE);
  else
    throw std::runtime_error("EncryptorV2: Unsupported encryption algorithm type");

  gckLatestPrefix_ = Name(accessPrefix_)
    .append(getNAME_COMPONENT_GCK())
    .append(getNAME_COMPONENT_LATEST());
}

void
EncryptorV2::Impl::KeyManager::initializeCk()
{
  regenerateCk();

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<KeyManager>& parent)
    : parent_(parent)
    {}

    void
    onInterest
      (const ptr_lib::shared_ptr<const Name>& prefix,
       const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
       uint64_t interestFilterId,
       const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
      ptr_lib::shared_ptr<Data> data = parent_->storage_.find(*interest);
      if (data) {
        _LOG_TRACE("Serving " << data->getName() << " from InMemoryStorage");
        try {
          face.putData(*data);
        } catch (const std::exception& ex) {
          _LOG_ERROR("Error in Face.putData: " << ex.what());
        }
      }
      else {
        _LOG_TRACE("Didn't find CK data for " << interest->getName());
        // TODO: Send NACK?
      }
    }

    void
    onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
      _LOG_ERROR("Failed to register prefix: " << *prefix);
    }

    ptr_lib::shared_ptr<KeyManager> parent_;
  };

  // We make a shared_ptr object since it needs to exist after we return, and
  // pass shared_from_this() to keep a pointer to this Impl.
  ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
    (shared_from_this());
  ckRegisteredPrefixId_ = parent_->face_->registerPrefix
    (Name(ckPrefix_).append(getNAME_COMPONENT_CK()),
     bind(&Callbacks::onInterest, callbacks, _1, _2, _3, _4, _5),
     bind(&Callbacks::onRegisterFailed, callbacks, _1));
}

void
EncryptorV2::Impl::KeyManager::shutdown()
{
  parent_->face_->unsetInterestFilter(ckRegisteredPrefixId_);
  if (kekPendingInterestId_ > 0)
    parent_->face_->removePendingInterest(kekPendingInterestId_);
  if (gckPendingInterestId_ > 0)
    parent_->face_->removePendingInterest(gckPendingInterestId_);
}

ptr_lib::shared_ptr<EncryptedContent>
EncryptorV2::Impl::encrypt
  (const uint8_t* plainData, size_t plainDataLength,
   const uint8_t *associatedData, size_t associatedDataLength)
{
  // Use the first key manager in the prioritized list which has a ready key.
  for (size_t i = 0; i < keyManagers_.size(); ++i) {
    // Below, encrypt only checks if a first GCK has been retrieved. We must also
    // check isKeyReady() to make sure the access manager is responding.
    if (!keyManagers_[i]->isKeyReady())
      continue;

    ptr_lib::shared_ptr<EncryptedContent> encryptedContent = keyManagers_[i]->encrypt
      (plainData, plainDataLength, associatedData, associatedDataLength);
    if (encryptedContent) {
      iKeyManagerLastEncryption_ = i;
      return encryptedContent;
    }
  }

  // No access manager is responding. Maybe use the key manager of the last encryption.
  if (iKeyManagerLastEncryption_ >= 0) {
    ptr_lib::shared_ptr<EncryptedContent> encryptedContent =
      keyManagers_[iKeyManagerLastEncryption_]->encrypt
        (plainData, plainDataLength, associatedData, associatedDataLength);
    if (encryptedContent) {
      _LOG_TRACE
        ("No access manager is responding. Used possibly stale content key from " <<
         keyManagers_[iKeyManagerLastEncryption_]->getAccessPrefix().toUri());
      return encryptedContent;
    }
  }

  throw runtime_error("EncryptorV2 has not fetched the first group content key (GCK)");
}

ptr_lib::shared_ptr<EncryptedContent>
EncryptorV2::Impl::KeyManager::encrypt
  (const uint8_t* plainData, size_t plainDataLength,
   const uint8_t *associatedData, size_t associatedDataLength)
{
  if (parent_->isUsingGck() && ckName_.size() == 0)
    // The caller will check this and throw an exception if needed.
    return ptr_lib::shared_ptr<EncryptedContent>();

  ndn_Error error;
  ptr_lib::shared_ptr<vector<uint8_t> > encryptedData;
  ptr_lib::shared_ptr<EncryptedContent> content =
    ptr_lib::make_shared<EncryptedContent>();

  if (parent_->algorithmType_ == ndn_EncryptAlgorithmType_ChaCha20Poly1305) {
    // Generate the initial vector.
    uint8_t initialVector[ndn_CHACHA20_NONCE_LENGTH];
    if ((error = CryptoLite::generateRandomBytes
         (initialVector, sizeof(initialVector))))
      throw runtime_error(ndn_getErrorString(error));
    content->setInitialVector(Blob(initialVector, sizeof(initialVector)));
    content->setAlgorithmType(parent_->algorithmType_);

    // Add room for the authentication tag.
    encryptedData.reset
      (new vector<uint8_t>(plainDataLength + ndn_POLY1305_BLOCK_LENGTH));
    size_t encryptedDataLength;
    if ((error = ChaCha20AlgorithmLite::encryptPoly1305
         (&ckBits_[0], ckBits_.size(), initialVector, sizeof(initialVector),
          plainData, plainDataLength, associatedData, associatedDataLength,
          &encryptedData->front(), encryptedDataLength)))
      throw runtime_error(string("ChaCha20Algorithm: ") + ndn_getErrorString(error));
    encryptedData->resize(encryptedDataLength);
  }
  else {
    uint8_t initialVector[AES_IV_SIZE];
    if ((error = CryptoLite::generateRandomBytes
         (initialVector, sizeof(initialVector))))
      throw runtime_error(ndn_getErrorString(error));
    content->setInitialVector(Blob(initialVector, sizeof(initialVector)));
    // This is the default, so don't call setAlgorithmType();

    // Add room for the padding.
    encryptedData.reset
      (new vector<uint8_t>(plainDataLength + ndn_AES_BLOCK_LENGTH));
    size_t encryptedDataLength;
    if ((error = AesAlgorithmLite::encrypt256Cbc
         (&ckBits_[0], ckBits_.size(), initialVector, sizeof(initialVector),
          plainData, plainDataLength, &encryptedData->front(), encryptedDataLength)))
      throw runtime_error(string("AesAlgorithm: ") + ndn_getErrorString(error));
    encryptedData->resize(encryptedDataLength);
  }

  content->setPayload(Blob(encryptedData, false));
  content->setKeyLocatorName(ckName_);
  content->setAlgorithmType(parent_->algorithmType_);

  return content;
}

void
EncryptorV2::Impl::encrypt
  (const Blob& plainData, const Blob& associatedData,
   const OnEncryptSuccess& onSuccess,
   const EncryptError::OnError& onErrorIn)
{
  // If the given OnError is omitted, use the one given to the constructor.
  EncryptError::OnError onError = (onErrorIn ? onErrorIn : onError_);

  bool canEncrypt = false;
  for (size_t i = 0; i < keyManagers_.size(); ++i) {
    if (keyManagers_[i]->isKeyReady())
      canEncrypt = true;
    // Even if we set canEncrypt true, continue to call isKeyReady for all
    // key managers so that they can check for a new GCK.
  }

  // Use a ready key manager, or the last one that did an encryption.
  if (canEncrypt || iKeyManagerLastEncryption_ >= 0) {
    ptr_lib::shared_ptr<EncryptedContent> encryptedContent;
    try {
      // If a key was made ready, then processPendingEncrypts() should already have
      // been called, but check anyway.
      processPendingEncrypts();

      encryptedContent = encrypt
        (plainData.buf(), plainData.size(), associatedData.buf(),
         associatedData.size());
    } catch (const std::exception& ex) {
      onError(EncryptError::ErrorCode::EncryptionFailure,
        string("Error in encrypt: ") + ex.what());
    }

    if (encryptedContent) {
      try {
        onSuccess(encryptedContent);
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in onSuccess: " << ex.what());
      } catch (...) {
        _LOG_ERROR("Error in onSuccess.");
      }
    }
    else
      // isKeyReady returned true, but encrypt returned null, meaning not really ready.
      // We don't expect this to happen.
      onError(EncryptError::ErrorCode::EncryptionFailure,
        "EncryptorV2: A content key is ready, but unable to encrypt");
  }
  else {
    // There isn't a ready content key. Save in pendingEncrypts_ until ready.
    _LOG_TRACE
      ("The GCK is not yet available, so adding to the pending encrypt queue");
    pendingEncrypts_.push_back
      (ptr_lib::make_shared<PendingEncrypt>
       (plainData, associatedData, onSuccess, onError));
  }
}

void
EncryptorV2::Impl::processPendingEncrypts()
{
  if (pendingEncrypts_.size() == 0)
    return;

  for (size_t i = 0; i < pendingEncrypts_.size(); ++i) {
    PendingEncrypt& pendingEncrypt = *pendingEncrypts_[i];

    // TODO: If this calls onError, should we quit so that there is only one exit
    // from the asynchronous operation?
    ptr_lib::shared_ptr<EncryptedContent> encryptedContent = encrypt
      (pendingEncrypt.plainData.buf(), pendingEncrypt.plainData.size(),
       pendingEncrypt.associatedData.buf(), pendingEncrypt.associatedData.size());
    if (encryptedContent) {
      try {
        pendingEncrypt.onSuccess(encryptedContent);
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in onSuccess: " << ex.what());
      } catch (...) {
        _LOG_ERROR("Error in onSuccess.");
      }
    }
    else
      // This should only be called when a key is ready, but encrypt returned
      // null, meaning not really ready. We don't expect this to happen.
      _LOG_ERROR("EncryptorV2: A content key is ready, but unable to do pending encrypt");
  }

  pendingEncrypts_.clear();
}

Blob
EncryptorV2::Impl::getContentKey(const Name& keyName)
{
  // Call isKeyReady of each key manager to let it fetch if needed.
  for (size_t i = 0; i < keyManagers_.size(); ++i)
    keyManagers_[i]->isKeyReady();

  auto key = contentKeys_.find(keyName);
  if (key == contentKeys_.end())
    // Not found.
    return Blob();
  else
    return key->second;
}

bool
EncryptorV2::Impl::KeyManager::isKeyReady()
{
  if (parent_->isUsingGck()) {
    auto now = system_clock::now();

    if (ckName_.size() == 0) {
      // We have not yet fetched a GCK.
      if (!isGckRetrievalInProgress_) {
        nextCheckForNewGck_ =
          now + duration_cast<system_clock::duration>(parent_->checkForNewGckInterval_);
        // When the GCK is fetched, this will process the pending encrypts.
        checkForNewGck();
      }

      // The caller will update pendingEncrypts_ and wait for a ready key.
      return false;
    }

    if (now > nextCheckForNewGck_) {
      // Need to check for a new GCK.
      nextCheckForNewGck_ =
        now + duration_cast<system_clock::duration>(parent_->checkForNewGckInterval_);
      if (!isGckRetrievalInProgress_)
        checkForNewGck();
    }

    if (parent_->keyManagers_.size() > 1)
      // There are multiple access managers with possibility of failover, so
      // only say the GCK is ready if the access manager is responding.
      return accessManagerIsResponding_;
    else
      // There is only one access manager, so use an existing GCK even if we
      // are unable to fetch a new GCK.
      return true;
  }

  return true;
}

void
EncryptorV2::Impl::KeyManager::regenerateCk()
{
  if (parent_->isUsingGck())
    throw runtime_error("This EncryptorV2 uses a group content key. Cannot regenerateCk()");

  // TODO: Ensure that the CK Data packet for the old CK is published when the
  // CK is updated before the KEK is fetched.

  ckName_ = Name(ckPrefix_);
  ckName_.append(getNAME_COMPONENT_CK());
  // The version is the ID of the CK.
  ckName_.appendVersion((uint64_t)ndn_getNowMilliseconds());

  _LOG_TRACE("Generating new CK: " + ckName_.toUri());
  ndn_Error error;
  if ((error = CryptoLite::generateRandomBytes(&ckBits_[0], ckBits_.size())))
    throw runtime_error(ndn_getErrorString(error));
  // Also store for historical retrieval.
  parent_->contentKeys_[ckName_] = Blob(ckBits_);

  // One implication: If the CK is updated before the KEK is fetched, then
  // the KDK for the old CK will not be published.
  if (!kekData_)
    retryFetchingKek();
  else
    makeAndPublishCkData(parent_->onError_);
}

void
EncryptorV2::Impl::KeyManager::retryFetchingKek()
{
  if (isKekRetrievalInProgress_)
    return;

  _LOG_TRACE("Retrying fetching of the KEK");
  isKekRetrievalInProgress_ = true;

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<KeyManager>& parent)
    : parent_(parent)
    {}

    void
    onReady()
    {
      _LOG_TRACE("The KEK was retrieved and published");
      parent_->isKekRetrievalInProgress_ = false;
    }

    void
    onError(EncryptError::ErrorCode errorCode, const string& message)
    {
      _LOG_TRACE("Failed to retrieve KEK: " + message);
      parent_->isKekRetrievalInProgress_ = false;
      parent_->parent_->onError_(errorCode, message);
    }

    ptr_lib::shared_ptr<KeyManager> parent_;
  };

  // We make a shared_ptr object since it needs to exist after we return, and
  // pass shared_from_this() to keep a pointer to this Impl.
  ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
    (shared_from_this());
  fetchKekAndPublishCkData
    (bind(&Callbacks::onReady, callbacks),
     bind(&Callbacks::onError, callbacks, _1, _2),
     N_RETRIES);
}

void
EncryptorV2::Impl::KeyManager::fetchKekAndPublishCkData
  (const Face::Callback& onReady, const EncryptError::OnError& onError,
   int nTriesLeft)
{
  _LOG_TRACE("Fetching KEK: " <<
             Name(accessPrefix_).append(getNAME_COMPONENT_KEK()));

  if (kekPendingInterestId_ > 0) {
    onError(EncryptError::ErrorCode::General,
      "fetchKekAndPublishCkData: There is already a kekPendingInterestId_");
    return;
  }

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks
      (const ptr_lib::shared_ptr<KeyManager>& parent, const Face::Callback& onReady,
       const EncryptError::OnError& onError, int nTriesLeft)
    : parent_(parent), onReady_(onReady), onError_(onError),
      nTriesLeft_(nTriesLeft)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<Data>& kekData)
    {
      parent_->kekPendingInterestId_ = 0;

      // Validate the Data signature.
      parent_->parent_->validator_->validate
        (*kekData,
         [=](auto&) {
           parent_->kekData_ = kekData;
           if (parent_->makeAndPublishCkData(onError_))
             onReady_();
           // Otherwise, failure has already been reported.
         },
         [=](auto&, auto& error) {
           onError_(EncryptError::ErrorCode::CkRetrievalFailure,
             "Validate KEK Data failure: " + error.toString());
         });
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->kekPendingInterestId_ = 0;
      if (nTriesLeft_ > 1)
        parent_->fetchKekAndPublishCkData(onReady_, onError_, nTriesLeft_ - 1);
      else {
        onError_(EncryptError::ErrorCode::KekRetrievalTimeout,
          "Retrieval of KEK [" + interest->getName().toUri() + "] timed out");
        _LOG_TRACE("Scheduling retry after all timeouts");
        parent_->parent_->face_->callLater
          (RETRY_DELAY_KEK_RETRIEVAL,
           bind(&EncryptorV2::Impl::KeyManager::retryFetchingKek, parent_));
      }
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->kekPendingInterestId_ = 0;
      if (nTriesLeft_ > 1) {
        parent_->parent_->face_->callLater
          (RETRY_DELAY_AFTER_NACK,
           bind(&EncryptorV2::Impl::KeyManager::fetchKekAndPublishCkData, parent_,
                onReady_, onError_, nTriesLeft_ - 1));
      }
      else {
        ostringstream message;
        message <<  "Retrieval of KEK [" << interest->getName().toUri() <<
          "] failed. Got NACK (" << networkNack->getReason() << ")";
        onError_(EncryptError::ErrorCode::KekRetrievalFailure, message.str());
        _LOG_TRACE("Scheduling retry from NACK");
        parent_->parent_->face_->callLater
          (RETRY_DELAY_KEK_RETRIEVAL,
           bind(&EncryptorV2::Impl::KeyManager::retryFetchingKek, parent_));
      }
    }

    ptr_lib::shared_ptr<KeyManager> parent_;
    Face::Callback onReady_;
    EncryptError::OnError onError_;
    int nTriesLeft_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this(), onReady, onError, nTriesLeft);
    kekPendingInterestId_ = parent_->face_->expressInterest
      (Interest(Name(accessPrefix_).append(getNAME_COMPONENT_KEK()))
               .setMustBeFresh(true)
               .setCanBePrefix(true),
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    onError(EncryptError::ErrorCode::General,
            string("expressInterest error: ") + ex.what());
  }
}

bool
EncryptorV2::Impl::KeyManager::makeAndPublishCkData(
  const EncryptError::OnError& onError)
{
  try {
    RsaPublicKeyLite kek;
    if (kek.decode(kekData_->getContent()) != NDN_ERROR_success)
      throw runtime_error("RsaAlgorithm: Error decoding public key");

    // TODO: use RSA_size, etc. to get the proper size of the output buffer.
    ptr_lib::shared_ptr<vector<uint8_t> > encryptedData(new vector<uint8_t>(1000));
    size_t encryptedDataLength;
    ndn_Error error;
    if ((error = kek.encrypt
#if 0 // See https://github.com/operantnetworks/ndn-ind/issues/13
         (&ckBits_[0], ckBits_.size(), ndn_EncryptAlgorithmType_RsaOaep,
#else
         (&ckBits_[0], ckBits_.size(), ndn_EncryptAlgorithmType_RsaPkcs,
#endif
          &encryptedData->front(), encryptedDataLength)))
      throw runtime_error("RsaAlgorithm: Error encrypting with public key");
    encryptedData->resize(encryptedDataLength);
    EncryptedContent content;
    content.setPayload(Blob(encryptedData, false));

    Data ckData
      (Name(ckName_).append(getNAME_COMPONENT_ENCRYPTED_BY())
       .append(kekData_->getName()));
    ckData.setContent(content.wireEncodeV2());
    // FreshnessPeriod can serve as a soft access control for revoking access.
    ckData.getMetaInfo().setFreshnessPeriod(DEFAULT_CK_FRESHNESS_PERIOD);
    parent_->keyChain_->sign(ckData, ckDataSigningInfo_);
    storage_.insert(ckData);

    _LOG_TRACE("Publishing CK data: " << ckData.getName());
    return true;
  } catch (const std::exception& ex) {
    onError(EncryptError::ErrorCode::EncryptionFailure,
      "Failed to encrypt generated CK with KEK " + kekData_->getName().toUri());
    return false;
  }
}

void
EncryptorV2::Impl::KeyManager::checkForNewGck()
{
  if (isGckRetrievalInProgress_)
    // Already checking.
    return;
  isGckRetrievalInProgress_ = true;

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<KeyManager>& parent)
    : parent_(parent)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& ckInterest,
       const ptr_lib::shared_ptr<Data>& gckLatestData)
    {
      parent_->accessManagerIsResponding_ = true;

      // Validate the Data signature.
      parent_->parent_->validator_->validate
        (*gckLatestData,
         [=](auto&) {
           Name newGckName;
           try {
             newGckName.wireDecode(gckLatestData->getContent());
           } catch (const std::exception& ex) {
             // Don't use the waiting next GCK.
             parent_->nextGckBits_ = Blob();
             parent_->isGckRetrievalInProgress_ = false;
             _LOG_ERROR("Error decoding GCK name in: " << gckLatestData->getName().toUri());
             return;
           }

           if (!parent_->nextGckBits_.isNull()) {
             // There is a next GCK waiting to see if the access manager is still responding.
             if (newGckName.equals(parent_->nextGckName_)) {
               // The access manager is responding and still using the same GCK name.
               auto now = system_clock::now();

               if (now - parent_->nextGckReceiptTime_ > parent_->parent_->checkForNewGckInterval_) {
                 // Enough time has passed for others to fetch it, so use the new GCK and
                 // process pending encrypts, as done in decryptGckAndProcessPendingEncrypts.
                 _LOG_DEBUG("EncryptorV2: The next GCK is ready " << parent_->nextGckName_.toUri());
                 parent_->ckName_ = parent_->nextGckName_;
                 ndn_memcpy(&parent_->ckBits_[0], parent_->nextGckBits_.buf(), parent_->ckBits_.size());
                 // Also store for historical retrieval.
                 parent_->parent_->contentKeys_[parent_->ckName_] = Blob(parent_->nextGckBits_);
                 parent_->nextGckBits_ = Blob();
                 parent_->isGckRetrievalInProgress_ = false;
                 try {
                   // We now have a key, so we can process pending encrypts if needed.
                   parent_->parent_->processPendingEncrypts();
                 } catch (const std::exception& ex) {
                   _LOG_ERROR("Error encrypting pending data: " << ex.what());
                   return;
                 }
               }
               else {
                 // Not enough time has passed for others to fetch, so wait and try again.
                 _LOG_DEBUG("EncryptorV2: Still waiting to start using the next GCK " <<
                            parent_->nextGckName_.toUri());
                 parent_->isGckRetrievalInProgress_ = false;
               }
             }
             else {
               // We don't expect this, but the access manager just changed the name
               // of the GCK, so we have to start over and fetch it.
               parent_->nextGckBits_ = Blob();
               // Leave isGckRetrievalInProgress_ true.
               parent_->fetchGck(newGckName, N_RETRIES);
             }

             return;
           }

           if (newGckName.equals(parent_->ckName_)) {
             // The latest is the same name, so do nothing.
             parent_->isGckRetrievalInProgress_ = false;
             return;
           }

           // Leave isGckRetrievalInProgress_ true.
           parent_->fetchGck(newGckName, N_RETRIES);
         },
         [=](auto&, auto& error) {
           // Don't use the waiting next GCK.
           parent_->nextGckBits_ = Blob();
           parent_->isGckRetrievalInProgress_ = false;
           _LOG_ERROR("Validate GCK latest_ Data failure: " << error.toString());
         });
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->accessManagerIsResponding_ = false;
      // Don't use the waiting next GCK.
      parent_->nextGckBits_ = Blob();
      parent_->isGckRetrievalInProgress_ = false;
      _LOG_ERROR("Timeout for GCK _latest packet: " << interest->getName().toUri());
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->accessManagerIsResponding_ = false;
      // Don't use the waiting next GCK.
      parent_->nextGckBits_ = Blob();
      parent_->isGckRetrievalInProgress_ = false;
      ostringstream message;
      _LOG_ERROR("Network nack for GCK _latest packet: " << interest->getName().toUri() <<
        ". Got NACK (" << networkNack->getReason() << ")");
    }

    ptr_lib::shared_ptr<KeyManager> parent_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this());
    parent_->face_->expressInterest
      (Interest(gckLatestPrefix_).setMustBeFresh(true).setCanBePrefix(true),
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    _LOG_ERROR("expressInterest error: " << ex.what());
  }
}

void
EncryptorV2::Impl::KeyManager::fetchGck(const Name& gckName, int nTriesLeft)
{
  // This is only called from checkForNewGck, so isGckRetrievalInProgress_ is true.

  // <access-prefix>/GCK/<gck-id>  /ENCRYPTED-BY /<credential-identity>/KEY/<key-id>
  // \                          /                \                                 /
  //  -----------  -------------                  ----------------  ---------------
  //             \/                                               \/
  //           gckName                                    from configuration

  Name encryptedGckName(gckName);
  encryptedGckName
    .append(getNAME_COMPONENT_ENCRYPTED_BY())
    .append(parent_->credentialsKey_->getName());

  _LOG_TRACE("EncryptorV2: Fetching GCK " << encryptedGckName);

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks
      (const ptr_lib::shared_ptr<KeyManager>& parent, const Name& gckName,
       int nTriesLeft)
    : parent_(parent), gckName_(gckName), nTriesLeft_(nTriesLeft)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& ckInterest,
       const ptr_lib::shared_ptr<Data>& ckData)
    {
      parent_->accessManagerIsResponding_ = true;
      try {
        parent_->gckPendingInterestId_ = 0;

        // Leave isGckRetrievalInProgress_ true.
        parent_->decryptGckAndProcessPendingEncrypts(gckName_, *ckData);
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in EncryptorV2::fetchGck onData: " << ex.what());
      }
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->gckPendingInterestId_ = 0;
      if (nTriesLeft_ > 1)
        parent_->fetchGck(gckName_, nTriesLeft_ - 1);
      else {
        parent_->accessManagerIsResponding_ = false;
        parent_->isGckRetrievalInProgress_ = false;
        _LOG_ERROR("Retrieval of GCK [" << interest->getName().toUri() << "] timed out");
      }
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->gckPendingInterestId_ = 0;
      parent_->accessManagerIsResponding_ = false;
      parent_->isGckRetrievalInProgress_ = false;
      ostringstream message;
      _LOG_ERROR("Retrieval of GCK [" << interest->getName().toUri() <<
        "] failed. Got NACK (" << networkNack->getReason() << ")");
    }

    ptr_lib::shared_ptr<KeyManager> parent_;
    Name gckName_;
    int nTriesLeft_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this(), gckName, nTriesLeft);
    Interest interest(encryptedGckName);
    interest.setMustBeFresh(false).setCanBePrefix(true);
    if (parent_->gckLatestInterestLifetime_.count() >= 0)
      // Override the default interest lifetime.
      interest.setInterestLifetime(parent_->gckLatestInterestLifetime_);
    gckPendingInterestId_ = parent_->face_->expressInterest
      (interest,
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    _LOG_ERROR("expressInterest error: " << ex.what());
  }
}

void
EncryptorV2::Impl::KeyManager::decryptGckAndProcessPendingEncrypts(
  const Name& gckName, const Data& gckData)
{
  // This is only called from fetchGck, so isGckRetrievalInProgress_ is true.

  _LOG_TRACE("EncryptorV2: Decrypting GCK data " << gckData.getName());

  EncryptedContent content;
  try {
    content.wireDecodeV2(gckData.getContent());
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    _LOG_ERROR("Error decrypting EncryptedContent: " << ex.what());
    return;
  }

  Blob decryptedCkBits;
  try {
    decryptedCkBits = parent_->keyChain_->getTpm().decrypt
      (content.getPayload().buf(), content.getPayload().size(),
       parent_->credentialsKey_->getName());
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    _LOG_ERROR("Error decrypting the GCK: " << ex.what());
    return;
  }
  if (decryptedCkBits.isNull()) {
    isGckRetrievalInProgress_ = false;
    _LOG_ERROR("Could not decrypt secret, " << 
      parent_->credentialsKey_->getName().toUri() << " not found in TPM");
    return;
  }

  if (decryptedCkBits.size() != ckBits_.size()) {
    isGckRetrievalInProgress_ = false;
    _LOG_ERROR("The decrypted group content key is not the correct size for the encryption algorithm");
    return;
  }

  // Only check for multiple access managers if ckName_.size() != 0, meaning
  // that we have fetched a GCK at least once.
  if (ckName_.size() != 0 && parent_->keyManagers_.size() > 1) {
    // There are multiple access managers with possibility of failover, so we
    // first wait for checkForNewGck to check if this access manager is still
    // responding before starting to use this next GCK, to make sure others have
    // fetched it.
    nextGckReceiptTime_ = system_clock::now();
    nextGckName_ = gckName;
    nextGckBits_ = decryptedCkBits;
    isGckRetrievalInProgress_ = false;
    _LOG_DEBUG("EncryptorV2: Waiting to start using the next GCK " << gckName.toUri());
    return;
  }

  ckName_ = gckName;
  ndn_memcpy(&ckBits_[0], decryptedCkBits.buf(), ckBits_.size());
  // Also store for historical retrieval.
  parent_->contentKeys_[ckName_] = Blob(decryptedCkBits);
  isGckRetrievalInProgress_ = false;
  _LOG_DEBUG("EncryptorV2: The GCK is ready " << gckName.toUri());
  try {
    // We now have a key, so we can process pending encrypts if needed.
    parent_->processPendingEncrypts();
  } catch (const std::exception& ex) {
    _LOG_ERROR("Error encrypting pending data: " << ex.what());
    return;
  }
}

EncryptorV2::Values* EncryptorV2::values_ = 0;

}

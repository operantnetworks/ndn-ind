/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/encrypt/encryptor-v2.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *   Support ChaCha20-Ploy1305, GCK, encrypted Interest.
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
: accessPrefix_(accessPrefix), ckPrefix_(ckPrefix),
  validator_(validator),
  ckDataSigningInfo_(ckDataSigningInfo), isKekRetrievalInProgress_(false),
  onError_(onError), keyChain_(keyChain), face_(face),
  algorithmType_(algorithmType), kekPendingInterestId_(0),
  isGckRetrievalInProgress_(false), gckPendingInterestId_(0)
{
  if (algorithmType == ndn_EncryptAlgorithmType_ChaCha20Poly1305)
    ckBits_.resize(ndn_CHACHA20_KEY_LENGTH);
  else if (algorithmType == ndn_EncryptAlgorithmType_AesCbc)
    ckBits_.resize(AES_KEY_SIZE);
  else
    throw std::runtime_error("EncryptorV2: Unsupported encryption algorithm type");
}

EncryptorV2::Impl::Impl
  (const Name& accessPrefix, const EncryptError::OnError& onError,
   PibKey* credentialsKey, Validator* validator, KeyChain* keyChain, Face* face,
   ndn_EncryptAlgorithmType algorithmType)
: accessPrefix_(accessPrefix), onError_(onError), credentialsKey_(credentialsKey),
  validator_(validator),
  keyChain_(keyChain), face_(face), algorithmType_(algorithmType),
  isKekRetrievalInProgress_(false), ckRegisteredPrefixId_(0),
  kekPendingInterestId_(0), isGckRetrievalInProgress_(false),
  gckPendingInterestId_(0)
{
  if (algorithmType == ndn_EncryptAlgorithmType_ChaCha20Poly1305)
    ckBits_.resize(ndn_CHACHA20_KEY_LENGTH);
  else if (algorithmType == ndn_EncryptAlgorithmType_AesCbc)
    ckBits_.resize(AES_KEY_SIZE);
  else
    throw std::runtime_error("EncryptorV2: Unsupported encryption algorithm type");

  gckLatestPrefix_ = Name(accessPrefix_)
    .append(getNAME_COMPONENT_GCK())
    .append(getNAME_COMPONENT_LATEST());
}

void
EncryptorV2::Impl::initializeCk()
{
  regenerateCk();

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<Impl>& parent)
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

    ptr_lib::shared_ptr<Impl> parent_;
  };

  // We make a shared_ptr object since it needs to exist after we return, and
  // pass shared_from_this() to keep a pointer to this Impl.
  ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
    (shared_from_this());
  ckRegisteredPrefixId_ = face_->registerPrefix
    (Name(ckPrefix_).append(getNAME_COMPONENT_CK()),
     bind(&Callbacks::onInterest, callbacks, _1, _2, _3, _4, _5),
     bind(&Callbacks::onRegisterFailed, callbacks, _1));
}

void
EncryptorV2::Impl::shutdown()
{
  face_->unsetInterestFilter(ckRegisteredPrefixId_);
  if (kekPendingInterestId_ > 0)
    face_->removePendingInterest(kekPendingInterestId_);
  if (gckPendingInterestId_ > 0)
    face_->removePendingInterest(gckPendingInterestId_);
}

ptr_lib::shared_ptr<EncryptedContent>
EncryptorV2::Impl::encrypt
  (const uint8_t* plainData, size_t plainDataLength,
   const uint8_t *associatedData, size_t associatedDataLength)
{
  if (isUsingGck() && ckName_.size() == 0)
    throw runtime_error("EncryptorV2 has not fetched the first group content key (GCK)");

  ndn_Error error;
  ptr_lib::shared_ptr<vector<uint8_t> > encryptedData;
  ptr_lib::shared_ptr<EncryptedContent> content =
    ptr_lib::make_shared<EncryptedContent>();

  if (algorithmType_ == ndn_EncryptAlgorithmType_ChaCha20Poly1305) {
    // Generate the initial vector.
    uint8_t initialVector[ndn_CHACHA20_NONCE_LENGTH];
    if ((error = CryptoLite::generateRandomBytes
         (initialVector, sizeof(initialVector))))
      throw runtime_error(ndn_getErrorString(error));
    content->setInitialVector(Blob(initialVector, sizeof(initialVector)));
    content->setAlgorithmType(algorithmType_);

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
  content->setAlgorithmType(algorithmType_);

  return content;
}

void
EncryptorV2::Impl::encrypt
  (const Blob& plainData, const Blob& associatedData,
   const OnEncryptSuccess& onSuccess, const EncryptError::OnError& onErrorIn)
{
  // If the given OnError is omitted, use the one given to the constructor.
  EncryptError::OnError onError = (onErrorIn ? onErrorIn : onError_);

  if (isUsingGck()) {
    auto now = system_clock::now();

    if (ckName_.size() == 0) {
      // We haven't fetched the first GCK.
      _LOG_TRACE
        ("The GCK is not yet available, so adding to the pending encrypt queue");
      pendingEncrypts_.push_back
        (ptr_lib::make_shared<PendingEncrypt>
         (plainData, associatedData, onSuccess, onError));

      if (!isGckRetrievalInProgress_) {
        nextCheckForNewGck_ =
          now + duration_cast<system_clock::duration>(checkForNewGckInterval_);
        // When the GCK is fetched, this will process the pending encrypts.
        checkForNewGck(onError);
      }

      return;
    }

    if (now > nextCheckForNewGck_) {
      // Need to check for a new GCK.
      nextCheckForNewGck_ =
        now + duration_cast<system_clock::duration>(checkForNewGckInterval_);
      if (!isGckRetrievalInProgress_)
        checkForNewGck(onError);
      // Continue below to encrypt with the current key.
    }
  }

  ptr_lib::shared_ptr<EncryptedContent> encryptedContent = encrypt
    (plainData.buf(), plainData.size(), associatedData.buf(),
     associatedData.size());
  try {
    onSuccess(encryptedContent);
  } catch (const std::exception& ex) {
    _LOG_ERROR("Error in onSuccess: " << ex.what());
  } catch (...) {
    _LOG_ERROR("Error in onSuccess.");
  }
}

void
EncryptorV2::Impl::regenerateCk()
{
  if (isUsingGck())
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

  // One implication: If the CK is updated before the KEK is fetched, then
  // the KDK for the old CK will not be published.
  if (!kekData_)
    retryFetchingKek();
  else
    makeAndPublishCkData(onError_);
}

void
EncryptorV2::Impl::retryFetchingKek()
{
  if (isKekRetrievalInProgress_)
    return;

  _LOG_TRACE("Retrying fetching of the KEK");
  isKekRetrievalInProgress_ = true;

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<Impl>& parent)
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
      parent_->onError_(errorCode, message);
    }

    ptr_lib::shared_ptr<Impl> parent_;
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
EncryptorV2::Impl::fetchKekAndPublishCkData
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
      (const ptr_lib::shared_ptr<Impl>& parent, const Face::Callback& onReady,
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
      parent_->validator_->validate
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
        parent_->face_->callLater
          (RETRY_DELAY_KEK_RETRIEVAL,
           bind(&EncryptorV2::Impl::retryFetchingKek, parent_));
      }
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->kekPendingInterestId_ = 0;
      if (nTriesLeft_ > 1) {
        parent_->face_->callLater
          (RETRY_DELAY_AFTER_NACK,
           bind(&EncryptorV2::Impl::fetchKekAndPublishCkData, parent_,
                onReady_, onError_, nTriesLeft_ - 1));
      }
      else {
        ostringstream message;
        message <<  "Retrieval of KEK [" << interest->getName().toUri() <<
          "] failed. Got NACK (" << networkNack->getReason() << ")";
        onError_(EncryptError::ErrorCode::KekRetrievalFailure, message.str());
        _LOG_TRACE("Scheduling retry from NACK");
        parent_->face_->callLater
          (RETRY_DELAY_KEK_RETRIEVAL,
           bind(&EncryptorV2::Impl::retryFetchingKek, parent_));
      }
    }

    ptr_lib::shared_ptr<Impl> parent_;
    Face::Callback onReady_;
    EncryptError::OnError onError_;
    int nTriesLeft_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this(), onReady, onError, nTriesLeft);
    kekPendingInterestId_ = face_->expressInterest
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
EncryptorV2::Impl::makeAndPublishCkData(const EncryptError::OnError& onError)
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
    keyChain_->sign(ckData, ckDataSigningInfo_);
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
EncryptorV2::Impl::checkForNewGck(const EncryptError::OnError& onError)
{
  if (isGckRetrievalInProgress_)
    // Already checking.
    return;
  isGckRetrievalInProgress_ = true;

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks
      (const ptr_lib::shared_ptr<Impl>& parent,
       const EncryptError::OnError& onError)
    : parent_(parent), onError_(onError)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& ckInterest,
       const ptr_lib::shared_ptr<Data>& gckLatestData)
    {
      // Validate the Data signature.
      parent_->validator_->validate
        (*gckLatestData,
         [=](auto&) {
           Name newGckName;
           try {
             newGckName.wireDecode(gckLatestData->getContent());
           } catch (const std::exception& ex) {
             parent_->isGckRetrievalInProgress_ = false;
             onError_(EncryptError::ErrorCode::CkRetrievalFailure,
               string("Error decoding GCK name in: ") + gckLatestData->getName().toUri());
             return;
           }

           if (newGckName.equals(parent_->ckName_)) {
             // The latest is the same name, so do nothing.
             parent_->isGckRetrievalInProgress_ = false;
             return;
           }

           // Leave isGckRetrievalInProgress_ true.
           parent_->fetchGck(newGckName, onError_, N_RETRIES);
         },
         [=](auto&, auto& error) {
           parent_->isGckRetrievalInProgress_ = false;
           onError_(EncryptError::ErrorCode::CkRetrievalFailure,
             "Validate GCK latest_ Data failure: " + error.toString());
         });
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->isGckRetrievalInProgress_ = false;
      onError_(EncryptError::ErrorCode::CkRetrievalFailure,
        "Timeout for GCK _latest packet: " + interest->getName().toUri());
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->isGckRetrievalInProgress_ = false;
      ostringstream message;
      message << "Network nack for GCK _latest packet: " << interest->getName().toUri() <<
        ". Got NACK (" << networkNack->getReason() << ")";
      onError_(EncryptError::ErrorCode::CkRetrievalFailure, message.str());
    }

    ptr_lib::shared_ptr<Impl> parent_;
    EncryptError::OnError onError_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this(), onError);
    face_->expressInterest
      (Interest(gckLatestPrefix_).setMustBeFresh(true).setCanBePrefix(true),
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    onError_(EncryptError::ErrorCode::General,
             string("expressInterest error: ") + ex.what());
  }
}

void
EncryptorV2::Impl::fetchGck(
  const Name& gckName, const EncryptError::OnError& onError, int nTriesLeft)
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
    .append(credentialsKey_->getName());

  _LOG_TRACE("EncryptorV2: Fetching GCK " << encryptedGckName);

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks
      (const ptr_lib::shared_ptr<Impl>& parent, const Name& gckName,
       const EncryptError::OnError& onError, int nTriesLeft)
    : parent_(parent), gckName_(gckName), onError_(onError),
      nTriesLeft_(nTriesLeft)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& ckInterest,
       const ptr_lib::shared_ptr<Data>& ckData)
    {
      try {
        parent_->gckPendingInterestId_ = 0;

        // Leave isGckRetrievalInProgress_ true.
        parent_->decryptGckAndProcessPendingDecrypts(gckName_, *ckData, onError_);
      } catch (const std::exception& ex) {
        onError_(EncryptError::ErrorCode::General,
          string("Error in EncryptorV2::fetchGck onData: ") + ex.what());
      }
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->gckPendingInterestId_ = 0;
      if (nTriesLeft_ > 1)
        parent_->fetchGck(gckName_, onError_, nTriesLeft_ - 1);
      else {
        parent_->isGckRetrievalInProgress_ = false;
        onError_(EncryptError::ErrorCode::CkRetrievalTimeout,
          "Retrieval of GCK [" + interest->getName().toUri() + "] timed out");
      }
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->gckPendingInterestId_ = 0;
      parent_->isGckRetrievalInProgress_ = false;
      ostringstream message;
      message << "Retrieval of GCK [" << interest->getName().toUri() <<
        "] failed. Got NACK (" << networkNack->getReason() << ")";
      onError_(EncryptError::ErrorCode::CkRetrievalFailure, message.str());
    }

    ptr_lib::shared_ptr<Impl> parent_;
    Name gckName_;
    EncryptError::OnError onError_;
    int nTriesLeft_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this(), gckName, onError, nTriesLeft);
    gckPendingInterestId_ = face_->expressInterest
      (Interest(encryptedGckName).setMustBeFresh(false).setCanBePrefix(true),
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    onError_(EncryptError::ErrorCode::General,
            string("expressInterest error: ") + ex.what());
  }
}

void
EncryptorV2::Impl::decryptGckAndProcessPendingDecrypts(
  const Name& gckName, const Data& gckData, const EncryptError::OnError& onError)
{
  // This is only called from fetchGck, so isGckRetrievalInProgress_ is true.

  _LOG_TRACE("EncryptorV2: Decrypting GCK data " << gckData.getName());

  EncryptedContent content;
  try {
    content.wireDecodeV2(gckData.getContent());
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    onError(EncryptError::ErrorCode::InvalidEncryptedFormat,
      string("Error decrypting EncryptedContent: ") + ex.what());
    return;
  }

  Blob decryptedCkBits;
  try {
    decryptedCkBits = keyChain_->getTpm().decrypt
      (content.getPayload().buf(), content.getPayload().size(),
       credentialsKey_->getName());
  } catch (const std::exception& ex) {
    isGckRetrievalInProgress_ = false;
    onError(EncryptError::ErrorCode::DecryptionFailure,
      string("Error decrypting the GCK: ") + ex.what());
    return;
  }
  if (decryptedCkBits.isNull()) {
    isGckRetrievalInProgress_ = false;
    onError(EncryptError::ErrorCode::TpmKeyNotFound,
      "Could not decrypt secret, " + credentialsKey_->getName().toUri() +
    " not found in TPM");
    return;
  }

  if (decryptedCkBits.size() != ckBits_.size()) {
    isGckRetrievalInProgress_ = false;
    onError(EncryptError::ErrorCode::DecryptionFailure,
      "The decrypted group content key is not the correct size for the encryption algorithm");
    return;
  }
  ckName_ = gckName;
  ndn_memcpy(&ckBits_[0], decryptedCkBits.buf(), ckBits_.size());
  isGckRetrievalInProgress_ = false;

  for (size_t i = 0; i < pendingEncrypts_.size(); ++i) {
    PendingEncrypt& pendingEncrypt = *pendingEncrypts_[i];

    // TODO: If this calls onError, should we quit so that there is only one exit
    // from the asynchronous operation?
    ptr_lib::shared_ptr<EncryptedContent> encryptedContent = encrypt
      (pendingEncrypt.plainData.buf(), pendingEncrypt.plainData.size(),
       pendingEncrypt.associatedData.buf(), pendingEncrypt.associatedData.size());
    try {
      pendingEncrypt.onSuccess(encryptedContent);
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onSuccess: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onSuccess.");
    }
  }

  pendingEncrypts_.clear();
}

EncryptorV2::Values* EncryptorV2::values_ = 0;

}

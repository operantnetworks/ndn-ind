/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020-2021 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/encrypt/encryptor-v2.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use std::chrono. Support ChaCha20-Ploy1305, GCK,
 *   encrypted Interest, multiple access managers. Support ndn_ind_dll.
 *   Add setGckLatestInterestLifetime.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.hpp
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

#ifndef NDN_ENCRYPTOR_V2_HPP
#define NDN_ENCRYPTOR_V2_HPP

#include "../face.hpp"
#include "../security/key-chain.hpp"
#include "../security/v2/validator.hpp"
#include "../in-memory-storage/in-memory-storage-retaining.hpp"
#include "encrypted-content.hpp"
#include "encrypt-error.hpp"

// Give friend access to the tests.
class TestEncryptorV2_EncryptAndPublishCk_Test;
class TestEncryptorV2_EnumerateDataFromInMemoryStorage_Test;

namespace ndn {

ndn_ind_dll extern const std::chrono::nanoseconds RETRY_DELAY_AFTER_NACK;
ndn_ind_dll extern const std::chrono::nanoseconds RETRY_DELAY_KEK_RETRIEVAL;
ndn_ind_dll extern const std::chrono::nanoseconds DEFAULT_CK_FRESHNESS_PERIOD;

/**
 * EncryptorV2 encrypts the requested content for name-based access control (NAC)
 * using security v2. For the meaning of "KEK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 */
class ndn_ind_dll EncryptorV2 {
public:
  typedef func_lib::function<void
    (const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent)> OnEncryptSuccess;

  typedef func_lib::function<void
    (const ptr_lib::shared_ptr<Data>& data,
     const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent)> OnEncryptDataSuccess;

  typedef func_lib::function<void
    (const ptr_lib::shared_ptr<Interest>& interest,
     const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent)> OnEncryptInterestSuccess;

  /**
   * Create an EncryptorV2 for encrypting using a group KEK and KDK. This uses
   * the face to register to receive Interests for the prefix {ckPrefix}/CK.
   * @param accessPrefix The NAC prefix to fetch the Key Encryption Key (KEK)
   * (e.g., /access/prefix/NAC/data/subset). This copies the Name.
   * @param ckPrefix The prefix under which Content Keys (CK) will be generated.
   * (Each will have a unique version appended.) This copies the Name.
   * @param ckDataSigningInfo The SigningInfo parameters to sign the Content Key
   * (CK) Data packet. This copies the SigningInfo.
   * @param onError On failure to create the CK data (failed to fetch the KEK,
   * failed to encrypt with the KEK, etc.), this calls
   * onError(errorCode, message) where errorCode is from the
   * EncryptError::ErrorCode enum, and message is an error string. The encrypt
   * method will continue trying to retrieve the KEK until success (with each
   * attempt separated by RETRY_DELAY_KEK_RETRIEVAL) and onError may be
   * called multiple times.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param validator The validation policy to ensure correctness of the KEK.
   * @param keyChain The KeyChain used to sign Data packets.
   * @param face The Face that will be used to fetch the KEK and publish CK data.
   * @param algorithmType (optional) The encryption algorithm type for this
   * EncryptorV2. If omitted or ndn_EncryptAlgorithmType_AesCbc, use AES 256 in
   * CBC mode. If ndn_EncryptAlgorithmType_ChaCha20Poly1305, use ChaCha20-Poly1305.
   */
  EncryptorV2
    (const Name& accessPrefix, const Name& ckPrefix,
     const SigningInfo& ckDataSigningInfo, const EncryptError::OnError& onError,
     Validator* validator, KeyChain* keyChain, Face* face,
     ndn_EncryptAlgorithmType algorithmType = ndn_EncryptAlgorithmType_AesCbc)
  : impl_(new Impl
          (accessPrefix, ckPrefix, ckDataSigningInfo, onError, validator, 
           keyChain, face, algorithmType))
  {
    impl_->initializeCk();
  }

  /**
   * Create an EncryptorV2 for encrypting using a group content key (GCK) which
   * is provided by the access manager.
   * @param accessPrefix The NAC prefix to fetch the group content key (GCK)
   * (e.g., /access/prefix/NAC/data/subset). This copies the Name.
   * @param onError On failure to create the CK data (failed to fetch the KEK,
   * failed to encrypt with the KEK, etc.), this calls
   * onError(errorCode, message) where errorCode is from the
   * EncryptError::ErrorCode enum, and message is an error string. The encrypt
   * method will continue trying to retrieve the KEK until success (with each
   * attempt separated by RETRY_DELAY_KEK_RETRIEVAL) and onError may be
   * called multiple times.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param credentialsKey The credentials key to be used to retrieve and
   * decrypt the GCK.
   * @param validator The validation policy to ensure correctness of the GCK.
   * @param keyChain The KeyChain used to access the credentials key.
   * @param face The Face that will be used to fetch the GCK.
   * @param algorithmType (optional) The encryption algorithm type for this
   * EncryptorV2. If omitted or ndn_EncryptAlgorithmType_AesCbc, use AES 256 in
   * CBC mode. If ndn_EncryptAlgorithmType_ChaCha20Poly1305, use ChaCha20-Poly1305.
   */
  EncryptorV2
    (const Name& accessPrefix, const EncryptError::OnError& onError,
     PibKey* credentialsKey, Validator* validator, KeyChain* keyChain, Face* face,
     ndn_EncryptAlgorithmType algorithmType = ndn_EncryptAlgorithmType_AesCbc)
  : impl_(new Impl
          (&accessPrefix, 1, onError, credentialsKey, validator, keyChain, face,
           algorithmType))
  {
    impl_->initializeGck();
  }

  /**
   * Create an EncryptorV2 for encrypting using a group content key (GCK) which
   * is provided by one of the access managers in a prioritized list.
   * @param accessPrefixes A pointer to a prioritized array where each element
   * is the NAC prefix of an access manager for fetching the group content key
   * (GCK) (e.g., /access/prefix/NAC/data/subset). This will repeatedly try to
   * fetch the GCK from all access managers and encrypt will GCK that was
   * successfully fetched from the first (highest-priority) access manager in
   * the list. This copies the Names.
   * @param nAccessPrefixes The number of elements in the accessPrefixes array.
   * @param onError On failure to create the CK data (failed to fetch the KEK,
   * failed to encrypt with the KEK, etc.), this calls
   * onError(errorCode, message) where errorCode is from the
   * EncryptError::ErrorCode enum, and message is an error string. The encrypt
   * method will continue trying to retrieve the KEK until success (with each
   * attempt separated by RETRY_DELAY_KEK_RETRIEVAL) and onError may be
   * called multiple times.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param credentialsKey The credentials key to be used to retrieve and
   * decrypt the GCK.
   * @param validator The validation policy to ensure correctness of the GCK.
   * @param keyChain The KeyChain used to access the credentials key.
   * @param face The Face that will be used to fetch the GCK.
   * @param algorithmType (optional) The encryption algorithm type for this
   * EncryptorV2. If omitted or ndn_EncryptAlgorithmType_AesCbc, use AES 256 in
   * CBC mode. If ndn_EncryptAlgorithmType_ChaCha20Poly1305, use ChaCha20-Poly1305.
   */
  EncryptorV2
    (const Name* accessPrefixes, size_t nAccessPrefixes,
     const EncryptError::OnError& onError, PibKey* credentialsKey,
     Validator* validator, KeyChain* keyChain, Face* face,
     ndn_EncryptAlgorithmType algorithmType = ndn_EncryptAlgorithmType_AesCbc)
  : impl_(new Impl
          (accessPrefixes, nAccessPrefixes, onError, credentialsKey, validator,
           keyChain, face, algorithmType))
  {
    impl_->initializeGck();
  }

  void
  shutdown() { impl_->shutdown(); }

  /**
   * Encrypt the plainData using the existing content key and return a new
   * EncryptedContent.
   * @param plainData The data to encrypt.
   * @param plainDataLength The length of plainData.
   * @param associatedData (optional) A pointer to the associated data which is
   * included in the calculation of the authentication tag, but is not
   * encrypted. If associatedDataLength is 0, then this can be NULL. If the
   * associatedData is omitted or if associatedDataLength is 0, then no
   * associated data is used.
   * @param associatedDataLength (optional) The length of associatedData.
   * @return The new EncryptedContent.
   * @throws runtime_error if this EncryptorV2 is using a group content key (GCK)
   * and the first GCK has not been fetched. (When using a group content key,
   * you should call the asynchronous encrypt method with the onSuccess callback.)
   */
  ptr_lib::shared_ptr<EncryptedContent>
  encrypt
    (const uint8_t* plainData, size_t plainDataLength,
     const uint8_t *associatedData = 0, size_t associatedDataLength = 0)
  {
    return impl_->encrypt
      (plainData, plainDataLength, associatedData, associatedDataLength);
  }

  /**
   * Encrypt the plainData using the existing content key and return a new
   * EncryptedContent.
   * @param plainData The data to encrypt.
   * @param associatedData (optional) The associated data which is included in
   * the calculation of the authentication tag, but is not encrypted. If
   * associatedData.size() is 0, then this can be an isNull() Blob. If the
   * associatedData is omitted or if its size() is 0, then no associated data is
   * used.
   * @return The new EncryptedContent.
   * @throws runtime_error if this EncryptorV2 is using a group content key (GCK)
   * and the first GCK has not been fetched. (When using a group content key,
   * you should call the asynchronous encrypt method with the onSuccess callback.)
   */
  ptr_lib::shared_ptr<EncryptedContent>
  encrypt(const Blob& plainData, const Blob& associatedData = Blob())
  {
    return encrypt
      (plainData.buf(), plainData.size(), associatedData.buf(),
       associatedData.size());
  }

  /**
   * Encrypt the plainData using the existing content key and call the onSuccess
   * callback with a new EncryptedContent. If this EncryptorV2 is using a group
   * content key (GCK) then this may fetch a new GCK before calling the
   * onSuccess callback.
   * @param plainData The data to encrypt.
   * @param associatedData The associated data which is included in the
   * calculation of the authentication tag, but is not encrypted. If
   * associatedData.size() is 0, then this can be an isNull() Blob. If the
   * associatedData size() is 0, then no associated data is used.
   * @param onSuccess On successful encryption, this calls
   * onSuccess(encryptedContent) where encryptedContent is the new 
   * EncryptedContent.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError (optional) On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string. If omitted, call the onError given to the constructor. (Even though
   * the constructor has an onError, this is provided separately since this
   * asynchronous method completes either by calling onSuccess or onError.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  void
  encrypt
    (const Blob& plainData, const Blob& associatedData,
     const OnEncryptSuccess& onSuccess,
     const EncryptError::OnError& onError = EncryptError::OnError())
  {
    return impl_->encrypt(plainData, associatedData, onSuccess, onError);
  }

  /**
   * Encrypt the plainData (with no associated data) using the existing content
   * key and call the onSuccess callback with a new EncryptedContent. If this
   * EncryptorV2 is using a group content key (GCK) then this may fetch a new
   * GCK before calling the onSuccess callback.
   * @param plainData The data to encrypt.
   * @param onSuccess On successful encryption, this calls
   * onSuccess(encryptedContent) where encryptedContent is the new
   * EncryptedContent.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError (optional) On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string. If omitted, call the onError given to the constructor. (Even though
   * the constructor has an onError, this is provided separately since this
   * asynchronous method completes either by calling onSuccess or onError.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  void
  encrypt
    (const Blob& plainData, const OnEncryptSuccess& onSuccess,
     const EncryptError::OnError& onError = EncryptError::OnError())
  {
    return encrypt(plainData, Blob(), onSuccess, onError);
  }

  /**
   * Encrypt the Data packet content using the existing content key and
   * replace the content with the wire encoding of the new EncryptedContent. If
   * this EncryptorV2 is using a group content key (GCK) then this may fetch a
   * new GCK before calling the onSuccess callback.
   * When encrypting, use the encoding of the Data packet name as the
   * "associated data".
   * @param data The Data packet whose content is encrypted and replaced with a
   * new EncryptedContent. (This is also passed to the onSuccess callback.)
   * @param onSuccess On successful encryption, this calls
   * onSuccess(data, encryptedContent) where data is the the modified Data object
   * that was provided, and encryptedContent is the new EncryptedContent whose
   * encoding replaced the Data packet content.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError (optional) On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string. If omitted, call the onError given to the constructor. (Even though
   * the constructor has an onError, this is provided separately since this
   * asynchronous method completes either by calling onSuccess or onError.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat (optional) A WireFormat object used to encode the Data
   * packet name. If omitted, use WireFormat::getDefaultWireFormat().
   */
  void
  encrypt
    (const ptr_lib::shared_ptr<Data>& data, const OnEncryptDataSuccess& onSuccess,
     const EncryptError::OnError& onError = EncryptError::OnError(),
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    encrypt
      (data->getContent(), data->getName().wireEncode(wireFormat),
       [=](const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent) {
         data->setContent(encryptedContent->wireEncodeV2());
         onSuccess(data, encryptedContent);
       },
       onError);
  }

  /**
   * Encrypt the Interest ApplicationParameters using the existing content key
   * and replace the ApplicationParameters with the wire encoding of the new
   * EncryptedContent. If this EncryptorV2 is using a group content key (GCK)
   * then this may fetch a new GCK before calling the onSuccess callback.
   * When encrypting, use the encoding of the Interest name as the "associated
   * data". This appends a ParametersSha256Digest component to the Interest name.
   * @param interest The Interest whose ApplicationParameters is encrypted and
   * replaced with a new EncryptedContent. (This is also passed to the onSuccess
   * callback.)
   * @param onSuccess On successful encryption, this calls
   * onSuccess(interest, encryptedContent) where interest is the the modified
   * Interest object that was provided, and encryptedContent is the new
   * EncryptedContent whose encoding replaced the Interest ApplicationParameters.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError (optional) On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string. If omitted, call the onError given to the constructor. (Even though
   * the constructor has an onError, this is provided separately since this
   * asynchronous method completes either by calling onSuccess or onError.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat (optional) A WireFormat object used to encode the
   * Interest name. If omitted, use WireFormat::getDefaultWireFormat().
   */
  void
  encrypt
    (const ptr_lib::shared_ptr<Interest>& interest,
     const OnEncryptInterestSuccess& onSuccess,
     const EncryptError::OnError& onError = EncryptError::OnError(),
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  /**
   * Create a new Content Key (CK) and publish the corresponding CK Data packet.
   * This uses the onError given to the constructor to report errors.
   * @throws runtime_error if this EncryptorV2 uses a group content key.
   */
  void
  regenerateCk() { impl_->regenerateCk(); }

  /**
   * Set the interval for sending an Interest to the access manager to get the
   * name of the latest GCK (and to fetch it if it is new). If you don't call
   * this, then use the default of 1 minute.
   * @param checkForNewGckInterval The interval.
   */
  void
  setCheckForNewGckInterval(std::chrono::nanoseconds checkForNewGckInterval)
  {
    impl_->setCheckForNewGckInterval(checkForNewGckInterval);
  }

  /**
   * Set the Interest lifetime for the Interest sent to the access manager to
   * get the name of the latest GCK. If you don't call this, then use the
   * default Interest lifetime as defined by the Interest class.
   * @param gckLatestInterestLifetime The Interest lifetime.
   */
  void
  setGckLatestInterestLifetime(std::chrono::nanoseconds gckLatestInterestLifetime)
  {
    impl_->setGckLatestInterestLifetime(gckLatestInterestLifetime);
  }

  /**
   * Get the number of packets stored in in-memory storage.
   * @return The number of packets.
   */
  size_t
  size() { return impl_->size(); }

  /**
   * Get the content key for the key name. If this EncryptorV2 is using a group
   * content key (GCK), this may also initiate a check for new keys.
   * @param keyName The name of the generated CK or fetched GCK.
   * @return The key for the name, or an isNull() Blob if not found.
   */
  Blob
  getContentKey(const Name& keyName) { return impl_->getContentKey(keyName); }

  static const Name::Component&
  getNAME_COMPONENT_ENCRYPTED_BY() { return getValues().NAME_COMPONENT_ENCRYPTED_BY; }

  static const Name::Component&
  getNAME_COMPONENT_NAC() { return getValues().NAME_COMPONENT_NAC; }

  static const Name::Component&
  getNAME_COMPONENT_KEK() { return getValues().NAME_COMPONENT_KEK; }

  static const Name::Component&
  getNAME_COMPONENT_KDK() { return getValues().NAME_COMPONENT_KDK; }

  static const Name::Component&
  getNAME_COMPONENT_CK() { return getValues().NAME_COMPONENT_CK; }

  static const Name::Component&
  getNAME_COMPONENT_GCK() { return getValues().NAME_COMPONENT_GCK; }

  static const Name::Component&
  getNAME_COMPONENT_LATEST() { return getValues().NAME_COMPONENT_LATEST; }

  static const int AES_KEY_SIZE = 32;
  static const int AES_IV_SIZE = 16;
  static const int N_RETRIES = 3;

private:
  // Give friend access to the tests.
  friend class ::TestEncryptorV2_EncryptAndPublishCk_Test;
  friend class ::TestEncryptorV2_EnumerateDataFromInMemoryStorage_Test;

  /**
   * Values holds values used by the static member values_.
   */
  class Values {
  public:
    Values()
    : NAME_COMPONENT_ENCRYPTED_BY("ENCRYPTED-BY"),
      NAME_COMPONENT_NAC("NAC"),
      NAME_COMPONENT_KEK("KEK"),
      NAME_COMPONENT_KDK("KDK"),
      NAME_COMPONENT_CK("CK"),
      NAME_COMPONENT_GCK("GCK"),
      NAME_COMPONENT_LATEST("_latest")
    {}

    Name::Component NAME_COMPONENT_ENCRYPTED_BY;
    Name::Component NAME_COMPONENT_NAC;
    Name::Component NAME_COMPONENT_KEK;
    Name::Component NAME_COMPONENT_KDK;
    Name::Component NAME_COMPONENT_CK;
    Name::Component NAME_COMPONENT_GCK;
    Name::Component NAME_COMPONENT_LATEST;
  };

  /**
   * Get the static Values object, creating it if needed. We do this explicitly
   * because some C++ environments don't handle static constructors well.
   * @return The static Values object.
   */
  static Values&
  getValues()
  {
    if (!values_)
      values_ = new Values();

    return *values_;
  }

  static Values* values_;

  /**
   * EncryptorV2::Impl does the work of EncryptorV2. It is a separate class so
   * that EncryptorV2 can create an instance in a shared_ptr to use in callbacks.
   */
  class Impl : public ptr_lib::enable_shared_from_this<Impl> {
  public:
    /**
     * Create a new Impl, which should belong to a shared_ptr. Then you must 
     * call initialize(). See the EncryptorV2 constructor for parameter
     * documentation.
     */
    Impl
      (const Name& accessPrefix, const Name& ckPrefix,
       const SigningInfo& ckDataSigningInfo, const EncryptError::OnError& onError,
       Validator* validator, KeyChain* keyChain, Face* face,
       ndn_EncryptAlgorithmType algorithmType);

    Impl
      (const Name* accessPrefixes, size_t nAccessPrefixes, const EncryptError::OnError& onError,
       PibKey* credentialsKey, Validator* validator, KeyChain* keyChain, Face* face,
       ndn_EncryptAlgorithmType algorithmType);

    /**
     * Complete the work of the constructor for a (non-group) content key. This
     * is needed because we can't call shared_from_this() in the constructor.
     */
    void
    initializeCk()
    {
      // For non-GCK, there is only one KeyManager.
      keyManagers_[0]->initializeCk();
    }

    /**
     * Complete the work of the constructor for a group content key. This is
     * needed because we can't call shared_from_this() in the constructor.
     */
    void
    initializeGck()
    {
      checkForNewGckInterval_ = std::chrono::minutes(1);
      gckLatestInterestLifetime_ = std::chrono::milliseconds(-1);
    }

    void
    shutdown()
    {
      for (int i = 0; i < keyManagers_.size(); ++i)
        keyManagers_[i]->shutdown();
    }

    ptr_lib::shared_ptr<EncryptedContent>
    encrypt
      (const uint8_t* plainData, size_t plainDataLength,
       const uint8_t *associatedData, size_t associatedDataLength);

    void
    encrypt
      (const Blob& plainData, const Blob& associatedData,
       const OnEncryptSuccess& onSuccess,
       const EncryptError::OnError& onError);

    /**
     * Create a new Content Key (CK) and publish the corresponding CK Data
     * packet. This uses the onError given to the constructor to report errors.
     */
    void
    regenerateCk()
    {
      // For non-GCK, there is only one KeyManager.
      keyManagers_[0]->regenerateCk();
    }

    void
    setCheckForNewGckInterval(std::chrono::nanoseconds checkForNewGckInterval)
    {
      checkForNewGckInterval_ = checkForNewGckInterval;
    }

    void
    setGckLatestInterestLifetime(std::chrono::nanoseconds gckLatestInterestLifetime)
    {
      gckLatestInterestLifetime_ = gckLatestInterestLifetime;
    }

    size_t
    size()
    {
      if (isUsingGck())
        throw std::runtime_error
          ("This EncryptorV2 uses a group content key. Cannot get the number of published CK packets");

      // For non-GCK, there is only one KeyManager.
      return keyManagers_[0]->size();
    }

    Blob
    getContentKey(const Name& keyName);

  private:
    // Give friend access to the tests.
    friend class ::TestEncryptorV2_EncryptAndPublishCk_Test;
    friend class ::TestEncryptorV2_EnumerateDataFromInMemoryStorage_Test;

    class PendingEncrypt {
    public:
      PendingEncrypt
        (const Blob& plainDataIn, const Blob& associatedDataIn,
         const OnEncryptSuccess& onSuccessIn,
         const EncryptError::OnError& onErrorIn)
      : plainData(plainDataIn), associatedData(associatedDataIn),
        onSuccess(onSuccessIn), onError(onErrorIn)
      {}

      Blob plainData;
      Blob associatedData;
      OnEncryptSuccess onSuccess;
      EncryptError::OnError onError;
    };

    /**
     * EncryptorV2::Impl::KeyManager keeps track of the key associated with a
     * particular access prefix.
     */
    class KeyManager : public ptr_lib::enable_shared_from_this<KeyManager> {
    public:
      KeyManager
        (Impl* parent, const Name& accessPrefix, const Name& ckPrefix,
         const SigningInfo& ckDataSigningInfo);

      KeyManager(Impl* parent, const Name& accessPrefix);

      /**
       * Complete the work of the constructor for a (non-group) content key. This
       * is needed because we can't call shared_from_this() in the constructor.
       */
      void
      initializeCk();

      void
      shutdown();

      /**
       * Encrypt the plainData using the existing content key for this KeyManager
       * and return a new EncryptedContent.
       * @param plainData The data to encrypt.
       * @param plainDataLength The length of plainData.
       * @param associatedData (optional) A pointer to the associated data which is
       * included in the calculation of the authentication tag, but is not
       * encrypted. If associatedDataLength is 0, then this can be NULL. If the
       * associatedData is omitted or if associatedDataLength is 0, then no
       * associated data is used.
       * @param associatedDataLength (optional) The length of associatedData.
       * @return The new EncryptedContent or null if using a group content key (GCK)
       * and the first GCK has not been fetched. The caller should check for null
       * and throw an exception if encryption cannot be performed.
       */
      ptr_lib::shared_ptr<EncryptedContent>
      encrypt
        (const uint8_t* plainData, size_t plainDataLength,
         const uint8_t *associatedData, size_t associatedDataLength);

      /**
       * Check if the content key is ready for calling encrypt. This may send an
       * Interest to check if there is a new GCK.
       * @return True if the key is ready. If false, then the caller should
       * save in pendingEncrypts_ until a key is ready.
       */
      bool
      isKeyReady();

      void
      regenerateCk();

      size_t
      size() { return storage_.size(); }

      const Name&
      getAccessPrefix() const { return accessPrefix_; }

    private:
      // Give friend access to the tests.
      friend class ::TestEncryptorV2_EncryptAndPublishCk_Test;
      friend class ::TestEncryptorV2_EnumerateDataFromInMemoryStorage_Test;

    void
    retryFetchingKek();

    /**
     * Create an Interest for <access-prefix>/KEK to retrieve the
     * <access-prefix>/KEK/<key-id> KEK Data packet, and set kekData_.
     * @param onReady When the KEK is retrieved and published, this calls
     * onReady().
     * @param onError On failure, this calls onError(errorCode, message) where
     * errorCode is from the EncryptError::ErrorCode enum, and message is an
     * error string.
     * @param nTriesLeft The number of retries for expressInterest timeouts.
     */
    void
    fetchKekAndPublishCkData
      (const Face::Callback& onReady, const EncryptError::OnError& onError,
       int nTriesLeft);

    /**
     * Make a CK Data packet for ckName_ encrypted by the KEK in kekData_ and
     * insert it in the storage_.
     * @param onError On failure, this calls onError(errorCode, message) where
     * errorCode is from the EncryptError::ErrorCode enum, and message is an
     * error string.
     * @return True on success, else false.
     */
    bool
    makeAndPublishCkData(const EncryptError::OnError& onError);

    /**
     * Send an interest for the gckLatestPrefix_ to get the name of the latest
     * GCK. If it doesn't match gckName_, then call fetchGck().
     */
    void
    checkForNewGck();

    /**
     * Fetch the Data packet <gckName>/ENCRYPTED-BY/<credentials-key> and call
     * decryptGck to decrypt it.
     * @param gckName The name of the group content key formed from the
     * access prefix, e.g. <access-prefix>/GCK/<gck-id> .
     * @param nTriesLeft If fetching times out, decrement nTriesLeft and try
     * again until it is zero.
     */
    void
    fetchGck(const Name& gckName, int nTriesLeft);

    /**
     * Decrypt the gckData fetched by fetchGck(), then copy it to ckBits_ and
     * copy gckName to ckName_ . Then process pending encrypts.
     * Also store the name and key in parent_->contentKeys_.
     * @param gckName The Name that fetchGck() used to fetch.
     * @param gckData The GCK Data packet fetched by fetchGck().
     */
    void decryptGckAndProcessPendingEncrypts(
      const Name& gckName, const Data& gckData);

      Impl* parent_;
      Name accessPrefix_;
      // Generated CK name or fetched GCK name.
      Name ckName_;
      // Generated CK or fetched GCK bits.
      std::vector<uint8_t> ckBits_;

      // For creating CK Data packets. Not used for GCK.
      Name ckPrefix_;
      bool isKekRetrievalInProgress_;
      ptr_lib::shared_ptr<Data> kekData_;
      SigningInfo ckDataSigningInfo_;

      // Storage for encrypted CKs. Not used for GCK.
      InMemoryStorageRetaining storage_;
      uint64_t ckRegisteredPrefixId_;
      uint64_t kekPendingInterestId_;

      // For fetching and decrypting the GCK. Not used for CK.
      std::chrono::system_clock::time_point nextCheckForNewGck_;
      bool isGckRetrievalInProgress_;
      Name gckLatestPrefix_;
      uint64_t gckPendingInterestId_;
      bool accessManagerIsResponding_;
      // The next GCK to use after enough time to be sure others have fetched it.
      std::chrono::system_clock::time_point nextGckReceiptTime_;
      Name nextGckName_;
      Blob nextGckBits_;
    };

    bool
    isUsingGck() { return !!credentialsKey_; }

    /**
     * For each entry in pendingEncrypts_, call encrypt. If there are no
     * pending encrypts, then this does nothing and returns quickly.
     */
    void
    processPendingEncrypts();

    // For fetching and decrypting the GCK. Not used for CK.
    std::chrono::nanoseconds checkForNewGckInterval_;
    std::chrono::nanoseconds gckLatestInterestLifetime_; /**< -1 ms to use the default */
    std::vector<ptr_lib::shared_ptr<PendingEncrypt> > pendingEncrypts_;
    PibKey* credentialsKey_;

    EncryptError::OnError onError_;
    Validator* validator_;
    KeyChain* keyChain_;
    Face* face_;
    ndn_EncryptAlgorithmType algorithmType_;
    std::vector<ptr_lib::shared_ptr<KeyManager> > keyManagers_;
    // The index in keyManagers_ of the last successful encryption.
    int iKeyManagerLastEncryption_;
    // A historical record mapping the generated CK name or fetched GCK name to
    // the content key.
    std::map<Name, Blob> contentKeys_;
  };

  ptr_lib::shared_ptr<Impl> impl_;
};

}

#endif

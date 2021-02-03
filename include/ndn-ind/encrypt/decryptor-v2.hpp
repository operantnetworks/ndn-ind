/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020-2021 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/encrypt/decryptor-v2.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use std::chrono. Support ChaCha20-Ploy1305, GCK,
 *   encrypted Interest, multiple access managers. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/decryptor.hpp
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

#ifndef NDN_DECRYPTOR_V2_HPP
#define NDN_DECRYPTOR_V2_HPP

#include "../security/key-chain.hpp"
#include "../security/v2/validator.hpp"
#include "encryptor-v2.hpp"
#include "encrypted-content.hpp"
#include "encrypt-error.hpp"

namespace ndn {

/**
 * DecryptorV2 decrypts the supplied EncryptedContent element, using
 * asynchronous operations, contingent on the retrieval of the CK Data packet,
 * the KDK, and the successful decryption of both of these. For the meaning of
 * "KDK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 */
class ndn_ind_dll DecryptorV2 {
public:
  typedef func_lib::function<void(const Blob& plainData)> DecryptSuccessCallback;

  /**
   * Create a DecryptorV2 with the given parameters.
   * @param credentialsKey The credentials key to be used to retrieve and
   * decrypt the KDK.
   * @param validator The validation policy to ensure the validity of the KDK
   * and CK.
   * @param keyChain The KeyChain that will be used to decrypt the KDK.
   * @param face The Face that will be used to fetch the CK and KDK.
   * @param contentKeyCache An EncyptorV2 for calling getContentKey() to first
   * check if it has already fetched the content key. If null, don't check.
   */
  DecryptorV2
    (PibKey* credentialsKey, Validator* validator, KeyChain* keyChain,
     Face* face, EncryptorV2* contentKeyCache = 0)
  : impl_(new Impl(credentialsKey, validator, keyChain, face, contentKeyCache))
  {
  }

  void
  shutdown() { impl_->shutdown(); }

  /**
   * Asynchronously decrypt the encryptedContent.
   * @param encryptedContent The EncryptedContent to decrypt, which must have
   * a KeyLocator with a KEYNAME and and initial vector. This does not copy
   * the EncryptedContent object. If you may change it later, then pass in a
   * copy of the object.
   * @param associatedData The associated data which is included in the
   * calculation of the authentication tag, but is not encrypted. If
   * associatedData.size() is 0, then this can be an isNull() Blob. If
   * associatedData.size() is 0, then no associated data is used.
   * @param onSuccess On successful decryption, this calls
   * onSuccess(plainData) where plainData is the decrypted Blob.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  void
  decrypt
    (const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent,
     const Blob& associatedData, const DecryptSuccessCallback& onSuccess,
     const EncryptError::OnError& onError)
  {
    impl_->decrypt(encryptedContent, associatedData, onSuccess, onError);
  }

  /**
   * Asynchronously decrypt the encryptedContent.
   * @param encryptedContent The EncryptedContent to decrypt, which must have
   * a KeyLocator with a KEYNAME and and initial vector. This does not copy
   * the EncryptedContent object. If you may change it later, then pass in a
   * copy of the object.
   * @param onSuccess On successful decryption, this calls
   * onSuccess(plainData) where plainData is the decrypted Blob.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  void
  decrypt
    (const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent,
     const DecryptSuccessCallback& onSuccess,
     const EncryptError::OnError& onError)
  {
    decrypt(encryptedContent, Blob(), onSuccess, onError);
  }

  /**
   * Asynchronously decrypt the Data packet content by decoding it as an
   * EncryotedContent. When decrypting, use the encoding of the Data packet name
   * as the "associated data".
   * @param data The Data packet whose content is decoded as an EncryptdContent
   * and whose name encoding is used as the "associated data".
   * @param onSuccess On successful decryption, this calls
   * onSuccess(plainData) where plainData is the decrypted Blob.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string.
   * @param wireFormat (optional) A WireFormat object used to encode the Data 
   * packet name to use as the "associated data". If omitted, use
   * WireFormat::getDefaultWireFormat().
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  void
  decrypt
    (const Data& data, const DecryptSuccessCallback& onSuccess,
     const EncryptError::OnError& onError,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    ptr_lib::shared_ptr<EncryptedContent> encryptedContent
      (new EncryptedContent());
    try {
      encryptedContent->wireDecodeV2(data.getContent());
    } catch (const std::exception& ex) {
      onError(EncryptError::ErrorCode::DecryptionFailure,
        std::string("Error decoding the Data content as EncryptedContent: ") + ex.what());
      return;
    }

    decrypt
      (encryptedContent, data.getName().wireEncode(wireFormat), onSuccess,
       onError);
  }

  /**
   * Asynchronously decrypt the Interest's ApplicationParameters by decoding it
   * as an EncryotedContent. When decrypting, use the encoding of the 
   * Interest name (up to the ParametersSha256Digest component) as the
   * "associated data".
   * @param interest The Interest whose ApplicationParameters is decoded as an
   * EncryptdContent and whose name encoding (up to the ParametersSha256Digest
   * component) is used as the "associated data".
   * @param onSuccess On successful decryption, this calls
   * onSuccess(plainData) where plainData is the decrypted Blob.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError On failure, this calls onError(errorCode, message)
   * where errorCode is from EncryptError::ErrorCode, and message is an error
   * string.
   * @param wireFormat (optional) A WireFormat object used to encode the 
   * Interest name to use as the "associated data". If omitted, use
   * WireFormat::getDefaultWireFormat().
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  void
  decrypt
    (const Interest& interest, const DecryptSuccessCallback& onSuccess,
     const EncryptError::OnError& onError,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  class ContentKey {
  public:
    class PendingDecrypt {
    public:
      PendingDecrypt
        (const ptr_lib::shared_ptr<EncryptedContent>& encryptedContentIn,
         const Blob& associatedDataIn,
         const DecryptSuccessCallback& onSuccessIn,
         const EncryptError::OnError& onErrorIn)
      : encryptedContent(encryptedContentIn), associatedData(associatedDataIn),
        onSuccess(onSuccessIn), onError(onErrorIn)
      {}

      ptr_lib::shared_ptr<EncryptedContent> encryptedContent;
      Blob associatedData;
      DecryptSuccessCallback onSuccess;
      EncryptError::OnError onError;
    };

    ContentKey()
    : isRetrieved(false), pendingInterest(0)
    {}

    bool isRetrieved;
    Blob bits;
    uint64_t pendingInterest;
    std::vector<ptr_lib::shared_ptr<PendingDecrypt> > pendingDecrypts;
  };

private:
  /**
   * DecryptorV2::Impl does the work of DecryptorV2. It is a separate class so
   * that DecryptorV2 can create an instance in a shared_ptr to use in callbacks.
   */
  class Impl : public ptr_lib::enable_shared_from_this<Impl> {
  public:
    Impl
      (PibKey* credentialsKey, Validator* validator, KeyChain* keyChain,
       Face* face, EncryptorV2* contentKeyCache);

    void
    shutdown();

  void
  decrypt
    (const ptr_lib::shared_ptr<EncryptedContent>& encryptedContent,
     const Blob& associatedData, const DecryptSuccessCallback& onSuccess,
     const EncryptError::OnError& onError);

  private:
    void
    fetchCk
      (const Name& ckName, const ptr_lib::shared_ptr<ContentKey>& contentKey,
       const EncryptError::OnError& onError, int nTriesLeft);

    void
    fetchKdk
      (const ptr_lib::shared_ptr<ContentKey>& contentKey, const Name& kdkPrefix,
       const ptr_lib::shared_ptr<Data>& ckData,
       const EncryptError::OnError& onError, int nTriesLeft);

    /**
     * @return True for success, false for error (where this has called onError).
     */
    bool
    decryptAndImportKdk
      (const Data& kdkData, const EncryptError::OnError& onError);

    /**
     * Fetch the encrypted group content key by appending ckName with
     * /ENCRYPTED-BY/<credential-identity>/KEY/<key-id> . When received, call
     * decryptCkAndProcessPendingDecrypts().
     * @param ckName The Name from the KeyLocator of the EncryptedContent.
     * Assume this has GCK instead of CK.
     * @param contentKey The ContentKey structure for storing the content key bits
     * (passed to decryptCkAndProcessPendingDecrypts()).
     * @param onError On failure, this calls onError(errorCode, message)
     * where errorCode is from EncryptError::ErrorCode, and message is an error
     * string.
     * @param nTriesLeft If fetching times out, decrement nTriesLeft and try
     * again until it is zero.
     */
    void
    fetchGck
      (const Name& ckName, const ptr_lib::shared_ptr<ContentKey>& contentKey,
       const EncryptError::OnError& onError, int nTriesLeft);

    /**
     * Decrypt ckData to get the content key bits, store them in the contentKey
     * structure, and call doDecrypt for each entry in pendingDecrypts.
     * @param contentKey The ContentKey structure for storing the content key bits.
     * @param ckData The retrieved Data packet with the encrypted content key.
     * @param kdkKeyName This decrypts the ckData contents with the private key
     * in the internalKeyChain_ with the name kdkKeyName. However, if kdkKeyName 
     * is empty, assume that ckData is a group content key and decrypt using the
     * private key in keyChain_ with the name credentialsKey_->getName() .
     * @param onError
     */
    void
    decryptCkAndProcessPendingDecrypts
      (ContentKey& contentKey, const Data& ckData, const Name& kdkKeyName,
       const EncryptError::OnError& onError);

    static void
    doDecrypt
      (const EncryptedContent& content, const Blob& ckBits,
       const Blob& associatedData, const DecryptSuccessCallback& onSuccess,
       const EncryptError::OnError& onError);

    /**
     * Convert the KEK name to the KDK prefix:
     * <access-namespace>/KEK/<key-id> ==> <access-namespace>/KDK/<key-id>.
     * @param kekName The KEK name.
     * @param onError This calls onError(errorCode, message) for an error.
     * @return The KDK prefix, or an empty Name if an error was reported to
     * onError.
     */
    static Name
    convertKekNameToKdkPrefix
      (const Name& kekName, const EncryptError::OnError& onError);

    /**
     * Extract the KDK information from the CK Data packet name. The KDK
     * identity name plus the KDK key ID together identify the KDK private key
     * in the KeyChain.
     * @param ckDataName The name of the CK Data packet.
     * @param ckName The CK name from the Interest used to fetch the CK Data
     * packet.
     * @param onError This calls onError(errorCode, message) for an error.
     * @param kdkPrefix This sets kdkPrefix to the KDK prefix.
     * @param kdkIdentityName This sets kdkIdentityName to the KDK identity name.
     * @param kdkKeyId This sets kdkKeyId to the KDK key ID.
     * @return True for success or false if an error was reported to onError.
     */
    static bool
    extractKdkInfoFromCkName
      (const Name& ckDataName, const Name& ckName,
       const EncryptError::OnError& onError, Name& kdkPrefix,
       Name& kdkIdentityName, Name& kdkKeyId);

    PibKey* credentialsKey_;
    Validator* validator_;
    Face* face_;
    EncryptorV2* contentKeyCache_;
    // The external keychain with access credentials.
    KeyChain* keyChain_;
    // The internal in-memory keychain for temporarily storing KDKs.
    KeyChain internalKeyChain_;

    // TODO: add some expiration, so they are not stored forever.
    std::map<Name, ptr_lib::shared_ptr<ContentKey> > contentKeys_;
  };

  ptr_lib::shared_ptr<Impl> impl_;
};

}

#endif

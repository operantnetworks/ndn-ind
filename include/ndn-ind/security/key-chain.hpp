/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013-2020 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

#ifndef NDN_KEY_CHAIN_HPP
#define NDN_KEY_CHAIN_HPP

#include <map>
#include <stdexcept>
#include "../data.hpp"
#include "../interest.hpp"
#include "../face.hpp"
#include "pib/pib.hpp"
#include "pib/pib.hpp"
#include "tpm/tpm.hpp"
#include "signing-info.hpp"
#include "key-params.hpp"
#include "safe-bag.hpp"

namespace ndn {

class PolicyManager;
class ConfigFile;

/**
 * KeyChain is the main class of the security library.
 *
 * The KeyChain class provides a set of interfaces to the security library such as identity management, policy configuration
 * and packet signing and verification.
 * @note This class is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 */
class KeyChain {
public:
  /**
   * A KeyChain::Error extends runtime_error and represents an error in KeyChain
   * processing.
   */
  class Error : public std::runtime_error
  {
  public:
    Error(const std::string& what)
    : std::runtime_error(what)
    {
    }
  };

  /**
   * A KeyChain::InvalidSigningInfoError extends KeyChain::Error to indicate
   * that the supplied SigningInfo is invalid.
   */
  class InvalidSigningInfoError : public Error
  {
  public:
    InvalidSigningInfoError(const std::string& what)
    : Error(what)
    {
    }
  };

  /**
   * A KeyChain::LocatorMismatchError extends KeyChain::Error to indicate that
   * the supplied TPM locator does not match the locator stored in the PIB.
   */
  class LocatorMismatchError : public Error
  {
  public:
    LocatorMismatchError(const std::string& what)
    : Error(what)
    {
    }
  };

  typedef func_lib::function<ptr_lib::shared_ptr<PibImpl>
    (const std::string& location)> MakePibImpl;

  typedef func_lib::function<ptr_lib::shared_ptr<TpmBackEnd>
    (const std::string& location)> MakeTpmBackEnd;

  /**
   * Create a KeyChain to use the PIB and TPM defined by the given locators.
   * This creates a security v2 KeyChain that uses CertificateV2, Pib, Tpm and
   * Validator.
   * @param pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
   * @param tpmLocator The TPM locator, e.g., "tpm-memory:".
   * @param allowReset (optional) If true, the PIB will be reset when the
   * supplied tpmLocator mismatches the one in the PIB. If omitted, don't allow
   * reset.
   * @throws KeyChain::LocatorMismatchError if the supplied TPM locator does not
   * match the locator stored in the PIB.
   */
  KeyChain
    (const std::string& pibLocator, const std::string& tpmLocator,
     bool allowReset = false);

  /**
   * Create a security v2 KeyChain with explicitly-created PIB and TPM objects.
   * @param pibImpl An explicitly-created PIB object of a subclass of PibImpl.
   * @param tpmBackEnd An explicitly-created TPM object of a subclass of
   * TpmBackEnd.
   */
  KeyChain
    (const ptr_lib::shared_ptr<PibImpl>& pibImpl,
     const ptr_lib::shared_ptr<TpmBackEnd>& tpmBackEnd);

  /**
   * Create a KeyChain with the default PIB and TPM, which are
   * platform-dependent and can be overridden system-wide or individually by the
   * user. This creates a security v2 KeyChain that uses CertificateV2, Pib, Tpm
   * and Validator. However, if the default security v1 database file still
   * exists, and the default security v2 database file does not yet exists,then
   * assume that the system is running an older NFD and create a security v1
   * KeyChain with the default IdentityManager and a NoVerifyPolicyManager.
   */
  KeyChain();

  Pib&
  getPib() { return *pib_; }

  Tpm&
  getTpm() { return *tpm_; }

  // Identity management

  /**
   * Create a security V2 identity for identityName. This method will check if
   * the identity exists in PIB and whether the identity has a default key and
   * default certificate. If the identity does not exist, this method will
   * create the identity in PIB. If the identity's default key does not exist,
   * this method will create a key pair and set it as the identity's default
   * key. If the key's default certificate is missing, this method will create a
   * self-signed certificate for the key. If identityName did not exist and no
   * default identity was selected before, the created identity will be set as
   * the default identity.
   * @param identityName The name of the identity.
   * @param params (optional) The key parameters if a key needs to be generated
   * for the identity. If omitted, use getDefaultKeyParams().
   * @return The created PibIdentity instance.
   */
  ptr_lib::shared_ptr<PibIdentity>
  createIdentityV2
    (const Name& identityName, const KeyParams& params = getDefaultKeyParams());

  /**
   * Delete the identity. After this operation, the identity is invalid.
   * @param identity The identity to delete.
   */
  void
  deleteIdentity(PibIdentity& identity);

  /**
   * Set the identity as the default identity.
   * @param identity The identity to make the default.
   */
  void
  setDefaultIdentity(PibIdentity& identity);

  // Key management

  /**
   * Create a key for the identity according to params. If the identity had no
   * default key selected, the created key will be set as the default for this
   * identity. This method will also create a self-signed certificate for the
   * created key.
   * @param identity A valid PibIdentity object.
   * @param params (optional) The key parameters if a key needs to be generated
   * for the identity. If omitted, use getDefaultKeyParams().
   * @return The new PibKey.
   */
  ptr_lib::shared_ptr<PibKey>
  createKey
    (PibIdentity& identity, const KeyParams& params = getDefaultKeyParams());

  /**
   * Delete the given key of the given identity. The key becomes invalid.
   * @param identity A valid PibIdentity object.
   * @param key The key to delete.
   * @throws invalid_argument If the key does not belong to the identity.
   */
  void
  deleteKey(PibIdentity& identity, PibKey& key);

  /**
   * Set the key as the default key of identity.
   * @param identity A valid PibIdentity object.
   * @param key The key to become the default.
   * @throws invalid_argument If the key does not belong to the identity.
   */
  void
  setDefaultKey(PibIdentity& identity, PibKey& key);

  // Certificate management

  /**
   * Add a certificate for the key. If the key had no default certificate
   * selected, the added certificate will be set as the default certificate for
   * this key.
   * @param key A valid PibKey object.
   * @param certificate The certificate to add. This copies the object.
   * @note This method overwrites a certificate with the same name, without
   * considering the implicit digest.
   * @throws invalid_argument If the key does not match the certificate.
   */
  void
  addCertificate(PibKey& key, const CertificateV2& certificate);

  /**
   * Delete the certificate with the given name from the given key.
   * If the certificate does not exist, this does nothing.
   * @param key A valid PibKey object.
   * @param certificateName The name of the certificate to delete.
   * @throws invalid_argument If certificateName does not follow certificate
   * naming conventions.
   */
  void
  deleteCertificate(PibKey& key, const Name& certificateName);

  /**
   * Set the certificate as the default certificate of the key. The certificate
   * will be added to the key, potentially overriding an existing certificate if
   * it has the same name (without considering implicit digest).
   * @param key A valid PibKey object.
   * @param certificate The certificate to become the default. This copies the
   * object.
   */
  void
  setDefaultCertificate(PibKey& key, const CertificateV2& certificate);

  // Signing

  /**
   * Wire encode the Data object, sign it according to the supplied signing
   * parameters, and set its signature.
   * @param data The Data object to be signed. This replaces its Signature
   * object based on the type of key and other info in the SigningInfo params,
   * and updates the wireEncoding.
   * @param params The signing parameters.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   * @throws KeyChain::Error if signing fails.
   * @throws KeyChain::InvalidSigningInfoError if params is invalid, or if the
   * identity, key or certificate specified in params does not exist.
   */
  void
  sign(Data& data, const SigningInfo& params,
       WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  /**
   * Wire encode the Data object, sign it with the default key of the default
   * identity, and set its signature.
   * @param data The Data object to be signed. This replaces its Signature
   * object based on the type of key of the default identity, and updates the
   * wireEncoding.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   */
  void
  sign(Data& data, WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    sign(data, getDefaultSigningInfo(), wireFormat);
  }

  /**
   * Sign Interest according to the supplied signing parameters. Append a
   * SignatureInfo to the Interest name, sign the encoded name components and
   * append a final name component with the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param params The signing parameters.
   * @param wireFormat (optional) A WireFormat object used to encode the input
   * and encode the appended components. If omitted, use WireFormat
   * getDefaultWireFormat().
   * @throws KeyChain::Error if signing fails.
   * @throws KeyChain::InvalidSigningInfoError if params is invalid, or if the
   * identity, key or certificate specified in params does not exist.
   */
  void
  sign(Interest& interest, const SigningInfo& params,
       WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  /**
   * Sign the Interest with the default key of the default identity. Append a
   * SignatureInfo to the Interest name, sign the encoded name components and
   * append a final name component with the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param wireFormat (optional) A WireFormat object used to encode the input
   * and encode the appended components. If omitted, use WireFormat
   * getDefaultWireFormat().
   */
  void
  sign(Interest& interest,
       WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    sign(interest, getDefaultSigningInfo(), wireFormat);
  }

  /**
   * Sign the byte array according to the supplied signing parameters.
   * @param buffer The byte array to be signed.
   * @param bufferLength the length of buffer.
   * @param params (optional) The signing parameters. If params refers to an
   * identity, this selects the default key of the identity. If params refers to
   * a key or certificate, this selects the corresponding key. If params is
   * omitted, this selects the default key of the default identity.
   * @return The signature Blob, or an isNull Blob if params.getDigestAlgorithm()
   * is unrecognized.
   */
  Blob
  sign(const uint8_t* buffer, size_t bufferLength,
       const SigningInfo& params = getDefaultSigningInfo());

  /**
   * Generate a self-signed certificate for the public key and add it to the
   * PIB. This creates the certificate name from the key name by appending
   * "self" and a version based on the current time. If no default certificate
   * for the key has been set, then set the certificate as the default for the
   * key.
   * @param key The PibKey with the key name and public key.
   * @param wireFormat (optional) A WireFormat object used to encode the
   * certificate. If omitted, use WireFormat getDefaultWireFormat().
   * @return The new certificate.
   */
  ptr_lib::shared_ptr<CertificateV2>
  selfSign
    (ptr_lib::shared_ptr<PibKey>& key,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  // Import and export

  /**
   * Export a certificate and its corresponding private key in a SafeBag.
   * @param certificate The certificate to export. This gets the key from the
   * TPM using certificate.getKeyName().
   * @param password (optional) The password for encrypting the private key,
   * which should have characters in the range of 1 to 127. If the password is
   * supplied, use it to put a PKCS #8 EncryptedPrivateKeyInfo in the SafeBag.
   * If the password is null, put an unencrypted PKCS #8 PrivateKeyInfo in the
   * SafeBag.
   * @param passwordLength (optional) The length of the password. If password is
   * null, this is ignored.
   * @return A SafeBag carrying the certificate and private key.
   * @throws KeyChain::Error certificate.getKeyName() key does not exist, if the
   * password is null and the TPM does not support exporting an unencrypted
   * private key, or for other errors exporting the private key.
   */
  ptr_lib::shared_ptr<SafeBag>
  exportSafeBag
    (const CertificateV2& certificate, const uint8_t* password = 0,
     size_t passwordLength = 0);

  /**
   * Import a certificate and its corresponding private key encapsulated in a
   * SafeBag. If the certificate and key are imported properly, the default
   * setting will be updated as if a new key and certificate is added into this
   * KeyChain.
   * @param safeBag The SafeBag containing the certificate and private key. This
   * copies the values from the SafeBag.
   * @param password (optional) The password for decrypting the private key,
   * which should have characters in the range of 1 to 127. If the password is
   * supplied, use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the
   * password is omitted or null, import an unencrypted PKCS #8 PrivateKeyInfo.
   * @param passwordLength (optional) The length of the password. If password is
   * omitted or null, this is ignored.
   * @throws KeyChain::Error if the private key cannot be imported, or if a
   * public key or private key of the same name already exists, or if a
   * certificate of the same name already exists.
   */
  void
  importSafeBag
    (const SafeBag& safeBag, const uint8_t* password = 0,
     size_t passwordLength = 0);

  // PIB & TPM backend registry

  /**
   * Add to the PIB factories map where scheme is the key and makePibImpl is the
   * value. If your application has its own PIB implementations, this must be
   * called before creating a KeyChain instance which uses your PIB scheme.
   * @param scheme The PIB scheme.
   * @param makePibImpl A callback which takes the PIB location and returns a
   * new PibImpl instance.
   */
  static void
  registerPibBackend(const std::string& scheme, const MakePibImpl& makePibImpl)
  {
    getPibFactories()[scheme] = makePibImpl;
  }

  /**
   * Add to the TPM factories map where scheme is the key and makeTpmBackEnd is
   * the value. If your application has its own TPM implementations, this must
   * be called before creating a KeyChain instance which uses your TPM scheme.
   * @param scheme The TPM scheme.
   * @param makeTpmBackEnd A callback which takes the TPM location and returns a
   * new TpmBackEnd instance.
   */
  static void
  registerTpmBackend
    (const std::string& scheme, const MakeTpmBackEnd& makeTpmBackEnd)
  {
    getTpmFactories()[scheme] = makeTpmBackEnd;
  }

  /**
   * Delete the identity from the public and private key storage. If the
   * identity to be deleted is the current default system default, this will not
   * delete the identity and will return immediately.
   * @param identityName The name of the identity.
   */
  void
  deleteIdentity(const Name& identityName)
  {
    try {
      deleteIdentity(*pib_->getIdentity(identityName));
    } catch (const Pib::Error& ex) {
    }
  }

  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws Pib::Error if the default identity is not set.
   */
  Name
  getDefaultIdentity() { return pib_->getDefaultIdentity()->getName(); }

  /**
   * Get the default certificate name of the default identity.
   * @return The requested certificate name.
   * @throws Pib::Error if the default identity is not set or the default key 
   * name for the identity is not set or the default certificate name for the
   * key name is not set.
   */
  Name
  getDefaultCertificateName()
  {
    return pib_->getDefaultIdentity()->getDefaultKey()->getDefaultCertificate()
      ->getName();
  }

  /*****************************************
   *              Sign/Verify              *
   *****************************************/

  /**
   * Wire encode the Data object, sign it and set its signature.
   * @param data The Data object to be signed.  This updates its signature and key locator field and wireEncoding.
   * @param certificateName The certificate name of the key to use for signing.
   * @param wireFormat (optional) A WireFormat object used to encode the input. If omitted, use WireFormat getDefaultWireFormat().
   */
  void
  sign(Data& data, const Name& certificateName,
       WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    SigningInfo signingInfo;
    signingInfo.setSigningCertificateName(certificateName);
    sign(data, signingInfo, wireFormat);
  }

  /**
   * Append a SignatureInfo to the Interest name, sign the name components and
   * append a final name component with the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param certificateName The certificate name of the key to use for signing.
   * @param wireFormat (optional) A WireFormat object used to encode the input. If omitted,
   * use WireFormat getDefaultWireFormat().
   */
  void
  sign
    (Interest& interest, const Name& certificateName,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    SigningInfo signingInfo;
    signingInfo.setSigningCertificateName(certificateName);
    sign(interest, signingInfo, wireFormat);
  }

  /**
   * Wire encode the Data object, digest it and set its SignatureInfo to
   * a DigestSha256.
   * @param data The Data object to be signed. This updates its signature and
   * wireEncoding.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   */
  void
  signWithSha256
    (Data& data, WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    SigningInfo signingInfo;
    signingInfo.setSha256Signing();
    sign(data, signingInfo, wireFormat);
  }

  /**
   * Append a SignatureInfo for DigestSha256 to the Interest name, digest the
   * name components and append a final name component with the signature bits
   * (which is the digest).
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   */
  void
  signWithSha256
    (Interest& interest, WireFormat& wireFormat = *WireFormat::getDefaultWireFormat())
  {
    SigningInfo signingInfo;
    signingInfo.setSha256Signing();
    sign(interest, signingInfo, wireFormat);
  }

  /**
   * Set the Face which will be used to fetch required certificates.
   * @param face A pointer to the Face object.
   */
  void
  setFace(Face* face) { face_ = face; }

  /**
   * Wire encode the Data object, compute an HmacWithSha256 and update the
   * signature value.
   * @param data The Data object to be signed. It should already have an
   * HmacWithSha256Signature with a KeyLocator for the key name. This updates
   * its signature and wireEncoding.
   * @param key The key for the HmacWithSha256.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   * @note This method is an experimental feature. The API may change.
   */
  static void
  signWithHmacWithSha256
    (Data& data, const Blob& key,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  /**
   * Append a SignatureInfo to the Interest name, compute an HmacWithSha256
   * signature for the name components and append a final name component with
   * the signature bits.
   * @param interest The Interest object to be signed. This appends name
   * components of SignatureInfo and the signature bits.
   * @param key The key for the HmacWithSha256.
   * @param keyName The name of the key for the KeyLocator in the SignatureInfo.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   * @note This method is an experimental feature. The API may change.
   */
  static void
  signWithHmacWithSha256
    (Interest& interest, const Blob& key, const Name& keyName,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  /**
   * Compute a new HmacWithSha256 for the data packet and verify it against
   * the signature value.
   * @param data The Data object to verify.
   * @param key The key for the HmacWithSha256.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   * @return True if the signature verifies, otherwise false.
   * @note This method is an experimental feature. The API may change.
   */
  static bool
  verifyDataWithHmacWithSha256
    (const Data& data, const Blob& key,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  /**
   * Compute a new HmacWithSha256 for all but the final name component and
   * verify it against the signature value in the final name component.
   * @param interest The Interest object to verify.
   * @param key The key for the HmacWithSha256.
   * @param wireFormat (optional) A WireFormat object used to encode the input.
   * If omitted, use WireFormat getDefaultWireFormat().
   * @return True if the signature verifies, otherwise false.
   * @note This method is an experimental feature. The API may change.
   */
  static bool
  verifyInterestWithHmacWithSha256
    (const Interest& interest, const Blob& key,
     WireFormat& wireFormat = *WireFormat::getDefaultWireFormat());

  static const KeyParams&
  getDefaultKeyParams();

  /**
   * @deprecated Use getDefaultKeyParams().
   */
  static const RsaKeyParams DEPRECATED_IN_NDN_IND DEFAULT_KEY_PARAMS;

private:
  friend class CommandInterestSigner;

  /**
   * Do the work of the constructor to create a KeyChain from the given locators.
   * @param pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
   * @param tpmLocator The TPM locator, e.g., "tpm-memory:".
   * @param allowReset If true, the PIB will be reset when the supplied
   * tpmLocator mismatches the one in the PIB.
   * @throws KeyChain::LocatorMismatchError if the supplied TPM locator does not
   * match the locator stored in the PIB.
   */
  void
  construct
    (std::string pibLocator, std::string tpmLocator, bool allowReset);

  /**
   * Get the PIB factories map. On the first call, this initializes the map with
   * factories for standard PibImpl implementations.
   * @return A map where the key is the scheme string and the value is the
   * MakePibImpl callback.
   */
  static std::map<std::string, MakePibImpl>&
  getPibFactories();

  /**
   * Get the TPM factories map. On the first call, this initializes the map with
   * factories for standard TpmBackEnd implementations.
   * @return A map where the key is the scheme string and the value is the
   * MakeTpmBackEnd callback.
   */
  static std::map<std::string, MakeTpmBackEnd>&
  getTpmFactories();

  /**
   * Parse the uri and set the scheme and location.
   */
  static void
  parseLocatorUri
    (const std::string& uri, std::string& scheme, std::string& location);

  /**
   * Parse the pibLocator and set the pibScheme and pibLocation.
   */
  static void
  parseAndCheckPibLocator
    (const std::string& pibLocator, std::string& pibScheme,
     std::string& pibLocation);

  /**
   * Parse the tpmLocator and set the tpmScheme and tpmLocation.
   */
  static void
  parseAndCheckTpmLocator
    (const std::string& tpmLocator, std::string& tpmScheme,
     std::string& tpmLocation);

  static std::string
  getDefaultPibScheme();

  static std::string
  getDefaultTpmScheme();

  /**
   * Create a Pib according to the pibLocator
   * @param pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
   * @return A new Pib object.
   */
  static ptr_lib::shared_ptr<Pib>
  createPib(const std::string& pibLocator);

  /**
   * Create a Tpm according to the tpmLocator
   * @param tpmLocator The TPM locator, e.g., "tpm-memory:".
   * @return A new Tpm object.
   */
  static ptr_lib::shared_ptr<Tpm>
  createTpm(const std::string& tpmLocator);

  static std::string
  getDefaultPibLocator(ConfigFile& config);

  static std::string
  getDefaultTpmLocator(ConfigFile& config);

  /**
   * Prepare a Signature object according to signingInfo and get the signing key
   * name.
   * @param params The signing parameters.
   * @param keyName Set keyName to the signing key name.
   * @return A new Signature object with the SignatureInfo.
   * @throws InvalidSigningInfoError when the requested signing method cannot be
   * satisfied.
   */
  ptr_lib::shared_ptr<Signature>
  prepareSignatureInfo(const SigningInfo& params, Name& keyName);

  /**
   * Sign the byte array using the key with name keyName.
   * @param buffer The byte array to be signed.
   * @param bufferLength the length of buffer.
   * @param keyName The name of the key.
   * @param digestAlgorithm The digest algorithm.
   * @return The signature Blob, or an isNull Blob if the key does not exist, or
   * for an unrecognized digestAlgorithm.
   */
  Blob
  sign(const uint8_t* buffer, size_t bufferLength, const Name& keyName,
       DigestAlgorithm digestAlgorithm) const;

  static const SigningInfo&
  getDefaultSigningInfo();

  Face* face_; // for security v1

  ptr_lib::shared_ptr<Pib> pib_;
  ptr_lib::shared_ptr<Tpm> tpm_;

  static std::string* defaultPibLocator_;
  static std::string* defaultTpmLocator_;
  static std::map<std::string, MakePibImpl>* pibFactories_;
  static std::map<std::string, MakeTpmBackEnd>* tpmFactories_;
  static SigningInfo* defaultSigningInfo_;
  static KeyParams* defaultKeyParams_;
};

}

#endif

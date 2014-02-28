/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "../../c/util/crypto.h"
#include <ndn-cpp/sha256-with-rsa-signature.hpp>
#include <ndn-cpp/security/security-exception.hpp>
#include <ndn-cpp/security/identity/identity-storage.hpp>
#include <ndn-cpp/security/policy/self-verify-policy-manager.hpp>

using namespace std;

namespace ndn {

/**
 * Verify the signature on the data packet using the given public key.  If there is no data.getDefaultWireEncoding(),
 * this calls data.wireEncode() to set it.
 * TODO: Move this general verification code to a more central location.
 * @param data The data packet with the signed portion and the signature to verify.  The data packet must have a
 * Sha256WithRsaSignature.
 * @param publicKeyDer The DER-encoded public key used to verify the signature.
 * @return true if the signature verifies, false if not.
 * @throw SecurityException if data does not have a Sha256WithRsaSignature.
 */
static bool
verifySha256WithRsaSignature(const Data& data, const Blob& publicKeyDer)
{
  const Sha256WithRsaSignature *signature = dynamic_cast<const Sha256WithRsaSignature*>(data.getSignature());
  if (!signature)
    throw SecurityException("signature is not Sha256WithRsaSignature.");
  
  // Set the data packet's default wire encoding if it is not already there.
  if (!data.getDefaultWireEncoding())
    data.wireEncode();
  
  // Set signedPortionDigest to the digest of the signed portion of the wire encoding.
  uint8_t signedPortionDigest[SHA256_DIGEST_LENGTH];
  ndn_digestSha256(data.getDefaultWireEncoding().signedBuf(), data.getDefaultWireEncoding().signedSize(), signedPortionDigest);
  
  // Verify the signedPortionDigest.
  // Use a temporary pointer since d2i updates it.
  const uint8_t *derPointer = publicKeyDer.buf();
  RSA *rsaPublicKey = d2i_RSA_PUBKEY(NULL, &derPointer, publicKeyDer.size());
  if (!rsaPublicKey)
    throw UnrecognizedKeyFormatException("Error decoding public key in d2i_RSAPublicKey");
  int success = RSA_verify
    (NID_sha256, signedPortionDigest, sizeof(signedPortionDigest), (uint8_t *)signature->getSignature().buf(),
     signature->getSignature().size(), rsaPublicKey);
  // Free the public key before checking for success.
  RSA_free(rsaPublicKey);
  
  // RSA_verify returns 1 for a valid signature.
  return (success == 1);
}

SelfVerifyPolicyManager::~SelfVerifyPolicyManager()
{
}

bool 
SelfVerifyPolicyManager::skipVerifyAndTrust(const Data& data)
{ 
  return false; 
}

bool
SelfVerifyPolicyManager::requireVerify(const Data& data)
{ 
  return true; 
}
    
ptr_lib::shared_ptr<ValidationRequest>
SelfVerifyPolicyManager::checkVerificationPolicy
  (const ptr_lib::shared_ptr<Data>& data, int stepCount, const OnVerified& onVerified, const OnVerifyFailed& onVerifyFailed)
{ 
  const Sha256WithRsaSignature *signature = dynamic_cast<Sha256WithRsaSignature *>(data->getSignature());
  if (!signature)
    throw SecurityException("SelfVerifyPolicyManager: Signature is not Sha256WithRsaSignature.");
  
  if (signature->getKeyLocator().getType() == ndn_KeyLocatorType_KEY) {
    // Use the public key DER directly.
    if (verifySha256WithRsaSignature(*data, signature->getKeyLocator().getKeyData()))
      onVerified(data);
    else
      onVerifyFailed(data); 
  }
  else if (signature->getKeyLocator().getType() == ndn_KeyLocatorType_KEYNAME && identityStorage_) {
    // Assume the key name is a certificate name.
    Blob publicKeyDer = identityStorage_->getKey
      (IdentityCertificate::certificateNameToPublicKeyName(signature->getKeyLocator().getKeyName()));
    if (!publicKeyDer)
      // Can't find the public key with the name.
      onVerifyFailed(data);
    
    if (verifySha256WithRsaSignature(*data, publicKeyDer))
      onVerified(data);
    else
      onVerifyFailed(data); 
  }
  else
    // Can't find a key to verify.
    onVerifyFailed(data); 
  
  // No more steps, so return a null ValidationRequest.
  return ptr_lib::shared_ptr<ValidationRequest>();
}

bool 
SelfVerifyPolicyManager::checkSigningPolicy(const Name& dataName, const Name& certificateName)
{ 
  return true; 
}

Name 
SelfVerifyPolicyManager::inferSigningIdentity(const Name& dataName)
{ 
  return Name(); 
}

}

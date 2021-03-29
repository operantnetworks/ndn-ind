/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/v2/certificate-v2.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono. Decode X.509.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate.cpp
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

#include <ndn-ind/security/validity-period.hpp>
#include <ndn-ind/sha256-with-ecdsa-signature.hpp>
#include <ndn-ind/sha256-with-rsa-signature.hpp>
#include <ndn-ind/digest-sha256-signature.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include "../../encoding/der/der-node-type.hpp"
#include <ndn-ind/encoding/base64.hpp>
#include <ndn-ind/security/v2/certificate-v2.hpp>
#include <ndn-ind/key-locator.hpp>

using namespace std;
using namespace std::chrono;

namespace ndn {

CertificateV2::CertificateV2()
{
  getMetaInfo().setType(ndn_ContentType_KEY);
}

CertificateV2::CertificateV2(const Data& data)
// Use the copy constructor.  It clones the signature object.
: Data(data)
{
  const CertificateV2 *certificate = dynamic_cast<const CertificateV2*>(&data);
  if (certificate)
    x509Info_ = certificate->x509Info_;
  checkFormat();
}

void
CertificateV2::checkFormat()
{
  if (!isValidName(getName()))
    throw Error
      ("The Data Name does not follow the certificate naming convention");

  if (getMetaInfo().getType() != ndn_ContentType_KEY)
    throw Error("The Data ContentType is not KEY");

  if (getMetaInfo().getFreshnessPeriod().count() < 0)
    throw Error("The Data FreshnessPeriod is not set");

  if (getContent().size() == 0)
    throw Error("The Data Content is empty");
}

const Blob&
CertificateV2::getPublicKey() const
{
  if (x509Info_)
    return x509Info_->getPublicKey();

  if (getContent().size() == 0)
    throw Error("The public key is not set (the Data content is empty)");

  return getContent();
}

ValidityPeriod&
CertificateV2::getValidityPeriod()
{
  if (x509Info_)
    return const_cast<ValidityPeriod&>(x509Info_->getValidityPeriod());

  if (!ValidityPeriod::canGetFromSignature(getSignature()))
    throw invalid_argument("The SignatureInfo does not have a ValidityPeriod");

  return ValidityPeriod::getFromSignature(getSignature());
}

void
CertificateV2::printCertificate(ostream& output) const
{
  output << "Certificate name:\n";
  output << "  " << getName() << "\n";
  output << "Validity:\n";
  output << "  NotBefore: " << toIsoString
    (getValidityPeriod().getNotBefore()) << "\n";
  output << "  NotAfter: "  << toIsoString
    (getValidityPeriod().getNotAfter()) << "\n";

  /* TODO: Print the extension.
  try {
    const Block& info = cert.getSignature().getSignatureInfo()
      .getTypeSpecificTlv(tlv::AdditionalDescription);
    output << "Additional Description:\n";
    for (const auto& item : v2::AdditionalDescription(info)) {
      output << "  " << item.first << ": " << item.second << "\n";
    }
  }
  catch (const SignatureInfo::Error&) {
    // ignore
  }
  */

  output << "Public key bits:\n";
  output << toBase64(*getPublicKey(), true);

  output << "Signature Information:\n";
  output << "  Signature Type: ";
  if (dynamic_cast<const Sha256WithEcdsaSignature*>(getSignature()))
    output << "SignatureSha256WithEcdsa\n";
  else if (dynamic_cast<const Sha256WithRsaSignature*>(getSignature()))
    output << "SignatureSha256WithRsa\n";
  else
    output << "<unknown>\n";

  if (KeyLocator::canGetFromSignature(getSignature())) {
    output << "  Key Locator: ";
    const KeyLocator& keyLocator(KeyLocator::getFromSignature(getSignature()));
    if (keyLocator.getType() == ndn_KeyLocatorType_KEYNAME) {
      if (keyLocator.getKeyName().equals(getKeyName()))
        output << "Self-Signed ";

      output << "Name=" << keyLocator.getKeyName() << "\n";
    }
    else
      output << "<no KeyLocator key name>\n";
  }
}

void
CertificateV2::wireDecode(const Blob& inputIn, WireFormat& wireFormat)
{
  Blob input(inputIn);
  if (input.size() >= 1 && input.buf()[0] == DerNodeType_Sequence) {
    // Replace the input with a Data packet that encapsulates the X.509 certificate.
    X509CertificateInfo x509Info(input);
    Data data(x509Info.getSubjectName());
    data.setContent(input);
    data.getMetaInfo().setType(ndn_ContentType_KEY);
    data.getMetaInfo().setFreshnessPeriod(hours(1));

    // Set a DigestSha256 signature.
    data.setSignature(DigestSha256Signature());
    // Encode once to get the signed portion.
    SignedBlob encoding = data.wireEncode(wireFormat);
    // Compute the SHA-256 here so that we don't depend on KeyChain.
    uint8_t digest[ndn_SHA256_DIGEST_SIZE];
    CryptoLite::digestSha256(encoding.signedBuf(), encoding.signedSize(), digest);
    data.getSignature()->setSignature(Blob(digest, sizeof(digest)));

    input = data.wireEncode(wireFormat);
    // Proceed below to re-decode from the encapsulated content.
  }

  Data::wireDecode(input, wireFormat);
  checkFormat();

  if (dynamic_cast<DigestSha256Signature*>(getSignature())) {
    // The signature is DigestSha256. Try to decode the content as an X.509 certificate.
    try {
      x509Info_ = ptr_lib::make_shared<X509CertificateInfo>(getContent());
    } catch (const std::exception& ex) {
      // The content doesn't seem to be an X.509 certificate. Ignore.
    }
  }
}

bool
CertificateV2::isValidName(const Name& certificateName)
{
  if (X509CertificateInfo::isEncapsulatedX509(certificateName))
    // This is an X.509 name from an encapsulated certificate, so don't check it.
    return true;

  // /<NameSpace>/KEY/[KeyId]/[IssuerId]/[Version]
  return (certificateName.size() >= MIN_CERT_NAME_LENGTH &&
          certificateName.get(KEY_COMPONENT_OFFSET) == getKEY_COMPONENT());
}

Name
CertificateV2::extractIdentityFromCertName(const Name& certificateName)
{
  if (!isValidName(certificateName)) {
    throw invalid_argument
      ("Certificate name `" + certificateName.toUri() +
        "` does not follow the naming conventions");
  }

  return certificateName.getPrefix(KEY_COMPONENT_OFFSET);
}

Name
CertificateV2::extractKeyNameFromCertName(const Name& certificateName)
{
  if (!isValidName(certificateName)) {
    throw invalid_argument
      ("Certificate name `" + certificateName.toUri() +
        "` does not follow the naming conventions");
  }

  // Trim everything after the key ID.
  return certificateName.getPrefix(KEY_ID_OFFSET + 1);
}

const Name::Component&
CertificateV2::getKEY_COMPONENT()
{
  if (!KEY_COMPONENT)
    KEY_COMPONENT = new Name::Component("KEY");

  return *KEY_COMPONENT;
}

Name::Component* CertificateV2::KEY_COMPONENT = 0;

}

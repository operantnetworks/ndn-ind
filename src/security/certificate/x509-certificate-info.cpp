/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
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
#include "../../encoding/der/der-node.hpp"
#include <ndn-ind/security/certificate/x509-certificate-info.hpp>

using namespace std;

namespace ndn {

typedef DerNode::DerSequence DerSequence;

static const char *RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
static const char *PSEUDONYM_OID = "2.5.4.65";

X509CertificateInfo::X509CertificateInfo(const Blob& encoding)
{
  // See https://tools.ietf.org/html/rfc5280 .
  // Certificate  ::=  SEQUENCE  {
  //      tbsCertificate       TBSCertificate,
  //      signatureAlgorithm   AlgorithmIdentifier,
  //      signatureValue       BIT STRING  }
  DerSequence* tbsCertificate;
  DerSequence* signatureAlgorithm;
  try {
    root_ = DerNode::parse(encoding);
    const vector<ptr_lib::shared_ptr<DerNode> >& rootChildren =
      root_->getChildren();
    if (rootChildren.size() < 3)
      throw runtime_error("X509CertificateInfo: Expected 3 certificate fields");
    tbsCertificate = &DerNode::getSequence(rootChildren, 0);
    signatureAlgorithm = &DerNode::getSequence(rootChildren, 1);
    DerNode::DerBitString* signatureValueNode = dynamic_cast<DerNode::DerBitString*>
      (rootChildren[2].get());

    // Expect the first byte of the BIT STRING to be zero.
    if (!signatureValueNode || signatureValueNode->getPayload().size() < 1 ||
        signatureValueNode->getPayload().buf()[0] != 0)
      throw runtime_error("X509CertificateInfo: Cannot decode signatureValue");
    signatureValue_ = Blob
      (signatureValueNode->getPayload().buf() + 1,
       signatureValueNode->getPayload().size() - 1);

    // Get the signed portion.
    size_t beginOffset = root_->getHeaderSize();
    size_t endOffset = beginOffset + tbsCertificate->getSize();
    signedEncoding_ = SignedBlob(encoding, beginOffset, endOffset);
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CertificateInfo: Cannot decode certificate: ") +
      ex.what());
  }

  //TBSCertificate  ::=  SEQUENCE  {
  //      version         [0]  EXPLICIT Version DEFAULT v1,
  //      serialNumber         CertificateSerialNumber,
  //      signature            AlgorithmIdentifier,
  //      issuer               Name,
  //      validity             Validity,
  //      subject              Name,
  //      subjectPublicKeyInfo SubjectPublicKeyInfo,
  //      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  //                           -- If present, version MUST be v2 or v3
  //      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  //                           -- If present, version MUST be v2 or v3
  //      extensions      [3]  EXPLICIT Extensions OPTIONAL
  //                           -- If present, version MUST be v3
  //      }
  try {
    const vector<ptr_lib::shared_ptr<DerNode> >& tbsChildren =
      tbsCertificate->getChildren();

    int versionOffset = 0;
    if (tbsChildren.size() >= 1 &&
        dynamic_cast<DerNode::DerExplicit*>(tbsChildren[0].get()))
      // There is a version.
      versionOffset = 1;
    if (tbsChildren.size() < 6 + versionOffset)
      throw runtime_error("X509CertificateInfo: Expected 6 TBSCertificate fields");

    issuerName_ = makeName(*tbsChildren[2 + versionOffset]);

    // validity
    const vector<ptr_lib::shared_ptr<DerNode> >& validityChildren =
      DerNode::getSequence(tbsChildren, 3 + versionOffset).getChildren();
    DerNode::DerUtcTime* notBefore = dynamic_cast<DerNode::DerUtcTime*>
      (validityChildren[0].get());
    DerNode::DerUtcTime* notAfter = dynamic_cast<DerNode::DerUtcTime*>
      (validityChildren[1].get());
    if (!notBefore || !notAfter)
      throw runtime_error("X509CertificateInfo: Cannot decode Validity");
    validityPeriod_ = ValidityPeriod(notBefore->toTimePoint(), notAfter->toTimePoint());

    subjectName_ = makeName(*tbsChildren[4 + versionOffset]);

    publicKey_ = tbsChildren[5 + versionOffset]->encode();
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CertificateInfo: Cannot decode the TBSCertificate: ") +
      ex.what());
  }
}

X509CertificateInfo::X509CertificateInfo
  (const Name& issuerName, const ValidityPeriod& validityPeriod,
   const Name& subjectName, const Blob& publicKey, const Blob& signatureValue)
: issuerName_(issuerName), validityPeriod_(validityPeriod),
  subjectName_(subjectName), publicKey_(publicKey), signatureValue_(signatureValue)
{
  ptr_lib::shared_ptr<DerSequence> algorithmIdentifier(new DerSequence());
  algorithmIdentifier->addChild(ptr_lib::make_shared<DerNode::DerOid>(RSA_ENCRYPTION_OID));
  algorithmIdentifier->addChild(ptr_lib::make_shared<DerNode::DerNull>());

  ptr_lib::shared_ptr<DerSequence> tbsCertificate(new DerSequence());
  //TBSCertificate  ::=  SEQUENCE  {
  //      serialNumber         CertificateSerialNumber,
  //      signature            AlgorithmIdentifier,
  //      issuer               Name,
  //      validity             Validity,
  //      subject              Name,
  //      subjectPublicKeyInfo SubjectPublicKeyInfo
  //      }
  tbsCertificate->addChild(ptr_lib::make_shared<DerNode::DerInteger>(0));
  tbsCertificate->addChild(algorithmIdentifier);
  tbsCertificate->addChild(makeX509Name(issuerName));

  ptr_lib::shared_ptr<DerSequence> validity(new DerSequence());
  validity->addChild(ptr_lib::make_shared<DerNode::DerUtcTime>
    (validityPeriod.getNotBefore()));
  validity->addChild(ptr_lib::make_shared<DerNode::DerUtcTime>
    (validityPeriod.getNotAfter()));
  tbsCertificate->addChild(validity);

  tbsCertificate->addChild(makeX509Name(subjectName));

  try {
    tbsCertificate->addChild(DerNode::parse(publicKey));
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CertificateInfo: publicKey encoding is invalid DER: ") +
      ex.what());
  }

  // Certificate  ::=  SEQUENCE  {
  //      tbsCertificate       TBSCertificate,
  //      signatureAlgorithm   AlgorithmIdentifier,
  //      signatureValue       BIT STRING  }
  root_ = ptr_lib::make_shared<DerSequence>();
  ((DerSequence*)root_.get())->addChild(tbsCertificate);
  ((DerSequence*)root_.get())->addChild(algorithmIdentifier);
  ((DerSequence*)root_.get())->addChild
    (ptr_lib::make_shared<DerNode::DerBitString>(signatureValue.buf(), signatureValue.size(), 0));

  // Get the signed portion.
  size_t beginOffset = root_->getHeaderSize();
  size_t endOffset = beginOffset + tbsCertificate->getSize();
  signedEncoding_ = SignedBlob(root_->encode(), beginOffset, endOffset);
}

Name
X509CertificateInfo::makeName(DerNode& x509Name)
{
  // Check if there is a UTF8 string with the OID for "pseudonym".
  const vector<ptr_lib::shared_ptr<DerNode> >& components = x509Name.getChildren();
  for (int i = 0; i < components.size(); ++i) {
    DerNode::DerSet* component = dynamic_cast<DerNode::DerSet*>(components[i].get());
    if (!component)
      // Not a valid X.509 name. Don't worry about it and continue below to use the encoding.
      break;
    const vector<ptr_lib::shared_ptr<DerNode> >& componentChildren =
      component->getChildren();
    if (componentChildren.size() != 1)
      break;
    DerSequence* typeAndValue = dynamic_cast<DerSequence*>(componentChildren[0].get());
    if (!typeAndValue)
      break;
    const vector<ptr_lib::shared_ptr<DerNode> >& typeAndValueChildren =
      typeAndValue->getChildren();
    if (typeAndValueChildren.size() != 2)
      break;

    DerNode::DerOid* oid = dynamic_cast<DerNode::DerOid*>(typeAndValueChildren[0].get());
    DerNode::DerUtf8String* value = dynamic_cast<DerNode::DerUtf8String*>
      (typeAndValueChildren[1].get());

    if (oid && value && oid->toVal().toRawStr() == PSEUDONYM_OID)
      return Name(value->toVal().toRawStr());
  }
  
  return Name().append(getX509_COMPONENT()).append(x509Name.encode());
}

ptr_lib::shared_ptr<DerNode>
X509CertificateInfo::makeX509Name(const Name& name)
{
  if (isEncapsulatedX509(name))
    // Just decode the second component.
    return DerNode::parse(name.get(1).getValue());

  // Make an X.509 name with an "pseudonym.
  ptr_lib::shared_ptr<DerSequence> root(new DerSequence());
  ptr_lib::shared_ptr<DerSequence> typeAndValue(new DerSequence());
  typeAndValue->addChild(ptr_lib::make_shared<DerNode::DerOid>(OID(PSEUDONYM_OID)));
  string uri = name.toUri();
  typeAndValue->addChild(ptr_lib::make_shared<DerNode::DerUtf8String>
    ((const uint8_t*)uri.c_str(), uri.size()));
  ptr_lib::shared_ptr<DerNode::DerSet> component(new DerNode::DerSet());
  component->addChild(typeAndValue);

  root->addChild(component);
  return root;
}

const Name::Component&
X509CertificateInfo::getX509_COMPONENT()
{
  if (!X509_COMPONENT)
    X509_COMPONENT = new Name::Component("x509");

  return *X509_COMPONENT;
}

Name::Component* X509CertificateInfo::X509_COMPONENT = 0;

}

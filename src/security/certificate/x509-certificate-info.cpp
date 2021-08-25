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
static const char *SUBJECT_ALTERNATIVE_NAME_OID = "2.5.29.17";
static const char *CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31";
static const int GENERAL_NAME_URI_TYPE = 0x86;

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

    serialNumber_ = tbsChildren[0 + versionOffset]->getPayload();
    issuerName_ = makeName(tbsChildren[2 + versionOffset].get(), 0);

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

    // Get the extensions.
    DerNode* extensions = 0;
    DerNode::DerExplicit* extensionsExplicit = dynamic_cast<DerNode::DerExplicit*>
      (tbsChildren[tbsChildren.size() - 1].get());
    if (extensionsExplicit && extensionsExplicit->getTag() == 3 &&
        extensionsExplicit->getChildren().size() == 1)
      extensions = extensionsExplicit->getChildren()[0].get();

    subjectName_ = makeName(tbsChildren[4 + versionOffset].get(), extensions);

    publicKey_ = tbsChildren[5 + versionOffset]->encode();

    crlDistributionUri_ = findCrlDistributionUri(extensions);
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CertificateInfo: Cannot decode the TBSCertificate: ") +
      ex.what());
  }
}

X509CertificateInfo::X509CertificateInfo
  (const Name& issuerName, const ValidityPeriod& validityPeriod,
   const Name& subjectName, const Blob& publicKey, const Blob& signatureValue,
   const Blob& serialNumber)
: issuerName_(issuerName), validityPeriod_(validityPeriod),
  subjectName_(subjectName), publicKey_(publicKey), signatureValue_(signatureValue),
  serialNumber_(serialNumber)
{
  // We are using certificate extensions, so we must set the version.
  ptr_lib::shared_ptr<DerNode::DerExplicit> version(new DerNode::DerExplicit(0));
  version->addChild(ptr_lib::make_shared<DerNode::DerInteger>(2));

  ptr_lib::shared_ptr<DerSequence> algorithmIdentifier(new DerSequence());
  algorithmIdentifier->addChild(ptr_lib::make_shared<DerNode::DerOid>(RSA_ENCRYPTION_OID));
  algorithmIdentifier->addChild(ptr_lib::make_shared<DerNode::DerNull>());

  ptr_lib::shared_ptr<DerSequence> tbsCertificate(new DerSequence());
  //TBSCertificate  ::=  SEQUENCE  {
  //      version         [0]  EXPLICIT Version DEFAULT v1,
  //      serialNumber         CertificateSerialNumber,
  //      signature            AlgorithmIdentifier,
  //      issuer               Name,
  //      validity             Validity,
  //      subject              Name,
  //      subjectPublicKeyInfo SubjectPublicKeyInfo
  //      }
  tbsCertificate->addChild(version);

  if (serialNumber.size() > 0 && serialNumber.buf()[0] >= 0x80)
    throw runtime_error
      ("X509CertificateInfo: Negative serial numbers are not currently supported");
  tbsCertificate->addChild(ptr_lib::make_shared<DerNode::DerInteger>
    (serialNumber.buf(), serialNumber.size()));

  tbsCertificate->addChild(algorithmIdentifier);
  tbsCertificate->addChild(makeX509Name(issuerName, 0));

  ptr_lib::shared_ptr<DerSequence> validity(new DerSequence());
  validity->addChild(ptr_lib::make_shared<DerNode::DerUtcTime>
    (validityPeriod.getNotBefore()));
  validity->addChild(ptr_lib::make_shared<DerNode::DerUtcTime>
    (validityPeriod.getNotAfter()));
  tbsCertificate->addChild(validity);

  ptr_lib::shared_ptr<DerSequence> extensions(new DerSequence());
  tbsCertificate->addChild(makeX509Name(subjectName, extensions.get()));

  try {
    tbsCertificate->addChild(DerNode::parse(publicKey));
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CertificateInfo: publicKey encoding is invalid DER: ") +
      ex.what());
  }

  if (extensions->getChildren().size() > 0) {
    // makeX509Name added to extensions, so include it.
    ptr_lib::shared_ptr<DerNode::DerExplicit> extensionsExplicit
      (new DerNode::DerExplicit(3));
    extensionsExplicit->addChild(extensions);
    tbsCertificate->addChild(extensionsExplicit);
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
X509CertificateInfo::makeName(DerNode* x509Name, DerNode* extensions)
{
  if (extensions) {
    // Try to get the URI field in the Subject Alternative Names.

    //Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
    //
    // Extension  ::=  SEQUENCE  {
    //    extnID      OBJECT IDENTIFIER,
    //    critical    BOOLEAN DEFAULT FALSE,
    //    extnValue   OCTET STRING
    //                -- contains the DER encoding of an ASN.1 value
    //                -- corresponding to the extension type identified
    //                -- by extnID
    //    }
    //
    // subjectAltName EXTENSION ::= {
    //   SYNTAX GeneralNames
    //   IDENTIFIED BY id-ce-subjectAltName
    // }
    //
    // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    //
    // GeneralName ::= CHOICE {
    //   otherName  [0] INSTANCE OF OTHER-NAME,
    //   rfc822Name  [1] IA5String,
    //   dNSName    [2] IA5String,
    //   x400Address  [3] ORAddress,
    //   directoryName  [4] Name,
    //   ediPartyName  [5] EDIPartyName,
    //   uniformResourceIdentifier [6] IA5String,
    //   IPAddress  [7] OCTET STRING,
    //   registeredID  [8] OBJECT IDENTIFIER
    const vector<ptr_lib::shared_ptr<DerNode> >& extensionsChildren =
      extensions->getChildren();

    for (int i = 0; i < extensionsChildren.size(); ++i) {
      DerSequence* extension = dynamic_cast<DerSequence*>(extensionsChildren[i].get());
      if (!extension)
        // We don't expect this.
        continue;
      const vector<ptr_lib::shared_ptr<DerNode> >& extensionChildren =
        extension->getChildren();

      if (extensionChildren.size() < 2 || extensionChildren.size() > 3)
        // We don't expect this.
        continue;
      DerNode::DerOid* oid = dynamic_cast<DerNode::DerOid*>(extensionChildren[0].get());
      // Ignore "critical".
      DerNode::DerOctetString* extensionValue = dynamic_cast<DerNode::DerOctetString*>
        (extensionChildren[extensionChildren.size() - 1].get());
      if (!oid || !extensionValue)
        // We don't expect this.
        continue;
      if (oid->toVal().toRawStr() != SUBJECT_ALTERNATIVE_NAME_OID)
        // Try the next extension.
        continue;

      try {
        ptr_lib::shared_ptr<DerNode> generalNames = DerNode::parse(extensionValue->toVal());
        const vector<ptr_lib::shared_ptr<DerNode> >& generalNamesChildren =
          generalNames->getChildren();
        for (int i = 0; i < generalNamesChildren.size(); ++i) {
          DerNode::DerImplicitByteString* value =
            dynamic_cast<DerNode::DerImplicitByteString*>(generalNamesChildren[i].get());
          if (!value)
            // We don't expect this.
            continue;

          if (value->getType() == GENERAL_NAME_URI_TYPE)
            // Return an NDN name made from the URI.
            return Name(value->toVal().toRawStr());
        }
      } catch (const std::exception& ex) {
        // We don't expect this.
        continue;
      }
    }
  }

  // Default behavior: Encapsulate the X.509 name.
  return Name().append(getX509_COMPONENT()).append(x509Name->encode());
}

ptr_lib::shared_ptr<DerNode>
X509CertificateInfo::makeX509Name(const Name& name, DerNode* extensionsNode)
{
  if (isEncapsulatedX509(name))
    // Just decode the second component.
    return DerNode::parse(name.get(1).getValue());

  string uri = name.toUri();
  DerSequence* extensions = dynamic_cast<DerSequence*>(extensionsNode);
  if (extensions) {
    // Add the Subject Alternative Names without checking if one already exists.
    DerSequence generalNames;
    generalNames.addChild(ptr_lib::make_shared<DerNode::DerImplicitByteString>
      ((const uint8_t*)uri.c_str(), uri.size(), GENERAL_NAME_URI_TYPE));
    Blob generalNamesEncoding = generalNames.encode();

    ptr_lib::shared_ptr<DerSequence> extension(new DerSequence());
    extension->addChild(ptr_lib::make_shared<DerNode::DerOid>
      (OID(SUBJECT_ALTERNATIVE_NAME_OID)));
    extension->addChild(ptr_lib::make_shared<DerNode::DerOctetString>
      (generalNamesEncoding.buf(), generalNamesEncoding.size()));
    extensions->addChild(extension);
  }

  // Make an X.509 name with a "pseudonym". This is only temporary because in
  // production the X.509 certificate is created specially with a separate
  // X.509 name with an NDN name in Subject Alternative Names.
  ptr_lib::shared_ptr<DerSequence> root(new DerSequence());
  ptr_lib::shared_ptr<DerSequence> typeAndValue(new DerSequence());
  typeAndValue->addChild(ptr_lib::make_shared<DerNode::DerOid>(OID(PSEUDONYM_OID)));
  typeAndValue->addChild(ptr_lib::make_shared<DerNode::DerUtf8String>
    ((const uint8_t*)uri.c_str(), uri.size()));
  ptr_lib::shared_ptr<DerNode::DerSet> component(new DerNode::DerSet());
  component->addChild(typeAndValue);

  root->addChild(component);

  return root;
}

string
X509CertificateInfo::findCrlDistributionUri(DerNode* extensions)
{
  if (!extensions)
    return "";

  // See makeName() for the definition of Extensions and GeneralNames.
  //
  // CRLDistPointSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
  //
  // DistributionPoint ::= SEQUENCE {
  //   distributionPoint [0] DistributionPointName OPTIONAL,
  //   reasons      [1] ReasonFlags OPTIONAL,
  //   cRLIssuer    [2] GeneralNames OPTIONAL
  // }
  //
  // DistributionPointName ::= CHOICE {
  //   fullname  [0] GeneralNames,
  //   nameRelativeToCRLIssuer [1] RelativeDistinguishedName
  // }
  const vector<ptr_lib::shared_ptr<DerNode> >& extensionsChildren =
    extensions->getChildren();

  for (int iExtension = 0; iExtension < extensionsChildren.size(); ++iExtension) {
    DerSequence* extension = 
      dynamic_cast<DerSequence*>(extensionsChildren[iExtension].get());
    if (!extension)
      // We don't expect this.
      continue;
    const vector<ptr_lib::shared_ptr<DerNode> >& extensionChildren =
      extension->getChildren();

    if (extensionChildren.size() < 2 || extensionChildren.size() > 3)
      // We don't expect this.
      continue;
    DerNode::DerOid* oid = dynamic_cast<DerNode::DerOid*>(extensionChildren[0].get());
    // Ignore "critical".
    DerNode::DerOctetString* extensionValue = dynamic_cast<DerNode::DerOctetString*>
      (extensionChildren[extensionChildren.size() - 1].get());
    if (!oid || !extensionValue)
      // We don't expect this.
      continue;
    if (oid->toVal().toRawStr() != CRL_DISTRIBUTION_POINTS_OID)
      // Try the next extension.
      continue;

    try {
      ptr_lib::shared_ptr<DerNode> distributionPointList = DerNode::parse(extensionValue->toVal());
      const vector<ptr_lib::shared_ptr<DerNode> >& distributionPointListChildren =
        distributionPointList->getChildren();
      for (int i = 0; i < distributionPointListChildren.size(); ++i) {
        const vector<ptr_lib::shared_ptr<DerNode> >& distributionPointChildren =
          distributionPointListChildren[i]->getChildren();

        for (int j = 0; j < distributionPointChildren.size(); ++j) {
          // Get distributionPoint [0] DistributionPointName.
          DerNode::DerExplicit* distributionNameExplicit = dynamic_cast<DerNode::DerExplicit*>
            (distributionPointChildren[j].get());
          if (distributionNameExplicit && distributionNameExplicit->getTag() == 0 &&
              distributionNameExplicit->getChildren().size() == 1) {
            // Get fullname [0] GeneralNames.
            DerNode::DerExplicit* fullNameExplicit = dynamic_cast<DerNode::DerExplicit*>
              (distributionNameExplicit->getChildren()[0].get());
            if (fullNameExplicit && fullNameExplicit->getTag() == 0 &&
                fullNameExplicit->getChildren().size() == 1) {
              // Get an implicit GeneralName URI.
              DerNode::DerImplicitByteString* value =
                dynamic_cast<DerNode::DerImplicitByteString*>
                  (fullNameExplicit->getChildren()[0].get());
              if (value && value->getType() == GENERAL_NAME_URI_TYPE)
                return value->toVal().toRawStr();
            }
          }
        }
      }
    } catch (const std::exception& ex) {
      // We don't expect this.
      continue;
    }
  }

  return "";
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

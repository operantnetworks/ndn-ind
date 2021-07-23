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
#include <ndn-ind/security/certificate/x509-crl-info.hpp>

using namespace std;

namespace ndn {

typedef DerNode::DerSequence DerSequence;

X509CrlInfo::X509CrlInfo(const Blob& encoding)
{
  // See https://tools.ietf.org/html/rfc5280 .
  // CertificateList  ::=  SEQUENCE  {
  //       tbsCertList          TBSCertList,
  //       signatureAlgorithm   AlgorithmIdentifier,
  //       signatureValue       BIT STRING  }
  DerSequence* tbsCertList;
  DerSequence* signatureAlgorithm;
  try {
    root_ = DerNode::parse(encoding);
    const vector<ptr_lib::shared_ptr<DerNode> >& rootChildren =
      root_->getChildren();
    if (rootChildren.size() < 3)
      throw runtime_error("X509CrlInfo: Expected 3 CRL fields");
    tbsCertList = &DerNode::getSequence(rootChildren, 0);
    signatureAlgorithm = &DerNode::getSequence(rootChildren, 1);
    DerNode::DerBitString* signatureValueNode = dynamic_cast<DerNode::DerBitString*>
      (rootChildren[2].get());

    // Expect the first byte of the BIT STRING to be zero.
    if (!signatureValueNode || signatureValueNode->getPayload().size() < 1 ||
        signatureValueNode->getPayload().buf()[0] != 0)
      throw runtime_error("X509CrlInfo: Cannot decode signatureValue");
    signatureValue_ = Blob
      (signatureValueNode->getPayload().buf() + 1,
       signatureValueNode->getPayload().size() - 1);

    // Get the signed portion.
    size_t beginOffset = root_->getHeaderSize();
    size_t endOffset = beginOffset + tbsCertList->getSize();
    signedEncoding_ = SignedBlob(encoding, beginOffset, endOffset);
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CrlInfo: Cannot decode CRL: ") +
      ex.what());
  }

  // TBSCertList  ::=  SEQUENCE  {
  //      version                 Version OPTIONAL,
  //                                   -- if present, MUST be v2
  //      signature               AlgorithmIdentifier,
  //      issuer                  Name,
  //      thisUpdate              Time,
  //      nextUpdate              Time OPTIONAL,
  //      revokedCertificates     SEQUENCE OF SEQUENCE  {
  //           userCertificate         CertificateSerialNumber,
  //           revocationDate          Time,
  //           crlEntryExtensions      Extensions OPTIONAL
  //                                    -- if present, version MUST be v2
  //                                }  OPTIONAL,
  //      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
  //                                    -- if present, version MUST be v2
  //                                }
  try {
    const vector<ptr_lib::shared_ptr<DerNode> >& tbsChildren =
      tbsCertList->getChildren();

    int versionOffset = 0;
    if (tbsChildren.size() >= 1 &&
        dynamic_cast<DerNode::DerInteger*>(tbsChildren[0].get()))
      // There is a version.
      versionOffset = 1;
    if (tbsChildren.size() < 5 + versionOffset)
      throw runtime_error("X509CrlInfo: Expected 5 TBSCertList fields");

    issuerName_ = X509CertificateInfo::makeName
      (tbsChildren[1 + versionOffset].get(), 0);

    // Get thisUpdate and nextUpdate.
    DerNode::DerUtcTime* thisUpdate = dynamic_cast<DerNode::DerUtcTime*>
      (tbsChildren[2 + versionOffset].get());
    DerNode::DerUtcTime* nextUpdate = dynamic_cast<DerNode::DerUtcTime*>
      (tbsChildren[3 + versionOffset].get());
    if (!thisUpdate || !nextUpdate)
      throw runtime_error("X509CrlInfo: Cannot decode thisUpdate and nextUpdate");
    thisUpdate_ = thisUpdate->toTimePoint();
    nextUpdate_ = nextUpdate->toTimePoint();

    // Get the revoked certificate entries.
    const vector<ptr_lib::shared_ptr<DerNode> >& revokedCertificatesChildren =
      tbsChildren[4 + versionOffset]->getChildren();
    revokedCertificates_.reserve(revokedCertificatesChildren.size());
    for (int i = 0; i < revokedCertificatesChildren.size(); ++i) {
      DerSequence* revokedCertificate = dynamic_cast<DerSequence*>
        (revokedCertificatesChildren[i].get());
      if (!revokedCertificate)
        // We don't expect this.
        continue;
      const vector<ptr_lib::shared_ptr<DerNode> >& revokedCertificateChildren =
        revokedCertificate->getChildren();
      if (revokedCertificateChildren.size() < 2)
        throw runtime_error("X509CrlInfo: Cannot decode revokedCertificate sequence");

      DerNode::DerInteger* serialNumber = dynamic_cast<DerNode::DerInteger*>
        (revokedCertificateChildren[0].get());
      if (!serialNumber)
        throw runtime_error("X509CrlInfo: Cannot get serial number from revokedCertificate");
      DerNode::DerUtcTime* revocationDate = dynamic_cast<DerNode::DerUtcTime*>
        (revokedCertificateChildren[1].get());
      if (!revocationDate)
        throw runtime_error("X509CrlInfo: Cannot get revocation date from revokedCertificate");

      revokedCertificates_.push_back
        (RevokedCertificate(serialNumber->getPayload(), revocationDate->toTimePoint()));
    }

    // For now, ignore the extensions.
  } catch (const std::exception& ex) {
    throw runtime_error(string("X509CrlInfo: Cannot decode the TBSCertList: ") +
      ex.what());
  }
}

const X509CrlInfo::RevokedCertificate&
X509CrlInfo::getRevokedCertificate(size_t i) const
{
  if (i >= revokedCertificates_.size())
    throw runtime_error("X509CrlInfo::getRevokedCertificate: Index is out of bounds");

  return revokedCertificates_[i];
}

}

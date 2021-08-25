/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/v2/certificate-storage.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-storage.cpp
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

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/security/v2/certificate-storage.hpp>

using namespace std;

INIT_LOGGER("ndn.CertificateStorage");

namespace ndn {

ptr_lib::shared_ptr<CertificateV2>
CertificateStorage::findTrustedCertificate
  (const Interest& interestForCertificate)
{
  ptr_lib::shared_ptr<CertificateV2> certificate =
    trustAnchors_.find(interestForCertificate);
  if (!!certificate)
    return certificate;

  certificate = verifiedCertificateCache_.find(interestForCertificate);
  return certificate;
}

bool
CertificateStorage::isCertificateKnown(const Name& certificatePrefix)
{
  return !!trustAnchors_.find(certificatePrefix) ||
         !!verifiedCertificateCache_.find(certificatePrefix) ||
         !!unverifiedCertificateCache_.find(certificatePrefix);
}

bool
CertificateStorage::cacheVerifiedCertificate(const CertificateV2& certificate)
{
  ptr_lib::shared_ptr<X509CrlInfo> crlInfo = verifiedCrlCache_.find
    (certificate.getIssuerName());
  if (crlInfo) {
    const X509CrlInfo::RevokedCertificate* revoked = findRevokedCertificate
      (*crlInfo, certificate.getX509SerialNumber());
    if (revoked) {
      _LOG_ERROR("REVOKED: The CRL with thisUpdate time " <<
        toIsoString(crlInfo->getThisUpdate()) << " has revoked serial number " <<
        revoked->getSerialNumber().toHex() << " at time " <<
        toIsoString(revoked->getRevocationDate()) << ". Rejecting fetched certificate " <<
        certificate.getName().toUri());
      return false;
    }
  }

  verifiedCertificateCache_.insert(certificate);
  return true;
}

void
CertificateStorage::cacheVerifiedCrl(const X509CrlInfo& crlInfo)
{
  verifiedCrlCache_.insert(crlInfo);

  // Remove revoked certificates from verifiedCertificateCache_ .
  const std::map<Name, CertificateCacheV2::Entry>& certificates =
    verifiedCertificateCache_.getCertificatesByName();
  vector<Name> certificatesToRemove;
  for (auto certEntry = certificates.begin(); certEntry != certificates.end(); ++certEntry) {
    if (!certEntry->second.certificate_->getIssuerName().equals(crlInfo.getIssuerName()))
      // The certificate is not from the same issuer as the CRL.
      continue;

    const X509CrlInfo::RevokedCertificate* revoked = findRevokedCertificate
      (crlInfo, certEntry->second.certificate_->getX509SerialNumber());
    if (revoked) {
      _LOG_ERROR("REVOKED: The newly-fetched CRL with thisUpdate time " <<
        toIsoString(crlInfo.getThisUpdate()) << " has revoked serial number " <<
        revoked->getSerialNumber().toHex() << " at time " <<
        toIsoString(revoked->getRevocationDate()) << ". Removing certificate " <<
        certEntry->second.certificate_->getName().toUri());
      // Remove below after we finish reading the list.
      certificatesToRemove.push_back(certEntry->second.certificate_->getName());
    }
  }

  // Now remove the revoked certificates.
  for (size_t i = 0; i < certificatesToRemove.size(); ++i)
    verifiedCertificateCache_.deleteCertificate(certificatesToRemove[i]);
}

const X509CrlInfo::RevokedCertificate*
CertificateStorage::findRevokedCertificate
  (const X509CrlInfo& crlInfo, const Blob& serialNumber)
{
  if (serialNumber.size() == 0)
    // This can happen by calling getX509SerialNumber() on a non-X.509 certificate.
    return 0;

  for (size_t i = 0; i < crlInfo.getRevokedCertificateCount(); ++i) {
    const X509CrlInfo::RevokedCertificate& entry =
      crlInfo.getRevokedCertificate(i);
    if (entry.getSerialNumber().equals(serialNumber))
      return &entry;
  }

  return 0;
}

}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/security/v2/certificate-storage.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use std::chrono. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-storage.hpp
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

#ifndef NDN_CERTIFICATE_STORAGE_HPP
#define NDN_CERTIFICATE_STORAGE_HPP

#include "certificate-cache-v2.hpp"
#include "x509-crl-cache.hpp"
#include "trust-anchor-container.hpp"

namespace ndn {

/**
 * The CertificateStorage class stores trusted anchors and has a verified
 * certificate cache, and an unverified certificate cache.
 */
class ndn_ind_dll CertificateStorage {
public:
  CertificateStorage()
  : verifiedCertificateCache_(std::chrono::hours(1)),
    unverifiedCertificateCache_(std::chrono::minutes(5))
  {
  }

  /**
   * Find a trusted certificate in the trust anchor container or in the
   * verified cache.
   * @param interestForCertificate The Interest for the certificate.
   * @return The found certificate, or null if not found.
   */
  ptr_lib::shared_ptr<CertificateV2>
  findTrustedCertificate(const Interest& interestForCertificate);

  /**
   * Check if the certificate with the given name prefix exists in the verified
   * cache, the unverified cache, or in the set of trust anchors.
   * @param certificatePrefix The certificate name prefix.
   * @return True if the certificate is known.
   */
  bool
  isCertificateKnown(const Name& certificatePrefix);

  /**
   * Cache the unverified certificate for a period of time (5 minutes).
   * @param certificate The certificate packet, which is copied.
   */
  void
  cacheUnverifiedCertificate(const CertificateV2& certificate)
  {
    unverifiedCertificateCache_.insert(certificate);
  }

  /**
   * Get the trust anchor container.
   * @return The trust anchor container.
   */
  const TrustAnchorContainer&
  getTrustAnchors() const { return trustAnchors_; }

  /**
   * Get the verified certificate cache.
   * @return The verified certificate cache.
   */
  const CertificateCacheV2&
  getVerifiedCertificateCache() const { return verifiedCertificateCache_; }

  /**
   * Get the unverified certificate cache.
   * @return The unverified certificate cache.
   */
  const CertificateCacheV2&
  getUnverifiedCertificateCache() const { return unverifiedCertificateCache_; }

  /**
   * Load a static trust anchor. Static trust anchors are permanently associated
   * with the validator and never expire.
   * @param groupId The certificate group id.
   * @param certificate The certificate to load as a trust anchor, which is
   * copied.
   */
  void
  loadAnchor(const std::string& groupId, const CertificateV2& certificate)
  {
    trustAnchors_.insert(groupId, certificate);
  }

  /**
   * Load dynamic trust anchors. Dynamic trust anchors are associated with the
   * validator for as long as the underlying trust anchor file (or set of files)
   * exists.
   * @param groupId The certificate group id, which must not be empty.
   * @param path The path to load the trust anchors.
   * @param refreshPeriod  The refresh time for the anchors under path. This 
   * must be positive. The relevant trust anchors will only be updated when find
   * is called.
   * @param isDirectory (optional) If true, then path is a directory. If false
   * or omitted, it is a single file.
   * @throws std::invalid_argument If refreshPeriod is not positive.
   * @throws TrustAnchorContainer::Error a group with groupId already exists
   */
  void
  loadAnchor
    (const std::string& groupId, const std::string& path,
     std::chrono::nanoseconds refreshPeriod, bool isDirectory = false)
  {
    trustAnchors_.insert(groupId, path, refreshPeriod, isDirectory);
  }

  /**
   * Remove any previously loaded static or dynamic trust anchors.
   */
  void
  resetAnchors() { trustAnchors_.clear(); }

  /**
   * Check if the CRL revoked the certificate and if not then
   * cache the verified certificate a period of time (1 hour).
   * @param certificate The certificate object, which is copied.
   * @return True for success, false if the CRL from the issuer has revoked this
   * certificate (in which case there is a log message).
   */
  bool
  cacheVerifiedCertificate(const CertificateV2& certificate);

  /**
   * Cache the verified CRL in the X509CrlCache, and evict certificates from the
   * verified certificate cache which have the same issuer as the CRL and which
   * have a serial number in the revocation list. The cached CRL will be used to
   * check if a new certificate is revoked before adding the the verified
   * certificate cache.
   * @param crlInfo The X509CrlInfo object, which is copied.
   */
  void
  cacheVerifiedCrl(const X509CrlInfo& crlInfo);

  /**
   * Remove any cached verified certificates.
   */
  void
  resetVerifiedCertificates() { verifiedCertificateCache_.clear(); }

  /**
   * Set the offset when the cache insert() and refresh() get the current time,
   * which should only be used for testing.
   * @param nowOffset The offset.
   */
  void
  setCacheNowOffset_(std::chrono::nanoseconds nowOffset)
  {
    verifiedCertificateCache_.setNowOffset_(nowOffset);
    unverifiedCertificateCache_.setNowOffset_(nowOffset);
  }

  /**
   * Find the first entry in crlInfo where the entry's serial number matches the
   * given serial number.
   * @param crlInfo The X509CrlInfo to search.
   * @param serialNumber The serial number to match as a Blob with the bytes of
   * the integer. If serialNumber.size() == 0, this does not match it.
   * @return The matching RevokedCertificate entry, or null if not found. The
   * pointer to the entry becomes invalid if the crlInfo is changed, so make a
   * copy if you need it long-term.
   */
  static const X509CrlInfo::RevokedCertificate*
  findRevokedCertificate(const X509CrlInfo& crlInfo, const Blob& serialNumber);

private:
  // Disable the copy constructor and assignment operator.
  CertificateStorage(const CertificateStorage& other);
  CertificateStorage& operator=(const CertificateStorage& other);

protected:
  TrustAnchorContainer trustAnchors_;
  CertificateCacheV2 verifiedCertificateCache_;
  CertificateCacheV2 unverifiedCertificateCache_;
  X509CrlCache verifiedCrlCache_;
};

}

#endif

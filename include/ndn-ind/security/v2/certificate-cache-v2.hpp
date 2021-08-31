/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/security/v2/certificate-cache-v2.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use std::chrono. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-cache.hpp
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

#ifndef NDN_CERTIFICATE_CACHE_V2_HPP
#define NDN_CERTIFICATE_CACHE_V2_HPP

#include <float.h>
#include <map>
#include "../../interest.hpp"
#include "certificate-v2.hpp"

namespace ndn {

/**
 * A CertificateCacheV2 holds other user's verified certificates in security v2
 * format CertificateV2. A certificate is removed no later than its NotAfter
 * time, or maxLifetime after it has been added to the cache.
 */
class ndn_ind_dll CertificateCacheV2 {
public:
  /**
   * Create a CertificateCacheV2.
   * @param maxLifetime (optional) The maximum time that certificates can live
   * inside the cache. If omitted, use getDefaultLifetime().
   */
  CertificateCacheV2(std::chrono::nanoseconds maxLifetime = getDefaultLifetime());

  /**
   * Insert the certificate into the cache. The inserted certificate will be
   * removed no later than its NotAfter time, or maxLifetime given
   * to the constructor.
   * @param certificate The certificate object, which is copied.
   */
  void
  insert(const CertificateV2& certificate);

  /**
   * Find the certificate by the given key name.
   * @param certificatePrefix The certificate prefix for searching for the
   * certificate.
   * @return The found certificate, or null if not found. You must not modify
   * the returned object. If you need to modify it, then make a copy.
   */
  ptr_lib::shared_ptr<CertificateV2>
  find(const Name& certificatePrefix) const;

  /**
   * Find the certificate by the given interest.
   * @param interest The input interest object.
   * @return The found certificate which matches the interest, or null if not
   * found. You must not modify the returned object. If you need to modify it,
   * then make a copy.
   * @note ChildSelector is not supported.
   */
  ptr_lib::shared_ptr<CertificateV2>
  find(const Interest& interest) const;

  /**
   * Remove the certificate whose name equals the given name. If no such
   * certificate is in the cache, do nothing.
   * @param certificateName The name of the certificate.
   */
  void
  deleteCertificate(const Name& certificateName);

  /**
   * Clear all certificates from the cache.
   */
  void
  clear();

  /**
   * Get the default maximum lifetime (1 hour).
   * @return The default lifetime.
   */
  static std::chrono::nanoseconds
  getDefaultLifetime() { return std::chrono::hours(1); }

  /**
   * Set the offset when insert() and refresh() get the current time, which
   * should only be used for testing.
   * @param nowOffset The offset.
   */
  void
  setNowOffset_(std::chrono::nanoseconds nowOffset)
  {
    nowOffset_ = nowOffset;
  }

  /**
   * CertificateCacheV2::Entry is the value of the certificatesByName_ map.
   */
  class Entry {
  public:
    /**
     * Create a new CertificateCacheV2::Entry with the given values.
     * @param certificate The certificate.
     * @param removalTime The removal time for this entry.
     */
    Entry
      (const ptr_lib::shared_ptr<CertificateV2>& certificate,
       std::chrono::system_clock::time_point removalTime)
    : certificate_(certificate), removalTime_(removalTime)
    {}

    Entry()
    {}

    ptr_lib::shared_ptr<CertificateV2> certificate_;
    std::chrono::system_clock::time_point removalTime_;
  };

  /**
   * Get the list of cached certificates, which you should not modify.
   * @return A map where the key is the certificate Name and the value is
   * the CertificateCacheV2::Entry which has the certificate_.
   */
  const std::map<Name, Entry>&
  getCertificatesByName() const
  {
    return certificatesByName_;
  }

private:
  /**
   * Remove all outdated certificate entries.
   */
  void
  refresh();

  // Disable the copy constructor and assignment operator.
  CertificateCacheV2(const CertificateCacheV2& other);
  CertificateCacheV2& operator=(const CertificateCacheV2& other);

  std::map<Name, Entry> certificatesByName_;
  std::chrono::system_clock::time_point nextRefreshTime_;
  std::chrono::nanoseconds maxLifetime_;
  std::chrono::nanoseconds nowOffset_;
};

}

#endif

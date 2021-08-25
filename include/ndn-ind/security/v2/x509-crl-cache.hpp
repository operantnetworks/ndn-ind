/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
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

#ifndef NDN_CRL_CACHE_HPP
#define NDN_CRL_CACHE_HPP

#include <float.h>
#include <map>
#include "../../interest.hpp"
#include "../certificate/x509-crl-info.hpp"

namespace ndn {

/**
 * An X509CrlCache holds retrieved X509CrlInfo objects, indexed by the
 * encapsulated X.509 name of the issuer. A CRL is removed no later than
 * its nextUpdate time.
 */
class ndn_ind_dll X509CrlCache {
public:
  /**
   * Create an X509CrlCache.
   */
  X509CrlCache();

  /**
   * Insert the CRL into the cache. (This does not validate its signature.) If
   * the current time is outside of the range of the thisUpdate time and
   * nextUpdate time, then log a message and don't insert. If the thisUpdate
   * time is before the thisUpdate time of an existing CRL from the same issuer,
   * then log a message and don't insert. If a CRL exists with the same issuer
   * name, it is replaced. The inserted CRL will be removed no later than its
   * nextUpdate time.
   * @param crlInfo The X509CrlInfo object, which is copied.
   * @return True for success, false if not inserted for some reason such as
   * already expired (the reason is sent to the log output).
   */
  bool
  insert(const X509CrlInfo& crlInfo);

  /**
   * Find the certificate by the given issuer name.
   * @param issuerName The encapsulated X.509 issuer name.
   * @return The found X509CrlInfo, or null if not found. You must not modify
   * the returned object. If you need to modify it, then make a copy.
   */
  ptr_lib::shared_ptr<X509CrlInfo>
  find(const Name& issuerName) const;

  /**
   * Clear all CRLs from the cache.
   */
  void
  clear()
  {
    crlsByName_.clear();
    nextRefreshTime_ = std::chrono::system_clock::time_point::max();
  }

  /**
   * X509CrlCache::Entry is the value of the crlsByName_ map.
   */
  class Entry {
  public:
    /**
     * Create a new X509CrlCache::Entry with the given values.
     * @param crlInfo The X509CrlInfo.
     * @param removalTime The removal time for this entry.
     */
    Entry
      (const ptr_lib::shared_ptr<X509CrlInfo>& crlInfo,
       std::chrono::system_clock::time_point removalTime)
    : crlInfo_(crlInfo), removalTime_(removalTime)
    {}

    Entry()
    {}

    ptr_lib::shared_ptr<X509CrlInfo> crlInfo_;
    std::chrono::system_clock::time_point removalTime_;
  };

private:
  /**
   * Remove all outdated CRL entries.
   */
  void
  refresh();

  // Disable the copy constructor and assignment operator.
  X509CrlCache(const X509CrlCache& other);
  X509CrlCache& operator=(const X509CrlCache& other);

  std::map<Name, Entry> crlsByName_;
  std::chrono::system_clock::time_point nextRefreshTime_;
};

}

#endif

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/v2/certificate-cache-v2.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-cache.cpp
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

#include <algorithm>
#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/security/v2/certificate-cache-v2.hpp>

using namespace std;
using namespace std::chrono;

INIT_LOGGER("ndn.CertificateCacheV2");

namespace ndn {

CertificateCacheV2::CertificateCacheV2(nanoseconds maxLifetime)
: maxLifetime_(maxLifetime),
  nextRefreshTime_(system_clock::time_point::max()),
  nowOffset_(0)
{
}

void
CertificateCacheV2::insert(const CertificateV2& certificate)
{
  auto notAfterTime = certificate.getValidityPeriod().getNotAfter();
  // nowOffset_ is only used for testing.
  auto now = system_clock::now() + duration_cast<system_clock::duration>(nowOffset_);
  if (notAfterTime < now) {
    _LOG_DEBUG("Not adding " << certificate.getName().toUri() <<
      ": already expired at " << toIsoString(notAfterTime));
    return;
  }

  auto removalTime =
    min(notAfterTime, now + duration_cast<system_clock::duration>(maxLifetime_));
  if (removalTime < nextRefreshTime_)
    // We need to run refresh() sooner.)
    nextRefreshTime_ = removalTime;

  auto removalHours = duration_cast<hours>(removalTime - now).count();
  _LOG_DEBUG("Adding " << certificate.getName().toUri() << ", will remove in "
    << removalHours << " hours");
  ptr_lib::shared_ptr<CertificateV2> certificateCopy(new CertificateV2(certificate));
  certificatesByName_[certificateCopy->getName()] =
    Entry(certificateCopy, removalTime);
}

ptr_lib::shared_ptr<CertificateV2>
CertificateCacheV2::find(const Name& certificatePrefix) const
{
  if (certificatePrefix.size() > 0 &&
      certificatePrefix[-1].isImplicitSha256Digest())
    _LOG_DEBUG("Certificate search using a name with an implicit digest is not yet supported");

  const_cast<CertificateCacheV2*>(this)->refresh();

  map<Name, Entry>::const_iterator itr =
    certificatesByName_.lower_bound(certificatePrefix);
  if (itr == certificatesByName_.end() ||
      !certificatePrefix.isPrefixOf(itr->second.certificate_->getName()))
    return ptr_lib::shared_ptr<CertificateV2>();
  return itr->second.certificate_;
}

ptr_lib::shared_ptr<CertificateV2>
CertificateCacheV2::find(const Interest& interest) const
{
  if (interest.getChildSelector() >= 0)
    _LOG_DEBUG("Certificate search using a ChildSelector is not supported. Searching as if this selector not specified");

  if (interest.getName().size() > 0 &&
      interest.getName()[-1].isImplicitSha256Digest())
    _LOG_DEBUG("Certificate search using a name with an implicit digest is not yet supported");

  const_cast<CertificateCacheV2*>(this)->refresh();

  for (map<Name, Entry>::const_iterator i =
         certificatesByName_.lower_bound(interest.getName());
       i != certificatesByName_.end() &&
         interest.getName().isPrefixOf(i->second.certificate_->getName());
       ++i) {
    if (interest.matchesData(*i->second.certificate_))
      return i->second.certificate_;
  }

  return ptr_lib::shared_ptr<CertificateV2>();
}

void
CertificateCacheV2::deleteCertificate(const Name& certificateName)
{
  certificatesByName_.erase(certificateName);
  // This may be the certificate to be removed at nextRefreshTime_ by refresh(),
  // but just allow refresh() to run instead of update nextRefreshTime_ now.
}

void
CertificateCacheV2::clear()
{
  certificatesByName_.clear();
  nextRefreshTime_ = system_clock::time_point::max();
}

void
CertificateCacheV2::refresh()
{
  // nowOffset_ is only used for testing.
  auto now = system_clock::now() + duration_cast<system_clock::duration>(nowOffset_);
  if (now < nextRefreshTime_)
    return;

  // We recompute nextRefreshTime_.
  auto nextRefreshTime = system_clock::time_point::max();
  // Keep a separate list of entries to erase since we can't erase while iterating.
  vector<Name> namesToErase;
  for (map<Name, Entry>::const_iterator i = certificatesByName_.begin();
       i != certificatesByName_.end(); ++i) {
    if (i->second.removalTime_ <= now)
      namesToErase.push_back(i->first);
    else
      nextRefreshTime = min(nextRefreshTime, i->second.removalTime_);
  }

  nextRefreshTime_ = nextRefreshTime;
  // Now actually erase.
  for (int i = 0; i < namesToErase.size(); ++i)
    certificatesByName_.erase(namesToErase[i]);
}

}

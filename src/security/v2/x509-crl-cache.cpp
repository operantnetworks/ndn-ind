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

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/security/v2/x509-crl-cache.hpp>

using namespace std;
using namespace std::chrono;

INIT_LOGGER("ndn.X509CrlCache");

namespace ndn {

X509CrlCache::X509CrlCache()
: nextRefreshTime_(system_clock::time_point::max())
{
}

bool
X509CrlCache::insert(const X509CrlInfo& crlInfo)
{
  auto now = system_clock::now();

  // Check if the validity period is in range.
  if (now < crlInfo.getThisUpdate()) {
    _LOG_INFO("The current time is before the CRL thisUpdate time " <<
      toIsoString(crlInfo.getThisUpdate()) << ": Not adding CRL from issuer " <<
      crlInfo.getIssuerName().toUri());
    return false;
  }
  auto nextUpdate = crlInfo.getNextUpdate();
  if (nextUpdate < now) {
    _LOG_INFO("The current time is already past the CRL nextUpdate time " <<
      toIsoString(nextUpdate) << ": Not adding CRL from issuer " <<
      crlInfo.getIssuerName().toUri());
    return false;
  }

  // Check if a more recent CRL already exists.
  ptr_lib::shared_ptr<X509CrlInfo> otherCrlInfo = find(crlInfo.getIssuerName());
  if (otherCrlInfo && otherCrlInfo->getThisUpdate() > crlInfo.getThisUpdate()) {
    _LOG_INFO(
      "There is already a CRL from the same issuer with newer thisUpdate time: Not adding CRL with thisUpdate time " <<
      toIsoString(crlInfo.getThisUpdate()) << " from issuer " <<
      crlInfo.getIssuerName().toUri());
    return false;
  }

  auto removalHours = duration_cast<hours>(nextUpdate - now).count();
  _LOG_DEBUG("Adding CRL from issuer " << crlInfo.getIssuerName().toUri() <<
    ", will remove in " << removalHours << " hours");
  ptr_lib::shared_ptr<X509CrlInfo> crlInfoCopy(new X509CrlInfo(crlInfo));
  crlsByName_[crlInfoCopy->getIssuerName()] = Entry(crlInfoCopy, nextUpdate);

  return true;
}

ptr_lib::shared_ptr<X509CrlInfo>
X509CrlCache::find(const Name& issuerName) const
{
  const_cast<X509CrlCache*>(this)->refresh();

  map<Name, Entry>::const_iterator itr = crlsByName_.find(issuerName);
  if (itr == crlsByName_.end())
    return ptr_lib::shared_ptr<X509CrlInfo>();
  return itr->second.crlInfo_;
}

void
X509CrlCache::refresh()
{
  auto now = system_clock::now();
  if (now < nextRefreshTime_)
    return;

  // We recompute nextRefreshTime_.
  auto nextRefreshTime = system_clock::time_point::max();
  // Keep a separate list of entries to erase since we can't erase while iterating.
  vector<Name> issuerNamesToErase;
  for (map<Name, Entry>::const_iterator i = crlsByName_.begin();
       i != crlsByName_.end(); ++i) {
    if (i->second.removalTime_ <= now) {
      _LOG_DEBUG("Removing cached CRL with next update " <<
        toIsoString(i->second.crlInfo_->getNextUpdate()) <<
        " from issuer " << i->second.crlInfo_->getIssuerName().toUri());
      issuerNamesToErase.push_back(i->first);
    }
    else
      nextRefreshTime = min(nextRefreshTime, i->second.removalTime_);
  }

  nextRefreshTime_ = nextRefreshTime;
  // Now actually erase.
  for (int i = 0; i < issuerNamesToErase.size(); ++i)
    crlsByName_.erase(issuerNamesToErase[i]);
}

}

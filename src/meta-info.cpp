/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/meta-info.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
#include <ndn-ind/meta-info.hpp>
#include "c/data.h"

using namespace std;

namespace ndn {

void
MetaInfo::get(MetaInfoLite& metaInfoLite) const
{
  // Set the deprecated timestamp from the struct ndn_MetaInfo since
  //   MetaInfoLite doesn't expose it.
  ((struct ndn_MetaInfo *)&metaInfoLite)->timestampMilliseconds = 
    toMillisecondsSince1970(timestamp_);
  metaInfoLite.setType(type_);
  metaInfoLite.setOtherTypeCode(otherTypeCode_);
  metaInfoLite.setFreshnessPeriod(toMilliseconds(freshnessPeriod_));
  metaInfoLite.setFinalBlockId(NameLite::Component(finalBlockId_.getValue()));
}

void
MetaInfo::set(const MetaInfoLite& metaInfoLite)
{
  // Get the deprecated timestamp from the struct ndn_MetaInfo since
  //   MetaInfoLite doesn't expose it.
  timestamp_ = fromMillisecondsSince1970
    (((struct ndn_MetaInfo *)&metaInfoLite)->timestampMilliseconds);
  setType(metaInfoLite.getType());
  // Set otherTypeCode_ directly to avoid the non-negative check.
  otherTypeCode_ = metaInfoLite.getOtherTypeCode();
  setFreshnessPeriod(fromMilliseconds(metaInfoLite.getFreshnessPeriod()));
  setFinalBlockId(Name::Component(Blob(metaInfoLite.getFinalBlockId().getValue())));
}

void
MetaInfo::setOtherTypeCode(int otherTypeCode)
{
  if (otherTypeCode < 0)
    throw runtime_error("MetaInfo other type code must be non-negative");

  otherTypeCode_ = otherTypeCode;
  ++changeCount_;
}

}

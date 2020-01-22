/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
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

#ifndef NDN_META_INFO_HPP
#define NDN_META_INFO_HPP

#include <math.h>
#include "name.hpp"
#include "c/data-types.h"
#include "lite/meta-info-lite.hpp"

namespace ndn {

/**
 * A MetaInfo holds the meta info which is signed inside the data packet.
 */
class MetaInfo {
public:
  MetaInfo()
  : timestamp_(std::chrono::milliseconds(-1)), changeCount_(0)
  {
    type_ = ndn_ContentType_BLOB;
    otherTypeCode_ = -1;
    freshnessPeriod_ = std::chrono::nanoseconds(-1);
  }

  /**
   * Set metaInfoLite to point to the values in this meta info object, without
   * copying any memory.
   * WARNING: The resulting pointers in metaInfoLite are invalid after a further
   * use of this object which could reallocate memory.
   * @param metaInfoLite The MetaInfoLite object which receives the values.
   */
  void
  get(MetaInfoLite& metaInfoLite) const;

  /**
   * Clear this meta info, and set the values by copying from metaInfoLite.
   * @param metaInfoLite A MetaInfoLite object.
   */
  void
  set(const MetaInfoLite& metaInfoLite);

  /**
   * @deprecated Use the application-specific content to store a timestamp.
   */
  std::chrono::system_clock::time_point
  DEPRECATED_IN_NDN_IND getTimestamp() const
  {
    return timestamp_;
  }

  /**
   * Get the content type.
   * @return The content type enum value. If this is ndn_ContentType_OTHER_CODE,
   * then call getOtherTypeCode() to get the unrecognized content type code.
   */
  ndn_ContentType
  getType() const { return type_; }

  /**
   * Get the content type code from the packet which is other than a recognized
   * ContentType enum value. This is only meaningful if getType() is
   * ndn_ContentType_OTHER_CODE.
   * @return The type code.
   */
  int
  getOtherTypeCode() const { return otherTypeCode_; }

  std::chrono::nanoseconds
  getFreshnessPeriod() const { return freshnessPeriod_; }

  /**
   * Get the final block ID.
   * @return The final block ID as a Name::Component.  If the name component
   * getValue().size() is 0, then the final block ID is not specified.
   */
  const Name::Component&
  getFinalBlockId() const { return finalBlockId_; }

  /**
   * @deprecated Use getFinalBlockId.
   */
  const Name::Component&
  DEPRECATED_IN_NDN_IND getFinalBlockID() const { return getFinalBlockId(); }

  /**
   * @deprecated Use the application-specific content to store a timestamp.
   */
  void
  DEPRECATED_IN_NDN_IND setTimestamp
    (std::chrono::system_clock::time_point timestamp)
  {
    timestamp_ = timestamp;
    ++changeCount_;
  }

  /**
   * Set the content type.
   * @param type The content type enum value. If the packet's content type is
   * not a recognized ContentType enum value, use ndn_ContentType_OTHER_CODE and
   * call setOtherTypeCode().
   */
  void
  setType(ndn_ContentType type)
  {
    type_ = type;
    ++changeCount_;
  }

  /**
   * Set the packet's content type code to use when the content type enum is
   * ndn_ContentType_OTHER_CODE. If the packet's content type code is a
   * recognized enum value, just call setType().
   * @param otherTypeCode The packet's unrecognized content type code, which
   * must be non-negative.
   */
  void
  setOtherTypeCode(int otherTypeCode);

  void
  setFreshnessPeriod(std::chrono::nanoseconds freshnessPeriod)
  {
    freshnessPeriod_ = freshnessPeriod;
    ++changeCount_;
  }

  /**
   * Set the final block ID.
   * @param finalBlockId The final block ID as a Name::Component.  If the name
   * component getValue().size() is 0, then the final block ID is not specified.
   */
  void
  setFinalBlockId(const Name::Component& finalBlockId)
  {
    finalBlockId_ = finalBlockId;
    ++changeCount_;
  }

  /**
   * @deprecated Use setFinalBlockId.
   */
  void
  DEPRECATED_IN_NDN_IND setFinalBlockID(const Name::Component& finalBlockId)
  {
    finalBlockId_ = finalBlockId;
    ++changeCount_;
  }

  /**
   * Get the change count, which is incremented each time this object is changed.
   * @return The change count.
   */
  uint64_t
  getChangeCount() const { return changeCount_; }

private:
  std::chrono::system_clock::time_point timestamp_; /**< time_point. -1 ms for none */
  ndn_ContentType type_;         /**< default is ndn_ContentType_BLOB. -1 for none */
  int otherTypeCode_;
  std::chrono::nanoseconds freshnessPeriod_; /**< -1 ms for none */
  Name::Component finalBlockId_; /** size 0 for none */
  uint64_t changeCount_;
};

}

#endif

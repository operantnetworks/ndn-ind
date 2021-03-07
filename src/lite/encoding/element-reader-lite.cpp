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

#include "../../c/encoding/element-reader.h"
#include <ndn-ind/lite/encoding/element-reader-lite.hpp>

namespace ndn {

ElementReaderLite::ElementReaderLite
  (ElementListenerLite* elementListener, DynamicUInt8ArrayLite* buffer,
   bool readRawPackets)
{
  ndn_ElementReader_initialize
    (this, elementListener, buffer, readRawPackets ? 1 : 0);
}

void
ElementReaderLite::reset(ElementListenerLite* elementListener)
{
  ndn_ElementReader_reset(this, elementListener);
}

ndn_Error
ElementReaderLite::onReceivedData(const uint8_t *data, size_t dataLength)
{
  return ndn_ElementReader_onReceivedData(this, data, dataLength);
}

}

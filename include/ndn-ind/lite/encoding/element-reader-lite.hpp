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

#ifndef NDN_ELEMENT_READER_LITE_HPP
#define NDN_ELEMENT_READER_LITE_HPP

#include "../util/dynamic-uint8-array-lite.hpp"
#include "element-listener-lite.hpp"

namespace ndn {

/**
 * An ElementReaderLite lets the application call onReceivedData() which calls
 * elementListener->onReceivedElement when an entire element has been read.
 *
 */
class ndn_ind_dll ElementReaderLite : private ndn_ElementReader {
public:
  /**
   * Create an ElementReaderLite with the elementListener and a buffer for saving
   * partial data.
   * @param elementListener A pointer to the ElementListenerLite used by
   * onReceivedData. If this is null, you can set it later with reset().
   * @param buffer A pointer to a DynamicUInt8ArrayLite which is used to save data
   * before calling the elementListener. The object must remain valid during the
   * entire life of this ElementReaderLite. If the reallocFunction function
   * pointer is null, its array must be large enough to save a full element,
   * perhaps MAX_NDN_PACKET_SIZE bytes.
   * However, if readRawPackets is true, then the buffer is not used.
   * @param readRawPackets (optional) If true, then call
   * elementListener->onReceivedElement for each received packet as-is. If omitted
   * or false,then use the ndn_TlvStructureDecoder to ensure that
   * elementListener->onReceivedElement is called once for a whole TLV packet.
   */
  ElementReaderLite
    (ElementListenerLite* elementListener, DynamicUInt8ArrayLite* buffer,
     bool readRawPackets = false);

  /**
   * Reset the state of this ElementReaderLite to begin reading new data and use
   * the given elementListener. Keep using the buffer provided to the constructor.
   * @param elementListener A pointer to the ElementListenerLite used by
   * onReceivedData.
   */
  void
  reset(ElementListenerLite* elementListener);

  /**
   * Continue to read data until the end of an element, then call
   * (*elementListener->onReceivedElement)(element, elementLength).
   * The buffer passed to onReceivedElement is only valid during this call. If
   * you need the data later, you must copy.
   * @param data pointer to the buffer with the incoming element's bytes.
   * @param dataLength length of data.
   * @return 0 for success, else an error code.
   */
  ndn_Error
  onReceivedData(const uint8_t *data, size_t dataLength);
};

}

#endif

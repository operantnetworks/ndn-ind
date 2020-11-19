/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-ind/c/encoding/element-reader-types.h
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Add readRawPackets.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2015-2020 Regents of the University of California.
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

#ifndef NDN_ELEMENT_READER_TYPES_H
#define NDN_ELEMENT_READER_TYPES_H

#include "../util/dynamic-uint8-array-types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ndn_ElementListener;
typedef void (*ndn_OnReceivedElement)
  (struct ndn_ElementListener *self, const uint8_t *element, size_t elementLength);

/** An ndn_ElementListener struct holds a function pointer onReceivedElement.  You can extend this struct with data that
 * will be passed to onReceivedElement.
 */
struct ndn_ElementListener {
  ndn_OnReceivedElement onReceivedElement; /**< see ndn_ElementListener_initialize */
};

struct ndn_TlvStructureDecoder {
  int gotElementEnd; /**< boolean */
  size_t offset;
  int state;
  size_t headerLength;
  int useHeaderBuffer; /**< boolean */
  // 8 bytes is enough to hold the extended bytes in the length encoding where it is an 8-byte number.
  uint8_t headerBuffer[8];
  size_t nBytesToRead;
  unsigned int firstOctet;
};

/**
 * A ndn_ElementReader lets you call ndn_ElementReader_onReceivedData multiple times which uses an
 * ndn_TlvStructureDecoder as needed to detect the end of a TLV element,
 * and calls (*elementListener->onReceivedElement)(element, elementLength) with the element.
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 * However, if readRawPackets is 1, then onReceivedElement for each received packet without processing.
 */
struct ndn_ElementReader {
  struct ndn_ElementListener *elementListener;
  int readRawPackets;       /**< boolean */
  struct ndn_TlvStructureDecoder tlvStructureDecoder; /**< Only used if readRawPackets == 0. */
  int usePartialData;       /**< boolean. Only used if readRawPackets == 0. */
  int gotPartialDataError;  /**< boolean. Only meaningful if usePartialData. Only used if readRawPackets == 0. */
  struct ndn_DynamicUInt8Array* partialData; /**< Only used if readRawPackets == 0. */
  size_t partialDataLength;                  /**< Only used if readRawPackets == 0. */
};

#ifdef __cplusplus
}
#endif

#endif

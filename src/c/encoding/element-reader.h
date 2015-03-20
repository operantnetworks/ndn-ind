/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

#ifndef NDN_ELEMENT_READER_H
#define NDN_ELEMENT_READER_H

#include "element-listener.h"
#include "binary-xml-structure-decoder.h"
#include "tlv/tlv-structure-decoder.h"
#include "../util/dynamic-uint8-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A ndn_ElementReader lets you call ndn_ElementReader_onReceivedData multiple times which uses an
 * ndn_BinaryXmlStructureDecoder or ndn_TlvStructureDecoder as needed to detect the end of a binary XML or TLV element,
 * and calls (*elementListener->onReceivedElement)(element, elementLength) with the element.
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 */
struct ndn_ElementReader {
  struct ndn_ElementListener *elementListener;
  struct ndn_BinaryXmlStructureDecoder binaryXmlStructureDecoder;
  struct ndn_TlvStructureDecoder tlvStructureDecoder;
  int usePartialData;
  struct ndn_DynamicUInt8Array partialData;
  size_t partialDataLength;
  int useTlv; /**< boolean */
};

/**
 * Initialize an ndn_ElementReader struct with the elementListener and a buffer for saving partial data.
 * @param self pointer to the ndn_ElementReader struct
 * @param elementListener pointer to the ndn_ElementListener used by 
 * ndn_ElementReader_onReceivedData. If this is 0, you can set it later with
 * ndn_ElementReader_reset.
 * @param buffer the allocated buffer.  If reallocFunction is null, this should 
 * be large enough to save a full element, perhaps MAX_NDN_PACKET_SIZE bytes.
 * @param bufferLength the length of the buffer
 * @param reallocFunction see ndn_DynamicUInt8Array_ensureLength.  This may be 0.
 */
static __inline void ndn_ElementReader_initialize
  (struct ndn_ElementReader *self, struct ndn_ElementListener *elementListener,
   uint8_t *buffer, size_t bufferLength, ndn_ReallocFunction reallocFunction)
{
  self->elementListener = elementListener;
  ndn_BinaryXmlStructureDecoder_initialize(&self->binaryXmlStructureDecoder);
  ndn_TlvStructureDecoder_initialize(&self->tlvStructureDecoder);
  self->usePartialData = 0;
  ndn_DynamicUInt8Array_initialize(&self->partialData, buffer, bufferLength, reallocFunction);
}

/**
 * Reset the state of this ElementReader to begin reading new data and use the
 * given elementListener. Keep using the buffer provided to
 * ndn_ElementReader_initialize.
 * @param self pointer to the ndn_ElementReader struct.
 * @param elementListener pointer to the ndn_ElementListener used by
 * ndn_ElementReader_onReceivedData.
 */
static __inline void ndn_ElementReader_reset
  (struct ndn_ElementReader *self, struct ndn_ElementListener *elementListener)
{
  self->elementListener = elementListener;
  ndn_BinaryXmlStructureDecoder_reset(&self->binaryXmlStructureDecoder);
  ndn_TlvStructureDecoder_reset(&self->tlvStructureDecoder);
  self->usePartialData = 0;
}

/**
 * Continue to read data until the end of an element, then call (*elementListener->onReceivedElement)(element, elementLength).
 * The buffer passed to onReceivedElement is only valid during this call.  If you need the data later, you must copy.
 * @param self pointer to the ndn_ElementReader struct
 * @param data pointer to the buffer with the incoming element's bytes
 * @param dataLength length of data
 * @return 0 for success, else an error code
 */
ndn_Error ndn_ElementReader_onReceivedData
  (struct ndn_ElementReader *self, uint8_t *data, size_t dataLength);

#ifdef __cplusplus
}
#endif

#endif

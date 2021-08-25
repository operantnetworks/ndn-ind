/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020-2021 Operant Networks, Incorporated.
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/encoding/der/der-node.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono. Add DerSet,
 *   DerUtcTime, DerExplicit and DerIa5String.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

#ifndef NDN_DER_NODE_HPP
#define NDN_DER_NODE_HPP

#include <ndn-ind/util/blob.hpp>
#include <ndn-ind/encoding/oid.hpp>
#include "../../util/dynamic-uint8-vector.hpp"
#include "der-node-type.hpp"

namespace ndn {

/**
 * DerNode implements the DER node types used in encoding/decoding DER-formatted
 * data.
 */
class DerNode {
public:
  virtual size_t
  getSize();

  /**
   * Get the number of bytes of the encoded header (not the size field in the
   * header).
   * @return The header size.
   */
  size_t
  getHeaderSize()
  {
    // Call getSize() which may update the header.
    getSize();
    return header_.size();
  }

  /**
   * Get the raw data encoding for this node.
   * @return The raw data encoding.
   */
  virtual Blob
  encode();

  /**
   * Parse the data from the input buffer recursively and return the root as an
   * object of a subclass of DerNode.
   * @param inputBuf The input buffer to read from. This reads from startIdx.
   * @param inputBufLength The number of bytes in the input buffer.
   * @param startIdx (optional) The offset into the buffer. If omitted, use 0.
   * @return A shared_ptr for an object of a subclass of DerNode.
   */
  static ptr_lib::shared_ptr<DerNode>
  parse(const uint8_t* inputBuf, size_t inputBufLength, size_t startIdx = 0);

  static ptr_lib::shared_ptr<DerNode>
  parse(const Blob& input, size_t startIdx = 0)
  {
    return parse(input.buf(), input.size(), startIdx);
  }

  static ptr_lib::shared_ptr<DerNode>
  parse(const std::vector<uint8_t>& input, size_t startIdx = 0)
  {
    return parse(&input[0], input.size(), startIdx);
  }

  /**
   * Convert the encoded data to a standard representation. Overridden by some
   * subclasses (e.g. DerBoolean).
   * @return The encoded data as a Blob.
   */
  virtual Blob
  toVal();

  /**
   * Get a copy of the payload bytes.
   * @return A copy of the payload.
   */
  Blob
  getPayload() { return Blob(&payload_[0], payloadPosition_); }

  /**
   * If this object is a DerSequence or DerSet, get the children of this node.
   * Otherwise, throw an exception.
   * (DerSequence and DerSet override to implement this method.)
   * @return The children as an array of shared_ptr<DerNode>.
   * @throws DerDecodingException if this object is not a DerSequence or DerSet.
   */
  virtual const std::vector<ptr_lib::shared_ptr<DerNode> >&
  getChildren();

  class DerStructure;

  ////////
  // Now for all the node types...
  // Class definitions are after the definition of DerNode.
  ////////

  class DerByteString;
  class DerBoolean;
  class DerInteger;
  class DerBitString;
  class DerOctetString;
  class DerNull;
  class DerOid;
  class DerSequence;
  class DerSet;
  class DerUtf8String;
  class DerPrintableString;
  class DerIa5String;
  class DerUtcTime;
  class DerGeneralizedTime;
  class DerExplicit;
  class DerImplicitByteString;

  /**
   * Check that index is in bounds for the children list, cast children[index]
   * to DerSequence and return it.
   * @param children The list of DerNode, usually returned by another
   * call to getChildren.
   * @param index The index of the children.
   * @return children[index] cast to DerSequence.
   * @throws DerDecodingException if index is out of bounds or if
   * children[index] is not a DerSequence.
   */
  static DerNode::DerSequence&
  getSequence
    (const std::vector<ptr_lib::shared_ptr<DerNode> >&children, size_t index);

protected:
  /**
   * Create a generic DER node with the given nodeType. This is a private
   * constructor used by one of the public DerNode subclasses defined below.
   * @param nodeType The DER node type.
   */
  DerNode(DerNodeType nodeType)
  : nodeType_(nodeType),
    parent_(0),
    payload_(0),
    payloadPosition_(0)
  {
  }

  /**
   * Encode the given size and update the header.
   * @param size The size to encode in the header.
   */
  void
  encodeHeader(size_t size);

  /**
   * Extract the header from an input buffer and return the size.
   * @param inputBuf The input buffer to read from.
   * @param startIdx The offset into the buffer.
   * @return The parsed size in the header.
   */
  size_t
  decodeHeader(const uint8_t* inputBuf, size_t inputBufLength, size_t startIdx);

  /**
   * Decode and store the data from an input buffer.
   * @param inputBuf The input buffer to read from. This reads from startIdx.
   * @param startIdx The offset into the buffer.
   */
  virtual void
  decode(const uint8_t* inputBuf, size_t inputBufLength, size_t startIdx);

  /**
   * Call payload_.copy to copy value into payload_ at payloadPosition_. Update
   * payloadPosition_.
   * @param value The buffer to copy from.
   * @param valueLength The length of the value buffer.
   */
  void
  payloadAppend(const uint8_t *value, size_t valueLength)
  {
    payloadPosition_ = payload_.copy(value, valueLength, payloadPosition_);
  }

  DerStructure* parent_;
  DerNodeType nodeType_;
  std::vector<uint8_t> header_;
  DynamicUInt8Vector payload_;
  size_t payloadPosition_;
};

/**
 * A DerStructure extends DerNode to hold other DerNodes.
 */
class DerNode::DerStructure : public DerNode {
public:
  /**
   * Override to get the total length of the encoding, including children.
   * @return The total (header + payload) length.
   */
  virtual size_t
  getSize();

  /**
   * Get the children of this node.
   * @return The children as an array of shared_ptr<DerNode>.
   */
  virtual const std::vector<ptr_lib::shared_ptr<DerNode> >&
  getChildren();

  void
  addChild(const ptr_lib::shared_ptr<DerNode>& node, bool notifyParent = false)
  {
    if (isExplicitNode(nodeType_) && nodeList_.size() >= 1)
      throw std::runtime_error("An explicit node can have only one child");
    node->parent_ = this;
    nodeList_.push_back(node);

    if (notifyParent) {
      if (parent_)
        parent_->setChildChanged();
    }

    childChanged_ = true;
  }

  /**
   * Override the base encode to return raw data encoding for this node and
   * its children.
   * @return The raw data encoding.
   */
  virtual Blob
  encode();

  /**
   * Check if the node type is for an explicit node.
   * @param nodeType The node type byte
   * @return True if for explicit.
   */
  static bool
  isExplicitNode(int nodeType) { return (nodeType & 0xe0) == 0xa0; }

protected:
  /**
   * Create a DerStructure with the given nodeType. This is a protected
   * constructor. To create an object, use DerSequence or DerSet.
   * @param nodeType The DER node type.
   */
  DerStructure(DerNodeType nodeType)
  : DerNode(nodeType),
    childChanged_(false),
    size_(0)
  {
  }

  /**
   * Override the base decode to decode and store the data from an input buffer.
   * Recursively populates child nodes.
   * @param inputBuf The input buffer to read from. This reads from startIdx.
   * @param startIdx The offset into the buffer.
   */
  virtual void
  decode(const uint8_t* inputBuf, size_t inputBufLength, size_t startIdx);

private:
  void
  updateSize();

  /**
   * Mark the child list as dirty, so that we update size when necessary.
   */
  void
  setChildChanged()
  {
    if (parent_)
      parent_->setChildChanged();
    childChanged_ = true;
  }

  bool childChanged_;
  std::vector<ptr_lib::shared_ptr<DerNode> > nodeList_;
  size_t size_;
};

/**
 * A DerByteString extends DerNode to handle byte strings.
 */
class DerNode::DerByteString : public DerNode {
public:
  /**
   * Override to return just the byte string.
   * @return The byte string as a copy of the payload ByteBuffer.
   */
  virtual Blob
  toVal();

protected:
  /**
   * Create a DerByteString with the given inputData and nodeType. This is a
   * protected constructor used by one of the public subclasses such as
   * DerOctetString or DerPrintableString.
   * @param inputData An input buffer containing the string to encode.
   * @param inputDataLength The length of inputData.
   * @param nodeType The specific DER node type.
   */
  DerByteString
    (const uint8_t* inputData, size_t inputDataLength, DerNodeType nodeType)
  : DerNode(nodeType)
  {
    if (inputData) {
      payloadAppend(inputData, inputDataLength);
      encodeHeader(inputDataLength);
    }
  }
};

/**
 * DerBoolean extends DerNode to encode a boolean value.
 * Note: This uses the base class toVal which returns a one-byte Blob, where
 * the boolean value is toVal().buf()[0] != 0 .
 */
class DerNode::DerBoolean : public DerNode {
public:
  /**
   *Create a new DerBoolean for the value.
   * @param value The value to encode.
   */
  DerBoolean(bool value)
  : DerNode(DerNodeType_Boolean)
  {
    uint8_t val = value ? 0xff : 0x00;
    payloadAppend(&val, 1);
    encodeHeader(1);
  }

  DerBoolean()
  : DerNode(DerNodeType_Boolean)
  {
  }
};

/**
 * DerInteger extends DerNode to encode an integer value.
 */
class DerNode::DerInteger : public DerNode {
public:
  /**
   * Create a new DerInteger for the value.
   * @param integer The value to encode.
   */
  DerInteger(int integer);

  /**
   * Create a DerInteger with the given byte array.
   * @param inputData The bytes of the integer.
   * @param inputDataLength The length of inputData.
   * @throws DerEncodingException if the first byte of inputData is >= 0x80.
   * (Negative integers are not supported.)
   */
  DerInteger(const uint8_t* inputData, size_t inputDataLength);

  DerInteger();

  /**
   * Parse the payload as an integer and return the value.  We don't override
   * toVal() because that wants to return a Blob.
   * @return the payload as an integer.
   */
  int
  toIntegerVal() const;
};

/**
 * A DerBitString extends DerNode to handle a bit string.
 */
class DerNode::DerBitString : public DerNode {
public:
  /**
   * Create a DerBitString with the given padding and inputBuf.
   * @param inputBuf An input buffer containing the bit octets to encode.
   * @param inputBufLength The number of bytes in inputBuf.
   * @param paddingLength The number of bits of padding at the end of the bit
   * string.  Should be less than 8.
   */
  DerBitString(const uint8_t* inputBuf, size_t inputBufLength, int paddingLength)
  : DerNode(DerNodeType_BitString)
  {
    uint8_t pad = paddingLength & 0xff;
    payloadAppend(&pad, 1);
    payloadAppend(inputBuf, inputBufLength);
    encodeHeader(payloadPosition_);
  }

  DerBitString()
  : DerNode(DerNodeType_BitString)
  {
  }
};

/**
 * DerOctetString extends DerByteString to encode a string of bytes.
 * @param inputData An input buffer containing the string to encode.
 * @param inputDataLength The length of inputData.
 */
class DerNode::DerOctetString : public DerByteString {
public:
  DerOctetString(const uint8_t* inputData, size_t inputDataLength)
  : DerByteString(inputData, inputDataLength, DerNodeType_OctetString)
  {
  }

  DerOctetString()
  : DerByteString(0, 0, DerNodeType_OctetString)
  {
  }
};

/**
 * A DerNull extends DerNode to encode a null value.
 */
class DerNode::DerNull : public DerNode {
public:
  /**
   * Create a DerNull.
   */
  DerNull()
  : DerNode(DerNodeType_Null)
  {
    encodeHeader(0);
  }
};

/**
 * A DerOid extends DerNode to represent an object identifier
 */
class DerNode::DerOid : public DerNode {
public:
  /**
   * Create a DerOid with the given object identifier. The object identifier
   * string must begin with 0,1, or 2 and must contain at least 2 digits.
   * @param oidStr The OID string to encode.
   */
  DerOid(const std::string& oidStr)
  : DerNode(DerNodeType_ObjectIdentifier)
  {
    // Use OID to construct the integer list.
    OID tempOid(oidStr);
    prepareEncoding(tempOid.getIntegerList());
  }

  /**
   * Create a DerOid with the given object identifier. The object identifier
   * string must begin with 0,1, or 2 and must contain at least 2 digits.
   * @param oid The OID string to encode.
   */
  DerOid(const OID& oid)
  : DerNode(DerNodeType_ObjectIdentifier)
  {
    prepareEncoding(oid.getIntegerList());
  }

  DerOid()
  : DerNode(DerNodeType_ObjectIdentifier)
  {
  }

  /**
   * Override to return the string representation of the OID.
   * @return The string representation of the OID as bytes in a Blob.
   */
  virtual Blob
  toVal();

private:
  /**
   * Encode a sequence of integers into an OID object and set the payload.
   * @param value The vector of integers.
   */
  void
  prepareEncoding(const std::vector<int>& value);

  /**
   * Compute the encoding for one part of an OID, where values greater than 128
   * must be encoded as multiple bytes.
   * @param value A component of an OID.
   * @return The encoded buffer.
   */
  static std::vector<uint8_t>
  encode128(int value);

  /**
   * Convert an encoded component of the encoded OID to the original integer.
   * @param offset The offset into this node's payload.
   * @param skip Set skip to the number of payload bytes to skip.
   * @return The original integer.
   */
  int
  decode128(size_t offset, size_t& skip);
};

class DerNode::DerSequence : public DerStructure {
public:
  /**
   * Create a DerSequence.
   */
  DerSequence()
  : DerStructure(DerNodeType_Sequence)
  {
  }
};

class DerNode::DerSet : public DerStructure {
public:
  /**
   * Create a DerSet.
   */
  DerSet()
  : DerStructure(DerNodeType_Set)
  {
  }
};

/**
 * A DerUtf8String extends DerByteString to handle a a printable string. No
 * escaping or other modification is done to the string.
 * @param inputData An input buffer containing the string to encode.
 * @param inputDataLength The length of inputData.
 */
class DerNode::DerUtf8String : public DerByteString {
public:
  DerUtf8String(const uint8_t* inputData, size_t inputDataLength)
  : DerByteString(inputData, inputDataLength, DerNodeType_Utf8String)
  {
  }

  DerUtf8String()
  : DerByteString(0, 0, DerNodeType_Utf8String)
  {
  }
};

/**
 * A DerPrintableString extends DerByteString to handle a a printable string. No
 * escaping or other modification is done to the string.
 * @param inputData An input buffer containing the string to encode.
 * @param inputDataLength The length of inputData.
 */
class DerNode::DerPrintableString : public DerByteString {
public:
  DerPrintableString(const uint8_t* inputData, size_t inputDataLength)
  : DerByteString(inputData, inputDataLength, DerNodeType_PrintableString)
  {
  }

  DerPrintableString()
  : DerByteString(0, 0, DerNodeType_PrintableString)
  {
  }
};

/**
 * A DerIa5String extends DerByteString to handle an IA5 string.
 * @param inputData An input buffer containing the string to encode.
 * @param inputDataLength The length of inputData.
 */
class DerNode::DerIa5String : public DerByteString {
public:
  DerIa5String(const uint8_t* inputData, size_t inputDataLength)
  : DerByteString(inputData, inputDataLength, DerNodeType_Ia5String)
  {
  }

  DerIa5String()
  : DerByteString(0, 0, DerNodeType_Ia5String)
  {
  }
};

/**
 * A DerUtcTime extends DerNode to represent a date and time in UTC format.
 */
class DerNode::DerUtcTime : public DerNode {
public:
  /**
   * Create a DerUtcTime with the given time.
   * @param time The time.
   */
  DerUtcTime(std::chrono::system_clock::time_point time)
  : DerNode(DerNodeType_UtcTime)
  {
    std::string derTime = toUtcTimeString(time);
    payloadAppend((const uint8_t*)&derTime[0], derTime.size());
    encodeHeader(payloadPosition_);
  }

  DerUtcTime()
  : DerNode(DerNodeType_UtcTime)
  {
  }

  /**
   * Interpret the result of toVal() as a time string and return the time.
   * @return The time.
   */
  std::chrono::system_clock::time_point
  toTimePoint();

private:
  /**
   * Convert a UNIX timestamp to the internal string representation.
   * @param time The time.
   * @return The string representation.
   */
  static std::string
  toUtcTimeString(std::chrono::system_clock::time_point time);
};

/**
 * A DerGeneralizedTime extends DerNode to represent a date and time, with
 * millisecond accuracy.
 */
class DerNode::DerGeneralizedTime : public DerNode {
public:
  /**
   * Create a DerGeneralizedTime with the given time.
   * @param time The time.
   */
  DerGeneralizedTime(std::chrono::system_clock::time_point time)
  : DerNode(DerNodeType_GeneralizedTime)
  {
    std::string derTime = toDerTimeString(time);
    payloadAppend((const uint8_t*)&derTime[0], derTime.size());
    encodeHeader(payloadPosition_);
  }

  DerGeneralizedTime()
  : DerNode(DerNodeType_GeneralizedTime)
  {
  }

  /**
   * Interpret the result of toVal() as a time string and return the time.
   * @return The time.
   */
  std::chrono::system_clock::time_point
  toMillisecondsSince1970();

private:
  /**
   * Convert a UNIX timestamp to the internal string representation.
   * @param time The time.
   * @return The string representation.
   */
  static std::string
  toDerTimeString(std::chrono::system_clock::time_point time);
};

/**
 * A DerExplicit is a structure with a specific tag and holds one child.
 */
class DerNode::DerExplicit : public DerStructure {
public:
  /**
   * Create a DerExplicit with the given tag.
   * @param tag The tag which must be less than or equal to 0x1f.
   * @throws DerDecodingException if the tag is not less than or equal to 0x1f.
   */
  DerExplicit(int tag);

  /**
   * Get the tag part of the node type.
   * @return The tag.
   */
  int
  getTag() { return nodeType_ & 0x1f; }
};

/**
 * DerImplicitByteString extends DerByteString to encode a string of bytes using
 * an IMPLICIT node type.
 */
class DerNode::DerImplicitByteString : public DerByteString {
public:
  /**
   * Create a DerImplicitByteString with the input value.
   * @param inputData An input buffer containing the bytes to encode.
   * @param inputDataLength The length of inputData.
   * @param type The value of the DER type, for example 0x81 . It is an error if
   * bit 6 is set (meaning a structured type) or if bits 7 and 8 are zero (not
   * an implicit tag).
   */
  DerImplicitByteString
    (const uint8_t* inputData, size_t inputDataLength, int type)
  : DerByteString(inputData, inputDataLength, (DerNodeType)type)
  {
    if (!isImplicit(type))
      throw std::runtime_error
        ("DerImplicitByteString: The type is not for a non-structured IMPLICIT value");
  }

  DerImplicitByteString(int type)
  : DerByteString(0, 0, (DerNodeType)type)
  {
    if (!isImplicit(type))
      throw std::runtime_error
        ("DerImplicitByteString: The type is not for a non-structured IMPLICIT value");
  }

  /**
   * Get the value of the DER type.
   * @return The value of the DER type, for example 0x81.
   */
  int
  getType() { return (int)nodeType_; }

  /**
   * Check if the type code is for a non-structured IMPLICIT value.
   * @param type The type code.
   * @return True if for non-structured IMPLICIT value.
   */
  static bool
  isImplicit(int type)
  {
    return (type & 0x20) == 0 && (type & 0xc0) != 0;
  }
};

}

#endif

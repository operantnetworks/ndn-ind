/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/digest-sha256-signature.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
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
#include <ndn-ind/digest-sha256-signature.hpp>

using namespace std;

namespace ndn {

ptr_lib::shared_ptr<Signature>
DigestSha256Signature::clone() const
{
  return ptr_lib::shared_ptr<Signature>(new DigestSha256Signature(*this));
}

const Blob&
DigestSha256Signature::getSignature() const
{
  return signature_;
}

void
DigestSha256Signature::setSignature(const Blob& signature)
{
  signature_ = signature;
  ++changeCount_;
}

void
DigestSha256Signature::get(SignatureLite& signatureLite) const
{
  // Initialize unused fields.
  signatureLite.clear();

  signatureLite.setType(ndn_SignatureType_DigestSha256Signature);
  signatureLite.setSignature(signature_);
}

void
DigestSha256Signature::set(const SignatureLite& signatureLite)
{
  // The caller should already have checked the type, but check again.
  if (signatureLite.getType() != ndn_SignatureType_DigestSha256Signature)
    throw runtime_error("signatureLite is not the expected type DigestSha256Signature");

  setSignature(Blob(signatureLite.getSignature()));
}

uint64_t
DigestSha256Signature::getChangeCount() const
{
  return changeCount_;
}

}

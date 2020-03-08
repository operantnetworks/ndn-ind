/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/lite/encrypt/algo/aes-algorithm-lite.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
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

#include "../../../c/encrypt/algo/des-algorithm.h"
#include <ndn-ind/lite/encrypt/algo/des-algorithm-lite.hpp>

#if NDN_IND_HAVE_LIBCRYPTO

namespace ndn {

ndn_Error
DesAlgorithmLite::decryptEdeCbcPkcs5Padding
  (const uint8_t* key, size_t keyLength, const uint8_t* initialVector,
   size_t initialVectorLength, const uint8_t* encryptedData,
   size_t encryptedDataLength, uint8_t* plainData, size_t& plainDataLength)
{
  return ndn_DesAlgorithm_decryptEdeCbcPkcs5Padding
    (key, keyLength, initialVector, initialVectorLength, encryptedData,
     encryptedDataLength, plainData, &plainDataLength);
}

ndn_Error
DesAlgorithmLite::encryptEdeCbcPkcs5Padding
  (const uint8_t* key, size_t keyLength, const uint8_t* initialVector,
   size_t initialVectorLength, const uint8_t* plainData,
   size_t plainDataLength, uint8_t* encryptedData, size_t& encryptedDataLength)
{
  return ndn_DesAlgorithm_encryptEdeCbcPkcs5Padding
    (key, keyLength, initialVector, initialVectorLength, plainData,
     plainDataLength, encryptedData, &encryptedDataLength);
}

}

#endif // NDN_IND_HAVE_LIBCRYPTO

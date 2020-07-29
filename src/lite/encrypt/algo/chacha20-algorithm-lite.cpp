/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
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

#include "../../../c/encrypt/algo/chacha20-algorithm.h"
#include <ndn-ind/lite/encrypt/algo/chacha20-algorithm-lite.hpp>

#if NDN_IND_HAVE_LIBCRYPTO

namespace ndn {

ndn_Error
ChaCha20AlgorithmLite::decryptPoly1305
  (const uint8_t* key, size_t keyLength, const uint8_t* nonce,
   size_t nonceLength, const uint8_t* encryptedData, size_t encryptedDataLength,
   const uint8_t *associatedData, size_t associatedDataLength,
   uint8_t* plainData, size_t& plainDataLength)
{
  return ndn_ChaCha20Algorithm_decryptPoly1305
    (key, keyLength, nonce, nonceLength, encryptedData, encryptedDataLength,
     associatedData, associatedDataLength, plainData, &plainDataLength);
}

ndn_Error
ChaCha20AlgorithmLite::encryptPoly1305
  (const uint8_t* key, size_t keyLength, const uint8_t* nonce,
   size_t nonceLength, const uint8_t* plainData, size_t plainDataLength,
   const uint8_t *associatedData, size_t associatedDataLength,
   uint8_t* encryptedData, size_t& encryptedDataLength)
{
  return ndn_ChaCha20Algorithm_encryptPoly1305
    (key, keyLength, nonce, nonceLength, plainData, plainDataLength,
     associatedData, associatedDataLength, encryptedData, &encryptedDataLength);
}

}

#endif // NDN_IND_HAVE_LIBCRYPTO

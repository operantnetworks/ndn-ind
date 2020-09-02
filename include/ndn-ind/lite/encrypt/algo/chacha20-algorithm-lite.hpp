/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Regents of the University of California.
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

#ifndef NDN_CHACHA20_ALGORITHM_LITE_HPP
#define NDN_CHACHA20_ALGORITHM_LITE_HPP

#include "../../util/blob-lite.hpp"
#include "../../../c/errors.h"

namespace ndn {

/**
 * The ChaCha20AlgorithmLite class provides static methods to encrypt and decrypt
 * using the ChaCha20-Poly1305 symmetric key cipher.
 * @note This class is an experimental feature. The API may change.
 */
class ChaCha20AlgorithmLite {
public:
  /**
   * Use the key to decrypt encryptedData using ChaCha20-Poly1305.
   * @param key A pointer to the key byte array.
   * @param keyLength The length of key. It is an error if this is not
   * ndn_CHACHA20_KEY_LENGTH. This value is proved as a safety check that the
   * correct algorithm is being used.
   * @param nonce A pointer to the nonce byte array (also referred to as the
   * initial vector).
   * @param nonceLength The length of nonce. It is an error if this is not
   * ndn_CHACHA20_NONCE_LENGTH. This value is proved as a safety check that the
   * correct algorithm is being used.
   * @param encryptedData A pointer to the input byte array to decrypt.
   * @param encryptedDataLength The length of encryptedData.
   * @param associatedData A pointer to the associated data which is included in
   * the calculation of the authentication tag, but is not decrypted. If
   * associatedDataLength is 0, then this can be NULL.
   * @param associatedDataLength The length of associatedData.
   * @param plainData A pointer to the decrypted output buffer. The caller
   * must provide a large enough buffer, which should be at least
   * encryptedDataLength bytes.
   * @param plainDataLength This sets plainDataLength to the number of bytes
   * placed in the plainData buffer.
   * @return 0 for success, else NDN_ERROR_Incorrect_key_size for incorrect
   * keyLength or NDN_ERROR_Incorrect_initial_vector_size for incorrect
   * nonceLength.
   */
  static ndn_Error
  decryptPoly1305
    (const uint8_t* key, size_t keyLength, const uint8_t* nonce,
     size_t nonceLength, const uint8_t* encryptedData,
     size_t encryptedDataLength, const uint8_t *associatedData,
     size_t associatedDataLength, uint8_t* plainData, size_t& plainDataLength);

  /**
   * Use the key to decrypt encryptedData using AES 256 in CBC mode.
   * @param key The key byte array. It is an error if its size is not
   * ndn_CHACHA20_KEY_LENGTH. This value is proved as a safety check that the
   * correct algorithm is being used.
   * @param nonce The the nonce byte array (also referred to as the initial
   * vector). It is an error if its size is not ndn_CHACHA20_NONCE_LENGTH. This
   * value is proved as a safety check that the correct algorithm is being used.
   * @param encryptedData The input byte array to decrypt.
   * @param associatedData The associated data which is included in the
   * calculation of the authentication tag, but is not decrypted. If
   * associatedData.size() is 0, then this can be an isNull() Blob.
   * @param associatedDataLength The length of associatedData.
   * @param plainData A pointer to the decrypted output buffer. The caller
   * must provide a large enough buffer, which should be at least
   * encryptedData.size() bytes.
   * @param plainDataLength This sets plainDataLength to the number of bytes
   * placed in the plainData buffer.
   * @return 0 for success, else NDN_ERROR_Incorrect_key_size for incorrect
   * key.size() or NDN_ERROR_Incorrect_initial_vector_size for incorrect
   * nonce.size().
   */
  static ndn_Error
  decryptPoly1305
    (const BlobLite& key, const BlobLite& nonce, const BlobLite& encryptedData,
     const BlobLite& associatedData, uint8_t *plainData, size_t& plainDataLength)
  {
    return decryptPoly1305
      (key.buf(), key.size(), nonce.buf(), nonce.size(), encryptedData.buf(),
       encryptedData.size(), associatedData.buf(), associatedData.size(),
       plainData, plainDataLength);
  }

  /**
   * Use the key to encrypt plainData using ChaCha20-Poly1305.
   * @param key A pointer to the key byte array.
   * @param keyLength The length of key. It is an error if this is not
   * ndn_CHACHA20_KEY_LENGTH. This value is proved as a safety check that the
   * correct algorithm is being used.
   * @param nonce A pointer to the nonce byte array (also referred to as the
   * initial vector).
   * @param nonceLength The length of nonce. It is an error if this is not
   * ndn_CHACHA20_NONCE_LENGTH. This value is proved as a safety check that the
   * correct algorithm is being used.
   * @param plainData A pointer to the input byte array to encrypt.
   * @param plainDataLength The length of plainData.
   * @param associatedData A pointer to the associated data which is included in
   * the calculation of the authentication tag, but is not encrypted. If
   * associatedDataLength is 0, then this can be NULL.
   * @param associatedDataLength The length of associatedData.
   * @param encryptedData A pointer to the encrypted output buffer. The caller
   * must provide a large enough buffer, which should be at least
   * plainDataLength + ndn_POLY1305_BLOCK_LENGTH bytes. (The
   * ndn_POLY1305_BLOCK_LENGTH bytes are for the authentication tag. There are
   * no padding bytes.)
   * @param encryptedDataLength This sets encryptedDataLength to the number of
   * bytes placed in the encryptedData buffer.
   * @return 0 for success, else NDN_ERROR_Incorrect_key_size for incorrect
   * keyLength or NDN_ERROR_Incorrect_initial_vector_size for incorrect
   * nonceLength.
   */
  static ndn_Error
  encryptPoly1305
    (const uint8_t* key, size_t keyLength, const uint8_t* nonce,
     size_t nonceLength, const uint8_t* plainData, size_t plainDataLength,
     const uint8_t *associatedData, size_t associatedDataLength,
     uint8_t* encryptedData, size_t& encryptedDataLength);

  /**
   * Use the key to encrypt plainData using ChaCha20-Poly1305.
   * @param key The key byte array. It is an error if its size is not
   * ndn_CHACHA20_KEY_LENGTH. This value is proved as a safety check that the
   * correct algorithm is being used.
   * @param nonce The the nonce byte array (also referred to as the initial
   * vector). It is an error if its size is not ndn_CHACHA20_NONCE_LENGTH. This
   * value is proved as a safety check that the correct algorithm is being used.
   * @param plainData The input byte array to encrypt.
   * @param associatedData The associated data which is included in the
   * calculation of the authentication tag, but is not encrypted. If
   * associatedData.size() is 0, then this can be an isNull() Blob.
   * @param associatedDataLength The length of associatedData.
   * @param encryptedData A pointer to the encrypted output buffer. The caller
   * must provide a large enough buffer, which should be at least
   * plainData.size() + ndn_POLY1305_BLOCK_LENGTH bytes. (The
   * ndn_POLY1305_BLOCK_LENGTH bytes are for the authentication tag. There are
   * no padding bytes.)
   * @param encryptedDataLength This sets encryptedDataLength to the number of
   * bytes placed in the encryptedData buffer.
   * @return 0 for success, else NDN_ERROR_Incorrect_key_size for incorrect
   * key.size() or NDN_ERROR_Incorrect_initial_vector_size for incorrect
   * nonce.size().
   */
  static ndn_Error
  encryptPoly1305
    (const BlobLite& key, const BlobLite& nonce, const BlobLite& plainData,
     const BlobLite& associatedData, uint8_t *encryptedData,
     size_t& encryptedDataLength)
  {
    return encryptPoly1305
      (key.buf(), key.size(), nonce.buf(), nonce.size(),
       plainData.buf(), plainData.size(), associatedData.buf(),
       associatedData.size(), encryptedData, encryptedDataLength);
  }
};

}

#endif

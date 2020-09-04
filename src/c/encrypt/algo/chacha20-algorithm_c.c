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

#include "../../util/crypto.h"
#include "chacha20-algorithm.h"

#if NDN_IND_HAVE_LIBCRYPTO_1_1

#include <openssl/evp.h>

ndn_Error
ndn_ChaCha20Algorithm_decryptPoly1305
  (const uint8_t *key, size_t keyLength, const uint8_t *nonce,
   size_t nonceLength, const uint8_t *encryptedData, size_t encryptedDataLength,
   const uint8_t *associatedData, size_t associatedDataLength,
   uint8_t *plainData, size_t *plainDataLength)
{
  EVP_CIPHER_CTX *ctx;
  int outLength1, outLength2, dummyOutLength, finalStatus;

  if (keyLength != ndn_CHACHA20_KEY_LENGTH)
    return NDN_ERROR_Incorrect_key_size;
  if (nonceLength != ndn_CHACHA20_NONCE_LENGTH)
    return NDN_ERROR_Incorrect_initial_vector_size;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return NDN_ERROR_Error_in_decrypt_operation;

  EVP_DecryptInit
    (ctx, EVP_chacha20_poly1305(), (const unsigned char*)key,
     (const unsigned char*)nonce);

  // Specify the associated data.
  EVP_DecryptUpdate
    (ctx, NULL, &dummyOutLength, associatedData, associatedDataLength);

  // Subtract the tag length.
  if (encryptedDataLength < ndn_POLY1305_BLOCK_LENGTH)
    // (We don't expect this to happen.)
    return NDN_ERROR_Error_in_decrypt_operation;
  EVP_DecryptUpdate
    (ctx, (unsigned char*)plainData, &outLength1,
     (const unsigned char*)encryptedData, encryptedDataLength - 
      ndn_POLY1305_BLOCK_LENGTH);

  // Set the expected tag value.
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ndn_POLY1305_BLOCK_LENGTH,
    (unsigned char*)(encryptedData + encryptedDataLength - ndn_POLY1305_BLOCK_LENGTH));
  finalStatus = EVP_DecryptFinal
    (ctx, (unsigned char*)plainData + outLength1, &outLength2);

  EVP_CIPHER_CTX_free(ctx);
  *plainDataLength = outLength1 + outLength2;

  return finalStatus > 0 ? NDN_ERROR_success : NDN_ERROR_Error_in_decrypt_operation;
}

ndn_Error
ndn_ChaCha20Algorithm_encryptPoly1305
  (const uint8_t *key, size_t keyLength, const uint8_t *nonce,
   size_t nonceLength, const uint8_t *plainData, size_t plainDataLength,
   const uint8_t *associatedData, size_t associatedDataLength,
   uint8_t *encryptedData, size_t *encryptedDataLength)
{
  EVP_CIPHER_CTX *ctx;
  int outLength1, outLength2, dummyOutLength;

  if (keyLength != ndn_CHACHA20_KEY_LENGTH)
    return NDN_ERROR_Incorrect_key_size;
  if (nonceLength != ndn_CHACHA20_NONCE_LENGTH)
    return NDN_ERROR_Incorrect_initial_vector_size;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return NDN_ERROR_Error_in_encrypt_operation;

  EVP_EncryptInit
    (ctx, EVP_chacha20_poly1305(), (const unsigned char*)key,
     (const unsigned char*)nonce);

  // Specify the associated data.
  EVP_EncryptUpdate
    (ctx, NULL, &dummyOutLength, associatedData, associatedDataLength);

  EVP_EncryptUpdate
    (ctx, (unsigned char*)encryptedData, &outLength1,
     (const unsigned char*)plainData, plainDataLength);

  // Since there is no padding. we expect outLength2 to be zero. But use it anyway.
  EVP_EncryptFinal
    (ctx, (unsigned char*)encryptedData + outLength1, &outLength2);

  unsigned char tag[ndn_POLY1305_BLOCK_LENGTH];
  // Get the tag.
  EVP_CIPHER_CTX_ctrl
    (ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag),
     (unsigned char*)encryptedData + outLength1 + outLength2);

  EVP_CIPHER_CTX_free(ctx);
  *encryptedDataLength = outLength1 + outLength2 + sizeof(tag);

  return NDN_ERROR_success;
}

#else // NDN_IND_HAVE_LIBCRYPTO_1_1

ndn_Error
ndn_ChaCha20Algorithm_decryptPoly1305
  (const uint8_t *key, size_t keyLength, const uint8_t *nonce,
   size_t nonceLength, const uint8_t *encryptedData, size_t encryptedDataLength,
   const uint8_t *associatedData, size_t associatedDataLength,
   uint8_t *plainData, size_t *plainDataLength)
{
  // ./configure didn't find OpenSSL 1.1+.
  return NDN_ERROR_Unsupported_algorithm_type;
}

ndn_Error
ndn_ChaCha20Algorithm_encryptPoly1305
  (const uint8_t *key, size_t keyLength, const uint8_t *nonce,
   size_t nonceLength, const uint8_t *plainData, size_t plainDataLength,
   const uint8_t *associatedData, size_t associatedDataLength,
   uint8_t *encryptedData, size_t *encryptedDataLength)
{
  // ./configure didn't find OpenSSL 1.1+.
  NDN_ERROR_Unsupported_algorithm_type;
}

#endif // NDN_IND_HAVE_LIBCRYPTO_1_1

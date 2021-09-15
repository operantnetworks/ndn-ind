/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/c/common.h
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2013-2020 Regents of the University of California.
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

#ifndef NDN_COMMON_H
#define NDN_COMMON_H

#include "../ndn-ind-config.h"
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
  #ifdef NDN_IND_EXPORTS
    #define ndn_ind_dll __declspec(dllexport)
  #else
    #define ndn_ind_dll __declspec(dllimport)
  #endif
#else
  #define ndn_ind_dll
#endif

#if defined(_WIN32)
#ifdef NDN_IND_TOOLS_EXPORTS
#define ndn_ind_tools_dll __declspec(dllexport)
#else
#define ndn_ind_tools_dll __declspec(dllimport)
#endif
#else
#define ndn_ind_tools_dll
#endif

#if NDN_IND_HAVE_ATTRIBUTE_DEPRECATED
  #define DEPRECATED_IN_NDN_IND __attribute__((deprecated))
#else
  #define DEPRECATED_IN_NDN_IND
#endif

#if !NDN_IND_HAVE_ROUND
#define round(x) floor((x) + 0.5)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A time interval represented as the number of milliseconds.
 */
typedef double ndn_Milliseconds;

/**
 * The calendar time represented as the number of milliseconds since 1/1/1970.
 */
typedef double ndn_MillisecondsSince1970;

/**
 * Get the current time in milliseconds.
 * @return The current time in milliseconds since 1/1/1970 UTC, including
 * fractions of a millisecond (according to timeval.tv_usec).
 */
ndn_ind_dll ndn_MillisecondsSince1970
ndn_getNowMilliseconds();

/**
 * The practical limit of the size of a network-layer packet. If a packet is
 * larger than this, the library or application MAY drop it. This constant is
 * defined in this low-level header file so that internal code can use it, but
 * applications should use the static inline API method
 * Face::getMaxNdnPacketSize() which is equivalent.
 */
enum { MAX_NDN_PACKET_SIZE = 8800 };

/**
 * The size in bytes of a SHA-256 digest. We define this separately so that we
 * don't have to include the openssl header everywhere.
 */
enum { ndn_SHA256_DIGEST_SIZE = 32 };

/**
 * The block size in bytes for the AES algorithm. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_AES_BLOCK_LENGTH = 16 };

/**
 * The key size in bytes for the AES 128 algorithm. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_AES_128_KEY_LENGTH = 16 };

/**
 * The key size in bytes for the AES 256 algorithm. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_AES_256_KEY_LENGTH = 32 };

/**
 * The key size in bytes for the DES EDE3 algorithm. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_DES_EDE3_KEY_LENGTH = 24 };

/**
 * The block size in bytes for the DES algorithm. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_DES_BLOCK_LENGTH = 8 };

/**
 * The size in bytes of a Poly1305 block (and of the ChaCha20-Poly1305 tag). We
 * define this separately so that we don't have to include the openssl header
 * everywhere.
 */
enum { ndn_POLY1305_BLOCK_LENGTH = 16 };

/**
 * The key size in bytes for the ChaCha20 algorithm. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_CHACHA20_KEY_LENGTH = 32 };

/**
 * The key size in bytes for the ChaCha20 nonce. We define this separately
 * so that we don't have to include the openssl header everywhere.
 */
enum { ndn_CHACHA20_NONCE_LENGTH = 12 };

#ifdef __cplusplus
}
#endif

#endif

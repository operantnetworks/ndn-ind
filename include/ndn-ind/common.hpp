/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
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

#ifndef NDN_COMMON_HPP
#define NDN_COMMON_HPP

#include <vector>
#include <string>
#include <sstream>
#include <chrono>
// common.h includes ndn-ind-config.h.
#include "c/common.h"

// Depending on where ./configure found shared_ptr and the options --with-std-shared-ptr
//   and --with-boost-shared-ptr, define the ptr_lib namespace.
// We always use ndn::ptr_lib.
#if NDN_IND_HAVE_STD_SHARED_PTR && NDN_IND_WITH_STD_SHARED_PTR
#include <memory>
namespace ndn { namespace ptr_lib = std; }
#elif NDN_IND_HAVE_BOOST_SHARED_PTR && NDN_IND_WITH_BOOST_SHARED_PTR
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/enable_shared_from_this.hpp>
namespace ndn { namespace ptr_lib = boost; }
#else
#error You cannot ./configure with both --with-std-shared-ptr=no and --with-boost-shared-ptr=no
#endif

// Depending on where ./configure found function and the options --with-std-function
//   and --with-boost-function, define the func_lib namespace.
// We always use ndn::func_lib.
#if NDN_IND_HAVE_STD_FUNCTION && NDN_IND_WITH_STD_FUNCTION
#include <functional>
// Define the func_lib namespace explicitly to pull in _1, _2, etc.
namespace ndn { namespace func_lib {
  using std::function;
  using std::mem_fn;
  using std::bind;
  using std::ref;

  using std::placeholders::_1;
  using std::placeholders::_2;
  using std::placeholders::_3;
  using std::placeholders::_4;
  using std::placeholders::_5;
  using std::placeholders::_6;
  using std::placeholders::_7;
  using std::placeholders::_8;
  using std::placeholders::_9;

  // Define this namespace for backwards compatibility with code that pulls in _1, etc. with:
  // using namespace ndn::func_lib::placeholders;
  namespace placeholders {}
} }
#elif NDN_IND_HAVE_BOOST_FUNCTION && NDN_IND_WITH_BOOST_FUNCTION
#include <boost/function.hpp>
#include <boost/bind.hpp>
namespace ndn { namespace func_lib = boost; }
#else
#error You cannot ./configure with both --with-std-function=no and --with-boost-function=no
#endif

namespace ndn {

/**
 * A time interval represented as the number of milliseconds.
 */
typedef double Milliseconds;

/**
 * Write the hex representation of the bytes in array to the result.
 * @param array The array of bytes.
 * @param arrayLength The number of bytes in array.
 * @param result The output stream to write to.
 */
void
toHex(const uint8_t* array, size_t arrayLength, std::ostringstream& result);

/**
 * Write the hex representation of the bytes in array to the result.
 * @param array The array of bytes.
 * @param result The output stream to write to.
 */
static __inline void
toHex(const std::vector<uint8_t>& array, std::ostringstream& result)
{
  return toHex(&array[0], array.size(), result);
}

/**
 * Return the hex representation of the bytes in array.
 * @param array The array of bytes.
 * @param arrayLength The number of bytes in array.
 * @return The hex string.
 */
std::string
toHex(const uint8_t* array, size_t arrayLength);

/**
 * Return the hex representation of the bytes in array.
 * @param array The array of bytes.
 * @return The hex string.
 */
static __inline std::string
toHex(const std::vector<uint8_t>& array)
{
  return toHex(&array[0], array.size());
}

/**
 * Modify str in place to erase whitespace on the left and right.
 * @param str The string to modify.
 */
void
ndn_trim(std::string& str);

/**
 * Compare the strings for equality, ignoring case.
 * @param s1 The first string to compare.
 * @param s2 The second string to compare.
 * @return True if the strings are equal, ignoring case.
 */
bool
equalsIgnoreCase(const std::string& s1, const std::string& s2);

/**
 * Convert the system_clock::time_point to a double value of the number of
 * milliseconds since the epoch (January 1, 1970). This is needed because
 * lower-level functions don't use std::chrono.
 * @param t The system_clock::time_point.
 * @return Milliseconds since the epoch, which may have fractions of a millisecond.
 */
static __inline double
toMillisecondsSince1970(std::chrono::system_clock::time_point t)
{
  // Use nanoseconds so that we can get fractions of a millisecond.
  return 1e-6 * (double)std::chrono::duration_cast<std::chrono::nanoseconds>
    (t.time_since_epoch()).count();
}

/**
 * Convert the double value of the number of milliseconds since the epoch to a
 * system_clock::time_point. This is needed because lower-level functions don't
 * use std::chrono.
 * @param ms Milliseconds since the epoch, which may have fractions of a millisecond.
 * @return The system_clock::time_point time.
 */
static __inline std::chrono::system_clock::time_point
fromMillisecondsSince1970(double ms)
{
  // Use nanoseconds so that we can get fractions of a millisecond.
  return std::chrono::system_clock::time_point
    (std::chrono::duration_cast<std::chrono::system_clock::duration>
     (std::chrono::nanoseconds((int64_t)(ms * 1e6))));
}

}

#endif

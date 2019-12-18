/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST.
#include <ndn-ind/ndn-ind-config.h>
#ifdef NDN_IND_HAVE_BOOST

#include <ndn-ind/util/time.hpp>

#include <sstream>

namespace ndn {
namespace time {

using std::shared_ptr;
using namespace std::chrono;

/////////////////////////////////////////////////////////////////////////////////////////////

system_clock::time_point
system_clock::now() noexcept
{
  return time_point(std::chrono::system_clock::now().time_since_epoch());
}

std::time_t
system_clock::to_time_t(const system_clock::time_point& t) noexcept
{
  return duration_cast<seconds>(t.time_since_epoch()).count();
}

system_clock::time_point
system_clock::from_time_t(std::time_t t) noexcept
{
  return time_point(seconds(t));
}

/////////////////////////////////////////////////////////////////////////////////////////////

#ifdef __APPLE__
// Note that on macOS platform std::chrono::steady_clock is not truly monotonic, so we use
// system_clock instead.  Refer to https://svn.boost.org/trac/boost/ticket/7719)
typedef std::chrono::system_clock base_steady_clock;
#else
typedef std::chrono::steady_clock base_steady_clock;
#endif

steady_clock::time_point
steady_clock::now() noexcept
{
  return time_point(base_steady_clock::now().time_since_epoch());
}

/////////////////////////////////////////////////////////////////////////////////////////////

const system_clock::TimePoint&
getUnixEpoch()
{
  static constexpr system_clock::TimePoint epoch(seconds::zero());
  return epoch;
}

} // namespace time
} // namespace ndn

#endif // NDN_IND_HAVE_BOOST

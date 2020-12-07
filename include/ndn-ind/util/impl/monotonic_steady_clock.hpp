/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: ndn-cxx/util/time.hpp
 * Original repository: https://github.com/named-data/ndn-cxx
 *
 * Summary of Changes: Rename steady_clock to MonotonicSteadyClock. Remove other unused code.
 *   Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (c) 2013-2020 Regents of the University of California.
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

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST_ASIO.
#include "../../ndn-ind-config.h"
#ifdef NDN_IND_HAVE_BOOST_ASIO

#ifndef NDN_UTIL_TIME_HPP
#define NDN_UTIL_TIME_HPP

#include <chrono>

namespace ndn {
namespace scheduler {

/**
 * MonotonicSteadyClock represents a monotonic clock. The time points of this
 * clock cannot decrease as physical time moves forward. This clock is
 * not related to wall clock time, and is best suitable for measuring
 * intervals.
 * On most systems, this is the same as std::chrono::stead_clock. But on macOS,
 * we need to override the behavior of now() so that it is monotonic.
 */
class ndn_ind_dll MonotonicSteadyClock
{
public:
  using duration   = std::chrono::steady_clock::duration;
  using rep        = duration::rep;
  using period     = duration::period;
  using time_point = std::chrono::time_point<MonotonicSteadyClock>;
  static constexpr bool is_steady = true;

  typedef time_point TimePoint;
  typedef duration Duration;

  static time_point
  now() noexcept
  {
#ifdef __APPLE__
// Note that on macOS platform std::chrono::steady_clock is not truly monotonic, so we use
// system_clock instead.  Refer to https://svn.boost.org/trac/boost/ticket/7719)
    return time_point(std::chrono::system_clock::now().time_since_epoch());
#else
    return time_point(std::chrono::steady_clock::now().time_since_epoch());
#endif
  }
};

} // namespace scheduler
} // namespace ndn

#endif // NDN_UTIL_TIME_HPP

#endif // NDN_IND_HAVE_BOOST_ASIO

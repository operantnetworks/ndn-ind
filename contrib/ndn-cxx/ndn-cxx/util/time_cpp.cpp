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

namespace ndn {
namespace time {

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

} // namespace time
} // namespace ndn

#endif // NDN_IND_HAVE_BOOST

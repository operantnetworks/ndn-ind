/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: ndn-cxx/util/impl/steady-timer.hpp
 * Original repository: https://github.com/named-data/ndn-cxx
 *
 * Summary of Changes: Conditional compile on NDN_IND_HAVE_BOOST_ASIO. Use base class MonotonicSteadyClock.
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

#ifndef NDN_UTIL_IMPL_STEADY_TIMER_HPP
#define NDN_UTIL_IMPL_STEADY_TIMER_HPP

#include "monotonic_steady_clock.hpp"

#include <boost/asio/basic_waitable_timer.hpp>

namespace ndn {
namespace scheduler {

class ndn_ind_dll SteadyTimer : public boost::asio::basic_waitable_timer<MonotonicSteadyClock>
{
public:
  using boost::asio::basic_waitable_timer<MonotonicSteadyClock>::basic_waitable_timer;
};

} // namespace scheduler
} // namespace ndn

#endif // NDN_UTIL_IMPL_STEADY_TIMER_HPP

#endif // NDN_IND_HAVE_BOOST_ASIO

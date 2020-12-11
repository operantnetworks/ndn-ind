/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: ndn-cxx/detail/cancel-handle.cpp
 * Original repository: https://github.com/named-data/ndn-cxx
 *
 * Summary of Changes: Conditional compile on NDN_IND_HAVE_BOOST_ASIO. Added ScopedCancelHandle.
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

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST.
#include "../../ndn-ind-config.h"
#ifdef NDN_IND_HAVE_BOOST

#ifndef NDN_DETAIL_CANCEL_HANDLE_HPP
#define NDN_DETAIL_CANCEL_HANDLE_HPP

#include "../../c/common.h"
#include <functional>

namespace ndn {
namespace scheduler {

/** \brief Handle to cancel an operation.
 */
class ndn_ind_dll CancelHandle
{
public:
  CancelHandle() noexcept = default;

  explicit
  CancelHandle(std::function<void()> cancel);

  /** \brief Cancel the operation.
   */
  void
  cancel() const;

private:
  mutable std::function<void()> m_cancel;
};

/** \brief Cancels an operation automatically upon destruction.
 */
class ndn_ind_dll ScopedCancelHandle
{
public:
  ScopedCancelHandle() noexcept = default;

  /** \brief Implicit constructor from CancelHandle.
   */
  ScopedCancelHandle(CancelHandle hdl);

  /** \brief Copy construction is disallowed.
   */
  ScopedCancelHandle(const ScopedCancelHandle&) = delete;

  /** \brief Move constructor.
   */
  ScopedCancelHandle(ScopedCancelHandle&& other);

  /** \brief Copy assignment is disallowed.
   */
  ScopedCancelHandle&
  operator=(const ScopedCancelHandle&) = delete;

  /** \brief Move assignment operator.
   */
  ScopedCancelHandle&
  operator=(ScopedCancelHandle&& other);

  /** \brief Cancel the operation.
   */
  ~ScopedCancelHandle();

  /** \brief Cancel the operation.
   */
  void
  cancel();

  /** \brief Release the operation so that it won't be cancelled when this ScopedCancelHandle is
   *         destructed.
   *  \return the CancelHandle.
   */
  CancelHandle
  release();

private:
  CancelHandle m_hdl;
};

} // namespace scheduler
} // namespace ndn

#endif // NDN_DETAIL_CANCEL_HANDLE_HPP

#endif // NDN_IND_HAVE_BOOST

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/security/security-exception.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2013-2020 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
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

#ifndef NDN_SECURITY_EXCEPTION_HPP
#define NDN_SECURITY_EXCEPTION_HPP

#include "../c/common.h"
#include <exception>
#include <string>

namespace ndn {

class ndn_ind_dll SecurityException : public std::exception {
public:
  SecurityException(const std::string& errorMessage) throw();

  virtual ~SecurityException() throw();

  std::string
  Msg() const { return errorMessage_; }

  virtual const char*
  what() const throw();

private:
  const std::string errorMessage_;
};

class ndn_ind_dll UnrecognizedKeyFormatException : public SecurityException {
public:
  UnrecognizedKeyFormatException(const std::string& errorMessage)
  : SecurityException(errorMessage)
  {
  }
};

class ndn_ind_dll UnrecognizedDigestAlgorithmException : public SecurityException {
public:
  UnrecognizedDigestAlgorithmException(const std::string& errorMessage)
  : SecurityException(errorMessage)
  {
  }
};

}

#endif

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/encoding/element-listener.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Add readRawPackets. Put element-listener.hpp in API. Support ndn_ind_dll.
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

#ifndef NDN_ELEMENT_LISTENER_HPP
#define NDN_ELEMENT_LISTENER_HPP

#include <ndn-ind/c/encoding/element-reader-types.h>

namespace ndn {

/**
 * An ElementListener extends an ndn_ElementListener struct to proved an abstract virtual onReceivedElement function which wraps
 * the onReceivedElement used by the ndn_ElementListener struct.  You must extend this class to override onReceivedElement.
 */
class ndn_ind_dll ElementListener : public ndn_ElementListener {
public:
  ElementListener();

  /**
   * This is called when an entire element is received.  You must extend this class to override this method.
   * @param element pointer to the element. The element buffer is
   * only valid during the call to onReceivedElement. If you need the data in the
   * buffer after onReceivedElement returns, then you must copy it.
   * @param elementLength length of element
   */
  virtual void
  onReceivedElement(const uint8_t *element, size_t elementLength) = 0;

private:
  /**
   * Call the virtual method onReceivedElement. This is used to initialize the base ndn_ElementListener struct.
   * @param self
   * @param element
   * @param elementLength
   */
  static void
  staticOnReceivedElement(struct ndn_ElementListener *self, const uint8_t *element, size_t elementLength);
};

}

#endif

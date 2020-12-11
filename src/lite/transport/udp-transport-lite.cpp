/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/lite/transport/udp-transport-lite.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Add readRawPackets. Support WinSock2.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2015-2020 Regents of the University of California.
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

// Only compile if we have Unix or Windows socket support.
#include <ndn-ind/ndn-ind-config.h>
#if NDN_IND_HAVE_UNISTD_H || defined(_WIN32)

#include "../../c/transport/udp-transport.h"
#include <ndn-ind/lite/transport/udp-transport-lite.hpp>

namespace ndn {

UdpTransportLite::UdpTransportLite(DynamicUInt8ArrayLite& buffer, bool readRawPackets)
{
  ndn_UdpTransport_initialize(this, &buffer, readRawPackets ? 1 : 0);
}

bool
UdpTransportLite::isLocal() { return ndn_UdpTransport_isLocal() != 0; }

ndn_Error
UdpTransportLite::connect
  (const char* host, unsigned short port, ElementListenerLite& elementListener)
{
  return ndn_UdpTransport_connect(this, host, port, &elementListener);
}

ndn_Error
UdpTransportLite::send(const uint8_t* data, size_t dataLength)
{
  return ndn_UdpTransport_send(this, data, dataLength);
}

ndn_Error
UdpTransportLite::processEvents(uint8_t *buffer, size_t bufferLength)
{
  return ndn_UdpTransport_processEvents(this, buffer, bufferLength);
}

ndn_Error
UdpTransportLite::close()
{
  return ndn_UdpTransport_close(this);
}

}

#endif // NDN_IND_HAVE_UNISTD_H

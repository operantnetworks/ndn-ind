/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/transport/tcp-transport.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Add readRawPackets. Put element-listener.hpp in API. Support WinSock2.
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

// Only compile if we have Unix or Windows socket support.
#include <ndn-ind/ndn-ind-config.h>
#if NDN_IND_HAVE_UNISTD_H || defined(_WIN32)

#include <stdexcept>
#include <stdlib.h>
#include "../c/transport/tcp-transport.h"
#include "../c/encoding/element-reader.h"
#include "../util/dynamic-uint8-vector.hpp"
#include <ndn-ind/transport/tcp-transport.hpp>

using namespace std;

namespace ndn {

TcpTransport::ConnectionInfo::~ConnectionInfo()
{
}

TcpTransport::TcpTransport(bool readRawPackets)
  : isConnected_(false), transport_(new struct ndn_TcpTransport),
    elementBuffer_(new DynamicUInt8Vector(1000)), connectionInfo_("", 0)
{
  ndn_TcpTransport_initialize
    (transport_.get(), elementBuffer_.get(), readRawPackets ? 1 : 0);
}

bool
TcpTransport::isLocal(const Transport::ConnectionInfo& connectionInfo)
{
  const TcpTransport::ConnectionInfo& tcpConnectionInfo =
    dynamic_cast<const TcpTransport::ConnectionInfo&>(connectionInfo);

  if (connectionInfo_.getHost() == "" ||
      connectionInfo_.getHost() != tcpConnectionInfo.getHost()) {
    ndn_Error error;
    int intIsLocal;
    if ((error = ndn_TcpTransport_isLocal
         ((char *)tcpConnectionInfo.getHost().c_str(), &intIsLocal)))
      throw runtime_error(ndn_getErrorString(error));

    // Cache the result in isLocal_ and save connectionInfo_ for next time.
    connectionInfo_ = tcpConnectionInfo;
    isLocal_ = (intIsLocal != 0);
  }

  return isLocal_;
}

bool
TcpTransport::isAsync() { return false; }

void
TcpTransport::connect
  (const Transport::ConnectionInfo& connectionInfo,
   ElementListener& elementListener, const OnConnected& onConnected)
{
  const TcpTransport::ConnectionInfo& tcpConnectionInfo =
    dynamic_cast<const TcpTransport::ConnectionInfo&>(connectionInfo);

  ndn_Error error;
  if (tcpConnectionInfo.hasSocketDescriptor()) {
    // Just use the already-open socket.
    if ((error = ndn_TcpTransport_useSocket
         (transport_.get(), tcpConnectionInfo.getSocketDescriptor(),
          &elementListener)))
      throw runtime_error(ndn_getErrorString(error));
  }
  else {
    if ((error = ndn_TcpTransport_connect
         (transport_.get(), (char *)tcpConnectionInfo.getHost().c_str(),
          tcpConnectionInfo.getPort(), &elementListener)))
      throw runtime_error(ndn_getErrorString(error));
  }

  isConnected_ = true;
  if (onConnected)
    onConnected();
}

void
TcpTransport::send(const uint8_t *data, size_t dataLength)
{
  ndn_Error error;
  if ((error = ndn_TcpTransport_send(transport_.get(), data, dataLength)))
    throw runtime_error(ndn_getErrorString(error));
}

void
TcpTransport::processEvents()
{
  uint8_t buffer[MAX_NDN_PACKET_SIZE];
  ndn_Error error;
  if ((error = ndn_TcpTransport_processEvents
       (transport_.get(), buffer, sizeof(buffer))))
    throw runtime_error(ndn_getErrorString(error));
}

bool
TcpTransport::getIsConnected()
{
  return isConnected_;
}

void
TcpTransport::close()
{
  ndn_Error error;
  if ((error = ndn_TcpTransport_close(transport_.get())))
    throw runtime_error(ndn_getErrorString(error));
}

}

#endif // NDN_IND_HAVE_UNISTD_H

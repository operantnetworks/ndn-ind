/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
 * @author: From ndn-squirrel https://github.com/remap/ndn-squirrel/blob/master/src/transport/micro-forwarder-transport.nut
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

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind-tools/micro-forwarder/micro-forwarder-transport.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn;
using namespace ndn::func_lib;

INIT_LOGGER("ndntools.MicroForwarderTransport");

namespace ndntools {

MicroForwarderTransport::ConnectionInfo::~ConnectionInfo()
{
}

MicroForwarderTransport::MicroForwarderTransport()
: elementBuffer_(1000),
  elementReader_(0, &elementBuffer_)
{
}

bool
MicroForwarderTransport::isLocal(const Transport::ConnectionInfo& connectionInfo)
{
  return true;
}

bool
MicroForwarderTransport::isAsync() { return false; }

void
MicroForwarderTransport::connect
  (const Transport::ConnectionInfo& connectionInfo,
   ElementListener& elementListener, const OnConnected& onConnected)
{
  const MicroForwarderTransport::ConnectionInfo* microforwarderConnectionInfo =
    dynamic_cast<const MicroForwarderTransport::ConnectionInfo*>(&connectionInfo);
  if (!microforwarderConnectionInfo)
    throw runtime_error
      ("MicroForwarderTransport::connect: connectionInfo is not a MicroForwarderTransport::ConnectionInfo");
  if (!microforwarderConnectionInfo->getForwarder())
    throw runtime_error
      ("MicroForwarderTransport::connect: connectionInfo getForwarder() is null");

  connectionInfo_ = *microforwarderConnectionInfo;
  elementReader_.reset(&ElementListenerLite::downCast(elementListener));

  endpoint_.reset(new Endpoint(this));
  // Endpoint doesn't use the ConnectionInfo so pass a default object.
  // The MicroForwader will call endpoint_->connect with its elementListener.
  int faceId = connectionInfo_.getForwarder()->addFace
    ("internal://app", endpoint_, ptr_lib::make_shared<Transport::ConnectionInfo>());
  connectionInfo_.getForwarder()->registerRoute(Name("/"), faceId);

  if (onConnected)
    onConnected();
}

void
MicroForwarderTransport::send(const uint8_t *data, size_t dataLength)
{
  if (!endpoint_)
    // This should have been set in connect().
    throw std::runtime_error
      ("MicroForwarderTransport.send: The transport is not connected");

  // This will call onReceivedElement on the ElementListener provided by the
  // MicroForwader.
  endpoint_->onReceivedData(data, dataLength);
}

void
MicroForwarderTransport::processEvents()
{
  if (connectionInfo_.getForwarder())
    connectionInfo_.getForwarder()->processEvents();
}

bool
MicroForwarderTransport::getIsConnected()
{
  // This is created in connect();
  return !!endpoint_;
}

}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-ind/transport/tcp-transport.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Add readRawPackets. Support ndn_ind_dll.
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

#ifndef NDN_TCP_TRANSPORT_HPP
#define NDN_TCP_TRANSPORT_HPP

#include <string>
#include "../common.hpp"
#include "transport.hpp"
#if defined(_WIN32)
#include <winsock2.h>
#endif

struct ndn_TcpTransport;

namespace ndn {

class DynamicUInt8Vector;

/**
 * TcpTransport extends the Transport interface to implement communication over
 * TCP.
 */
class ndn_ind_dll TcpTransport : public Transport {
public:
  /**
   * A TcpTransport::ConnectionInfo extends Transport::ConnectionInfo to hold
   * the host and port info for the TCP connection.
   */
  class ndn_ind_dll ConnectionInfo : public Transport::ConnectionInfo {
  public:
    /**
     * Create a ConnectionInfo with the given host and port.
     * @param host The host for the connection.
     * @param port The port number for the connection. If omitted, use 6363.
     */
    ConnectionInfo(const char *host, unsigned short port = 6363)
    : host_(host), port_(port)
    {
#if defined(_WIN32)
      socketDescriptor_ = INVALID_SOCKET;
#else
      socketDescriptor_ = -1;
#endif
    }

    /**
     * Create a ConnectionInfo to use an already-open socket descriptor.
     * @param socketDescriptor The socket descriptor which must already be open.
     */
#if defined(_WIN32)
    ConnectionInfo(SOCKET socketDescriptor)
#else
    ConnectionInfo(int socketDescriptor)
#endif
    : socketDescriptor_(socketDescriptor), port_(-1)
    {
    }

    /**
     * Check if an already-open socket descriptor was given to the constructor.
     * @return True if there is an already-open socket descriptor.
     */
    bool
    hasSocketDescriptor() const
    {
#if defined(_WIN32)
      return socketDescriptor_ != INVALID_SOCKET;
#else
      return socketDescriptor_ >= 0;
#endif
    }

    /**
     * Get the socket descriptor given to the constructor.
     * @return The socket descriptor.
     */
#if defined(_WIN32)
    SOCKET
#else
    int
#endif
    getSocketDescriptor() const { return socketDescriptor_; }

    /**
     * Get the host given to the constructor, or undefined if the constructor
     * was called with a socketDescriptor.
     * @return A string reference for the host.
     */
    const std::string&
    getHost() const { return host_; }

    /**
     * Get the port given to the constructor, or undefined if the constructor
     * was called with a socketDescriptor.
     * @return The port number.
     */
    unsigned short
    getPort() const { return port_; }

    virtual
    ~ConnectionInfo();

  private:
#if defined(_WIN32)
  SOCKET socketDescriptor_; /**< INVALID_SOCKET if not already connected */
#else
  int socketDescriptor_; /**< -1 if not already connected */
#endif
    std::string host_;
    unsigned short port_;
  };

  /**
   * Create a TcpTransport.
   * @param readRawPackets (optional) If true, then call
   * elementListener->onReceivedElement for each received packet as-is. If
   * false or omitted, then use the ndn_TlvStructureDecoder to ensure that
   * elementListener->onReceivedElement is called once for a whole TLV packet.
   */
  TcpTransport(bool readRawPackets = false);

  /**
   * Determine whether this transport connecting according to connectionInfo is
   * to a node on the current machine; results are cached. According to
   * http://redmine.named-data.net/projects/nfd/wiki/ScopeControl#local-face,
   * TCP transports with a loopback address are local. If connectionInfo
   * contains a host name, this will do a blocking DNS lookup; otherwise
   * this will parse the IP address and examine the first octet to determine if
   * it is a loopback address (e.g. the first IPv4 octet is 127 or IPv6 is "::1").
   * @param connectionInfo A TcpTransport.ConnectionInfo with the host to check.
   * @return True if the host is local, false if not.
   */
  virtual bool
  isLocal(const Transport::ConnectionInfo& connectionInfo);

  /**
   * Override to return false since connect does not need to use the onConnected
   * callback.
   * @return False.
   */
  virtual bool
  isAsync();

  /**
   * Connect according to the info in ConnectionInfo, and processEvents() will
   * use elementListener.
   * @param connectionInfo A reference to a TcpTransport::ConnectionInfo.
   * @param elementListener Not a shared_ptr because we assume that it will
   * remain valid during the life of this object.
   * @param onConnected This calls onConnected() when the connection is
   * established.
   */
  virtual void
  connect
    (const Transport::ConnectionInfo& connectionInfo,
     ElementListener& elementListener, const OnConnected& onConnected);

  /**
   * Send data to the host
   * @param data A pointer to the buffer of data to send.
   * @param dataLength The number of bytes in data.
   */
  virtual void
  send(const uint8_t *data, size_t dataLength);

  /**
   * Process any data to receive.  For each element received, call
   * elementListener.onReceivedElement. This is non-blocking and will return
   * immediately if there is no data to receive. You should normally not call
   * this directly since it is called by Face.processEvents.
   * @throws This may throw an exception for reading data or in the callback for
   * processing the data.  If you call this from an main event loop, you may
   * want to catch and log/disregard all exceptions.
   */
  virtual void
  processEvents();

  virtual bool
  getIsConnected();

  /**
   * Close the connection to the host.
   */
  virtual void
  close();

private:
  ptr_lib::shared_ptr<struct ndn_TcpTransport> transport_;
  ptr_lib::shared_ptr<DynamicUInt8Vector> elementBuffer_;
  bool isConnected_;
  ConnectionInfo connectionInfo_;
  bool isLocal_;
};

}

#endif

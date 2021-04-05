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

#ifndef NDN_MICRO_FORWARDER_TRANSPORT_HPP
#define NDN_MICRO_FORWARDER_TRANSPORT_HPP

#include "micro-forwarder.hpp"
#include <ndn-ind/lite/util/dynamic-malloc-uint8-array-lite.hpp>
#include <ndn-ind/lite/encoding/element-reader-lite.hpp>
#include <ndn-ind/transport/transport.hpp>

namespace ndntools {

/**
 * A MicroForwarderTransport extends Transport to communicate with a
 * MicroForwarder object. This can be used as the transport in the Face constructor.
 */
class ndn_ind_dll MicroForwarderTransport : public ndn::Transport {
public:
  /**
   * A MicroForwarderTransport::ConnectionInfo extends Transport::ConnectionInfo
   * to hold the MicroForwarder object to connect to.
   */
  class ndn_ind_dll ConnectionInfo : public Transport::ConnectionInfo {
  public:
    /**
     * Create a ConnectionInfo for the forwarder object.
     * @param forwarder (optional) The MicroForwarder to communicate with. If
     * omitted or null, use the default MicroForwarder::get().
     */
    ConnectionInfo(MicroForwarder* forwarder = 0)
    {
      forwarder_ = (forwarder ? forwarder : MicroForwarder::get());
    }

    /**
     * Get the MicroForwarder object given to the constructor.
     * @return The MicroForwarder object.
     */
    MicroForwarder*
    getForwarder() const { return forwarder_; }

    virtual
    ~ConnectionInfo();

  private:
    MicroForwarder* forwarder_;
  };

  /**
   * Create a MicroForwarderTransport.
   */
  MicroForwarderTransport();

  /**
   * Determine whether this transport connecting according to connectionInfo is
   * to a node on the current machine. MicroForwarder transports are always local.
   * @param connectionInfo This is ignored.
   * @return True because MicroForwarder transports are always local.
   */
  virtual bool
  isLocal(const ndn::Transport::ConnectionInfo& connectionInfo);

  /**
   * Override to return false since connect does not need to use the onConnected
   * callback.
   * @return False.
   */
  virtual bool
  isAsync();

  /**
   * Connect to connectionInfo.getForwarder() by calling its addFace with an
   * endpoint Transport connected to this Transport. processEvents() will use
   * elementListener.
   * @param connectionInfo The ConnectionInfo with the MicroForwarder object.
   * @param elementListener Not a shared_ptr because we assume that it will
   * remain valid during the life of this object.
   * @param onConnected This calls onConnected() when the connection is
   * established.
   */
  virtual void
  connect
    (const ndn::Transport::ConnectionInfo& connectionInfo,
     ndn::ElementListener& elementListener, const OnConnected& onConnected);

  /**
   * Send data to the MicroForwarder indicated by the ConnectionInfo.
   * @param data A pointer to the buffer of data to send.
   * @param dataLength The number of bytes in data.
   */
  virtual void
  send(const uint8_t *data, size_t dataLength);

  /**
   * This is called by Face.processEvents(). Just call the MicroForwarder's
   * processEvents() (which will call processEvents() for its Transport objects).
   */
  virtual void
  processEvents();

  virtual bool
  getIsConnected();

private:
  friend class MicroForwarder;

  /**
   * A MicroForwarderTransport::Endpoint extends Transport and is the the
   * Transport used in calling the MicroForwarder addFace method, as the endpoint
   * of this connection in the MicroForwarder.
   */
  class Endpoint : public ndn::Transport {
  public:
    Endpoint(MicroForwarderTransport* transport)
    : elementBuffer_(1000),
      elementReader_(0, &elementBuffer_),
      transport_(transport)
    {}

    virtual bool
    isLocal(const ndn::Transport::ConnectionInfo& connectionInfo) { return true;}

    virtual bool
    isAsync() { return false; }

    /**
     * This is called by the MicroForwarder when MicroForwarderTransport::connect
     * calls the MicroForwarder's addFace. Give the elementListener to the
     * elementReader_.
     * @param connectionInfo
     * @param elementListener
     * @param onConnected
     */
    virtual void
    connect(const ndn::Transport::ConnectionInfo& connectionInfo,
      ndn::ElementListener& elementListener, const OnConnected& onConnected)
    {
      // Ignore the connectionInfo. We already got what we need in the constructor.
      elementReader_.reset(&ndn::ElementListenerLite::downCast(elementListener));

      if (onConnected)
        onConnected();
    }

    /**
     * This is called by MicroForwarderTransport::send. Just pass the data to
     * the elementReader_ which will call onReceivedElement on the
     * elementListener provided by the MicroForwarder (when
     * MicroForwarderTransport::connect called its addFace).
     */
    void
    onReceivedData(const uint8_t *data, size_t dataLength)
    {
      elementReader_.onReceivedData(data, dataLength);
    }

    /**
     * Pass the data to the MicroForwarderTransport which will call
     * onReceivedElement on the elementListener given to its connect method.
     */
    virtual void
    send(const uint8_t *data, size_t dataLength)
    {
      transport_->elementReader_.onReceivedData(data, dataLength);
    }

    virtual void
    processEvents() {}

    virtual bool
    getIsConnected() { return true; }

  private:
    friend class MicroForwarder;

    ndn::DynamicMallocUInt8ArrayLite elementBuffer_;
    ndn::ElementReaderLite elementReader_;
    MicroForwarderTransport* transport_;
  };

private:
  ConnectionInfo connectionInfo_;
  ndn::DynamicMallocUInt8ArrayLite elementBuffer_;
  ndn::ElementReaderLite elementReader_;
  ndn::ptr_lib::shared_ptr<Endpoint> endpoint_;
  bool isLocal_;
  // Set outFaceId_ to specify the only output face for sending packets.
  int outFaceId_;
};

}

#endif

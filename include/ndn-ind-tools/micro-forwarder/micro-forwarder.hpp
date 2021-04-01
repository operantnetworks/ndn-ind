/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
 * @author: From ndn-squirrel https://github.com/remap/ndn-squirrel/blob/master/tools/micro-forwarder.nut
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

#ifndef NDN_MICRO_FORWARDER_HPP
#define NDN_MICRO_FORWARDER_HPP

#include <ndn-ind/interest.hpp>
#include <ndn-ind/data.hpp>
#include <ndn-ind/face.hpp>
#include <ndn-ind/transport/transport.hpp>

namespace ndntools {

/**
 * A MicroForwarder holds a PIT, FIB and faces to function as a simple NDN
 * forwarder. It has a single instance which you can access with
 * MicroForwarder::get().
 */
class ndn_ind_dll MicroForwarder {
  class ForwarderFace;

public:
  MicroForwarder()
  : minPitEntryLifetime_(std::chrono::minutes(1)),
    localhostNamePrefix("/localhost"),
    localhopNamePrefix("/localhop"),
    broadcastNamePrefix("/ndn/broadcast")
  {
  }

  /**
   * Add a new face to communicate with the given transport. This immediately
   * connects using the connectionInfo.
   * @param uri The URI to use in the faces/query and faces/list commands.
   * @param transport An object of a subclass of Transport to use
   * for communication. If the transport object has a "setOnReceivedObject"
   * method, then use it to set the onReceivedObject callback.
   * @param connectionInfo This must be a ConnectionInfo from the same subclass
   * of Transport as transport.
   * @return The new face ID.
   */
  int
  addFace
    (const std::string& uri, 
     const ndn::ptr_lib::shared_ptr<ndn::Transport>& transport,
     const ndn::ptr_lib::shared_ptr<const ndn::Transport::ConnectionInfo>& connectionInfo);

  /**
   * Add a new face to communicate with TCP to host:port. This immediately
   * connects. The URI to use in the faces/query and faces/list commands will be
   * "tcp://host:port" .
   * @param host The host for the TCP connection.
   * @param port (optional) The port for the TCP connection. If omitted, use 6363.
   * @return The new face ID.
   */
  int
  addFace(const char *host, unsigned short port = 6363);

  /**
   * Find or create the FIB entry with the given name and add the ForwarderFace
   * with the given faceId. All routes are multicast by default.
   * @param name The name of the FIB entry.
   * @param faceId The face ID of the face for the route.
   * @param cost (optional) The cost of the next hop for the given face. If a
   * next hop for the given name and face already exists, update its cost with
   * this value. If omitted, use 0.
   * @return True for success, or false if can't find the ForwarderFace with
   * faceId.
   */
  bool
  addRoute(const ndn::Name& name, int faceId, int cost = 0);

  /**
   * Send a remote register prefix command over face with faceId to the remote
   * forwarder. This allows the remote forwarder to forward interests back to
   * here which match the prefix. On the remote node, nfd.conf must have a
   * "localhop_security" section which allows remote prefix registration.
   * @param faceId The face ID of the face for sending the command.
   * @param prefix The prefix for remote registration. You can use the default
   * Name() so that the remote forwarder will forward all interests to here, but
   * if you want to limit the traffic, then use the prefix of the interests that
   * the local application needs to receive.
   * @param commandKeyChain The KeyChain object for signing command interests,
   * which must remain valid until this calls onRegisterFailed or onRegisterSuccess.
   * @param commandCertificateName The certificate name corresponding to the
   * key in commandKeyChain which is used for signing command interests. This
   * makes a copy of the Name. You can get the default certificate name with
   * commandKeyChain.getDefaultCertificateName() .
   * @param onRegisterFailed
   * @param onRegisterSuccess
   */
  void
  remoteRegisterPrefix
    (int faceId, const ndn::Name& prefix, ndn::KeyChain& commandKeyChain,
     const ndn::Name& commandCertificateName,
     const ndn::OnRegisterFailed& onRegisterFailed,
     const ndn::OnRegisterSuccess& onRegisterSuccess = ndn::OnRegisterSuccess());

  /**
   * Call processEvents() for the Transport object in each face. This is
   * normally called by MicroForwarderTransport::processEvents() which is called
   * by the application when it calls Face::processEvents(), so an application
   * normally doesn't need to call this directly.
   */
  void
  processEvents();

  /**
   * This is called by the Transport's ElementListener when an entire TLV
   * element is received. If it is an Interest, look in the FIB for forwarding.
   * If it is a Data packet, look in the PIT to match an Interest.
   * @param face The ForwarderFace with the Transport that received the element.
   * @param element A pointer to the element. The element buffer is
   * only valid during the call to onReceivedElement. If you need the data in
   * the buffer after onReceivedElement returns, then you must copy it.
   * @param elementLength The length of element
   */
  void
  onReceivedElement
    (ForwarderFace* face, const uint8_t *element, size_t elementLength);

  /**
   * Get a singleton instance of a MicroForwarder.
   * @return The singleton instance.
   */
  static MicroForwarder*
  get()
  {
    if (!instance_)
      instance_ = new MicroForwarder();

    return instance_;
  }

private:
  /**
   * A ForwarderFace is used by the faces list to represent a connection using
   * the* given Transport. (This is not to be confused with the application Face.)
   */
  class ForwarderFace : public ndn::ElementListener {
  public:
    /**
     * Create a ForwarderFace and set the faceId to a unique value.
     * @param parent The parent MicroForwarder.
     * @param uri The URI to use in the faces/query and faces/list commands.
     * @param transport Communicate using the Transport object. You must call
     * transport.connect with an elementListener object whose
     * onReceivedElement(element, elementLength) calls
     * MicroForwarder.onReceivedElement(face, element, elementLength), with this
     * face.
     */
    ForwarderFace
      (MicroForwarder* parent, const std::string uri,
       const ndn::ptr_lib::shared_ptr<ndn::Transport>& transport)
    : parent_(parent), uri_(uri), transport_(transport)
    {
      faceId_ = ++lastFaceId_;
    }

    const std::string&
    getUri() const { return uri_; }

    ndn::Transport*
    getTransport() const { return transport_.get(); }

    int
    getFaceId() const { return faceId_; }

    /**
     * Check if this face is still enabled.
     * @returns True if this face is still enabled.
     */
    bool
    isEnabled() { return !!transport_; }

    /**
     * Disable this face so that isEnabled() returns false.
     */
    void
    disable() { transport_.reset(); };

    /**
     * Send the data buffer to the transport
     * @param data A pointer to the buffer of data to send.
     * @param dataLength The number of bytes in data.
     */
    void
    send(const uint8_t *data, size_t dataLength)
    {
      if (transport_)
        transport_->send(data, dataLength);
    }

    void
    send(const std::vector<uint8_t>& data) { send(&data[0], data.size()); }

    /**
     * Call transport_->processEvents().
     */
    void
    processEvents() { transport_->processEvents(); }

    /**
     * This overrides ElementListener::onReceivedElement and is called by the
     * Transport when a new TLV element is received. Just call the parent
     * onReceivedElement.
     */
    void
    onReceivedElement(const uint8_t *element, size_t elementLength) override;

  private:
    MicroForwarder* parent_;
    std::string uri_;
    ndn::ptr_lib::shared_ptr<ndn::Transport> transport_;
    int faceId_;
    static int lastFaceId_;
  };

  /**
   * A PitEntry is used in the PIT to record the face on which an Interest came
   * in. (This is not to be confused with the PIT entry object used by the
   * application library's PendingInterestTable class.)
   */
  class PitEntry {
  public:
    /**
     * Create a PitEntry for the interest and incoming face.
     * @param interest The pending Interest. This does not make a copy.
     * @param inFace The Interest's incoming face (and where the matching Data
     * packet will be sent).
     * @param timeoutEndTime The time when the interest times out.
     * @param entryEndTime The time when this entry should be removed.
     */
    PitEntry
      (const ndn::ptr_lib::shared_ptr<ndn::Interest>& interest,
       ForwarderFace* inFace,
       std::chrono::system_clock::time_point timeoutEndTime,
       std::chrono::system_clock::time_point entryEndTime)
    : interest_(interest), inFace_(inFace),
      timeoutEndTime_(timeoutEndTime), entryEndTime_(entryEndTime),
      isRemoved_(false)
    {
    }

    ndn::ptr_lib::shared_ptr<ndn::Interest>&
    getInterest() { return interest_; }

    ForwarderFace*
    getInFace() { return inFace_; }

    void
    clearInFace() { inFace_ = 0; }

    std::chrono::system_clock::time_point
    getTimeoutEndTime() { return timeoutEndTime_; }

    void
    setTimeoutEndTime(std::chrono::system_clock::time_point timeoutEndTime)
    {
      timeoutEndTime_ = timeoutEndTime;
    }

    std::chrono::system_clock::time_point
    getEntryEndTime() { return entryEndTime_; }

    void
    setEntryEndTime(std::chrono::system_clock::time_point entryEndTime)
    {
      entryEndTime_ = entryEndTime;
    }

    /**
     * Set the isRemoved_ flag true.
     */
    void
    setIsRemoved() { isRemoved_ = true; }

  private:
    ndn::ptr_lib::shared_ptr<ndn::Interest> interest_;
    ForwarderFace* inFace_;
    // timeoutEndTime_ is based on the Interest lifetime.
    std::chrono::system_clock::time_point timeoutEndTime_;
    // entryEndTime_ is when this entry should be removed. (The entry is kept
    // around longer than the Interest lifetime to detect a duplicate nonce.)
    std::chrono::system_clock::time_point entryEndTime_;
    bool isRemoved_;
  };

  /**
   * A FibEntry holds a list of NextHopRecord where each record has a
   * ForwarderFace and its related cost.
   */
  class NextHopRecord {
  public:
    /**
     * Create a NextHopRecord with the given values.
     * @param face The ForwarderFace for this next hop.
     * @param cost The cost of this next hop on the given face.
     */
    NextHopRecord(ForwarderFace* face, int cost)
    : face_(face), cost_(cost)
    {
    }

    ForwarderFace*
    getFace() { return face_; }

    int
    getCost() { return cost_; }

    void
    setCost(int cost) { cost_ = cost; }

  private:
    ForwarderFace* face_;
    int cost_;
  };

  /**
   * A FibEntry is used in the FIB to match a registered name with a list of
   * related NextHopRecord.
   */
  class FibEntry {
  public:
    /**
     * Create a FibEntry with the given registered name.
     * @param name The registered name for this FIB entry.
     */
    FibEntry (const ndn::Name& name)
    : name_(name)
    {
    }

    ndn::Name&
    getName() { return name_; }

    /**
     * Get the number of entries in the list of NextHopRecord.
     * @return The number of entries.
     */
    int
    getNextHopCount() { return nextHops_.size(); }

    /**
     * Get the NextHopRecord at the given index.
     * @param i The index in the list of NextHopRecord.
     * @return The NextHopRecord.
     */
    NextHopRecord&
    getNextHop(int i) { return *nextHops_[i]; }

    void
    addNextHop(const ndn::ptr_lib::shared_ptr<NextHopRecord>& nextHop)
    {
      nextHops_.push_back(nextHop);
    }

    /**
     * Get the index in the list of NextHopRecord with the given face.
     * @param fact The face to search for.
     * @return The index of the matching NextHopRecord, or -1 if not found.
     */
    int
    nextHopIndexOf(ForwarderFace* face)
    {
      for (int i = 0; i < nextHops_.size(); ++i) {
        if (nextHops_[i]->getFace() == face)
          return i;
      }

      return -1;
    }

  private:
    ndn::Name name_;
    std::vector<ndn::ptr_lib::shared_ptr<NextHopRecord> > nextHops_;
  };

  /**
   * Find the face in faces_ with the faceId.
   * @param The faceId.
   * @return The ForwarderFace, or null if not found.
   */
  ForwarderFace*
  findFace(int faceId);

  /**
   * Mark the PitEntry at PIT_[i] as removed (in case something references it)
   * and remove it.
   */
  void
  removePitEntry(int i)
  {
    PIT_[i]->setIsRemoved();
    PIT_.erase(PIT_.begin() + i);
  }

  std::vector<ndn::ptr_lib::shared_ptr<PitEntry> > PIT_;
  std::vector<ndn::ptr_lib::shared_ptr<FibEntry> > FIB_;
  std::vector<ndn::ptr_lib::shared_ptr<ForwarderFace> > faces_;
  std::chrono::nanoseconds minPitEntryLifetime_;

  ndn::Name localhostNamePrefix;
  ndn::Name localhopNamePrefix;
  ndn::Name broadcastNamePrefix;

  static MicroForwarder* instance_;
};

}

#endif

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

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/encoding/tlv-wire-format.hpp>
#include <ndn-ind/lite/encoding/tlv-0_3-wire-format-lite.hpp>
#include <ndn-ind/lite/lp/lp-packet-lite.hpp>
#include <ndn-ind/transport/tcp-transport.hpp>
#include <ndn-ind/network-nack.hpp>
#include "../../src/lp/lp-packet.hpp"
#include <ndn-ind-tools/micro-forwarder/micro-forwarder.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn;
using namespace ndn::func_lib;

INIT_LOGGER("ndntools.MicroForwarder");

namespace ndntools {

int
MicroForwarder::addFace
  (const string& uri, const ptr_lib::shared_ptr<Transport>& transport,
   const ptr_lib::shared_ptr<const Transport::ConnectionInfo>& connectionInfo)
{
  auto face = ptr_lib::make_shared<ForwarderFace>(this, uri, transport);

  transport->connect(*connectionInfo, *face, Transport::OnConnected());
  faces_.push_back(face);

  int faceId = face->getFaceId();
  _LOG_INFO("Created face " << faceId << ": " << uri);
  return faceId;
}

int
MicroForwarder::addFace(const char *host, unsigned short port)
{
  return addFace
    (string("tcp://") + host + ":" + to_string(port),
     ptr_lib::make_shared<TcpTransport>(),
     ptr_lib::make_shared<TcpTransport::ConnectionInfo>(host, port));
}

bool
MicroForwarder::registerRoute(const ndn::Name& name, int faceId, int cost)
{
  ForwarderFace* nextHopFace = findFace(faceId);
  if (!nextHopFace) {
    _LOG_INFO("Register route: Unrecognized face id " << faceId);
    return false;
  }

  // Check for a FIB entry for the name and add the face.
  for (int i = 0; i < FIB_.size(); ++i) {
    FibEntry& fibEntry = *FIB_[i];

    if (fibEntry.getName().equals(name)) {
      int nextHopIndex = fibEntry.nextHopIndexOf(nextHopFace);
      if (nextHopIndex >= 0)
        // A next hop with the face is already added, so just update its cost.
        fibEntry.getNextHop(nextHopIndex).setCost(cost);
      else
        // The face is not already added.
        fibEntry.addNextHop(ptr_lib::make_shared<NextHopRecord>(nextHopFace, cost));

      _LOG_INFO("Register route: Added face " << faceId <<
        " to existing FIB entry for: " << name);
      return true;
    }
  }

  // Make a new FIB entry.
  auto fibEntry = ptr_lib::make_shared<FibEntry>(name);
  fibEntry->addNextHop(ptr_lib::make_shared<NextHopRecord>(nextHopFace, cost));
  FIB_.push_back(fibEntry);

  _LOG_INFO("Register route: Added face id " << faceId <<
    " to new FIB entry for: " << name);
  return true;
}

void
MicroForwarder::processEvents()
{
  for (int i = 0; i < faces_.size(); ++i) {
    faces_[i]->processEvents();
  }
}

void
MicroForwarder::ForwarderFace::onReceivedElement
  (const uint8_t *element, size_t elementLength)
{
  parent_->onReceivedElement(this, element, elementLength);
}

void
MicroForwarder::onReceivedElement
  (ForwarderFace* face, const uint8_t *element, size_t elementLength)
{
  const int Tlv_Interest = 5;
  const int Tlv_Data = 6;
  const int Tlv_LpPacket_LpPacket = 100;
  const uint8_t *interestOrData = element;
  size_t interestOrDataLength = elementLength;
  ptr_lib::shared_ptr<LpPacket> lpPacket;
  if (element[0] == Tlv_LpPacket_LpPacket) {
    // Decode the LpPacket and replace element with the fragment.
    // Use LpPacketLite to avoid copying the fragment.
    struct ndn_LpPacketHeaderField headerFields[5];
    LpPacketLite lpPacketLite
      (headerFields, sizeof(headerFields) / sizeof(headerFields[0]));

    ndn_Error error;
    if ((error = Tlv0_3WireFormatLite::decodeLpPacket
         (lpPacketLite, element, elementLength)))
      throw runtime_error(ndn_getErrorString(error));
    interestOrData = lpPacketLite.getFragmentWireEncoding().buf();
    interestOrDataLength = lpPacketLite.getFragmentWireEncoding().size();
    // We have saved the wire encoding, so clear to copy it to lpPacket.
    lpPacketLite.setFragmentWireEncoding(BlobLite());

    lpPacket.reset(new LpPacket());
    lpPacket->set(lpPacketLite);
  }

  // First, decode as Interest or Data.
  ptr_lib::shared_ptr<Interest> interest;
  ptr_lib::shared_ptr<Data> data;

  if (interestOrData[0] == Tlv_Interest) {
    interest.reset(new Interest());
    interest->wireDecode(interestOrData, interestOrDataLength, *TlvWireFormat::get());
  }
  else if (interestOrData[0] == Tlv_Data) {
    data.reset(new Data());
    data->wireDecode(interestOrData, interestOrDataLength, *TlvWireFormat::get());
  }

  auto now = system_clock::now();
  // Remove timed-out PIT entries
  // Iterate backwards so we can remove the entry and keep iterating.
  for (int i = PIT_.size() - 1; i >= 0; --i) {
    PitEntry& entry = *PIT_[i];
    // For removal, we also check the timeoutEndTime in case it is greater
    // than entryEndTime.
    if (now >= entry.getEntryEndTime() && now >= entry.getTimeoutEndTime())
      removePitEntry(i);
    else if (now >= entry.getTimeoutEndTime())
      // Timed out, so set inFace_ null which prevents using the PIT entry to
      // return a Data packet, but we keep the PIT entry to check for a
      // duplicate nonce. (If a fresh Interest arrives with the same name, a
      // new PIT entry will be created.)
      entry.clearInFace();
  }

  if (lpPacket) {
    ptr_lib::shared_ptr<NetworkNack> networkNack =
      NetworkNack::getFirstHeader(*lpPacket);
    if (networkNack) {
      if (!interest)
        // We got a Nack but not for an Interest, so drop the packet.
        return;

      // All prefixes have multicast strategy by default, so drop the Nack so
      // that it doesn't consume the PIT entry.
      _LOG_DEBUG("Dropped Interest with Nack on face " << face->getFaceId() <<
        ", reason code " << networkNack->getReason() << ": " << interest->getName());
      return;
    }
  }

  // Now process as Interest or Data.
  if (interest) {
    _LOG_DEBUG("Received Interest on face " << face->getFaceId() << ": " <<
       interest->getName());

    if (localhostNamePrefix.match(interest->getName()))
      // Ignore localhost.
      return;

    if (localhopNamePrefix.match(interest->getName()))
      // Ignore localhop.
      return;

    // First check for a duplicate nonce on any face.
    for (int i = 0; i < PIT_.size(); ++i) {
      PitEntry& entry = *PIT_[i];
      if (entry.getInterest()->getNonce().equals(interest->getNonce())) {
        _LOG_DEBUG("Dropped Interest with duplicate nonce " << interest->getNonce().toHex()
          << ": " << interest->getName());
        return;
      }
    }

    // Check for a duplicate Interest.
    system_clock::time_point timeoutEndTime;
    if (interest->getInterestLifetime().count() >= 0)
      timeoutEndTime = now + 
        duration_cast<system_clock::duration>(interest->getInterestLifetime());
    else
      // Use a default timeout.
      timeoutEndTime = now + seconds(4);
    system_clock::time_point entryEndTime = 
      now + duration_cast<system_clock::duration>(minPitEntryLifetime_);
    bool isDuplicateInterest = false;
    for (int i = 0; i < PIT_.size(); ++i) {
      PitEntry& entry = *PIT_[i];
      // TODO: Check interest equality of appropriate selectors.
      if (entry.getInterest()->getName().equals(interest->getName())) {
        // Duplicate interest. If it's a new face, then we'll create a PIT entry,
        // but won't forward.
        isDuplicateInterest = true;

        if (entry.getInFace() == face) {
          // Update the interest timeout.
          if (timeoutEndTime > entry.getTimeoutEndTime())
            entry.setTimeoutEndTime(timeoutEndTime);
          // Also update the PIT entry timeout.
          entry.setEntryEndTime(entryEndTime);

          _LOG_DEBUG("Duplicate Interest on same face " << face->getFaceId() << ": "
            << interest->getName());
          return;
        }
      }
    }

    // Add to the PIT.
    auto pitEntry = ptr_lib::make_shared<PitEntry>
      (interest, face, timeoutEndTime, entryEndTime);
    PIT_.push_back(pitEntry);
    _LOG_DEBUG("Added PIT entry for Interest: " << interest->getName());

    if (isDuplicateInterest)
      // Don't forward a duplicate interest.
      return;

    if (broadcastNamePrefix.match(interest->getName())) {
      // Special case: broadcast to all faces.
      for (int i = 0; i < faces_.size(); ++i) {
        ForwarderFace* outFace = faces_[i].get();
        // Don't send the interest back to where it came from.
        if (outFace != face) {
          _LOG_DEBUG("Broadcasted Interest to face " << outFace->getFaceId() << ": "
            << interest->getName());
          // Forward the full element including any LP header.
          outFace->send(element, elementLength);
        }
      }
    }
    else {
      // Send the interest to the faces in matching FIB entries.
      for (int i = 0; i < FIB_.size(); ++i) {
        FibEntry& fibEntry = *FIB_[i];

        // This behavior is multicast.
        // TODO: Need to allow for "best route" and longest prefix match?
        if (fibEntry.getName().match(interest->getName())) {
          for (int j = 0; j < fibEntry.getNextHopCount(); ++j) {
            ForwarderFace* outFace = fibEntry.getNextHop(j).getFace();

            // Don't send the interest back to where it came from.
            if (outFace != face) {
              _LOG_DEBUG("Forwarded Interest to face " << outFace->getFaceId() << ": "
                << interest->getName());
              // Forward the full element including any LP header.
              outFace->send(element, elementLength);
            }
          }
        }
      }
    }
  }
  else if (data) {
    _LOG_DEBUG("Received Data on face " << face->getFaceId() << ": " << data->getName());

    // Send the data packet to the face for each matching PIT entry.
    for (int i = 0; i < PIT_.size(); ++i) {
      PitEntry& entry = *PIT_[i];
      if (entry.getInFace() && entry.getInterest()->matchesData(*data)) {
        _LOG_DEBUG("Forwarded Data to face " << entry.getInFace()->getFaceId()
          << ": " << data->getName());
        // Forward the full element including any LP header.
        entry.getInFace()->send(element, elementLength);

        // The PIT entry is consumed, so set clear the inFace_ which prevents
        // using it to return another Data packet, but we keep the PIT entry to
        // check for a duplicate nonce. It will be deleted after entryEndTime.
        // (If a fresh Interest arrives with the same name, a new PIT entry will
        // be created.)
        entry.clearInFace();
      }
    }
  }
}

MicroForwarder::ForwarderFace*
MicroForwarder::findFace(int faceId)
{
  for (int i = 0; i < faces_.size(); ++i) {
    if (faces_[i]->getFaceId() == faceId)
      return faces_[i].get();
  }

  return 0;
}

int MicroForwarder::ForwarderFace::lastFaceId_ = 0;
MicroForwarder* MicroForwarder::instance_ = 0;

}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
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

/**
 * This is similar to test-echo-consumer, but demonstrates how to use
 * TcpTransport directly with raw packets. You would not normally do this in an
 * NDN application. But this example is here to show the flexibility of
 * TcpTransport.
 *
 * This is meant to work with test-publish-async-nfd. This sends encodes an
 * Interest and sends it to the TCP socket which is connected to NFD.
 * Then this waits for a packet that it decodes as a Data packet.
 */

#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <ndn-ind/interest.hpp>
#include <ndn-ind/transport/tcp-transport.hpp>

using namespace std;
using namespace ndn;

/**
 * MyElementListener extends ElementListener and overrides onReceivedElement
 * which is called by the Transport when a packet is received.
 */
class MyElementListener : public ElementListener {
public:
  MyElementListener() {
    callbackCount_ = 0;
  }

  virtual void
    onReceivedElement(const uint8_t *element, size_t elementLength)
  {
    ++callbackCount_;

    // Process the raw incoming packet.
    // For simplicity, assume that this is the response Data packet from
    // test-publish-async-nfd, so decode as a Data packet.
    // In a production application, we would check the format of the bytes
    // in the packet and do error handling.
    auto data = ptr_lib::make_shared<Data>();
    data->wireDecode(element, elementLength);
    cout << "Got data packet with name " << data->getName().toUri() << endl;
    cout << data->getContent().toRawStr() << endl;
  }

  int callbackCount_;
};

int main(int argc, char** argv)
{
  // Silence the warning from Interest wire encode.
  Interest::setDefaultCanBePrefix(true);

  string word;
  cout << "Enter a word to echo:" << endl;
  cin >> word;

  // Create a TcpTransport with readRawPackets true.
  auto transport = ptr_lib::make_shared<TcpTransport>(true);
  auto host = "localhost";

  // Make the ElementListener which has our onReceivedElement callback.
  MyElementListener elementListener;

  // Connect to the NFD at the host address. Provide the onConnected callback
  // this is called when if finishes opening the TCP connection.
  transport->connect
    (TcpTransport::ConnectionInfo(host), elementListener,
     [=]() {
       // This is the onConnected callback. Create an interest /testecho/<word>.
       Name name("/testecho");
       name.append(word);
       Interest interest(name);
       cout << "Express name " << name.toUri() << endl;

       // We are using the raw TcpTransport directly so we must encode the Interest.
       Blob encoding = interest.wireEncode();
       transport->send(encoding.buf(), encoding.size());
     });

  // The main event loop. Loop until onReceivedElement increments callbackCount_.
  while (elementListener.callbackCount_ < 1) {
    // Call processEvents which polls the socket. If there is no incoming data,
    // processEvents returns immediately, otherwise it reads the incoming data
    // and calls the onReceivedElement method of the ElementListener object
    // given to Transport connect.
    transport->processEvents();
    // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
    usleep(10000);
  }

  return 0;
}

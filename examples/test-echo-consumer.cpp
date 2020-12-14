/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: examples/test-echo-consumer.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
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

#include <cstdlib>
#include <iostream>
#include <ndn-ind/face.hpp>
#include <ndn-ind/transport/tcp-transport.hpp>
#if NDN_IND_HAVE_UNISTD_H
#include <unistd.h>
#elif defined(_WIN32)
#include "windows.h"
#endif

using namespace std;
using namespace ndn;
using namespace ndn::func_lib;

class Counter
{
public:
  Counter() {
    callbackCount_ = 0;
  }

  void onData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
  {
    ++callbackCount_;
    cout << "Got data packet with name " << data->getName().toUri() << endl;
    for (size_t i = 0; i < data->getContent().size(); ++i)
      cout << (*data->getContent())[i];
    cout << endl;
  }

  void onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
  {
    ++callbackCount_;
    cout << "Time out for interest " << interest->getName().toUri() << endl;
  }

  int callbackCount_;
};

static void
usage()
{
  cerr << "Usage: test-echo-consumer [options]\n"
       << "  -n name-prefix  If omitted, use /testecho\n"
       << "  -h host         If omitted or \"\", the default Face connects to the local forwarder\n"
       << "  -p port         If omitted, use 6363\n"
       << "  -?              Print this help" << endl;
}

int main(int argc, char** argv)
{
  Name namePrefix("/testecho");
  string host = "";
  int port = 6363;

  for (int i = 1; i < argc; ++i) {
    string arg = argv[i];
    string value = (i + 1 < argc ? argv[i + 1] : "");

    if (arg == "-?") {
      usage();
      return 0;
    }
    else if (arg == "-n") {
      namePrefix = Name(value);
      ++i;
    }
    else if (arg == "-h") {
      host = value;
      ++i;
    }
    else if (arg == "-p") {
      port = atoi(value.c_str());
      if (port == 0) {
        usage();
        return 1;
      }
      ++i;
    }
    else {
      cerr << "Unrecognized option: " << arg << endl;
      usage();
      return 1;
    }
  }

  try {
    // Silence the warning from Interest wire encode.
    Interest::setDefaultCanBePrefix(true);

    ptr_lib::shared_ptr<Face> face;
    if (host == "")
      // The default Face will connect using a Unix socket, or to "localhost".
      face.reset(new Face());
    else
      face.reset(new Face
        (ptr_lib::make_shared<TcpTransport>(), 
         ptr_lib::make_shared<TcpTransport::ConnectionInfo>(host.c_str(), port)));

    // Counter holds data used by the callbacks.
    Counter counter;

    string word;
    cout << "Enter a word to echo:" << endl;
    cin >> word;

    Name name(namePrefix);
    name.append(word);
    cout << "Express name " << name.toUri() << endl;
    // Use bind to pass the counter object to the callbacks.
    face->expressInterest(name, bind(&Counter::onData, &counter, _1, _2), bind(&Counter::onTimeout, &counter, _1));

    // The main event loop.
    while (counter.callbackCount_ < 1) {
      face->processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
#if NDN_IND_HAVE_UNISTD_H
      usleep(10000);
#elif defined(_WIN32)
      Sleep(10);
#endif
    }
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
  return 0;
}

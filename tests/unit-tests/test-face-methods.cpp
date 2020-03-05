/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: tests/unit-tests/test-face-methods.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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

#include "gtest/gtest.h"
#include <ndn-ind/face.hpp>
#include <sstream>
#if NDN_IND_HAVE_TIME_H
#include <time.h>
#endif
#if NDN_IND_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <ndn-ind/security/key-chain.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn;
using namespace ndn::func_lib;

class CallbackCounter
{
public:
  CallbackCounter()
  {
    onDataCallCount_ = 0;
    onTimeoutCallCount_ = 0;
    onNetworkNackCallCount_ = 0;
  }

  void
  onData(const ptr_lib::shared_ptr<const Interest>& interest,
         const ptr_lib::shared_ptr<Data>& data)
  {
    interest_ = *interest;
    data_ = *data;
    ++onDataCallCount_;
  }

  void
  onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
  {
    interest_ = *interest;
    ++onTimeoutCallCount_;
  }

  void
  onNetworkNack(const ptr_lib::shared_ptr<const Interest>& interest,
                const ptr_lib::shared_ptr<NetworkNack>& networkNack)
  {
    interest_ = *interest;
    networkNack_ = *networkNack;
    ++onNetworkNackCallCount_;
  }

  int onDataCallCount_;
  int onTimeoutCallCount_;
  int onNetworkNackCallCount_;
  Interest interest_;
  Data data_;
  NetworkNack networkNack_;

};

class RegisterCounter
{
public:
  RegisterCounter(KeyChain& keyChain)
  : keyChain_(keyChain)
  {
    onInterestCallCount_ = 0;
    onRegisterFailedCallCount_ = 0;
  }

  void
  onInterest
    (const ptr_lib::shared_ptr<const Name>& prefix,
     const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
     uint64_t interestFilterId,
     const ptr_lib::shared_ptr<const InterestFilter>& filter)
  {
    ++onInterestCallCount_;

    Data data(interest->getName());
    string content("SUCCESS");
    data.setContent((const uint8_t *)&content[0], content.size());
    keyChain_.sign(data);
    face.putData(data);
  }

  void
  onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
  {
    ++onRegisterFailedCallCount_;
  }

  KeyChain& keyChain_;
  int onInterestCallCount_;
  int onRegisterFailedCallCount_;
};

// Returns a CallbackCounter object so we can test data callback and timeout behavior.
CallbackCounter
runExpressNameTest
  (Face& face, const string& interestName, nanoseconds timeout = milliseconds(10000),
   bool useOnNack = false)
{
  Name name(interestName);
  CallbackCounter counter;
  if (useOnNack)
    face.expressInterest
      (name, bind(&CallbackCounter::onData, &counter, _1, _2),
       bind(&CallbackCounter::onTimeout, &counter, _1),
       bind(&CallbackCounter::onNetworkNack, &counter, _1, _2));
  else
    face.expressInterest
      (name, bind(&CallbackCounter::onData, &counter, _1, _2),
       bind(&CallbackCounter::onTimeout, &counter, _1));

  auto startTime = system_clock::now();
  while (system_clock::now() - startTime < timeout &&
         counter.onDataCallCount_ == 0 && counter.onTimeoutCallCount_ == 0) {
    face.processEvents();
    // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
    usleep(10000);
  }

  return counter;
}

class TestFaceRegisterMethods : public ::testing::Test {
public:
  TestFaceRegisterMethods()
  {
    faceIn.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName());
    faceOut.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName());
  }

  virtual void
  TearDown()
  {
    faceIn.shutdown();
    faceOut.shutdown();

    // Give time to shut down the face before the next test.
    auto timeout = milliseconds(500);
    auto startTime = system_clock::now();
    while (system_clock::now() - startTime < timeout) {
      faceIn.processEvents();
      faceOut.processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
      usleep(10000);
    }
  }

  Face faceIn;
  Face faceOut;
  KeyChain keyChain;
};

TEST_F(TestFaceRegisterMethods, RegisterPrefixResponse)
{
  Name prefixName("/test");

  RegisterCounter registerCounter(keyChain);

  faceIn.registerPrefix
    (prefixName,
     bind(&RegisterCounter::onInterest, &registerCounter, _1, _2, _3, _4, _5),
     bind(&RegisterCounter::onRegisterFailed, &registerCounter, _1));

  // Give the "server" time to register the interest.
  auto timeout = milliseconds(1000);
  auto startTime = system_clock::now();
  while (system_clock::now() - startTime < timeout) {
    faceIn.processEvents();
    usleep(10000);
  }

  // Now express an interest on this new face, and see if onInterest is called.
  CallbackCounter counter;
  // Add the timestamp so it is unique and we don't get a cached response.
  ostringstream component;
  component << "hello" << duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
  Name interestName = Name(prefixName).append(component.str());
  faceOut.expressInterest
    (interestName, bind(&CallbackCounter::onData, &counter, _1, _2),
     bind(&CallbackCounter::onTimeout, &counter, _1));

  // Process events for the in and out faces.
  timeout = milliseconds(10000);
  startTime = system_clock::now();
  while (system_clock::now() - startTime < timeout) {
    faceIn.processEvents();
    faceOut.processEvents();

    bool done = true;
    if (registerCounter.onInterestCallCount_ == 0 &&
        registerCounter.onRegisterFailedCallCount_ == 0)
      // Still processing faceIn.
      done = false;
    if (counter.onDataCallCount_ == 0 && counter.onTimeoutCallCount_ == 0)
      // Still processing face_out.
      done = false;

    if (done)
      break;

    usleep(10000);
  }

  ASSERT_EQ(registerCounter.onRegisterFailedCallCount_, 0) <<
            "Failed to register prefix at all";
  ASSERT_EQ(registerCounter.onInterestCallCount_, 1) <<
            "Expected 1 onInterest callback";
  ASSERT_EQ(counter.onDataCallCount_, 1) <<
            "Expected 1 onData callback";

  // Check the message content.
  Data& data = counter.data_;
  string content("SUCCESS");
  Blob expectedBlob((const uint8_t *)&content[0], content.size());
  ASSERT_TRUE(expectedBlob.equals(data.getContent())) <<
              "Data received on face does not match expected format";
}

class TestFaceInterestMethods : public ::testing::Test {
public:
  TestFaceInterestMethods()
  {
  }

  virtual void
  TearDown()
  {
    face.shutdown();

    // Give time to shut down the face before the next test.
    auto timeout = milliseconds(500);
    auto startTime = system_clock::now();
    while (system_clock::now() - startTime < timeout) {
      face.processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
      usleep(10000);
    }
  }

  Face face;
};

/*
TODO: Replace this with a test that connects to a Face on localhost
def test_specific_interest(self):
  uri = "/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4"
  (dataCallback, timeoutCallback) = self.run_express_name_test(uri)
  self.assertTrue(timeoutCallback.call_count == 0, 'Unexpected timeout on expressed interest')

  // check that the callback was correct
  self.assertEqual(dataCallback.call_count, 1, 'Expected 1 onData callback, got '+str(dataCallback.call_count))

  onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

  // just check that the interest was returned correctly?
  callbackInterest = onDataArgs[0]
  self.assertTrue(callbackInterest.getName().equals(Name(uri)), 'Interest returned on callback had different name')
*/

TEST_F(TestFaceInterestMethods, Timeout)
{
  string uri = "/test123/timeout";
  CallbackCounter counter = runExpressNameTest(face, uri);

  // we're expecting a timeout callback, and only 1
  ASSERT_EQ(counter.onDataCallCount_, 0) << "Data callback called for invalid interest";

  ASSERT_TRUE(counter.onTimeoutCallCount_ == 1) << "Expected 1 timeout call, got " << counter.onTimeoutCallCount_;

  // just check that the interest was returned correctly?
  const Interest& callbackInterest = counter.interest_;
  ASSERT_TRUE(callbackInterest.getName().equals(Name(uri))) << "Interest returned on callback had different name";
}

TEST_F(TestFaceInterestMethods, RemovePending)
{
  Name name("/ndn/edu/ucla/remap/");
  CallbackCounter counter;
  uint64_t interestID = face.expressInterest
    (name, bind(&CallbackCounter::onData, &counter, _1, _2),
     bind(&CallbackCounter::onTimeout, &counter, _1));

  face.removePendingInterest(interestID);

  auto timeout = milliseconds(10000);
  auto startTime = system_clock::now();
  while (system_clock::now() - startTime < timeout &&
         counter.onDataCallCount_ == 0 && counter.onTimeoutCallCount_ == 0) {
    face.processEvents();
    // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
    usleep(10000);
  }

  ASSERT_EQ(counter.onDataCallCount_, 0) << "Should not have called data callback after interest was removed";
  ASSERT_TRUE(counter.onTimeoutCallCount_ == 0) << "Should not have called timeout callback after interest was removed";
}

TEST_F(TestFaceInterestMethods, MaxNdnPacketSize)
{
  // Construct an interest whose encoding is one byte larger than getMaxNdnPacketSize.
  const size_t targetSize = Face::getMaxNdnPacketSize() + 1;
  // Start with an interest which is almost the right size.
  uint8_t componentValue[targetSize];
  Interest interest;
  interest.getName().append(componentValue, targetSize);
  size_t initialSize = interest.wireEncode().size();
  // Now replace the component with the desired size which trims off the extra encoding.
  interest.setName
    (Name().append(componentValue, targetSize - (initialSize - targetSize)));
  size_t interestSize = interest.wireEncode().size();
  ASSERT_EQ(targetSize, interestSize) << "Wrong interest size for MaxNdnPacketSize";
  
  CallbackCounter counter;
  ASSERT_THROW
    (face.expressInterest
     (interest, bind(&CallbackCounter::onData, &counter, _1, _2),
      bind(&CallbackCounter::onTimeout, &counter, _1)),
     runtime_error) <<
    "expressInterest didn't throw an exception when the interest size exceeds getMaxNdnPacketSize()";
}

TEST_F(TestFaceInterestMethods, NetworkNack)
{
  ostringstream uri;
  uri << "/noroute" << duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    // Use a short timeout since we expect an immediate Nack.
  CallbackCounter counter = runExpressNameTest(face, uri.str(), milliseconds(1000), true);

  // We're expecting a network Nack callback, and only 1.
  ASSERT_EQ(0, counter.onDataCallCount_) <<
            "Data callback called for unroutable interest";
  ASSERT_EQ(0, counter.onTimeoutCallCount_) <<
            "Timeout callback called for unroutable interest";
  ASSERT_EQ(1, counter.onNetworkNackCallCount_) <<
            "Expected 1 network Nack call";

  ASSERT_EQ(counter.networkNack_.getReason(), ndn_NetworkNackReason_NO_ROUTE) <<
            "Network Nack has unexpected reason";
}

int
main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

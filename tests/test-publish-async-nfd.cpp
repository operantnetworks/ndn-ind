/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include <cstdlib>
#include <iostream>
#include <time.h>
#include <unistd.h>
#include <ndn-cpp/face.hpp>
#include <ndn-cpp/security/key-chain.hpp>

using namespace std;
using namespace ndn;

class Echo {
public:
  Echo(KeyChain &keyChain, const Name& certificateName)
  : keyChain_(keyChain), certificateName_(certificateName), responseCount_(0)
  { 
  }
  
  // onInterest.
  void operator()
     (const ptr_lib::shared_ptr<const Name>& prefix, 
      const ptr_lib::shared_ptr<const Interest>& interest, Transport& transport,
      uint64_t registeredPrefixId) 
  {
    ++responseCount_;
    
    // Make and sign a Data packet.
    Data data(interest->getName());
    string content(string("Echo ") + interest->getName().toUri());
    data.setContent((const uint8_t *)&content[0], content.size());
    keyChain_.sign(data, certificateName_);
    Blob encodedData = data.wireEncode();

    cout << "Sent content " << content << endl;
    transport.send(*encodedData);
  }
  
  // onRegisterFailed.
  void operator()(const ptr_lib::shared_ptr<const Name>& prefix)
  {
    ++responseCount_;
    cout << "Register failed for prefix " << prefix->toUri() << endl;
  }

  KeyChain keyChain_;
  Name certificateName_;
  int responseCount_;
};

int main(int argc, char** argv)
{
  try {
    Face face("localhost");
        
    // Use the system default key chain and certificate name to sign commands.
    KeyChain keyChain;
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName());
   
    // Also use the default certificate name to sign data packets.
    Echo echo(keyChain, keyChain.getDefaultCertificateName());
    Name prefix("/testecho");
    cout << "Register prefix  " << prefix.toUri() << endl;
    face.registerPrefix(prefix, func_lib::ref(echo), func_lib::ref(echo));
    
    // The main event loop.  
    // Wait forever to receive one interest for the prefix.
    while (echo.responseCount_ < 1) {
      face.processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
      usleep(10000);
    }
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
  return 0;
}

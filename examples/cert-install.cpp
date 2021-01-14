/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020-2021 Operant Networks, Incorporated.
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

#include <iostream>
#include <fstream>
#include <sstream>
#include <ndn-ind/security/pib/pib-sqlite3.hpp>
#include <ndn-ind/encoding/base64.hpp>

using namespace std;
using namespace ndn;

/**
 * Add a certificate from a base64 encoding file to the default PIB. If the PIB
 * identity or key does not exist, create it. Make the added certificate the
 * default certificate for the key. This utility is needed because
 * "ndnsec cert-install" expects the identity with its private key to already
 * exist.
 */
int main(int argc, char* argv[])
{
  string certificateFileName;
  if (argc == 2)
    certificateFileName = argv[1];
  else {
    cout << "usage:" << endl <<
      "cert-install <base64-cert-file>" << endl;
    return 1;
  }

  ifstream file(certificateFileName);
  if (!file) {
    cout << "Can't open file: " << certificateFileName << endl;
    return 1;
  }

  stringstream certificateBase64;
  while (file >> certificateBase64.rdbuf());

  vector<uint8_t> certificateEncoding;
  fromBase64(certificateBase64.str(), certificateEncoding);
  CertificateV2 certificate;
  certificate.wireDecode(certificateEncoding);

  PibSqlite3 pibImpl;
  pibImpl.addCertificate(certificate);
  pibImpl.setDefaultCertificateOfKey(certificate.getKeyName(), certificate.getName());
  cout << "Certificate has been added and set as default for the key:\n  " <<
    certificate.getName() << endl;
  
  return 0;
}

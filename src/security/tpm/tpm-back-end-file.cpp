/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/tpm/tpm-back-end-file.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
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

#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <ndn-ind/encoding/base64.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/security/tpm/tpm-private-key.hpp>
#include <ndn-ind/security/tpm/tpm-key-handle-memory.hpp>
#ifdef NDN_IND_HAVE_BOOST_FILESYSTEM
#include <boost/filesystem.hpp>
#endif
#if defined(_WIN32)
#include <direct.h>
#endif
#include <ndn-ind/security/tpm/tpm-back-end-file.hpp>

using namespace std;

namespace ndn {

TpmBackEndFile::TpmBackEndFile(const string& locationPath)
{
  if (locationPath != "") {
    keyStorePath_ = locationPath;
    if (keyStorePath_[keyStorePath_.size() - 1] == '/' ||
        keyStorePath_[keyStorePath_.size() - 1] == '\\')
      // Strip the ending path separator.
      keyStorePath_.erase(keyStorePath_.size() - 1);
  }
  else {
    // Note: We don't use <filesystem> support because it is not "header-only"
    // and requires linking to libraries.
    const char* home = getenv("HOME");
    if (!home || *home == '\0')
      // Don't expect this to happen;
      home = ".";
    string homeDir(home);
    if (homeDir[homeDir.size() - 1] == '/' || homeDir[homeDir.size() - 1] == '\\')
      // Strip the ending path separator.
      homeDir.erase(homeDir.size() - 1);

    // TODO: Handle non-unix file systems which don't use "/".
    keyStorePath_ = homeDir + "/.ndn/ndnsec-key-file";
  }

  // ::mkdir will work if the parent directory already exists, which is most cases.
#if defined(_WIN32)
  int status = ::_mkdir(keyStorePath_.c_str());
#else
  int status = ::mkdir(keyStorePath_.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
  // EEXIST means the directory already exists, so it's OK.
  if (status != 0 && status != EEXIST) {
    // Can't create the directory with ::mkdir.
#ifdef NDN_IND_HAVE_BOOST_FILESYSTEM
    // Try with create_directories.
    boost::filesystem::create_directories(keyStorePath_);
#else
    throw TpmBackEnd::Error
      (string("TpmBackEndFile: Error '") + strerror(errno) + "' in 'mkdir " + keyStorePath_ +
       "' . Create the parent directory and try again.");
#endif
  }
}

bool
TpmBackEndFile::doHasKey(const Name& keyName) const
{
  {
    ifstream file(toFilePath(keyName).c_str());
    if (!file.good())
      return false;
  }

  try {
    loadKey(keyName);
    return true;
  }
  catch (const runtime_error&) {
    return false;
  }
}

ptr_lib::shared_ptr<TpmKeyHandle>
TpmBackEndFile::doGetKeyHandle(const Name& keyName) const
{
  if (!doHasKey(keyName))
    return ptr_lib::shared_ptr<TpmKeyHandle>();

  return ptr_lib::make_shared<TpmKeyHandleMemory>(loadKey(keyName));
}

ptr_lib::shared_ptr<TpmKeyHandle>
TpmBackEndFile::doCreateKey(const Name& identityName, const KeyParams& params)
{
  ptr_lib::shared_ptr<TpmPrivateKey> key = TpmPrivateKey::generatePrivateKey
    (params);
  ptr_lib::shared_ptr<TpmKeyHandle> keyHandle(new TpmKeyHandleMemory(key));

  setKeyName(*keyHandle, identityName, params);

  try {
    saveKey(keyHandle->getKeyName(), key);
    return keyHandle;
  }
  catch (const runtime_error& e) {
    throw TpmBackEnd::Error(string("Cannot write the key to disk: ") + e.what());
  }
}

void
TpmBackEndFile::doDeleteKey(const Name& keyName)
{
  string keyPath = toFilePath(keyName);

  {
    ifstream file(keyPath.c_str());
    if (!file.good())
      // Already removed.
      return;
  }

  if (remove(keyPath.c_str()) != 0)
    throw TpmBackEnd::Error("Cannot delete the key");
}

Blob
TpmBackEndFile::doExportKey
  (const Name& keyName, const uint8_t* password, size_t passwordLength)
{
  ptr_lib::shared_ptr<TpmPrivateKey> key;
  try {
    key = loadKey(keyName);
  } catch (const std::exception& ex) {
    throw TpmBackEnd::Error(string("Cannot export private key: ") + ex.what());
  }

  if (password)
    return key->toEncryptedPkcs8(password, passwordLength);
  else
    return key->toPkcs8();
}

void
TpmBackEndFile::doImportKey
  (const Name& keyName, const uint8_t* pkcs8, size_t pkcs8Length,
   const uint8_t* password, size_t passwordLength)
{
  ptr_lib::shared_ptr<TpmPrivateKey> key(new TpmPrivateKey());
  try {
    if (password)
      key->loadEncryptedPkcs8(pkcs8, pkcs8Length, password, passwordLength);
    else {
      key->loadPkcs8(pkcs8, pkcs8Length);
    }
  } catch (const TpmPrivateKey::Error& ex) {
    throw TpmBackEnd::Error(string("Cannot import private key: ") + ex.what());
  }

  saveKey(keyName, key);
}

ptr_lib::shared_ptr<TpmPrivateKey>
TpmBackEndFile::loadKey(const Name& keyName) const
{
  ptr_lib::shared_ptr<TpmPrivateKey> key(new TpmPrivateKey());
  ifstream file(toFilePath(keyName).c_str());
  stringstream base64;
  base64 << file.rdbuf();
  vector<uint8_t> pkcs;
  fromBase64(base64.str(), pkcs);

  key->loadPkcs1(&pkcs.front(), pkcs.size());
  return key;
}

void
TpmBackEndFile::saveKey
  (const Name& keyName, const ptr_lib::shared_ptr<TpmPrivateKey>& key)
{
  string filePath = toFilePath(keyName);
  ofstream file(filePath.c_str());
  file << toBase64(*key->toPkcs1(), true);

  // Set the file permissions.
#if !defined(_WIN32) // Windows doesn't have Unix group permissions.
  ::chmod(filePath.c_str(), S_IRUSR);
#endif
}

string
TpmBackEndFile::toFilePath(const Name& keyName) const
{
  Blob keyEncoding = keyName.wireEncode();
  uint8_t digest[ndn_SHA256_DIGEST_SIZE];
  CryptoLite::digestSha256(keyEncoding, digest);

  return keyStorePath_ + "/" + Blob(digest, sizeof(digest)).toHex() + ".privkey";
}

}

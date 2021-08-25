/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
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

#ifndef NDN_X509_CERTIFICATE_INFO_HPP
#define NDN_X509_CERTIFICATE_INFO_HPP

#include "../../name.hpp"
#include "../../util/signed-blob.hpp"
#include "../validity-period.hpp"

namespace ndn {

class DerNode;

/**
 * An X509CertificateInfo holds the fields from decoding an X.509 certificate.
 */
class X509CertificateInfo {
public:
  /**
   * Create an X509CertificateInfo by decoding an X.509 certificate.
   * @param encoding The encoded X.509 certificate.
   * @throws runtime_error for error decoding the certificate.
   */
  X509CertificateInfo(const Blob& encoding);

  /**
   * Create an X509CertificateInfo from the given values. This sets the serial
   * number to 0. You can use getEncoding() to get the X.509 certificate.
   * @param issuerName The issuer name, which is converted according to
   * makeX509Name(). If the name doesn't start with /x509, then it should
   * follow conventions for an NDN key name.
   * @param validityPeriod The validity period.
   * @param subjectName The subject name, which is converted according to
   * makeX509Name(). If the name doesn't start with /x509, then it should
   * follow conventions for an NDN certificate name.
   * @param publicKey The bytes of the public key DER.
   * @param signatureValue The bytes of the signature value. This assumes the
   * algorithm is RSA with SHA-256.
   * @param serialNumber (optional) The serial number as a Blob with the bytes
   * of the integer. If omitted use a single byte of 00. The first bytes must be
   * >= 0x80. (Negative serial numbers are not supported.)
   */
  X509CertificateInfo
    (const Name& issuerName, const ValidityPeriod& validityPeriod,
     const Name& subjectName, const Blob& publicKey, const Blob& signatureValue,
     const Blob& serialNumber = Blob((const uint8_t*)"\0", 1));

  /**
   * Get the SignedBlob of the encoding with the offsets for the signed portion.
   * @return The SignedBlob of the encoding.
   */
  const SignedBlob&
  getEncoding() const { return signedEncoding_; }

  /**
   * Get the serial number.
   * @return The serial number as a Blob with the bytes of the integer.
   */
  const Blob&
  getSerialNumber() const { return serialNumber_; }

  /**
   * Get the issuer name which has been converted to an NDN name.
   * @return The issuer name.
   */
  const Name&
  getIssuerName() const { return issuerName_; }

  /**
   * Get the validity period
   * @return The validity period.
   */
  const ValidityPeriod&
  getValidityPeriod() const { return validityPeriod_; }

  /**
   * Get the subject name which has been converted to an NDN name.
   * @return The subject name.
   */
  const Name&
  getSubjectName() const { return subjectName_; }

  /**
   * Get the public key DER encoding.
   * @return The DER encoding Blob.
   */
  const Blob&
  getPublicKey() const { return publicKey_; }

  /**
   * Get the signature value bytes.
   * @return The signature value.
   */
  const Blob&
  getSignatureValue() const { return signatureValue_; }

  /**
   * In the extensions find the X509v3 CRL Distribution Points extension and get
   * the first fullname URI.
   * @return The CRL distribution URI, or "" if not found.
   */
  const std::string&
  getCrlDistributionUri() const { return crlDistributionUri_; }

  /**
   * Check if the Name has two components and the first component is "x509". The
   * second component should be the encoding of the X.509 name.
   * @param name The Name to check.
   * @return True if name is an encapsulated X.509 name.
   */
  static bool
  isEncapsulatedX509(const Name& name)
  {
    return name.size() == 2 && name.get(0).equals(getX509_COMPONENT());
  }

  /**
   * Make an NDN Name from the URI field in the Subject Alternative Names
   * extension, if available. Otherwise make an NDN name that encapsulates the
   * X.509 name, where the first component is "x509" and the second is the
   * encoded X.509 name. This should be the reverse operation of makeX509Name().
   * @param x509Name The DerNode of the X.509 name, used if extensions is null
   * or doesn't have a URI field in the Subject Alternative Names.
   * @param extensions The DerNode of the extensions (the only child of the
   * DerExplicit node with tag 3). If this is null, don't use it.
   * @return The NDN Name.
   */
  static Name
  makeName(DerNode* x509Name, DerNode* extensions);

  /**
   * If the Name has two components and the first is "x509" (see
   * isEncapsulatedX509), then return a DerNode made from the second component.
   * Otherwise, return a DerNode which is a short representation of the Name,
   * and update the extensions by adding a Subject Alternative Names extension
   * with a URI field for the NDN Name. This should be the reverse operation of
   * makeName().
   * @param name The NDN name.
   * @param extensions The DerNode of the extensions (the only child of the
   * DerExplicit node with tag 3). If the NDN Name is not an encapsulated X.509
   * name, then add the Subject Alternative Names extensions (without first
   * checking if extensions already has one). If this is null, don't use it.
   * @return A DerNode of the X.509 name.
   */
  static ptr_lib::shared_ptr<DerNode>
  makeX509Name(const Name& name, DerNode* extensions);

  /**
   * In the extensions, find the X509v3 CRL Distribution Points extension and
   * get the first fullname URI.
   * @param extensions The DerNode of the extensions (the only child of the
   * DerExplicit node with tag 3). If this is null, don't use it and return "".
   * @return The first fullname URI in the distributionPoint, or "" if not found.
   */
  static std::string
  findCrlDistributionUri(DerNode* extensions);

  /**
   * Get the name component for "x509". This is a method because not all C++
   * environments support static constructors.
   * @return The name component for "KEY".
   */
  static const Name::Component&
  getX509_COMPONENT();

private:
  ptr_lib::shared_ptr<DerNode> root_;
  SignedBlob signedEncoding_;
  Blob serialNumber_;
  Name issuerName_;
  ValidityPeriod validityPeriod_;
  Name subjectName_;
  Blob publicKey_;
  Blob signatureValue_;
  std::string crlDistributionUri_;
  static Name::Component* X509_COMPONENT;
};

}

#endif

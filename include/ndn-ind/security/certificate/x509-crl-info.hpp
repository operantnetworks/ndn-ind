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

#ifndef NDN_X509_CRL_INFO_HPP
#define NDN_X509_CRL_INFO_HPP

#include "../../name.hpp"
#include "../../util/signed-blob.hpp"

namespace ndn {

class DerNode;

/**
 * An X509CrlInfo holds the fields from decoding an X.509 Certificate Revocation
 * List (CRL).
 */
class X509CrlInfo {
public:
  /**
   * A RevokedCertificate holds the serial number and other information in the
   * entry of a CRL's list of revoked certificates.
   */
  class RevokedCertificate {
  public:
    /**
     * Create a RevokedCertificate with the given values.
     * @param serialNumber The revoked certificate's serial number as a Blob
     * with the bytes of the integer.
     * @param revocationDate The revocation date.
     */
    RevokedCertificate
      (const Blob& serialNumber,
       std::chrono::system_clock::time_point revocationDate)
    : serialNumber_(serialNumber),
      revocationDate_(revocationDate)
    {
    }

    /**
     * Get this entry's serial number.
     * @return The serial number as a Blob with the bytes of the integer.
     */
    const Blob&
    getSerialNumber() const { return serialNumber_; }

    /**
     * Get this entry's revocation date.
     * @return The revocation date.
     */
    std::chrono::system_clock::time_point
    getRevocationDate() const { return revocationDate_; }

  private:
    Blob serialNumber_;
    std::chrono::system_clock::time_point revocationDate_;
  };

  /**
   * Create an X509CrlInfo by decoding an X.509 CRL.
   * @param encoding The encoded X.509 CRL.
   * @throws runtime_error for error decoding the CRL.
   */
  X509CrlInfo(const Blob& encoding);

  /**
   * Get the SignedBlob of the encoding with the offsets for the signed portion.
   * @return The SignedBlob of the encoding.
   */
  const SignedBlob&
  getEncoding() const { return signedEncoding_; }

  /**
   * Get the issuer name which has been converted to an NDN name.
   * @return The issuer name.
   */
  const Name&
  getIssuerName() const { return issuerName_; }

  /**
   * Get the thisUpdate time.
   * @return The thisUpdate time.
   */
  std::chrono::system_clock::time_point
  getThisUpdate() const { return thisUpdate_; }

  /**
   * Get the nextUpdate time.
   * @return The nextUpdate time.
   */
  std::chrono::system_clock::time_point
  getNextUpdate() const { return nextUpdate_; }

  /**
   * Get the number of entries in the revoked certificates list.
   * @return The number of revoked certificate entries.
   */
  size_t
  getRevokedCertificateCount() const { return revokedCertificates_.size(); }

  /**
   * Get the revoked certificate entry at the given index.
   * @param i The index of the revoked certificate entry, starting from 0.
   * @return The entry at the index.
   * @throws runtime_error If i is out of range.
   */
  const RevokedCertificate&
  getRevokedCertificate(size_t i) const;

  /**
   * Get the signature value bytes.
   * @return The signature value.
   */
  const Blob&
  getSignatureValue() const { return signatureValue_; }

private:
  ptr_lib::shared_ptr<DerNode> root_;
  SignedBlob signedEncoding_;
  Name issuerName_;
  std::chrono::system_clock::time_point thisUpdate_;
  std::chrono::system_clock::time_point nextUpdate_;
  std::vector<RevokedCertificate> revokedCertificates_;
  Blob signatureValue_;
};

}

#endif

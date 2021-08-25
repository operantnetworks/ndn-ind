/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
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

#ifndef NDN_X509_CRL_FETCHER_HPP
#define NDN_X509_CRL_FETCHER_HPP

#include "../../face.hpp"
#include "validator.hpp"
#include "../certificate/x509-crl-info.hpp"

namespace ndn {

/**
 * An X509CrlFetcher sends periodic Interests to fetch the latest embedded X.509
 * CRL for a particular issuer from a particular CRL publisher (whose prefix is
 * different from the CRL issuer). See the constructor for details.
 */
class X509CrlFetcher {
public:
  /**
   * Create a X509CrlFetcher for the given issuer and publisher prefix. This
   * immediately uses the Face to send the first _latest Interest to the CRL
   * publisher: <crlPublisherPrefix>/crl/<issuerName>/_latest . When a new
   * CRL arrives and is validated, call validator.cacheVerifiedCrl which will
   * evict any certificates on the revocation list and will save the CRL for
   * checking if new certificates are revoked. (Note that cacheVerifiedCrl is
   * a method of CertificateStorage which is a base class of Validator.) You
   * must create a X509CrlFetcher object (separate from the Validator) which
   * must remain valid for the duration of your application. If you want to
   * delete the X509CrlFetcher before the end of your application, you should
   * call shutdown().
   * @param issuerName The encapsulated X.509 issuer name of the CRL.
   * @param crlPublisherPrefix The NDN prefix for sending _latest Interests and
   * Interests to fetch the CRL. (This is different from the CRL issuer which
   * is an encapsulated X.509 name and not routable.)
   * @param face The Face for sending Interests.
   * @param validator The Validator for checking the signature on the _latest
   * Data packet from the CRL publisher, and for getting the CRL issuer's
   * public key, and for calling cacheVerifiedCrl.
   * @param checkForNewCrlInterval The interval between sending a _latest
   * Interest to the CRL publisher to check for a new CRL.
   * @param noResponseWarningInterval If there is no response from the CRL
   * publisher after this interval, log a message each time the Interest times
   * out.
   */
  X509CrlFetcher
    (const Name& issuerName, const Name& crlPublisherPrefix, Face* face,
     Validator* validator, std::chrono::nanoseconds checkForNewCrlInterval,
     std::chrono::nanoseconds noResponseWarningInterval)
  : impl_(new Impl
      (issuerName, crlPublisherPrefix, face, validator, checkForNewCrlInterval,
       noResponseWarningInterval))
  {
    impl_->start();
  }

  /**
   * Get the issuer name for this CRL manager.
   * @return The issuer Name.
   */
  const Name&
  getIssuerName() const { return impl_->getIssuerName(); }

  /**
   * Shut down this X509CrlFetcher and stop sending _latest Interests to fetch
   * a new CRL.
   */
  void
  shutdown() { impl_->shutdown(); }

  static const int N_RETRIES = 3;

private:
  /**
   * X509CrlFetcher::Impl does the work of X509CrlFetcher. It is a separate
   * class so that X509CrlFetcher can create an instance in a shared_ptr to use
   * in callbacks.
   */
  class Impl : public ptr_lib::enable_shared_from_this<Impl> {
  public:
    /**
     * Create a new Impl, which should belong to a shared_ptr. Then you must
     * call start(). See the X509CrlFetcher constructor for parameter
     * documentation.
     */
    Impl
      (const Name& issuerName, const Name& crlPublisherPrefix, Face* face,
       Validator* validator, std::chrono::nanoseconds checkForNewCrlInterval,
       std::chrono::nanoseconds noResponseWarningInterval);

    void
    start() { checkForNewCrl(); }

    const Name&
    getIssuerName() const { return issuerName_; }

    void
    shutdown()
    {
      isEnabled_ = false;
      if (crlPendingInterestId_ > 0)
        face_->removePendingInterest(crlPendingInterestId_);
    }

  private:
    /**
     * Send an interest for the crlLatestPrefix_ to get the name of the latest
     * CRL, and schedule sending the next one after checkForNewCrlInterval_.
     * If it doesn't match currentCrlName_, then call fetchCrl().
     */
    void
    checkForNewCrl();

    /**
     * Fetch the segment Data packets <newCrlName>/<segment> .  We don't expect
     * the CRL to have too many segments or need to be fetched with millisecond
     * efficiency, so fetch segments one at a time.
     * @param newCrlName The name of the CRL to fetch.
     * @param expectedSegment The expected segment number. On the first call, use 0.
     * @param nTriesLeft If fetching times out, decrement nTriesLeft and try
     * again until it is zero.
     * @param segments A shared_ptr to a vector where we append each segment Blob
     * as it comes in. On the first call, use ptr_lib::make_shared<vector<Blob> >() .
     */
    void
    fetchCrl
      (const Name& newCrlName, int expectedSegment, int nTriesLeft,
       const ptr_lib::shared_ptr<std::vector<Blob> >& segments);

    /**
     * Validate the CRL signature, then set currentCrlName_ to newCrlName.
     * @param newCrlName The name of the CRL that was fetched.
     * @param crlInfo The X509CrlInfo of the fetched and decoded CRL.
     */
    void
    validateAndProcessNewCrl
      (const Name& newCrlName, const ptr_lib::shared_ptr<X509CrlInfo>& crlInfo);

    /**
     * This is called on a timeout or network nack from the publisher to log a
     * warning if more than noResponseWarningInterval_ has elapsed since
     * lastResponseTime_ .
     */
    void
    maybeLogResponseWarning();

    Name issuerName_;
    Name crlPublisherPrefix_;
    Face* face_;
    Validator* validator_;
    std::chrono::nanoseconds checkForNewCrlInterval_;
    std::chrono::nanoseconds noResponseWarningInterval_;
    Name currentCrlName_;

    bool isEnabled_;
    bool isCrlRetrievalInProgress_;
    Name crlLatestPrefix_;
    uint64_t crlPendingInterestId_;
    std::chrono::system_clock::time_point lastResponseTime_;
  };

  ptr_lib::shared_ptr<Impl> impl_;
};

}

#endif

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Regents of the University of California.
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

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/security/verification-helpers.hpp>
#include <ndn-ind/security/v2/x509-crl-fetcher.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn::func_lib;

INIT_LOGGER("ndn.X509CrlFetcher");

namespace ndn {

X509CrlFetcher::Impl::Impl
  (const Name& issuerName, const Name& crlPublisherPrefix, Face* face,
   Validator* validator, std::chrono::nanoseconds checkForNewCrlInterval,
   std::chrono::nanoseconds noResponseWarningInterval)
: issuerName_(issuerName),
  face_(face),
  crlPublisherPrefix_(crlPublisherPrefix),
  validator_(validator),
  checkForNewCrlInterval_(checkForNewCrlInterval),
  noResponseWarningInterval_(noResponseWarningInterval),
  isCrlRetrievalInProgress_(false),
  isEnabled_(true),
  crlPendingInterestId_(0)
{
  crlLatestPrefix_ = Name(crlPublisherPrefix)
    .append("crl")
    .append(issuerName.wireEncode())
    .append("_latest");
  lastResponseTime_ = system_clock::now();
}

void
X509CrlFetcher::Impl::checkForNewCrl()
{
  if (!isEnabled_)
    // shutdown() set this false.
    return;

  // Schedule the next check now.
  face_->callLater
    (checkForNewCrlInterval_,
     bind(&X509CrlFetcher::Impl::checkForNewCrl, shared_from_this()));

  if (isCrlRetrievalInProgress_)
    // Already checking.
    return;
  isCrlRetrievalInProgress_ = true;

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<X509CrlFetcher::Impl>& parent)
    : parent_(parent)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<Data>& crlLatestData)
    {
      parent_->lastResponseTime_ = system_clock::now();

      // Validate the Data signature.
      parent_->validator_->validate(
        *crlLatestData,
        [=](auto&) {
          Name newCrlName;
          try {
            newCrlName.wireDecode(crlLatestData->getContent());
          } catch (const std::exception& ex) {
            parent_->isCrlRetrievalInProgress_ = false;
            _LOG_ERROR("Error decoding CRL name in: " << crlLatestData->getName().toUri());
            return;
          }

          if (newCrlName.equals(parent_->currentCrlName_)) {
            // The latest is the same name, so do nothing.
            _LOG_TRACE("Got CRL _latest response with same CRL name: " << newCrlName.toUri());
            parent_->isCrlRetrievalInProgress_ = false;
            return;
          }

          // Leave isCrlRetrievalInProgress_ true.
          parent_->fetchCrl
            (newCrlName, 0, N_RETRIES, ptr_lib::make_shared<vector<Blob> >());
        },
        [=](auto&, auto& error) {
          parent_->isCrlRetrievalInProgress_ = false;
          _LOG_ERROR("Validate CRL _latest Data failure: " << error.toString());
        });
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->isCrlRetrievalInProgress_ = false;
      _LOG_ERROR("Timeout for CRL _latest packet: " << interest->getName().toUri());
      parent_->maybeLogResponseWarning();
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->isCrlRetrievalInProgress_ = false;
      ostringstream message;
      _LOG_ERROR("Network nack for CRL _latest packet: " << interest->getName().toUri() <<
        ". Got NACK (" << networkNack->getReason() << ")");
      parent_->maybeLogResponseWarning();
    }

    ptr_lib::shared_ptr<X509CrlFetcher::Impl> parent_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this());
    face_->expressInterest
      (Interest(crlLatestPrefix_).setMustBeFresh(true).setCanBePrefix(true),
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
    _LOG_TRACE("Sent CRL _latest Interest " << crlLatestPrefix_.toUri());
  } catch (const std::exception& ex) {
    isCrlRetrievalInProgress_ = false;
    _LOG_ERROR("expressInterest error: " << ex.what());
  }
}

void
X509CrlFetcher::Impl::fetchCrl
  (const Name& newCrlName, int expectedSegment, int nTriesLeft,
   const ptr_lib::shared_ptr<vector<Blob> >& segments)
{
  Name crlSegmentName(newCrlName);
  crlSegmentName.appendSegment(expectedSegment);

  _LOG_TRACE("Fetching CRL segment " << crlSegmentName);

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks
      (const ptr_lib::shared_ptr<X509CrlFetcher::Impl>& parent,
       const Name& newCrlName, int expectedSegment, int nTriesLeft,
       const ptr_lib::shared_ptr<vector<Blob> >& segments)
    : parent_(parent), newCrlName_(newCrlName), expectedSegment_(expectedSegment),
      nTriesLeft_(nTriesLeft), segments_(segments)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& crlSegmentInterest,
       const ptr_lib::shared_ptr<Data>& segmentData)
    {
      try {
        parent_->crlPendingInterestId_ = 0;
        parent_->lastResponseTime_ = system_clock::now();

        if (!segmentData->getName().get(-1).isSegment()) {
          parent_->isCrlRetrievalInProgress_ = false;
          _LOG_ERROR("fetchCrl: The CRL segment Data packet name does not end in a segment: " <<
                     segmentData->getName().toUri());
          return;
        }
        int segment = segmentData->getName().get(-1).toSegment();
        if (segment != expectedSegment_) {
          // Since we fetch in sequence, we don't expect this.
          parent_->isCrlRetrievalInProgress_ = false;
          _LOG_ERROR("fetchCrl: Expected segment " << expectedSegment_ <<
            ", but got " << segmentData->getName().toUri());
          return;
        }

        int finalBlockId = -1;
        if (segmentData->getMetaInfo().getFinalBlockId().getValue().size() > 0)
          finalBlockId = segmentData->getMetaInfo().getFinalBlockId().toSegment();
        if (segment == finalBlockId) {
          // Finished. Concatenate the CRL segments.
          segments_->push_back(segmentData->getContent());
          size_t totalSize = 0;
          for (size_t i = 0; i < segments_->size(); ++i)
            totalSize += segments_->at(i).size();

          ptr_lib::shared_ptr<vector<uint8_t> > buffer =
            ptr_lib::make_shared<vector<uint8_t> >(totalSize);
          size_t offset = 0;
          for (size_t i = 0; i < segments_->size(); ++i) {
            const Blob& segment = segments_->at(i);
            memcpy(&(*buffer)[offset], segment.buf(), segment.size());
            offset += segment.size();
          }

          // Decode and process the CRL.
          // Leave isCrlRetrievalInProgress_ true.
          parent_->validateAndProcessNewCrl
            (newCrlName_, ptr_lib::make_shared<X509CrlInfo>(Blob(buffer, false)));

          // This CRL has been processed, so allow checking for new CRLs.
          parent_->isCrlRetrievalInProgress_ = false;
          return;
        }

        // Save the segment and fetch the next one.
        segments_->push_back(segmentData->getContent());
        parent_->fetchCrl(newCrlName_, expectedSegment_ + 1, N_RETRIES, segments_);
      } catch (const std::exception& ex) {
        parent_->isCrlRetrievalInProgress_ = false;
        _LOG_ERROR("Error in fetchCrl onData: " << ex.what());
      }
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      parent_->crlPendingInterestId_ = 0;
      if (nTriesLeft_ > 1)
        parent_->fetchCrl
          (newCrlName_, expectedSegment_, nTriesLeft_ - 1, segments_);
      else {
        parent_->isCrlRetrievalInProgress_ = false;
        _LOG_ERROR("Retrieval of CRL segment [" << interest->getName().toUri() <<
                   "] timed out");
        parent_->maybeLogResponseWarning();
      }
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      parent_->crlPendingInterestId_ = 0;
      parent_->isCrlRetrievalInProgress_ = false;
      _LOG_ERROR("Retrieval of CRL segment [" << interest->getName().toUri() <<
        "] failed. Got NACK (" << networkNack->getReason() << ")");
      parent_->maybeLogResponseWarning();
    }

    ptr_lib::shared_ptr<X509CrlFetcher::Impl> parent_;
    Name newCrlName_;
    int expectedSegment_;
    int nTriesLeft_;
    ptr_lib::shared_ptr<vector<Blob> > segments_;
  };

  try {
    // We make a shared_ptr object since it needs to exist after we return, and
    // pass shared_from_this() to keep a pointer to this Impl.
    ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
      (shared_from_this(), newCrlName, expectedSegment, nTriesLeft, segments);
    crlPendingInterestId_ = face_->expressInterest
      (Interest(crlSegmentName).setMustBeFresh(false).setCanBePrefix(true),
       bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    isCrlRetrievalInProgress_ = false;
    _LOG_ERROR("expressInterest error: " << ex.what());
  }
}

void
X509CrlFetcher::Impl::validateAndProcessNewCrl
  (const Name& newCrlName, const ptr_lib::shared_ptr<X509CrlInfo>& crlInfo)
{
  if (crlInfo->getIssuerName() != issuerName_) {
    // This shouldn't happen, but we check anyway.
    _LOG_ERROR("The fetched CRL issuer name is not the expected name: Not adding CRL from issuer " <<
      crlInfo->getIssuerName().toUri());
    return;
  }
  
  // Right now, we only support a CRL which is signed by a trust anchor because
  // the issuer name is an encapsulated X.509 name and not routable, so it must
  // already be present as the trust anchor.
  // Get the issuer certificate (the self-signed trust anchor) and use it to
  // validate the CRL.
  ptr_lib::shared_ptr<CertificateV2> issuerCertificate =
    validator_->getTrustAnchors().find(crlInfo->getIssuerName());
  if (!issuerCertificate) {
    // This shouldn't happen, but we check anyway.
    _LOG_ERROR("CRL issuer's certificate is not in the trust anchors: Not adding CRL from issuer " <<
      crlInfo->getIssuerName().toUri());
    return;
  }
  if (!VerificationHelpers::verifySignature
      (crlInfo->getEncoding().signedBuf(), crlInfo->getEncoding().signedSize(),
       crlInfo->getSignatureValue().buf(), crlInfo->getSignatureValue().size(),
       issuerCertificate->getPublicKey())) {
    _LOG_ERROR("CRL signature validation failure: Not adding CRL from issuer " <<
      crlInfo->getIssuerName().toUri());
    return;
  }

  // The CRL signature is valid. Save the current name, meaning that we have
  // successfully fetched it from the CRL publisher. cacheVerifiedCrl may
  // discover that the CRL has a bad validity period but that is not our
  // concern here. No matter what, we will just wait for a new version from the
  // CRL publisher.
  currentCrlName_ = newCrlName;

  // cacheVerifiedCrl checks the CRL validity period, saves the CRL and checks
  // if currently stored certificates are revoked.
  // This copies the crlInfo.
  validator_->cacheVerifiedCrl(*crlInfo);
}

void
X509CrlFetcher::Impl::maybeLogResponseWarning()
{
  auto elapsed = system_clock::now() - lastResponseTime_;
  if (elapsed > noResponseWarningInterval_)
    _LOG_WARN("CRL ALARM: No response in " <<
      (duration_cast<minutes>(elapsed).count() / 60.0) <<
      " hours from the CRL publisher at " << crlPublisherPrefix_.toUri());
}

}

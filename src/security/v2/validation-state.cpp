/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/v2/validation-state.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. In verifyOriginalPacket, check CRL.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-state.cpp
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

#include <stdexcept>
#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/security/verification-helpers.hpp>
#include <ndn-ind/security/v2/certificate-storage.hpp>
#include <ndn-ind/security/v2/validation-state.hpp>

INIT_LOGGER("ndn.ValidationState");

using namespace std;

namespace ndn {

ValidationState::~ValidationState() {}

void
ValidationState::setOutcome(bool outcome)
{
  if (hasOutcome_)
    throw runtime_error("The ValidationState already has an outcome");

  hasOutcome_ = true;
  outcome_ = outcome;
}

ptr_lib::shared_ptr<CertificateV2>
ValidationState::verifyCertificateChain
  (const ptr_lib::shared_ptr<CertificateV2>& trustedCertificate)
{
  ptr_lib::shared_ptr<CertificateV2> validatedCertificate = trustedCertificate;
  for (size_t i = 0; i < certificateChain_.size(); ++i) {
    ptr_lib::shared_ptr<CertificateV2> certificateToValidate =
      certificateChain_[i];

    if (!VerificationHelpers::verifyDataSignature
        (*certificateToValidate, *validatedCertificate)) {
      fail(ValidationError(ValidationError::INVALID_SIGNATURE,
           "Invalid signature of certificate `" +
           certificateToValidate->getName().toUri() + "`"));
      certificateChain_.erase
        (certificateChain_.begin() + i, certificateChain_.end());
      return ptr_lib::shared_ptr<CertificateV2>();
    }
    else {
      _LOG_TRACE("OK signature for certificate `" << certificateToValidate->getName() << "`");
      validatedCertificate = certificateToValidate;
    }
  }

  return validatedCertificate;
}

DataValidationState::DataValidationState
  (const Data& data, const DataValidationSuccessCallback& successCallback,
   const DataValidationFailureCallback& failureCallback)
: successCallback_(successCallback),
  failureCallback_(failureCallback)
{
  // Make a copy.
  if (dynamic_cast<const CertificateV2*>(&data))
    data_ = ptr_lib::make_shared<CertificateV2>(data);
  else
    data_ = ptr_lib::make_shared<Data>(data);

  if (!successCallback_)
    throw runtime_error("The successCallback is null");
  if (!failureCallback_)
    throw runtime_error("The failureCallback is null");
}

void
DataValidationState::verifyOriginalPacket
  (const CertificateV2& trustedCertificate,
   const CertificateStorage* certificateStorage)
{
  if (VerificationHelpers::verifyDataSignature(*data_, trustedCertificate)) {
    CertificateV2* originalCertificate = dynamic_cast<CertificateV2*>(data_.get());
    if (certificateStorage && originalCertificate) {
      // The original packet is a certificate. Check if the issuer has revoked it.
      const X509CrlInfo::RevokedCertificate* revoked =
        certificateStorage->findRevokedCertificate
          (originalCertificate->getIssuerName(), originalCertificate->getX509SerialNumber());
      if (revoked) {
        fail(ValidationError(ValidationError::REVOKED,
          "The CRL from issuer " + originalCertificate->getIssuerName().toUri() +
          " has revoked serial number " + revoked->getSerialNumber().toHex() +
          " at time " + toIsoString(revoked->getRevocationDate()) +
          ". Rejecting certificate " + originalCertificate->getName().toUri()));
        return;
      }
    }

    _LOG_TRACE("OK signature for data `" << data_->getName() << "`");
    try {
      successCallback_(*data_);
    } catch (const std::exception& ex) {
      _LOG_ERROR("DataValidationState::fail: Error in successCallback: " << ex.what());
    } catch (...) {
      _LOG_ERROR("DataValidationState::fail: Error in successCallback.");
    }
    setOutcome(true);
  }
  else
    fail(ValidationError(ValidationError::INVALID_SIGNATURE,
      "Invalid signature of data `" + data_->getName().toUri() + "`"));
}

void
DataValidationState::bypassValidation()
{
  _LOG_TRACE("Signature verification bypassed for data `" << data_->getName()
             << "`");
  try {
    successCallback_(*data_);
  } catch (const std::exception& ex) {
    _LOG_ERROR("DataValidationState::fail: Error in successCallback: " << ex.what());
  } catch (...) {
    _LOG_ERROR("DataValidationState::fail: Error in successCallback.");
  }
  setOutcome(true);
}

void
DataValidationState::fail(const ValidationError& error)
{
  _LOG_TRACE(error);
  try {
    failureCallback_(*data_, error);
  } catch (const std::exception& ex) {
    _LOG_ERROR("DataValidationState::fail: Error in failureCallback: " << ex.what());
  } catch (...) {
    _LOG_ERROR("DataValidationState::fail: Error in failureCallback.");
  }
  setOutcome(false);
}

InterestValidationState::InterestValidationState
  (const Interest& interest,
   const InterestValidationSuccessCallback& successCallback,
   const InterestValidationFailureCallback& failureCallback)
: interest_(interest),
  failureCallback_(failureCallback)
{
  successCallbacks_.push_back(successCallback);
  if (!successCallback)
    throw runtime_error("The successCallback is null");
  if (!failureCallback_)
    throw runtime_error("The failureCallback is null");
}

void
InterestValidationState::verifyOriginalPacket
  (const CertificateV2& trustedCertificate,
   const CertificateStorage* certificateStorage)
{
  if (VerificationHelpers::verifyInterestSignature(interest_, trustedCertificate)) {
    _LOG_TRACE("OK signature for interest `" << interest_.getName() << "`");
    for (size_t i = 0; i < successCallbacks_.size(); ++i) {
      try {
        successCallbacks_[i](interest_);
      } catch (const std::exception& ex) {
        _LOG_ERROR("InterestValidationState::fail: Error in successCallback: " << ex.what());
      } catch (...) {
        _LOG_ERROR("InterestValidationState::fail: Error in successCallback.");
      }
    }
    setOutcome(true);
  }
  else
    fail(ValidationError(ValidationError::INVALID_SIGNATURE,
      "Invalid signature of interest `" + interest_.getName().toUri() + "`"));
}

void
InterestValidationState::bypassValidation()
{
  _LOG_TRACE("Signature verification bypassed for interest `" <<
             interest_.getName() << "`");
  for (size_t i = 0; i < successCallbacks_.size(); ++i) {
    try {
      successCallbacks_[i](interest_);
    } catch (const std::exception& ex) {
      _LOG_ERROR("InterestValidationState::fail: Error in successCallback: " << ex.what());
    } catch (...) {
      _LOG_ERROR("InterestValidationState::fail: Error in successCallback.");
    }
  }
  setOutcome(true);
}

void
InterestValidationState::fail(const ValidationError& error)
{
  _LOG_TRACE(error);
  try {
    failureCallback_(interest_, error);
  } catch (const std::exception& ex) {
    _LOG_ERROR("InterestValidationState::fail: Error in failureCallback: " << ex.what());
  } catch (...) {
    _LOG_ERROR("InterestValidationState::fail: Error in failureCallback.");
  }
  setOutcome(false);
}

}

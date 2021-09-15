/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp-tools/usersync/generalized-content.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Use std::chrono.
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

#ifndef NDN_GENERALIZED_CONTENT_HPP
#define NDN_GENERALIZED_CONTENT_HPP

#include <ndn-ind/face.hpp>
#include <ndn-ind/util/segment-fetcher.hpp>
#include <ndn-ind/util/memory-content-cache.hpp>
#include "content-meta-info.hpp"

namespace ndntools {

/**
 * GeneralizedContent has the static publish and fetch methods which fetches meta
 * info and segmented content. See the methods for more detail.
 * @note The support for GeneralizedContent is experimental and the API is not finalized.
 */
class ndn_ind_tools_dll GeneralizedContent : public ndn::ptr_lib::enable_shared_from_this<GeneralizedContent> {
public:
  enum ErrorCode {
    // Repeat the error codes from SegmentFetcher.
    INTEREST_TIMEOUT = 1,
    DATA_HAS_NO_SEGMENT = 2,
    SEGMENT_VERIFICATION_FAILED = 3,

    META_INFO_DECODING_FAILED = 4
  };

  typedef ndn::func_lib::function<void
    (const ndn::ptr_lib::shared_ptr<ContentMetaInfo>& metaInfo,
     const ndn::Blob& content)> OnComplete;

  typedef ndn::func_lib::function<void
    (ErrorCode errorCode, const std::string& message)> OnError;

  /**
   * Use the contentCache to publish a Data packet named [prefix]/_meta whose
   * content is the encoded metaInfo. If metaInfo.getHasSegments() is true then
   * use the contentCache to publish the segments of the content.
   * @param contentCache This calls contentCache.add to add the Data packets.
   * After this call, the MemoryContentCache must remain valid long enough to
   * respond to Interest for the published Data packets.
   * @param prefix The Name prefix for the published Data packets.
   * @param freshnessPeriod The freshness period for the packets.
   * @param signingKeyChain This calls signingKeyChain.sign to sign the packets.
   * @param signingCertificateName The certificate name of the key used in
   * signingKeyChain.sign .
   * @param metaInfo The ContentMetaInfo for the _meta packet.
   * @param content The content which is segmented and published. If
   * metaInfo.getHasSegments() is false then this is ignored.
   * @param contentSegmentSize The the number of bytes for each segment of the
   * content. (This is is the size of the content in the segment Data packet,
   * not the size of the entire segment Data packet with overhead.) The final
   * segment may be smaller than this. If metaInfo.getHasSegments() is false
   * then this is ignored.
   */
  static void
  publish
    (ndn::MemoryContentCache& contentCache, const ndn::Name& prefix,
     std::chrono::nanoseconds freshnessPeriod, ndn::KeyChain* signingKeyChain,
     const ndn::Name& signingCertificateName, const ContentMetaInfo& metaInfo,
     const ndn::Blob& content, size_t contentSegmentSize);

  /**
   * Initiate meta info and segmented content fetching. This first fetches and
   * decodes <prefix>/_meta . If the ContentSize in the _meta info is not zero
   * then also fetch segments such as <prefix>/%00 .
   * @param face This calls face.expressInterest to fetch the _meta info and
   * segments.
   * @param prefix The prefix of the Data packets before the _meta or segment
   * number components.
   * @param verifySegment When a Data packet is received this calls
   * verifySegment(data). If it returns false then abort fetching and call
   * onError with SEGMENT_VERIFICATION_FAILED. If data validation is not
   * required, use DontVerifySegment.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onComplete When all segments are received, call
   * onComplete(metaInfo, content) where metaInfo is the decoded ContentMetaInfo
   * object and content is the concatenation of the content of all the segments.
   * However, if the metaInfo content size is zero, then this does not fetch
   * segments and the content is null.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError Call onError(errorCode, message) for timeout or an error
   * processing segments.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param interestLifetime (optional) The Interest lifetime for fetching the 
   * _meta info and segments. If omitted, use the default value from the default
   * Interest object.
   */
  static void
  fetch
    (ndn::Face& face, const ndn::Name& prefix,
     const ndn::SegmentFetcher::VerifySegment& verifySegment,
     const OnComplete& onComplete, const OnError& onError,
     std::chrono::nanoseconds interestLifetime = std::chrono::seconds(4));

private:
  /**
   * Create a new GeneralizedContent to use the Face. See the static fetch method
   * for details. After creating the SegmentFetcher, call fetchMetaInfo.
   */
  GeneralizedContent
    (ndn::Face& face, const ndn::Name& prefix, 
     const ndn::SegmentFetcher::VerifySegment& verifySegment,
     const OnComplete& onComplete, const OnError& onError,
     std::chrono::nanoseconds interestLifetime)
  : face_(face), prefix_(prefix), verifySegment_(verifySegment),
    onComplete_(onComplete), onError_(onError),
    interestLifetime_(interestLifetime)
  {
  }

  void
  fetchMetaInfo();

  void
  onMetaInfoReceived
    (const ndn::ptr_lib::shared_ptr<const ndn::Interest>& originalInterest,
     const ndn::ptr_lib::shared_ptr<ndn::Data>& data);

  void
  onMetaInfoTimeout(const ndn::ptr_lib::shared_ptr<const ndn::Interest>& interest);

  void
  onContentReceived(const ndn::Blob& content);

  void
  onSegmentFetcherError
    (ndn::SegmentFetcher::ErrorCode errorCode, const std::string& message);

  ndn::Face& face_;
  ndn::Name prefix_;
  ndn::SegmentFetcher::VerifySegment verifySegment_;
  OnComplete onComplete_;
  OnError onError_;
  std::chrono::nanoseconds interestLifetime_;
  ndn::ptr_lib::shared_ptr<ContentMetaInfo> metaInfo_;
};

}

#endif

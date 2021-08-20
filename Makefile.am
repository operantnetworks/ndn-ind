include aminclude.am

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS=${BOOST_CPPFLAGS} ${PTHREAD_CFLAGS}
AM_LDFLAGS=${BOOST_LDFLAGS} ${BOOST_SYSTEM_LIB} ${BOOST_REGEX_LIB} ${BOOST_ASIO_LIB} ${BOOST_CHRONO_LIB} ${BOOST_FILESYSTEM_LIB} ${PTHREAD_LIBS}

# "make install" will also install the include headers.
SUBDIRS = include

lib_LTLIBRARIES = libndn-c.la libndn-ind.la libndn-ind-tools.la
libndn_ind_tools_la_LIBADD = libndn-ind.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndn-ind.pc

# Make ndn-ind-config.h so we recompile the .pb.cc after Protobuf is installed or removed.
%.pb.cc: %.proto include/ndn-ind/ndn-ind-config.h
	if test "no${PROTOC}" == "no"; then \
	  cat protobuf-stub.txt > $@ ; \
	else \
	  $(PROTOC) --proto_path=$(dir $<) --cpp_out=$(dir $<) $< ; \
	fi

# On clean, remake the Protobuf code.
CLEANFILES = \
  examples/channel-status.pb.cc \
  examples/chatbuf.pb.cc \
  examples/control-parameters.pb.cc \
  examples/face-query-filter.pb.cc \
  examples/face-status.pb.cc \
  examples/fib-entry.pb.cc \
  examples/rib-entry.pb.cc \
  src/sync/sync-state.pb.cc \
  tools/usersync/content-meta-info.pb.cc

check_PROGRAMS = bin/unit-tests/test-access-manager-v2 \
  bin/unit-tests/test-certificate \
  bin/unit-tests/test-control-parameters-encode-decode \
  bin/unit-tests/test-control-response \
  bin/unit-tests/test-data-methods bin/unit-tests/test-decryptor-v2 \
  bin/unit-tests/test-der-encode-decode bin/unit-tests/test-encryptor-v2 \
  bin/unit-tests/test-face-methods \
  bin/unit-tests/test-interest-methods bin/unit-tests/test-key-chain \
  bin/unit-tests/test-invertible-bloom-lookup-table \
  bin/unit-tests/test-name-conventions \
  bin/unit-tests/test-name-methods bin/unit-tests/test-pib-certificate-container \
  bin/unit-tests/test-pib-identity-container \
  bin/unit-tests/test-pib-identity-impl bin/unit-tests/test-pib-impl \
  bin/unit-tests/test-pib-key-container bin/unit-tests/test-pib-key-impl \
  bin/unit-tests/test-psync-state bin/unit-tests/test-regex \
  bin/unit-tests/test-registration-callbacks \
  bin/unit-tests/test-signing-info bin/unit-tests/test-tpm-back-ends \
  bin/unit-tests/test-tpm-private-key bin/unit-tests/test-validation-policy-command-interest \
  bin/unit-tests/test-validation-policy-config bin/unit-tests/test-validator-null \
  bin/unit-tests/test-validator

noinst_PROGRAMS = bin/test-access-manager bin/test-channel-discovery bin/test-chrono-chat \
  bin/test-custom-tpm bin/test-echo-consumer bin/test-echo-consumer-lite \
  bin/test-custom-tpm bin/test-echo-consumer-raw-tcp \
  bin/test-encode-decode-benchmark bin/test-encode-decode-data \
  bin/test-encode-decode-fib-entry bin/test-encode-decode-interest \
  bin/test-full-psync-with-users bin/test-full-psync \
  bin/test-generalized-content bin/test-get-async bin/test-get-async-threadsafe \
  bin/test-list-channels bin/test-list-faces bin/test-list-rib \
  bin/test-prefix-discovery \
  bin/test-publish-async-nfd bin/test-publish-async-nfd-lite bin/test-register-route \
  bin/test-secured-interest-responder bin/test-secured-interest-sender \
  bin/test-sign-verify-data-hmac bin/cert-install

# Public C headers.
# NOTE: If a new directory is added, then add it to ndn_ind_c_headers in include/Makefile.am.
ndn_ind_c_headers = \
  include/ndn-ind/ndn-ind-config.h \
  include/ndn-ind/c/common.h \
  include/ndn-ind/c/control-parameters-types.h \
  include/ndn-ind/c/control-response-types.h \
  include/ndn-ind/c/data-types.h \
  include/ndn-ind/c/delegation-set-types.h \
  include/ndn-ind/c/errors.h \
  include/ndn-ind/c/forwarding-flags.h \
  include/ndn-ind/c/interest-types.h \
  include/ndn-ind/c/key-types.h \
  include/ndn-ind/c/name-types.h \
  include/ndn-ind/c/network-nack-types.h \
  include/ndn-ind/c/registration-options-types.h \
  include/ndn-ind/c/encoding/element-reader-types.h \
  include/ndn-ind/c/encrypt/encrypted-content-types.h \
  include/ndn-ind/c/encrypt/algo/encrypt-params-types.h \
  include/ndn-ind/c/lp/congestion-mark-types.h \
  include/ndn-ind/c/lp/incoming-face-id-types.h \
  include/ndn-ind/c/lp/lp-packet-types.h \
  include/ndn-ind/c/security/ec-private-key-types.h \
  include/ndn-ind/c/security/ec-public-key-types.h \
  include/ndn-ind/c/security/rsa-private-key-types.h \
  include/ndn-ind/c/security/rsa-public-key-types.h \
  include/ndn-ind/c/security/validity-period-types.h \
  include/ndn-ind/c/transport/transport-types.h \
  include/ndn-ind/c/util/blob-types.h \
  include/ndn-ind/c/util/dynamic-uint8-array-types.h

# Public C++ headers.
# NOTE: If a new directory is added, then add it to ndn_ind_cpp_headers in include/Makefile.am.
ndn_ind_cpp_headers = \
  include/ndn-ind/common.hpp \
  include/ndn-ind/control-parameters.hpp \
  include/ndn-ind/control-response.hpp \
  include/ndn-ind/data.hpp \
  include/ndn-ind/delegation-set.hpp \
  include/ndn-ind/digest-sha256-signature.hpp \
  include/ndn-ind/exclude.hpp \
  include/ndn-ind/face.hpp \
  include/ndn-ind/forwarding-flags.hpp \
  include/ndn-ind/generic-signature.hpp \
  include/ndn-ind/hmac-with-sha256-signature.hpp \
  include/ndn-ind/interest-filter.hpp \
  include/ndn-ind/interest.hpp \
  include/ndn-ind/key-locator.hpp \
  include/ndn-ind/link.hpp \
  include/ndn-ind/meta-info.hpp \
  include/ndn-ind/name.hpp \
  include/ndn-ind/network-nack.hpp \
  include/ndn-ind/registration-options.hpp \
  include/ndn-ind/sha256-with-ecdsa-signature.hpp \
  include/ndn-ind/sha256-with-rsa-signature.hpp \
  include/ndn-ind/signature.hpp \
  include/ndn-ind/threadsafe-face.hpp \
  include/ndn-ind/encoding/oid.hpp \
  include/ndn-ind/encoding/protobuf-tlv.hpp \
  include/ndn-ind/encoding/tlv-0_1-wire-format.hpp \
  include/ndn-ind/encoding/tlv-0_1_1-wire-format.hpp \
  include/ndn-ind/encoding/tlv-0_2-wire-format.hpp \
  include/ndn-ind/encoding/tlv-0_3-wire-format.hpp \
  include/ndn-ind/encoding/tlv-wire-format.hpp \
  include/ndn-ind/encoding/wire-format.hpp \
  include/ndn-ind/encrypt/access-manager-v2.hpp \
  include/ndn-ind/encrypt/decryptor-v2.hpp \
  include/ndn-ind/encrypt/encrypted-content.hpp \
  include/ndn-ind/encrypt/encryptor-v2.hpp \
  include/ndn-ind/in-memory-storage/in-memory-storage-retaining.hpp \
  include/ndn-ind/lite/control-parameters-lite.hpp \
  include/ndn-ind/lite/control-response-lite.hpp \
  include/ndn-ind/lite/data-lite.hpp \
  include/ndn-ind/lite/delegation-set-lite.hpp \
  include/ndn-ind/lite/exclude-lite.hpp \
  include/ndn-ind/lite/forwarding-flags-lite.hpp \
  include/ndn-ind/lite/interest-lite.hpp \
  include/ndn-ind/lite/key-locator-lite.hpp \
  include/ndn-ind/lite/meta-info-lite.hpp \
  include/ndn-ind/lite/name-lite.hpp \
  include/ndn-ind/lite/network-nack-lite.hpp \
  include/ndn-ind/lite/registration-options-lite.hpp \
  include/ndn-ind/lite/signature-lite.hpp \
  include/ndn-ind/lite/encoding/element-listener-lite.hpp \
  include/ndn-ind/lite/encoding/element-reader-lite.hpp \
  include/ndn-ind/lite/encoding/tlv-0_1_1-wire-format-lite.hpp \
  include/ndn-ind/lite/encoding/tlv-0_2-wire-format-lite.hpp \
  include/ndn-ind/lite/encoding/tlv-0_3-wire-format-lite.hpp \
  include/ndn-ind/lite/encrypt/encrypted-content-lite.hpp \
  include/ndn-ind/lite/encrypt/algo/aes-algorithm-lite.hpp \
  include/ndn-ind/lite/encrypt/algo/chacha20-algorithm-lite.hpp \
  include/ndn-ind/lite/encrypt/algo/des-algorithm-lite.hpp \
  include/ndn-ind/lite/lp/congestion-mark-lite.hpp \
  include/ndn-ind/lite/lp/incoming-face-id-lite.hpp \
  include/ndn-ind/lite/lp/lp-packet-lite.hpp \
  include/ndn-ind/lite/security/ec-private-key-lite.hpp \
  include/ndn-ind/lite/security/ec-public-key-lite.hpp \
  include/ndn-ind/lite/security/rsa-private-key-lite.hpp \
  include/ndn-ind/lite/security/rsa-public-key-lite.hpp \
  include/ndn-ind/lite/security/validity-period-lite.hpp \
  include/ndn-ind/lite/transport/tcp-transport-lite.hpp \
  include/ndn-ind/lite/transport/udp-transport-lite.hpp \
  include/ndn-ind/lite/transport/unix-transport-lite.hpp \
  include/ndn-ind/lite/util/blob-lite.hpp \
  include/ndn-ind/lite/util/crypto-lite.hpp \
  include/ndn-ind/lite/util/dynamic-malloc-uint8-array-lite.hpp \
  include/ndn-ind/lite/util/dynamic-uint8-array-lite.hpp \
  include/ndn-ind/security/security-common.hpp \
  include/ndn-ind/security/command-interest-preparer.hpp \
  include/ndn-ind/security/command-interest-signer.hpp \
  include/ndn-ind/security/key-chain.hpp \
  include/ndn-ind/security/key-params.hpp \
  include/ndn-ind/security/safe-bag.hpp \
  include/ndn-ind/security/security-exception.hpp \
  include/ndn-ind/security/signing-info.hpp \
  include/ndn-ind/security/validity-period.hpp \
  include/ndn-ind/security/validator-config-error.hpp \
  include/ndn-ind/security/validator-config.hpp \
  include/ndn-ind/security/validator-null.hpp \
  include/ndn-ind/security/validity-period.hpp \
  include/ndn-ind/security/verification-helpers.hpp \
  include/ndn-ind/security/certificate/certificate-extension.hpp \
  include/ndn-ind/security/certificate/certificate-subject-description.hpp \
  include/ndn-ind/security/certificate/certificate.hpp \
  include/ndn-ind/security/certificate/public-key.hpp \
  include/ndn-ind/security/certificate/x509-certificate-info.hpp \
  include/ndn-ind/security/certificate/x509-crl-info.hpp \
  include/ndn-ind/security/pib/pib-certificate-container.hpp \
  include/ndn-ind/security/pib/pib-identity.hpp \
  include/ndn-ind/security/pib/pib-identity-container.hpp \
  include/ndn-ind/security/pib/pib-impl.hpp \
  include/ndn-ind/security/pib/pib-key.hpp \
  include/ndn-ind/security/pib/pib-key-container.hpp \
  include/ndn-ind/security/pib/pib-memory.hpp \
  include/ndn-ind/security/pib/pib-sqlite3.hpp \
  include/ndn-ind/security/pib/pib.hpp \
  include/ndn-ind/security/tpm/helper-osx.hpp \
  include/ndn-ind/security/tpm/tpm.hpp \
  include/ndn-ind/security/tpm/tpm-back-end.hpp \
  include/ndn-ind/security/tpm/tpm-back-end-file.hpp \
  include/ndn-ind/security/tpm/tpm-back-end-memory.hpp \
  include/ndn-ind/security/tpm/tpm-back-end-osx.hpp \
  include/ndn-ind/security/tpm/tpm-key-handle.hpp \
  include/ndn-ind/security/tpm/tpm-key-handle-memory.hpp \
  include/ndn-ind/security/tpm/tpm-key-handle-osx.hpp \
  include/ndn-ind/security/tpm/tpm-private-key.hpp \
  include/ndn-ind/security/v2/certificate-cache-v2.hpp \
  include/ndn-ind/security/v2/certificate-fetcher-from-network.hpp \
  include/ndn-ind/security/v2/certificate-fetcher-offline.hpp \
  include/ndn-ind/security/v2/certificate-fetcher.hpp \
  include/ndn-ind/security/v2/certificate-request.hpp \
  include/ndn-ind/security/v2/certificate-storage.hpp \
  include/ndn-ind/security/v2/certificate-v2.hpp \
  include/ndn-ind/security/v2/trust-anchor-container.hpp \
  include/ndn-ind/security/v2/trust-anchor-group.hpp \
  include/ndn-ind/security/v2/validation-error.hpp \
  include/ndn-ind/security/v2/validation-policy-accept-all.hpp \
  include/ndn-ind/security/v2/validation-policy-command-interest.hpp \
  include/ndn-ind/security/v2/validation-policy-config.hpp \
  include/ndn-ind/security/v2/validation-policy-from-pib.hpp \
  include/ndn-ind/security/v2/validation-policy-simple-hierarchy.hpp \
  include/ndn-ind/security/v2/validation-policy.hpp \
  include/ndn-ind/security/v2/validation-state.hpp \
  include/ndn-ind/security/v2/validator.hpp \
  include/ndn-ind/security/v2/x509-crl-cache.hpp \
  include/ndn-ind/security/v2/x509-crl-fetcher.hpp \
  include/ndn-ind/security/v2/validator-config/config-checker.hpp \
  include/ndn-ind/security/v2/validator-config/config-filter.hpp \
  include/ndn-ind/security/v2/validator-config/config-name-relation.hpp \
  include/ndn-ind/security/v2/validator-config/config-rule.hpp \
  include/ndn-ind/sync/chrono-sync2013.hpp \
  include/ndn-ind/sync/full-psync2017.hpp \
  include/ndn-ind/sync/full-psync2017-with-users.hpp \
  include/ndn-ind/sync/psync-missing-data-info.hpp \
  include/ndn-ind/sync/psync-producer-base.hpp \
  include/ndn-ind/transport/async-tcp-transport.hpp \
  include/ndn-ind/transport/async-unix-transport.hpp \
  include/ndn-ind/transport/tcp-transport.hpp \
  include/ndn-ind/transport/transport.hpp \
  include/ndn-ind/transport/udp-transport.hpp \
  include/ndn-ind/transport/unix-transport.hpp \
  include/ndn-ind/util/blob.hpp \
  include/ndn-ind/util/change-counter.hpp \
  include/ndn-ind/util/exponential-re-express.hpp \
  include/ndn-ind/util/logging.hpp \
  include/ndn-ind/util/memory-content-cache.hpp \
  include/ndn-ind/util/segment-fetcher.hpp \
  include/ndn-ind/util/signed-blob.hpp \
  include/ndn-ind/util/impl/asio-fwd.hpp \
  include/ndn-ind/util/impl/cancel-handle.hpp \
  include/ndn-ind/util/impl/monotonic_steady_clock.hpp \
  include/ndn-ind/util/impl/steady-timer.hpp

# Public ndn-ind-tools C++ headers.
# NOTE: If a new directory is added, then add it to ndn_ind_tools_cpp_headers in include/Makefile.am.
ndn_ind_tools_cpp_headers = \
  include/ndn-ind-tools/micro-forwarder/micro-forwarder.hpp \
  include/ndn-ind-tools/micro-forwarder/micro-forwarder-transport.hpp \
  include/ndn-ind-tools/usersync/channel-discovery.hpp \
  include/ndn-ind-tools/usersync/content-meta-info.hpp \
  include/ndn-ind-tools/usersync/generalized-content.hpp \
  include/ndn-ind-tools/usersync/prefix-discovery.hpp

# Just the C code.
libndn_c_la_SOURCES = ${ndn_ind_c_headers} \
  contrib/apache/apr_base64.c contrib/apache/apr_base64.h \
  contrib/murmur-hash/murmur-hash.c contrib/murmur-hash/murmur-hash.h \
  src/c/control-parameters_c.c src/c/control-parameters.h \
  src/c/control-response.h \
  src/c/data.h \
  src/c/delegation-set.h \
  src/c/errors.c src/c/errors.h \
  src/c/forwarding-flags-impl.h \
  src/c/interest_c.c src/c/interest.h \
  src/c/key-locator.h \
  src/c/name_c.c src/c/name.h \
  src/c/network-nack_c.c src/c/network-nack.h \
  src/c/registration-options.c src/c/registration-options.h \
  src/c/encoding/element-listener.h \
  src/c/encoding/element-reader.c src/c/encoding/element-reader.h \
  src/c/encoding/tlv-0_2-wire-format_c.c src/c/encoding/tlv-0_2-wire-format.h \
  src/c/encoding/tlv-0_3-wire-format_c.c src/c/encoding/tlv-0_3-wire-format.h \
  src/c/encoding/tlv/tlv-control-parameters.c src/c/encoding/tlv/tlv-control-parameters.h \
  src/c/encoding/tlv/tlv-control-response.c src/c/encoding/tlv/tlv-control-response.h \
  src/c/encoding/tlv/tlv-data.c src/c/encoding/tlv/tlv-data.h \
  src/c/encoding/tlv/tlv-delegation-set.c src/c/encoding/tlv/tlv-delegation-set.h \
  src/c/encoding/tlv/tlv-decoder.c src/c/encoding/tlv/tlv-decoder.h \
  src/c/encoding/tlv/tlv-encoder.c src/c/encoding/tlv/tlv-encoder.h \
  src/c/encoding/tlv/tlv-encrypted-content.c src/c/encoding/tlv/tlv-encrypted-content.h \
  src/c/encoding/tlv/tlv-interest.c src/c/encoding/tlv/tlv-interest.h \
  src/c/encoding/tlv/tlv-key-locator.c src/c/encoding/tlv/tlv-key-locator.h \
  src/c/encoding/tlv/tlv-lp-packet.c src/c/encoding/tlv/tlv-lp-packet.h \
  src/c/encoding/tlv/tlv-name.c src/c/encoding/tlv/tlv-name.h \
  src/c/encoding/tlv/tlv-signature-info.c src/c/encoding/tlv/tlv-signature-info.h \
  src/c/encoding/tlv/tlv-structure-decoder.c src/c/encoding/tlv/tlv-structure-decoder.h \
  src/c/encoding/tlv/tlv.h \
  src/c/encrypt/encrypted-content.h \
  src/c/encrypt/algo/aes-algorithm_c.c src/c/encrypt/algo/aes-algorithm.h \
  src/c/encrypt/algo/chacha20-algorithm_c.c src/c/encrypt/algo/chacha20-algorithm.h \
  src/c/encrypt/algo/des-algorithm_c.c src/c/encrypt/algo/des-algorithm.h \
  src/c/lp/congestion-mark_c.c src/c/lp/congestion-mark.h \
  src/c/lp/incoming-face-id_c.c src/c/lp/incoming-face-id.h \
  src/c/lp/lp-packet.h \
  src/c/security/ec-private-key.c src/c/util/ec-private-key.h \
  src/c/security/ec-public-key.c src/c/util/ec-public-key.h \
  src/c/security/rsa-private-key.c src/c/util/rsa-private-key.h \
  src/c/security/rsa-public-key.c src/c/util/rsa-public-key.h \
  src/c/security/validity-period.h \
  src/c/transport/socket-transport.c src/c/transport/socket-transport.h \
  src/c/transport/tcp-transport_c.c src/c/transport/tcp-transport.h \
  src/c/transport/udp-transport.h \
  src/c/transport/unix-transport.h \
  src/c/util/blob_c.c src/c/util/blob.h \
  src/c/util/crypto.c src/c/util/crypto.h \
  src/c/util/dynamic-uint8-array.c src/c/util/dynamic-uint8-array.h \
  src/c/util/ndn_memory.c src/c/util/ndn_memory.h \
  src/c/util/ndn_realloc.c src/c/util/ndn_realloc.h \
  src/c/util/time.c src/c/util/time.h

# C++ code and also the C code.
libndn_ind_la_SOURCES = ${libndn_c_la_SOURCES} ${ndn_ind_cpp_headers} \
  contrib/ndn-cxx/ndn-cxx/detail/cancel-handle.cpp \
  contrib/ndn-cxx/ndn-cxx/util/scheduler.cpp \
  src/common.cpp \
  src/control-parameters.cpp \
  src/control-response.cpp \
  src/data.cpp \
  src/delegation-set.cpp \
  src/digest-sha256-signature.cpp \
  src/exclude.cpp \
  src/face.cpp \
  src/generic-signature.cpp \
  src/hmac-with-sha256-signature.cpp \
  src/interest-filter.cpp \
  src/interest.cpp \
  src/key-locator.cpp \
  src/link.cpp \
  src/meta-info.cpp \
  src/name.cpp \
  src/network-nack.cpp \
  src/node.cpp src/node.hpp \
  src/signature.cpp \
  src/sha256-with-ecdsa-signature.cpp \
  src/sha256-with-rsa-signature.cpp \
  src/threadsafe-face.cpp \
  src/encoding/base64.cpp src/encoding/base64.hpp \
  src/encoding/element-listener.cpp src/encoding/element-listener.hpp \
  src/encoding/oid.cpp \
  src/encoding/protobuf-tlv.cpp \
  src/encoding/tlv-0_1-wire-format.cpp \
  src/encoding/tlv-0_1_1-wire-format.cpp \
  src/encoding/tlv-0_2-wire-format.cpp \
  src/encoding/tlv-0_3-wire-format.cpp \
  src/encoding/tlv-decoder.hpp \
  src/encoding/tlv-encoder.hpp \
  src/encoding/tlv-wire-format.cpp \
  src/encoding/wire-format.cpp \
  src/encoding/der/der-exception.cpp src/encoding/der/der-exception.hpp \
  src/encoding/der/der-node.cpp src/encoding/der/der-node.hpp \
  src/encrypt/access-manager-v2.cpp \
  src/encrypt/decryptor-v2.cpp \
  src/encrypt/encrypted-content.cpp \
  src/encrypt/encryptor-v2.cpp \
  src/impl/delayed-call-table.cpp src/impl/delayed-call-table.hpp \
  src/impl/interest-filter-table.cpp src/impl/interest-filter-table.hpp \
  src/impl/pending-interest-table.cpp src/impl/pending-interest-table.hpp \
  src/impl/registered-prefix-table.cpp src/impl/registered-prefix-table.hpp \
  src/in-memory-storage/in-memory-storage-retaining.cpp \
  src/lite/control-parameters-lite.cpp \
  src/lite/control-response-lite.cpp \
  src/lite/data-lite.cpp \
  src/lite/delegation-set-lite.cpp \
  src/lite/exclude-lite.cpp \
  src/lite/interest-lite.cpp \
  src/lite/key-locator-lite.cpp \
  src/lite/meta-info-lite.cpp \
  src/lite/name-lite.cpp \
  src/lite/network-nack-lite.cpp \
  src/lite/registration-options-lite.cpp \
  src/lite/signature-lite.cpp \
  src/lite/encoding/element-listener-lite.cpp \
  src/lite/encoding/element-reader-lite.cpp \
  src/lite/encoding/tlv-0_2-wire-format-lite.cpp \
  src/lite/encoding/tlv-0_3-wire-format-lite.cpp \
  src/lite/encrypt/encrypted-content-lite.cpp \
  src/lite/encrypt/algo/aes-algorithm-lite.cpp \
  src/lite/encrypt/algo/chacha20-algorithm-lite.cpp \
  src/lite/encrypt/algo/des-algorithm-lite.cpp \
  src/lite/lp/congestion-mark-lite.cpp \
  src/lite/lp/incoming-face-id-lite.cpp \
  src/lite/lp/lp-packet-lite.cpp \
  src/lite/security/ec-private-key-lite.cpp \
  src/lite/security/ec-public-key-lite.cpp \
  src/lite/security/rsa-private-key-lite.cpp \
  src/lite/security/rsa-public-key-lite.cpp \
  src/lite/security/validity-period-lite.cpp \
  src/lite/transport/tcp-transport-lite.cpp \
  src/lite/transport/udp-transport-lite.cpp \
  src/lite/transport/unix-transport-lite.cpp \
  src/lite/util/blob-lite.cpp \
  src/lite/util/crypto-lite.cpp \
  src/lite/util/dynamic-malloc-uint8-array-lite.cpp \
  src/lite/util/dynamic-uint8-array-lite.cpp \
  src/lp/congestion-mark.cpp src/lp/congestion-mark.hpp \
  src/lp/incoming-face-id.cpp src/lp/incoming-face-id.hpp \
  src/lp/lp-packet.cpp src/lp/lp-packet.hpp \
  src/security/command-interest-preparer.cpp \
  src/security/command-interest-signer.cpp \
  src/security/key-chain.cpp \
  src/security/key-params.cpp \
  src/security/safe-bag.cpp \
  src/security/security-exception.cpp \
  src/security/signing-info.cpp \
  src/security/validator-null.cpp \
  src/security/validity-period.cpp \
  src/security/verification-helpers.cpp \
  src/security/certificate/certificate-extension.cpp \
  src/security/certificate/certificate-subject-description.cpp \
  src/security/certificate/certificate.cpp \
  src/security/certificate/public-key.cpp \
  src/security/certificate/x509-certificate-info.cpp \
  src/security/certificate/x509-crl-info.cpp \
  src/security/pib/pib-certificate-container.cpp \
  src/security/pib/pib-identity.cpp \
  src/security/pib/pib-identity-container.cpp \
  src/security/pib/pib-key.cpp \
  src/security/pib/pib-key-container.cpp \
  src/security/pib/pib-memory.cpp \
  src/security/pib/pib-sqlite3.cpp \
  src/security/pib/pib.cpp \
  src/security/pib/detail/pib-identity-impl.cpp \src/security/pib/detail/pib-identity-impl.hpp \
  src/security/pib/detail/pib-key-impl.cpp \src/security/pib/detail/pib-key-impl.hpp \
  src/security/tpm/tpm.cpp \
  src/security/tpm/tpm-back-end.cpp \
  src/security/tpm/tpm-back-end-file.cpp \
  src/security/tpm/tpm-back-end-memory.cpp \
  src/security/tpm/tpm-back-end-osx.cpp \
  src/security/tpm/tpm-key-handle.cpp \
  src/security/tpm/tpm-key-handle-memory.cpp \
  src/security/tpm/tpm-key-handle-osx.cpp \
  src/security/tpm/tpm-private-key.cpp \
  src/security/v2/certificate-cache-v2.cpp \
  src/security/v2/certificate-fetcher-from-network.cpp \
  src/security/v2/certificate-fetcher-offline.cpp \
  src/security/v2/certificate-fetcher.cpp \
  src/security/v2/certificate-storage.cpp \
  src/security/v2/certificate-v2.cpp \
  src/security/v2/trust-anchor-container.cpp \
  src/security/v2/trust-anchor-group.cpp \
  src/security/v2/validation-error.cpp \
  src/security/v2/validation-policy-accept-all.cpp \
  src/security/v2/validation-policy-command-interest.cpp \
  src/security/v2/validation-policy-config.cpp \
  src/security/v2/validation-policy-from-pib.cpp \
  src/security/v2/validation-policy-simple-hierarchy.cpp \
  src/security/v2/validation-policy.cpp \
  src/security/v2/validation-state.cpp \
  src/security/v2/validator.cpp \
  src/security/v2/x509-crl-cache.cpp \
  src/security/v2/x509-crl-fetcher.cpp \
  src/security/v2/validator-config/config-checker.cpp \
  src/security/v2/validator-config/config-filter.cpp \
  src/security/v2/validator-config/config-name-relation.cpp \
  src/security/v2/validator-config/config-rule.cpp \
  src/sync/sync-state.pb.cc \
  src/sync/chrono-sync2013.cpp \
  src/sync/digest-tree.cpp src/sync/digest-tree.hpp \
  src/sync/full-psync2017.cpp \
  src/sync/full-psync2017-with-users.cpp \
  src/sync/psync-producer-base.cpp \
  src/sync/detail/invertible-bloom-lookup-table.cpp src/sync/detail/invertible-bloom-lookup-table.hpp \
  src/sync/detail/psync-segment-publisher.cpp src/sync/detail/psync-segment-publisher.hpp \
  src/sync/detail/psync-state.cpp src/sync/detail/psync-state.hpp \
  src/sync/detail/psync-user-prefixes.cpp src/sync/detail/psync-user-prefixes.hpp \
  src/transport/async-tcp-transport.cpp \
  src/transport/async-unix-transport.cpp \
  src/transport/tcp-transport.cpp \
  src/transport/transport.cpp \
  src/transport/udp-transport.cpp \
  src/transport/unix-transport.cpp \
  src/util/blob-stream.hpp \
  src/util/boost-info-parser.cpp src/util/boost-info-parser.hpp \
  src/util/command-interest-generator.cpp src/util/command-interest-generator.hpp \
  src/util/config-file.cpp src/util/config-file.hpp \
  src/util/dynamic-uint8-vector.cpp src/util/dynamic-uint8-vector.hpp \
  src/util/exponential-re-express.cpp \
  src/util/logging.cpp \
  src/util/memory-content-cache.cpp \
  src/util/segment-fetcher.cpp \
  src/util/sqlite3-statement.cpp src/util/sqlite3-statement.hpp \
  src/util/regex/ndn-regex-backref-manager.cpp src/util/regex/ndn-regex-backref-manager.hpp \
  src/util/regex/ndn-regex-backref-matcher.cpp src/util/regex/ndn-regex-backref-matcher.hpp \
  src/util/regex/ndn-regex-component-matcher.cpp src/util/regex/ndn-regex-component-matcher.hpp \
  src/util/regex/ndn-regex-component-set-matcher.cpp src/util/regex/ndn-regex-component-set-matcher.hpp \
  src/util/regex/ndn-regex-matcher-base.cpp src/util/regex/ndn-regex-matcher-base.hpp \
  src/util/regex/ndn-regex-pattern-list-matcher.cpp src/util/regex/ndn-regex-pattern-list-matcher.hpp \
  src/util/regex/ndn-regex-pseudo-matcher.cpp src/util/regex/ndn-regex-pseudo-matcher.hpp \
  src/util/regex/ndn-regex-repeat-matcher.cpp src/util/regex/ndn-regex-repeat-matcher.hpp \
  src/util/regex/ndn-regex-top-matcher.cpp src/util/regex/ndn-regex-top-matcher.hpp

# The ndn-ind-tools library.
libndn_ind_tools_la_SOURCES = ${ndn_ind_tools_cpp_headers} ${ndn_ind_cpp_headers} \
  tools/micro-forwarder/micro-forwarder.cpp \
  tools/micro-forwarder/micro-forwarder-transport.cpp \
  tools/usersync/content-meta-info.pb.cc \
  tools/usersync/channel-discovery.cpp \
  tools/usersync/content-meta-info.cpp \
  tools/usersync/generalized-content.cpp tools/usersync/prefix-discovery.cpp

bin_test_access_manager_SOURCES = examples/test-access-manager.cpp
bin_test_access_manager_LDADD = libndn-ind.la

bin_test_channel_discovery_SOURCES = examples/test-channel-discovery.cpp
bin_test_channel_discovery_LDADD = libndn-ind.la libndn-ind-tools.la

bin_test_chrono_chat_SOURCES = examples/chatbuf.pb.cc examples/test-chrono-chat.cpp
bin_test_chrono_chat_LDADD = libndn-ind.la

bin_test_custom_tpm_SOURCES = examples/test-custom-tpm.cpp
bin_test_custom_tpm_LDADD = libndn-ind.la

bin_test_echo_consumer_lite_SOURCES = examples/test-echo-consumer-lite.cpp
bin_test_echo_consumer_lite_LDADD = libndn-ind.la

bin_test_echo_consumer_raw_tcp_SOURCES = examples/test-echo-consumer-raw-tcp.cpp
bin_test_echo_consumer_raw_tcp_LDADD = libndn-ind.la

bin_test_echo_consumer_SOURCES = examples/test-echo-consumer.cpp
bin_test_echo_consumer_LDADD = libndn-ind.la

bin_test_encode_decode_benchmark_SOURCES = examples/test-encode-decode-benchmark.cpp
bin_test_encode_decode_benchmark_LDADD = libndn-ind.la

bin_test_encode_decode_data_SOURCES = examples/test-encode-decode-data.cpp
bin_test_encode_decode_data_LDADD = libndn-ind.la

bin_test_encode_decode_fib_entry_SOURCES = examples/fib-entry.pb.cc examples/test-encode-decode-fib-entry.cpp
bin_test_encode_decode_fib_entry_LDADD = libndn-ind.la

bin_test_encode_decode_interest_SOURCES = examples/test-encode-decode-interest.cpp
bin_test_encode_decode_interest_LDADD = libndn-ind.la

bin_test_full_psync_SOURCES = examples/test-full-psync.cpp
bin_test_full_psync_LDADD = libndn-ind.la

bin_test_full_psync_with_users_SOURCES = examples/test-full-psync-with-users.cpp
bin_test_full_psync_with_users_LDADD = libndn-ind.la

bin_test_generalized_content_SOURCES = examples/test-generalized-content.cpp
bin_test_generalized_content_LDADD = libndn-ind.la libndn-ind-tools.la

bin_test_get_async_SOURCES = examples/test-get-async.cpp
bin_test_get_async_LDADD = libndn-ind.la

bin_test_get_async_threadsafe_SOURCES = examples/test-get-async-threadsafe.cpp
bin_test_get_async_threadsafe_LDADD = libndn-ind.la

bin_test_list_channels_SOURCES = examples/channel-status.pb.cc examples/test-list-channels.cpp
bin_test_list_channels_LDADD = libndn-ind.la

bin_test_list_faces_SOURCES = examples/face-status.pb.cc examples/test-list-faces.cpp
bin_test_list_faces_LDADD = libndn-ind.la

bin_test_list_rib_SOURCES = examples/rib-entry.pb.cc examples/test-list-rib.cpp
bin_test_list_rib_LDADD = libndn-ind.la

bin_test_prefix_discovery_SOURCES = examples/test-prefix-discovery.cpp
bin_test_prefix_discovery_LDADD = libndn-ind.la libndn-ind-tools.la

bin_test_publish_async_nfd_SOURCES = examples/test-publish-async-nfd.cpp
bin_test_publish_async_nfd_LDADD = libndn-ind.la

bin_test_publish_async_nfd_lite_SOURCES = examples/test-publish-async-nfd-lite.cpp
bin_test_publish_async_nfd_lite_LDADD = libndn-ind.la

bin_test_secured_interest_responder_SOURCES = examples/test-secured-interest-responder.cpp
bin_test_secured_interest_responder_LDADD = libndn-ind.la

bin_test_secured_interest_sender_SOURCES = examples/test-secured-interest-sender.cpp
bin_test_secured_interest_sender_LDADD = libndn-ind.la

bin_test_sign_verify_data_hmac_SOURCES = examples/test-sign-verify-data-hmac.cpp
bin_test_sign_verify_data_hmac_LDADD = libndn-ind.la

bin_test_register_route_SOURCES = \
  examples/control-parameters.pb.cc examples/face-query-filter.pb.cc \
  examples/face-status.pb.cc examples/test-register-route.cpp
bin_test_register_route_LDADD = libndn-ind.la

bin_cert_install_SOURCES = examples/cert-install.cpp
bin_cert_install_LDADD = libndn-ind.la

# Unit tests

bin_unit_tests_test_access_manager_v2_SOURCES = tests/unit-tests/test-access-manager-v2.cpp \
  tests/unit-tests/encrypt-static-data.cpp \
  tests/unit-tests/identity-management-fixture.cpp \
  tests/unit-tests/in-memory-storage-face.cpp \
  contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_access_manager_v2_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_access_manager_v2_LDADD = libndn-ind.la

bin_unit_tests_test_certificate_SOURCES = tests/unit-tests/test-certificate.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_certificate_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_certificate_LDADD = libndn-ind.la

bin_unit_tests_test_control_parameters_encode_decode_SOURCES = tests/unit-tests/test-control-parameters-encode-decode.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_control_parameters_encode_decode_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_control_parameters_encode_decode_LDADD = libndn-ind.la

bin_unit_tests_test_control_response_SOURCES = tests/unit-tests/test-control-response.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_control_response_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_control_response_LDADD = libndn-ind.la

bin_unit_tests_test_data_methods_SOURCES = tests/unit-tests/test-data-methods.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_data_methods_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_data_methods_LDADD = libndn-ind.la

bin_unit_tests_test_decryptor_v2_SOURCES = tests/unit-tests/test-decryptor-v2.cpp \
  tests/unit-tests/encrypt-static-data.cpp \
  tests/unit-tests/identity-management-fixture.cpp \
  tests/unit-tests/in-memory-storage-face.cpp \
  contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_decryptor_v2_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_decryptor_v2_LDADD = libndn-ind.la

bin_unit_tests_test_der_encode_decode_SOURCES = tests/unit-tests/test-der-encode-decode.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_der_encode_decode_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_der_encode_decode_LDADD = libndn-ind.la

bin_unit_tests_test_encryptor_v2_SOURCES = tests/unit-tests/test-encryptor-v2.cpp \
  tests/unit-tests/encrypt-static-data.cpp \
  tests/unit-tests/identity-management-fixture.cpp \
  tests/unit-tests/in-memory-storage-face.cpp \
  contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_encryptor_v2_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_encryptor_v2_LDADD = libndn-ind.la

bin_unit_tests_test_face_methods_SOURCES = tests/unit-tests/test-face-methods.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_face_methods_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_face_methods_LDADD = libndn-ind.la

bin_unit_tests_test_interest_methods_SOURCES = tests/unit-tests/test-interest-methods.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_interest_methods_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_interest_methods_LDADD = libndn-ind.la

bin_unit_tests_test_key_chain_SOURCES = tests/unit-tests/test-key-chain.cpp \
  tests/unit-tests/identity-management-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_key_chain_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_key_chain_LDADD = libndn-ind.la

bin_unit_tests_test_invertible_bloom_lookup_table_SOURCES = \
  tests/unit-tests/test-invertible-bloom-lookup-table.cpp \
  contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_invertible_bloom_lookup_table_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_invertible_bloom_lookup_table_LDADD = libndn-ind.la

bin_unit_tests_test_name_conventions_SOURCES = tests/unit-tests/test-name-conventions.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_name_conventions_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_name_conventions_LDADD = libndn-ind.la

bin_unit_tests_test_name_methods_SOURCES = tests/unit-tests/test-name-methods.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_name_methods_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_name_methods_LDADD = libndn-ind.la

bin_unit_tests_test_pib_certificate_container_SOURCES = tests/unit-tests/test-pib-certificate-container.cpp \
  tests/unit-tests/pib-data-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_pib_certificate_container_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_pib_certificate_container_LDADD = libndn-ind.la

bin_unit_tests_test_pib_identity_container_SOURCES = tests/unit-tests/test-pib-identity-container.cpp \
  tests/unit-tests/pib-data-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_pib_identity_container_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_pib_identity_container_LDADD = libndn-ind.la

bin_unit_tests_test_pib_identity_impl_SOURCES = tests/unit-tests/test-pib-identity-impl.cpp \
  tests/unit-tests/pib-data-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_pib_identity_impl_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_pib_identity_impl_LDADD = libndn-ind.la

bin_unit_tests_test_pib_impl_SOURCES = tests/unit-tests/test-pib-impl.cpp \
  tests/unit-tests/pib-data-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_pib_impl_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_pib_impl_LDADD = libndn-ind.la

bin_unit_tests_test_pib_key_container_SOURCES = tests/unit-tests/test-pib-key-container.cpp \
  tests/unit-tests/pib-data-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_pib_key_container_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_pib_key_container_LDADD = libndn-ind.la

bin_unit_tests_test_pib_key_impl_SOURCES = tests/unit-tests/test-pib-key-impl.cpp \
  tests/unit-tests/pib-data-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_pib_key_impl_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_pib_key_impl_LDADD = libndn-ind.la

bin_unit_tests_test_regex_SOURCES = tests/unit-tests/test-regex.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_regex_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_regex_LDADD = libndn-ind.la

bin_unit_tests_test_psync_state_SOURCES = tests/unit-tests/test-psync-state.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_psync_state_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_psync_state_LDADD = libndn-ind.la

bin_unit_tests_test_registration_callbacks_SOURCES = tests/unit-tests/test-registration-callbacks.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_registration_callbacks_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_registration_callbacks_LDADD = libndn-ind.la

bin_unit_tests_test_signing_info_SOURCES = tests/unit-tests/test-signing-info.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_signing_info_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_signing_info_LDADD = libndn-ind.la

bin_unit_tests_test_tpm_back_ends_SOURCES = tests/unit-tests/test-tpm-back-ends.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_tpm_back_ends_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_tpm_back_ends_LDADD = libndn-ind.la

bin_unit_tests_test_tpm_private_key_SOURCES = tests/unit-tests/test-tpm-private-key.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_tpm_private_key_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_tpm_private_key_LDADD = libndn-ind.la

bin_unit_tests_test_validation_policy_command_interest_SOURCES = \
  tests/unit-tests/test-validation-policy-command-interest.cpp \
  tests/unit-tests/identity-management-fixture.cpp \
  tests/unit-tests/validator-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_validation_policy_command_interest_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_validation_policy_command_interest_LDADD = libndn-ind.la

bin_unit_tests_test_validation_policy_config_SOURCES = tests/unit-tests/test-validation-policy-config.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_validation_policy_config_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_validation_policy_config_LDADD = libndn-ind.la

bin_unit_tests_test_validator_null_SOURCES = tests/unit-tests/test-validator-null.cpp \
  tests/unit-tests/identity-management-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_validator_null_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_validator_null_LDADD = libndn-ind.la

bin_unit_tests_test_validator_SOURCES = tests/unit-tests/test-validator.cpp \
  tests/unit-tests/identity-management-fixture.cpp \
  tests/unit-tests/validator-fixture.cpp contrib/gtest-1.7.0/fused-src/gtest/gtest-all.cc
bin_unit_tests_test_validator_CPPFLAGS = -I./contrib/gtest-1.7.0/fused-src
bin_unit_tests_test_validator_LDADD = libndn-ind.la

TESTS = ${check_PROGRAMS}

dist_noinst_SCRIPTS = autogen.sh

# "make install" will install these in the install include directory, for example
# /usr/local/ndn-ind/name.hpp.
# These files are included by the application with, for example
# #include <ndn-ind/namp.hpp>
# Internal include headers are not put in this public install directory.

# Public C headers.
ndn_cpp_c_headers = \
  $(wildcard ndn-ind/*.h) \
  $(wildcard ndn-ind/c/*.*) \
  $(wildcard ndn-ind/c/encoding/*.*) \
  $(wildcard ndn-ind/c/encrypt/*.*) \
  $(wildcard ndn-ind/c/encrypt/algo/*.*) \
  $(wildcard ndn-ind/c/lp/*.*) \
  $(wildcard ndn-ind/c/security/*.*) \
  $(wildcard ndn-ind/c/transport/*.*) \
  $(wildcard ndn-ind/c/util/*.*)

# Public C++ headers.
# Use ndn-ind/*.hpp instead of *.* to not overwrite *.h from above.
ndn_cpp_cpp_headers = \
  $(wildcard ndn-ind/*.hpp) \
  $(wildcard ndn-ind/encoding/*.*) \
  $(wildcard ndn-ind/encrypt/*.*) \
  $(wildcard ndn-ind/in-memory-storage/*.*) \
  $(wildcard ndn-ind/lite/*.*) \
  $(wildcard ndn-ind/lite/encoding/*.*) \
  $(wildcard ndn-ind/lite/encrypt/*.*) \
  $(wildcard ndn-ind/lite/encrypt/algo/*.*) \
  $(wildcard ndn-ind/lite/lp/*.*) \
  $(wildcard ndn-ind/lite/security/*.*) \
  $(wildcard ndn-ind/lite/transport/*.*) \
  $(wildcard ndn-ind/lite/util/*.*) \
  $(wildcard ndn-ind/security/*.*) \
  $(wildcard ndn-ind/security/certificate/*.*) \
  $(wildcard ndn-ind/security/pib/*.*) \
  $(wildcard ndn-ind/security/tpm/*.*) \
  $(wildcard ndn-ind/security/v2/*.*) \
  $(wildcard ndn-ind/security/v2/validator-config/*.*) \
  $(wildcard ndn-ind/sync/*.*) \
  $(wildcard ndn-ind/tools/usersync/*.*) \
  $(wildcard ndn-ind/transport/*.*) \
  $(wildcard ndn-ind/util/*.*) \
  $(wildcard ndn-ind/util/impl/*.*)

# Public ndn-ind-tools C++ headers.
ndn_cpp_tools_cpp_headers = \
  $(wildcard ndn-ind-tools/usersync/*.*)

nobase_include_HEADERS = $(ndn_cpp_c_headers) $(ndn_cpp_cpp_headers) \
  $(ndn_cpp_tools_cpp_headers)

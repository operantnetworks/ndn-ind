NDN-IND Lite: A light-weight C++ layer over the C language core in NDN-IND
--------------------------------------------------------------------------

NDN-IND is a Named Data Networking client library for C++ and C. The main C++
API uses the Standard Library classes like std::vector and shared_ptr to
automatically manage memory in objects. For data packet encoding, decoding and
network transport, the C++ API calls an inner core written in pure C which does
not make any assumptions about memory management or support libraries.

Some platforms don't support the C++ Standard Library or
run-time info for exceptions. To support such platforms, the
NDN-IND Lite API was developed which, like the C core, does not make assumptions
about memory management or support libraries. While functionally equivalent to
the C core, the NDN-IND Lite takes advantage of C++ syntax to simplify the API.
For example, the following C code initializes a MetaInfo struct:

    struct ndn_MetaInfo metaInfo;
    ndn_MetaInfo_initialize(&metaInfo);

The following equivalent NDN-IND Lite code initializes a MetaInfoLite object:

    MetaInfoLite metaInfo;

The MetaInfoLite constructor internally calls the same ndn_MetaInfo_initialize
function, but C++ syntax, method overloading and namespace support makes the
NDN-IND Lite code cleaner and less error-prone.

NDN-IND Lite itself does not use "new", std::vector, shared_ptr or other
memory manipulation functions. The application is responsible for managing
memory and providing pointers to NDN-IND Lite. The following code creates the
name "/ndn/ucla":

    ndn_NameComponent nameComponents[10];
    NameLite name(nameComponents, 10);
    ndn_Error error;
    if ((error = name.append("ndn")))
      return error;
    if ((error = name.append("ucla")))
      return error;

The code cannot allocate new memory to enlarge the name components array, so a
sufficiently large array is provided to the NameLite constructor. The append
method is provided a pre-allocated buffer for the component value, in this case
a static C string. The append method returns an error if there is not enough
room in the nameComponents array to add another entry to point to the new
component value. (NDN-IND Lite uses error codes instead of exceptions.)

See the inline documentation for the classes and methods in include/ndn-cpp/lite.


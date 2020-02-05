## Red Hat 7.7

### Install Red Hat 7.7

These are instructions to install NDN-IND plus NFD-IND and DNMP on Red Hat Enterprise Linux 7.7 .

Install Red Hat Enterprise Linux 7.7 from the Binary DVD or other media. (Hint: During
installation, in "Network and Host Name", enable your ethernet port. It is much
easier to do this during installation.) 

When you log in to Red Hat, use the Subscription Manager to register so that you can use the yum 
package manager. (Use your Red Hat username, not your email address.)

The packages from the install DVD need to be updated. In a terminal, enter:

    sudo yum update

Reboot.

### Compiler

We need to upgrade the compiler. The following instructions are copied from
https://developers.redhat.com/blog/2019/03/05/yum-install-gcc-8-clang-6/

In a terminal, enter:

    sudo subscription-manager repos --enable rhel-7-server-optional-rpms \
        --enable rhel-server-rhscl-7-rpms \
        --enable rhel-7-server-devtools-rpms
    sudo yum install devtoolset-8 llvm-toolset-6.0

To compile, you have to enter a special bash shell. All compilation steps must be
done after entering this command:

    scl enable devtoolset-8 llvm-toolset-6.0 bash

### Prerequisites

To install the prerequisites, in a terminal, enter:

    sudo yum install git openssl-devel sqlite-devel libpcap-devel python-devel zlib-devel bzip2-devel log4cxx-devel autoconf automake libtool

To set up PKG_CONFIG_PATH, enter:

    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig    

### Boost

The version of Boost provided by yum is too old, so we need to build it. In a terminal, enter:

    cd ~
    wget https://dl.bintray.com/boostorg/release/1.71.0/source/boost_1_71_0.tar.gz
    tar xvfz boost_1_71_0.tar.gz
    cd boost_1_71_0
    ./bootstrap.sh --with-toolset=clang --with-libraries=all
    ./b2
    sudo ./b2 install

### Protobuf

Yum doesn't have Protobuf, so we need to build it. In a terminal, enter:

    cd ~
    git clone --recursive https://github.com/protocolbuffers/protobuf
    cd protobuf
    ./autogen.sh
    CC=clang CXX=clang++ ./configure
    make
    sudo make install

### NDN-CXX and NFD

To build NDN-CXX and the patched version of NFD, in a terminal, enter:

    cd ~
    git clone https://github.com/named-data/ndn-cxx
    cd ndn-cxx
    git checkout 5149350bb437201e59b5d541568ce86e91993034
    ./waf configure --check-cxx-compiler=clang++ --boost-includes=/usr/local/include --boost-libs=/usr/local/lib
    ./waf
    sudo ./waf install

    cd ~
    git clone --recursive https://github.com/operantnetworks/nfd-ind
    cd nfd-ind
    git checkout patched
    ./waf configure --check-cxx-compiler=clang++ --boost-includes=/usr/local/include --boost-libs=/usr/local/lib
    ./waf
    sudo ./waf install
    sudo cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf

### NDN-IND

To build NDN-IND, in a terminal, enter:

    cd ~
    git clone https://github.com/operantnetworks/ndn-ind
    cd ndn-ind
    CC=clang CXX=clang++ ./configure
    make
    sudo make install

### DNMP

To build DNMP, in a terminal, enter:

    cd ~
    git clone https://github.com/jefft0/DNMP
    cd DNMP
    git checkout ndn-ind
    make

### ldconfig

The usual library directories are not on the load path by default. The following
needs to be run once to configure the system:

    sudo sh -c "echo /usr/local/lib64 >> /etc/ld.so.conf"
    sudo sh -c "echo /usr/local/lib >> /etc/ld.so.conf"
    sudo ldconfig

## Test

In one terminal, enter:

    nfd-start

In a second terminal, enter:

    cd ~/DNMP
    ./nod

In a third terminal, enter:

    cd ~/DNMP
    ./genericCLI -p Pinger -c 10

The last command should print 10 ping responses.

## Common problems

If you get a compiler error like "g++ not found" or "strchr not found", remember that you need enter the special bash shell with this command:

    scl enable devtoolset-8 llvm-toolset-6.0 bash

If you get an error like "libndn-cxx not found", remember that you need to update PKG_CONFIG_PATH with this command:

    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig

If you run an application and get an error that a library is not found, make sure you run the commands in the "ldconfig"
section to add the library directories.

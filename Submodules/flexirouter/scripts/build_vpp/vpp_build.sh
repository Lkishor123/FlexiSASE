#!/bin/bash

set -e  # exit on the first command failure


for i in "$@"
do
case $i in
    -c*|--clean*)
    CLEAN=YES
    shift
    ;;
    --release*)
    RELEASE=-release
    shift
    ;;
    *)
          # unknown option
    ;;
esac
done
echo "CLEAN:   ${CLEAN}"
echo "RELEASE: ${RELEASE}"


cd vpp

VPP_PATH=`pwd`
if [ ! -z "${RELEASE}" ]
then
  VPP_PATH_BINARIES=$VPP_PATH/build-root/build-vpp-native/vpp
else
  VPP_PATH_BINARIES=$VPP_PATH/build-root/build-vpp_debug-native/vpp
fi


if  [ "${CLEAN}" == "YES" ] ; then
  make wipe${RELEASE}
fi
make build${RELEASE}

cd -

cd vppsb
cd netlink

sed -i 's/AM_CFLAGS += -O2.*/AM_CFLAGS += -O2 -DCLIB_VEC64=0/g' Makefile.am

libtoolize
aclocal
autoconf
automake --add-missing
if [ -z "${RELEASE}" ]; then
  ENABLE_DEBUG=--enable-debug
fi
./configure VPP_DIR=$VPP_PATH $ENABLE_DEBUG
if  [ "${CLEAN}" == "YES" ] ; then
  make clean
fi
make

if [ -d $VPP_PATH_BINARIES/lib/ ]; then
  ln -sfn $(pwd)/.libs/librtnl.so $VPP_PATH_BINARIES/lib/librtnl.so
  ln -sfn $(pwd)/.libs/librtnl.so.0 $VPP_PATH_BINARIES/lib/librtnl.so.0
fi

cd -

cd router

cmd="sed -i 's#AM_CFLAGS.*#AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@ -I/usr/include/libnl3/ -DCLIB_DEBUG -DCLIB_VEC64=0 -I../../vpp/src -I$VPP_PATH_BINARIES -I../netlink -L../netlink/.libs#g' Makefile.am"
echo $smd
eval $cmd

libtoolize
aclocal
autoconf
automake --add-missing
./configure
if  [ "${CLEAN}" == "YES" ] ; then
  make clean
fi
make

if [ -d $VPP_PATH_BINARIES/lib/ ]; then
  ln -sfn $(pwd)/.libs/router.so $VPP_PATH_BINARIES/lib/vpp_plugins/router.so
fi

cd $VPP_PATH
cd ..

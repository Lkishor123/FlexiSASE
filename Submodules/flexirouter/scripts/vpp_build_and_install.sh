#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`


for i in "$@"
do
case $i in
    --release*)
    RELEASE=--release
    shift
    ;;
    --clean*)
    CLEAN=--clean
    shift
    ;;
    *)
    # unknown option
    ;;
esac
done

$SCRIPTPATH/build_vpp/vpp_build.sh ${RELEASE} ${CLEAN}
$SCRIPTPATH/build_vpp/vpp_install.sh ${RELEASE} ${CLEAN}

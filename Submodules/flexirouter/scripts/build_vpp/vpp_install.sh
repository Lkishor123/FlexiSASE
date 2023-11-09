#!/bin/bash

#set -e  # exit on the first command failure
#set -x  # echo executed commands while expanding variables

# keep track of the last executed command
trap 'last_status=$?; last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
# echo an error message before exiting
trap 'if [ $last_status == 0 ]; then echo "DONE"; else echo "ABORTED !"; fi' EXIT



# Parse arguments
for i in "$@"
do
case $i in
    --install-root*)
    INSTALL_ROOT=$(realpath $2)
    shift   # skip argument name
    shift   # skip argument value
    ;;
    --release*)
    RELEASE=YES
    shift   # skip argument name
    ;;
    *)
    # unknown option
    INSTALL_ROOT=$(realpath $1)
    shift   # skip argument name
    ;;
esac
done

echo "INSTALL_ROOT: ${INSTALL_ROOT}"
echo "RELEASE: ${RELEASE}"

function copy_vpp_binaries {
    SRC_DIR=$1/
    DST_DIR=$INSTALL_ROOT$2
    SRC_FILES=
    if [ "$3" != "" ]; then
        SRC_FILES="-name $3"
    fi

    if [ ! -d $DST_DIR ]; then
        sudo mkdir -p $DST_DIR
    fi
    find $SRC_DIR -maxdepth 1 -type f $SRC_FILES | sudo xargs -I {} cp {} $DST_DIR/
    find $SRC_DIR -maxdepth 1 -type l $SRC_FILES | sudo xargs -I {} cp {} $DST_DIR/
}


# Clean leftovers from the previous installations or elder versions of vpp.
# For example, vpp 21.01 does not generates plugin tests, so it does not overrides
# the old ones if exist. They fail vpp start, as they are not compatibe with 21.01
#
if [ -d /usr/lib/vpp_api_test_plugins ]; then
    sudo rm -rf /usr/lib/vpp_api_test_plugins
fi
if [ -d /usr/local/lib/python3.6/dist-packages/vpp_papi ]; then
    sudo rm -rf /usr/local/lib/python3.6/dist-packages/vpp_papi
fi
if [ -d /usr/lib/x86_64-linux-gnu/vpp_plugins ]; then
    sudo rm -rf /usr/lib/x86_64-linux-gnu/vpp_plugins/*
fi
if [ -d /usr/lib/x86_64-linux-gnu/vpp_api_test_plugins ]; then
    sudo rm -rf /usr/lib/x86_64-linux-gnu/vpp_api_test_plugins/*
fi


cd vpp

VPP_PATH=`pwd`
if [ ! -z $RELEASE ]
then
  VPP_PATH_BINARIES=$VPP_PATH/build-root/build-vpp-native/vpp
else
  VPP_PATH_BINARIES=$VPP_PATH/build-root/build-vpp_debug-native/vpp
fi

copy_vpp_binaries $VPP_PATH_BINARIES/bin             /usr/bin
copy_vpp_binaries $VPP_PATH_BINARIES/lib             /usr/lib/x86_64-linux-gnu
copy_vpp_binaries $VPP_PATH_BINARIES/lib/vpp_plugins /usr/lib/x86_64-linux-gnu/vpp_plugins
copy_vpp_binaries $VPP_PATH_BINARIES/lib/vpp_api_test_plugins /usr/lib/x86_64-linux-gnu/vpp_api_test_plugins
if [ ! -f $INSTALL_ROOT/etc/vpp/startup.conf ]; then
    copy_vpp_binaries $VPP_PATH/src/vpp/conf /etc/vpp "startup.conf"
fi
if [ ! -f $INSTALL_ROOT/etc/sysctl.d/80-vpp.conf ]; then
    copy_vpp_binaries $VPP_PATH/src/vpp/conf /etc/sysctl.d "80-vpp.conf"
fi

# The flexiwan-router image installs vpp-api into /usr/lib/python2.7/dist-packages/,
# when the official installation either by 'pip isntall vpp-papi' or by fdio script
# installs it into /usr/local/lib/python2.7/dist-packages/.
# To ensure the proper files are taken just remove both folders and run fdio script.
#
if [ -d /usr/lib/python2.7/dist-packages/vpp_papi ]; then
    sudo rm -rf /usr/lib/python2.7/dist-packages/vpp_papi*
fi
if [ -d /usr/local/lib/python2.7/dist-packages/vpp_papi ]; then
    sudo rm -rf /usr/local/lib/python2.7/dist-packages/vpp_papi*
fi
cd src/vpp-api/python
sudo python setup.py install
cd -

if [ ! -d /usr/share/vpp/api ]; then
    sudo mkdir -p /usr/share/vpp/api
fi
sudo rm -rf /usr/share/vpp/api/*
sudo find $VPP_PATH_BINARIES -type f -name "*.api.json" -exec cp {} /usr/share/vpp/api/ \;

cd $VPP_PATH

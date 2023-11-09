# flexiWAN Official Repository

The official respository for flexiwan is in https://gitlab.com/flexiwangroup

# About flexiWAN

flexiWAN is the world's first open source [SD-WAN](https://flexiwan.com/). flexiWAN offers a complete SD-WAN solution comprising of flexiEdge (the edge router) and flexiManage (the central management system) with core SD-WAN functionality. Our mission is to democratize the SD-WAN Market through an open source & modular  SD-WAN solution lowering barriers to entry for companies to adopt it or offer services based on the flexiWAN SD-WAN solution. To learn more about the flexiWAN's unique approach to networking, visit the [flexiWAN](https://flexiwan.com/) website, and follow the company on [Twitter](https://twitter.com/FlexiWan) and [LinkedIn](https://www.linkedin.com/company/flexiwan).

To contact us please drop us an email at yourfriends@flexiwan.com, or for any general issue please use our [Google User Group](https://groups.google.com/a/flexiwan.com/forum/#!forum/flexiwan-users)

# flexiRouter

This repository contains the flexiWAN vRouter component. flexiRouter is comprised of FD.io VPP + VPPSB.
It is published together with flexiAgent and FRR.

# How to build and use VPP

## Prepare

Install required packages.

```
sudo ./scripts/prepare.sh
```

## Build

Build VPP and VPPSB plugins.

```
./scripts/vpp_build.sh
```

## Run 

Run in an interactive mode.

### Server 1
```
sudo ./scripts/run_vpp.sh 192.168.31.76 192.168.31.1 20.20.20.1
```

### Server 2
```
sudo ./scripts/run_vpp.sh 192.168.31.47 192.168.31.1 10.10.10.1
```

After exit Ethernet interfaces will be released.

## Configure

Run from a different console after VPP prompt is ready.

### Server 1
```
sudo ./scripts/conf_vpp.sh 192.168.31.76 192.168.31.1 20.20.20.1
```

### Server 2
```
sudo ./scripts/conf_vpp.sh 192.168.31.47 192.168.31.1 10.10.10.1
```

## Feature

### Server 1
```
cd scripts/<feature_name>/server1
sudo ./conf.sh
```

### Server 2
```
cd scripts/<feature_name>/server2
sudo ./conf.sh
```

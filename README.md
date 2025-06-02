# dpdk_sample_forwarder
Sample dpdk forwarder project

# Requirements
dpdk-dev library should be installed

hugepages should be allocated, example:

`sudo dpdk-hugepages.py -p 2M --setup 4G
sudo chmod 777 /dev/hugepages/`

# How to build
`cd dpdk_sample_forwarder
cmake -B build .
cd ./build
make`

# Command line args
--blocked-ips - list of src ip's to drop from forwarding
--reset-mac - reset src macs to 0
Example:
dpdk_simple_forwarder --blocked-ips=192.168.0.1,192.168.10.5,192.168.0.158 --reset-mac

# Testing with pcap files
Application can be tested without harware ethernet interfaces.
Using with pcap files (sample pcap files can be found in pcaps dir):
dpdk_simple_forwarder --vdev='net_pcap0,rx_pcap=input1.pcap' --vdev='net_pcap1,tx_pcap=output1.pcap'
Using with pcap files and cmnd line args:
dpdk_simple_forwarder --vdev='net_pcap0,rx_pcap=input1.pcap' --vdev='net_pcap1,tx_pcap=output1.pcap' -- --blocked-ips=192.168.0.1,192.168.10.5,192.168.0.158 --reset-mac

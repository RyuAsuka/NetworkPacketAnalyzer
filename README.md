# NetworkPacketAnalyzer

![pyver](https://img.shields.io/pypi/pyversions/numpy) 
![platform](https://img.shields.io/conda/pn/conda-forge/python)
![license](https://img.shields.io/github/license/RyuAsuka/NetworkPacketAnalyzer)

## Introduction

NetworkPacketAnalyzer is a network packet analyzer based on Python. 
The techniques originated from 
[CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter). This programe
has fixed some bugs and unreasonable logics of CICFlowMeter.

## Usage

### Analyze pcap files

```
$ bin/NetworkPacketAnalyzer <input_file> <output_file>
``` 

The input file should be in`.pcap` format. (Maybe the `.pcapng` format also available but it has not been fully test yet)

The output file should be in `.csv` format.

### Realtime analyzing

Not implemented yet.

## Preconditions

* [Wireshark](https://www.wireshark.org/)
* [scapy](https://scapy.net/)
* [numpy](https://numpy.org/)
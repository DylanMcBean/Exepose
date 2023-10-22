# Exepose

## Overview

This project is dedicated to the analysis of executables, with a primary focus on aiding the reverse engineering of malware. By providing statistical analysis and insights into the nature of binary executables, our goal is to bolster the security of computer systems by understanding the inner workings and intentions of potentially malicious software.

## Current Status

**Work-In-Progress (WIP)**: The current version of the tool is in active development. Our aim is to support more executable formats in the future. Presently, we are meticulously working through ELF. As of now, we've achieved parsing and validation of the ELF headers.

### Supported Formats

- ELF (Executable and Linkable Format) - Linux executables, object code, shared libraries, and even core dumps can be in ELF format.

## Features

- **ELF File Analysis**: Our tool can read, validate, and provide insights into ELF headers, which can be instrumental in understanding the nature of the executable.
  
- **Statistical Analysis**: Get statistical data about the binary to understand patterns, anomalies, and more.

- **User-Friendly Interface**: Designed to be intuitive and straightforward to use for both novice and expert users.

## Motivation

Malware analysis and reverse engineering are critical in today's cyber threat landscape. By understanding the behavior, intention, and mechanisms of malware, we can develop countermeasures, improve system security, and remain a step ahead of malicious actors.

This tool was born out of the necessity to make this analysis process smoother, more efficient, and more accessible to security researchers and enthusiasts alike.

## Getting Started

### Prerequisites

- None as of yet

### Installation

```
git clone https://github.com/DylanMcBean/Exepose
cd Exepose
```

### Usage

```
cd ./tools
make clean && make && make run
```

## Contribution

We welcome contributions! If you find a bug, have a feature request, or want to contribute to the code, please open an issue or submit a pull request.

## License

MIT License

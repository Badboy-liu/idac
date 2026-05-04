# idac

`idac` is a small research utility that mirrors the Python implementation in
[`scripts/ida_keygen.py`](scripts/ida_keygen.py) with a C++23 executable in
[`src/main.cpp`](src/main.cpp).

The project currently contains:

- a C++ implementation built with CMake
- a Python reference implementation
- a JSON license template under `data/`
- a generated `idapro.hexlic` sample under `data/`

## Legal Notice

This repository contains code that can generate license data and modify IDA
library binaries. Use it only in environments where you have explicit
authorization to perform license and binary-patching research. Do not use it to
violate software licenses, bypass access controls, or run commercial software
without a valid license.

## Requirements

- CMake 4.1 or newer
- A C++23 compiler
- RapidJSON
- OpenSSL
- Python 3.9 or newer, for the reference script

The C++ target expects RapidJSON and OpenSSL to be discoverable by CMake:

```sh
find_package(RapidJSON CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
```

If you use vcpkg, configure CMake with your vcpkg toolchain file.

## Project Layout

```text
.
├── CMakeLists.txt
├── README.md
├── data/
│   ├── idapro.hexlic      # Generated sample license output
│   └── licenses.json      # License payload template
├── scripts/
│   └── ida_keygen.py      # Python reference implementation
└── src/
    └── main.cpp           # C++23 implementation
```

## Build

```sh
cmake -B cmake-build-debug
cmake --build cmake-build-debug
```

The build produces the `idac` executable in the configured build directory.

## Data Files

The C++ executable searches for the license template in this order:

1. `licenses.json`
2. `data/licenses.json`
3. `../data/licenses.json`

It writes `idapro.hexlic` to the current working directory.

## Python Reference

The Python script is kept as a readable reference implementation for the same
core behavior as the C++ executable. It uses only Python standard library
modules.

## Notes

- `cmake-build-debug/` is ignored by Git.
- `.idea/` is ignored by Git.
- The generated `idapro.hexlic` file is present in `data/` as a sample artifact.

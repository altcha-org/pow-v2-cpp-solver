# ALTCHA PoW v2 C++ Solver

A C++ implementation of the ALTCHA Proof-of-Work (PoW) v2 mechanism. This tool is designed for benchmarking and testing.

## Usage

The solver accepts a JSON challenge and an optional thread count.

```sh
./build/altcha_solver <challenge_json> [num_threads]
```

### Examples

Auto-detect threads:
```sh
./build/altcha_solver challenge.json
```

Manual thread count (e.g., 8 threads):
```sh
./build/altcha_solver challenge.json 8
```

## Prerequisites

Ensure you have the following dependencies installed on your system:

* OpenSSL (for SHA hashing)
* Argon2 (the core hashing algorithm for v2)
* C++17 compatible compiler

## Installation & Build

### Linux (Debian/Ubuntu)

```sh
# Install dependencies
sudo apt install -y build-essential libssl-dev libargon2-dev

# Compile
g++ src/altcha_solver.cpp -o build/altcha_solver \
    -std=c++17 -O3 \
    -lssl -lcrypto -largon2 -pthread
```

### macOS

```sh
# Install dependencies
brew install openssl argon2

# Compile
clang++ src/altcha_solver.cpp -o build/altcha_solver \
    -std=c++17 -O3 -arch arm64 \
    -I$(brew --prefix)/opt/openssl/include \
    -I$(brew --prefix)/opt/argon2/include \
    -L$(brew --prefix)/opt/openssl/lib \
    -L$(brew --prefix)/opt/argon2/lib \
    -lcrypto -largon2 -pthread
```

## License

MIT

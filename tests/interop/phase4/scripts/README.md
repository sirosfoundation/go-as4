# Phase4 Interoperability Test Scripts

This directory contains scripts for running interoperability tests between go-as4 and [phase4](https://github.com/phax/phase4).

## Prerequisites

- Go 1.21+
- Java 17+
- Maven 3.8+
- OpenSSL
- keytool (comes with JDK)
- A local clone of phase4: `git clone https://github.com/phax/phase4.git`

## Quick Start

### 1. Set up environment

```bash
# Point to your phase4 clone
export PHASE4_DIR=/path/to/phase4

# Or if using the default location:
export PHASE4_DIR=/home/leifj/work/siros.org/eDelivery/phase4
```

### 2. Generate certificates and start phase4

In one terminal:
```bash
cd tests/interop/phase4/scripts
./start-phase4.sh
```

This will:
- Generate test CA and leaf certificates
- Create a Java truststore with the CA certificate
- Rebuild phase4-test
- Start the phase4 server on port 9090

### 3. Run the tests

In another terminal:
```bash
cd tests/interop/phase4/scripts
./run-tests.sh
```

## Scripts

### `setup-certs.sh`

Generates test certificates:
- `certs/go-as4-ca.crt` / `.key` - CA certificate and private key
- `certs/go-as4-test.crt` / `.key` - Leaf certificate and private key
- `certs/go-as4-chain.crt` - Full certificate chain

Also creates a Java truststore at `${PHASE4_DIR}/phase4-test/src/main/resources/keys/interop-truststore.jks`.

### `start-phase4.sh`

Starts the phase4 test server:
- Runs `setup-certs.sh` to ensure certs are fresh
- Rebuilds phase4-test
- Starts server on port 9090 (configurable via `PORT` env var)

### `run-tests.sh`

Runs the go-as4 interop tests:
- Builds the Go test binary
- Runs tests against phase4

Environment variables:
- `PHASE4_URL` - URL of phase4 server (default: `http://localhost:9090/as4`)
- `MODE` - Test mode: `client`, `server`, or `all` (default: `client`)
- `VERBOSE` - Set to any value for verbose output

## Test Modes

- **client**: go-as4 sends messages to phase4 (tests go-as4 as sender)
- **server**: phase4 sends messages to go-as4 (tests go-as4 as receiver)
- **all**: Both directions

## Troubleshooting

### "Address already in use"

Kill existing processes:
```bash
lsof -ti:9090 | xargs kill -9
lsof -ti:10090 | xargs kill -9  # stop monitor port
```

### Certificate validation errors

Regenerate certificates and restart phase4:
```bash
./setup-certs.sh
# Restart phase4 server
```

### Build failures

Ensure you have the correct Java and Maven versions:
```bash
java -version  # Should be 17+
mvn -version   # Should be 3.8+
```

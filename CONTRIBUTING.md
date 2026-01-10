# Contributing to go-as4

Thank you for your interest in contributing to go-as4!

## Development Setup

1. Install Go 1.21 or later
2. Clone the repository:
   ```bash
   git clone https://github.com/sirosfoundation/go-as4.git
   cd go-as4
   ```
3. Install dependencies:
   ```bash
   go mod download
   ```

## Running Tests

```bash
go test ./...
```

## Code Style

- Follow standard Go conventions
- Run `gofmt` before committing
- Add godoc comments for all exported types and functions
- Keep functions focused and testable

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests and ensure they pass
6. Submit a pull request

## Specification Compliance

When implementing features, always reference the eDelivery AS4 2.0 specification:
https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0

## Areas for Contribution

- Complete AES-GCM encryption implementation
- MIME multipart handling
- Pull MEP support
- Four Corner Topology enhancements
- Additional test coverage
- Documentation improvements
- Example applications

## Questions?

Open an issue for discussion before starting major work.

# Architecture Decision Records

This directory contains the Architecture Decision Records (ADRs) for the go-as4 project.

## About ADRs

An Architecture Decision Record captures an important architectural decision made along with its context and consequences. ADRs help:

- Document the reasoning behind technical decisions
- Communicate decisions to team members and stakeholders
- Provide historical context for future maintainers

For more information about ADRs, see: https://github.com/joelparkerhenderson/architecture-decision-record

## ADR Index

### Core Decisions

| ADR | Title | Status |
|-----|-------|--------|
| [001](001-cryptographic-libraries.md) | Cryptographic Libraries | Accepted |
| [002](002-test-coverage.md) | Test Coverage | Accepted |
| [003](003-type-conventions.md) | Type Conventions | Accepted |
| [004](004-error-handling.md) | Error Handling | Accepted |

### AS4-Specific Decisions

| ADR | Title | Status |
|-----|-------|--------|
| [005](005-phase4-reference-testing.md) | Phase4 Reference Testing | Accepted |
| [006](006-signedxml-integration.md) | SignedXML Integration | Accepted |
| [007](007-ws-security-compliance.md) | WS-Security Compliance | Accepted |
| [008](008-authzen-trust-framework.md) | AuthZEN Trust Framework | Accepted |

## Template

When creating a new ADR, use this template:

```markdown
# ADR-NNN: Title

## Status

[Proposed | Accepted | Deprecated | Superseded]

## Context

What is the issue that we're seeing that is motivating this decision?

## Decision

What is the change that we're proposing and/or doing?

## Rationale

Why is this the best choice among alternatives?

## Consequences

What becomes easier or more difficult because of this change?
```

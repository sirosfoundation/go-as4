# ADR-003: Type Conventions

## Status

Accepted

## Context

Go 1.18+ introduced the `any` type alias as a more readable alternative to `interface{}`. The codebase needs consistency in type usage.

## Decision

We use the newer `any` instead of `interface{}` to represent a value that can have any type, even in complex types.

Examples:
- `map[string]interface{}` becomes `map[string]any`
- `func(interface{})` becomes `func(any)`

## Rationale

- **Functionality**: Both `any` and `interface{}` can hold values of any type
- **Interchangeability**: They can be used interchangeably in code
- **Readability**: `any` is generally considered more readable
- **Compiler treatment**: The compiler treats them identically
- **Modern Go**: Aligns with modern Go conventions (1.18+)

## Consequences

- Existing code should be updated during refactoring
- New code must use `any`
- Go 1.18+ is the minimum supported version

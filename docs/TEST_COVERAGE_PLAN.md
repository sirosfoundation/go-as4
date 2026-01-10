# Test Coverage Improvement Plan

**Goal:** Achieve >70% test coverage per ADR-002  
**Starting Point:** 47.6%  
**Current:** 55.7%  
**Gap:** +14.3 percentage points remaining

## Current Coverage Status (Updated)

| Package | Coverage | Status | Priority |
|---------|----------|--------|----------|
| `pkg/pmode` | 100.0% | ✅ Complete | Done |
| `pkg/mep` | 90.9% | ✅ Excellent | Done |
| `pkg/reliability` | 90.4% | ✅ Excellent | Done |
| `pkg/transport` | 88.0% | ✅ Excellent | Done |
| `pkg/mime` | 81.0% | ✅ Above target | Maintenance |
| `pkg/compression` | 72.7% | ✅ Above target | Maintenance |
| `pkg/message` | 72.7% | ✅ Above target | Maintenance |
| `pkg/msh` | 67.4% | ⚠️ Near target | P3 |
| `pkg/security` | 47.8% | ❌ Below target | P2 |
| `pkg/as4` | 19.5% | ❌ Below target | P2 |

## Testing Strategy

### Phase 1: Unit Tests for Data Structures ✅ COMPLETE

Tests implemented for pure data structures with minimal dependencies.

#### 1.1 `pkg/pmode` - P-Mode Configuration ✅

- [x] Create and retrieve P-Mode
- [x] Remove P-Mode
- [x] Find P-Mode by service/action
- [x] Find P-Mode - no match returns nil
- [x] Default P-Mode has valid structure
- [x] Security profiles return correct algorithms
- [x] Namespace version detection

**Coverage achieved:** 100%

#### 1.2 `pkg/mep` - Message Exchange Patterns ✅

- [x] One-way push handler creation
- [x] One-way push handler - HandleRequest returns error (expected)
- [x] One-way push handler - HandleReceipt delegates to custom handler
- [x] Two-way push handler creation
- [x] Two-way handler - all setters work correctly
- [x] Two-way handler - request/response flow

**Coverage achieved:** 90.9%

#### 1.3 `pkg/reliability` - Message Tracking ✅

- [x] Track message and retrieve
- [x] Message state transitions (submitted → sending → awaiting → received)
- [x] Error handling with retry limit
- [x] Retry timing with exponential backoff
- [x] Duplicate detection within window
- [x] Duplicate detection outside window (not duplicate)
- [x] Message hash computation is deterministic
- [x] Receipt validator placeholder

**Coverage achieved:** 90.4%

### Phase 2: Integration-Ready Tests ✅ COMPLETE

#### 2.1 `pkg/transport` - HTTPS Transport ✅

- [x] Default config has sensible TLS settings
- [x] Client creation with nil config uses defaults
- [x] Client creation with custom config
- [x] Server rejects non-POST requests
- [x] Server handles empty body gracefully
- [x] HTTP handler tests with mock server

**Coverage achieved:** 88.0%

### Phase 3: Complex Integration (Remaining Work)

#### 3.1 `pkg/as4` - Main Client/Server (Partial)

Constructor tests implemented. Full message flow tests require:
- Mock transport layer
- Integration test setup

**Current coverage:** 19.5%

**Remaining work:**
- [ ] SendMessage error paths (no P-Mode match)
- [ ] HandleMessage parsing tests  
- [ ] serializeSignal tests

#### 3.2 `pkg/security` - Improve Existing Coverage

**Current:** 47.8%  
**Target:** 70%

**Focus areas:**
- [ ] Signature verification edge cases
- [ ] Token reference creation variants
- [ ] Error paths in signing operations
- [ ] Key loading error handling

#### 3.3 `pkg/msh` - Minor Improvements

**Current:** 67.4%  
**Target:** 70%

- [ ] Additional edge cases (+2.6%)

## Implementation Order

### Completed
1. ✅ **Phase 1:** `pkg/pmode`, `pkg/mep` (pure data structures)
2. ✅ **Phase 1:** `pkg/reliability` (isolated logic, no network)
3. ✅ **Phase 2:** `pkg/transport` (with mocking)
4. ✅ **Phase 2:** `pkg/as4` (constructors)

### Remaining
5. 🔲 **Phase 3:** `pkg/security` improvements (+22.2% needed)
6. 🔲 **Phase 3:** `pkg/as4` message flow tests
7. 🔲 **Phase 4:** `pkg/msh` polish (+2.6% needed)

## Success Metrics

| Milestone | Target Coverage | Packages Above 70% | Status |
|-----------|-----------------|-------------------|--------|
| Starting Point | 47.6% | 3/10 | ✅ |
| After Phase 1 | ~60% | 6/10 | ✅ |
| After Phase 2 | ~65% | 7/10 | ✅ (55.7%) |
| After Phase 3 | ~70% | 9/10 | 🔲 |
| After Phase 4 | >70% | 10/10 | 🔲 |

## Running Coverage

```bash
# Full coverage report
make test-coverage

# Package-specific coverage
go test -cover ./pkg/pmode/...

# Detailed function coverage
go test -coverprofile=coverage.out ./pkg/... && go tool cover -func=coverage.out

# HTML report
go tool cover -html=coverage.out -o coverage.html
```

## Notes

- Tests should not require external services (mock HTTP where needed)
- Follow table-driven test patterns per Go conventions
- Focus on behavior, not implementation details
- Error paths are as important as happy paths

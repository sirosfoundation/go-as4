# Phase4 Reference Testing - Summary

## What We've Done

### 1. Cloned phase4 Library ✅
- Successfully cloned phase4 from https://github.com/phax/phase4
- Location: `/home/leifj/work/siros.org/eDelivery/phase4`
- This is a mature Java AS4 library using the same WSS4J/Apache CXF stack as Domibus

### 2. Analyzed phase4 Structure ✅

**Key Findings:**
- **Test Infrastructure**: phase4 has MockJettySetup for self-contained testing
- **Test Cases**: Comprehensive examples in `phase4-test/` covering:
  - Unsigned messages
  - Signed messages (RSA-SHA256)
  - Encrypted messages (AES-128-GCM) ← **This matches our target!**
  - Signed + Encrypted
  - Attachments with compression
  
- **Same Crypto Libraries**: Uses WSS4J like Domibus
- **Clear API**: `AS4ClientUserMessage` with fluent builder pattern

### 3. Created Testing Tools Structure ✅

Created `/home/leifj/work/siros.org/eDelivery/phase4-tools/` with:

```
phase4-tools/
├── pom.xml                    # Parent POM
├── README.md                  # Usage documentation
└── message-dumper/
    ├── pom.xml
    └── src/main/java/org/example/
        └── Phase4MessageDumper.java  # Message generation tool
```

### 4. Created Documentation ✅

**File**: `/home/leifj/work/siros.org/eDelivery/go-as4/docs/phase4-reference-testing.md`

This comprehensive document includes:
- Analysis of phase4 capabilities
- Testing strategy (3 phases)
- Proposed test implementations
- Benefits over Domibus testing
- Step-by-step implementation plan

## Next Steps

### Immediate (Fix Build Error)

The Phase4MessageDumper has minor API errors. Need to remove `getMessageID()` calls and just use `MessageHelperMethods.createRandomMessageID()` directly.

### Phase 1: Message Comparison

1. **Fix and build phase4-tools**
   ```bash
   cd /home/leifj/work/siros.org/eDelivery/phase4-tools
   mvn clean compile exec:java
   ```

2. **Generate reference messages**
   - Unsigned
   - Signed (RSA-SHA256 with SHA-256 digest)
   - Encrypted (AES-128-GCM)
   - Signed + Encrypted

3. **Compare with Go messages**
   - Extract SignedInfo from both
   - Compare canonicalization byte-for-byte
   - Identify differences

### Phase 2: Root Cause Analysis

**Focus on Canonicalization:**
```bash
# Extract SignedInfo from phase4 message
xmllint --xpath '//*[local-name()="SignedInfo"]' \
    /tmp/phase4-messages/signed-message.xml > phase4-signedinfo.xml

# Extract from Go message
xmllint --xpath '//*[local-name()="SignedInfo"]' \
    /tmp/go-message.xml > go-signedinfo.xml

# Compare
diff -u phase4-signedinfo.xml go-signedinfo.xml
```

### Phase 3: Live Testing

1. **Start phase4 test server**
2. **Send Go messages to phase4**
   - If phase4 accepts: Our implementation is correct, Domibus config issue
   - If phase4 rejects: Compare rejection reason with phase4's error details
3. **Send phase4 messages to Go server**
   - Validate our verification code

## Why This Approach is Better

### vs. Domibus Testing

| Aspect | Domibus | phase4 |
|--------|---------|--------|
| **Source Code** | Complex, hard to debug | Clean, well-documented |
| **Setup** | Docker, database, P-Mode | Simple Maven build |
| **Iteration Speed** | Slow (restart Docker) | Fast (Java main) |
| **Error Messages** | Generic ("FailedDecryption") | Detailed (actual crypto errors) |
| **Message Dumps** | Need to intercept | Built-in dumping |
| **Debugging** | External only | Can step through Java |

### Advantages for Our Situation

1. **Same Crypto Stack**: phase4 uses WSS4J, just like Domibus
   - If it works with phase4, it should work with Domibus
   - Eliminates "is it our code or their config?" question

2. **Clear Test Cases**: phase4-test shows exactly how to:
   - Create RSA-SHA256 signatures
   - Use AES-128-GCM encryption
   - Structure AS4 messages properly

3. **Message Comparison**: Easy to get canonical phase4 messages
   - Shows us exactly what WSS4J expects
   - Can compare byte-for-byte with our output

4. **Fast Debugging Loop**:
   ```bash
   # Change Go code
   go run tests/interop/cmd/main.go
   
   # Compare with phase4
   diff go-message.xml phase4-message.xml
   
   # Iterate quickly
   ```

## Critical Insight

Our self-verification proves our signatures are **mathematically correct**. The issue must be in:

1. **Canonicalization format** - WSS4J expects specific C14N output
2. **XML structure** - Element ordering or namespace declarations
3. **Configuration mismatch** - P-Mode settings (already addressed)

Phase4 will definitively show us which one because:
- It's the reference implementation for WSS4J usage
- We can see its source code
- We can compare our XML output directly

## Current Status

✅ **Completed:**
- phase4 cloned and analyzed
- Testing infrastructure designed
- Documentation created
- Message dumper tool scaffolded

⚠️ **Pending:**
- Fix minor API error in Phase4MessageDumper.java
- Build and run message generator
- Compare Go vs. phase4 canonical output

## Expected Outcome

After completing phase4 comparison, we will know:

1. **If our canonicalization matches WSS4J**: 
   - YES → Domibus config issue
   - NO → Specific bytes that differ

2. **If our message structure is correct**:
   - YES → Focus on P-Mode/policy alignment
   - NO → Specific elements that need adjustment

3. **If our crypto operations are compatible**:
   - YES → Signature/encryption algorithms correct
   - NO → Algorithm parameter adjustments needed

This eliminates guesswork and provides concrete, actionable debugging data.

## Files Created

1. `/home/leifj/work/siros.org/eDelivery/go-as4/docs/phase4-reference-testing.md`
   - Comprehensive testing plan
   
2. `/home/leifj/work/siros.org/eDelivery/phase4-tools/README.md`
   - Tool usage documentation
   
3. `/home/leifj/work/siros.org/eDelivery/phase4-tools/pom.xml`
   - Maven project configuration
   
4. `/home/leifj/work/siros.org/eDelivery/phase4-tools/message-dumper/`
   - Message generation tool (needs minor fix)

## Recommendation

**Immediate Action**: Fix the Phase4MessageDumper API errors and generate reference messages. This will give us concrete comparison points within 10 minutes rather than continued blind debugging against Domibus.

The signedxml canonicalization change we just made might be correct, but without a reference implementation to compare against, we're still guessing. Phase4 gives us the ground truth.

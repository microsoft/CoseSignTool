# V3 Architecture Documentation Index

## Quick Start

**New to V3?** Start here:
1. [V3 Architecture Summary](V3_Architecture_Summary.md) - Quick overview with examples
2. [V3 CoseSigner Architecture](V3_CoseSigner_Architecture.md) - Complete detailed documentation

## Documentation Structure

### 📋 Summary Documents

#### [V3_Architecture_Summary.md](V3_Architecture_Summary.md)
**Purpose**: Quick reference guide for V3 architecture  
**Contents**:
- Architecture overview diagram
- Core abstractions (interfaces and classes)
- Key design decisions and rationale
- Workflow examples (local and remote)
- Thread safety guidelines
- DI patterns
- Testing strategy
- Migration guide from V2

**Best for**: Getting started, quick reference, understanding design decisions

---

#### [V3_Architecture_Verification.md](V3_Architecture_Verification.md)
**Purpose**: Documentation completeness checklist  
**Contents**:
- Completed updates verification
- Architecture consistency checks
- Design decisions validation
- Documentation quality metrics
- Implementation readiness checklist

**Best for**: Ensuring documentation is complete and consistent

---

### 📖 Detailed Documentation

#### [V3_CoseSigner_Architecture.md](V3_CoseSigner_Architecture.md)
**Purpose**: Complete detailed architecture specification (1659 lines)  
**Contents**:
- Executive summary
- Key architectural insight
- Architecture overview with diagrams
- Complete interface definitions
- Implementation examples:
  - LocalCertificateSigningKey
  - LocalCertificateSigningService
  - RemoteCertificateSigningKey
  - RemoteCertificateSigningService
  - RemoteRsaWrapper
- Header contributor system
- Dependency injection support
- Factory usage patterns
- Thread safety requirements
- Testing strategy
- Benefits and conclusion

**Best for**: Implementation details, code examples, comprehensive understanding

---

## Core Concepts

### Architecture Layers

```
┌─────────────────────────────────────┐
│       Factory Layer                 │
│  DirectSignatureFactory             │
│  IndirectSignatureFactory           │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Signing Service Layer            │
│  ISigningService                    │
│  LocalCertificateSigningService     │
│  RemoteCertificateSigningService    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Signing Key Layer               │
│  ISigningKey                        │
│  LocalCertificateSigningKey         │
│  RemoteCertificateSigningKey        │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      .NET COSE Layer                │
│  CoseSigner                         │
│  CoseKey                            │
│  CoseSign1Message                   │
└─────────────────────────────────────┘
```

### Key Abstractions

| Abstraction | Responsibility | Document Section |
|-------------|----------------|------------------|
| `ISigningKey` | Emit CoseKey, provide metadata | [Summary](V3_Architecture_Summary.md#1-isigningkey) / [Detailed](V3_CoseSigner_Architecture.md#isigningkey) |
| `SigningKeyMetadata` | Describe key properties | [Summary](V3_Architecture_Summary.md#2-signingkeymetadata) / [Detailed](V3_CoseSigner_Architecture.md#signingkeymetadata) |
| `ISigningService` | Orchestrate signing with headers | [Summary](V3_Architecture_Summary.md#3-isigningservice) / [Detailed](V3_CoseSigner_Architecture.md#isigningservice---emits-cosesigner) |
| `SigningContext` | Per-operation information | [Summary](V3_Architecture_Summary.md#4-signingcontext) / [Detailed](V3_CoseSigner_Architecture.md#signingcontext) |
| `IHeaderContributor` | Contribute COSE headers | [Summary](V3_Architecture_Summary.md#5-iheadercontributor) / [Detailed](V3_CoseSigner_Architecture.md#iheadercontributor) |
| `HeaderContributorContext` | Context for header contributors | [Summary](V3_Architecture_Summary.md#6-headercontributorcontext) / [Detailed](V3_CoseSigner_Architecture.md#headercontributorcontext) |

## Design Decisions

### Major Design Decisions

| Decision | Rationale | Document |
|----------|-----------|----------|
| **ISigningKey Abstraction** | Separates key lifecycle from signing orchestration | [Summary - Design Decisions](V3_Architecture_Summary.md#-isigningkey-abstraction) |
| **Simplified HeaderContributorContext** | ISigningKey provides everything needed | [Verification - Design Decision 2](V3_Architecture_Verification.md#2-simplified-headercontributorcontext-) |
| **No IHeaderContributorFactory** | Services know what contributors they need | [Summary - Design Decisions](V3_Architecture_Summary.md#-no-iheadercontributorfactory) |
| **Certificate Not on Metadata** | Not all keys are certificate-based | [Summary - Design Decisions](V3_Architecture_Summary.md#-certificate-not-on-signingkeymetadata) |
| **No AsymmetricAlgorithm Assumptions** | PQC compatibility (ML-DSA) | [Summary - Design Decisions](V3_Architecture_Summary.md#-no-asymmetricalgorithm-assumptions) |

### Removed Patterns

These patterns were considered and explicitly removed:

| Removed Pattern | Reason | Alternative |
|----------------|--------|-------------|
| `IHeaderContributorFactory` | Services create contributors directly | Services instantiate contributors in constructor |
| `Certificate` on `SigningKeyMetadata` | Not all keys are certificate-based | Use `AdditionalMetadata["Certificate"]` |
| `EnableScittCompliance` in `SigningContext` | Implementation detail, not per-operation | Service-level implementation choice |
| `Priority` on `IHeaderContributor` | Service controls order | Service maintains ordered list |
| `KeyMetadata` property on `HeaderContributorContext` | Duplication | Use `SigningKey.Metadata` |
| `CoseSigner` property on `HeaderContributorContext` | Pre-creation unnecessary | Build CoseSigner after headers applied |

## Implementation Guides

### Quick Implementation Guide

1. **Choose Key Type**:
   - Local certificate → `LocalCertificateSigningKey`
   - Remote signing → `RemoteCertificateSigningKey`

2. **Create Signing Service**:
   - `LocalCertificateSigningService` or `RemoteCertificateSigningService`

3. **Create Factory**:
   - `DirectSignatureFactory` (with signing service)

4. **Sign**:
   ```csharp
   var message = factory.Sign(payload);
   ```

See: [Summary - Workflow Examples](V3_Architecture_Summary.md#workflow-examples)

### DI Setup Guide

See: [Summary - Dependency Injection](V3_Architecture_Summary.md#dependency-injection)

Complete example: [Detailed - DI Setup](V3_CoseSigner_Architecture.md#complete-di-setup-example)

### Custom Header Contributors

See: [Summary - Custom Headers](V3_Architecture_Summary.md#custom-headers)

Complete examples: [Detailed - Header Contributors](V3_CoseSigner_Architecture.md#iheadercontributor)

## Testing

### Testing Strategy

See: [Summary - Testing Strategy](V3_Architecture_Summary.md#testing-strategy)

Complete examples: [Detailed - Testing Strategy](V3_CoseSigner_Architecture.md#testing-strategy)

### Test Coverage

| Test Area | Document |
|-----------|----------|
| ISigningKey caching | [Summary](V3_Architecture_Summary.md#test-isigningkey-caching) / [Detailed](V3_CoseSigner_Architecture.md#test-1-cosekey-reuse-local) |
| Certificate rotation | [Summary](V3_Architecture_Summary.md#test-remote-certificate-rotation) / [Detailed](V3_CoseSigner_Architecture.md#test-3-remote-certificate-change) |
| Header contributors | [Summary](V3_Architecture_Summary.md#test-header-contributors) / [Detailed](V3_CoseSigner_Architecture.md#iheadercontributor) |

## Migration

### From V2 to V3

See: [Summary - Migration Path](V3_Architecture_Summary.md#migration-path-from-v2)

Key changes:
1. Replace `SigningKey` with `ISigningKey` implementation
2. Update services to use `ISigningKey`
3. Remove `IHeaderContributorFactory`
4. Update `HeaderContributorContext` usage
5. Update header contributors to access `context.SigningKey.Metadata`

## Benefits

### Why V3 Architecture?

See: [Detailed - Benefits](V3_CoseSigner_Architecture.md#benefits-of-v3-architecture-with-isigningkey)

Key benefits:
- ✅ Clean separation of concerns
- ✅ Minimal API surface
- ✅ DI-friendly and testable
- ✅ Thread-safe by design
- ✅ Extensible without modification
- ✅ PQC-ready (ML-DSA support)
- ✅ Uses .NET's battle-tested COSE implementation

## FAQ

### How do I add a new key type?
Implement `ISigningKey` interface. See: [Summary - ISigningKey](V3_Architecture_Summary.md#1-isigningkey)

### How do I add custom headers?
Implement `IHeaderContributor` interface. See: [Summary - Custom Headers](V3_Architecture_Summary.md#custom-headers)

### How does certificate rotation work?
`RemoteCertificateSigningKey` checks thumbprint on each `GetCoseKey()` call. See: [Detailed - Remote Key](V3_CoseSigner_Architecture.md#remotecertificatesigningkey-implementation)

### Is the design thread-safe?
Yes, with lock-based caching and immutable contributors. See: [Summary - Thread Safety](V3_Architecture_Summary.md#thread-safety)

### How do I set up dependency injection?
See: [Summary - DI Registration](V3_Architecture_Summary.md#registration-example)

### How do I test my implementation?
See: [Summary - Testing Strategy](V3_Architecture_Summary.md#testing-strategy)

---

## Document Maintenance

### Last Updated
- V3_CoseSigner_Architecture.md: 2024 (comprehensive update)
- V3_Architecture_Summary.md: 2024 (created)
- V3_Architecture_Verification.md: 2024 (created)

### Contributing
When updating documentation:
1. Update detailed docs first ([V3_CoseSigner_Architecture.md](V3_CoseSigner_Architecture.md))
2. Update summary ([V3_Architecture_Summary.md](V3_Architecture_Summary.md))
3. Update verification checklist ([V3_Architecture_Verification.md](V3_Architecture_Verification.md))
4. Update this index if adding new sections

### Status
✅ **All documentation complete and verified**

See [V3_Architecture_Verification.md](V3_Architecture_Verification.md) for completeness checklist.

# V3 Architecture - Detailed Class Diagrams

## Core Interface Hierarchy

```mermaid
classDiagram
    class ISigningService {
        <<interface>>
        +SigningKey SigningKey
        +SigningMetadata Metadata
        +IReadOnlyList~IHeaderContributor~ RequiredHeaderContributors
        +bool IsRemote
        +Dispose()
    }
    
    class SigningKey {
        <<abstract>>
        #CoseKey _coseKey
        +CoseAlgorithm Algorithm
        +int AlgorithmId
        +KeyType KeyType
        +int SignatureSize
        +Sign(ReadOnlySpan~byte~) byte[]
        +Sign(Stream) byte[]*
        +SignAsync(Stream, CancellationToken) Task~byte[]~*
        +Verify(ReadOnlySpan~byte~, ReadOnlySpan~byte~) bool
        +Verify(Stream, ReadOnlySpan~byte~) bool*
        +VerifyAsync(Stream, ReadOnlyMemory~byte~, CancellationToken) Task~bool~*
        +CreateToBeSignedBuilder() ToBeSignedBuilder
        +Dispose()*
    }
    
    class CoseKey {
        <<.NET Runtime>>
        +CoseAlgorithm Algorithm
        +KeyType KeyType
        +HashAlgorithmName HashAlgorithm
        +Sign(ReadOnlySpan~byte~, Span~byte~) int
        +Verify(ReadOnlySpan~byte~, ReadOnlySpan~byte~) bool
        +ComputeSignatureSize() int
        +CreateToBeSignedBuilder() ToBeSignedBuilder
    }
    
    class IHeaderContributor {
        <<interface>>
        +int Priority
        +IReadOnlyCollection~CoseHeaderLabel~ MandatoryProtectedHeaders
        +IReadOnlyCollection~CoseHeaderLabel~ MandatoryUnprotectedHeaders
        +ContributeProtectedHeaders(CoseHeaderMap headers, SigningContext context)
        +ContributeUnprotectedHeaders(CoseHeaderMap headers, SigningContext context)
    }
    
    ISigningService --> SigningKey : provides
    SigningKey --> CoseKey : wraps
    ISigningService --> IHeaderContributor : manages
```

## Signing Service and SigningKey Hierarchy

```mermaid
classDiagram
    class ISigningService {
        <<interface>>
        +SigningKey SigningKey
        +SigningMetadata Metadata
    }
    
    class LocalCertificateSigningService {
        -X509Certificate2 _certificate
        -SigningKey _signingKey
        -List~IHeaderContributor~ _headerContributors
        +FromWindowsStore(string thumbprint, StoreName store)$ LocalCertificateSigningService
        +FromPfxFile(string path, string password)$ LocalCertificateSigningService
        +FromCertificate(X509Certificate2 cert)$ LocalCertificateSigningService
    }
    
    class RemoteCertificateSigningService {
        -IRemoteSigningClient _client
        -SigningKey _signingKey
        -X509Certificate2 _certificate
        -List~IHeaderContributor~ _headerContributors
        +ForAzureTrustedSigning(string endpoint, string account, TokenCredential cred)$ RemoteCertificateSigningService
        +ForAzureKeyVault(Uri vaultUri, string certName, TokenCredential cred)$ RemoteCertificateSigningService
    }
    
    class SigningKey {
        <<abstract>>
        #CoseKey _coseKey
        +Sign(ReadOnlySpan~byte~) byte[]
        +Sign(Stream) byte[]*
        +SignAsync(Stream, CancellationToken) Task~byte[]~*
    }
    
    class LocalSigningKey {
        -CoseKey _coseKey
        -AsymmetricAlgorithm _key
        -HashAlgorithmName _hashAlgorithm
        +Sign(Stream) byte[]
        +SignAsync(Stream, CancellationToken) Task~byte[]~
    }
    
    class RemoteSigningKey {
        -IRemoteSigningClient _client
        -CoseAlgorithm _algorithm
        -HashAlgorithmName _hashAlgorithm
        +Sign(Stream) byte[]
        +SignAsync(Stream, CancellationToken) Task~byte[]~
    }
    
    class CoseKey {
        <<.NET Runtime>>
        +Sign(ReadOnlySpan~byte~, Span~byte~) int
        +Verify(ReadOnlySpan~byte~, ReadOnlySpan~byte~) bool
    }
    
    ISigningService <|.. LocalCertificateSigningService : implements
    ISigningService <|.. RemoteCertificateSigningService : implements
    SigningKey <|-- LocalSigningKey : extends
    SigningKey <|-- RemoteSigningKey : extends
    LocalSigningKey --> CoseKey : wraps
    LocalCertificateSigningService --> LocalSigningKey : creates
    RemoteCertificateSigningService --> RemoteSigningKey : creates
```

## CoseKey Integration and Key Type Support

```mermaid
classDiagram
    class SigningKey {
        <<abstract>>
        #CoseKey _coseKey
        +CoseAlgorithm Algorithm
        +KeyType KeyType
    }
    
    class LocalSigningKey {
        -CoseKey _coseKey
        -AsymmetricAlgorithm _key
        +FromCertificate(X509Certificate2)$ LocalSigningKey
        +FromRsa(RSA, RSASignaturePadding, HashAlgorithmName)$ LocalSigningKey
        +FromECDsa(ECDsa, HashAlgorithmName)$ LocalSigningKey
        +FromMLDsa(MLDsa)$ LocalSigningKey
    }
    
    class CoseKey {
        <<.NET Runtime>>
        +CoseAlgorithm Algorithm
        +KeyType KeyType
        +Sign(ReadOnlySpan~byte~, Span~byte~) int
        +Verify(ReadOnlySpan~byte~, ReadOnlySpan~byte~) bool
        +ComputeSignatureSize() int
        +CreateToBeSignedBuilder() ToBeSignedBuilder
    }
    
    class RSA {
        <<.NET>>
        +SignData(byte[], HashAlgorithmName, RSASignaturePadding) byte[]
        +VerifyData(byte[], byte[], HashAlgorithmName, RSASignaturePadding) bool
    }
    
    class ECDsa {
        <<.NET>>
        +SignData(byte[], HashAlgorithmName) byte[]
        +VerifyData(byte[], byte[], HashAlgorithmName) bool
    }
    
    class MLDsa {
        <<.NET Experimental>>
        +SignData(ReadOnlySpan~byte~, Span~byte~)
        +VerifyData(ReadOnlySpan~byte~, ReadOnlySpan~byte~) bool
    }
    
    class IncrementalHash {
        <<.NET>>
        +CreateHash(HashAlgorithmName)$ IncrementalHash
        +AppendData(byte[], int, int)
        +GetHashAndReset() byte[]
    }
    
    SigningKey <|-- LocalSigningKey
    LocalSigningKey --> CoseKey : wraps
    CoseKey --> RSA : uses internally
    CoseKey --> ECDsa : uses internally
    CoseKey --> MLDsa : uses internally
    LocalSigningKey --> IncrementalHash : uses for stream signing
    
    note for CoseKey "Microsoft's COSE implementation\nHandles algorithm mapping\nRSA → PS256/PS384/PS512\nECDsa → ES256/ES384/ES512\nML-DSA → MLDsa44/65/87"
    note for LocalSigningKey "Adds stream/async support\nusing IncrementalHash for\nRSA and ECDsa"
```

## Header Contributor Hierarchy

```mermaid
classDiagram
    class IHeaderContributor {
        <<interface>>
        +int Priority
        +ContributeProtectedHeaders()
        +ContributeUnprotectedHeaders()
    }
    
    class AlgorithmHeaderContributor {
        +Priority = 5
        +MandatoryProtectedHeaders = [Algorithm]
        +ContributeProtectedHeaders()
    }
    
    class CertificateHeaderContributor {
        -X509Certificate2 _certificate
        -IReadOnlyList~X509Certificate2~ _chain
        +Priority = 10
        +MandatoryUnprotectedHeaders = [X5T, X5Chain]
        +ContributeUnprotectedHeaders()
    }
    
    class ContentTypeHeaderContributor {
        +Priority = 20
        +ContributeProtectedHeaders()
    }
    
    class HashVHeaderContributor {
        -HashVStructure _hashV
        +Priority = 15
        +MandatoryProtectedHeaders = [Location]
        +ContributeProtectedHeaders()
    }
    
    class ScittHeaderContributor {
        +Priority = 30
        +ContributeProtectedHeaders()
    }
    
    IHeaderContributor <|.. AlgorithmHeaderContributor : implements
    IHeaderContributor <|.. CertificateHeaderContributor : implements
    IHeaderContributor <|.. ContentTypeHeaderContributor : implements
    IHeaderContributor <|.. HashVHeaderContributor : implements
    IHeaderContributor <|.. ScittHeaderContributor : implements
```

## Factory and Options

```mermaid
classDiagram
    class DirectSignatureFactory {
        <<static>>
        +Sign(byte[] payload, DirectSigningOptions options)$ CoseSign1Message
        +SignDetached(byte[] payload, DirectSigningOptions options)$ CoseSign1Message
        -BuildToBeSignedStructure(CoseHeaderMap headers, byte[] payload)$ byte[]
        -AddCustomHeaders(CoseHeaderMap headers, Dictionary customHeaders)$
    }
    
    class IndirectSignatureFactory {
        <<static>>
        +SignWithHashV(byte[] payload, IndirectSigningOptions options)$ CoseSign1Message
        +SignWithHashEnvelope(byte[] payload, IndirectSigningOptions options)$ CoseSign1Message
        -CreateHashVStructure(byte[] hash, Uri location)$ HashVStructure
        -CreateHashEnvelope(byte[] payload, HashAlgorithmName algo)$ HashEnvelope
    }
    
    class DirectSigningOptions {
        +ISigningService SigningService
        +string ContentType
        +bool EmbedPayload
        +Dictionary~CoseHeaderLabel,CoseHeaderValue~ CustomProtectedHeaders
        +Dictionary~CoseHeaderLabel,CoseHeaderValue~ CustomUnprotectedHeaders
        +List~IHeaderContributor~ AdditionalHeaderContributors
        +bool EnableScittCompliance
    }
    
    class IndirectSigningOptions {
        +ISigningService SigningService
        +CoseHashAlgorithm HashAlgorithm
        +Uri PayloadLocation
        +string ContentType
        +List~IHeaderContributor~ AdditionalHeaderContributors
    }
    
    DirectSignatureFactory --> DirectSigningOptions : uses
    IndirectSignatureFactory --> IndirectSigningOptions : uses
    DirectSigningOptions --> ISigningService : contains
    IndirectSigningOptions --> ISigningService : contains
```

## Complete Object Composition

```mermaid
classDiagram
    class Caller {
        +CreateSigningService()
        +Sign()
    }
    
    class LocalCertificateSigningService {
    }
    
    class RsaCryptographicProvider {
    }
    
    class CertificateHeaderContributor {
    }
    
    class AlgorithmHeaderContributor {
    }
    
    class DirectSigningOptions {
    }
    
    class DirectSignatureFactory {
    }
    
    class CoseSign1Message {
    }
    
    Caller --> LocalCertificateSigningService : creates
    LocalCertificateSigningService --> RsaCryptographicProvider : contains
    LocalCertificateSigningService --> CertificateHeaderContributor : provides
    LocalCertificateSigningService --> AlgorithmHeaderContributor : provides
    
    Caller --> DirectSigningOptions : creates
    DirectSigningOptions --> LocalCertificateSigningService : references
    
    Caller --> DirectSignatureFactory : calls Sign()
    DirectSignatureFactory --> DirectSigningOptions : receives
    DirectSignatureFactory --> IHeaderContributor : collects from service
    DirectSignatureFactory --> ICryptographicProvider : uses for signing
    DirectSignatureFactory --> CoseSign1Message : creates
    
    Caller --> CoseSign1Message : receives
```

## Remote Signing Architecture

```mermaid
classDiagram
    class RemoteCertificateSigningService {
        -IRemoteSigningClient _client
        -X509Certificate2 _publicCertificate
    }
    
    class IRemoteSigningClient {
        <<interface>>
        +GetPublicCertificate() X509Certificate2
        +SignData(byte[] data) byte[]
        +GetCertificateChain() List~X509Certificate2~
    }
    
    class AzureTrustedSigningClient {
        -string _endpoint
        -string _accountName
        -TokenCredential _credential
        +GetPublicCertificate() X509Certificate2
        +SignData(byte[] data) byte[]
    }
    
    class AzureKeyVaultClient {
        -Uri _vaultUri
        -string _keyName
        -TokenCredential _credential
        +GetPublicCertificate() X509Certificate2
        +SignData(byte[] data) byte[]
    }
    
    class RemoteCryptographicProvider {
        -IRemoteSigningClient _client
        +SignData(byte[] data, HashAlgorithmName hash) byte[]
    }
    
    RemoteCertificateSigningService --> IRemoteSigningClient : uses
    RemoteCertificateSigningService --> RemoteCryptographicProvider : contains
    RemoteCryptographicProvider --> IRemoteSigningClient : delegates to
    
    IRemoteSigningClient <|.. AzureTrustedSigningClient : implements
    IRemoteSigningClient <|.. AzureKeyVaultClient : implements
```

## Signing Flow - Object Interactions

```mermaid
sequenceDiagram
    participant C as Caller
    participant LSS as LocalCertificateSigningService
    participant RCP as RsaCryptographicProvider
    participant CHC as CertificateHeaderContributor
    participant AHC as AlgorithmHeaderContributor
    participant DSO as DirectSigningOptions
    participant DSF as DirectSignatureFactory
    participant CSM as CoseSign1Message
    
    C->>LSS: FromWindowsStore(thumbprint)
    activate LSS
    LSS->>LSS: Load certificate from store
    LSS->>RCP: new RsaCryptographicProvider(rsaKey)
    LSS->>CHC: new CertificateHeaderContributor(cert, chain)
    LSS->>AHC: new AlgorithmHeaderContributor()
    LSS-->>C: service instance
    deactivate LSS
    
    C->>DSO: new DirectSigningOptions { service, contentType }
    
    C->>DSF: Sign(payload, options)
    activate DSF
    DSF->>LSS: Get RequiredHeaderContributors
    LSS-->>DSF: [CHC, AHC]
    
    DSF->>CHC: ContributeUnprotectedHeaders(headers, context)
    activate CHC
    CHC->>CHC: Add X5T header
    CHC->>CHC: Add X5Chain header
    deactivate CHC
    
    DSF->>AHC: ContributeProtectedHeaders(headers, context)
    activate AHC
    AHC->>AHC: Add Algorithm header
    deactivate AHC
    
    DSF->>DSF: BuildToBeSignedStructure(headers, payload)
    
    DSF->>LSS: Get CryptographicProvider
    LSS-->>DSF: RsaCryptographicProvider
    
    DSF->>RCP: SignData(toBeSigned, hashAlgorithm)
    activate RCP
    RCP->>RCP: Compute RSA signature
    RCP-->>DSF: signature bytes
    deactivate RCP
    
    DSF->>CSM: new CoseSign1Message(headers, payload, signature)
    DSF-->>C: CoseSign1Message
    deactivate DSF
```

## PQC Hybrid Signing Flow

```mermaid
sequenceDiagram
    participant C as Caller
    participant HSS as HybridSigningService
    participant HCP as HybridCryptographicProvider
    participant RCP as RsaCryptographicProvider
    participant MCP as MLDsaCryptographicProvider
    participant DSF as DirectSignatureFactory
    
    C->>HSS: Create with RSA + ML-DSA keys
    HSS->>RCP: new RsaCryptographicProvider(rsaKey)
    HSS->>MCP: new MLDsaCryptographicProvider(mldsaKey)
    HSS->>HCP: new HybridCryptographicProvider(rcp, mcp)
    HSS-->>C: service instance
    
    C->>DSF: Sign(payload, options with HSS)
    DSF->>HCP: SignData(toBeSigned, hashAlgorithm)
    
    activate HCP
    HCP->>RCP: SignData(toBeSigned, hashAlgorithm)
    RCP-->>HCP: classical signature
    
    HCP->>MCP: SignData(toBeSigned, hashAlgorithm)
    MCP-->>HCP: PQC signature
    
    HCP->>HCP: Combine signatures
    HCP-->>DSF: hybrid signature
    deactivate HCP
    
    DSF-->>C: CoseSign1Message with hybrid signature
```

## Extension Point - Custom Signing Service

```mermaid
classDiagram
    class ISigningService {
        <<interface>>
    }
    
    class CustomHsmSigningService {
        -IHsmClient _hsmClient
        -string _keyIdentifier
        -HsmCryptographicProvider _cryptoProvider
        +FromHsmConfig(endpoint, keyId, cred)$ CustomHsmSigningService
        +CryptographicProvider ICryptographicProvider
        +Metadata SigningMetadata
        +RequiredHeaderContributors IReadOnlyList
        +IsRemote bool
    }
    
    class HsmCryptographicProvider {
        -IHsmClient _client
        -string _keyId
        +SignData(byte[], HashAlgorithmName) byte[]
        +VerifySignature(byte[], byte[], HashAlgorithmName) bool
    }
    
    class HsmHeaderContributor {
        -string _keyIdentifier
        +Priority = 25
        +ContributeProtectedHeaders()
    }
    
    ISigningService <|.. CustomHsmSigningService : implements
    CustomHsmSigningService --> HsmCryptographicProvider : contains
    CustomHsmSigningService --> HsmHeaderContributor : provides
```

## Data Flow Architecture

```
┌─────────────┐
│   Payload   │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────┐
│     DirectSignatureFactory.Sign()       │
│  1. Collect header contributors         │
│  2. Execute contributors (priority)     │
│  3. Build protected headers map         │
│  4. Build unprotected headers map       │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│    Build ToBeSigned Structure           │
│  Sig_structure = [                      │
│    "Signature1",                        │
│    protected_headers_bstr,              │
│    empty_or_serialized_ext_aad,         │
│    payload                              │
│  ]                                      │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  ICryptographicProvider.SignData()      │
│  • Hash the ToBeSigned structure        │
│  • Sign the hash with private key       │
│  • Return signature bytes               │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│      Create CoseSign1Message            │
│  • Protected headers (CBOR encoded)     │
│  • Unprotected headers (CBOR encoded)   │
│  • Payload (embedded or null)           │
│  • Signature bytes                      │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────┐
│   Return    │
│  Message    │
└─────────────┘
```

## Component Responsibility Matrix

| Component | Responsibility | Knows About | Doesn't Know About |
|-----------|---------------|-------------|-------------------|
| **ISigningService** | Coordinate signing operations | CryptographicProvider, HeaderContributors, Metadata | COSE message structure, Factory logic |
| **ICryptographicProvider** | Sign/verify data | Key material, algorithms | COSE headers, Certificates |
| **IHeaderContributor** | Add headers to COSE message | Header labels, values, context | Signing logic, key material |
| **DirectSignatureFactory** | Orchestrate signing flow | Options, headers, signing service | Key details, certificate internals |
| **IndirectSignatureFactory** | Orchestrate indirect signing | Hash structures, locations | Key details, signing internals |
| **LocalCertificateSigningService** | Manage local certificate | Certificate, chain, local crypto | Remote services, factory logic |
| **RemoteCertificateSigningService** | Manage remote signing | Remote client, public cert | Local key storage, factory logic |

## Layer Separation

```
┌─────────────────────────────────────────────────────────┐
│                    CALLER LAYER                          │
│  • Creates signing services                             │
│  • Creates options                                      │
│  • Calls factories                                      │
│  • Receives signed messages                             │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   FACTORY LAYER                          │
│  • Orchestrates signing flow                            │
│  • Collects header contributors                         │
│  • Builds COSE message structure                        │
│  • Returns CoseSign1Message                             │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  SERVICE LAYER                           │
│  • Provides cryptographic provider                      │
│  • Provides header contributors                         │
│  • Manages certificates/keys                            │
│  • Abstracts local vs remote                            │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              CRYPTOGRAPHIC LAYER                         │
│  • Sign data with keys                                  │
│  • Verify signatures                                    │
│  • Encrypt/decrypt (if supported)                       │
│  • Abstract RSA/ECDsa/ML-DSA/etc.                       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                 HEADER LAYER                             │
│  • Add mandatory headers                                │
│  • Add optional headers                                 │
│  • Priority-based execution                             │
│  • Context-aware contribution                           │
└─────────────────────────────────────────────────────────┘
```

This architecture ensures clean separation of concerns with well-defined boundaries between layers.

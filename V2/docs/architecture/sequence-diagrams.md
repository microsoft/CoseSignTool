# Sequence Diagrams

This page contains Mermaid sequence diagrams that document the **runtime call ordering** and the **dependency graph** across CoseSignTool V2’s major subsystems.

> These diagrams are based on the current V2 implementation (factories, validator orchestration, default-component discovery, and CLI plugin loading).

---

## Signing (Direct)

The preferred entry point is `CoseSign1MessageFactory`, which routes based on the runtime type of `SigningOptions`.

```mermaid
sequenceDiagram
    autonumber
    participant App as Consumer/App
    participant Router as CoseSign1MessageFactory
    participant Direct as DirectSignatureFactory
    participant Svc as ISigningService<SigningOptions>
    participant Cose as System.Security.Cryptography.Cose
    participant T as ITransparencyProvider (0..n)

    App->>Router: CreateCoseSign1MessageAsync(payload, contentType, DirectSignatureOptions)
    Router->>Direct: CreateCoseSign1MessageAsync(...)

    Direct->>Direct: Build header contributors
    Note over Direct: ContentTypeHeaderContributor is prepended

    Direct->>Svc: GetCoseSigner(SigningContext)
    Svc-->>Direct: CoseSigner

    alt EmbedPayload == true
        Direct->>Cose: CoseSign1Message.SignEmbedded(...)
    else EmbedPayload == false
        Direct->>Cose: CoseSign1Message.SignDetachedAsync(stream, ...)
    end

    Direct->>Cose: CoseMessage.DecodeSign1(signatureBytes)

    alt Transparency configured AND not disabled
        loop Each provider
            Direct->>T: AddTransparencyProofAsync(message)
            T-->>Direct: (possibly new) message
        end
    else Transparency disabled or none configured
        Note over Direct: Skip transparency providers
    end

    Direct-->>Router: CoseSign1Message
    Router-->>App: CoseSign1Message
```

Notes:
- **Transparency proofs are applied only by the async message-returning APIs** (e.g., `CreateCoseSign1MessageAsync`). The byte-returning APIs (`CreateCoseSign1MessageBytes*`) produce a valid signature but do not apply transparency.

---

## Signing (Indirect / Hash Envelope)

Indirect signatures hash the payload and sign the hash, while storing the hash-envelope metadata in protected headers.

```mermaid
sequenceDiagram
    autonumber
    participant App as Consumer/App
    participant Router as CoseSign1MessageFactory
    participant Indirect as IndirectSignatureFactory
    participant Direct as DirectSignatureFactory
    participant Svc as ISigningService<SigningOptions>
    participant Cose as System.Security.Cryptography.Cose
    participant T as ITransparencyProvider (0..n)

    App->>Router: CreateCoseSign1MessageAsync(payload, contentType, IndirectSignatureOptions)
    Router->>Indirect: CreateCoseSign1MessageAsync(...)

    Indirect->>Indirect: Compute payload hash (HashAlgorithm)
    Indirect->>Indirect: Build CoseHashEnvelopeHeaderContributor
    Indirect->>Indirect: Build DirectSignatureOptions (payload = hash)

    Indirect->>Direct: CreateCoseSign1MessageAsync(hashBytes, contentType, directOptions)

    Direct->>Svc: GetCoseSigner(SigningContext)
    Svc-->>Direct: CoseSigner
    Direct->>Cose: CoseSign1Message.SignEmbedded(hashBytes, ...)
    Direct->>Cose: CoseMessage.DecodeSign1(signatureBytes)

    alt Transparency configured AND not disabled
        loop Each provider
            Direct->>T: AddTransparencyProofAsync(message)
            T-->>Direct: (possibly new) message
        end
    end

    Direct-->>Indirect: CoseSign1Message
    Indirect-->>Router: CoseSign1Message
    Router-->>App: CoseSign1Message
```

---

## Validation (Staged Orchestration)

`CoseSign1Validator` enforces the secure-by-default stage ordering:
1) key material resolution → 2) trust → 3) signature verification → 4) post-signature policy.

```mermaid
sequenceDiagram
    autonumber
    participant App as Consumer/App
    participant Msg as CoseSign1Message
    participant V as CoseSign1Validator
    participant R as ISigningKeyResolver (0..n)
    participant Plan as CompiledTrustPlan
    participant Cose as System.Security.Cryptography.Cose
    participant P as IPostSignatureValidator (0..n)

    App->>Msg: Validate(validator)
    Msg->>V: Validate(message)

    Note over V: Stage 1 — Key Material Resolution
    loop Resolvers (first success wins)
        V->>R: Resolve / ResolveAsync
        R-->>V: SigningKeyResolutionResult
    end

    alt No signing key resolved
        V-->>Msg: Resolution Failure
        Msg-->>App: CoseSign1ValidationResult (later stages NotApplicable)
    else Signing key resolved
        Note over V: Stage 2 — Signing Key Trust
        V->>Plan: EvaluateWithAudit*(messageId, message, subject, options)
        Plan-->>V: TrustDecision (+ TrustDecisionAudit)

        alt Trust plan NOT satisfied
            V-->>Msg: Trust Failure
            Msg-->>App: CoseSign1ValidationResult (signature/post NotApplicable)
        else Trust plan satisfied
            Note over V: Stage 3 — Signature Verification
            V->>Cose: message.VerifyEmbedded(...) OR VerifyDetached(...)
            Cose-->>V: bool

            alt Signature invalid
                V-->>Msg: Signature Failure
                Msg-->>App: CoseSign1ValidationResult (post NotApplicable)
            else Signature valid
                Note over V: Stage 4 — Post-Signature
                loop Post-signature validators
                    V->>P: Validate / ValidateAsync(PostSignatureValidationContext)
                    P-->>V: ValidationResult
                end
                V-->>Msg: Overall Success
                Msg-->>App: CoseSign1ValidationResult
            end
        end
    end
```

---

## Validation (DI Composition)

V2 validation is configured via DI. You opt into trust packs (and related staged services) via `ConfigureCoseValidation()` and `Enable*Trust(...)`, then create an `ICoseSign1Validator` using `ICoseSign1ValidatorFactory`.

```mermaid
sequenceDiagram
    autonumber
    participant App as Consumer/App
    participant SC as ServiceCollection
    participant VB as ICoseValidationBuilder
    participant SP as IServiceProvider
    participant F as ICoseSign1ValidatorFactory
    participant Msg as CoseSign1Message

    App->>SC: new ServiceCollection()
    App->>SC: ConfigureCoseValidation()
    SC-->>VB: ICoseValidationBuilder
    App->>VB: Enable*Trust(...)
    App->>SP: BuildServiceProvider()
    App->>F: Resolve ICoseSign1ValidatorFactory
    F-->>App: Create(...)
    App->>Msg: Validate(validator)
    Msg-->>App: CoseSign1ValidationResult
```

---

## CLI (Plugin Loading → Verify)

The CLI uses plugins to contribute signing commands, verification providers, and transparency providers.

```mermaid
sequenceDiagram
    autonumber
    participant Main as CoseSignTool.Program
    participant CB as CommandBuilder
    participant PL as PluginLoader
    participant LC as PluginLoadContext
    participant Asm as Plugin Assembly
    participant P as IPlugin
    participant VP as IVerificationProvider (0..n)
    participant VC as VerifyCommandHandler
    participant Msg as CoseSign1Message
    participant VB as ICoseValidationBuilder
    participant F as ICoseSign1ValidatorFactory

    Main->>CB: BuildRootCommand(additionalPluginDirs)
    CB->>PL: LoadPluginsAsync(pluginsDir, additionalDirs)

    loop Each plugin subdirectory
        PL->>LC: new PluginLoadContext(...)
        PL->>LC: LoadFromAssemblyPath(*.Plugin.dll)
        LC-->>PL: Assembly
        PL->>Asm: GetTypes()
        Asm-->>PL: IPlugin types
        PL->>P: Activator.CreateInstance()
        PL->>P: InitializeAsync()
    end

    CB->>P: GetExtensions()
    P-->>CB: PluginExtensions
    CB->>VP: (collect verification providers)

    Note over VC: Later, when `verify` runs...
    VC->>VP: IsActivated(parseResult)
    VC->>VB: ConfigureCoseValidation()
    VC->>VP: ConfigureValidation(validationBuilder, parseResult, context)
    VP-->>VC: (register trust packs + staged services)
    VC->>F: Resolve ICoseSign1ValidatorFactory
    F-->>VC: Create(...)
    VC->>Msg: Validate(validator)
    Msg-->>VC: CoseSign1ValidationResult
```

---

## See Also

- Validation framework: `CoseSign1.Validation` (staged orchestration)
- Signing factories: `CoseSign1.Factories` (direct + indirect)
- Plugin model: `CoseSignTool.Abstractions` + `CoseSignTool` (CLI)

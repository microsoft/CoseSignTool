# Trust plans and policies (C++)

The trust authoring surface is in `<cose/sign1/trust.hpp>`.

There are two related concepts:

- **Trust policy** (`TrustPolicyBuilder`): a fluent surface for message-scope and pack-specific
  requirements, compiled into a bundled plan.
- **Trust plan builder** (`TrustPlanBuilder`): selects pack default plans and composes them
  (OR/AND), or compiles allow-all/deny-all plans.

## Authoring a trust policy

```cpp
#include <cose/cose.hpp>

cose::ValidatorBuilder builder;
cose::WithCertificates(builder);
cose::WithMst(builder, mst_opts);

// Create a policy from the builder
cose::TrustPolicyBuilder policy(builder);

// Message-scope rules chain fluently
policy
    .RequireContentTypeNonEmpty()
    .And()
    .RequireCwtClaimsPresent()
    .And()
    .RequireCwtIssEq("did:x509:abc123");

// Pack-specific rules use free functions
cose::RequireX509ChainTrusted(policy);
policy.And();
cose::RequireSigningCertificatePresent(policy);

// Compile and attach
auto plan = policy.Compile();
cose::WithCompiledTrustPlan(builder, plan);
auto validator = builder.Build();
```

## Using pack default plans

Packs can provide default trust plans. Use `TrustPlanBuilder` to compose them:

```cpp
cose::ValidatorBuilder builder;
cose::WithMst(builder, mst_opts);

cose::TrustPlanBuilder plan_builder(builder);
plan_builder.AddAllPackDefaultPlans();

// Compile as OR (any pack's default plan passing is sufficient)
auto plan = plan_builder.CompileOr();
cose::WithCompiledTrustPlan(builder, plan);

auto validator = builder.Build();
```

## Plan composition modes

| Method | Behavior |
|--------|----------|
| `CompileOr()` | Any selected plan passing is sufficient |
| `CompileAnd()` | All selected plans must pass |
| `CompileAllowAll()` | Unconditionally passes |
| `CompileDenyAll()` | Unconditionally fails |

## Inspecting registered packs

```cpp
cose::TrustPlanBuilder plan_builder(builder);
size_t count = plan_builder.PackCount();

for (size_t i = 0; i < count; ++i) {
    std::string name = plan_builder.PackName(i);
    bool has_default = plan_builder.PackHasDefaultPlan(i);
}
```

## Error handling

- Constructing a `TrustPolicyBuilder` or `TrustPlanBuilder` from a consumed builder throws `cose::cose_error`.
- Calling methods on a moved-from builder throws `cose::cose_error`.
- `Compile()` throws if required pack facts are unavailable (pack not registered).
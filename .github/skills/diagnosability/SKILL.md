---
name: diagnosability
description: Ensure V2 produces production-quality diagnostics: actionable exceptions, unique error codes, correlation IDs, structured logging with event IDs, and no sensitive-data leakage. Use when changing error handling/logging, introducing new failure modes, or designing public APIs.
compatibility: Intended for this repository’s V2/ .NET solution.
metadata:
  source: migrated-from-.github/agents/05c-diagnosability.agent.md
---

# Skill Instructions

## Scope
- Work exclusively within `V2/`.

## What to do
1. Improve exception messages to be actionable (what/why/how), preserve inner exceptions.
2. Ensure each failure mode has a unique, documented error code.
3. Flow correlation IDs through operations and include them in logs/exceptions.
4. Ensure public-facing classes accept `ILogger<T>` via constructor injection (and validate it), so logging is testable and consistent.
5. Use structured logging with event IDs; capture duration and key context (sanitized).
6. Use the HighPerformanceLogging standard for log messages: prefer source-generated logging via `LoggerMessage` partial methods for frequently executed paths.
7. Never log secrets, key material, or payload contents.

## Hard requirements
- `ILogger<T>` MUST be injected into public-facing classes (no static/global loggers).
- Hot paths MUST use HighPerformanceLogging (`[LoggerMessage]` source-generated logging).
- Do not use string interpolation, concatenation, or `string.Format` in logging messages.
- For `LogError`/`LogCritical`, pass the `Exception` as the dedicated exception parameter.
- Log messages MUST include an `EventId` for significant operations.

## Static/extension patterns
- Static methods that need logging MUST accept an `ILogger`/`ILogger<T>` parameter.
- Static helper/utility classes MUST NOT create their own `LoggerFactory` or cache loggers.
- Extension methods SHOULD be implemented as source-generated logger extensions (see reference) and called as `logger.SomeEvent(...)`.
- If a type cannot accept `ILogger<T>` (pure static utility), it should do no logging and instead return enough context for the caller to log.

For detailed standards, templates, and audit commands, see [references/REFERENCE.md](references/REFERENCE.md).

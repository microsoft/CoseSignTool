# CLI Reference

CoseSignTool provides a command-line interface for signing, verifying, and inspecting COSE Sign1 messages.

## Installation

```bash
dotnet tool install -g CoseSignTool
cosesigntool --help
```

## Global Options

| Option | Description |
|--------|-------------|
| `-f`, `--output-format <format>` | Output format: `text`, `json`, `xml`, `quiet` |
| `--verbose` | Show detailed help including all options and examples |
| `--verbosity <N>` | Set logging verbosity level (0=quiet .. 4=trace) |
| `-vv` | Debug verbosity (equivalent to `--verbosity 3`) |
| `-vvv` | Trace verbosity (equivalent to `--verbosity 4`) |
| `--log-file <path>` | Write logs to file |
| `--log-file-append` | Append to existing log file |
| `--log-file-overwrite` | Overwrite existing log file (default) |
| `--additional-plugin-dir <dir>` | Load plugins from an additional directory |

## Commands

### sign

```bash
cosesigntool sign <root> <provider> [<payload>] [options]
```

- `<payload>` is optional: provide a file, `-` for stdin, or omit to read stdin.
- `<provider>` comes from plugins.

See [sign.md](sign.md) for the full sign reference.

### verify

```bash
cosesigntool verify <root> [<signature>] [options]
```

Verification roots:

- `x509` - X.509 trust and certificate policy options
- `akv` - Azure Key Vault key-only trust (kid pattern validation)
- `mst` - MST receipt trust (requires pinned keys or trusted ledger allow-list)

See [verify.md](verify.md) for root-specific options and examples.

### inspect

```bash
cosesigntool inspect [<file>] [options]
```

See [inspect.md](inspect.md) for details.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | File not found |
| 4 | Certificate not found |
| 5 | Certificate error |
| 10 | Signing failed |
| 20 | Validation failed |
| 21 | Invalid signature |
| 22 | Verification failed |
| 23 | Certificate expired |
| 24 | Untrusted certificate |
| 30 | Plugin error |
| 40 | Inspection failed |

## Logging

```bash
cosesigntool verify x509 document.cose -vvv --log-file debug.log
```

See [Logging and Diagnostics](../guides/logging-diagnostics.md) for more examples.

## Plugins

Plugins are automatically loaded from the `plugins/` subdirectory next to the executable.

```bash
cosesigntool --additional-plugin-dir /path/to/plugins verify x509 document.cose
```

See [Plugin Development](../plugins/README.md) for creating custom plugins.

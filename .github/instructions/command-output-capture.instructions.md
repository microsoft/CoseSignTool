# Command Output Capture Policy — All Agents

> **Applies to:** `**` (all files, all agents, all tasks in this repository)

## Mandatory Rule: Capture Once, Search the File

**Tests, builds, and coverage commands in this repository are expensive — often taking minutes or tens of minutes to complete.** Agents MUST capture full command output to a file on the first execution, then search/filter/reason over that file for all subsequent analysis. **Re-running the same command with a different filter is strictly prohibited.**

## The Problem This Solves

❌ **PROHIBITED pattern** — re-running a command to filter differently:
```powershell
# First run: agent pipes to Select-String looking for errors
cargo test --workspace 2>&1 | Select-String "FAILED"

# Second run: same command, different filter (WASTING MINUTES)
cargo test --workspace 2>&1 | Select-String "error\[E"

# Third run: same command, yet another filter (COMPLETELY UNACCEPTABLE)
cargo test --workspace 2>&1 | Select-String "test result"
```

Each of those runs takes the **full execution time** of the command. Three filter passes on a 10-minute test suite wastes 20 minutes.

## Required Pattern: Capture Full Output to a File

✅ **REQUIRED pattern** — run once, capture everything, search the file:
```powershell
# Step 1: Run the command ONCE, capture ALL output (stdout + stderr) to a file
cargo test --workspace 2>&1 | Out-File -FilePath "$env:TEMP\test-output.txt" -Encoding utf8

# Step 2: Search the captured file as many times as needed (instant)
Select-String -Path "$env:TEMP\test-output.txt" -Pattern "FAILED"
Select-String -Path "$env:TEMP\test-output.txt" -Pattern "error\[E"
Select-String -Path "$env:TEMP\test-output.txt" -Pattern "test result"
Get-Content "$env:TEMP\test-output.txt" | Select-String "warning"
```

## Specific Rules

### 1. All Long-Running Commands MUST Capture to File

Any command that takes more than ~10 seconds MUST have its full output captured to a temporary file. This includes but is not limited to:

| Command Type | Examples |
|---|---|
| Test suites | `cargo test`, `dotnet test`, `npm test`, `pytest` |
| Builds | `cargo build`, `dotnet build`, `msbuild`, `npm run build` |
| Coverage | `cargo llvm-cov`, `dotnet test --collect`, coverage scripts |
| Linting | `cargo clippy`, `dotnet format`, `eslint` |
| Package restore | `cargo fetch`, `dotnet restore`, `npm install` |
| Any CI script | `collect-coverage.ps1`, or any orchestrating script |

### 2. Capture Syntax

Use one of these patterns to capture output:

**PowerShell (preferred in this repo):**
```powershell
# Capture stdout + stderr to file
<command> 2>&1 | Out-File -FilePath "$env:TEMP\<descriptive-name>.txt" -Encoding utf8

# Or use Tee-Object if you also want to see live output
<command> 2>&1 | Tee-Object -FilePath "$env:TEMP\<descriptive-name>.txt"
```

**Bash/Shell:**
```bash
<command> > /tmp/<descriptive-name>.txt 2>&1
```

**Rust/Cargo specific:**
```powershell
cargo test --workspace --no-fail-fast 2>&1 | Out-File -FilePath "$env:TEMP\cargo-test-output.txt" -Encoding utf8
cargo clippy --workspace 2>&1 | Out-File -FilePath "$env:TEMP\cargo-clippy-output.txt" -Encoding utf8
```

### 3. Search the File, NOT Re-Run the Command

After capturing, use these tools to analyze the output file:

```powershell
# Find specific patterns
Select-String -Path "$env:TEMP\cargo-test-output.txt" -Pattern "FAILED|error"

# Count occurrences
(Select-String -Path "$env:TEMP\cargo-test-output.txt" -Pattern "test result").Count

# Get context around matches
Select-String -Path "$env:TEMP\cargo-test-output.txt" -Pattern "FAILED" -Context 5,5

# Read specific line ranges
Get-Content "$env:TEMP\cargo-test-output.txt" | Select-Object -Skip 100 -First 50

# Get summary (tail)
Get-Content "$env:TEMP\cargo-test-output.txt" -Tail 50
```

### 4. When Re-Running IS Allowed

A command may only be re-executed if:
- The **source code has been modified** since the last run (i.e., you are testing a fix)
- The command **genuinely needs different arguments** (e.g., different `--package`, different test filter)
- The previous output file was **lost or corrupted**
- You need output from a **different command entirely**

A command MUST NOT be re-executed merely to:
- Apply a different `Select-String`, `grep`, `findstr`, or `Where-Object` filter
- See a different portion of the same output
- Count or summarize results differently
- Reformat or restructure the same data

### 5. File Naming Convention

Use descriptive names in `$env:TEMP` (or `/tmp` on Unix):
```
$env:TEMP\cargo-test-output.txt
$env:TEMP\cargo-clippy-output.txt
$env:TEMP\dotnet-build-output.txt
$env:TEMP\coverage-output.txt
```

### 6. Cleanup

Delete temporary output files when the task is complete:
```powershell
Remove-Item "$env:TEMP\cargo-test-output.txt" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\cargo-clippy-output.txt" -ErrorAction SilentlyContinue
```

## Summary

| Step | Action |
|------|--------|
| **Run** | Execute the command **once**, redirect all output to a file |
| **Search** | Use `Select-String`, `Get-Content`, `grep` on the **file** |
| **Iterate** | Modify code → re-run command → capture to file again |
| **Never** | Re-run the same command just to apply a different text filter |

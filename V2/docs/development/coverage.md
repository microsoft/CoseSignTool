# Code Coverage Guide

This guide explains how to measure and maintain code coverage for CoseSignTool V2.

## Overview

Code coverage measures how much of the codebase is exercised by tests. High coverage helps ensure code quality and catches regressions.

## Coverage Targets

V2 uses a strict **coverage gate** that must remain green.

| Category | Target | Notes |
|----------|--------|-------|
| Overall (V2 gate) | 95%+ | Enforced by `V2/collect-coverage.ps1` |
| Security-critical | 95%+ | Validators, signing, verification |
| Public API | As high as practical | Prefer tests for public surface |

## Running Coverage

### Coverage Gate (Recommended)

Run the same script used by the repo’s coverage gate:

```powershell
cd V2
powershell -ExecutionPolicy Bypass -File .\collect-coverage.ps1
```

Output:
- `V2/coverage.cobertura.xml`
- `V2/coverage-report/index.html`

The script exits non-zero if:
- the build fails,
- line coverage is below 95%, or
- tests fail (even if the coverage percentage is met).

### Prerequisites

The gate script requires these .NET tools to be available on PATH:

```powershell
dotnet tool install -g dotnet-coverage
dotnet tool install -g dotnet-reportgenerator-globaltool
```

If you already have them installed, you can skip this step.

### Basic Coverage Collection

```bash
dotnet test --collect:"XPlat Code Coverage"
```

### With Coverage Report

```bash
# Install report generator
dotnet tool install -g dotnet-reportgenerator-globaltool

# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults

# Generate HTML report
reportgenerator -reports:./TestResults/**/coverage.cobertura.xml -targetdir:./coverage-report -reporttypes:Html

# Open report (PowerShell)
Start-Process .\coverage-report\index.html
```

### Specific Projects

```bash
dotnet test V2/CoseSign1.Tests/CoseSign1.Tests.csproj --collect:"XPlat Code Coverage"
```

## Coverage Configuration

### coverlet.runsettings

Create a `coverlet.runsettings` file for configuration:

```xml
<?xml version="1.0" encoding="utf-8" ?>
<RunSettings>
  <DataCollectionRunSettings>
    <DataCollectors>
      <DataCollector friendlyName="XPlat Code Coverage">
        <Configuration>
          <Format>cobertura,opencover</Format>
          <Exclude>[*.Tests]*,[*]*.Migrations.*</Exclude>
          <Include>[CoseSign1*]*,[CoseSignTool*]*,[DIDx509*]*</Include>
          <ExcludeByAttribute>Obsolete,GeneratedCodeAttribute,CompilerGeneratedAttribute,ExcludeFromCodeCoverage</ExcludeByAttribute>
          <SingleHit>false</SingleHit>
          <UseSourceLink>true</UseSourceLink>
        </Configuration>
      </DataCollector>
    </DataCollectors>
  </DataCollectionRunSettings>
</RunSettings>
```

Use with:

```bash
dotnet test --settings coverlet.runsettings --collect:"XPlat Code Coverage"
```

## Excluding Code from Coverage

### Using Attributes

```csharp
using System.Diagnostics.CodeAnalysis;

[ExcludeFromCodeCoverage]
public class GeneratedCode
{
    // This class won't be included in coverage
}

public class MyClass
{
    [ExcludeFromCodeCoverage]
    public void DebugOnlyMethod()
    {
        // This method won't be included
    }
}
```

### Using Configuration

In `coverlet.runsettings`:

```xml
<Exclude>
  [*]*.Migrations.*,
  [*]*.Generated.*,
  [*.Tests]*
</Exclude>

<ExcludeByAttribute>
  Obsolete,
  GeneratedCodeAttribute,
  CompilerGeneratedAttribute,
  ExcludeFromCodeCoverage
</ExcludeByAttribute>
```

## Coverage Reports

### Report Types

| Type | Description | Use Case |
|------|-------------|----------|
| Cobertura | XML format | CI/CD integration |
| OpenCover | XML format | Historical tracking |
| HTML | Interactive web report | Local development |
| Badges | SVG/PNG images | README display |

### Generating Multiple Formats

```bash
reportgenerator \
  -reports:./TestResults/**/coverage.cobertura.xml \
  -targetdir:./coverage-report \
  -reporttypes:"Html;Cobertura;Badges"
```

## CI/CD Integration

### Azure DevOps

```yaml
- task: DotNetCoreCLI@2
  displayName: 'Run Tests with Coverage'
  inputs:
    command: 'test'
    projects: '**/*.Tests.csproj'
    arguments: '--collect:"XPlat Code Coverage" --results-directory $(Agent.TempDirectory)/TestResults'

- task: PublishCodeCoverageResults@1
  displayName: 'Publish Coverage'
  inputs:
    codeCoverageTool: 'Cobertura'
    summaryFileLocation: '$(Agent.TempDirectory)/TestResults/**/coverage.cobertura.xml'
```

### GitHub Actions

```yaml
- name: Run Tests with Coverage
  run: dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults

- name: Generate Coverage Report
  run: |
    dotnet tool install -g dotnet-reportgenerator-globaltool
    reportgenerator -reports:./TestResults/**/coverage.cobertura.xml -targetdir:./coverage-report

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./TestResults/**/coverage.cobertura.xml
```

## Analyzing Coverage

### Understanding the Report

```
Assembly Coverage:
- CoseSign1: 92.5% (185/200 lines)
  - DirectSignatureFactory: 95.0%
  - CoseSign1MessageReader: 88.0%

Uncovered Lines:
- DirectSignatureFactory.cs:45 - Error handling branch
- CoseSign1MessageReader.cs:78-82 - Rare edge case
```

### Finding Gaps

1. **Sort by coverage** - Focus on lowest coverage files first
2. **Check public methods** - Ensure all public API is covered
3. **Review uncovered branches** - Look for error handling gaps
4. **Check edge cases** - Null inputs, empty collections, boundaries

## Improving Coverage

### Adding Missing Tests

```csharp
// Uncovered: null input handling
[Test]
public void Method_WithNullInput_ThrowsArgumentNullException()
{
  Assert.Throws<ArgumentNullException>(() => _sut.Method(null));
}

// Uncovered: empty collection
[Test]
public void ProcessItems_WithEmptyList_ReturnsEmpty()
{
    var result = _sut.ProcessItems(Array.Empty<Item>());
  Assert.That(result, Is.Empty);
}

// Uncovered: boundary condition
[Test]
public void ValidateSize_AtMaximum_Succeeds()
{
    var result = _sut.ValidateSize(MaxSize);
  Assert.That(result, Is.True);
}
```

### Testing Error Paths

```csharp
[Test]
public async Task SignAsync_WhenServiceFails_ThrowsSigningException()
{
    // Arrange
    _mockService.Setup(s => s.SignAsync(It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CoseAlgorithm>(), It.IsAny<CancellationToken>()))
        .ThrowsAsync(new HttpRequestException("Service unavailable"));
    
    // Act & Assert
    Assert.ThrowsAsync<SigningException>(() => _sut.CreateSignatureAsync(payload));
}
```

## Coverage Thresholds

### Enforcing Minimum Coverage

The repo’s enforced threshold is implemented in `V2/collect-coverage.ps1`.

If you want a quick local check without the full gate script, you can still run coverage with `dotnet test --collect:"XPlat Code Coverage"`, but it will not match the gate’s tooling/output.

### In CI/CD

```yaml
- script: |
    coverage=$(grep -oP 'line-rate="\K[^"]+' TestResults/**/coverage.cobertura.xml | head -1)
    coverage_percent=$(echo "$coverage * 100" | bc)
    if (( $(echo "$coverage_percent < 80" | bc -l) )); then
      echo "Coverage $coverage_percent% is below threshold of 80%"
      exit 1
    fi
  displayName: 'Check Coverage Threshold'
```

## Best Practices

1. **Run coverage locally** before committing
2. **Review coverage in PRs** - Don't merge coverage regressions
3. **Focus on meaningful coverage** - Quality over quantity
4. **Test behavior, not implementation** - Coverage should be a side effect
5. **Exclude generated code** - Don't inflate numbers artificially
6. **Track coverage trends** - Monitor for regressions over time

## See Also

- [Testing Guide](testing.md)
- [Development Setup](setup.md)
- [Guides: Testing](../guides/testing.md)

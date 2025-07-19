# CoseSignTool Coding Standards for GitHub Copilot

This file ensures GitHub Copilot follows the repository's coding standards as defined in .editorconfig and established patterns.

## Code Generation Preferences

### File Headers
- Always include the Microsoft copyright header at the top of all C# files:
```csharp
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
```

### Namespace and Using Directives
- Use file-scoped namespaces (C# 10+ feature): `namespace MyNamespace;`
- Place using directives inside the namespace
- Sort System directives first, then others alphabetically
- Do not separate import directive groups with blank lines
- Follow namespace-to-folder structure matching

### Naming Conventions
- **Constants**: PascalCase (e.g., `DefaultStoreName`)
- **Static private fields**: `s_` prefix with camelCase (e.g., `s_factory`)
- **Private/internal instance fields**: `_` prefix with camelCase (e.g., `_commands`)
- **Public properties/methods**: PascalCase
- **Local variables**: camelCase
- **Parameters**: camelCase

### Code Style Preferences
- **Braces**: Always use braces for control statements (enforced as error)
- **var usage**: Avoid `var` - use explicit types for clarity
- **this qualifier**: Avoid `this.` unless absolutely necessary
- **Predefined types**: Use predefined types (`int`, `string`) over .NET types (`Int32`, `String`)
- **Null checking**: Prefer `is null` over `== null`
- **Object initialization**: Prefer object and collection initializers
- **String interpolation**: Use simplified interpolation when possible

### Expression Preferences
- **Expression-bodied members**: 
  - Use for properties, indexers, and accessors when appropriate
  - Avoid for methods, constructors, and operators (prefer block bodies)
- **Pattern matching**: Prefer pattern matching over `is` with cast checks
- **Target-typed new**: Use when type is apparent (e.g., `List<string> items = new();`)
- **Using statements**: Prefer simple using statements over using blocks

### Formatting Rules
- **Indentation**: 4 spaces (no tabs)
- **End of line**: CRLF (Windows line endings)
- **Final newline**: Do not insert final newline
- **Trim whitespace**: Always trim trailing whitespace
- **New lines**: 
  - Opening braces on new line for all constructs
  - `else`, `catch`, `finally` on new lines
  - Members in object initializers on new lines

### Space Preferences
- No space after casts: `(int)value`
- Space after keywords: `if (condition)`
- Space around binary operators: `a + b`
- Space after commas: `Method(a, b, c)`
- Space around colons in inheritance: `class Derived : Base`
- No space before dots: `object.Property`
- No space in empty parentheses: `Method()`

### Modifier Order
Follow this order: `public`, `private`, `protected`, `internal`, `static`, `extern`, `new`, `virtual`, `abstract`, `sealed`, `override`, `readonly`, `unsafe`, `volatile`, `async`

### Error Handling and Diagnostics
- Null reference warnings are suggestions, not errors
- Unused parameters should be flagged
- Platform compatibility should be validated
- File headers are required (enforced as error)
- Missing braces are errors
- Unused private members are errors

### Project-Specific Patterns
- **Plugin naming**: Use `.Plugin.csproj` suffix for auto-packaging
- **Assembly naming**: Use `.Plugin.dll` suffix for runtime discovery
- **Exit codes**: Use the `PluginExitCode` enum for plugin commands
- **Async patterns**: Always use `CancellationToken` parameters in async methods
- **Interface implementation**: Implement plugin interfaces (`ICoseSignToolPlugin`, `IPluginCommand`)
- **Error handling**: Use appropriate exit codes and console error output

### Documentation
- Use XML documentation comments for public APIs
- Include parameter descriptions and return value documentation
- Use `<summary>`, `<param>`, `<returns>` tags appropriately
- Document exceptions with `<exception>` tags

### Testing Patterns
- Use descriptive test method names
- Follow Arrange-Act-Assert pattern
- Use meaningful assertions with clear error messages
- Include both positive and negative test cases

### Plugin Development Guidelines
- Implement `PluginCommandBase` for command implementations
- Use proper dependency injection patterns
- Handle configuration through `IConfiguration`
- Implement proper cancellation token support
- Follow security best practices for plugin loading

## Example Code Structure

```csharp
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;
using CoseSignTool.Abstractions;

namespace CoseSignTool.MyPlugin;

/// <summary>
/// Example plugin implementation following repository standards.
/// </summary>
public class ExamplePlugin : ICoseSignToolPlugin
{
    private readonly List<IPluginCommand> _commands;
    private static readonly object s_lockObject = new();

    public ExamplePlugin()
    {
        _commands = new List<IPluginCommand>
        {
            new ExampleCommand()
        };
    }

    public string Name => "Example Plugin";
    public string Version => "1.0.0";
    public string Description => "An example plugin demonstrating coding standards.";
    public IEnumerable<IPluginCommand> Commands => _commands;

    public void Initialize(IConfiguration? configuration = null)
    {
        // Initialization logic here
    }
}

/// <summary>
/// Example command implementation.
/// </summary>
public class ExampleCommand : PluginCommandBase
{
    public override string Name => "example";
    public override string Description => "Example command for demonstration.";
    public override string Usage => "example --input <file> [--output <file>]";
    
    public override IDictionary<string, string> Options => new Dictionary<string, string>
    {
        ["--input"] = "input",
        ["--output"] = "output"
    };

    public override async Task<PluginExitCode> ExecuteAsync(
        IConfiguration configuration, 
        CancellationToken cancellationToken = default)
    {
        try
        {
            string inputFile = GetRequiredValue(configuration, "input");
            string? outputFile = GetOptionalValue(configuration, "output");

            if (!File.Exists(inputFile))
            {
                Console.Error.WriteLine($"Input file not found: {inputFile}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            // Process the file
            await ProcessFileAsync(inputFile, outputFile, cancellationToken);
            
            return PluginExitCode.Success;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation was cancelled");
            return PluginExitCode.UnknownError;
        }
        catch (ArgumentNullException ex)
        {
            Console.Error.WriteLine($"Missing required option: {ex.ParamName}");
            return PluginExitCode.MissingRequiredOption;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unexpected error: {ex.Message}");
            return PluginExitCode.UnknownError;
        }
    }

    private static async Task ProcessFileAsync(
        string inputFile, 
        string? outputFile, 
        CancellationToken cancellationToken)
    {
        // Implementation here
        await Task.CompletedTask;
    }
}
```

## Summary
When generating code for this repository, always:
1. Include the Microsoft copyright header
2. Use file-scoped namespaces
3. Follow the specified naming conventions
4. Use explicit types instead of var
5. Include proper error handling with appropriate exit codes
6. Implement cancellation token support in async methods
7. Use the established plugin patterns for extensibility
8. Follow the formatting and spacing rules exactly as specified
9. Include comprehensive XML documentation for public APIs
10. Ensure all generated code follows the .editorconfig rules

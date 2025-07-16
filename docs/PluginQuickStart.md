# Plugin Quick Start Guide

This guide will help you create your first CoseSignTool plugin in just a few minutes.

## Prerequisites

- .NET 8.0 SDK
- CoseSignTool source code or binaries
- A code editor (Visual Studio, VS Code, etc.)

## Step 1: Create the Plugin Project

Create a new class library project:

```bash
dotnet new classlib -n MyFirstPlugin
cd MyFirstPlugin
```

Update the project file (`MyFirstPlugin.csproj`):

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyName>MyFirst.Plugin</AssemblyName>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\CoseSignTool.Abstractions\CoseSignTool.Abstractions.csproj" />
  </ItemGroup>
</Project>
```

## Step 2: Create the Plugin Class

Replace the contents of `Class1.cs` with:

```csharp
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;

namespace MyFirstPlugin;

public class MyFirstPlugin : ICoseSignToolPlugin
{
    private readonly List<IPluginCommand> _commands;

    public MyFirstPlugin()
    {
        _commands = new List<IPluginCommand>
        {
            new HelloCommand()
        };
    }

    public string Name => "My First Plugin";
    public string Version => "1.0.0";
    public string Description => "A simple example plugin for CoseSignTool";
    public IEnumerable<IPluginCommand> Commands => _commands;

    public void Initialize(IConfiguration? configuration = null)
    {
        // Plugin initialization code here
        Console.WriteLine("My First Plugin initialized!");
    }
}
```

## Step 3: Create a Simple Command

Add a new file `HelloCommand.cs`:

```csharp
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;

namespace MyFirstPlugin;

public class HelloCommand : PluginCommandBase
{
    public override string Name => "hello";

    public override string Description => "Says hello with optional name parameter";

    public override string Usage => @"
hello - Says hello

Usage:
    CoseSignTool hello [--name <name>]

Options:
    --name    Name to greet (optional, default: 'World')
";

    public override IDictionary<string, string> Options => new Dictionary<string, string>
    {
        ["--name"] = "name"
    };

    public override async Task<PluginExitCode> ExecuteAsync(
        IConfiguration configuration, 
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Check for cancellation
            if (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            // Get the name parameter (optional)
            string name = GetOptionalValue(configuration, "name", "World") ?? "World";

            // Simple greeting
            Console.WriteLine($"Hello, {name}!");
            
            // Simulate some async work
            await Task.Delay(100, cancellationToken);
            
            Console.WriteLine("Plugin execution completed successfully.");

            return PluginExitCode.Success;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation was cancelled");
            return PluginExitCode.UnknownError;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return PluginExitCode.UnknownError;
        }
    }
}
```

## Step 4: Build the Plugin

Build your plugin:

```bash
dotnet build
```

## Step 5: Deploy the Plugin

1. Copy the built assembly to the CoseSignTool plugins directory:

```bash
# Windows
copy bin\Debug\net8.0\MyFirst.Plugin.dll "C:\path\to\CoseSignTool\plugins\"

# Linux/macOS
cp bin/Debug/net8.0/MyFirst.Plugin.dll /path/to/CoseSignTool/plugins/
```

2. Create the plugins directory if it doesn't exist:

```bash
mkdir plugins
```

## Step 6: Test Your Plugin

Run CoseSignTool to see your plugin in the help:

```bash
CoseSignTool --help
```

You should see your `hello` command listed under "Plugin Commands".

Test your command:

```bash
# Basic usage
CoseSignTool hello

# With name parameter
CoseSignTool hello --name "Developer"
```

## Step 7: Add More Functionality

Let's extend the hello command to work with files. Update `HelloCommand.cs`:

```csharp
public override string Usage => @"
hello - Says hello and optionally reads from a file

Usage:
    CoseSignTool hello [--name <name>] [--input <file>] [--output <file>]

Options:
    --name     Name to greet (optional, default: 'World')
    --input    Input file to read greeting from
    --output   Output file to write greeting to
";

public override IDictionary<string, string> Options => new Dictionary<string, string>
{
    ["--name"] = "name",
    ["--input"] = "input",
    ["--output"] = "output"
};

public override async Task<PluginExitCode> ExecuteAsync(
    IConfiguration configuration, 
    CancellationToken cancellationToken = default)
{
    try
    {
        cancellationToken.ThrowIfCancellationRequested();

        string name = GetOptionalValue(configuration, "name", "World") ?? "World";
        string? inputFile = GetOptionalValue(configuration, "input");
        string? outputFile = GetOptionalValue(configuration, "output");

        // Read from input file if specified
        if (!string.IsNullOrEmpty(inputFile))
        {
            if (!File.Exists(inputFile))
            {
                Console.Error.WriteLine($"Input file not found: {inputFile}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            string fileContent = await File.ReadAllTextAsync(inputFile, cancellationToken);
            name = fileContent.Trim();
        }

        string greeting = $"Hello, {name}! Greetings from My First Plugin.";

        // Write to output file if specified
        if (!string.IsNullOrEmpty(outputFile))
        {
            await File.WriteAllTextAsync(outputFile, greeting, cancellationToken);
            Console.WriteLine($"Greeting written to: {outputFile}");
        }
        else
        {
            Console.WriteLine(greeting);
        }

        return PluginExitCode.Success;
    }
    catch (OperationCanceledException)
    {
        Console.Error.WriteLine("Operation was cancelled");
        return PluginExitCode.UnknownError;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
        return PluginExitCode.UnknownError;
    }
}
```

## Step 8: Test Advanced Features

Rebuild and test the enhanced functionality:

```bash
dotnet build
# Copy the updated DLL to the plugins directory

# Test with input file
echo "Alice" > name.txt
CoseSignTool hello --input name.txt

# Test with output file
CoseSignTool hello --name "Bob" --output greeting.txt
cat greeting.txt
```

## Next Steps

Now that you have a basic plugin working:

1. **Read the full [Plugins.md](Plugins.md) documentation** for comprehensive details
2. **Study the Azure CTS Plugin** (`CoseSignTool.CTS.Plugin`) for a real-world example
3. **Add error handling** for edge cases and invalid inputs
4. **Implement validation** for required parameters
5. **Add unit tests** for your plugin commands
6. **Consider security** implications of file operations and user input

## Common Patterns

### Required vs Optional Parameters

```csharp
// Required parameter
string endpoint = GetRequiredValue(configuration, "endpoint");

// Optional parameter with default
string timeout = GetOptionalValue(configuration, "timeout", "30") ?? "30";

// Optional parameter that may be null
string? metadata = GetOptionalValue(configuration, "metadata");
```

### File Validation

```csharp
string filePath = GetRequiredValue(configuration, "file");

if (!File.Exists(filePath))
{
    Console.Error.WriteLine($"File not found: {filePath}");
    return PluginExitCode.UserSpecifiedFileNotFound;
}
```

### Cancellation Support

```csharp
// Check before expensive operations
cancellationToken.ThrowIfCancellationRequested();

// Pass to async methods
await someAsyncMethod(cancellationToken);

// Use in loops
for (int i = 0; i < items.Count; i++)
{
    cancellationToken.ThrowIfCancellationRequested();
    await ProcessItem(items[i], cancellationToken);
}
```

## Troubleshooting

**Plugin not found:**
- Ensure assembly name ends with `.Plugin.dll`
- Verify the DLL is in the `plugins` directory
- Check that your class implements `ICoseSignToolPlugin`

**Command not working:**
- Verify the `Options` dictionary maps command-line arguments correctly
- Check for typos in option names
- Ensure proper error handling and return codes

**Security errors:**
- Make sure plugins are only in the `plugins` subdirectory
- Don't try to load plugins from other locations

For more detailed information, see the complete [Plugins.md](Plugins.md) documentation.

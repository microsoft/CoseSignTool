# Plugin Development Examples

This directory contains example plugins demonstrating various patterns and capabilities of the CoseSignTool plugin system.

## Available Examples

### 1. HelloWorldPlugin
A minimal plugin that demonstrates:
- Basic plugin structure
- Simple command implementation
- Command-line argument handling
- File I/O operations

**Location**: `examples/HelloWorldPlugin/`

**Commands**:
- `hello` - Simple greeting command with optional parameters

### 2. FileProcessorPlugin
An intermediate plugin that demonstrates:
- Multiple commands in one plugin
- File validation and processing
- Error handling patterns
- Async operations

**Location**: `examples/FileProcessorPlugin/`

**Commands**:
- `hash` - Calculate file hashes
- `copy` - Copy files with validation
- `info` - Display file information

### 3. ServiceIntegrationPlugin
An advanced plugin that demonstrates:
- HTTP client integration
- Authentication patterns
- Configuration management
- Complex error handling

**Location**: `examples/ServiceIntegrationPlugin/`

**Commands**:
- `upload` - Upload files to a service
- `download` - Download files from a service
- `status` - Check service status

## Building Examples

To build all example plugins:

```bash
# From the repository root
dotnet build examples/
```

To build a specific example:

```bash
# From the repository root
dotnet build examples/HelloWorldPlugin/
```

## Running Examples

1. Build the examples
2. Deploy plugins using the enhanced subdirectory architecture:

**Enhanced Subdirectory Deployment (Recommended):**

```bash
# Create plugin subdirectories
mkdir plugins/HelloWorld.Plugin
mkdir plugins/FileProcessor.Plugin
mkdir plugins/ServiceIntegration.Plugin

# Windows - Copy plugins to subdirectories
copy examples\HelloWorldPlugin\bin\Debug\net8.0\*.* plugins\HelloWorld.Plugin\
copy examples\FileProcessorPlugin\bin\Debug\net8.0\*.* plugins\FileProcessor.Plugin\
copy examples\ServiceIntegrationPlugin\bin\Debug\net8.0\*.* plugins\ServiceIntegration.Plugin\

# Linux/macOS - Copy plugins to subdirectories  
cp examples/HelloWorldPlugin/bin/Debug/net8.0/* plugins/HelloWorld.Plugin/
cp examples/FileProcessorPlugin/bin/Debug/net8.0/* plugins/FileProcessor.Plugin/
cp examples/ServiceIntegrationPlugin/bin/Debug/net8.0/* plugins/ServiceIntegration.Plugin/
```

**Legacy Flat Deployment (Backward Compatibility):**

```bash
# Windows - Copy just plugin DLLs
copy examples\HelloWorldPlugin\bin\Debug\net8.0\HelloWorld.Plugin.dll plugins\
copy examples\FileProcessorPlugin\bin\Debug\net8.0\FileProcessor.Plugin.dll plugins\

# Linux/macOS - Copy just plugin DLLs
cp examples/HelloWorldPlugin/bin/Debug/net8.0/HelloWorld.Plugin.dll plugins/
cp examples/FileProcessorPlugin/bin/Debug/net8.0/FileProcessor.Plugin.dll plugins/
```

3. Run CoseSignTool to see the new commands:

```bash
CoseSignTool --help
```

**Benefits of Subdirectory Deployment:**
- Each example plugin is isolated with its own dependencies
- Easy to add/remove individual plugins
- No dependency conflicts between examples

## Learning Path

**Beginner**: Start with HelloWorldPlugin to understand basic concepts

**Intermediate**: Study FileProcessorPlugin for practical file operations

**Advanced**: Examine ServiceIntegrationPlugin for real-world service integration

## Testing

Each example includes unit tests demonstrating:
- Command execution testing
- Error case handling
- Mocking external dependencies
- Async operation testing

Run tests for all examples:

```bash
dotnet test examples/
```

## Best Practices Demonstrated

1. **Proper error handling and return codes**
2. **Input validation and sanitization**
3. **Resource management and disposal**
4. **Cancellation token support**
5. **Configuration pattern usage**
6. **Security considerations**
7. **Performance optimization**

## Contributing Examples

When adding new examples:

1. Follow the established directory structure
2. Include comprehensive documentation
3. Add unit tests for all functionality
4. Demonstrate specific patterns or capabilities
5. Update this README with the new example

For more detailed plugin development information, see:
- [Plugins.md](../Plugins.md) - Complete plugin documentation
- [PluginQuickStart.md](../PluginQuickStart.md) - Quick start guide

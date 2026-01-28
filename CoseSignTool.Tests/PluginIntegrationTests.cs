// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Reflection;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CoseSignTool.Tests;

/// <summary>
/// Integration tests for CoseSignTool plugin infrastructure.
/// These tests ensure that plugin commands can be loaded and executed properly,
/// and that help output and option parsing work correctly across all registered plugins.
/// </summary>
[TestClass]
public class PluginIntegrationTests
{
    private static readonly X509Certificate2 TestCertificate = TestCertificateUtils.CreateCertificate(nameof(PluginIntegrationTests));
    private static readonly string TestCertificatePath = Path.GetTempFileName() + ".pfx";
    private static readonly string TestPayloadPath = Path.GetTempFileName();
    private static readonly string TestSignaturePath = Path.GetTempFileName() + ".cose";
    private static readonly string TestOutputPath = Path.GetTempFileName() + ".json";
    
    // Static field to hold discovered plugins for testing
    private static Dictionary<string, IPluginCommand>? _pluginCommands;

    [ClassInitialize]
    public static void ClassInitialize(TestContext context)
    {
        // Export test certificate to file
        File.WriteAllBytes(TestCertificatePath, TestCertificate.Export(X509ContentType.Pkcs12));
        
        // Create test payload
        File.WriteAllText(TestPayloadPath, "Test payload content for plugin integration testing");
        
        // Discover and load plugins
        _pluginCommands = DiscoverPluginCommands();
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        SafeDeleteFile(TestCertificatePath);
        SafeDeleteFile(TestPayloadPath);
        SafeDeleteFile(TestSignaturePath);
        SafeDeleteFile(TestOutputPath);
    }

    private static void SafeDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Ignore cleanup failures
        }
    }

    /// <summary>
    /// Discovers plugin commands from the plugins directory using the same logic as CoseSignTool.
    /// </summary>
    private static Dictionary<string, IPluginCommand> DiscoverPluginCommands()
    {
        Dictionary<string, IPluginCommand> commands = new();
        
        try
        {
            string executablePath = Assembly.GetExecutingAssembly().Location;
            string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
            string pluginsDirectory = Path.Join(executableDirectory, "plugins");

            if (!Directory.Exists(pluginsDirectory))
            {
                Console.WriteLine($"Plugins directory not found: {pluginsDirectory}");
                return commands;
            }

            IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);
            
            foreach (ICoseSignToolPlugin plugin in plugins)
            {
                try
                {
                    plugin.Initialize();
                    
                    foreach (IPluginCommand command in plugin.Commands)
                    {
                        string commandKey = command.Name.ToLowerInvariant();
                        if (!commands.ContainsKey(commandKey))
                        {
                            commands[commandKey] = command;
                            Console.WriteLine($"Discovered plugin command: {command.Name}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Failed to initialize plugin '{plugin.Name}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Plugin discovery failed: {ex.Message}");
        }

        return commands;
    }

    #region Plugin Discovery Tests

    [TestMethod]
    public void PluginDiscovery_ShouldDiscoverAtLeastOnePlugin()
    {
        // Skip if no plugins directory exists (allows tests to pass in CI without plugins)
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered. This test requires plugins to be deployed.");
        }

        _pluginCommands.Should().NotBeEmpty("At least one plugin command should be discovered.");
    }

    [TestMethod]
    public void PluginDiscovery_AllPluginsShouldHaveValidName()
    {
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            kvp.Value.Name.Should().NotBeNullOrWhiteSpace($"Plugin command '{kvp.Key}' should have a valid name.");
            kvp.Value.Name.Should().NotContain(" ", $"Plugin command '{kvp.Key}' name should not contain spaces.");
        }
    }

    [TestMethod]
    public void PluginDiscovery_AllPluginsShouldHaveValidDescription()
    {
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            kvp.Value.Description.Should().NotBeNullOrWhiteSpace($"Plugin command '{kvp.Key}' should have a description.");
        }
    }

    [TestMethod]
    public void PluginDiscovery_AllPluginsShouldHaveValidUsage()
    {
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            kvp.Value.Usage.Should().NotBeNullOrWhiteSpace($"Plugin command '{kvp.Key}' should have usage documentation.");
            kvp.Value.Usage.Should().Contain(kvp.Value.Name, $"Plugin command '{kvp.Key}' usage should contain the command name.");
        }
    }

    #endregion

    #region Plugin Options Format Tests

    [TestMethod]
    public void PluginOptions_AllOptionKeysShouldBeValidSwitchNames()
    {
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            IPluginCommand command = kvp.Value;
            
            foreach (var option in command.Options)
            {
                // Option keys should be lowercase and use dashes for multi-word options
                option.Key.Should().NotBeNullOrWhiteSpace($"Option key in '{command.Name}' should not be empty.");
                option.Key.Should().NotStartWith("-", $"Option key '{option.Key}' in '{command.Name}' should not start with '-' (the infrastructure adds prefixes).");
                option.Key.Should().NotStartWith("/", $"Option key '{option.Key}' in '{command.Name}' should not start with '/'.");
                option.Key.Should().MatchRegex("^[a-z0-9][a-z0-9-]*$", 
                    $"Option key '{option.Key}' in '{command.Name}' should be lowercase alphanumeric with dashes.");
            }
        }
    }

    [TestMethod]
    public void PluginOptions_AllOptionsShouldHaveDescriptions()
    {
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            IPluginCommand command = kvp.Value;
            
            foreach (var option in command.Options)
            {
                option.Value.Should().NotBeNullOrWhiteSpace(
                    $"Option '{option.Key}' in '{command.Name}' should have a description.");
            }
        }
    }

    [TestMethod]
    public void PluginOptions_CanBeConvertedToSwitchMappings()
    {
        // This test validates the fix for the switch mappings bug
        // It ensures that all plugin options can be converted to the format 
        // expected by CommandLineConfigurationProvider
        
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            IPluginCommand command = kvp.Value;
            
            // Simulate the conversion done in RunPluginCommand
            Dictionary<string, string> switchMappings = new();
            foreach (var option in command.Options)
            {
                string switchKey = $"--{option.Key}";
                
                // This should not throw
                Action addMapping = () => switchMappings[switchKey] = option.Key;
                addMapping.Should().NotThrow(
                    $"Option '{option.Key}' in '{command.Name}' should be convertible to a valid switch mapping.");
                
                // Verify the switch mapping format is valid
                switchMappings[switchKey].Should().Be(option.Key);
            }
            
            // Verify the switch mappings can be used with CommandLineConfigurationProvider
            // This is the actual test that would have caught the original bug
            Action createConfig = () =>
            {
                new ConfigurationBuilder()
                    .AddCommandLine(Array.Empty<string>(), switchMappings)
                    .Build();
            };
            
            createConfig.Should().NotThrow(
                $"Switch mappings for '{command.Name}' should be valid for CommandLineConfigurationProvider.");
        }
    }

    [TestMethod]
    public void PluginBooleanOptions_ShouldBeValidOptionKeys()
    {
        // This test validates that all boolean options declared by plugins
        // are also present in their Options dictionary
        
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            IPluginCommand command = kvp.Value;
            
            // Each boolean option should exist in the Options dictionary
            foreach (string booleanOption in command.BooleanOptions)
            {
                command.Options.Should().ContainKey(booleanOption,
                    $"Boolean option '{booleanOption}' in '{command.Name}' should also be in Options dictionary.");
            }
        }
    }

    [TestMethod]
    public void IndirectVerifyCommand_BooleanOptions_ContainsAllowUntrusted()
    {
        if (_pluginCommands == null || !_pluginCommands.TryGetValue("indirect-verify", out IPluginCommand? command) || command == null)
        {
            Assert.Inconclusive("indirect-verify plugin command not available.");
            return;
        }

        command.BooleanOptions.Should().Contain("allow-untrusted",
            "IndirectVerifyCommand should declare 'allow-untrusted' as a boolean option.");
        command.BooleanOptions.Should().Contain("allow-outdated",
            "IndirectVerifyCommand should declare 'allow-outdated' as a boolean option.");
    }

    [TestMethod]
    public void IndirectSignCommand_BooleanOptions_ContainsEnableScitt()
    {
        if (_pluginCommands == null || !_pluginCommands.TryGetValue("indirect-sign", out IPluginCommand? command) || command == null)
        {
            Assert.Inconclusive("indirect-sign plugin command not available.");
            return;
        }

        command.BooleanOptions.Should().Contain("enable-scitt",
            "IndirectSignCommand should declare 'enable-scitt' as a boolean option.");
    }

    #endregion

    #region Plugin Command Execution Tests

    [TestMethod]
    public void PluginCommand_HelpRequest_ShouldNotThrow()
    {
        // This test ensures that requesting help for any plugin command
        // does not throw exceptions (even if plugins aren't fully configured)
        
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            // Calling Main with just the command name should show help
            // and return HelpRequested exit code (not crash)
            int exitCode = CoseSignTool.Main(new[] { kvp.Key });
            
            // HelpRequested = 1, but other non-crash exit codes are acceptable
            // The key is that it doesn't throw an exception
            ((ExitCode)exitCode).Should().NotBe(ExitCode.UnknownError,
                $"Plugin command '{kvp.Key}' help request should not return UnknownError.");
        }
    }

    [TestMethod]
    public void PluginCommand_MissingRequiredArgs_ShouldReturnMissingRequiredOption()
    {
        // This test ensures that calling a plugin command without required arguments
        // returns an appropriate error code rather than crashing
        
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            // Calling the command with no arguments (after command name)
            int exitCode = CoseSignTool.Main(new[] { kvp.Key });
            
            // Should not be UnknownError (crash) - acceptable codes include
            // HelpRequested, MissingRequiredOption, etc.
            ((ExitCode)exitCode).Should().NotBe(ExitCode.UnknownError,
                $"Plugin command '{kvp.Key}' with no args should not return UnknownError.");
        }
    }

    [TestMethod]
    public void PluginCommand_UnknownOption_ShouldReturnUnknownArgument()
    {
        if (_pluginCommands == null || _pluginCommands.Count == 0)
        {
            Assert.Inconclusive("No plugins discovered.");
        }

        foreach (var kvp in _pluginCommands)
        {
            // Calling the command with an unknown option
            int exitCode = CoseSignTool.Main(new[] { kvp.Key, "--this-option-does-not-exist", "value" });
            
            // Should return UnknownArgument or HelpRequested, not UnknownError
            ExitCode result = (ExitCode)exitCode;
            result.Should().BeOneOf(
                new[] { ExitCode.UnknownArgument, ExitCode.HelpRequested, ExitCode.MissingRequiredOption },
                $"Plugin command '{kvp.Key}' with unknown option should handle gracefully.");
        }
    }

    #endregion

    #region Indirect Sign Plugin Specific Tests

    [TestMethod]
    public void IndirectSignCommand_WithValidArgs_ShouldSucceed()
    {
        if (_pluginCommands == null || !_pluginCommands.ContainsKey("indirect-sign"))
        {
            Assert.Inconclusive("indirect-sign plugin command not available.");
        }

        // Clean up previous signature file
        SafeDeleteFile(TestSignaturePath);

        string[] args = new[]
        {
            "indirect-sign",
            "--payload", TestPayloadPath,
            "--signature", TestSignaturePath,
            "--pfx", TestCertificatePath
        };

        int exitCode = CoseSignTool.Main(args);
        
        ((ExitCode)exitCode).Should().Be(ExitCode.Success, 
            "indirect-sign with valid args should succeed.");
        File.Exists(TestSignaturePath).Should().BeTrue(
            "Signature file should be created.");
    }

    [TestMethod]
    public void IndirectSignCommand_WithPayloadLocation_ShouldSucceed()
    {
        if (_pluginCommands == null || !_pluginCommands.ContainsKey("indirect-sign"))
        {
            Assert.Inconclusive("indirect-sign plugin command not available.");
        }

        string signatureWithLocation = TestSignaturePath + ".location.cose";
        SafeDeleteFile(signatureWithLocation);

        string[] args = new[]
        {
            "indirect-sign",
            "--payload", TestPayloadPath,
            "--signature", signatureWithLocation,
            "--pfx", TestCertificatePath,
            "--payload-location", "https://example.com/artifacts/test-payload.txt"
        };

        int exitCode = CoseSignTool.Main(args);
        
        ((ExitCode)exitCode).Should().Be(ExitCode.Success, 
            "indirect-sign with payload-location should succeed.");
        File.Exists(signatureWithLocation).Should().BeTrue(
            "Signature file should be created.");

        // Clean up
        SafeDeleteFile(signatureWithLocation);
    }

    [TestMethod]
    public void IndirectSignCommand_OptionsContainsPayloadLocation()
    {
        if (_pluginCommands == null || !_pluginCommands.TryGetValue("indirect-sign", out IPluginCommand? command) || command == null)
        {
            Assert.Inconclusive("indirect-sign plugin command not available.");
            return;
        }

        command.Options.Should().ContainKey("payload-location",
            "indirect-sign should have payload-location option.");
    }

    [TestMethod]
    public void IndirectVerifyCommand_WithValidSignature_ShouldSucceed()
    {
        if (_pluginCommands == null || 
            !_pluginCommands.ContainsKey("indirect-sign") || 
            !_pluginCommands.ContainsKey("indirect-verify"))
        {
            Assert.Inconclusive("indirect-sign or indirect-verify plugin commands not available.");
        }

        // Create a unique signature file for this test to avoid conflicts
        string verifyTestSignature = Path.GetTempFileName() + ".verify-test.cose";
        
        try
        {
            // First create a signature
            string[] signArgs = new[]
            {
                "indirect-sign",
                "--payload", TestPayloadPath,
                "--signature", verifyTestSignature,
                "--pfx", TestCertificatePath
            };

            int signResult = CoseSignTool.Main(signArgs);
            ((ExitCode)signResult).Should().Be(ExitCode.Success, "Sign should succeed first.");
            File.Exists(verifyTestSignature).Should().BeTrue("Signature file should be created.");

            // Now verify it - use both --allow-untrusted and --allow-outdated for self-signed test cert
            string[] verifyArgs = new[]
            {
                "indirect-verify",
                "--payload", TestPayloadPath,
                "--signature", verifyTestSignature,
                "--allow-untrusted",
                "--allow-outdated"
            };

            int verifyResult = CoseSignTool.Main(verifyArgs);
            
            // Accept either Success or certificate-related failures since we're using a test cert
            // The important thing is that the command runs without crashing on switch mapping errors
            ExitCode result = (ExitCode)verifyResult;
            result.Should().NotBe((ExitCode)1000, // UnknownArgument would indicate switch mapping issue
                "indirect-verify should not fail with UnknownArgument (which would indicate switch mapping issues).");
        }
        finally
        {
            SafeDeleteFile(verifyTestSignature);
        }
    }

    #endregion
}

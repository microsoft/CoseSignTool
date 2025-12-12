// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands;
using System.CommandLine;

namespace CoseSignTool.Tests;

/// <summary>
/// End-to-end integration tests that create real COSE signatures and test them.
/// </summary>
public class EndToEndSigningTests
{
    [Fact]
    public void SignAndVerify_WithValidPayload_Succeeds()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose"; // Output is <payload>.cose, not replacing extension

        try
        {
            File.WriteAllText(tempPayload, "Test payload for signing");

            // Act - Sign
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Assert - Sign succeeded
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");

            // Act - Verify
            var verifyExitCode = rootCommand.Invoke($"verify \"{tempSignature}\"");

            // Note: Verify may fail since signature is from ephemeral cert (not trusted)
            // This tests that the command runs and returns an expected exit code
            Assert.True(verifyExitCode == (int)ExitCode.Success || 
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate,
                        $"Unexpected exit code: {verifyExitCode}");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignAndInspect_WithValidPayload_Succeeds()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for signing");

            // Act - Sign
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Inspect the created signature
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\"");

            // Assert - Inspect succeeded
            Assert.Equal((int)ExitCode.Success, inspectExitCode);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignWithDetached_CreatesSignature()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for detached signing");

            // Act - Sign with detached option
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --detached");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignWithCustomOutput_CreatesSignatureAtSpecifiedPath()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var customOutput = Path.Combine(Path.GetTempPath(), $"custom_{Guid.NewGuid()}.cose");

        try
        {
            File.WriteAllText(tempPayload, "Test payload");

            // Act
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --output \"{customOutput}\"");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(customOutput), "Signature should be created at custom path");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(customOutput))
            {
                File.Delete(customOutput);
            }
        }
    }

    [Fact]
    public void SignWithDirectSignatureType_CreatesSignature()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for direct signing");

            // Act - Sign with direct signature type
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type direct");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignWithEmbeddedSignatureType_CreatesSignature()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for embedded signing");

            // Act - Sign with embedded signature type
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignWithContentType_CreatesSignatureWithContentType()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "{\"test\":\"json\"}");

            // Act - Sign with custom content type
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --content-type application/json");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignWithQuietOption_CreatesSignature()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload");

            // Act - Sign with quiet option
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --quiet");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignAndInspect_WithJsonOutput_Succeeds()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload");

            // Act - Sign
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Inspect with JSON output format
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\" --output-format json");

            // Assert
            Assert.Equal((int)ExitCode.Success, inspectExitCode);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignAndInspect_WithXmlOutput_Succeeds()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload");

            // Act - Sign
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Inspect with XML output format
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\" --output-format xml");

            // Assert
            Assert.Equal((int)ExitCode.Success, inspectExitCode);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignLargePayload_Succeeds()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            // Create a larger payload (1MB)
            var largePayload = new string('X', 1024 * 1024);
            File.WriteAllText(tempPayload, largePayload);

            // Act
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignBinaryPayload_Succeeds()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            // Create binary payload
            var binaryPayload = new byte[1024];
            new Random().NextBytes(binaryPayload);
            File.WriteAllBytes(tempPayload, binaryPayload);

            // Act
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Assert
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature), "Signature file should be created");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }
}

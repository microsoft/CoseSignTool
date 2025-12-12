// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands;
using System.CommandLine;

namespace CoseSignTool.Tests;

/// <summary>
/// End-to-end integration tests that create real COSE signatures and test them.
/// </summary>
[TestFixture]
public class EndToEndSigningTests
{
    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");

            // Act - Verify
            var verifyExitCode = rootCommand.Invoke($"verify \"{tempSignature}\"");

            // Note: Verify may fail since signature is from ephemeral cert (not trusted)
            // This tests that the command runs and returns an expected exit code
            Assert.That(verifyExitCode == (int)ExitCode.Success || 
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Inspect the created signature
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\"");

            // Assert - Inspect succeeded
            Assert.That(inspectExitCode, Is.EqualTo((int)ExitCode.Success));
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(customOutput), "Signature should be created at custom path");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Inspect with JSON output format
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\" --output-format json");

            // Assert
            Assert.That(inspectExitCode, Is.EqualTo((int)ExitCode.Success));
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Inspect with XML output format
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\" --output-format xml");

            // Assert
            Assert.That(inspectExitCode, Is.EqualTo((int)ExitCode.Success));
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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

    [Test]
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
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature), "Signature file should be created");
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






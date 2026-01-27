// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

using System.CommandLine;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers.Extensions;

/// <summary>
/// Regression tests for CWT claims (SCITT compliance) to ensure the feature doesn't break.
/// These tests verify that:
/// 1. CWT claims are added by default when signing
/// 2. The --issuer option correctly overrides the default issuer
/// 3. The --cwt-subject option correctly overrides the default subject
/// 4. The --no-scitt option disables automatic CWT claims
/// 5. Combinations of options work correctly
/// </summary>
[TestFixture]
public class CwtClaimsRegressionTests
{
    /// <summary>
    /// CRITICAL: Verifies that CWT claims are added by default when signing.
    /// This is the core SCITT compliance requirement - signatures must have CWT claims by default.
    /// </summary>
    [Test]
    public void Sign_WithDefaultOptions_HasCwtClaimsWithDidX509Issuer()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for CWT claims verification");

            // Act - Sign with default options (no --issuer, --cwt-subject, or --no-scitt)
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");

            // Assert - Signing succeeded
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success), "Signing should succeed");
            Assert.That(File.Exists(tempSignature), "Signature file should be created");

            // Read and verify CWT claims
            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            // Verify CWT claims are present
            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, "CRITICAL: CWT claims MUST be present by default for SCITT compliance");
            Assert.That(claims, Is.Not.Null, "CWT claims object should not be null");

            // Verify issuer is a DID:x509 (auto-generated from certificate)
            Assert.That(claims!.Issuer, Is.Not.Null.And.Not.Empty, "Issuer must be present");
            Assert.That(claims.Issuer, Does.StartWith("did:x509:"), 
                "Default issuer should be a DID:x509 identifier derived from the certificate chain");

            // Verify subject has default value
            Assert.That(claims.Subject, Is.Not.Null.And.Not.Empty, "Subject must be present");
            Assert.That(claims.Subject, Is.EqualTo("unknown.intent"), 
                "Default subject should be 'unknown.intent'");

            // Verify timestamps are present
            Assert.That(claims.IssuedAt, Is.Not.Null, "IssuedAt (iat) must be present");
            Assert.That(claims.NotBefore, Is.Not.Null, "NotBefore (nbf) must be present");
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

    /// <summary>
    /// Verifies that the --cwt-subject option correctly overrides the default subject
    /// while keeping the auto-generated DID:x509 issuer.
    /// </summary>
    [Test]
    public void Sign_WithCustomSubject_HasCustomSubjectAndDidX509Issuer()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        const string customSubject = "pkg:npm/my-package@1.0.0";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for custom subject");

            // Act - Sign with custom subject only
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --cwt-subject \"{customSubject}\"");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, "CWT claims must be present");
            Assert.That(claims, Is.Not.Null);

            // Verify custom subject is used
            Assert.That(claims!.Subject, Is.EqualTo(customSubject), 
                "Custom subject should override the default");

            // Verify issuer is still auto-generated DID:x509
            Assert.That(claims.Issuer, Does.StartWith("did:x509:"), 
                "Issuer should still be auto-generated DID:x509 when only subject is customized");
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

    /// <summary>
    /// Verifies that the --issuer option correctly overrides the default DID:x509 issuer
    /// while using the default subject.
    /// </summary>
    [Test]
    public void Sign_WithCustomIssuer_HasCustomIssuerAndDefaultSubject()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        const string customIssuer = "https://build.example.com/pipeline";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for custom issuer");

            // Act - Sign with custom issuer only
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --issuer \"{customIssuer}\"");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, "CWT claims must be present");
            Assert.That(claims, Is.Not.Null);

            // Verify custom issuer is used
            Assert.That(claims!.Issuer, Is.EqualTo(customIssuer), 
                "Custom issuer should override the default DID:x509");

            // Note: When --issuer is specified without --cwt-subject, the contributor
            // creates claims with only the specified values + timestamps
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

    /// <summary>
    /// Verifies that both --issuer and --cwt-subject can be used together.
    /// </summary>
    [Test]
    public void Sign_WithCustomIssuerAndSubject_HasBothCustomValues()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        const string customIssuer = "https://build.contoso.com/release-pipeline";
        const string customSubject = "pkg:spdx/my-sbom@2.0.0";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for both custom values");

            // Act - Sign with both custom issuer and subject
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --issuer \"{customIssuer}\" --cwt-subject \"{customSubject}\"");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, "CWT claims must be present");
            Assert.That(claims, Is.Not.Null);

            // Verify both custom values
            Assert.That(claims!.Issuer, Is.EqualTo(customIssuer), "Custom issuer should be used");
            Assert.That(claims.Subject, Is.EqualTo(customSubject), "Custom subject should be used");

            // Verify timestamps are still present
            Assert.That(claims.IssuedAt, Is.Not.Null, "IssuedAt should still be present");
            Assert.That(claims.NotBefore, Is.Not.Null, "NotBefore should still be present");
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

    /// <summary>
    /// Verifies that --no-scitt disables automatic CWT claims generation.
    /// </summary>
    [Test]
    public void Sign_WithNoScitt_HasNoCwtClaims()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for --no-scitt");

            // Act - Sign with --no-scitt to disable CWT claims
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --no-scitt");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            // Verify NO CWT claims are present
            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.False, 
                "--no-scitt should prevent automatic CWT claims generation");
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

    /// <summary>
    /// Verifies that --no-scitt combined with --issuer adds only the custom issuer claim.
    /// </summary>
    [Test]
    public void Sign_WithNoScittAndCustomIssuer_HasOnlyCustomIssuer()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        const string customIssuer = "https://manual.issuer.example.com";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for --no-scitt with custom issuer");

            // Act - Sign with --no-scitt but provide custom issuer
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --no-scitt --issuer \"{customIssuer}\"");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            // CWT claims should be present because we explicitly specified --issuer
            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, 
                "CWT claims should be present when --issuer is specified, even with --no-scitt");
            Assert.That(claims, Is.Not.Null);

            // Verify only the custom issuer is used (no auto-generated DID:x509)
            Assert.That(claims!.Issuer, Is.EqualTo(customIssuer), 
                "Custom issuer should be used");
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

    /// <summary>
    /// Verifies CWT claims work correctly with indirect (default) signature type.
    /// </summary>
    [Test]
    public void Sign_IndirectSignature_HasCwtClaims()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for indirect signature");

            // Act - Sign with explicit indirect signature type
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --signature-type indirect");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, 
                "CWT claims must be present for indirect signatures (SCITT compliance)");
            Assert.That(claims!.Issuer, Does.StartWith("did:x509:"), 
                "Indirect signatures should have DID:x509 issuer by default");
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

    /// <summary>
    /// Verifies CWT claims work correctly with embedded signature type.
    /// </summary>
    [Test]
    public void Sign_EmbeddedSignature_HasCwtClaims()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for embedded signature");

            // Act - Sign with embedded signature type
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --signature-type embedded");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, 
                "CWT claims must be present for embedded signatures");
            Assert.That(claims!.Issuer, Does.StartWith("did:x509:"), 
                "Embedded signatures should have DID:x509 issuer by default");
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

    /// <summary>
    /// Verifies CWT claims work correctly with detached signature type.
    /// </summary>
    [Test]
    public void Sign_DetachedSignature_HasCwtClaims()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for detached signature");

            // Act - Sign with detached signature type
            var signExitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" --signature-type detached");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True, 
                "CWT claims must be present for detached signatures");
            Assert.That(claims!.Issuer, Does.StartWith("did:x509:"), 
                "Detached signatures should have DID:x509 issuer by default");
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

    /// <summary>
    /// Verifies that the DID:x509 issuer contains proper certificate information.
    /// </summary>
    [Test]
    public void Sign_DidX509Issuer_ContainsSubjectInformation()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for DID:x509 validation");

            // Act
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True);

            // DID:x509 format should be: did:x509:0:sha256:<hash>::subject:<subject-parts>
            var issuer = claims!.Issuer!;
            Assert.That(issuer, Does.StartWith("did:x509:0:sha256:"), 
                "DID:x509 should use sha256 hash algorithm");
            Assert.That(issuer, Does.Contain("::subject:"), 
                "DID:x509 should contain subject policy");
            
            // The ephemeral cert has CN=CoseSignTool Test Signer, O=Test Organization
            // URL-encoded in the DID would be something like CN:CoseSignTool%20Test%20Signer
            Assert.That(issuer, Does.Contain("CN:"), 
                "DID:x509 subject should contain CN (Common Name)");
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

    /// <summary>
    /// Verifies that CWT timestamps are reasonable (not in the past or far future).
    /// </summary>
    [Test]
    public void Sign_CwtTimestamps_AreReasonable()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var beforeSigning = DateTimeOffset.UtcNow.AddSeconds(-5); // Allow 5 second tolerance

        try
        {
            File.WriteAllText(tempPayload, "Test payload for timestamp validation");

            // Act
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            var afterSigning = DateTimeOffset.UtcNow.AddSeconds(5); // Allow 5 second tolerance

            // Assert
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            var signatureBytes = File.ReadAllBytes(tempSignature);
            var message = CoseSign1Message.DecodeSign1(signatureBytes);

            var hasCwtClaims = message.ProtectedHeaders.TryGetCwtClaims(out var claims);
            Assert.That(hasCwtClaims, Is.True);

            // IssuedAt should be close to now
            Assert.That(claims!.IssuedAt, Is.Not.Null);
            Assert.That(claims.IssuedAt!.Value, Is.GreaterThanOrEqualTo(beforeSigning), 
                "IssuedAt should not be before signing started");
            Assert.That(claims.IssuedAt.Value, Is.LessThanOrEqualTo(afterSigning), 
                "IssuedAt should not be after signing finished");

            // NotBefore should be close to now (typically equal to IssuedAt)
            Assert.That(claims.NotBefore, Is.Not.Null);
            Assert.That(claims.NotBefore!.Value, Is.GreaterThanOrEqualTo(beforeSigning), 
                "NotBefore should not be before signing started");
            Assert.That(claims.NotBefore.Value, Is.LessThanOrEqualTo(afterSigning), 
                "NotBefore should not be after signing finished");
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

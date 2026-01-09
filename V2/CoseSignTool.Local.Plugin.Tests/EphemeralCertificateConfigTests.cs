// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin.Tests;

using System.Text.Json;

/// <summary>
/// Tests for EphemeralCertificateConfig.
/// </summary>
[TestFixture]
public class EphemeralCertificateConfigTests
{
    /// <summary>
    /// Creates a temporary file with the given content and returns a disposable wrapper that cleans up the file.
    /// </summary>
    private static TempFileContext CreateTempFile(string content)
    {
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, content);
        return new TempFileContext(tempFile);
    }

    /// <summary>
    /// Disposable wrapper for temporary files that ensures cleanup.
    /// </summary>
    private sealed class TempFileContext : IDisposable
    {
        public string FilePath { get; }

        public TempFileContext(string filePath) => FilePath = filePath;

        public void Dispose()
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
    }

    #region Default Values Tests

    [Test]
    public void DefaultConstructor_SetsDefaultValues()
    {
        // Arrange & Act
        var config = new EphemeralCertificateConfig();

        // Assert
        Assert.That(config.Subject, Is.EqualTo("CN=CoseSignTool Test Signer, O=Test Organization"));
        Assert.That(config.Algorithm, Is.EqualTo("RSA"));
        Assert.That(config.KeySize, Is.Null);
        Assert.That(config.ValidityDays, Is.EqualTo(365));
        Assert.That(config.GenerateChain, Is.True);
        Assert.That(config.HashAlgorithm, Is.EqualTo("SHA256"));
    }

    [Test]
    public void EffectiveKeySize_ForRSA_Returns4096()
    {
        // Arrange
        var config = new EphemeralCertificateConfig { Algorithm = "RSA" };

        // Act & Assert
        Assert.That(config.EffectiveKeySize, Is.EqualTo(4096));
    }

    [Test]
    public void EffectiveKeySize_ForECDSA_Returns384()
    {
        // Arrange
        var config = new EphemeralCertificateConfig { Algorithm = "ECDSA" };

        // Act & Assert
        Assert.That(config.EffectiveKeySize, Is.EqualTo(384));
    }

    [Test]
    public void EffectiveKeySize_ForMLDSA_Returns65()
    {
        // Arrange
        var config = new EphemeralCertificateConfig { Algorithm = "MLDSA" };

        // Act & Assert
        Assert.That(config.EffectiveKeySize, Is.EqualTo(65));
    }

    [Test]
    public void EffectiveKeySize_WithCustomKeySize_ReturnsCustomValue()
    {
        // Arrange
        var config = new EphemeralCertificateConfig
        {
            Algorithm = "RSA",
            KeySize = 3072
        };

        // Act & Assert
        Assert.That(config.EffectiveKeySize, Is.EqualTo(3072));
    }

    [Test]
    public void EffectiveEnhancedKeyUsages_WhenEmpty_ReturnsCodeSigning()
    {
        // Arrange
        var config = new EphemeralCertificateConfig();

        // Act
        var ekus = config.EffectiveEnhancedKeyUsages;

        // Assert
        Assert.That(ekus, Has.Count.EqualTo(1));
        Assert.That(ekus[0], Is.EqualTo("CodeSigning"));
    }

    [Test]
    public void EffectiveEnhancedKeyUsages_WhenSet_ReturnsCustomValues()
    {
        // Arrange
        var config = new EphemeralCertificateConfig
        {
            EnhancedKeyUsages = new List<string> { "ServerAuth", "ClientAuth" }
        };

        // Act
        var ekus = config.EffectiveEnhancedKeyUsages;

        // Assert
        Assert.That(ekus, Has.Count.EqualTo(2));
        Assert.That(ekus, Does.Contain("ServerAuth"));
        Assert.That(ekus, Does.Contain("ClientAuth"));
    }

    [Test]
    public void EffectiveChainConfig_WhenNull_ReturnsDefaults()
    {
        // Arrange
        var config = new EphemeralCertificateConfig { Chain = null };

        // Act
        var chainConfig = config.EffectiveChainConfig;

        // Assert
        Assert.That(chainConfig, Is.Not.Null);
        Assert.That(chainConfig.RootSubject, Is.EqualTo("CN=CoseSignTool Test Root CA, O=Test Organization"));
        Assert.That(chainConfig.IntermediateSubject, Is.EqualTo("CN=CoseSignTool Test Intermediate CA, O=Test Organization"));
        Assert.That(chainConfig.RootValidityDays, Is.EqualTo(3650));
        Assert.That(chainConfig.IntermediateValidityDays, Is.EqualTo(1825));
    }

    [Test]
    public void EffectiveChainConfig_WhenSet_ReturnsCustomValues()
    {
        // Arrange
        var config = new EphemeralCertificateConfig
        {
            Chain = new ChainConfig
            {
                RootSubject = "CN=Custom Root",
                IntermediateSubject = "CN=Custom Intermediate",
                RootValidityDays = 7300,
                IntermediateValidityDays = 3650
            }
        };

        // Act
        var chainConfig = config.EffectiveChainConfig;

        // Assert
        Assert.That(chainConfig.RootSubject, Is.EqualTo("CN=Custom Root"));
        Assert.That(chainConfig.IntermediateSubject, Is.EqualTo("CN=Custom Intermediate"));
        Assert.That(chainConfig.RootValidityDays, Is.EqualTo(7300));
        Assert.That(chainConfig.IntermediateValidityDays, Is.EqualTo(3650));
    }

    #endregion

    #region Factory Method Tests

    [Test]
    public void CreateDefault_ReturnsConfigWithDefaults()
    {
        // Act
        var config = EphemeralCertificateConfig.CreateDefault();

        // Assert
        Assert.That(config.Algorithm, Is.EqualTo("RSA"));
        Assert.That(config.EffectiveKeySize, Is.EqualTo(4096));
        Assert.That(config.ValidityDays, Is.EqualTo(365));
        Assert.That(config.GenerateChain, Is.True);
    }

    [Test]
    public void CreateMinimal_ReturnsMinimalConfig()
    {
        // Act
        var config = EphemeralCertificateConfig.CreateMinimal();

        // Assert - Minimal doesn't override subject, so it uses default
        Assert.That(config.Subject, Is.EqualTo("CN=CoseSignTool Test Signer, O=Test Organization"));
        Assert.That(config.Algorithm, Is.EqualTo("RSA"));
        Assert.That(config.EffectiveKeySize, Is.EqualTo(2048));
        Assert.That(config.ValidityDays, Is.EqualTo(1));
        Assert.That(config.GenerateChain, Is.False);
    }

    [Test]
    public void CreatePostQuantum_ReturnsMlDsaConfig()
    {
        // Act
        var config = EphemeralCertificateConfig.CreatePostQuantum();

        // Assert
        Assert.That(config.Algorithm, Is.EqualTo("MLDSA"));
        Assert.That(config.EffectiveKeySize, Is.EqualTo(65));
        Assert.That(config.GenerateChain, Is.True);
    }

    #endregion

    #region JSON Serialization Tests

    [Test]
    public void LoadFromJson_WithValidJson_ReturnsConfig()
    {
        // Arrange
        var json = """
        {
            "Subject": "CN=Custom Subject",
            "Algorithm": "ECDSA",
            "KeySize": 521,
            "ValidityDays": 90,
            "GenerateChain": false
        }
        """;

        // Act
        var config = EphemeralCertificateConfig.LoadFromJson(json);

        // Assert
        Assert.That(config.Subject, Is.EqualTo("CN=Custom Subject"));
        Assert.That(config.Algorithm, Is.EqualTo("ECDSA"));
        Assert.That(config.KeySize, Is.EqualTo(521));
        Assert.That(config.ValidityDays, Is.EqualTo(90));
        Assert.That(config.GenerateChain, Is.False);
    }

    [Test]
    public void LoadFromJson_WithPartialJson_UsesDefaults()
    {
        // Arrange
        var json = """
        {
            "Subject": "CN=Custom Subject"
        }
        """;

        // Act
        var config = EphemeralCertificateConfig.LoadFromJson(json);

        // Assert
        Assert.That(config.Subject, Is.EqualTo("CN=Custom Subject"));
        Assert.That(config.Algorithm, Is.EqualTo("RSA")); // Default
        Assert.That(config.ValidityDays, Is.EqualTo(365)); // Default
        Assert.That(config.GenerateChain, Is.True); // Default
    }

    [Test]
    public void LoadFromJson_WithChainConfig_ParsesChain()
    {
        // Arrange
        var json = """
        {
            "Subject": "CN=Leaf",
            "GenerateChain": true,
            "Chain": {
                "RootSubject": "CN=Custom Root CA",
                "IntermediateSubject": "CN=Custom Intermediate CA",
                "RootValidityDays": 7300,
                "IntermediateValidityDays": 3650
            }
        }
        """;

        // Act
        var config = EphemeralCertificateConfig.LoadFromJson(json);

        // Assert
        Assert.That(config.Chain, Is.Not.Null);
        Assert.That(config.Chain!.RootSubject, Is.EqualTo("CN=Custom Root CA"));
        Assert.That(config.Chain.IntermediateSubject, Is.EqualTo("CN=Custom Intermediate CA"));
        Assert.That(config.Chain.RootValidityDays, Is.EqualTo(7300));
        Assert.That(config.Chain.IntermediateValidityDays, Is.EqualTo(3650));
    }

    [Test]
    public void LoadFromJson_WithEnhancedKeyUsages_ParsesEkus()
    {
        // Arrange
        var json = """
        {
            "EnhancedKeyUsages": ["CodeSigning", "LifetimeSigning", "1.3.6.1.5.5.7.3.1"]
        }
        """;

        // Act
        var config = EphemeralCertificateConfig.LoadFromJson(json);

        // Assert
        Assert.That(config.EnhancedKeyUsages, Has.Count.EqualTo(3));
        Assert.That(config.EnhancedKeyUsages, Does.Contain("CodeSigning"));
        Assert.That(config.EnhancedKeyUsages, Does.Contain("LifetimeSigning"));
        Assert.That(config.EnhancedKeyUsages, Does.Contain("1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void LoadFromJson_CaseInsensitivePropertyNames()
    {
        // Arrange
        var json = """
        {
            "subject": "CN=Lower Case",
            "algorithm": "ecdsa",
            "generateChain": false
        }
        """;

        // Act
        var config = EphemeralCertificateConfig.LoadFromJson(json);

        // Assert
        Assert.That(config.Subject, Is.EqualTo("CN=Lower Case"));
        Assert.That(config.Algorithm, Is.EqualTo("ecdsa"));
        Assert.That(config.GenerateChain, Is.False);
    }

    [Test]
    public void LoadFromJson_WithInvalidJson_ThrowsException()
    {
        // Arrange
        var json = "{ invalid json }";

        // Act & Assert
        Assert.Throws<JsonException>(() => EphemeralCertificateConfig.LoadFromJson(json));
    }

    [Test]
    public void LoadFromFile_WithValidFile_ReturnsConfig()
    {
        // Arrange
        var json = """
        {
            "Subject": "CN=File Test Subject",
            "Algorithm": "RSA",
            "KeySize": 3072
        }
        """;

        using var tempFile = CreateTempFile(json);

        // Act
        var config = EphemeralCertificateConfig.LoadFromFile(tempFile.FilePath);

        // Assert
        Assert.That(config.Subject, Is.EqualTo("CN=File Test Subject"));
        Assert.That(config.Algorithm, Is.EqualTo("RSA"));
        Assert.That(config.KeySize, Is.EqualTo(3072));
    }

    [Test]
    public void LoadFromFile_WithNonExistentFile_ThrowsException()
    {
        // Arrange
        var nonExistentPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() => EphemeralCertificateConfig.LoadFromFile(nonExistentPath));
    }

    #endregion

    #region ChainConfig Tests

    [Test]
    public void ChainConfig_DefaultConstructor_SetsDefaults()
    {
        // Arrange & Act
        var chainConfig = new ChainConfig();

        // Assert
        Assert.That(chainConfig.RootSubject, Is.EqualTo("CN=CoseSignTool Test Root CA, O=Test Organization"));
        Assert.That(chainConfig.IntermediateSubject, Is.EqualTo("CN=CoseSignTool Test Intermediate CA, O=Test Organization"));
        Assert.That(chainConfig.RootValidityDays, Is.EqualTo(3650));
        Assert.That(chainConfig.IntermediateValidityDays, Is.EqualTo(1825));
    }

    #endregion

    #region Roundtrip Tests

    [Test]
    public void JsonRoundtrip_PreservesAllProperties()
    {
        // Arrange
        var original = new EphemeralCertificateConfig
        {
            Subject = "CN=Roundtrip Test",
            Algorithm = "ECDSA",
            KeySize = 384,
            ValidityDays = 180,
            GenerateChain = true,
            HashAlgorithm = "SHA512",
            EnhancedKeyUsages = new List<string> { "CodeSigning", "TimeStamping" },
            Chain = new ChainConfig
            {
                RootSubject = "CN=Roundtrip Root",
                IntermediateSubject = "CN=Roundtrip Intermediate",
                RootValidityDays = 5000,
                IntermediateValidityDays = 2500
            }
        };

        // Act
        var json = JsonSerializer.Serialize(original, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        var restored = EphemeralCertificateConfig.LoadFromJson(json);

        // Assert
        Assert.That(restored.Subject, Is.EqualTo(original.Subject));
        Assert.That(restored.Algorithm, Is.EqualTo(original.Algorithm));
        Assert.That(restored.KeySize, Is.EqualTo(original.KeySize));
        Assert.That(restored.ValidityDays, Is.EqualTo(original.ValidityDays));
        Assert.That(restored.GenerateChain, Is.EqualTo(original.GenerateChain));
        Assert.That(restored.HashAlgorithm, Is.EqualTo(original.HashAlgorithm));
        Assert.That(restored.EnhancedKeyUsages, Is.EqualTo(original.EnhancedKeyUsages));
        Assert.That(restored.Chain!.RootSubject, Is.EqualTo(original.Chain.RootSubject));
        Assert.That(restored.Chain.IntermediateSubject, Is.EqualTo(original.Chain.IntermediateSubject));
        Assert.That(restored.Chain.RootValidityDays, Is.EqualTo(original.Chain.RootValidityDays));
        Assert.That(restored.Chain.IntermediateValidityDays, Is.EqualTo(original.Chain.IntermediateValidityDays));
    }

    #endregion
}
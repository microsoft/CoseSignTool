// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security;
using CoseSignTool.Abstractions.Security;

namespace CoseSignTool.Abstractions.Tests.Security;

/// <summary>
/// Tests for SecurePasswordProvider.
/// </summary>
[TestFixture]
public class SecurePasswordProviderTests
{
    private string? TempPasswordFile;

    [TearDown]
    public void TearDown()
    {
        if (TempPasswordFile != null && File.Exists(TempPasswordFile))
        {
            File.Delete(TempPasswordFile);
            TempPasswordFile = null;
        }

        // Clean up any test environment variables
        Environment.SetEnvironmentVariable("TEST_PFX_PASSWORD", null);
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, null);
    }

    [Test]
    public void DefaultPfxPasswordEnvVar_HasExpectedValue()
    {
        Assert.That(SecurePasswordProvider.DefaultPfxPasswordEnvVar, Is.EqualTo("COSESIGNTOOL_PFX_PASSWORD"));
    }

    [Test]
    public void ConvertToSecureString_WithNullString_ReturnsEmptySecureString()
    {
        // Act
        var result = SecurePasswordProvider.ConvertToSecureString(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(0));
        Assert.That(result.IsReadOnly(), Is.True);
    }

    [Test]
    public void ConvertToSecureString_WithEmptyString_ReturnsEmptySecureString()
    {
        // Act
        var result = SecurePasswordProvider.ConvertToSecureString(string.Empty);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(0));
        Assert.That(result.IsReadOnly(), Is.True);
    }

    [Test]
    public void ConvertToSecureString_WithPassword_ReturnsSecureStringWithCorrectLength()
    {
        // Arrange
        var password = "testpassword123";

        // Act
        var result = SecurePasswordProvider.ConvertToSecureString(password);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(password.Length));
        Assert.That(result.IsReadOnly(), Is.True);
    }

    [Test]
    public void ConvertToPlainString_WithNullSecureString_ReturnsNull()
    {
        // Act
        var result = SecurePasswordProvider.ConvertToPlainString(null);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void ConvertToPlainString_WithEmptySecureString_ReturnsNull()
    {
        // Arrange
        var secure = new SecureString();
        secure.MakeReadOnly();

        // Act
        var result = SecurePasswordProvider.ConvertToPlainString(secure);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void ConvertToPlainString_RoundTrips_Successfully()
    {
        // Arrange
        var original = "MySecretPassword!@#123";

        // Act
        var secure = SecurePasswordProvider.ConvertToSecureString(original);
        var result = SecurePasswordProvider.ConvertToPlainString(secure);

        // Assert
        Assert.That(result, Is.EqualTo(original));
    }

    [Test]
    public void Copy_WithNullSecureString_ReturnsEmptySecureString()
    {
        // Act
        var result = SecurePasswordProvider.Copy(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(0));
        Assert.That(result.IsReadOnly(), Is.True);
    }

    [Test]
    public void Copy_WithSecureString_ReturnsCopyWithSameValue()
    {
        // Arrange
        var original = SecurePasswordProvider.ConvertToSecureString("TestPassword");

        // Act
        var copy = SecurePasswordProvider.Copy(original);

        // Assert
        Assert.That(copy, Is.Not.SameAs(original));
        Assert.That(copy.Length, Is.EqualTo(original.Length));

        var originalPlain = SecurePasswordProvider.ConvertToPlainString(original);
        var copyPlain = SecurePasswordProvider.ConvertToPlainString(copy);
        Assert.That(copyPlain, Is.EqualTo(originalPlain));
    }

    [Test]
    public void GetPasswordFromEnvironment_WithUnsetVariable_ReturnsNull()
    {
        // Act
        var result = SecurePasswordProvider.GetPasswordFromEnvironment("NONEXISTENT_PASSWORD_VAR");

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void GetPasswordFromEnvironment_WithEmptyVariable_ReturnsNull()
    {
        // Arrange
        Environment.SetEnvironmentVariable("TEST_PFX_PASSWORD", "");

        // Act
        var result = SecurePasswordProvider.GetPasswordFromEnvironment("TEST_PFX_PASSWORD");

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void GetPasswordFromEnvironment_WithSetVariable_ReturnsSecureString()
    {
        // Arrange
        var password = "EnvTestPassword123";
        Environment.SetEnvironmentVariable("TEST_PFX_PASSWORD", password);

        // Act
        var result = SecurePasswordProvider.GetPasswordFromEnvironment("TEST_PFX_PASSWORD");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Length, Is.EqualTo(password.Length));

        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(password));
    }

    [Test]
    public void GetPasswordFromEnvironment_UsesDefaultEnvVarName()
    {
        // Arrange
        var password = "DefaultEnvVarTest";
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, password);

        // Act
        var result = SecurePasswordProvider.GetPasswordFromEnvironment();

        // Assert
        Assert.That(result, Is.Not.Null);
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(password));
    }

    [Test]
    public void ReadPasswordFromFile_WithNonExistentFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var filePath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.txt");

        // Act & Assert
        Assert.Throws<FileNotFoundException>(
            () => SecurePasswordProvider.ReadPasswordFromFile(filePath));
    }

    [Test]
    public void ReadPasswordFromFile_WithExistingFile_ReturnsPassword()
    {
        // Arrange
        var password = "FilePassword123!";
        TempPasswordFile = Path.Combine(Path.GetTempPath(), $"password_{Guid.NewGuid()}.txt");
        File.WriteAllText(TempPasswordFile, password);

        // Act
        var result = SecurePasswordProvider.ReadPasswordFromFile(TempPasswordFile);

        // Assert
        Assert.That(result, Is.Not.Null);
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(password));
    }

    [Test]
    public void ReadPasswordFromFile_TrimsTrailingNewlines()
    {
        // Arrange
        var password = "FilePassword";
        TempPasswordFile = Path.Combine(Path.GetTempPath(), $"password_{Guid.NewGuid()}.txt");
        File.WriteAllText(TempPasswordFile, password + "\r\n");

        // Act
        var result = SecurePasswordProvider.ReadPasswordFromFile(TempPasswordFile);

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(password));
    }

    [Test]
    public void IsInteractiveInputAvailable_ReturnsBoolean()
    {
        // Act - Just verify it doesn't throw
        var result = SecurePasswordProvider.IsInteractiveInputAvailable();

        // Assert
        Assert.That(result, Is.TypeOf<bool>());
    }

    [Test]
    public void GetPassword_WithEnvironmentVariable_ReturnsEnvPassword()
    {
        // Arrange
        var password = "GetPasswordEnvTest";
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, password);

        // Act
        var result = SecurePasswordProvider.GetPassword();

        // Assert
        Assert.That(result, Is.Not.Null);
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(password));
    }

    [Test]
    public void GetPassword_WithPasswordFile_ReturnsFilePassword()
    {
        // Arrange - Make sure env var is not set
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, null);

        var password = "GetPasswordFileTest";
        TempPasswordFile = Path.Combine(Path.GetTempPath(), $"password_{Guid.NewGuid()}.txt");
        File.WriteAllText(TempPasswordFile, password);

        // Act
        var result = SecurePasswordProvider.GetPassword(passwordFilePath: TempPasswordFile);

        // Assert
        Assert.That(result, Is.Not.Null);
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(password));
    }

    [Test]
    public void GetPassword_EnvVarTakesPrecedenceOverFile()
    {
        // Arrange
        var envPassword = "EnvPassword";
        var filePassword = "FilePassword";

        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, envPassword);

        TempPasswordFile = Path.Combine(Path.GetTempPath(), $"password_{Guid.NewGuid()}.txt");
        File.WriteAllText(TempPasswordFile, filePassword);

        // Act
        var result = SecurePasswordProvider.GetPassword(passwordFilePath: TempPasswordFile);

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo(envPassword), "Environment variable should take precedence over file");
    }

    [Test]
    public void ConvertToSecureString_WithSpecialCharacters_PreservesAllCharacters()
    {
        // Arrange
        var password = "Test!@#$%^&*()_+-=[]{}|;':\",./<>?`~";

        // Act
        var secure = SecurePasswordProvider.ConvertToSecureString(password);
        var result = SecurePasswordProvider.ConvertToPlainString(secure);

        // Assert
        Assert.That(result, Is.EqualTo(password));
    }

    [Test]
    public void ConvertToSecureString_WithUnicodeCharacters_PreservesAllCharacters()
    {
        // Arrange
        var password = "Test密码пароль🔐";

        // Act
        var secure = SecurePasswordProvider.ConvertToSecureString(password);
        var result = SecurePasswordProvider.ConvertToPlainString(secure);

        // Assert
        Assert.That(result, Is.EqualTo(password));
    }
}

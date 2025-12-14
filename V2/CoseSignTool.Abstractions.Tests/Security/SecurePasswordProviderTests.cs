// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security;
using CoseSignTool.Abstractions.Security;
using Moq;

namespace CoseSignTool.Abstractions.Tests.Security;

/// <summary>
/// Tests for SecurePasswordProvider.
/// </summary>
[TestFixture]
public class SecurePasswordProviderTests
{
    private string? TempPasswordFile;
    private Mock<IConsole> MockConsole = null!;
    private SecurePasswordProvider Provider = null!;

    [SetUp]
    public void SetUp()
    {
        MockConsole = new Mock<IConsole>();
        Provider = new SecurePasswordProvider(MockConsole.Object);
    }

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
    public void IsInteractiveInputAvailable_WhenNotRedirectedAndUserInteractive_ReturnsTrue()
    {
        // Arrange
        MockConsole.Setup(c => c.IsInputRedirected).Returns(false);
        MockConsole.Setup(c => c.IsUserInteractive).Returns(true);

        // Act
        var result = Provider.IsInteractiveInputAvailable();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsInteractiveInputAvailable_WhenInputRedirected_ReturnsFalse()
    {
        // Arrange
        MockConsole.Setup(c => c.IsInputRedirected).Returns(true);
        MockConsole.Setup(c => c.IsUserInteractive).Returns(true);

        // Act
        var result = Provider.IsInteractiveInputAvailable();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsInteractiveInputAvailable_WhenNotUserInteractive_ReturnsFalse()
    {
        // Arrange
        MockConsole.Setup(c => c.IsInputRedirected).Returns(false);
        MockConsole.Setup(c => c.IsUserInteractive).Returns(false);

        // Act
        var result = Provider.IsInteractiveInputAvailable();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsInteractiveInputAvailable_WhenExceptionThrown_ReturnsFalse()
    {
        // Arrange
        MockConsole.Setup(c => c.IsInputRedirected).Throws<InvalidOperationException>();

        // Act
        var result = Provider.IsInteractiveInputAvailable();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void GetPassword_WithEnvironmentVariable_ReturnsEnvPassword()
    {
        // Arrange
        var password = "GetPasswordEnvTest";
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, password);

        // Act
        var result = Provider.GetPassword();

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
        var result = Provider.GetPassword(passwordFilePath: TempPasswordFile);

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
        var result = Provider.GetPassword(passwordFilePath: TempPasswordFile);

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

    [Test]
    public void Constructor_WithNullConsole_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SecurePasswordProvider(null!));
    }

    [Test]
    public void Default_ReturnsInstance()
    {
        // Act
        var instance = SecurePasswordProvider.Default;

        // Assert
        Assert.That(instance, Is.Not.Null);
    }

    [Test]
    public void ReadPasswordFromConsole_WithSimplePassword_ReturnsPassword()
    {
        // Arrange
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('t', ConsoleKey.T, false, false, false),
            new ConsoleKeyInfo('e', ConsoleKey.E, false, false, false),
            new ConsoleKeyInfo('s', ConsoleKey.S, false, false, false),
            new ConsoleKeyInfo('t', ConsoleKey.T, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.ReadPasswordFromConsole("Enter: ");

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("test"));
        MockConsole.Verify(c => c.Write("Enter: "), Times.Once);
        MockConsole.Verify(c => c.Write("*"), Times.Exactly(4));
        MockConsole.Verify(c => c.WriteLine(), Times.Once);
    }

    [Test]
    public void ReadPasswordFromConsole_WithBackspace_RemovesCharacter()
    {
        // Arrange
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('a', ConsoleKey.A, false, false, false),
            new ConsoleKeyInfo('b', ConsoleKey.B, false, false, false),
            new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false), // Delete 'b'
            new ConsoleKeyInfo('c', ConsoleKey.C, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.ReadPasswordFromConsole();

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("ac"));
        MockConsole.Verify(c => c.Write("\b \b"), Times.Once);
    }

    [Test]
    public void ReadPasswordFromConsole_BackspaceOnEmpty_DoesNothing()
    {
        // Arrange
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false), // Backspace on empty
            new ConsoleKeyInfo('x', ConsoleKey.X, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.ReadPasswordFromConsole();

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("x"));
        MockConsole.Verify(c => c.Write("\b \b"), Times.Never);
    }

    [Test]
    public void ReadPasswordFromConsole_WithEscape_ReturnsEmpty()
    {
        // Arrange
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('a', ConsoleKey.A, false, false, false),
            new ConsoleKeyInfo('b', ConsoleKey.B, false, false, false),
            new ConsoleKeyInfo('\x1b', ConsoleKey.Escape, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.ReadPasswordFromConsole();

        // Assert
        Assert.That(result.Length, Is.EqualTo(0));
    }

    [Test]
    public void ReadPasswordFromConsole_IgnoresControlCharacters()
    {
        // Arrange
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('a', ConsoleKey.A, false, false, false),
            new ConsoleKeyInfo('\t', ConsoleKey.Tab, false, false, false), // Tab - control character
            new ConsoleKeyInfo('b', ConsoleKey.B, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.ReadPasswordFromConsole();

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("ab"));
    }

    [Test]
    public void ReadPasswordFromConsole_WhenReadKeyThrows_FallsBackToReadLine()
    {
        // Arrange
        MockConsole.Setup(c => c.ReadKey(true)).Throws<InvalidOperationException>();
        MockConsole.Setup(c => c.ReadLine()).Returns("fallbackpassword");

        // Act
        var result = Provider.ReadPasswordFromConsole();

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("fallbackpassword"));
    }

    [Test]
    public void ReadPasswordFromConsole_WhenReadLineReturnsNull_ReturnsEmpty()
    {
        // Arrange
        MockConsole.Setup(c => c.ReadKey(true)).Throws<InvalidOperationException>();
        MockConsole.Setup(c => c.ReadLine()).Returns((string?)null);

        // Act
        var result = Provider.ReadPasswordFromConsole();

        // Assert
        Assert.That(result.Length, Is.EqualTo(0));
    }

    [Test]
    public void GetPassword_WhenNoEnvOrFile_CallsReadPasswordFromConsole()
    {
        // Arrange
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, null);
        
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('p', ConsoleKey.P, false, false, false),
            new ConsoleKeyInfo('w', ConsoleKey.W, false, false, false),
            new ConsoleKeyInfo('d', ConsoleKey.D, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.GetPassword(prompt: "Test: ");

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("pwd"));
        MockConsole.Verify(c => c.Write("Test: "), Times.Once);
    }

    [Test]
    public void GetPassword_WithNonExistentPasswordFile_FallsBackToConsole()
    {
        // Arrange
        Environment.SetEnvironmentVariable(SecurePasswordProvider.DefaultPfxPasswordEnvVar, null);
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.txt");
        
        var keyPresses = new Queue<ConsoleKeyInfo>(new[]
        {
            new ConsoleKeyInfo('x', ConsoleKey.X, false, false, false),
            new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false)
        });

        MockConsole.Setup(c => c.ReadKey(true)).Returns(() => keyPresses.Dequeue());

        // Act
        var result = Provider.GetPassword(passwordFilePath: nonExistentFile);

        // Assert
        var plain = SecurePasswordProvider.ConvertToPlainString(result);
        Assert.That(plain, Is.EqualTo("x"));
    }
}

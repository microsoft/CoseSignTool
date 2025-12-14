// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Security;

namespace CoseSignTool.Abstractions.Security;

/// <summary>
/// Provides secure password handling utilities for command-line applications.
/// Supports reading passwords from environment variables, secure console input, or files.
/// </summary>
/// <remarks>
/// This class is designed to avoid passwords being passed directly on the command line,
/// as command-line arguments are often logged in shell history, process lists, and audit logs.
/// 
/// Recommended usage order:
/// 1. Check for environment variable (CI/CD scenarios)
/// 2. Read from a secure file (automation scenarios)
/// 3. Prompt user interactively (interactive scenarios)
/// </remarks>
public static class SecurePasswordProvider
{
    /// <summary>
    /// Default environment variable name for PFX passwords.
    /// </summary>
    public const string DefaultPfxPasswordEnvVar = "COSESIGNTOOL_PFX_PASSWORD";

    /// <summary>
    /// Gets a password from the specified environment variable.
    /// </summary>
    /// <param name="environmentVariableName">Name of the environment variable.</param>
    /// <returns>SecureString containing the password, or null if not set.</returns>
    public static SecureString? GetPasswordFromEnvironment(string environmentVariableName = DefaultPfxPasswordEnvVar)
    {
        var password = Environment.GetEnvironmentVariable(environmentVariableName);
        if (string.IsNullOrEmpty(password))
        {
            return null;
        }

        return ConvertToSecureString(password);
    }

    /// <summary>
    /// Reads a password from a file. The file should contain only the password (no newline).
    /// </summary>
    /// <param name="filePath">Path to the password file.</param>
    /// <returns>SecureString containing the password.</returns>
    /// <exception cref="FileNotFoundException">If the file does not exist.</exception>
    public static SecureString ReadPasswordFromFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Password file not found: {filePath}", filePath);
        }

        var password = File.ReadAllText(filePath).TrimEnd('\r', '\n');
        return ConvertToSecureString(password);
    }

    /// <summary>
    /// Prompts the user for a password via secure console input.
    /// Characters are masked as they are typed.
    /// </summary>
    /// <param name="prompt">The prompt to display to the user.</param>
    /// <returns>SecureString containing the password.</returns>
    public static SecureString ReadPasswordFromConsole(string prompt = "Enter password: ")
    {
        Console.Write(prompt);
        var password = new SecureString();

        try
        {
            while (true)
            {
                var keyInfo = Console.ReadKey(intercept: true);

                if (keyInfo.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.RemoveAt(password.Length - 1);
                        Console.Write("\b \b"); // Erase the asterisk
                    }
                }
                else if (keyInfo.Key == ConsoleKey.Escape)
                {
                    // Clear input and return empty
                    Console.WriteLine();
                    password.Clear();
                    break;
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    password.AppendChar(keyInfo.KeyChar);
                    Console.Write('*');
                }
            }

            password.MakeReadOnly();
            return password;
        }
        catch (InvalidOperationException)
        {
            // Console input not available (e.g., redirected input)
            // Fall back to reading a line
            Console.WriteLine();
            var line = Console.ReadLine() ?? string.Empty;
            return ConvertToSecureString(line);
        }
    }

    /// <summary>
    /// Gets a password using the following priority order:
    /// 1. Environment variable (if set)
    /// 2. Password file (if path provided and file exists)
    /// 3. Interactive console prompt
    /// </summary>
    /// <param name="passwordFilePath">Optional path to a password file.</param>
    /// <param name="environmentVariableName">Environment variable name to check.</param>
    /// <param name="prompt">Prompt for interactive input.</param>
    /// <returns>SecureString containing the password.</returns>
    public static SecureString GetPassword(
        string? passwordFilePath = null,
        string environmentVariableName = DefaultPfxPasswordEnvVar,
        string prompt = "Enter PFX password: ")
    {
        // 1. Try environment variable
        var envPassword = GetPasswordFromEnvironment(environmentVariableName);
        if (envPassword != null)
        {
            return envPassword;
        }

        // 2. Try password file
        if (!string.IsNullOrEmpty(passwordFilePath) && File.Exists(passwordFilePath))
        {
            return ReadPasswordFromFile(passwordFilePath);
        }

        // 3. Interactive prompt
        return ReadPasswordFromConsole(prompt);
    }

    /// <summary>
    /// Determines if password input should be interactive based on the current execution context.
    /// Returns false if stdin is redirected (pipeline scenarios) or console is unavailable.
    /// </summary>
    public static bool IsInteractiveInputAvailable()
    {
        try
        {
            return !Console.IsInputRedirected && Environment.UserInteractive;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Converts a SecureString to a plain string.
    /// Use sparingly - only when required by APIs that don't support SecureString.
    /// </summary>
    /// <param name="secureString">The SecureString to convert.</param>
    /// <returns>The plain text string.</returns>
    public static string? ConvertToPlainString(SecureString? secureString)
    {
        if (secureString == null || secureString.Length == 0)
        {
            return null;
        }

        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToBSTR(secureString);
            return Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(ptr);
            }
        }
    }

    /// <summary>
    /// Converts a plain string to a SecureString.
    /// The original string should be cleared from memory as soon as possible after this call.
    /// </summary>
    /// <param name="plainString">The plain text string to convert.</param>
    /// <returns>A SecureString containing the value.</returns>
    public static SecureString ConvertToSecureString(string? plainString)
    {
        var secure = new SecureString();

        if (!string.IsNullOrEmpty(plainString))
        {
            foreach (char c in plainString)
            {
                secure.AppendChar(c);
            }
        }

        secure.MakeReadOnly();
        return secure;
    }

    /// <summary>
    /// Creates a SecureString copy of another SecureString.
    /// </summary>
    /// <param name="source">The source SecureString.</param>
    /// <returns>A new SecureString with the same value.</returns>
    public static SecureString Copy(SecureString? source)
    {
        if (source == null)
        {
            var empty = new SecureString();
            empty.MakeReadOnly();
            return empty;
        }

        // We have to go through plain string unfortunately
        var plain = ConvertToPlainString(source);
        try
        {
            return ConvertToSecureString(plain);
        }
        finally
        {
            // Clear the plain string from memory
            if (plain != null)
            {
                // Use GC to help clear the string from memory
                plain = null;
                GC.Collect(0, GCCollectionMode.Forced);
            }
        }
    }
}

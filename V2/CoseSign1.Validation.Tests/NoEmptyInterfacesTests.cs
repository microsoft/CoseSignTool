// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Text;

/// <summary>
/// Architectural guardrail tests.
/// </summary>
/// <remarks>
/// This test intentionally scans source files (not compiled assemblies) to enforce a repo-wide design rule:
/// V2 should not use empty interfaces ("marker interfaces").
///
/// Empty interfaces are brittle because they encode semantics in type identity rather than in an explicit API.
/// In V2, staged validation is represented via <see cref="CoseSign1.Validation.Interfaces.IValidator"/>
/// (stages + stage-aware Validate methods) and <see cref="CoseSign1.Validation.ValidationStage"/>,
/// which provide an explicit contract.
/// </remarks>
[TestFixture]
public sealed class NoEmptyInterfacesTests
{
    [Test]
    public void V2_Source_DoesNotContainEmptyInterfaces()
    {
        var v2Root = FindV2RootDirectory();
        var offenders = FindEmptyInterfaceDeclarations(v2Root);

        if (offenders.Count > 0)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Empty interface declarations are not allowed in V2.");
            sb.AppendLine("Replace marker interfaces with explicit APIs (e.g., stage-aware IValidator + ValidationStage).");
            sb.AppendLine();
            sb.AppendLine("Offenders:");
            foreach (var offender in offenders)
            {
                sb.AppendLine($"- {offender}");
            }

            Assert.Fail(sb.ToString());
        }
    }

    private static string FindV2RootDirectory()
    {
        // Test binaries run from V2/**/bin/**. Walk upward until we find V2/CoseSignToolV2.sln.
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current != null)
        {
            var candidate = Path.Combine(current.FullName, "CoseSignToolV2.sln");
            if (File.Exists(candidate))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        Assert.Fail("Could not locate V2 root directory (CoseSignToolV2.sln) from test execution directory.");
        return string.Empty;
    }

    private static List<string> FindEmptyInterfaceDeclarations(string v2Root)
    {
        var offenders = new List<string>();

        foreach (var filePath in Directory.EnumerateFiles(v2Root, "*.cs", SearchOption.AllDirectories))
        {
            if (IsGeneratedOrBuildOutput(filePath))
            {
                continue;
            }

            var text = File.ReadAllText(filePath);
            var stripped = StripCommentsAndStrings(text);

            int index = 0;
            while (true)
            {
                int interfaceKeywordIndex = IndexOfKeyword(stripped, "interface", index);
                if (interfaceKeywordIndex < 0)
                {
                    break;
                }

                int openBraceIndex = stripped.IndexOf('{', interfaceKeywordIndex);
                if (openBraceIndex < 0)
                {
                    break;
                }

                int closeBraceIndex = FindMatchingBraceIndex(stripped, openBraceIndex);
                if (closeBraceIndex < 0)
                {
                    break;
                }

                var body = stripped.Substring(openBraceIndex + 1, closeBraceIndex - openBraceIndex - 1);
                if (string.IsNullOrWhiteSpace(body))
                {
                    offenders.Add(Path.GetRelativePath(v2Root, filePath));
                }

                index = closeBraceIndex + 1;
            }
        }

        return offenders;
    }

    private static bool IsGeneratedOrBuildOutput(string filePath)
    {
        // Keep the guardrail focused on hand-authored source.
        var normalized = filePath.Replace('\\', '/');
        return normalized.Contains("/bin/")
            || normalized.Contains("/obj/")
            || normalized.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase)
            || normalized.EndsWith(".generated.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static int IndexOfKeyword(string text, string keyword, int startIndex)
    {
        // A minimal keyword matcher that requires non-identifier boundaries.
        for (int i = startIndex; i <= text.Length - keyword.Length; i++)
        {
            if (!text.AsSpan(i, keyword.Length).SequenceEqual(keyword))
            {
                continue;
            }

            bool leftOk = i == 0 || !IsIdentifierChar(text[i - 1]);
            bool rightOk = i + keyword.Length >= text.Length || !IsIdentifierChar(text[i + keyword.Length]);
            if (leftOk && rightOk)
            {
                return i;
            }
        }

        return -1;
    }

    private static bool IsIdentifierChar(char c)
    {
        return char.IsLetterOrDigit(c) || c == '_';
    }

    private static int FindMatchingBraceIndex(string text, int openBraceIndex)
    {
        int depth = 0;
        for (int i = openBraceIndex; i < text.Length; i++)
        {
            if (text[i] == '{')
            {
                depth++;
            }
            else if (text[i] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }

        return -1;
    }

    private static string StripCommentsAndStrings(string text)
    {
        // This is not a full C# parser; it is a conservative stripper sufficient for identifying
        // truly empty interface bodies like: `public interface IFoo { }`.
        var sb = new StringBuilder(text.Length);

        bool inLineComment = false;
        bool inBlockComment = false;
        bool inString = false;
        bool inVerbatimString = false;
        bool inChar = false;

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            char next = i + 1 < text.Length ? text[i + 1] : '\0';

            if (inLineComment)
            {
                if (c == '\n')
                {
                    inLineComment = false;
                    sb.Append(c);
                }
                continue;
            }

            if (inBlockComment)
            {
                if (c == '*' && next == '/')
                {
                    inBlockComment = false;
                    i++;
                }
                continue;
            }

            if (inString)
            {
                if (inVerbatimString)
                {
                    if (c == '"' && next == '"')
                    {
                        i++;
                        continue;
                    }

                    if (c == '"')
                    {
                        inString = false;
                        inVerbatimString = false;
                    }
                    continue;
                }

                if (c == '\\')
                {
                    i++;
                    continue;
                }

                if (c == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (inChar)
            {
                if (c == '\\')
                {
                    i++;
                    continue;
                }

                if (c == '\'')
                {
                    inChar = false;
                }
                continue;
            }

            if (c == '/' && next == '/')
            {
                inLineComment = true;
                i++;
                continue;
            }

            if (c == '/' && next == '*')
            {
                inBlockComment = true;
                i++;
                continue;
            }

            if (c == '@' && next == '"')
            {
                inString = true;
                inVerbatimString = true;
                i++;
                continue;
            }

            if (c == '"')
            {
                inString = true;
                continue;
            }

            if (c == '\'')
            {
                inChar = true;
                continue;
            }

            sb.Append(c);
        }

        return sb.ToString();
    }
}

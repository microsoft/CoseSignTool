// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using DIDx509.Parsing;

namespace DIDx509.Tests.Parsing;

[TestFixture]
public class PercentEncodingTests
{
    [Test]
    public void Encode_NullOrEmpty_ReturnsEmpty()
    {
        Assert.That(PercentEncoding.Encode(null!), Is.EqualTo(string.Empty));
        Assert.That(PercentEncoding.Encode(""), Is.EqualTo(string.Empty));
    }

    [Test]
    public void Decode_NullOrEmpty_ReturnsEmpty()
    {
        Assert.That(PercentEncoding.Decode(null!), Is.EqualTo(string.Empty));
        Assert.That(PercentEncoding.Decode(""), Is.EqualTo(string.Empty));
    }

    [Test]
    public void Encode_AllowedCharacters_NotEncoded()
    {
        // ALPHA / DIGIT / "-" / "." / "_" should not be encoded
        string input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._";
        string result = PercentEncoding.Encode(input);
        Assert.That(result, Is.EqualTo(input));
    }

    [Test]
    public void Encode_SpecialCharacters_EncodesCorrectly()
    {
        // Space should be %20
        Assert.That(PercentEncoding.Encode(" "), Is.EqualTo("%20"));

        // Colon should be %3A
        Assert.That(PercentEncoding.Encode(":"), Is.EqualTo("%3A"));

        // Slash should be %2F
        Assert.That(PercentEncoding.Encode("/"), Is.EqualTo("%2F"));

        // Question mark should be %3F
        Assert.That(PercentEncoding.Encode("?"), Is.EqualTo("%3F"));
    }

    [Test]
    public void Encode_TildeIsEncoded()
    {
        // Per DID:X509 spec, tilde (~) IS NOT allowed unencoded (differs from RFC 3986)
        string result = PercentEncoding.Encode("~");
        Assert.That(result, Is.EqualTo("%7E"));
    }

    [Test]
    public void Encode_UnicodeCharacters_EncodesAsUtf8()
    {
        // Unicode characters should be encoded as UTF-8 byte sequences
        string input = "日本語";
        string result = PercentEncoding.Encode(input);
        Assert.That(result, Does.Contain("%"));
        // Decode back should match original
        Assert.That(PercentEncoding.Decode(result), Is.EqualTo(input));
    }

    [Test]
    public void Decode_NoPercentEncoding_ReturnsOriginal()
    {
        string input = "simple-text_123.test";
        Assert.That(PercentEncoding.Decode(input), Is.EqualTo(input));
    }

    [Test]
    public void Decode_PercentEncodedSpace_DecodesCorrectly()
    {
        Assert.That(PercentEncoding.Decode("hello%20world"), Is.EqualTo("hello world"));
    }

    [Test]
    public void Decode_MultipleEncodedCharacters_DecodesCorrectly()
    {
        Assert.That(PercentEncoding.Decode("test%3A%2F%2Fvalue"), Is.EqualTo("test://value"));
    }

    [Test]
    public void Decode_MixedContent_DecodesCorrectly()
    {
        string input = "hello%20world%21test";
        Assert.That(PercentEncoding.Decode(input), Is.EqualTo("hello world!test"));
    }

    [Test]
    public void Decode_InvalidPercentEncoding_PreservesOriginal()
    {
        // Incomplete encoding at end
        string input = "test%2";
        Assert.That(PercentEncoding.Decode(input), Is.EqualTo("test%2"));
    }

    [Test]
    public void Decode_PercentNotFollowedByHex_PreservesPercent()
    {
        // % not followed by valid hex digits
        string input = "test%GGvalue";
        Assert.That(PercentEncoding.Decode(input), Is.EqualTo("test%GGvalue"));
    }

    [Test]
    public void Decode_ConsecutiveEncodedBytes_DecodesCorrectly()
    {
        // Test consecutive encoded bytes forming a multi-byte UTF-8 character
        // "日" in UTF-8 is E6 97 A5
        string encoded = "%E6%97%A5";
        Assert.That(PercentEncoding.Decode(encoded), Is.EqualTo("日"));
    }

    [Test]
    public void Decode_LowercaseHex_DecodesCorrectly()
    {
        Assert.That(PercentEncoding.Decode("%2f"), Is.EqualTo("/"));
    }

    [Test]
    public void Decode_UppercaseHex_DecodesCorrectly()
    {
        Assert.That(PercentEncoding.Decode("%2F"), Is.EqualTo("/"));
    }

    [Test]
    public void IsDidX509AllowedCharacter_UppercaseLetters_ReturnsTrue()
    {
        for (char c = 'A'; c <= 'Z'; c++)
        {
            Assert.That(PercentEncoding.IsDidX509AllowedCharacter(c), Is.True, $"'{c}' should be allowed");
        }
    }

    [Test]
    public void IsDidX509AllowedCharacter_LowercaseLetters_ReturnsTrue()
    {
        for (char c = 'a'; c <= 'z'; c++)
        {
            Assert.That(PercentEncoding.IsDidX509AllowedCharacter(c), Is.True, $"'{c}' should be allowed");
        }
    }

    [Test]
    public void IsDidX509AllowedCharacter_Digits_ReturnsTrue()
    {
        for (char c = '0'; c <= '9'; c++)
        {
            Assert.That(PercentEncoding.IsDidX509AllowedCharacter(c), Is.True, $"'{c}' should be allowed");
        }
    }

    [Test]
    public void IsDidX509AllowedCharacter_SpecialAllowed_ReturnsTrue()
    {
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('-'), Is.True);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('_'), Is.True);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('.'), Is.True);
    }

    [Test]
    public void IsDidX509AllowedCharacter_NotAllowed_ReturnsFalse()
    {
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter(' '), Is.False);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter(':'), Is.False);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('/'), Is.False);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('~'), Is.False);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('@'), Is.False);
        Assert.That(PercentEncoding.IsDidX509AllowedCharacter('#'), Is.False);
    }

    [Test]
    public void Encode_AndDecode_RoundTrip()
    {
        // Test that encoding and then decoding returns the original
        string[] testStrings =
        {
            "simple",
            "with spaces",
            "special:chars/here?and=more",
            "unicode日本語text",
            "mixed %20 literal percent"
        };

        foreach (var original in testStrings)
        {
            string encoded = PercentEncoding.Encode(original);
            string decoded = PercentEncoding.Decode(encoded);
            Assert.That(decoded, Is.EqualTo(original), $"Round trip failed for '{original}'");
        }
    }
}

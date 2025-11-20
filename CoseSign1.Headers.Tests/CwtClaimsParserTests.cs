// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests;

using FluentAssertions;
using NUnit.Framework;
using CoseSign1.Headers.Helpers;

/// <summary>
/// Tests for the CwtClaimsParser class.
/// </summary>
[TestFixture]
public class CwtClaimsParserTests
{
    #region Basic Parsing Tests

    [Test]
    public void ParseClaims_WithEmptyString_ReturnsEmptyDictionary()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("");
        result.Should().BeEmpty();
    }

    [Test]
    public void ParseClaims_WithNull_ReturnsEmptyDictionary()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims(null);
        result.Should().BeEmpty();
    }

    [Test]
    public void ParseClaims_WithWhitespace_ReturnsEmptyDictionary()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("   ");
        result.Should().BeEmpty();
    }

    [Test]
    public void ParseClaims_WithSingleIntegerClaim_ParsesCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=123");
        result.Should().ContainKey(3);
        result[3].Should().Be(123);
        result[3].Should().BeOfType<int>();
    }

    [Test]
    public void ParseClaims_WithSingleStringClaim_ParsesCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=audience");
        result.Should().ContainKey(3);
        result[3].Should().Be("audience");
        result[3].Should().BeOfType<string>();
    }

    [Test]
    public void ParseClaims_WithMultipleClaims_ParsesAll()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=audience,4=1234567890");
        result.Should().HaveCount(2);
        result[3].Should().Be("audience");
        result[4].Should().Be(1234567890);
    }

    #endregion

    #region Type Inference Tests

    [Test]
    public void ParseClaims_WithInt32Value_ParsesAsInt()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=123456");
        result[3].Should().BeOfType<int>();
        result[3].Should().Be(123456);
    }

    [Test]
    public void ParseClaims_WithInt64Value_ParsesAsLong()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=9223372036854775807");
        result[3].Should().BeOfType<long>();
        result[3].Should().Be(9223372036854775807L);
    }

    [Test]
    public void ParseClaims_WithBooleanTrue_ParsesAsBoolean()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=true");
        result[3].Should().BeOfType<bool>();
        result[3].Should().Be(true);
    }

    [Test]
    public void ParseClaims_WithBooleanFalse_ParsesAsBoolean()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=false");
        result[3].Should().BeOfType<bool>();
        result[3].Should().Be(false);
    }

    [Test]
    public void ParseClaims_WithBooleanMixedCase_ParsesAsBoolean()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=True,4=FALSE");
        result[3].Should().Be(true);
        result[4].Should().Be(false);
    }

    [Test]
    public void ParseClaims_WithHexByteArray_ParsesAsBytes()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=0x48656c6c6f");
        result[3].Should().BeOfType<byte[]>();
        byte[] bytes = (byte[])result[3];
        bytes.Should().Equal(new byte[] { 0x48, 0x65, 0x6c, 0x6c, 0x6f }); // "Hello" in hex
    }

    [Test]
    public void ParseClaims_WithHexByteArrayUpperCase_ParsesAsBytes()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=0xDEADBEEF");
        result[3].Should().BeOfType<byte[]>();
        byte[] bytes = (byte[])result[3];
        bytes.Should().Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
    }

    [Test]
    public void ParseClaims_WithEmptyHexString_ParsesAsEmptyByteArray()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=0x");
        result[3].Should().BeOfType<byte[]>();
        byte[] bytes = (byte[])result[3];
        bytes.Should().BeEmpty();
    }

    [Test]
    public void ParseClaims_WithNegativeNumber_ParsesAsInt()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=-12345");
        result[3].Should().BeOfType<int>();
        result[3].Should().Be(-12345);
    }

    [Test]
    public void ParseClaims_WithStringThatLooksLikeNumber_ParsesAsString()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=123abc");
        result[3].Should().BeOfType<string>();
        result[3].Should().Be("123abc");
    }

    #endregion

    #region Complex Claims Tests

    [Test]
    public void ParseClaims_WithMixedTypes_ParsesAllCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=audience,4=1234567890,5=true,6=0x48656c6c6f");
        result.Should().HaveCount(4);
        result[3].Should().BeOfType<string>();
        result[3].Should().Be("audience");
        result[4].Should().BeOfType<int>();
        result[4].Should().Be(1234567890);
        result[5].Should().BeOfType<bool>();
        result[5].Should().Be(true);
        result[6].Should().BeOfType<byte[]>();
        ((byte[])result[6]).Should().Equal(new byte[] { 0x48, 0x65, 0x6c, 0x6c, 0x6f });
    }

    [Test]
    public void ParseClaims_WithWhitespaceAroundValues_TrimsCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3= audience ,4= 123 ");
        result[3].Should().Be("audience");
        result[4].Should().Be(123);
    }

    [Test]
    public void ParseClaims_WithEmptyClaimPairs_SkipsThem()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=audience,,4=123");
        result.Should().HaveCount(2);
        result.Should().ContainKey(3);
        result.Should().ContainKey(4);
    }

    [Test]
    public void ParseClaims_WithStringContainingComma_ThrowsArgumentException()
    {
        // Note: This documents the limitation - values cannot contain unescaped commas
        // Comma is the delimiter, so "3=hello,world" is parsed as two claims
        Action act = () => CwtClaimsParser.ParseClaims("3=hello,world");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid claim format*")
            .WithMessage("*'world'*");
    }

    [Test]
    public void ParseClaims_WithStringContainingEquals_ParsesOnlyFirstEquals()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=key=value");
        result[3].Should().Be("key=value");
    }

    #endregion

    #region Error Handling Tests

    [Test]
    public void ParseClaims_WithInvalidFormat_ThrowsArgumentException()
    {
        Action act = () => CwtClaimsParser.ParseClaims("invalid");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid claim format*")
            .WithMessage("*Expected format: 'label=value'*");
    }

    [Test]
    public void ParseClaims_WithStringLabel_IsValid()
    {
        // String labels are valid per IANA CWT Claims registry
        var claims = CwtClaimsParser.ParseClaims("customlabel=value");
        claims.Should().ContainKey("customlabel");
        claims["customlabel"].Should().Be("value");
    }

    [Test]
    public void ParseClaims_WithReservedLabel1_ThrowsArgumentException()
    {
        Action act = () => CwtClaimsParser.ParseClaims("1=issuer");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Claim label 1 is reserved for issuer*")
            .WithMessage("*Use --cwt-issuer instead*");
    }

    [Test]
    public void ParseClaims_WithReservedLabel2_ThrowsArgumentException()
    {
        Action act = () => CwtClaimsParser.ParseClaims("2=subject");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Claim label 2 is reserved for subject*")
            .WithMessage("*Use --cwt-subject instead*");
    }

    [Test]
    public void ParseClaims_WithNegativeLabel_IsValid()
    {
        // Negative labels are valid per IANA CWT Claims registry
        // Labels -65536 to -1 are available for specification or unassigned use
        // Labels < -65536 are reserved for private use
        var claims = CwtClaimsParser.ParseClaims("-260=hcert,-1=custom");
        claims.Should().ContainKey(-260);
        claims.Should().ContainKey(-1);
        claims[-260].Should().Be("hcert");
        claims[-1].Should().Be("custom");
    }

    [Test]
    public void ParseClaims_WithInvalidHexString_ThrowsArgumentException()
    {
        Action act = () => CwtClaimsParser.ParseClaims("3=0xZZZZ");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid hex string*")
            .WithMessage("*non-hexadecimal characters*");
    }

    [Test]
    public void ParseClaims_WithOddLengthHexString_ThrowsArgumentException()
    {
        Action act = () => CwtClaimsParser.ParseClaims("3=0x123");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid hex string*")
            .WithMessage("*even number of characters*");
    }

    #endregion

    #region Validation Tests

    [Test]
    public void ValidateClaims_WithValidClaims_DoesNotThrow()
    {
        var claims = new Dictionary<object, object>
        {
            { 3, "audience" },
            { 4, 1234567890 },
            { 5, true }
        };

        Action act = () => CwtClaimsParser.ValidateClaims(claims);
        act.Should().NotThrow();
    }

    [Test]
    public void ValidateClaims_WithReservedLabel1_ThrowsArgumentException()
    {
        var claims = new Dictionary<object, object>
        {
            { 1, "issuer" },
            { 3, "audience" }
        };

        Action act = () => CwtClaimsParser.ValidateClaims(claims);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Claim label 1 is reserved for issuer*");
    }

    [Test]
    public void ValidateClaims_WithReservedLabel2_ThrowsArgumentException()
    {
        var claims = new Dictionary<object, object>
        {
            { 2, "subject" },
            { 3, "audience" }
        };

        Action act = () => CwtClaimsParser.ValidateClaims(claims);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Claim label 2 is reserved for subject*");
    }

    [Test]
    public void ValidateClaims_WithNegativeLabel_IsValid()
    {
        // Negative labels are valid per IANA CWT Claims registry
        var claims = new Dictionary<object, object>
        {
            { -260, "hcert" },
            { -1, "custom" }
        };

        Action act = () => CwtClaimsParser.ValidateClaims(claims);
        act.Should().NotThrow();
    }

    [Test]
    public void ValidateClaims_WithEmptyDictionary_DoesNotThrow()
    {
        var claims = new Dictionary<object, object>();
        Action act = () => CwtClaimsParser.ValidateClaims(claims);
        act.Should().NotThrow();
    }

    #endregion

    #region Edge Cases

    [Test]
    public void ParseClaims_WithZeroLabel_ParsesCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("0=value");
        result.Should().ContainKey(0);
        result[0].Should().Be("value");
    }

    [Test]
    public void ParseClaims_WithLargeLabel_ParsesCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("999999=value");
        result.Should().ContainKey(999999);
        result[999999].Should().Be("value");
    }

    [Test]
    public void ParseClaims_WithEmptyStringValue_ParsesAsEmptyString()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=");
        result[3].Should().Be("");
    }

    [Test]
    public void ParseClaims_WithUnicodeValue_ParsesCorrectly()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=Hello世界🌍");
        result[3].Should().Be("Hello世界🌍");
    }

    [Test]
    public void ParseClaims_WithSpecialCharacters_ParsesAsString()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=!@#$%^&*()");
        result[3].Should().Be("!@#$%^&*()");
    }

    [Test]
    public void ParseClaims_WithLeadingZeros_ParsesAsInt()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=00123");
        result[3].Should().BeOfType<int>();
        result[3].Should().Be(123);
    }

    [Test]
    public void ParseClaims_WithMaxInt32_ParsesAsInt()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=2147483647");
        result[3].Should().BeOfType<int>();
        result[3].Should().Be(2147483647);
    }

    [Test]
    public void ParseClaims_WithMinInt32_ParsesAsInt()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=-2147483648");
        result[3].Should().BeOfType<int>();
        result[3].Should().Be(-2147483648);
    }

    [Test]
    public void ParseClaims_WithOverflowInt32_ParsesAsLong()
    {
        Dictionary<object, object> result = CwtClaimsParser.ParseClaims("3=2147483648");
        result[3].Should().BeOfType<long>();
        result[3].Should().Be(2147483648L);
    }

    #endregion

    #region Properties Tests

    [Test]
    public void SupportedTypesDescription_ReturnsHelpfulMessage()
    {
        string description = CwtClaimsParser.SupportedTypesDescription;
        description.Should().Contain("integers");
        description.Should().Contain("booleans");
        description.Should().Contain("byte arrays");
        description.Should().Contain("strings");
        description.Should().Contain("0xHEX");
    }

    #endregion
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Tests;

using System;
using Azure;
using Azure.Core.TestCommon;
using Moq;

/// <summary>
/// Builds <c>CodeTransparencyClient.CreateEntryAsync</c> responses for unit tests.
/// </summary>
internal static class MstCreateEntryResponses
{
    /// <summary>
    /// A committed (201) response whose <c>Location</c> header points at <c>/entries/{entryId}</c>.
    /// </summary>
    /// <param name="entryId">The entry id to place in the <c>Location</c> header.</param>
    /// <param name="query">Optional query string appended to the <c>Location</c> header, without the leading '?'.</param>
    /// <returns>The response.</returns>
    public static NullableResponse<BinaryData> Committed(string entryId, string? query = null)
    {
        string location = $"https://mst.example.com/entries/{entryId}";
        if (!string.IsNullOrEmpty(query))
        {
            location = $"{location}?{query}";
        }

        MockResponse rawResponse = new MockResponse(201).AddHeader("Location", location);
        return Response.FromValue(BinaryData.FromBytes(new byte[] { 1, 2, 3 }), rawResponse);
    }

    /// <summary>
    /// A 201 response with no <c>Location</c> header and a body that is not a valid receipt,
    /// so no entry id can be determined.
    /// </summary>
    /// <returns>The response.</returns>
    public static NullableResponse<BinaryData> WithoutEntryId()
    {
        return Response.FromValue(BinaryData.FromBytes(new byte[] { 1, 2, 3 }), new MockResponse(201));
    }

    /// <summary>
    /// A response with no value and no <c>Location</c> header (e.g. a 303 the pipeline did not follow).
    /// </summary>
    /// <returns>The response.</returns>
    public static NullableResponse<BinaryData> NoValue()
    {
        Mock<NullableResponse<BinaryData>> response = new Mock<NullableResponse<BinaryData>>();
        response.Setup(r => r.HasValue).Returns(false);
        response.Setup(r => r.GetRawResponse()).Returns(new MockResponse(303, "See Other"));
        return response.Object;
    }
}
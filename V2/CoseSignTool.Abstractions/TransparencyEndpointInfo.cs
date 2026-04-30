// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Describes a transparency service endpoint that is compatible with a signing provider.
/// </summary>
/// <param name="ServiceType">Transparency service type (for example, <c>mst</c> or <c>rekor</c>).</param>
/// <param name="Endpoint">Transparency service endpoint URL.</param>
/// <param name="DisplayName">Human-readable service name.</param>
/// <param name="AutoSubmit">Whether automatic submission is recommended.</param>
public record TransparencyEndpointInfo(
    string ServiceType,
    string Endpoint,
    string DisplayName,
    bool AutoSubmit);
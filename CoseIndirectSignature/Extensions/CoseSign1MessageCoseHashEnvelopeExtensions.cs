// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature.Extensions;

using System;

/// <summary>
/// Extensions for <see cref="CoseSign1Message"/> to support COSE Hash Envelope.
/// </summary>
public static class CoseSign1MessageCoseHashEnvelopeExtensions
{
    /// <summary>
    /// Checks to see if the COSE Sign1 Message is a CoseHashEnvelope.
    /// https://www.ietf.org/archive/id/draft-ietf-cose-hash-envelope-04.html
    /// </summary>
    /// <param name="this">The <see cref="CoseSign1Message"/> to check.</param>
    /// <returns>True if <paramref name="this"/> is a CoseHashEnvelope, False otherwise.</returns>
    public static bool TryGetIsCoseHashEnvelope(this CoseSign1Message? @this)
    {
        if (@this == null)
        {
            Trace.TraceError($"{nameof(TryGetIsCoseHashEnvelope)} was called on a null CoseSign1Message object");
            return false;
        }

        if (@this.Content == null)
        {
            Trace.TraceWarning($"{nameof(TryGetIsCoseHashEnvelope)} was called on a detached CoseSign1Message object, which is not valid.");
            return false;
        }

        if(!@this.TryGetPayloadHashAlgorithm(out _))
        {
            Trace.TraceWarning($"{nameof(TryGetIsCoseHashEnvelope)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the PayloadHashAlg header present.");
            return false;
        }

        // This is a CoseHashEnvelope CoseSign1Message.
        return true;
    }

    /// <summary>
    /// Tries to get the payload hash algorithm from the protected headers of the CoseSign1Message.
    /// </summary>
    /// <param name="this">The <see cref="CoseSign1Message"/> to be checked for PayloadHashAlgorithm protected header value.</param>
    /// <param name="payloadHashAlgorithm">ill be set to valid <see cref="CoseHashAlgorithm"/> if the return value is True. null otherwise.</param>
    /// <returns>True if the message has a valid PayloadHashAlgorithm header value, false otherwise.</returns>
    /// <remarks>Returns false if the value is found in the unprotected headers at all.</remarks>
    public static bool TryGetPayloadHashAlgorithm(this CoseSign1Message? @this, out CoseHashAlgorithm? payloadHashAlgorithm)
    {
        if (@this == null)
        {
            Trace.TraceError($"{nameof(TryGetPayloadHashAlgorithm)} was called on a null CoseSign1Message object");
            payloadHashAlgorithm = null;
            return false;
        }

        CoseHashAlgorithm? extractedValue = null;
        // and MUST NOT be present in the unprotected header.
        if (@this.UnprotectedHeaders.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg], out CoseHeaderValue payloadHashAlgorithmValue))
        {
            Trace.TraceWarning($"{nameof(TryGetPayloadHashAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) with the PayloadHashAlg present in unprotected headers which is not valid.");
            payloadHashAlgorithm = null;
            return false;
        }

        // Label 258 (payload hash algorithm) MUST be present in the protected header
        if (@this.ProtectedHeaders.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg], out payloadHashAlgorithmValue))
        {
            extractedValue = GetCoseHashAlgorithmFromHeaderValue(payloadHashAlgorithmValue);
            if (extractedValue == null)
            {
                Trace.TraceWarning($"{nameof(TryGetPayloadHashAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) with the PayloadHashAlg header value not defined in the CoseHashAlgorithm enum.");
                payloadHashAlgorithm = null;
                return false;
            }

            payloadHashAlgorithm = extractedValue;
            return true;
        }

        Trace.TraceWarning($"{nameof(TryGetPayloadHashAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the PayloadHashAlg protected header present.");
        payloadHashAlgorithm = null;
        return false;
    }

    private static CoseHashAlgorithm? GetCoseHashAlgorithmFromHeaderValue(CoseHeaderValue payloadHeaderValue)
    {
        long value = payloadHeaderValue.GetValueAsInt32();
        if (Enum.IsDefined(typeof(CoseHashAlgorithm), value))
        {
            return (CoseHashAlgorithm)value;
        }
        else
        {
            Trace.TraceWarning($"Value {value} is not defined in the CoseHashAlgorithm enum.");
            return null;
        }
    }

    /// <summary>
    /// Tries to get the preimage content type as string from the headers of the CoseSign1Message.
    /// </summary>
    /// <param name="this">The <see cref="CoseSign1Message"/> to evaluate.</param>
    /// <param name="preImageContentType">OUT param which will have the value of the PreImageContentType Cose Header as a string.</param>
    /// <returns>True if the PreImageContentType header is found and <paramref name="preImageContentType"/> will be non-null, False otherwise.</returns>
    public static bool TryGetPreImageContentType(this CoseSign1Message? @this, out string? preImageContentType) =>
        TryGetPreImageContentType(@this, out preImageContentType, out _) && !string.IsNullOrWhiteSpace(preImageContentType);

    /// <summary>
    /// Tries to get the preimage content type as CoaP from the headers of the CoseSign1Message.
    /// </summary>
    /// <param name="this">The <see cref="CoseSign1Message"/> to evaluate.</param>
    /// <param name="coapPreImageContentType">OUT param which will have the value of the PreImageContentType Cose Header as a CoAP content type.</param>
    /// <returns>True if the PreImageContentType header is found and <paramref name="coapPreImageContentType"/> will be non-null, False otherwise.</returns>
    public static bool TryGetPreImageContentType(this CoseSign1Message? @this, out int? coapPreImageContentType) =>
        TryGetPreImageContentType(@this, out _, out coapPreImageContentType) && coapPreImageContentType != null;

    /// <summary>
    /// Tries to get the preimage content type from the headers of the CoseSign1Message.
    /// </summary>
    /// <param name="this">The <see cref="CoseSign1Message"/> to evaluate.</param>
    /// <param name="preImageContentType">OUT param which will have the value of the PreImageContentType Cose Header.</param>
    /// <param name="coapPreImageContentType">OUT param which will have the value of the PreImageContentType Cose Header as a CoAP content type.</param>
    /// <returns>True if the PreImageContentType header is found and <paramref name="preImageContentType"/> will be non-null, False otherwise.</returns>
    public static bool TryGetPreImageContentType(this CoseSign1Message? @this, out string? preImageContentType, out int? coapPreImageContentType)
    {
        coapPreImageContentType = null;
        preImageContentType = null;

        if (@this == null)
        {
            Trace.TraceError($"{nameof(TryGetPayloadHashAlgorithm)} was called on a null CoseSign1Message object");
            return false;
        }

        // Label 259 (content type of the preimage of the payload) MAY be
        // present in the protected header or unprotected header.

        // first check protected headers as its preferred to be present there
        if (@this.ProtectedHeaders.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PreimageContentType], out CoseHeaderValue preImageContentTypeValue))
        {
            try
            {
                preImageContentType = preImageContentTypeValue.GetValueAsString();
            }
            catch(InvalidOperationException)
            {
                coapPreImageContentType = preImageContentTypeValue.GetValueAsInt32();
            }
            return true;
        }

        // second check unprotected headers
        if (@this.UnprotectedHeaders.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PreimageContentType], out preImageContentTypeValue))
        {
            try
            {
                preImageContentType = preImageContentTypeValue.GetValueAsString();
            }
            catch (InvalidOperationException)
            {
                coapPreImageContentType = preImageContentTypeValue.GetValueAsInt32();
            }
            return true;
        }

        Trace.TraceWarning($"{nameof(TryGetPreImageContentType)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the PreimageContentType header present.");
        return false;
    }

    /// <summary>
    /// Tries to get the payload location from the protected headers of the CoseSign1Message.
    /// </summary>
    /// <param name="this">The <see cref="CoseSign1Message"/> this extension method will apply to.</param>
    /// <param name="payloadLocation">OUT reference to they payload location if the payload location is present in the <paramref name="this"/> message.</param>
    /// <returns>True if the payload location was extracted, false otherwise.</returns>
    /// <remarks>Will also return False if the value is found in the unprotected header.</remarks>
    public static bool TryGetPayloadLocation(this CoseSign1Message? @this, out string? payloadLocation)
    {
        if (@this == null)
        {
            Trace.TraceError($"{nameof(TryGetPayloadHashAlgorithm)} was called on a null CoseSign1Message object");
            payloadLocation = null;
            return false;
        }

        // Label 260 (payload_location) MAY be added to the protected
        // header and MUST NOT be presented in the unprotected header.

        if(@this.UnprotectedHeaders?.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadLocation], out CoseHeaderValue payloadLocationValue) ?? false)
        {
            // If the payload location is present in the unprotected headers, return false.
            Trace.TraceWarning($"{nameof(TryGetPayloadLocation)} was called on a CoseSign1Message object({@this.GetHashCode()}) with the PayloadLocation present in unprotected headers which is not valid.");
            payloadLocation = null;
            return false;
        }

        if (@this.ProtectedHeaders.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadLocation], out payloadLocationValue))
        {
            payloadLocation = payloadLocationValue.GetValueAsString();
            return true;
        }

        Trace.TraceWarning($"{nameof(TryGetPayloadLocation)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the PayloadLocation header present.");
        payloadLocation = null;
        return false;
    }

    /// <summary>
    /// Leverages the CoseHashEnvelope rules to validate content against the stored indirect hash of the content.
    /// </summary>
    /// <remarks>https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/03/</remarks>
    /// <param name="this">The <see cref="CoseSign1Message"/> to evaluate the CoseHashEnvelope structure</param>
    /// <param name="artifactBytes">The artifact bytes to evaluate.</param>
    /// <param name="artifactStream">The artifact stream to evaluate.</param>
    /// <exception cref="InvalidCoseDataException">Thrown if the <paramref name="this"/> object is not a valid CoseHashEnvelope message.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="this"/> is null.</exception>
    /// <returns>True if the Indirect signature in the CoseSign1Message matches the signature of the artifact bytes; False otherwise.</returns>
    internal static bool SignatureMatchesInternalCoseHashEnvelope(this CoseSign1Message @this, ReadOnlyMemory<byte>? artifactBytes = null, Stream? artifactStream = null)
    {
        if (@this == null)
        {
            Trace.TraceError($"{nameof(SignatureMatchesInternalCoseHashEnvelope)} was called on a null CoseSign1Message object");
            throw new ArgumentNullException(nameof(@this));
        }
        _ = @this.ProtectedHeaders.TryGetValue(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg], out CoseHeaderValue hashAlgValue);
        CoseHashAlgorithm? hashAlg = GetCoseHashAlgorithmFromHeaderValue(hashAlgValue);
        if (hashAlg == null)
        {
            string logMessage = $"The CoseSign1Message[{@this?.GetHashCode()}] object does not contain a valid PayloadHashAlg header value.";
            Trace.TraceWarning(logMessage);
            throw new InvalidCoseDataException(logMessage);
        }

        if(@this.Content == null || @this.Content.Value.Length == 0)
        {
            string logMessage = $"The CoseSign1Message[{@this?.GetHashCode()}] object does not contain a valid Content value for CoseHashEnvelope usage.";
            Trace.TraceWarning(logMessage);
            throw new InvalidCoseDataException(logMessage);
        }

        return IndirectSignatureFactory.HashMatches((CoseHashAlgorithm)hashAlg, @this.Content.Value, artifactBytes, artifactStream);
    }
}

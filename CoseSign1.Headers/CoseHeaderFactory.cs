// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

/// <summary>
/// A factory class to manage protected and unprotected headers. 
/// </summary>
public sealed class CoseHeaderFactory : ICoseHeaderFactory, IDisposable
{
    /// <summary>
    /// A single instance of the factory class.
    /// </summary>
    private static CoseHeaderFactory? SingletonInstance = null;

    /// <summary>
    /// A collection of headers where the value is an integer.
    /// CoseHeaderMap value accepts Int32 only.
    /// </summary>
    private List<CoseHeader<int>> IntHeaders { get; set; }

    /// <summary>
    /// A collection of headers where the value is a string.
    /// </summary>
    private List<CoseHeader<string>> StringHeaders { get; set; }

    /// <summary>
    /// Count of protected headers.
    /// </summary>
    public int ProtectedHeadersCount => IntHeaders.Where(h => h.IsProtected).ToList().Count() + StringHeaders.Where(h => h.IsProtected).ToList().Count();

    /// <summary>
    /// Count of unprotected headers.
    /// </summary>
    public int UnProtectedHeadersCount => IntHeaders.Where(h => !h.IsProtected).ToList().Count() + StringHeaders.Where(h => !h.IsProtected).ToList().Count();

    /// <summary>
    /// A private constructor.
    /// </summary>
    private CoseHeaderFactory()
    {
        IntHeaders = new();
        StringHeaders = new();
    }

    /// <summary>
    /// Returns the singleton instance of the factory class.
    /// </summary>
    /// <returns>The singleton instance of the factory class.</returns>
    public static CoseHeaderFactory Instance()
    {
        if (SingletonInstance == null)
        {
            SingletonInstance = new();
        }

        return SingletonInstance;
    }

    /// <summary>
    /// A helper method to add headers to the internal header collection.
    /// </summary>
    /// <typeparam name="TypeV">Data type of the header value.</typeparam>
    /// <param name="headers">A collection of user supplied headers.</param>
    /// <param name="isProtected">A flag to indicate if the collection is protected.</param>
    /// <exception cref="ArgumentException">A non-empty string header value is expected.</exception>
    private void AddHeadersInternal<TypeV>(IEnumerable<CoseHeader<TypeV>> headers, bool isProtected)
    {
        switch (typeof(TypeV))
        {
            case var x when x == typeof(int):
                headers.ToList().ForEach(h =>
                {
                    // We do not validate the supplied value as it is strongly typed to int.
                    // Caller is responsible for validations.
                    IntHeaders.Add(new CoseHeader<int>(h.Label, Convert.ToInt32(h.Value), isProtected));
                });

                break;
            case var x when x == typeof(string):
                headers.ToList().ForEach(h =>
                {
                    // We do not allow null or empty string as a string value although the caller might.
                    if (!CoseHeader<string>.IsValid((value) => { return !string.IsNullOrEmpty(value); }, h.Value.ToString()))
                    {
                        throw new ArgumentException($"A non-empty string value must be supplied for the header '{h.Label}'");
                    }

                    StringHeaders.Add(new CoseHeader<string>(h.Label, h.Value.ToString(), isProtected));
                });

                break;
            default:
                throw new NotImplementedException($"A header value of type {typeof(TypeV)} is unsupported");
        }
    }

    /// <summary>
    /// A wrapper method to facilitate the addition of protected headers to the internal collection.
    /// </summary>
    /// <typeparam name="TypeV">The data type of the header value.</typeparam>
    /// <param name="headers">A collection containing the protected headers.</param>
    public void AddProtectedHeaders<TypeV>(IEnumerable<CoseHeader<TypeV>> headers)
    {
        if(headers == null)
        {
            throw new ArgumentNullException("Protected headers cannot be null");
        }

        AddHeadersInternal<TypeV>(headers, true);
    }
    /// <summary>
    /// A wrapper method to facilitate the addition of unprotected headers to the internal collection. 
    /// </summary>
    /// <typeparam name="TypeV">The data type of the header value.</typeparam>
    /// <param name="headers">A collection containing the unprotected headers.</param>
    public void AddUnProtectedHeaders<TypeV>(IEnumerable<CoseHeader<TypeV>> headers)
    {
        if (headers == null)
        {
            throw new ArgumentNullException("UnProtected headers cannot be null");
        }

        AddHeadersInternal<TypeV>(headers, false);
    }

    /// <summary>
    /// Add the protected headers to the supplied header map. 
    /// </summary>
    /// <param name="protectedHeaders">The user-supplied protected headers will be added to this map.</param>
    public void ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        if (protectedHeaders == null)
        {
            return;
        }

        IntHeaders.Where(h => h.IsProtected).ToList().ForEach(h => protectedHeaders.Add(new CoseHeaderLabel(h.Label), h.Value));
        StringHeaders.Where(h => h.IsProtected).ToList().ForEach(h => protectedHeaders.Add(new CoseHeaderLabel(h.Label), h.Value));
    }

    /// <summary>
    /// Add the unprotected headers to the supplied header map.
    /// </summary>
    /// <param name="protectedHeaders">The user-supplied unprotected headers will be added to this map.</param>
    public void ExtendUnProtectedHeaders(CoseHeaderMap unProtectedHeaders)
    {
        if (unProtectedHeaders == null)
        {
            return;
        }

        IntHeaders.Where(h => !h.IsProtected).ToList().ForEach(h => unProtectedHeaders.Add(new CoseHeaderLabel(h.Label), h.Value));
        StringHeaders.Where(h => !h.IsProtected).ToList().ForEach(h => unProtectedHeaders.Add(new CoseHeaderLabel(h.Label), h.Value));
    }

    /// <summary>
    /// Dispose.
    /// </summary>
    public void Dispose()
    {
        IntHeaders.Clear();
        StringHeaders.Clear();
    }
}

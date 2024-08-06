// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

public class CertificateStoreHelperTests
{
    private const string DefaultStoreName = "My";
    private const StoreLocation DefaultStoreLocation = StoreLocation.CurrentUser;
    static List<X509Certificate2>? StoreCertSet;

    public CertificateStoreHelperTests()
    {
        using var certStore = new X509Store(DefaultStoreName, DefaultStoreLocation);
        certStore.Open(OpenFlags.ReadOnly);
        StoreCertSet = certStore.Certificates.Take(5).ToList();
        StoreCertSet.Should().NotBeEmpty();
    }

    [TestMethod]
    public void GetCertByThumbprint()
    {
        var storeCert = StoreCertSet?.First() ?? throw new ArgumentNullException();
        var foundCert = CoseHandler.LookupCertificate(storeCert.Thumbprint);
        foundCert.Should().Be(storeCert);
    }
}

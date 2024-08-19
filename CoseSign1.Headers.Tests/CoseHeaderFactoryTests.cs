// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests;

using System;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers.Local;

public class Tests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void AddHeadersCountTest()
    {
        using CoseHeaderFactory factory = CoseHeaderFactory.Instance();
        List<CoseHeader<int>> intProtectedHeaders = new();
        List<CoseHeader<string>> stringProtectedHeaders = new();

        List<CoseHeader<int>> intUnProtectedHeaders = new();

        // Add protected headers
        intProtectedHeaders.Add(new CoseHeader<int>("header1", 1000, true));
        intProtectedHeaders.Add(new CoseHeader<int>("header2", 87234, true));

        stringProtectedHeaders.Add(new CoseHeader<string>("header3", "value1", true));

        // Add unprotected headers
        intUnProtectedHeaders.Add(new CoseHeader<int>("header4", 100, false));

        // Add the headers to the factory
        factory.AddProtectedHeaders<int>(intProtectedHeaders);
        factory.AddProtectedHeaders<string>(stringProtectedHeaders);
        factory.AddUnProtectedHeaders(intUnProtectedHeaders);

        int expectedProtectedHeaderCount = 3;
        int expectedUnProtectedHeaderCount = 1;

        Assert.That(factory.ProtectedHeadersCount, Is.EqualTo(expectedProtectedHeaderCount));
        Assert.That(factory.UnProtectedHeadersCount, Is.EqualTo(expectedUnProtectedHeaderCount));
    }

    [Test]
    public void AddHeadersTest()
    {
        using CoseHeaderFactory factory = CoseHeaderFactory.Instance();

        CoseHeaderMap coseProtectedHeaders = new();
        coseProtectedHeaders.Add(new CoseHeaderLabel("Label1"), 32);
        factory.ExtendProtectedHeaders(coseProtectedHeaders);

        CoseHeaderMap coseUnProtectedHeaders = new();
        coseUnProtectedHeaders.Add(new CoseHeaderLabel("Label2"), "value1");
        factory.ExtendUnProtectedHeaders(coseUnProtectedHeaders);

        List<CoseHeader<string>> stringProtectedHeaders = new();
        List<CoseHeader<int>> intUnProtectedHeaders = new();

        stringProtectedHeaders.Add(new CoseHeader<string>("Label3", "value2", true));

        intUnProtectedHeaders.Add(new CoseHeader<int>("Label4", 45, false));
        intUnProtectedHeaders.Add(new CoseHeader<int>("Label5", 132, false));

        factory.AddProtectedHeaders(stringProtectedHeaders);
        factory.AddUnProtectedHeaders(intUnProtectedHeaders);

        factory.ExtendProtectedHeaders(coseProtectedHeaders);
        factory.ExtendUnProtectedHeaders(coseUnProtectedHeaders);

        Assert.That(coseProtectedHeaders.Count, Is.EqualTo(2));
        Assert.That(coseUnProtectedHeaders.Count, Is.EqualTo(3));
    }

    [Test]
    public void AddEmptyStringValueThrowsExceptionTest()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            List<CoseHeader<string>> stringProtectedHeaders = new();
            stringProtectedHeaders.Add(new CoseHeader<string>("header3", "", true));

            CoseHeaderFactory.Instance().AddProtectedHeaders<string>(stringProtectedHeaders);
            CoseHeaderFactory.Instance().Dispose();
        },
        "A non-empty string value must be supplied for the header 'header3'");
    }

    [Test]
    public void AddNullHeadersThrowsExceptionTest()
    {
        Assert.Throws<ArgumentNullException>(() => { CoseHeaderFactory.Instance().AddProtectedHeaders<int>(null); CoseHeaderFactory.Instance().Dispose(); }, "Protected headers cannot be null");
        Assert.Throws<ArgumentNullException>(() => { CoseHeaderFactory.Instance().AddUnProtectedHeaders<int>(null); CoseHeaderFactory.Instance().Dispose(); }, "unProtected headers cannot be null");
    }

    [Test]
    public void AddUnsupportedValueTypeTest()
    {
        Assert.Throws<NotImplementedException>(() =>
            {
                CoseHeaderFactory.Instance().AddProtectedHeaders<long>(new List<CoseHeader<long>> { new ("key1", 100, true) });
                CoseHeaderFactory.Instance().Dispose();
            },
            $"A header value of type {typeof(long)} is unsupported");
    }
}
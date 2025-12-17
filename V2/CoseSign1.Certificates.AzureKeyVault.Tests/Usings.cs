// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

global using System;
global using System.Security.Cryptography;
global using System.Security.Cryptography.X509Certificates;
global using System.Threading;
global using System.Threading.Tasks;
global using Azure;
global using Azure.Core;
global using Azure.Security.KeyVault.Certificates;
global using Azure.Security.KeyVault.Keys;
global using Azure.Security.KeyVault.Keys.Cryptography;
global using Azure.Security.KeyVault.Secrets;
global using CoseSign1.AzureKeyVault.Common;
global using CoseSign1.Certificates.AzureKeyVault;
global using CoseSign1.Tests.Common;
global using Moq;
global using NUnit.Framework;

// Model factories for creating mock responses
global using CertificateModelFactory = Azure.Security.KeyVault.Certificates.CertificateModelFactory;
global using KeyModelFactory = Azure.Security.KeyVault.Keys.KeyModelFactory;
global using SecretModelFactory = Azure.Security.KeyVault.Secrets.SecretModelFactory;

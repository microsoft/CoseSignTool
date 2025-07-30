// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

global using System.Security.Cryptography;
global using System.Security.Cryptography.Cose;
global using System.Security.Cryptography.X509Certificates;
global using System.Text;
global using System.Text.Json;
global using CoseIndirectSignature;
global using CoseIndirectSignature.Extensions;
global using CoseSign1;
global using CoseSign1.Certificates;
global using CoseSign1.Certificates.Extensions;
global using CoseSign1.Certificates.Local;
global using CoseSign1.Tests.Common;
global using CoseSignTool.Abstractions;
global using CoseSignTool.IndirectSignature.Plugin;
global using CoseX509;
global using Microsoft.Extensions.Configuration;
global using Microsoft.VisualStudio.TestTools.UnitTesting;

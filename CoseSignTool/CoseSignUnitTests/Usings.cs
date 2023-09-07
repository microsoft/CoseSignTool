// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

global using System.Formats.Cbor;
global using System.Security.Cryptography;
global using System.Security.Cryptography.Cose;
global using System.Security.Cryptography.X509Certificates;
global using System.Text;
global using CoseSign1;
global using CoseSign1.Abstractions;
global using CoseSign1.Abstractions.Exceptions;
global using CoseSign1.Abstractions.Interfaces;
global using CoseSign1.Certificates;
global using CoseSign1.Certificates.Exceptions;
global using CoseSign1.Certificates.Extensions;
global using CoseSign1.Certificates.Interfaces;
global using CoseSign1.Certificates.Local;
global using CoseSign1.Certificates.Local.Validators;
global using CoseSign1.Tests.Common;
global using CoseX509;
global using FluentAssertions;
global using Microsoft.VisualStudio.TestTools.UnitTesting;
global using Moq;

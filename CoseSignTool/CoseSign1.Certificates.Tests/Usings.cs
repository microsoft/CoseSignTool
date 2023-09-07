// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

global using System;
global using System.Collections.Generic;
global using System.Linq;
global using System.Security.Cryptography;
global using System.Security.Cryptography.Cose;
global using System.Security.Cryptography.X509Certificates;
global using System.Text;
global using CoseSign1.Abstractions;
global using CoseSign1.Abstractions.Interfaces;
global using CoseSign1.Certificates.Exceptions;
global using CoseSign1.Certificates.Interfaces;
global using CoseSign1.Certificates.Local;
global using CoseSign1.Certificates.Local.Validators;
global using CoseSign1.Interfaces;
global using CoseSign1.Tests.Common;
global using FluentAssertions;
global using Moq;
global using Moq.Protected;
global using NUnit.Framework;


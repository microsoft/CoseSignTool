// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

global using System;
global using System.Buffers;
global using System.Collections.Generic;
global using System.Collections.Specialized;
global using System.ComponentModel;
global using System.Diagnostics.CodeAnalysis;
global using System.IO;
global using System.Linq;
global using System.Security.Cryptography;
global using System.Security.Cryptography.X509Certificates;
global using System.Text.RegularExpressions;
global using CoseSign1;
global using CoseSign1.Certificates.Exceptions;
global using CoseSign1.Certificates.Extensions;
global using CoseSign1.Extensions;
global using CoseSign1.Headers;
global using CoseSign1.Headers.Local;
global using CoseSignTool.Local;
global using CoseX509;
global using Microsoft.Extensions.Configuration.CommandLine;
global using Newtonsoft.Json;



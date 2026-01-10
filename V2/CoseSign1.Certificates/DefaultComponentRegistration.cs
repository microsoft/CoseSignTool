// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.Abstractions;

[assembly: DefaultValidationComponentProvider(typeof(CertificateDefaultComponentProvider))]

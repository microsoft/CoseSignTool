// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation.Abstractions;

[assembly: DefaultValidationComponentProvider(typeof(AkvDefaultComponentProvider))]

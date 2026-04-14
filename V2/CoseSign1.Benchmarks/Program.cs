// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using BenchmarkDotNet.Running;

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This file is automatically included in all test projects via Directory.Build.props.
// It configures NUnit for parallel test execution at the fixture level.

using NUnit.Framework;

// Enable parallel test execution at the fixture (class) level.
// Tests within a class run sequentially, but different test classes run in parallel.
[assembly: Parallelizable(ParallelScope.Fixtures)]

// The number of parallel workers is controlled by coverage.runsettings:
//   <NumberOfTestWorkers>0</NumberOfTestWorkers> means "use processor count"
// This allows the parallelism level to automatically scale to the machine's CPU count.

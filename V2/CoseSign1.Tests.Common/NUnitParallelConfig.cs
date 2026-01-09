// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * This file is automatically included in all test projects via Directory.Build.props.
 * It configures NUnit for parallel test execution at all levels.
 */

/*
 * Enable parallel test execution at the all levels.
 * Tests within a class run sequentially, but different test classes run in parallel.
 */
[assembly: NUnit.Framework.Parallelizable(NUnit.Framework.ParallelScope.All)]

/*
 * The number of parallel workers is controlled by coverage.runsettings:
 *   NumberOfTestWorkers=0 means "use processor count"
 * This allows the parallelism level to automatically scale to the machine's CPU count.
 */

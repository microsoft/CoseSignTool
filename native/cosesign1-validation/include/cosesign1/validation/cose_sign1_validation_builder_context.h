// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

namespace cosesign1::validation {

/**
 * @file cose_sign1_validation_builder_context.h
 * @brief Configuration options that affect how a validation pipeline is executed.
 */
struct CoseSign1ValidationBuilderContext {
  /**
   * @brief When true, stops evaluation as soon as a failure is produced.
   *
   * When false, all eligible validators are run and failures are aggregated.
   */
  bool stop_on_first_failure = false;

  /**
   * @brief When true, non-"last" validators are evaluated concurrently.
   *
   * Validators that implement ILastCoseSign1Validator are never run in parallel with
   * other validators, and only run if all other validators pass.
   */
  bool run_in_parallel = false;
};

} // namespace cosesign1::validation

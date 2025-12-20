#pragma once

namespace cosesign1::internal {

// These are intentionally small hooks that exist solely so that certain
// header-defined validation types are instantiated/executed inside the
// cosesign1_signature module (not just in the test executable), allowing
// OpenCppCoverage to attribute those lines to the library.
void RunCoverageHooks_ValidationHeaders();

} // namespace cosesign1::internal

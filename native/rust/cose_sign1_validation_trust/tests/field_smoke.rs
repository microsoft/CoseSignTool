// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::field::Field;

#[derive(Debug)]
struct DummyFact;

#[test]
fn field_name_is_stable_and_copyable() {
    // Avoid `const` evaluation so coverage tools can observe execution.
    let ctor_bool: fn(&'static str) -> Field<DummyFact, bool> = Field::new;
    let ctor_i64: fn(&'static str) -> Field<DummyFact, i64> = Field::new;

    let f_bool = ctor_bool("present");
    let f_i64 = ctor_i64("count");

    let name: fn(&Field<DummyFact, bool>) -> &'static str = Field::name;
    assert_eq!(name(&f_bool), "present");
    assert_eq!(f_i64.name(), "count");

    let copied = f_bool;
    assert_eq!(copied.name(), "present");
}

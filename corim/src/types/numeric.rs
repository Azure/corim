// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Domain-neutral numeric ordering for CBOR integers and IEEE 754 values.

use core::cmp::Ordering;

pub(crate) fn compare_integer_float(integer: i128, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    let bound = 18_446_744_073_709_551_616.0_f64;
    if float >= bound {
        return Some(Ordering::Less);
    }
    if float < -bound {
        return Some(Ordering::Greater);
    }
    // The remaining finite range is within i128; fractions are compared below.
    let truncated = float as i128;
    match integer.cmp(&truncated) {
        Ordering::Equal => (truncated as f64).partial_cmp(&float),
        ordering => Some(ordering),
    }
}

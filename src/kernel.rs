use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kernel {
    Scalar,
    Avx2,
}

impl Kernel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Avx2 => "avx2",
        }
    }
}

pub fn avx2_available() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

pub fn best_kernel() -> Kernel {
    if avx2_available() {
        Kernel::Avx2
    } else {
        Kernel::Scalar
    }
}

pub fn find_exact_4(haystack: &[u8], needle: [u8; 4], stride: usize, out: &mut Vec<usize>) {
    match best_kernel() {
        Kernel::Avx2 if stride == 4 => {
            unsafe { find_exact_4_avx2(haystack, needle, out) };
        }
        _ => find_exact_4_scalar(haystack, needle, stride, out),
    }
}

pub fn find_exact_8(haystack: &[u8], needle: [u8; 8], stride: usize, out: &mut Vec<usize>) {
    match best_kernel() {
        Kernel::Avx2 if stride == 8 => {
            unsafe { find_exact_8_avx2(haystack, needle, out) };
        }
        _ => find_exact_8_scalar(haystack, needle, stride, out),
    }
}

pub fn find_exact_4_with(
    kernel: Kernel,
    haystack: &[u8],
    needle: [u8; 4],
    stride: usize,
    out: &mut Vec<usize>,
) {
    match kernel {
        Kernel::Avx2 if stride == 4 && avx2_available() => {
            unsafe { find_exact_4_avx2(haystack, needle, out) };
        }
        _ => find_exact_4_scalar(haystack, needle, stride, out),
    }
}

pub fn find_exact_8_with(
    kernel: Kernel,
    haystack: &[u8],
    needle: [u8; 8],
    stride: usize,
    out: &mut Vec<usize>,
) {
    match kernel {
        Kernel::Avx2 if stride == 8 && avx2_available() => {
            unsafe { find_exact_8_avx2(haystack, needle, out) };
        }
        _ => find_exact_8_scalar(haystack, needle, stride, out),
    }
}

pub fn find_exact_4_scalar(haystack: &[u8], needle: [u8; 4], stride: usize, out: &mut Vec<usize>) {
    let stride = stride.max(1);
    let mut offset = 0usize;
    while offset + 4 <= haystack.len() {
        if haystack[offset..offset + 4] == needle {
            out.push(offset);
        }
        offset += stride;
    }
}

pub fn find_exact_8_scalar(haystack: &[u8], needle: [u8; 8], stride: usize, out: &mut Vec<usize>) {
    let stride = stride.max(1);
    let mut offset = 0usize;
    while offset + 8 <= haystack.len() {
        if haystack[offset..offset + 8] == needle {
            out.push(offset);
        }
        offset += stride;
    }
}

#[target_feature(enable = "avx2")]
unsafe fn find_exact_4_avx2(haystack: &[u8], needle: [u8; 4], out: &mut Vec<usize>) {
    use std::arch::x86_64::{
        _mm256_castsi256_ps, _mm256_cmpeq_epi32, _mm256_loadu_si256, _mm256_movemask_ps,
        _mm256_set1_epi32,
    };

    let target = i32::from_le_bytes(needle);
    let lanes = 8usize;
    let step = lanes * 4;
    let aligned_end = (haystack.len() / step) * step;

    let wanted = _mm256_set1_epi32(target);
    let mut offset = 0usize;
    while offset < aligned_end {
        let block = unsafe { _mm256_loadu_si256(haystack.as_ptr().add(offset).cast()) };
        let equal = _mm256_cmpeq_epi32(block, wanted);
        let mask = _mm256_movemask_ps(_mm256_castsi256_ps(equal));
        if mask != 0 {
            let mut bits = mask as u32;
            while bits != 0 {
                let lane = bits.trailing_zeros() as usize;
                out.push(offset + lane * 4);
                bits &= bits - 1;
            }
        }
        offset += step;
    }
    let tail_base = offset;
    let mut tail = Vec::new();
    find_exact_4_scalar(&haystack[tail_base..], needle, 4, &mut tail);
    for found in tail {
        out.push(tail_base + found);
    }
}

#[target_feature(enable = "avx2")]
unsafe fn find_exact_8_avx2(haystack: &[u8], needle: [u8; 8], out: &mut Vec<usize>) {
    use std::arch::x86_64::{
        _mm256_castsi256_pd, _mm256_cmpeq_epi64, _mm256_loadu_si256, _mm256_movemask_pd,
        _mm256_set1_epi64x,
    };

    let target = i64::from_le_bytes(needle);
    let lanes = 4usize;
    let step = lanes * 8;
    let aligned_end = (haystack.len() / step) * step;

    let wanted = _mm256_set1_epi64x(target);
    let mut offset = 0usize;
    while offset < aligned_end {
        let block = unsafe { _mm256_loadu_si256(haystack.as_ptr().add(offset).cast()) };
        let equal = _mm256_cmpeq_epi64(block, wanted);
        let mask = _mm256_movemask_pd(_mm256_castsi256_pd(equal));
        if mask != 0 {
            let mut bits = mask as u32;
            while bits != 0 {
                let lane = bits.trailing_zeros() as usize;
                out.push(offset + lane * 8);
                bits &= bits - 1;
            }
        }
        offset += step;
    }
    let tail_base = offset;
    let mut tail = Vec::new();
    find_exact_8_scalar(&haystack[tail_base..], needle, 8, &mut tail);
    for found in tail {
        out.push(tail_base + found);
    }
}

pub fn find_bytes(haystack: &[u8], needle: &[u8], stride: usize, out: &mut Vec<usize>) {
    if needle.is_empty() || needle.len() > haystack.len() {
        return;
    }
    let stride = stride.max(1);
    if stride == 1 {
        for found in memchr::memmem::find_iter(haystack, needle) {
            out.push(found);
        }
        return;
    }
    for found in memchr::memmem::find_iter(haystack, needle) {
        if found.is_multiple_of(stride) {
            out.push(found);
        }
    }
}

pub fn find_pattern(
    haystack: &[u8],
    bytes: &[u8],
    mask: &[bool],
    stride: usize,
    out: &mut Vec<usize>,
) {
    if bytes.is_empty() || bytes.len() != mask.len() || bytes.len() > haystack.len() {
        return;
    }
    let stride = stride.max(1);
    let Some(anchor) = mask.iter().position(|m| *m) else {
        return;
    };
    let anchor_byte = bytes[anchor];
    let limit = haystack.len() - bytes.len();

    for hit in memchr::memchr_iter(anchor_byte, haystack) {
        if hit < anchor {
            continue;
        }
        let start = hit - anchor;
        if start > limit || !start.is_multiple_of(stride) {
            continue;
        }
        let window = &haystack[start..start + bytes.len()];
        if window
            .iter()
            .zip(bytes.iter().zip(mask.iter()))
            .all(|(actual, (wanted, must))| !*must || actual == wanted)
        {
            out.push(start);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn haystack_with(values: &[i32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn this_host_reports_its_avx2_support_consistently() {
        let detected = avx2_available();
        assert_eq!(
            best_kernel(),
            if detected {
                Kernel::Avx2
            } else {
                Kernel::Scalar
            }
        );
        assert_eq!(Kernel::Scalar.as_str(), "scalar");
        assert_eq!(Kernel::Avx2.as_str(), "avx2");
    }

    #[test]
    fn the_scalar_and_simd_kernels_agree_on_every_four_byte_match() {
        let mut values: Vec<i32> = (0..1000).map(|i| i % 97).collect();
        values[0] = 42;
        values[13] = 42;
        values[499] = 42;
        values[999] = 42;
        let haystack = haystack_with(&values);
        let needle = 42i32.to_le_bytes();

        let mut scalar = Vec::new();
        find_exact_4_with(Kernel::Scalar, &haystack, needle, 4, &mut scalar);
        let mut simd = Vec::new();
        find_exact_4_with(Kernel::Avx2, &haystack, needle, 4, &mut simd);
        simd.sort_unstable();
        simd.dedup();

        assert!(scalar.contains(&0));
        assert!(scalar.contains(&(13 * 4)));
        assert!(scalar.contains(&(999 * 4)));
        assert_eq!(
            scalar, simd,
            "the SIMD kernel must find exactly what the scalar kernel finds"
        );
    }

    #[test]
    fn the_scalar_and_simd_kernels_agree_on_every_eight_byte_match() {
        let values: Vec<i64> = (0..500).map(|i| if i % 71 == 0 { -7 } else { i }).collect();
        let haystack: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        let needle = (-7i64).to_le_bytes();

        let mut scalar = Vec::new();
        find_exact_8_with(Kernel::Scalar, &haystack, needle, 8, &mut scalar);
        let mut simd = Vec::new();
        find_exact_8_with(Kernel::Avx2, &haystack, needle, 8, &mut simd);
        simd.sort_unstable();
        simd.dedup();
        assert!(!scalar.is_empty());
        assert_eq!(scalar, simd);
    }

    #[test]
    fn the_kernels_agree_on_a_haystack_that_is_not_a_whole_number_of_vectors() {
        let needle = 5i32.to_le_bytes();
        for extra in 0..12usize {
            let mut values: Vec<i32> = (0..(64 + extra as i32)).map(|i| i % 11).collect();
            if let Some(last) = values.last_mut() {
                *last = 5;
            }
            let haystack = haystack_with(&values);
            let mut scalar = Vec::new();
            find_exact_4_with(Kernel::Scalar, &haystack, needle, 4, &mut scalar);
            let mut simd = Vec::new();
            find_exact_4_with(Kernel::Avx2, &haystack, needle, 4, &mut simd);
            simd.sort_unstable();
            simd.dedup();
            assert_eq!(scalar, simd, "mismatch with {extra} trailing values");
        }
    }

    #[test]
    fn an_unaligned_stride_falls_back_to_the_scalar_path_and_still_finds_matches() {
        let haystack = haystack_with(&[0, 42, 0, 42]);
        let needle = 42i32.to_le_bytes();
        let mut found = Vec::new();
        find_exact_4(&haystack, needle, 1, &mut found);
        assert_eq!(found, vec![4, 12]);

        let mut strided = Vec::new();
        find_exact_4(&haystack, needle, 8, &mut strided);
        assert_eq!(
            strided,
            Vec::<usize>::new(),
            "stepping by 8 only examines offsets 0 and 8; the matches sit at 4 and 12"
        );
    }

    #[test]
    fn byte_search_uses_the_optimised_substring_path_and_respects_stride() {
        let haystack = b"xxabcxxabc".to_vec();
        let mut all = Vec::new();
        find_bytes(&haystack, b"abc", 1, &mut all);
        assert_eq!(all, vec![2, 7]);

        let mut aligned = Vec::new();
        find_bytes(&haystack, b"abc", 2, &mut aligned);
        assert_eq!(aligned, vec![2], "offset 7 is not a multiple of 2");

        let mut nothing = Vec::new();
        find_bytes(&haystack, b"", 1, &mut nothing);
        assert!(nothing.is_empty());
    }

    #[test]
    fn a_wildcard_pattern_anchors_on_its_first_concrete_byte() {
        let haystack = vec![0x00, 0xcd, 0xff, 0x3d, 0xcd, 0x11, 0x3e, 0xcd, 0x99, 0x3d];
        let bytes = [0xcd, 0x00, 0x3d];
        let mask = [true, false, true];
        let mut found = Vec::new();
        find_pattern(&haystack, &bytes, &mask, 1, &mut found);
        assert_eq!(found, vec![1, 7]);
    }

    #[test]
    fn a_pattern_whose_anchor_is_not_the_first_byte_still_matches() {
        let haystack = vec![0x11, 0x22, 0xab, 0x33, 0x44, 0xab];
        let bytes = [0x00, 0x00, 0xab];
        let mask = [false, false, true];
        let mut found = Vec::new();
        find_pattern(&haystack, &bytes, &mask, 1, &mut found);
        assert_eq!(found, vec![0, 3]);
    }

    #[test]
    fn a_pattern_longer_than_the_haystack_finds_nothing_instead_of_panicking() {
        let mut found = Vec::new();
        find_pattern(&[1, 2], &[1, 2, 3], &[true, true, true], 1, &mut found);
        assert!(found.is_empty());
        find_bytes(&[1, 2], &[1, 2, 3], 1, &mut found);
        assert!(found.is_empty());
    }
}

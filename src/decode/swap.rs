//! Big-endian → native-endian batch byte-swap primitives.
//!
//! Each `swap_uXX_run` reads `count = src.len() / W` big-endian-on-wire
//! integers from `src` and writes their native-endian representation to
//! `dst`. `dst.len()` must equal `src.len()`. `src.len()` must be a
//! multiple of the element width.
//!
//! # SIMD policy
//!
//! These primitives are written as tight scalar loops over
//! `u{16,32,64,128}::from_be_bytes(...).to_ne_bytes()`. On modern
//! compilers and modern targets these auto-vectorize to the same
//! instructions hand-written intrinsics would emit:
//!
//! - **aarch64** — `vrev{32,64}q_u8` over 16-byte chunks (NEON is part of
//!   the `AArch64` baseline, so this is unconditional).
//! - **`x86_64`** — `pshufb` over 16-byte chunks when SSSE3 is enabled at
//!   build time (e.g. `RUSTFLAGS="-C target-cpu=native"`).
//!
//! An earlier revision of this file carried explicit `unsafe` NEON and
//! SSSE3 intrinsics. Per `CLAUDE.md` ("Coding conventions" → unsafe), we
//! removed them after the criterion bench in `benches/decode_into.rs`
//! showed the hand-rolled paths matched but did not beat the
//! auto-vectorized scalar code. The path back to explicit intrinsics is
//! short if a future workload justifies it, but it must be re-justified
//! by the bench.

#[inline]
pub(super) fn swap_u16_run(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), dst.len());
    debug_assert_eq!(src.len() % 2, 0);
    for (s, d) in src.chunks_exact(2).zip(dst.chunks_exact_mut(2)) {
        let v = u16::from_be_bytes([s[0], s[1]]);
        d.copy_from_slice(&v.to_ne_bytes());
    }
}

#[inline]
pub(super) fn swap_u32_run(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), dst.len());
    debug_assert_eq!(src.len() % 4, 0);
    for (s, d) in src.chunks_exact(4).zip(dst.chunks_exact_mut(4)) {
        let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
        d.copy_from_slice(&v.to_ne_bytes());
    }
}

#[inline]
pub(super) fn swap_u64_run(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), dst.len());
    debug_assert_eq!(src.len() % 8, 0);
    for (s, d) in src.chunks_exact(8).zip(dst.chunks_exact_mut(8)) {
        let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
        d.copy_from_slice(&v.to_ne_bytes());
    }
}

#[inline]
pub(super) fn swap_u128_run(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), dst.len());
    debug_assert_eq!(src.len() % 16, 0);
    for (s, d) in src.chunks_exact(16).zip(dst.chunks_exact_mut(16)) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(s);
        let v = u128::from_be_bytes(buf);
        d.copy_from_slice(&v.to_ne_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{swap_u128_run, swap_u16_run, swap_u32_run, swap_u64_run};

    fn assert_swap_round_trip<F>(elem_bytes: usize, swap: F)
    where
        F: Fn(&[u8], &mut [u8]),
    {
        for n in 1..=10usize {
            let len = n * elem_bytes;
            let src: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i & 0xff).unwrap_or(0))
                .collect();
            let mut dst = vec![0u8; len];
            swap(&src, &mut dst);
            for chunk in 0..n {
                let s = &src[chunk * elem_bytes..(chunk + 1) * elem_bytes];
                let d = &dst[chunk * elem_bytes..(chunk + 1) * elem_bytes];
                let mut expected: Vec<u8> = s.to_vec();
                expected.reverse();
                // Native-endian compare: on big-endian targets `to_ne_bytes`
                // would equal `to_be_bytes`. We don't gate on cfg here; the
                // test is run on aarch64/x86_64 hosts which are LE.
                #[cfg(target_endian = "little")]
                assert_eq!(d, expected.as_slice(), "n={n}");
                #[cfg(target_endian = "big")]
                assert_eq!(d, s, "n={n}");
            }
        }
    }

    #[test]
    fn u16_round_trip() {
        assert_swap_round_trip(2, swap_u16_run);
    }

    #[test]
    fn u32_round_trip() {
        assert_swap_round_trip(4, swap_u32_run);
    }

    #[test]
    fn u64_round_trip() {
        assert_swap_round_trip(8, swap_u64_run);
    }

    #[test]
    fn u128_round_trip() {
        assert_swap_round_trip(16, swap_u128_run);
    }
}

use crate::uplc::hamming::util;

fn naive(x: &[u8], y: &[u8]) -> u64 {
    assert_eq!(x.len(), y.len());
    x.iter()
        .zip(y)
        .fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64)
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Clone)]
pub struct DistanceError {
    _x: (),
}

/// Computes the bitwise [Hamming
/// distance](https://en.wikipedia.org/wiki/Hamming_distance) between
/// `x` and `y`, that is, the number of bits where `x` and `y` differ,
/// or, the number of set bits in the xor of `x` and `y`.
///
/// This is a highly optimised version of the following naive version:
///
/// ```rust
/// fn naive(x: &[u8], y: &[u8]) -> u64 {
///     x.iter().zip(y).fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64)
/// }
/// ```
///
/// This function requires that `x` and `y` have the same 8-byte
/// alignment. If not, `Err` is returned. If sub-optimal performance
/// can be tolerated, consider using `distance` which incorporates a
/// fallback to a slower but less restrictive algorithm.
///
/// It is essentially guaranteed that `x` and `y` will have the same
/// 8-byte alignment if they are both just `Vec<u8>`s of non-trivial
/// length (e.g. larger than 8) as in the example below.
///
/// This is implemented using the same tree-merging approach as
/// `weight`, see there for details.
///
/// # Panics
///
/// `x` and `y` must have the same length, or else `distance_fast` panics.
///
/// # Performance Comparison
///
/// | length | `naive` (ns) | `distance_fast` (ns) | `naive`/`distance_fast` |
/// |--:|--:|--:|--:|
/// | 1 | 5  | 6  | 0.83 |
/// | 10 | 44  | 45  | 0.97 |
/// | 100 | 461  | 473  | 0.97 |
/// | 1,000 | 4,510  | 397  | 11 |
/// | 10,000 | 46,700  | 2,740  | 17 |
/// | 100,000 | 45,600  | 20,400  | 22 |
/// | 1,000,000 | 4,590,000  | 196,000  | 23 |
///
/// # Examples
///
/// ```rust
/// let x = vec![0xFF; 1000];
/// let y = vec![0; 1000];
/// assert_eq!(hamming::distance_fast(&x, &y), Ok(8 * 1000));
///
/// // same alignment, but moderately complicated
/// assert_eq!(hamming::distance_fast(&x[1..1000 - 8], &y[8 + 1..]), Ok(8 * (1000 - 8 - 1)));
///
/// // differing alignments
/// assert!(hamming::distance_fast(&x[1..], &y[..999]).is_err());
/// ```
pub fn distance_fast(x: &[u8], y: &[u8]) -> Result<u64, DistanceError> {
    assert_eq!(x.len(), y.len());

    const M1: u64 = 0x5555555555555555;
    const M2: u64 = 0x3333333333333333;
    const M4: u64 = 0x0F0F0F0F0F0F0F0F;
    const M8: u64 = 0x00FF00FF00FF00FF;

    type T30 = [u64; 30];

    // can't fit a single T30 in
    let (head1, thirty1, tail1) = unsafe { util::align_to::<_, T30>(x) };
    let (head2, thirty2, tail2) = unsafe { util::align_to::<_, T30>(y) };

    if head1.len() != head2.len() {
        // The arrays required different shift amounts, so we can't
        // use aligned loads for both slices.
        return Err(DistanceError { _x: () });
    }

    debug_assert_eq!(thirty1.len(), thirty2.len());

    let mut count = naive(head1, head2) + naive(tail1, tail2);
    for (array1, array2) in thirty1.iter().zip(thirty2) {
        let mut acc = 0;
        for j_ in 0..10 {
            let j = j_ * 3;
            let mut count1 = array1[j] ^ array2[j];
            let mut count2 = array1[j + 1] ^ array2[j + 1];
            let mut half1 = array1[j + 2] ^ array2[j + 2];
            let mut half2 = half1;
            half1 &= M1;
            half2 = (half2 >> 1) & M1;
            count1 -= (count1 >> 1) & M1;
            count2 -= (count2 >> 1) & M1;
            count1 += half1;
            count2 += half2;
            count1 = (count1 & M2) + ((count1 >> 2) & M2);
            count1 += (count2 & M2) + ((count2 >> 2) & M2);
            acc += (count1 & M4) + ((count1 >> 4) & M4);
        }
        acc = (acc & M8) + ((acc >> 8) & M8);
        acc = acc + (acc >> 16);
        acc = acc + (acc >> 32);
        count += acc & 0xFFFF;
    }
    Ok(count)
}

/// Computes the bitwise [Hamming
/// distance](https://en.wikipedia.org/wiki/Hamming_distance) between
/// `x` and `y`, that is, the number of bits where `x` and `y` differ,
/// or, the number of set bits in the xor of `x` and `y`.
///
/// When `x` and `y` have the same 8-byte alignment, this uses
/// `distance_fast`, a highly optimised version of the following naive
/// version:
///
/// ```rust
/// fn naive(x: &[u8], y: &[u8]) -> u64 {
///     x.iter().zip(y).fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64)
/// }
/// ```
///
/// If alignments differ, a slower but less restrictive algorithm is
/// used.
///
/// It is essentially guaranteed that `x` and `y` will have the same
/// 8-byte alignment if they are both just `Vec<u8>`s of non-trivial
/// length (e.g. larger than 8) as in the example below.
///
/// # Panics
///
/// `x` and `y` must have the same length, or else `distance` panics.
///
/// # Performance Comparison
///
/// | length | `naive` (ns) | `distance` (ns) | `naive`/`distance` |
/// |--:|--:|--:|--:|
/// | 1 | 5  | 6  | 0.83 |
/// | 10 | 44  | 45  | 0.97 |
/// | 100 | 461  | 473  | 0.97 |
/// | 1,000 | 4,510  | 397  | 11 |
/// | 10,000 | 46,700  | 2,740  | 17 |
/// | 100,000 | 45,600  | 20,400  | 22 |
/// | 1,000,000 | 4,590,000  | 196,000  | 23 |
///
/// The benchmarks ensured that `x` and `y` had the same alignment.
///
/// # Examples
///
/// ```rust
/// let x = vec![0xFF; 1000];
/// let y = vec![0; 1000];
/// assert_eq!(hamming::distance(&x, &y), 8 * 1000);
/// ```
pub fn distance(x: &[u8], y: &[u8]) -> u64 {
    distance_fast(x, y).ok().unwrap_or_else(|| naive(x, y))
}

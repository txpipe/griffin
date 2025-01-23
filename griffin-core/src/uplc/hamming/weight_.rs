use crate::uplc::hamming::util;

fn naive(x: &[u8]) -> u64 {
    x.iter().fold(0, |a, b| a + b.count_ones() as u64)
}
/// Computes the [Hamming
/// weight](https://en.wikipedia.org/wiki/Hamming_weight) of `x`, that
/// is, the population count, or number of 1.
///
/// This is a highly optimised version of the following naive version:
///
/// ```rust
/// fn naive(x: &[u8]) -> u64 {
///     x.iter().fold(0, |a, b| a + b.count_ones() as u64)
/// }
/// ```
///
/// This uses Lauradoux Cédric's [tree-merging
/// approach](http://web.archive.org/web/20120411185540/http://perso.citi.insa-lyon.fr/claurado/hamming.html)
/// (as implemented by Kim Walisch in
/// [primesieve](http://primesieve.org/)) and achieves on the order of
/// 1-2 cycles per byte.
///
/// # Performance Comparison
///
/// | length | `naive` (ns) | `weight` (ns) | `naive`/`weight` |
/// |--:|--:|--:|--:|
/// | 1  | 5  | 16  | 0.31 |
/// | 10  | 29  | 51  | 0.56 |
/// | 100  | 284  | 392  | 0.72 |
/// | 1,000  | 2,780 | 340  | 8.2 |
/// | 10,000  | 27,700  | 2,300  | 12 |
/// | 100,000  | 276,000  | 17,900  | 15 |
/// | 1,000,000  | 2,770,000  | 172,000  | 16 |
///
/// # Example
///
/// ```rust
/// assert_eq!(hamming::weight(&[1, 0xFF, 1, 0xFF]), 1 + 8 + 1 + 8);
/// ```
pub fn weight(x: &[u8]) -> u64 {
    const M1: u64 = 0x5555555555555555;
    const M2: u64 = 0x3333333333333333;
    const M4: u64 = 0x0F0F0F0F0F0F0F0F;
    const M8: u64 = 0x00FF00FF00FF00FF;

    type T30 = [u64; 30];
    let (head, thirty, tail) = unsafe { util::align_to::<_, T30>(x) };

    let mut count = naive(head) + naive(tail);
    for array in thirty {
        let mut acc = 0;
        for j_ in 0..10 {
            let j = j_ * 3;
            let mut count1 = array[j];
            let mut count2 = array[j + 1];
            let mut half1 = array[j + 2];
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
    count
}

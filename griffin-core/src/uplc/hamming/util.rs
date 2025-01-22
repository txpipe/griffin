use core::{slice, mem};

/// Reinterpret as much of `x` as a slice of (correctly aligned) `U`s
/// as possible. (Same as `slice::align_to` but available in earlier
/// compilers.)
#[inline(never)] // critical for autovectorization in `weight`.
pub unsafe fn align_to<T, U>(x: &[T]) -> (&[T], &[U], &[T]) {
    let orig_size = mem::size_of::<T>();
    let size = mem::size_of::<U>();

    debug_assert!(orig_size < size && size % orig_size == 0);
    let size_ratio = size / orig_size;

    let alignment = mem::align_of::<U>();

    let ptr = x.as_ptr() as usize;
    // round up to the nearest multiple
    let aligned = (ptr + alignment - 1) / alignment * alignment;
    let byte_distance = aligned - ptr;

    // can't fit a single U in
    if mem::size_of_val(x) < size + byte_distance {
        return (x, &[], &[])
    }

    let (head, middle) = x.split_at(byte_distance / orig_size);

    assert!(middle.as_ptr() as usize % alignment == 0);
    let cast_middle =
        slice::from_raw_parts(middle.as_ptr() as *const U,
                              middle.len() / size_ratio);
    let tail = &middle[cast_middle.len() * size_ratio..];

    (head, cast_middle, tail)
}

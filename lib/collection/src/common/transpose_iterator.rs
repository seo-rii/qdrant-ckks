/// Convert a shape [N, M] to [M, N].
///
/// # Example
///
/// [
///    [1, 2, 3],
///    [4, 5, 6],
/// ]
///
/// to
///
/// [
///    [1, 4],
///    [2, 5],
///    [3, 6],
/// ]
///
/// # Panics
///
/// May panic if the input rows have inconsistent lengths.
pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    transposed_iter(v).collect()
}

/// Convert a shape [N, M] to an iterator which collects into [M, N].
///
/// # Example
///```text
/// [
///    [1, 2, 3],
///    [4, 5, 6],
/// ]
///
/// to
///
/// [1, 4] -> [2, 5] -> [3, 6]
///```
/// # Panics
///
/// May panic if the input rows have inconsistent lengths.
pub fn transposed_iter<T>(rectangle: Vec<Vec<T>>) -> impl Iterator<Item = Vec<T>> {
    let len = rectangle.first().map(Vec::len).unwrap_or(0);
    let mut iters: Vec<_> = rectangle.into_iter().map(|n| n.into_iter()).collect();
    (0..len).map(move |_| {
        iters
            .iter_mut()
            .map(|n| n.next().expect("Input is rectangular"))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose() {
        let v = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let res = transpose(v);
        let expected = [vec![1, 4], vec![2, 5], vec![3, 6]];
        for (i, column) in res.iter().enumerate() {
            assert_eq!(column, &expected[i]);
        }
    }

    #[test]
    fn test_transpose_empty_input() {
        let res: Vec<Vec<i32>> = transpose(Vec::new());

        assert!(res.is_empty());
    }
}

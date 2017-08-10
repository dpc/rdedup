#[test]
fn test_readerveciter() {

    let input = vec![0, 1, 2, 3, 4];
    let r2vi = ReaderVecIter::new(input.as_slice(), 2);
    let mut while_ok = WhileOk::new(r2vi);

    let v: Vec<Vec<_>> = (&mut while_ok).collect();

    assert_eq!(v, [vec![0, 1], vec![2, 3], vec![4]]);
    assert!(while_ok.e.is_none());

    let r2vi = ReaderVecIter::new(input.as_slice(), 2);
    let r2vi_e = r2vi.map(|x| match x {
        Ok(ref v) if *v == vec![2, 3] => {
            Err(io::Error::new(io::ErrorKind::Other, "error"))
        }
        x => x,
    });
    let mut while_ok = WhileOk::new(r2vi_e);

    let v: Vec<Vec<_>> = (&mut while_ok).collect();

    assert_eq!(v, [vec![0, 1]]);
    assert!(while_ok.e.is_some());
}

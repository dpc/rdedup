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

#[test]
fn test_chunker() {

    struct TestEdgeFinder {
        i: usize,
        edges: Vec<usize>,
    }

    impl TestEdgeFinder {
        fn new(edges: Vec<usize>) -> Self {
            TestEdgeFinder { edges: edges, i: 0 }
        }
    }

    impl EdgeFinder for TestEdgeFinder {
        fn find_edges(&mut self, buf: &[u8]) -> Vec<usize> {

            let mut v = vec![];

            for (i, _) in buf.iter().enumerate() {
                if self.edges.contains(&self.i) {
                    v.push(i);
                }

                self.i += 1;
            }

            v
        }
    }


    struct Case {
        input: Vec<u8>,
        buf_size: usize,
        edges: Vec<usize>,
        result: &'static str,
    };

    let test_cases = [
        Case {
            input: vec![0, 1, 2, 3, 4],
            buf_size: 2,
            edges: vec![1, 2, 3, 4, 5, 6],
            result: "[[0], [1], [2], [3], [4]]",
        },
        Case {
            input: vec![],
            buf_size: 2,
            edges: vec![],
            result: "[[]]",
        },
        Case {
            input: vec![],
            buf_size: 2,
            edges: vec![1, 2, 3, 4, 5, 6],
            result: "[[]]",
        },
        Case {
            input: vec![0, 1],
            buf_size: 1,
            edges: vec![2],
            result: "[[0, 1]]",
        },
        Case {
            input: vec![0, 1, 2, 3],
            buf_size: 2,
            edges: vec![],
            result: "[[0, 1, 2, 3]]",
        },
        Case {
            input: vec![0, 1, 2, 3, 4, 5],
            buf_size: 128,
            edges: vec![2],
            result: "[[0, 1], [2, 3, 4, 5]]",
        },
    ];

    for case in &test_cases {
        let r2vi = ReaderVecIter::new(case.input.as_slice(), case.buf_size);
        let mut while_ok = WhileOk::new(r2vi);

        let chunker = Chunker::new(
            &mut while_ok,
            TestEdgeFinder::new(case.edges.clone()),
        );
        let v: Vec<Vec<u8>> = chunker
            .map(|ch| {
                let v: Vec<u8> = ch.as_parts()
                    .iter()
                    .flat_map(|arcref| (**arcref).to_owned())
                    .collect();
                v
            })
            .collect();
        assert_eq!(format!("{:?}", v), case.result);
    }
}

//! Compiler-side helpers used by `Policy::compile`.

use std::{convert::TryFrom, sync};

use miniscript::{
    policy::Concrete as ConcretePolicy, AbsLockTime, DescriptorPublicKey, RelLockTime, Threshold,
};

use super::{
    multipath::deriv_paths_starting_at,
    parse::oxpub_to_key,
    path::{Locktime, OXpub, Path, Semantic},
    policy::{PolicyError, PolicyType},
    LianaDescError, LianaPolicyError,
};

/// Split a thresh(k, key0, .., key{n-1}) into one thresh(k, ...) per choice of `k`
/// participating keys. Returns the participating-key indices for each leaf, in
/// lexicographic order.
///
/// Example for `split_m_of_n(3, 2)` (2-of-3):
///   `[[0, 1], [0, 2], [1, 2]]`
/// → three tap leaves: `thresh(2, k0, k1)`, `thresh(2, k0, k2)`, `thresh(2, k1, k2)`.
fn split_m_of_n(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut buf = Vec::with_capacity(k);
    fn rec(start: usize, n: usize, k: usize, buf: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if buf.len() == k {
            out.push(buf.clone());
            return;
        }
        let need = k - buf.len();
        for i in start..=n.saturating_sub(need) {
            buf.push(i);
            rec(i + 1, n, k, buf, out);
            buf.pop();
        }
    }
    rec(0, n, k, &mut buf, &mut out);
    out
}

fn single_to_miniscript_policy(k: &OXpub, cursor: &mut u32) -> ConcretePolicy<DescriptorPublicKey> {
    let group = deriv_paths_starting_at(*cursor);
    *cursor += 2;
    ConcretePolicy::Key(oxpub_to_key(k, group))
}

fn multi_to_miniscript_policy(
    keys: &[OXpub],
    threshold: usize,
    cursor: &mut u32,
) -> Result<ConcretePolicy<DescriptorPublicKey>, PolicyError> {
    let group = deriv_paths_starting_at(*cursor);
    *cursor += 2;
    let subs: Vec<sync::Arc<ConcretePolicy<DescriptorPublicKey>>> = keys
        .iter()
        .map(|k| sync::Arc::new(ConcretePolicy::Key(oxpub_to_key(k, group.clone()))))
        .collect();
    Ok(ConcretePolicy::Thresh(
        Threshold::new(threshold, subs).map_err(|e| {
            PolicyError::Descriptor(LianaDescError::Miniscript(miniscript::Error::Threshold(e)))
        })?,
    ))
}

fn mandatory_to_miniscript_policy(
    keys: &[OXpub],
    mandatory_keys: &[OXpub],
    threshold: usize,
    cursor: &mut u32,
) -> Result<Vec<ConcretePolicy<DescriptorPublicKey>>, PolicyError> {
    let m = mandatory_keys.len();
    let n = keys.len();
    if threshold <= m || threshold > m + n {
        return Err(PolicyError::InvalidMandatoryThreshold {
            threshold,
            mandatory_count: m,
            cosigner_count: n,
        });
    }
    let cosigner_threshold = threshold - m;
    let subsets = split_m_of_n(n, cosigner_threshold);
    if subsets.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithMandatoryKey,
        ));
    }
    let mut leaves = Vec::with_capacity(subsets.len());
    for subset in subsets {
        let group = deriv_paths_starting_at(*cursor);
        *cursor += 2;
        let mut subs: Vec<sync::Arc<ConcretePolicy<DescriptorPublicKey>>> =
            Vec::with_capacity(threshold);
        for mk in mandatory_keys {
            subs.push(sync::Arc::new(ConcretePolicy::Key(oxpub_to_key(
                mk,
                group.clone(),
            ))));
        }
        for &i in &subset {
            subs.push(sync::Arc::new(ConcretePolicy::Key(oxpub_to_key(
                &keys[i],
                group.clone(),
            ))));
        }
        leaves.push(ConcretePolicy::Thresh(
            Threshold::new(threshold, subs).map_err(|e| {
                PolicyError::Descriptor(LianaDescError::Miniscript(miniscript::Error::Threshold(e)))
            })?,
        ));
    }
    Ok(leaves)
}

/// Emit one or more `ConcretePolicy` fragments for `path`, advancing `cursor` per the `+2`
/// (intra-leaf) / `+4` (between-path) convention. The fragments already have the path's
/// `Locktime` AND'd in. Also returns the even multipath indices assigned to each leaf.
pub(super) fn path_into_fragments(
    path: &Path,
    cursor: &mut u32,
) -> Result<(Vec<ConcretePolicy<DescriptorPublicKey>>, Vec<u32>), PolicyError> {
    let start = *cursor;
    let mut frags: Vec<ConcretePolicy<DescriptorPublicKey>> = match path.semantic() {
        Semantic::Single(k) => vec![single_to_miniscript_policy(k, cursor)],
        Semantic::Multi { keys, threshold } => {
            vec![multi_to_miniscript_policy(keys, *threshold, cursor)?]
        }
        Semantic::MultiWithMandatory {
            keys,
            mandatory_keys,
            threshold,
        } => mandatory_to_miniscript_policy(keys, mandatory_keys, *threshold, cursor)?,
        Semantic::Unknown { .. } | Semantic::Or(_) => {
            return Err(PolicyError::InconsistentPathsForType(PolicyType::Unknown));
        }
    };
    let indices: Vec<u32> = (start..*cursor).step_by(2).collect();

    // AND each fragment with the path's locktime.
    frags = match path.locktime() {
        Locktime::None => frags,
        Locktime::Relative(rl) => {
            let raw = rl.to_consensus_u32();
            let height: u16 = u16::try_from(raw).map_err(|_| {
                PolicyError::Descriptor(LianaDescError::Policy(LianaPolicyError::InsaneTimelock(
                    raw,
                )))
            })?;
            let lt = ConcretePolicy::Older(RelLockTime::from_height(height));
            frags
                .into_iter()
                .map(|f| ConcretePolicy::And(vec![sync::Arc::new(f), sync::Arc::new(lt.clone())]))
                .collect()
        }
        Locktime::AbsoluteRenewable(al) | Locktime::Absolute(al) => {
            let h = al.to_consensus_u32();
            let abs = AbsLockTime::from_consensus(h).map_err(|_| {
                PolicyError::Descriptor(LianaDescError::Policy(LianaPolicyError::InsaneTimelock(h)))
            })?;
            let lt = ConcretePolicy::After(abs);
            frags
                .into_iter()
                .map(|f| ConcretePolicy::And(vec![sync::Arc::new(f), sync::Arc::new(lt.clone())]))
                .collect()
        }
    };

    // `+2` boundary so the next path starts at +4 from this path's first leaf group.
    *cursor += 2;
    Ok((frags, indices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptors::path::{OXpub, TapPosition};
    use miniscript::bitcoin::{absolute, relative};
    use std::str::FromStr;

    fn oxpub_from_str(s: &str) -> OXpub {
        let DescriptorPublicKey::MultiXPub(x) = DescriptorPublicKey::from_str(s).unwrap() else {
            panic!("expected MultiXPub");
        };
        OXpub::new(x.origin, x.xkey)
    }

    fn k1() -> OXpub {
        oxpub_from_str("[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*")
    }

    fn k2() -> OXpub {
        oxpub_from_str("[abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*")
    }

    fn k3() -> OXpub {
        oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")
    }

    fn k4() -> OXpub {
        oxpub_from_str("[abcdef04]xpub661MyMwAqRbcF2FpaYbnrN7K6uPhiwg5u1LiqmsMSTnphuhQzpPv9RGdERxDd7pnnrEC8hxttAPi4wbSVsKeJYiHYymfpuxSD7TALTXqjq6/<0;1>/*")
    }

    /// Read the two multipath-leg indices off a Key fragment. Asserts the wrapped key is a
    /// `MultiXPub` with exactly two single-step paths and returns `(idx0, idx1)`.
    fn key_indices(p: &ConcretePolicy<DescriptorPublicKey>) -> (u32, u32) {
        let ConcretePolicy::Key(DescriptorPublicKey::MultiXPub(m)) = p else {
            panic!("expected Key(MultiXPub)");
        };
        let paths = m.derivation_paths.paths();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].len(), 1);
        assert_eq!(paths[1].len(), 1);
        (u32::from(paths[0][0]), u32::from(paths[1][0]))
    }

    // -------- split_m_of_n --------

    #[test]
    fn split_m_of_n_three_two() {
        // Canonical 2-of-3.
        assert_eq!(split_m_of_n(3, 2), vec![vec![0, 1], vec![0, 2], vec![1, 2]]);
    }

    #[test]
    fn split_m_of_n_four_two() {
        // All 6 lexicographic pairs from {0,1,2,3}.
        assert_eq!(
            split_m_of_n(4, 2),
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![0, 3],
                vec![1, 2],
                vec![1, 3],
                vec![2, 3],
            ]
        );
    }

    #[test]
    fn split_m_of_n_full_set() {
        assert_eq!(split_m_of_n(3, 3), vec![vec![0, 1, 2]]);
    }

    #[test]
    fn split_m_of_n_empty_subset() {
        // k = 0 yields a single empty subset.
        assert_eq!(split_m_of_n(3, 0), vec![Vec::<usize>::new()]);
    }

    #[test]
    fn split_m_of_n_k_greater_than_n() {
        assert!(split_m_of_n(2, 3).is_empty());
    }

    // -------- single_to_miniscript_policy --------

    #[test]
    fn single_advances_cursor_by_two() {
        let mut cursor = 10;
        let pol = single_to_miniscript_policy(&k1(), &mut cursor);
        assert_eq!(cursor, 12);
        assert_eq!(key_indices(&pol), (10, 11));
    }

    // -------- multi_to_miniscript_policy --------

    #[test]
    fn multi_two_of_three_shared_group_cursor_plus_two() {
        let mut cursor = 100;
        let pol = multi_to_miniscript_policy(&[k1(), k2(), k3()], 2, &mut cursor).unwrap();
        assert_eq!(cursor, 102);
        let ConcretePolicy::Thresh(t) = &pol else {
            panic!("expected Thresh");
        };
        assert_eq!(t.k(), 2);
        let subs = t.data();
        assert_eq!(subs.len(), 3);
        // All three sub-keys share the same (100, 101) derivation-path group.
        for sub in subs {
            assert_eq!(key_indices(sub.as_ref()), (100, 101));
        }
    }

    #[test]
    fn multi_one_of_one_degenerate() {
        let mut cursor = 0;
        let pol = multi_to_miniscript_policy(&[k1()], 1, &mut cursor).unwrap();
        assert_eq!(cursor, 2);
        let ConcretePolicy::Thresh(t) = &pol else {
            panic!("expected Thresh");
        };
        assert_eq!(t.k(), 1);
        assert_eq!(t.data().len(), 1);
    }

    #[test]
    fn multi_invalid_threshold_propagates_miniscript_error() {
        let mut cursor = 0;
        // threshold > keys.len() makes miniscript's Threshold::new reject.
        let err = multi_to_miniscript_policy(&[k1(), k2()], 5, &mut cursor).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::Descriptor(LianaDescError::Miniscript(miniscript::Error::Threshold(_)))
            ),
            "got {:?}", err
        );
    }

    // -------- mandatory_to_miniscript_policy --------

    #[test]
    fn mandatory_one_mand_two_cosigners_threshold_two() {
        // m=1, n=2, threshold=2 → cosigner_threshold = 1 → C(2,1)=2 leaves.
        let mut cursor = 50;
        let leaves = mandatory_to_miniscript_policy(&[k2(), k3()], &[k1()], 2, &mut cursor).unwrap();
        assert_eq!(leaves.len(), 2);
        // Each leaf consumes 2 multipath slots; cursor advanced by 4.
        assert_eq!(cursor, 54);
        // First leaf: [k1, k2] sharing group (50, 51).
        // Second leaf: [k1, k3] sharing group (52, 53).
        let expected_groups = [(50, 51), (52, 53)];
        for (leaf, group) in leaves.iter().zip(expected_groups.iter()) {
            let ConcretePolicy::Thresh(t) = leaf else {
                panic!("expected Thresh");
            };
            assert_eq!(t.k(), 2);
            let subs = t.data();
            assert_eq!(subs.len(), 2);
            for sub in subs {
                assert_eq!(key_indices(sub.as_ref()), *group);
            }
        }
    }

    #[test]
    fn mandatory_one_mand_three_cosigners_threshold_three() {
        // m=1, n=3, threshold=3 → cosigner_threshold = 2 → C(3,2)=3 leaves.
        let mut cursor = 0;
        let leaves =
            mandatory_to_miniscript_policy(&[k2(), k3(), k4()], &[k1()], 3, &mut cursor).unwrap();
        assert_eq!(leaves.len(), 3);
        assert_eq!(cursor, 6);
    }

    #[test]
    fn mandatory_threshold_equal_to_m_rejected() {
        let mut cursor = 0;
        let err = mandatory_to_miniscript_policy(&[k2(), k3()], &[k1()], 1, &mut cursor).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::InvalidMandatoryThreshold {
                    threshold: 1,
                    mandatory_count: 1,
                    cosigner_count: 2,
                }
            ),
            "got {:?}", err
        );
    }

    #[test]
    fn mandatory_threshold_above_m_plus_n_rejected() {
        let mut cursor = 0;
        let err = mandatory_to_miniscript_policy(&[k2(), k3()], &[k1()], 4, &mut cursor).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::InvalidMandatoryThreshold {
                    threshold: 4,
                    mandatory_count: 1,
                    cosigner_count: 2,
                }
            ),
            "got {:?}", err
        );
    }

    // -------- path_into_fragments --------

    fn single_path(locktime: Locktime) -> Path {
        Path::new(Semantic::Single(k1()), locktime, TapPosition::TapTree(vec![]))
    }

    #[test]
    fn fragments_single_no_locktime_advances_cursor_by_four() {
        let p = single_path(Locktime::None);
        let mut cursor = 200;
        let (frags, indices) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(indices, vec![200]);
        // +2 for the leaf group, +2 for the inter-path boundary.
        assert_eq!(cursor, 204);
        assert!(matches!(&frags[0], ConcretePolicy::Key(_)));
    }

    #[test]
    fn fragments_multi_two_of_three_one_fragment() {
        let p = Path::new(
            Semantic::Multi {
                keys: vec![k1(), k2(), k3()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut cursor = 0;
        let (frags, indices) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(indices, vec![0]);
        assert_eq!(cursor, 4);
        assert!(matches!(&frags[0], ConcretePolicy::Thresh(_)));
    }

    #[test]
    fn fragments_mandatory_indices_step_by_two() {
        // 1 mandatory + 2 cosigners, threshold 2 → 2 leaves, indices at start and start+2.
        let p = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![k2(), k3()],
                mandatory_keys: vec![k1()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut cursor = 1000;
        let (frags, indices) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(indices, vec![1000, 1002]);
        // 2 leaves * 2 + boundary 2 = 6.
        assert_eq!(cursor, 1006);
    }

    #[test]
    fn fragments_relative_locktime_wraps_with_older() {
        let p = single_path(Locktime::Relative(relative::LockTime::from_height(144)));
        let mut cursor = 0;
        let (frags, _) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 1);
        let ConcretePolicy::And(parts) = &frags[0] else {
            panic!("expected And");
        };
        assert_eq!(parts.len(), 2);
        assert!(matches!(parts[0].as_ref(), ConcretePolicy::Key(_)));
        let ConcretePolicy::Older(lt) = parts[1].as_ref() else {
            panic!("expected Older");
        };
        assert_eq!(lt.to_consensus_u32(), 144);
    }

    #[test]
    fn fragments_absolute_locktime_wraps_with_after() {
        let p = single_path(Locktime::Absolute(absolute::LockTime::from_height(500_000).unwrap()));
        let mut cursor = 0;
        let (frags, _) = path_into_fragments(&p, &mut cursor).unwrap();
        let ConcretePolicy::And(parts) = &frags[0] else {
            panic!("expected And");
        };
        let ConcretePolicy::After(abs) = parts[1].as_ref() else {
            panic!("expected After");
        };
        assert_eq!(abs.to_consensus_u32(), 500_000);
    }

    #[test]
    fn fragments_absolute_renewable_uses_same_after_branch() {
        let p = single_path(Locktime::AbsoluteRenewable(
            absolute::LockTime::from_height(500_000).unwrap(),
        ));
        let mut cursor = 0;
        let (frags, _) = path_into_fragments(&p, &mut cursor).unwrap();
        let ConcretePolicy::And(parts) = &frags[0] else {
            panic!("expected And");
        };
        assert!(matches!(parts[1].as_ref(), ConcretePolicy::After(_)));
    }

    #[test]
    fn fragments_or_semantic_rejected() {
        let p = Path::new(
            Semantic::Or(vec![Semantic::Single(k1()), Semantic::Single(k2())]),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut cursor = 0;
        let err = path_into_fragments(&p, &mut cursor).unwrap_err();
        assert!(
            matches!(err, PolicyError::InconsistentPathsForType(PolicyType::Unknown)),
            "got {:?}", err
        );
    }

    #[test]
    fn fragments_cursor_continues_across_paths_with_plus_four_boundary() {
        // Run two consecutive single-path calls and assert the inter-path boundary: the
        // second path's first index sits exactly 4 above the first path's last index.
        let p1 = single_path(Locktime::None);
        let p2 = single_path(Locktime::Relative(relative::LockTime::from_height(144)));
        let mut cursor = 0;
        let (_, indices1) = path_into_fragments(&p1, &mut cursor).unwrap();
        let (_, indices2) = path_into_fragments(&p2, &mut cursor).unwrap();
        let last1 = *indices1.last().unwrap();
        let first2 = indices2[0];
        assert_eq!(first2, last1 + 4);
    }
}

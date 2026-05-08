//! `Policy` and `SemanticDescriptor` - the new model for Tr Liana policies plus the top-level
//! enum that wraps a legacy [`LianaDescriptor`] or a new [`Policy`].

use std::{
    collections::{BTreeMap, BTreeSet},
    error, fmt,
};

use miniscript::{
    bitcoin::absolute::LOCK_TIME_THRESHOLD,
    descriptor::{TapTree, Tr},
    policy::Semantic as SemanticPolicy,
    {Descriptor, DescriptorPublicKey},
};

use super::{
    analysis::{bip341_nums, unspendable_internal_key},
    multipath::{
        assign_start_indices, get_multipath_index, group_taptree_leaves, LeafEntry,
        NUMS_MARKER_MULTIPATH,
    },
    parse::{compute_satisfaction_wu, infer_policy_type, oxpub, tr_key_path_wu},
    path::{Locktime, LocktimeError, Path, Semantic, SemanticError, TapPosition},
    LianaDescError,
};

/// Recognise an internal key tagged with `NUMS_MARKER_MULTIPATH` and the BIP-341 NUMS
/// pubkey. Cheap parser-side detection added on top of the legacy chain-code recompute
/// (which still works because `compute_nums_internal_key` derives the chain code with the
/// same algorithm as `analysis::unspendable_internal_xpub`).
fn is_new_style_nums(key: &DescriptorPublicKey) -> bool {
    let DescriptorPublicKey::MultiXPub(m) = key else {
        return false;
    };
    if m.xkey.public_key != bip341_nums() {
        return false;
    }
    let paths = m.derivation_paths.paths();
    paths.len() == 2
        && paths[0].len() == 1
        && paths[1].len() == 1
        && u32::from(paths[0][0]) == NUMS_MARKER_MULTIPATH[0]
        && u32::from(paths[1][0]) == NUMS_MARKER_MULTIPATH[1]
}

fn extract_leaves<'a>(
    tap_tree: &'a TapTree<DescriptorPublicKey>,
) -> Result<Vec<LeafEntry<'a>>, super::multipath::MultipathError> {
    let mut entries = Vec::new();
    for (idx, (depth, ms)) in tap_tree.iter().enumerate() {
        if is_nums_padding_leaf(ms) {
            continue;
        }
        let mut indices = Vec::new();
        for k in ms.iter_pk() {
            indices.push(get_multipath_index(&k)?);
        }
        entries.push(LeafEntry {
            index: idx,
            depth,
            indices,
            ms,
        });
    }
    Ok(entries)
}

/// Recognise a NUMS-keyed padding leaf inserted by `compile::nums_padding_leaf`. Real
/// path leaves never carry the BIP-341 NUMS pubkey, so any leaf whose only key is a
/// NUMS-pubkey'd `MultiXPub` is treated as padding and skipped during parsing.
fn is_nums_padding_leaf(ms: &miniscript::Miniscript<DescriptorPublicKey, miniscript::Tap>) -> bool {
    let mut keys = ms.iter_pk();
    let Some(first) = keys.next() else {
        return false;
    };
    if keys.next().is_some() {
        return false;
    }
    let DescriptorPublicKey::MultiXPub(m) = first else {
        return false;
    };
    m.xkey.public_key == bip341_nums()
}

/// Tag identifying the on-chain shape of a [`Policy`]. Inferred from the path set's semantic
/// content (locktime kind + presence of mandatory keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyType {
    /// Original Csv shape - relative timelock recovery (`older(...)`).
    Csv,
    /// Absolute-timelock recovery (`after(...)`).
    Cltv,
    /// Relative timelock with one or more mandatory-key paths.
    CsvWithMandatoryKey,
    /// Parsed from a descriptor we couldn't classify; not constructable via [`Policy::new`].
    Unknown,
    Invalid,
}

#[derive(Debug)]
pub enum PolicyError {
    /// A `Policy` must have at least one [`Path`].
    EmptyPaths,
    /// `Cltv` policies require absolute heights aligned to `CLTV_ALIGNMENT`.
    UnalignedCltv(u32),
    /// `Cltv` height is on the timestamp side (`>= LOCK_TIME_THRESHOLD`), which we don't accept.
    InsaneCltvHeight(u32),
    /// The given `paths` don't fit the declared `PolicyType` (e.g. `Cltv` with a relative
    /// locktime, or `Csv` with a `MultiWithMandatory` semantic).
    InconsistentPathsForType(PolicyType),
    /// `CsvWithMandatoryKey` requires at least one `MultiWithMandatory` path.
    NoMandatoryKeyPath,
    /// `MultiWithMandatory.threshold` is invalid: must satisfy
    /// `mandatory_count + 1 <= threshold <= mandatory_count + cosigner_count` so each leaf
    /// requires every mandatory key plus at least one cosigner.
    InvalidMandatoryThreshold {
        threshold: usize,
        mandatory_count: usize,
        cosigner_count: usize,
    },
    /// `Policy` cannot be constructed with `PolicyType::Unknown` - that variant is only produced
    /// by the parser when classification fails.
    UnknownNotConstructable,
    /// `Policy::from_descriptor` requires a Taproot descriptor.
    NotTaproot,
    /// Lower-level descriptor compilation/parsing error.
    Descriptor(LianaDescError),
    /// Compilation hasn't been performed yet (called `descriptor()` on a fresh `Policy::new`
    /// before `compile`).
    NotYetCompiled,
    /// A group of tap-tree leaves could not be classified into a known [`Path`] shape.
    UnrecognizedLeafGroup,
    /// `threshold` is out of range for the given key count (`threshold` must be in `[1, n]`,
    /// or exactly `1` for a single-key path).
    InvalidThreshold { threshold: usize, key_count: usize },
    /// Wrong number of non-timelocked (primary) paths. Every policy must have exactly one.
    InvalidPrimaryCount(usize),
    /// Two recovery paths share the same timelock height; recovery timelocks must be distinct.
    DuplicateTimelock(u32),
    /// Policy has no timelocked recovery path; every policy must have at least one.
    MissingRecoveryPath,
    /// Policy mixes more than one locktime flavor in the same descriptor. Each policy may use
    /// only one of: relative (`older`), aligned-renewable absolute (`after`), or
    /// foreign-unaligned absolute (`after`).
    MixedTimelockKinds,
    /// A signer key in the policy is not a real signer key (BIP-341 NUMS unspendable key,
    /// or zeroed chain code / pubkey).
    InvalidSignerKey(super::path::OXpubError),
    /// A `TapPosition::InternalKey` path carries a non-`None` locktime; the Tr internal key
    /// must be unconditionally spendable.
    InternalKeyWithLocktime,
    /// A `TapPosition::InternalKey` path's semantic is not `Single`; the Tr internal key is
    /// a single-key spend, not a multisig or threshold shape.
    InternalKeyNotSingle,
    /// More than one path is at `TapPosition::InternalKey`; a Tr descriptor has exactly one
    /// internal key.
    MultipleInternalKeys,
    /// The internal tree builder reported an error.
    TreeBuilder(super::tree_builder::TreeBuilderError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::EmptyPaths => write!(f, "Policy must contain at least one path."),
            Self::UnalignedCltv(t) => {
                write!(f, "CLTV height '{t}' is not aligned to the CLTV grid.")
            }
            Self::InsaneCltvHeight(t) => {
                write!(f, "CLTV height '{t}' is invalid (>= LOCK_TIME_THRESHOLD = {LOCK_TIME_THRESHOLD}).")
            }
            Self::InconsistentPathsForType(pt) => write!(
                f,
                "Path set is inconsistent with declared PolicyType '{pt:?}'."
            ),
            Self::NoMandatoryKeyPath => write!(
                f,
                "CsvWithMandatoryKey requires at least one MultiWithMandatory path."
            ),
            Self::InvalidMandatoryThreshold {
                threshold,
                mandatory_count,
                cosigner_count,
            } => write!(
                f,
                "Invalid MultiWithMandatory threshold {threshold}: must be in [{lo}, {hi}].",
                lo = mandatory_count + 1,
                hi = mandatory_count + cosigner_count,
            ),
            Self::UnknownNotConstructable => write!(
                f,
                "PolicyType::Unknown cannot be constructed; only the parser produces it."
            ),
            Self::NotTaproot => write!(f, "Policy::from_descriptor requires a Taproot descriptor."),
            Self::Descriptor(e) => write!(f, "{e}"),
            Self::NotYetCompiled => write!(f, "Policy has not been compiled to a descriptor yet."),
            Self::UnrecognizedLeafGroup => write!(f, "tap-tree leaf group could not be classified into a known path shape"),
            Self::InvalidThreshold { threshold, key_count } => write!(
                f,
                "threshold {threshold} is out of range for {key_count} key(s): must be in [1, {key_count}]",
            ),
            Self::InvalidPrimaryCount(c) => write!(
                f,
                "policy has {c} non-timelocked path(s); exactly one is required"
            ),
            Self::DuplicateTimelock(h) => write!(
                f,
                "two recovery paths share timelock height {h}; recovery timelocks must be distinct"
            ),
            Self::MissingRecoveryPath => {
                write!(f, "policy has no timelocked recovery path; at least one is required")
            }
            Self::MixedTimelockKinds => write!(
                f,
                "policy mixes more than one locktime flavor; only one of relative, aligned absolute, or foreign absolute is allowed per policy"
            ),
            Self::InvalidSignerKey(e) => match e {
                super::path::OXpubError::NumsKey => write!(
                    f,
                    "policy contains the BIP-341 NUMS unspendable key as a signer; that key cannot sign"
                ),
                super::path::OXpubError::ZeroedPubkey => write!(
                    f,
                    "policy contains a key with a zeroed public-key x-coordinate (placeholder / sentinel)"
                ),
                super::path::OXpubError::ZeroedChainCode => write!(
                    f,
                    "policy contains a key with a zeroed chain code (placeholder / sentinel)"
                ),
            },
            Self::InternalKeyWithLocktime => write!(
                f,
                "Tr internal-key path has a non-None locktime; the internal key must be unconditionally spendable"
            ),
            Self::InternalKeyNotSingle => write!(
                f,
                "Tr internal-key path semantic is not Single; the internal key is a single-key spend"
            ),
            Self::MultipleInternalKeys => write!(
                f,
                "policy declares more than one TapPosition::InternalKey path; a Tr descriptor has exactly one internal key"
            ),
            Self::TreeBuilder(e) => write!(f, "tree builder error: {e}"),
        }
    }
}

impl error::Error for PolicyError {}

impl From<super::tree_builder::TreeBuilderError> for PolicyError {
    fn from(e: super::tree_builder::TreeBuilderError) -> Self {
        PolicyError::TreeBuilder(e)
    }
}

impl From<LianaDescError> for PolicyError {
    fn from(e: LianaDescError) -> Self {
        Self::Descriptor(e)
    }
}

impl From<super::multipath::MultipathError> for PolicyError {
    fn from(e: super::multipath::MultipathError) -> Self {
        LianaDescError::from(e).into()
    }
}

impl From<SemanticError> for PolicyError {
    fn from(e: SemanticError) -> Self {
        match e {
            SemanticError::InvalidThreshold {
                threshold,
                key_count,
            } => PolicyError::InvalidThreshold {
                threshold,
                key_count,
            },
            SemanticError::InvalidMandatoryThreshold {
                threshold,
                mandatory_count,
                cosigner_count,
            } => PolicyError::InvalidMandatoryThreshold {
                threshold,
                mandatory_count,
                cosigner_count,
            },
            SemanticError::InvalidKey(e) => PolicyError::InvalidSignerKey(e),
        }
    }
}

impl From<LocktimeError> for PolicyError {
    fn from(e: LocktimeError) -> Self {
        match e {
            LocktimeError::InsaneAbsoluteHeight(h) => PolicyError::InsaneCltvHeight(h),
            LocktimeError::Unaligned(h) => PolicyError::UnalignedCltv(h),
        }
    }
}

/// A Tr-only Liana policy. Carries its [`Path`]s, an optional cached compiled
/// [`Descriptor<DescriptorPublicKey>`], and the [`PolicyType`] tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    paths: Vec<Path>,
    descriptor: Option<Descriptor<DescriptorPublicKey>>,
    policy_type: PolicyType,
}

impl Policy {
    /// Build a `Policy` from an explicit set of [`Path`]s and a [`PolicyType`].
    ///
    /// Validates that the paths are coherent with the tag (e.g. no `Absolute` locktimes in a
    /// `Csv` policy, no unaligned absolute heights in `Cltv`, at least one `MultiWithMandatory`
    /// in `CsvWithMandatoryKey`). Leaves `descriptor` as `None` - call [`Self::compile`] to
    /// produce the on-chain artefact.
    pub fn new(paths: Vec<Path>, policy_type: PolicyType) -> Result<Self, PolicyError> {
        if matches!(policy_type, PolicyType::Unknown) {
            return Err(PolicyError::UnknownNotConstructable);
        }
        let policy = Self {
            paths,
            descriptor: None,
            policy_type,
        };
        policy.sanitize()?;
        Ok(policy)
    }

    /// Construct a `Policy` from an existing Taproot multipath descriptor.
    ///
    /// Walks the descriptor:
    /// 1. **Internal key.** If the Tr internal key is *not* the deterministic NUMS unspendable,
    ///    record it as a `Path { semantic: Single, locktime: None, position: InternalKey }`.
    /// 2. **Tap tree leaves.** Enumerate `(index, depth, miniscript)` for each leaf, group
    ///    by multipath group, and try to classify each group as a [`Semantic`] shape with an
    ///    optional `older()` / `after()` locktime.
    /// 3. **Sort paths** by ascending multipath group.
    /// 4. **Infer `PolicyType`** from the resulting path set.
    /// 5. **Cache** the descriptor.
    pub fn from_descriptor(desc: &Descriptor<DescriptorPublicKey>) -> Result<Self, PolicyError> {
        let tr = match desc {
            Descriptor::Tr(tr) => tr,
            _ => return Err(PolicyError::NotTaproot),
        };

        let mut paths: Vec<Path> = Vec::new();

        // Skip the internal key when it's the deterministic NUMS unspendable. Two
        // detection paths: the cheap marker check (new-style NUMS carries
        // `NUMS_MARKER_MULTIPATH`), and the legacy chain-code recompute.
        let internal_key = tr.internal_key();
        let is_unspendable = is_new_style_nums(internal_key)
            || unspendable_internal_key(tr).as_ref() == Some(internal_key);
        if !is_unspendable {
            let semantic = if let Some(o) = oxpub(internal_key) {
                Semantic::Single(o)
            } else {
                Semantic::Unknown {
                    policy: SemanticPolicy::Key(internal_key.clone()),
                }
            };
            let mut p = Path::new(semantic, Locktime::None, TapPosition::InternalKey);
            p.set_satisfaction_wu(Some(tr_key_path_wu()));
            paths.push(p);
        }

        if let Some(tap_tree) = tr.tap_tree() {
            let leaves = extract_leaves(tap_tree).map_err(LianaDescError::from)?;
            paths.extend(group_taptree_leaves(leaves)?);
        }

        paths.sort_by_key(|p| match p.position() {
            TapPosition::InternalKey => 0usize,
            TapPosition::TapTree(leaves) => leaves.first().map(|l| l.0 + 1).unwrap_or(usize::MAX),
        });

        let policy_type = infer_policy_type(&paths);

        // Compute satisfaction_wu via rust-miniscript's satisfaction module now that each
        // leaf's depth and concrete miniscript are known.
        if let Some(tap_tree) = tr.tap_tree() {
            let by_leaf: BTreeMap<
                usize,
                (
                    u8,
                    &miniscript::Miniscript<DescriptorPublicKey, miniscript::Tap>,
                ),
            > = tap_tree
                .iter()
                .enumerate()
                .map(|(idx, (depth, ms))| (idx, (depth, ms)))
                .collect();
            for path in paths.iter_mut() {
                if let TapPosition::TapTree(leaves) = path.position() {
                    let refined = leaves
                        .first()
                        .and_then(|l| by_leaf.get(&l.0))
                        .and_then(|(depth, ms)| compute_satisfaction_wu(ms, *depth));
                    path.set_satisfaction_wu(refined);
                }
            }
        }

        Ok(Self {
            paths,
            descriptor: Some(desc.clone()),
            policy_type,
        })
    }

    /// Compile the policy into a Taproot multipath descriptor, rewriting every key's multipath
    /// to follow the path-role scheme.
    ///
    /// The compiler runs in three steps:
    /// 1. **Resolve global order.** Caller-set `Path::order` values define explicit tap-tree
    ///    positions (errors on duplicates or out-of-range); remaining `None`s are filled by
    ///    sorting on ascending locktime height.
    /// 2. **Assign `start_index` per path.** Walk paths in the resolved global order; each
    ///    path's role zone (`Semantic::starting_index(locktime)`) supplies the base, a per-zone
    ///    cursor walks `+2` per leaf inside a path and `+4` between paths.
    /// 3. **Emit.** For each path in global order: emit one fragment per `Single`/`Multi`
    ///    path or one fragment per `k`-of-`n` cosigner subset for `MultiWithMandatory`, AND
    ///    each fragment with the locktime, ask miniscript to compile each fragment **as a
    ///    single tap leaf** (we don't ask miniscript to build the tap tree or pick an internal
    ///    key), then assemble the tap tree manually via `assemble_tap_tree`. The internal key
    ///    is the `TapPosition::InternalKey` path's key if there is one, else the deterministic
    ///    BIP-341 NUMS unspendable from `compute_nums_internal_key`.
    ///
    /// Each call recompiles from scratch, populating `start_index`, `indices`, and `miniscript`
    /// on each path.
    pub fn compile(&mut self) -> Result<&Descriptor<DescriptorPublicKey>, PolicyError> {
        self.descriptor = None;
        self.auto_promote_internal_key_maybe();
        self.sanitize()?;

        self.resolve_global_order();
        assign_start_indices(&mut self.paths)?;

        let (internal_key, tap_tree) = super::tree_builder::build(&self.paths)?;

        let tr = Tr::new(internal_key, tap_tree)
            .map_err(|e| PolicyError::Descriptor(LianaDescError::Miniscript(e)))?;
        self.descriptor = Some(Descriptor::Tr(tr));
        Ok(self.descriptor.as_ref().unwrap())
    }

    /// Promote an eligible single-key path to the Tr internal key. Runs at the very start
    /// of [`Self::compile`], **before** [`Self::resolve_global_order`] auto-fills any
    /// unset ordering. Only caller-supplied `order` values are visible at this point.
    /// `Policy::sanitize` stays non-mutating.
    ///
    /// **Caller priority:** if any path already sits at `TapPosition::InternalKey`, the
    /// caller has made an explicit choice and this function is a no-op. Auto-promotion
    /// only kicks in when no path is currently on the internal key.
    ///
    /// A candidate is any path satisfying both:
    /// - locktime is `Locktime::None`,
    /// - semantic is [`Semantic::Single`].
    ///
    /// Position isn't in the filter: the caller-priority early return above already
    /// guarantees every remaining path sits at `TapPosition::TapTree(_)`. Paths the
    /// caller intended to live in the tree are still eligible. Promotion lifts them out
    /// of the tap tree onto the internal key.
    ///
    /// Selection: among candidates, pick the one whose caller-set `order` is smallest,
    /// with `order = None` ranked after any `Some(_)` (ties broken by position in
    /// `self.paths` for determinism). For typed policies the `InvalidPrimaryCount` rule
    /// keeps the candidate set tiny; for `PolicyType::Unknown` several candidates can
    /// coexist and the smallest caller order wins.
    ///
    /// If at least one candidate exists, the selected path is rewritten to
    /// `TapPosition::InternalKey`. Otherwise this is a no-op and `compile` falls back to
    /// the deterministic NUMS unspendable internal key.
    fn auto_promote_internal_key_maybe(&mut self) {
        if self
            .paths
            .iter()
            .any(|p| matches!(p.position(), TapPosition::InternalKey))
        {
            return;
        }
        let candidate = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                matches!(p.locktime(), Locktime::None)
                    && matches!(p.semantic(), Semantic::Single(_))
            })
            .min_by_key(|(idx, p)| (p.order().unwrap_or(usize::MAX), *idx))
            .map(|(idx, _)| idx);
        if let Some(idx) = candidate {
            self.paths[idx].set_position(TapPosition::InternalKey);
        }
    }

    /// Validate that the policy is compile-ready without producing a descriptor or mutating
    /// any state. This is the single source of truth for compile-readiness: [`Self::compile`]
    /// calls it as its first step and then trusts every invariant established here.
    ///
    /// `Ok(())` means [`Self::compile`] will not fail on validation; it can still fail later
    /// in miniscript compilation for a degenerate satisfaction shape.
    pub fn sanitize(&self) -> Result<(), PolicyError> {
        if self.paths.is_empty() {
            return Err(PolicyError::EmptyPaths);
        }
        validate_paths_for_type(&self.paths, self.policy_type)?;

        let mut internal_key_seen = false;
        for path in &self.paths {
            if path.semantic().starting_index(path.locktime()).is_none() {
                return Err(PolicyError::InconsistentPathsForType(self.policy_type));
            }
            if matches!(path.position(), TapPosition::InternalKey) {
                if !matches!(path.locktime(), Locktime::None) {
                    return Err(PolicyError::InternalKeyWithLocktime);
                }
                if !matches!(path.semantic(), Semantic::Single(_)) {
                    return Err(PolicyError::InternalKeyNotSingle);
                }
                if internal_key_seen {
                    return Err(PolicyError::MultipleInternalKeys);
                }
                internal_key_seen = true;
            }
        }

        Ok(())
    }

    /// Assign every path a concrete `order`, then return the slot-ordered `Vec<usize>`.
    ///
    /// Algorithm:
    /// 1. Collect every caller-set order into `used`. Caller values may repeat: paths
    ///    sharing an `order` form a priority group that the tap-tree builder later
    ///    places together at a single leaf depth.
    /// 2. Sort the unordered paths by ascending locktime height (insertion-index tie-break).
    /// 3. Walk a cursor from 0 upward, skipping values in `used`, and assign each
    ///    unordered path a fresh unique order. Fresh values never collide with
    ///    caller-supplied ones, so unordered paths never join a caller group.
    /// 4. Every path now has `order = Some(_)`; downstream helpers walk paths sorted by
    ///    that field.
    fn resolve_global_order(&mut self) {
        let used: BTreeSet<usize> = self.paths.iter().filter_map(|p| p.order()).collect();

        let mut unordered: Vec<usize> = self
            .paths
            .iter()
            .enumerate()
            .filter_map(|(i, p)| if p.order().is_none() { Some(i) } else { None })
            .collect();
        unordered.sort_by_key(|&i| {
            let h = match self.paths[i].locktime() {
                Locktime::Relative(rl) => rl.to_consensus_u32(),
                Locktime::Absolute(a) | Locktime::AbsoluteRenewable(a) => a.to_consensus_u32(),
                Locktime::None => 0,
            };
            (h, i)
        });

        let mut next_free = 0;
        for path_idx in unordered {
            while used.contains(&next_free) {
                next_free += 1;
            }
            self.paths[path_idx].set_order(Some(next_free));
            next_free += 1;
        }
    }

    pub fn paths(&self) -> &[Path] {
        &self.paths
    }

    pub fn descriptor(&self) -> Option<&Descriptor<DescriptorPublicKey>> {
        self.descriptor.as_ref()
    }

    pub fn policy_type(&self) -> PolicyType {
        self.policy_type
    }
}

fn validate_paths_for_type(paths: &[Path], policy_type: PolicyType) -> Result<(), PolicyError> {
    match policy_type {
        PolicyType::Csv => validate_csv_paths(paths),
        PolicyType::Cltv => validate_cltv_paths(paths),
        PolicyType::CsvWithMandatoryKey => validate_csv_with_mandatory_paths(paths),
        PolicyType::Unknown => validate_unknown_paths(paths),
        PolicyType::Invalid => Err(PolicyError::UnknownNotConstructable),
    }
}

/// Unknown: skip the policy-level invariants (primary count, recovery presence, mixing,
/// etc.) since the parser couldn't classify the descriptor into a known shape, but still
/// require every path to be **structurally** valid (`Semantic::validate` +
/// `Locktime::validate`). An `Unknown`-typed policy that contains a `Multi` with an
/// out-of-range threshold or a CLTV timestamp-style height is still rejected here.
fn validate_unknown_paths(paths: &[Path]) -> Result<(), PolicyError> {
    for p in paths {
        p.semantic().validate()?;
        p.locktime().validate()?;
    }
    Ok(())
}

/// Per-flavor dedup sets returned by [`check_common_invariants`]. Each set holds the heights
/// the validator already saw for that locktime flavor, so per-type validators can decide
/// which flavors are admissible without re-walking `self.paths`.
struct CommonInvariants {
    relative: BTreeSet<u32>,
    absolute_renewable: BTreeSet<u32>,
    absolute_foreign: BTreeSet<u32>,
}

/// Invariants every policy type must satisfy:
/// - exactly one non-timelocked (primary) path,
/// - at least one timelocked recovery,
/// - no two recoveries share a timelock height **within the same flavor** (relative,
///   aligned absolute, foreign absolute),
/// - no mixing of more than one locktime flavor in the same policy,
/// - no `Or` / `Unknown` semantics (uncompilable shapes regardless of policy type).
///
/// Returns the per-flavor sets of seen heights so per-type validators can assert which
/// flavors are admissible (e.g. Csv only allows `relative`).
fn check_common_invariants(
    paths: &[Path],
    policy_type: PolicyType,
) -> Result<CommonInvariants, PolicyError> {
    let mut primary_count: usize = 0;
    let mut relative: BTreeSet<u32> = BTreeSet::new();
    let mut absolute_renewable: BTreeSet<u32> = BTreeSet::new();
    let mut absolute: BTreeSet<u32> = BTreeSet::new();
    for p in paths {
        p.semantic().validate()?;
        p.locktime().validate()?;
        match p.semantic() {
            Semantic::Unknown { .. } | Semantic::Or(_) => {
                return Err(PolicyError::InconsistentPathsForType(policy_type));
            }
            _ => {}
        }
        match p.locktime() {
            Locktime::None => {
                primary_count += 1;
            }
            Locktime::Relative(rl) => {
                let h = rl.to_consensus_u32();
                if !relative.insert(h) {
                    return Err(PolicyError::DuplicateTimelock(h));
                }
            }
            Locktime::AbsoluteRenewable(lt) => {
                let h = lt.to_consensus_u32();
                if !absolute_renewable.insert(h) {
                    return Err(PolicyError::DuplicateTimelock(h));
                }
            }
            Locktime::Absolute(lt) => {
                let h = lt.to_consensus_u32();
                if !absolute.insert(h) {
                    return Err(PolicyError::DuplicateTimelock(h));
                }
            }
        }
    }
    if primary_count != 1 {
        return Err(PolicyError::InvalidPrimaryCount(primary_count));
    }
    let flavors_present = [&relative, &absolute_renewable, &absolute]
        .iter()
        .filter(|s| !s.is_empty())
        .count();
    if flavors_present == 0 {
        return Err(PolicyError::MissingRecoveryPath);
    }
    if flavors_present > 1 {
        return Err(PolicyError::MixedTimelockKinds);
    }
    Ok(CommonInvariants {
        relative,
        absolute_renewable,
        absolute_foreign: absolute,
    })
}

/// Csv: only relative-locktime recoveries; no `MultiWithMandatory` semantic.
fn validate_csv_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::Csv)?;
    if !inv.absolute_renewable.is_empty() || !inv.absolute_foreign.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(PolicyType::Csv));
    }
    for p in paths {
        if matches!(p.semantic(), Semantic::MultiWithMandatory { .. }) {
            return Err(PolicyError::InconsistentPathsForType(PolicyType::Csv));
        }
    }
    Ok(())
}

/// Cltv: only absolute-locktime recoveries (renewable **or** foreign, but not both, since
/// the common invariants forbid mixing flavors). No `MultiWithMandatory` semantic.
/// Renewable heights must be aligned to [`CLTV_ALIGNMENT`]; foreign (`Absolute`) heights
/// are accepted without alignment but rejected if they encode a timestamp
/// (`>= LOCK_TIME_THRESHOLD`).
fn validate_cltv_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::Cltv)?;
    if !inv.relative.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(PolicyType::Cltv));
    }
    for p in paths {
        if matches!(p.semantic(), Semantic::MultiWithMandatory { .. }) {
            return Err(PolicyError::InconsistentPathsForType(PolicyType::Cltv));
        }
    }
    Ok(())
}

/// CsvWithMandatoryKey: only relative-locktime recoveries, with at least one
/// [`Semantic::MultiWithMandatory`] path; mandatory-key thresholds must satisfy
/// `mandatory_count + 1 <= threshold <= mandatory_count + cosigner_count`.
fn validate_csv_with_mandatory_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::CsvWithMandatoryKey)?;
    if !inv.absolute_renewable.is_empty() || !inv.absolute_foreign.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithMandatoryKey,
        ));
    }
    let has_mandatory = paths
        .iter()
        .any(|p| matches!(p.semantic(), Semantic::MultiWithMandatory { .. }));
    if !has_mandatory {
        return Err(PolicyError::NoMandatoryKeyPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptors::path::{OXpub, Path, Semantic, TapPosition};
    use miniscript::{
        bitcoin::{absolute, relative},
        DescriptorPublicKey,
    };
    use std::str::FromStr;

    fn oxpub_from_str(s: &str) -> OXpub {
        let k = DescriptorPublicKey::from_str(s).unwrap();
        let DescriptorPublicKey::MultiXPub(x) = k else {
            panic!("expected MultiXPub")
        };
        OXpub::new(x.origin, x.xkey)
    }

    fn k1() -> OXpub {
        oxpub_from_str("[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*")
    }

    fn k2() -> OXpub {
        oxpub_from_str("[abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*")
    }

    #[test]
    fn semantic_starting_index_by_role() {
        // Primary: no locktime + Single/Multi.
        let primary = Semantic::Single(k1());
        assert_eq!(primary.starting_index(&Locktime::None), Some(512));

        // Csv recovery: relative locktime + Single/Multi.
        let csv = Semantic::Single(k1());
        let rel = Locktime::Relative(relative::LockTime::from_height(144));
        assert_eq!(csv.starting_index(&rel), Some(1024));

        // Csv with mandatory key: relative locktime + MultiWithMandatory.
        let mk = Semantic::MultiWithMandatory {
            keys: vec![k1(), k2()],
            mandatory_keys: vec![k2()],
            threshold: 2,
        };
        assert_eq!(mk.starting_index(&rel), Some(1536));

        // Cltv recovery: absolute locktime + Single/Multi.
        let cltv = Semantic::Single(k1());
        let abs = Locktime::AbsoluteRenewable(absolute::LockTime::from_height(824320).unwrap());
        assert_eq!(cltv.starting_index(&abs), Some(2048));

        // Off-table combinations return None.
        assert_eq!(mk.starting_index(&Locktime::None), None);
    }

    #[test]
    fn policy_new_rejects_empty() {
        assert!(matches!(
            Policy::new(vec![], PolicyType::Csv),
            Err(PolicyError::EmptyPaths)
        ));
    }

    #[test]
    fn policy_new_rejects_unknown_type() {
        let p = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        assert!(matches!(
            Policy::new(vec![p], PolicyType::Unknown),
            Err(PolicyError::UnknownNotConstructable)
        ));
    }

    #[test]
    fn cltv_rejects_unaligned_renewable() {
        // AbsoluteRenewable claims alignment - 824321 isn't on the 1024 grid → reject.
        let height = 824321;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        assert!(matches!(
            Policy::new(vec![primary, recov], PolicyType::Cltv),
            Err(PolicyError::UnalignedCltv(h)) if h == height
        ));
    }

    #[test]
    fn cltv_accepts_unaligned_foreign() {
        // The same unaligned height wrapped as Locktime::Absolute (foreign) is accepted.
        let height = 824321;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Absolute(lt),
            TapPosition::TapTree(vec![]),
        );
        let p = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        assert_eq!(p.policy_type(), PolicyType::Cltv);
    }

    #[test]
    fn cltv_accepts_aligned_height() {
        let height = 824320; // 805 * 1024
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let p = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        assert_eq!(p.policy_type(), PolicyType::Cltv);
        assert!(p.descriptor().is_none());
    }

    #[test]
    fn csv_rejects_absolute_locktime() {
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let bad = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        assert!(matches!(
            Policy::new(vec![primary, bad], PolicyType::Csv),
            Err(PolicyError::InconsistentPathsForType(PolicyType::Csv))
        ));
    }

    #[test]
    fn cltv_compile_then_parse_round_trip() {
        // Compile a Cltv policy with an aligned height; parser sees AbsoluteRenewable back.
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        // Aligned heights round-trip as AbsoluteRenewable (parser detects alignment).
        let has_renewable = parsed
            .paths()
            .iter()
            .any(|p| matches!(p.locktime(), Locktime::AbsoluteRenewable(_)));
        assert!(
            has_renewable,
            "no Locktime::AbsoluteRenewable in parsed paths for {}",
            desc
        );
    }

    #[test]
    fn cltv_compile_emits_after() {
        // Build a Cltv policy: one primary key on the internal key, one recovery key behind an
        // absolute timelock in the tap tree. Compile and assert that:
        //   - the resulting descriptor is Tr,
        //   - it contains `after(<aligned_height>)`,
        //   - the primary key sits in the primary role zone (<512;513>),
        //   - the recovery branch's keys live in the Cltv role zone (<2048;2049>).
        let height = 824320; // aligned to 1024
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains(&format!("after({height})")), "got {}", s);
        assert!(s.contains("<512;513>"), "got {}", s);
        assert!(s.contains("<2048;2049>"), "got {}", s);
    }

    #[test]
    fn csv_with_mandatory_round_trip() {
        // 1 mandatory + 2 cosigners, choosing 1 per leaf, total threshold 2. That gives
        // 2 leaves at <1536;1537> and <1538;1539> in the CsvWithMandatory role zone, which
        // is a power of 2 so both land at the same depth in the balanced binary tree.
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*");

        let lt = Locktime::Relative(relative::LockTime::from_height(144));
        let primary = Path::new(
            Semantic::Single(mandatory.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let path = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            lt,
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();

        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let mk_path = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiWithMandatory { .. }))
            .expect("expected a MultiWithMandatory path after recombine");
        if let Semantic::MultiWithMandatory {
            keys,
            mandatory_keys,
            threshold,
        } = mk_path.semantic()
        {
            assert_eq!(*threshold, 2);
            assert_eq!(mandatory_keys.len(), 1);
            assert_eq!(keys.len(), 2);
            assert_eq!(mandatory_keys[0].xkey, mandatory.xkey);
        } else {
            unreachable!("matched above");
        }
    }

    #[test]
    fn mandatory_threshold_must_exceed_mandatory_count() {
        // 1 mandatory + 2 cosigners but threshold=1 ≤ mandatory_count → reject.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let bad = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![k2(), oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")],
                mandatory_keys: vec![k1()],
                threshold: 1,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, bad], PolicyType::CsvWithMandatoryKey).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidMandatoryThreshold {
                threshold: 1,
                mandatory_count: 1,
                cosigner_count: 2
            }
        ));
    }

    #[test]
    fn satisfaction_wu_populated_after_compile_and_parse() {
        // After compile+parse, every TapTree path's satisfaction_wu must be Some(_) and > 0.
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        for p in parsed.paths() {
            if matches!(p.position(), TapPosition::TapTree(_)) {
                let w = p.satisfaction_wu().expect("expected wu for TapTree path");
                assert!(w > 0, "non-positive wu for TapTree path");
            }
        }
    }

    #[test]
    fn csv_with_mandatory_compile_emits_leaves() {
        // Build a CsvWithMandatoryKey policy with 1 mandatory + 2 cosigners and a *total*
        // threshold of 2 (1 mandatory + 1 cosigner per leaf). Picking 1 of 2 cosigners gives
        // 2 leaves; the path lives in the CsvWithMandatory role zone, so they get
        // multipath groups <1536;1537> and <1538;1539>.
        let mandatory = k1();
        let cosigner_a = k2();
        let cosigner_b = oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*");
        let primary = Path::new(
            Semantic::Single(mandatory.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![cosigner_a, cosigner_b],
                mandatory_keys: vec![mandatory],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains("<1536;1537>"), "missing <1536;1537> in {}", s);
        assert!(s.contains("<1538;1539>"), "missing <1538;1539> in {}", s);
    }

    #[test]
    fn non_pow2_mandatory_leaves_round_trip_at_same_depth() {
        // 1 mandatory + 3 cosigners, threshold 2 (1 mandatory + 1 cosigner per leaf).
        // Picking 1 of 3 cosigners gives 3 leaves, which is not a power of 2. The
        // floor-based builder must place all 3 leaves at the same depth (size-4 floor
        // with one NUMS padding leaf), and the parser must filter the padding leaf and
        // recognise the MultiWithMandatory shape on round-trip.
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*");
        let c3 = oxpub_from_str("[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*");

        let primary = Path::new(
            Semantic::Single(mandatory.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![c1, c2, c3],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );

        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();

        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let tap_tree = tr.tap_tree().as_ref().expect("tap tree present");
        let leaves: Vec<_> = tap_tree.iter().collect();
        assert_eq!(leaves.len(), 4, "size-4 floor: 3 real + 1 padding leaf");
        let real_depths: Vec<u8> = leaves
            .iter()
            .filter(|(_, ms)| !is_nums_padding_leaf(ms))
            .map(|(d, _)| *d)
            .collect();
        assert_eq!(real_depths.len(), 3);
        assert!(
            real_depths.iter().all(|&d| d == real_depths[0]),
            "all 3 real leaves must be at the same depth, got {:?}",
            real_depths
        );

        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let mk_parsed = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiWithMandatory { .. }))
            .expect("MultiWithMandatory path recovered after round-trip");
        if let Semantic::MultiWithMandatory {
            keys,
            mandatory_keys,
            threshold,
        } = mk_parsed.semantic()
        {
            assert_eq!(*threshold, 2);
            assert_eq!(mandatory_keys.len(), 1);
            assert_eq!(keys.len(), 3);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn internal_key_carries_seed_when_no_real_promotion() {
        // Multi primary + single timelocked recovery: no Single+Locktime::None candidate,
        // so no auto-promotion. Internal key falls back to NUMS, whose chain code must
        // equal what `analysis::unspendable_internal_xpub` recomputes.
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![k1(), k2()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let internal = tr.internal_key();
        let DescriptorPublicKey::MultiXPub(m) = internal else {
            panic!("internal key is not a MultiXPub")
        };
        assert_eq!(m.xkey.public_key, super::super::analysis::bip341_nums());
        let legacy = super::super::analysis::unspendable_internal_key(tr).expect("legacy key");
        let DescriptorPublicKey::MultiXPub(legacy_m) = legacy else {
            panic!("legacy key is not a MultiXPub")
        };
        assert_eq!(
            m.xkey.chain_code, legacy_m.xkey.chain_code,
            "new-style internal key chain code must match legacy unspendable_internal_xpub"
        );
    }

    #[test]
    fn first_padding_leaf_reuses_seed_when_internal_key_is_real() {
        // Primary single-key path + 3-leaf MultiWithMandatory recovery. The primary auto-
        // promotes to the internal key (real), so the first padding leaf takes the seed
        // chain code (= what the legacy detector would compute for a NUMS internal key).
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*");
        let c3 = oxpub_from_str("[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*");

        let primary = Path::new(
            Semantic::Single(k2()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mk_path = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![c1, c2, c3],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let legacy = super::super::analysis::unspendable_internal_key(tr).expect("legacy key");
        let DescriptorPublicKey::MultiXPub(legacy_m) = legacy else {
            panic!("legacy key is not a MultiXPub")
        };
        let seed = legacy_m.xkey.chain_code;

        let padding_leaves: Vec<_> = tr
            .tap_tree()
            .as_ref()
            .expect("tap tree present")
            .iter()
            .filter(|(_, ms)| is_nums_padding_leaf(ms))
            .collect();
        assert!(!padding_leaves.is_empty(), "expected at least one padding leaf");
        let first_padding = padding_leaves[0].1;
        let key = first_padding.iter_pk().next().expect("padding leaf has a key");
        let DescriptorPublicKey::MultiXPub(m) = key else {
            panic!("padding key is not MultiXPub")
        };
        assert_eq!(
            m.xkey.chain_code, seed,
            "first padding leaf chain code must equal the seed when internal key is real"
        );
    }

    #[test]
    fn padding_leaves_chain_via_sha256() {
        use miniscript::bitcoin::{bip32, hashes::sha256, hashes::Hash};
        // 1 mandatory + 5 cosigners, threshold 2 → C(5, 1) = 5 leaves. With auto-promoted
        // primary (single-key), the recovery subtree is size 8 with `m = 3` so the
        // canonical compaction exposes 2 free chunks (size 1 at depth 3, size 2 at
        // depth 2) → 2 padding leaves at distinct depths.
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*");
        let c3 = oxpub_from_str("[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*");
        let c4 = oxpub_from_str("[abcdef05]xpub661MyMwAqRbcEqgeH5cqyxRwY4UG21ey1MBJkNBX2xSTmGS9dCRmGQezqHE9mXUXzs9HqFzNEN2KkNw5o8xpqAXw2XxsVhGVm1LbRaEnxyT/<0;1>/*");
        let c5 = oxpub_from_str("[abcdef06]xpub661MyMwAqRbcEtYavp2XsS9QfH93wyVQnkWenWxWuWdaxDtjBqfzFfWPY83z3da5oYv2XmwgTT97GhGwX9HUGDEP4FERzzgmwaGNAz1emZr/<0;1>/*");

        let primary = Path::new(
            Semantic::Single(k2()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mk_path = Path::new(
            Semantic::MultiWithMandatory {
                keys: vec![c1, c2, c3, c4, c5],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };

        let padding_chain_codes: Vec<bip32::ChainCode> = tr
            .tap_tree()
            .as_ref()
            .expect("tap tree present")
            .iter()
            .filter_map(|(_, ms)| {
                if !is_nums_padding_leaf(ms) {
                    return None;
                }
                let key = ms.iter_pk().next()?;
                let DescriptorPublicKey::MultiXPub(m) = key else {
                    return None;
                };
                Some(m.xkey.chain_code)
            })
            .collect();
        assert!(
            padding_chain_codes.len() >= 2,
            "expected at least 2 padding leaves to exercise chaining, got {}",
            padding_chain_codes.len()
        );
        for w in padding_chain_codes.windows(2) {
            let prev_bytes = w[0].to_bytes();
            let expected: [u8; 32] = sha256::Hash::hash(prev_bytes.as_ref()).to_byte_array();
            assert_eq!(
                w[1].to_bytes(),
                expected,
                "consecutive padding leaves must chain via sha256"
            );
        }
    }

    #[test]
    fn legacy_csv_layout_parses_as_csv() {
        use miniscript::Descriptor;
        // Hand-rolled Csv-shape Tr descriptor using the legacy `<0;1>` (primary) / `<2;3>`
        // (recovery) adjacent-multipath layout. The compiler now emits the new 512+ layout,
        // but on-chain wallets created with the legacy layout must keep parsing as Csv.
        let s = "tr([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*,and_v(v:pk([abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<2;3>/*),older(144)))";
        let desc = Descriptor::<DescriptorPublicKey>::from_str(s).unwrap();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
    }

    #[test]
    fn csv_compile_emits_role_based_layout() {
        // Smoke test: Csv with primary on the internal key + a single relative-locked recovery
        // leaf must place primary at <512;513> (Primary role) and recovery at <1024;1025>
        // (Csv recovery role).
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains("<512;513>"), "missing <512;513> in {}", s);
        assert!(s.contains("<1024;1025>"), "missing <1024;1025> in {}", s);
    }

    #[test]
    fn csv_with_mandatory_requires_mandatory_path() {
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov_seq = relative::LockTime::from_height(144);
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(recov_seq),
            TapPosition::TapTree(vec![]),
        );
        // No MultiWithMandatory anywhere - should reject.
        assert!(matches!(
            Policy::new(vec![primary, recov], PolicyType::CsvWithMandatoryKey),
            Err(PolicyError::NoMandatoryKeyPath)
        ));
    }

    #[test]
    fn start_index_populated_after_compile() {
        // After compile, both paths must carry their assigned multipath base via start_index.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        assert_eq!(policy.paths()[1].start_index(), Some(1024));
    }

    #[test]
    fn csv_recoveries_sorted_by_relative_height() {
        // Two recovery paths inserted with the larger height first; both `order = None`. The
        // pre-emit pass must sort them by ascending locktime height, so `older(144)` lands at
        // the lower slot in the Csv zone.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let big = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(1000)),
            TapPosition::TapTree(vec![]),
        );
        let small = Path::new(
            Semantic::Single(oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, big, small], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        // primary at 512; small (older(144)) at 1024; big (older(1000)) at 1028.
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        assert_eq!(policy.paths()[1].start_index(), Some(1028));
        assert_eq!(policy.paths()[2].start_index(), Some(1024));
    }

    #[test]
    fn caller_order_overrides_timelock_sort() {
        // Same two recoveries as above, but the caller forces `older(1000)` to come before
        // `older(144)` in the global tap-tree order. The Csv-zone walk visits the
        // `older(1000)` path first → start_index = 1024; then `older(144)` → 1028.
        let mut primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        primary.set_order(Some(0));
        let mut big = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(1000)),
            TapPosition::TapTree(vec![]),
        );
        big.set_order(Some(1));
        let small = Path::new(
            Semantic::Single(oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, big, small], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        assert_eq!(policy.paths()[1].start_index(), Some(1024));
        assert_eq!(policy.paths()[2].start_index(), Some(1028));
    }

    #[test]
    fn path_order_reorders_tap_tree() {
        // Build a Cltv policy with both paths in the tap tree (no InternalKey path), then
        // pin recovery to global slot 0 and primary to slot 1. The first leaf in the tap
        // tree must then be the recovery leaf, i.e. `after(...)` shows up before the
        // primary's `pk` in the tap-tree iteration.
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let mut primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        primary.set_order(Some(1));
        let mut recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        recov.set_order(Some(0));
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let tap_tree = tr.tap_tree().as_ref().expect("tap tree present");
        let (_, first_leaf) = tap_tree.iter().next().expect("at least one leaf");
        let s = first_leaf.to_string();
        assert!(
            s.contains(&format!("after({height})")),
            "{}",
            format!("first leaf should be the recovery (`after`) path; got `{s}`"),
        );
    }

    #[test]
    fn duplicate_order_groups_leaves_at_one_depth() {
        // Two recoveries declare `order = Some(1)` and form a single priority group.
        // `tree_builder::build` concatenates their leaves into one `place_path` call,
        // so both land at the same tap-leaf depth.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mut recov_a = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        recov_a.set_order(Some(1));
        let mut recov_b = Path::new(
            Semantic::Single(oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")),
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        recov_b.set_order(Some(1));
        let mut policy = Policy::new(vec![primary, recov_a, recov_b], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let tap_tree = tr.tap_tree().as_ref().expect("tap tree present");
        let recov_depths: Vec<u8> = tap_tree
            .iter()
            .filter_map(|(d, ms)| ms.to_string().contains("older(").then_some(d))
            .collect();
        assert_eq!(recov_depths.len(), 2, "expected both recovery leaves");
        assert_eq!(
            recov_depths[0], recov_depths[1],
            "same-order recoveries must share tap-leaf depth"
        );
    }

    #[test]
    fn order_treats_caller_values_as_relative_ranking() {
        // Caller orders are gaps + values larger than path count: 7 and 100. Both should
        // be accepted; relative ranking puts the path with order=7 before the one with
        // order=100, and any unset paths after both. After compile the resolved positions
        // collapse into the dense slot range 0..N.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mut later = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(1000)),
            TapPosition::TapTree(vec![]),
        );
        later.set_order(Some(100));
        let mut earlier = Path::new(
            Semantic::Single(oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        earlier.set_order(Some(7));
        let mut policy = Policy::new(vec![primary, later, earlier], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        // primary auto-promotes to InternalKey at start_index 512.
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        // earlier (order=7) gets the lower Csv slot, later (order=100) gets the next.
        assert_eq!(policy.paths()[2].start_index(), Some(1024));
        assert_eq!(policy.paths()[1].start_index(), Some(1028));
    }

    #[test]
    fn sanitize_passes_for_valid_policy() {
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        assert!(policy.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_two_primaries() {
        // Two Locktime::None paths → InvalidPrimaryCount(2). `Policy::new` runs sanitize so
        // the rejection lands at construction.
        let p1 = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let p2 = Path::new(
            Semantic::Single(k2()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![p1, p2, recov], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPrimaryCount(2)),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn sanitize_rejects_internal_key_with_locktime() {
        // InternalKey path with a non-None locktime is structurally invalid. With a proper
        // primary in the tap tree the primary-count rule passes, and sanitize's per-path
        // InternalKey-position check is the gate that fires.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let bad = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, bad, recov], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::InternalKeyWithLocktime),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn sanitize_rejects_no_primary() {
        // Zero Locktime::None paths → InvalidPrimaryCount(0).
        let r1 = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let r2 = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![r1, r2], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPrimaryCount(0)),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn sanitize_rejects_duplicate_csv_timelock() {
        // Two recovery paths sharing the same `older(144)` height → DuplicateTimelock(144).
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let r1 = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let r2 = Path::new(
            Semantic::Single(oxpub_from_str("[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*")),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, r1, r2], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::DuplicateTimelock(144)),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn compile_auto_promotes_single_primary_to_internal_key() {
        // Caller forgot to put the Single primary on `TapPosition::InternalKey`. After
        // compile, that path should land at the Tr internal key and the descriptor's
        // internal key should be the caller's xpub (not a NUMS unspendable).
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        // The promoted path's position is now InternalKey.
        assert!(matches!(
            policy.paths()[0].position(),
            TapPosition::InternalKey
        ));
        // And the rendered descriptor's internal key carries the primary's xpub fingerprint.
        let s = desc.to_string();
        assert!(
            s.contains("[abcdef01]"),
            "{}",
            format!("primary xpub should appear at the Tr internal key; got `{s}`"),
        );
    }

    #[test]
    fn compile_promotes_first_ordered_single_primary() {
        // Caller pinned `order = Some(0)` on the Single primary. It's still a candidate
        // for promotion (caller-set order doesn't opt out anymore, the promotion picks
        // by lowest order to align with the caller's tap-tree intent).
        let mut primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        primary.set_order(Some(0));
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        assert!(matches!(
            policy.paths()[0].position(),
            TapPosition::InternalKey
        ));
    }
}

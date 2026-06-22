//! `SemanticDescriptor`: top-level dispatcher between the legacy [`LianaDescriptor`] (WSH and
//! legacy Tr Csv) and the new Tr-only [`bup::Policy`] flow.

use std::str::FromStr;

use bup::{Policy, PolicyError, PolicyType};
use miniscript::{Descriptor, DescriptorPublicKey};

use super::{LianaDescError, LianaDescriptor, LianaPolicyError};

/// Wraps either today's `LianaDescriptor` (WSH or legacy Tr Csv) or the new `bup::Policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SemanticDescriptor {
    Legacy(LianaDescriptor),
    Policy(Policy),
}

impl SemanticDescriptor {
    /// Parse a descriptor string. Tries the legacy path first; falls back to [`Policy::from_descriptor`]
    /// only when legacy parsing fails on a Tr input.
    ///
    /// Not a `FromStr` impl, since that would conflict with miniscript's blanket impls.
    pub fn parse_str(s: &str) -> Result<Self, LianaDescError> {
        match LianaDescriptor::from_str(s) {
            Ok(legacy) => Ok(SemanticDescriptor::Legacy(legacy)),
            Err(legacy_err) => {
                let desc = match Descriptor::<DescriptorPublicKey>::from_str(s) {
                    Ok(d) => d,
                    Err(_) => return Err(legacy_err),
                };
                if !matches!(desc, Descriptor::Tr(_)) {
                    return Err(legacy_err);
                }
                Policy::from_descriptor(&desc)
                    .map(SemanticDescriptor::Policy)
                    .map_err(|e| match e {
                        PolicyError::Miniscript(_) | PolicyError::Multipath(_) => {
                            LianaDescError::BupPolicy(e)
                        }
                        _ => LianaDescError::Policy(LianaPolicyError::IncompatibleDesc),
                    })
                    .or(Err(legacy_err))
            }
        }
    }

    pub fn as_legacy(&self) -> Option<&LianaDescriptor> {
        match self {
            SemanticDescriptor::Legacy(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_policy(&self) -> Option<&Policy> {
        match self {
            SemanticDescriptor::Policy(p) => Some(p),
            _ => None,
        }
    }

    /// `Legacy` reports [`PolicyType::Csv`]; `Policy` returns its tag.
    pub fn policy_type(&self) -> PolicyType {
        match self {
            SemanticDescriptor::Legacy(_) => PolicyType::Csv,
            SemanticDescriptor::Policy(p) => p.policy_type(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_csv_descriptor_does_not_reach_policy_parser() {
        let s = "wsh(or_d(pk([aabbccdd]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),and_v(v:pkh([aabbccdd]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*),older(52560))))#7437yjrs";
        let sd = SemanticDescriptor::parse_str(s).unwrap();
        assert!(matches!(sd, SemanticDescriptor::Legacy(_)));
        assert_eq!(sd.policy_type(), PolicyType::Csv);
    }
}

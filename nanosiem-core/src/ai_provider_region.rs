// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regional AI metadata retained for compatibility with existing renderers.
//!
//! NAN-3749: all hosted regions use the platform's Cloudflare Workers AI,
//! just like US tenants. A region value does not restrict providers, gateway
//! processing location, or model IDs. Malformed metadata is still rejected.

use thiserror::Error;

pub const AI_PROVIDER_REGION_ENV: &str = "NANO_AI_PROVIDER_REGION";

/// Accepted legacy AWS region metadata. Exact match only.
pub const AWS_REGION_IDS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "us-gov-east-1",
    "us-gov-west-1",
    "ca-central-1",
    "ca-west-1",
    "mx-central-1",
    "sa-east-1",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "ap-east-1",
    "ap-east-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-southeast-7",
    "il-central-1",
    "me-central-1",
    "me-south-1",
    "af-south-1",
];

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AiRegionRefusal {
    #[error("the region's AI provider region is not a valid AWS region id")]
    InvalidPin,
}

/// Legacy region metadata; valid values do not impose an AI residency policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AiProviderRegionPin {
    #[default]
    Unpinned,
    Pinned(&'static str),
    Invalid,
}

pub fn aws_region_id(value: &str) -> Option<&'static str> {
    AWS_REGION_IDS.iter().copied().find(|id| *id == value)
}

impl AiProviderRegionPin {
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            None => Self::Unpinned,
            Some(value) => aws_region_id(value).map_or(Self::Invalid, Self::Pinned),
        }
    }

    pub fn from_env() -> Self {
        match std::env::var(AI_PROVIDER_REGION_ENV) {
            Err(std::env::VarError::NotPresent) => Self::Unpinned,
            Err(std::env::VarError::NotUnicode(_)) => Self::Invalid,
            Ok(value) => Self::parse(Some(&value)),
        }
    }

    pub fn validate(self) -> Result<(), AiRegionRefusal> {
        match self {
            Self::Invalid => Err(AiRegionRefusal::InvalidPin),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regional_metadata_accepts_every_region_without_a_residency_gate() {
        assert_eq!(AiProviderRegionPin::parse(None), AiProviderRegionPin::Unpinned);
        assert!(AiProviderRegionPin::Unpinned.validate().is_ok());
        for region in AWS_REGION_IDS {
            let pin = AiProviderRegionPin::parse(Some(region));
            assert_eq!(pin, AiProviderRegionPin::Pinned(region));
            assert_eq!(pin.validate(), Ok(()));
        }
    }

    #[test]
    fn malformed_metadata_is_rejected() {
        for bad in ["", " ap-southeast-2", "AP-SOUTHEAST-2", "aus-syd-1", "ap-southeast-9"] {
            let pin = AiProviderRegionPin::parse(Some(bad));
            assert_eq!(pin, AiProviderRegionPin::Invalid);
            assert_eq!(pin.validate(), Err(AiRegionRefusal::InvalidPin));
        }
    }
}

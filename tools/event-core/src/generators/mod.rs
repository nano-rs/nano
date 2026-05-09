//! Profile-driven event generators
//!
//! Each generator produces events that match the real format
//! Vector expects, using profile data from the Ludus lab.

pub mod apache;
pub mod cloudtrail;
pub mod lateral_chain;
pub mod proxy;
pub mod sysmon;
pub mod winevt;

pub use apache::ApacheGenerator;
pub use cloudtrail::CloudTrailGenerator;
pub use lateral_chain::LateralChainGenerator;
pub use proxy::ProxyGenerator;
pub use sysmon::SysmonGenerator;
pub use winevt::WindowsEventGenerator;

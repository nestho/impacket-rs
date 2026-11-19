//! `impacket-experimental`: Bleeding-edge offensive research sandbox.
//!
//! Houses rapid prototypes, novel Active Directory authentication primitives,
//! zero-footprint reconnaissance implementations, and experimental RPC coercion techniques.
//! Features are gated behind explicit Cargo feature flags.

#[cfg(feature = "fast")]
pub mod fast;

#[cfg(feature = "adws")]
pub mod adws;

#[cfg(feature = "sapphire")]
pub mod sapphire;

#[cfg(feature = "coercion")]
pub mod coercion;

/// Returns the status of active experimental feature modules.
pub fn active_experimental_features() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut features = Vec::new();
    #[cfg(feature = "fast")]
    features.push("fast (RFC 6113 Kerberos Armoring)");
    #[cfg(feature = "adws")]
    features.push("adws (TCP 9389 SOAP Stealth Recon)");
    #[cfg(feature = "sapphire")]
    features.push("sapphire (S4U2Self PAC Transplant)");
    #[cfg(feature = "coercion")]
    features.push("coercion (Multi-Protocol Coercer)");
    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_experimental_registry() {
        let active = active_experimental_features();
        println!("Active experimental features: {:?}", active);
    }
}

//! Netinject provides a high level API for creating and deleting iptables rules which drop
//! packets. It's designed to help you test network failure scenarios.
//!
//! It can be used as a library, a script, and has a cleanup method which is specifically designed
//! for use from a daemon which can clean up after itself on exit.
mod error;
mod iptables_helpers;

extern crate iptables;

use error::{ipt_to_netinject_err, NetinjectResult};
use iptables::error::IPTResult;
use iptables::IPTables;
use iptables_helpers::{append_unique, delete, delete_chain, new_chain};

/// Specifies the protocol of the dropped packet. To drop multiple protocols, multiple rules should
/// be created.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub enum Protocol {
    TCP,
    UDP,
}

/// Specifies whether an inbound our outbound packet should be dropped. To drop in both directions,
/// two rules should be created.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Used to identify a packet to be dropped. When a rule is created, only packets for that
/// protocol, port, and direction will be dropped.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub struct Ident {
    pub protocol: Protocol,
    pub port: u16,
    pub direction: Direction,
}

// The filter table is a system defined iptables table where packet dropping rules are inserted.
const FILTER_TABLE: &str = "filter";

// The INPUT and OUTPUT chains are system defined iptables chains on the filter table. All inbound
// and outbound packets will pass by these chains.
const FILTER_INPUT_CHAIN: &str = "INPUT";
const FILTER_OUTPUT_CHAIN: &str = "OUTPUT";

// The NETINJECT_INPUT and NETINJECT_OUTPUT chains are defined by netinject. This is where
// netinject inserts rules for dropping inbound and outbound packets.
const NETINJECT_INPUT_CHAIN: &str = "NETINJECT_INPUT";
const NETINJECT_OUTPUT_CHAIN: &str = "NETINJECT_OUTPUT";

impl Ident {
    fn rule(&self) -> String {
        let protocol = match self.protocol {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
        };
        format!("-p {} --dport {} -j DROP", protocol, self.port.to_string())
    }

    fn chain(&self) -> &str {
        match self.direction {
            Direction::Inbound => NETINJECT_INPUT_CHAIN,
            Direction::Outbound => NETINJECT_OUTPUT_CHAIN,
        }
    }
}

/// Defines an API for creating and deleting iptables rules for dropping packets.
pub struct Netinject {
    ipt: IPTables,
}

impl Netinject {
    /// Initializes a Netinject for either IPv4 or IPv6 packets. Creating a new Netinject will
    /// mutate the systems iptables by adding chains and rules to the filter table.
    pub fn new(is_ipv6: bool) -> NetinjectResult<Netinject> {
        let ipt = iptables::new(is_ipv6).map_err(ipt_to_netinject_err)?;

        // Create our custom input chain.
        new_chain(&ipt, FILTER_TABLE, NETINJECT_INPUT_CHAIN).map_err(ipt_to_netinject_err)?;
        // Hook our custom input chain into the system's input chain so that all inbound packets
        // pass by our custom input chain.
        append_unique(
            &ipt,
            FILTER_TABLE,
            FILTER_INPUT_CHAIN,
            &format!("-j {}", NETINJECT_INPUT_CHAIN),
        )
        .map_err(ipt_to_netinject_err)?;

        // Create our custom output chain.
        new_chain(&ipt, FILTER_TABLE, NETINJECT_OUTPUT_CHAIN).map_err(ipt_to_netinject_err)?;
        // Hook our custom output chain into the system's output chain so that all outbound packets
        // pass by our custom output chain.
        append_unique(
            &ipt,
            FILTER_TABLE,
            FILTER_OUTPUT_CHAIN,
            &format!("-j {}", NETINJECT_OUTPUT_CHAIN),
        )
        .map_err(ipt_to_netinject_err)?;

        Ok(Netinject { ipt: ipt })
    }

    /// Creates an iptables rule which drops all packets matching the provided identifier.
    pub fn create(&self, ident: Ident) -> IPTResult<()> {
        self.ipt
            .append_unique(FILTER_TABLE, ident.chain(), &ident.rule())
    }

    /// Deletes a previously created iptables rule matching the provided identifier.
    pub fn delete(&self, ident: Ident) -> IPTResult<()> {
        self.ipt.delete(FILTER_TABLE, ident.chain(), &ident.rule())
    }

    /// Deletes all previously created iptables rules.
    pub fn delete_all(&self) -> IPTResult<()> {
        self.ipt.flush_chain(FILTER_TABLE, NETINJECT_INPUT_CHAIN)?;
        self.ipt.flush_chain(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN)
    }

    /// Removes all chains and rules that this program has created, leaving the system how it was
    /// to begin with.
    pub fn cleanup(&self) -> IPTResult<()> {
        delete(
            &self.ipt,
            FILTER_TABLE,
            FILTER_INPUT_CHAIN,
            &format!("-j {}", NETINJECT_INPUT_CHAIN),
        )?;
        delete_chain(&self.ipt, FILTER_TABLE, NETINJECT_INPUT_CHAIN)?;
        delete(
            &self.ipt,
            FILTER_TABLE,
            FILTER_OUTPUT_CHAIN,
            &format!("-j {}", NETINJECT_OUTPUT_CHAIN),
        )?;
        delete_chain(&self.ipt, FILTER_TABLE, NETINJECT_OUTPUT_CHAIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4: bool = false;

    #[test]
    fn test_init_and_cleanup() {
        let ipt = iptables::new(IPV4).unwrap();
        // Ensure test environment didn't leak from last test run.
        assert_exists(&ipt, false);

        let n1 = Netinject::new(IPV4).unwrap();
        assert_exists(&ipt, true);
        // Init a second time to make sure it doesn't error.
        let n2 = Netinject::new(IPV4).unwrap();
        assert_exists(&ipt, true);

        n1.cleanup().unwrap();
        assert_exists(&ipt, false);
        // Cleanup a second time to make sure it doesn't error.
        n2.cleanup().unwrap();
        assert_exists(&ipt, false);
    }

    #[test]
    fn test_create_and_delete() {
        let ipt = iptables::new(IPV4).unwrap();
        // Ensure test environment didn't leak from last test run.
        assert_exists(&ipt, false);

        let n = Netinject::new(IPV4).unwrap();

        let ident1 = Ident {
            protocol: Protocol::TCP,
            port: 5555,
            direction: Direction::Inbound,
        };
        let ident2 = Ident {
            protocol: Protocol::TCP,
            port: 5555,
            direction: Direction::Outbound,
        };

        let ident1_rule = ident1.rule();
        let ident2_rule = ident2.rule();

        n.create(ident1).unwrap();
        n.create(ident2).unwrap();
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_INPUT_CHAIN, &ident1_rule)
                .unwrap(),
            true
        );
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN, &ident2_rule)
                .unwrap(),
            true
        );

        n.delete(ident1).unwrap();
        n.delete(ident2).unwrap();
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_INPUT_CHAIN, &ident1_rule)
                .unwrap(),
            false
        );
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN, &ident2_rule)
                .unwrap(),
            false
        );

        n.cleanup().unwrap();
        assert_exists(&ipt, false);
    }

    #[test]
    fn test_create_and_delete_all() {
        let ipt = iptables::new(IPV4).unwrap();
        // Ensure test environment didn't leak from last test run.
        assert_exists(&ipt, false);

        let n = Netinject::new(IPV4).unwrap();

        let ident1 = Ident {
            protocol: Protocol::TCP,
            port: 5555,
            direction: Direction::Inbound,
        };
        let ident2 = Ident {
            protocol: Protocol::TCP,
            port: 5555,
            direction: Direction::Outbound,
        };

        let ident1_rule = ident1.rule();
        let ident2_rule = ident2.rule();

        n.create(ident1).unwrap();
        n.create(ident2).unwrap();
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_INPUT_CHAIN, &ident1_rule)
                .unwrap(),
            true
        );
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN, &ident2_rule)
                .unwrap(),
            true
        );

        n.delete_all().unwrap();
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_INPUT_CHAIN, &ident1_rule)
                .unwrap(),
            false
        );
        assert_eq!(
            ipt.exists(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN, &ident2_rule)
                .unwrap(),
            false
        );

        n.cleanup().unwrap();
        assert_exists(&ipt, false);
    }

    fn assert_exists(ipt: &IPTables, exists: bool) {
        assert_eq!(
            ipt.exists(
                FILTER_TABLE,
                FILTER_INPUT_CHAIN,
                &format!("-j {}", NETINJECT_INPUT_CHAIN)
            )
            .unwrap(),
            exists
        );
        assert_eq!(
            ipt.chain_exists(FILTER_TABLE, NETINJECT_INPUT_CHAIN)
                .unwrap(),
            exists
        );
        assert_eq!(
            ipt.exists(
                FILTER_TABLE,
                FILTER_OUTPUT_CHAIN,
                &format!("-j {}", NETINJECT_OUTPUT_CHAIN)
            )
            .unwrap(),
            exists
        );
        assert_eq!(
            ipt.chain_exists(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN)
                .unwrap(),
            exists
        );
    }
}

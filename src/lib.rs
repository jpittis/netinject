//! Netinject provides a high level API for creating and deleting iptables rules which drop
//! packets. It's designed to help you test network failure scenarios.
//!
//! It can be used as a library, a script, and has a cleanup method which is specifically designed
//! for use from a daemon which can clean up after itself on exit.
extern crate iptables;

use iptables::error::IPTResult;
use iptables::IPTables;

/// Specifies the protocol of the dropped packet. To drop multiple protocols, multiple rules should
/// be created.
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Protocol {
    TCP,
    UDP,
}

/// Specifies whether an inbound our outbound packet should be dropped. To drop in both directions,
/// two rules should be created.
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Used to identify a packet to be dropped. When a rule is created, only packets for that
/// protocol, port, and direction will be dropped.
#[derive(Hash, Eq, PartialEq, Debug)]
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
    pub fn new(is_ipv6: bool) -> IPTResult<Netinject> {
        let ipt = iptables::new(is_ipv6)?;
        // Create our custom input chain.
        ipt.new_chain(FILTER_TABLE, NETINJECT_INPUT_CHAIN)?;
        // Hook our custom input chain into the system's input chain so that all inbound packets
        // pass by our custom input chain.
        ipt.append_unique(
            FILTER_TABLE,
            FILTER_INPUT_CHAIN,
            &format!("-j {}", NETINJECT_INPUT_CHAIN),
        )?;
        // Create our custom output chain.
        ipt.new_chain(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN)?;
        // Hook our custom output chain into the system's output chain so that all outbound packets
        // pass by our custom output chain.
        ipt.append_unique(
            FILTER_TABLE,
            FILTER_OUTPUT_CHAIN,
            &format!("-j {}", NETINJECT_OUTPUT_CHAIN),
        )?;
        Ok(Netinject { ipt: ipt })
    }

    /// Creates an iptables rule which drops all packets matching the provided identifier.
    pub fn create(&mut self, ident: Ident) -> IPTResult<bool> {
        self.ipt
            .append_unique(FILTER_TABLE, ident.chain(), &ident.rule())
    }

    /// Deletes a previously created iptables rule matching the provided identifier.
    pub fn delete(&mut self, ident: Ident) -> IPTResult<bool> {
        self.ipt.delete(FILTER_TABLE, ident.chain(), &ident.rule())
    }

    /// Deletes all previously created iptables rules.
    pub fn delete_all(&mut self) -> IPTResult<bool> {
        self.ipt.flush_chain(FILTER_TABLE, NETINJECT_INPUT_CHAIN)?;
        self.ipt.flush_chain(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN)
    }

    /// Removes all chains and rules that this program has created, leaving the system how it was
    /// to begin with.
    pub fn cleanup(&mut self) -> IPTResult<bool> {
        self.ipt.delete(
            FILTER_TABLE,
            FILTER_INPUT_CHAIN,
            &format!("-j {}", NETINJECT_INPUT_CHAIN),
        )?;
        self.ipt.delete_chain(FILTER_TABLE, NETINJECT_INPUT_CHAIN)?;
        self.ipt.delete(
            FILTER_TABLE,
            FILTER_OUTPUT_CHAIN,
            &format!("-j {}", NETINJECT_OUTPUT_CHAIN),
        )?;
        self.ipt.delete_chain(FILTER_TABLE, NETINJECT_OUTPUT_CHAIN)
    }
}

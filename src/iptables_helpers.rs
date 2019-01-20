extern crate iptables;

use iptables::error::{IPTError, IPTResult};
use iptables::IPTables;

/// Behaves like new_chain except it does not produce an error when the chain already exists.
pub fn new_chain(ipt: &IPTables, table: &str, chain: &str) -> IPTResult<()> {
    match ipt.new_chain(table, chain) {
        // Chain was created.
        Ok(()) => Ok(()),
        // Chain already exists.
        Err(IPTError::BadExitStatus(1)) => Ok(()),
        err => err,
    }
}

/// Behaves just like append_uniquee except it does not produce an error when the rule already
/// exists.
pub fn append_unique(ipt: &IPTables, table: &str, chain: &str, rule: &str) -> IPTResult<()> {
    match ipt.append_unique(table, chain, rule) {
        // Rule was appended.
        Ok(()) => Ok(()),
        // Rule already exists.
        Err(IPTError::Other("the rule exists in the table/chain")) => Ok(()),
        err => err,
    }
}

/// Behaves just like delete except it does not produce an error when the rule does not exist or
/// when the jump target does not exist.
pub fn delete(ipt: &IPTables, table: &str, chain: &str, rule: &str) -> IPTResult<()> {
    match ipt.delete(table, chain, rule) {
        // Rule was deleted.
        Ok(()) => Ok(()),
        // Rule was not found.
        Err(IPTError::BadExitStatus(1)) => Ok(()),
        // Jump target chain was not found.
        Err(IPTError::BadExitStatus(2)) => Ok(()),
        err => err,
    }
}

/// Behaves just like delete_chain except it does produce an error when the chain does not exist.
pub fn delete_chain(ipt: &IPTables, table: &str, chain: &str) -> IPTResult<()> {
    match ipt.delete_chain(table, chain) {
        // Chain was deleted.
        Ok(()) => Ok(()),
        // Chain was not found.
        Err(IPTError::BadExitStatus(1)) => Ok(()),
        err => err,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const IPV4: bool = false;

    #[test]
    fn test_create_and_delete() {
        let ipt = iptables::new(IPV4).unwrap();
        // Ensure test environment didn't leak from last test run.
        assert_exists(&ipt, false);

        // Create a custom chain and rule.
        new_chain(&ipt, "filter", "CUSTOM_INPUT").unwrap();
        append_unique(&ipt, "filter", "INPUT", "-j CUSTOM_INPUT").unwrap();
        assert_exists(&ipt, true);

        // Create them a second time and ensure they don't produce errors.
        new_chain(&ipt, "filter", "CUSTOM_INPUT").unwrap();
        append_unique(&ipt, "filter", "INPUT", "-j CUSTOM_INPUT").unwrap();
        assert_exists(&ipt, true);

        // Delete the custom chain and rule.
        delete(&ipt, "filter", "INPUT", "-j CUSTOM_INPUT").unwrap();
        delete_chain(&ipt, "filter", "CUSTOM_INPUT").unwrap();
        assert_exists(&ipt, false);

        // Delete  them a second time to ensure they don't produce errors.
        delete(&ipt, "filter", "INPUT", "-j CUSTOM_INPUT").unwrap();
        delete_chain(&ipt, "filter", "CUSTOM_INPUT").unwrap();
        assert_exists(&ipt, false);
    }

    fn assert_exists(ipt: &IPTables, exists: bool) {
        assert_eq!(
            ipt.exists("filter", "INPUT", "-j CUSTOM_INPUT").unwrap(),
            exists
        );
        assert_eq!(ipt.chain_exists("filter", "CUSTOM_INPUT").unwrap(), exists);
    }
}

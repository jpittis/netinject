use iptables::error::IPTError;

#[derive(Debug)]
pub enum NetinjectError {
    PermissionDenied,
    IPTError(IPTError),
}

pub type NetinjectResult<T> = Result<T, NetinjectError>;

pub fn ipt_to_netinject_err(err: IPTError) -> NetinjectError {
    match err {
        IPTError::BadExitStatus(4) => NetinjectError::PermissionDenied,
        err => NetinjectError::IPTError(err),
    }
}

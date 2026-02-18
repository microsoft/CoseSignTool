use crate::ossl_wrappers::{EvpKey, EvpMdContext, VerifyOp};

use openssl_sys as ossl;

pub fn verify(key: &EvpKey, sig: &[u8], msg: &[u8]) -> Result<bool, String> {
    unsafe {
        let ctx = EvpMdContext::<VerifyOp>::new(key)?;

        let res = ossl::EVP_DigestVerify(
            ctx.ctx,
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
        );

        match res {
            1 => Ok(true),
            0 => Ok(false),
            err => Err(format!("Failed to verify signature, err: {}", err)),
        }
    }
}

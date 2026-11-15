//! EVM transactions (`evm.ts`): the [`EvmSigner`] seam and a local-key EIP-1559 signer. The plug-in always holds the signed raw
//! transaction before it is broadcast, so its hash is known up front: an ambiguous broadcast (#1121) is resolved by polling that
//! hash, never by signing a second transaction.

use alloc::string::String;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::crypto::{he, public_key, recover, sign_recoverable, uncompressed};
use super::errors::{Error, Result};
use super::rlp::{rlp_bytes, rlp_decode, rlp_list, rlp_u64_enc, rlp_uint, rlp_uint_enc};
use super::util::{arr, to_u64};

/// An unsigned EIP-1559 transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRequest {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: BigUint,
    pub max_fee_per_gas: BigUint,
    pub gas: u64,
    pub to: [u8; 20],
    pub value: BigUint,
    pub data: Vec<u8>,
}

/// A signed transaction: its exact bytes and hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTx {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
    pub request: TxRequest,
}

/// The wallet's EVM account. Implementations may be a hardware wallet or a remote signer; they only have to return the raw bytes.
pub trait EvmSigner {
    fn address(&self) -> [u8; 20];
    fn sign_transaction(&self, tx: &TxRequest) -> core::result::Result<Vec<u8>, String>;
}

fn fields(t: &TxRequest) -> Vec<Vec<u8>> {
    alloc::vec![
        rlp_u64_enc(t.chain_id),
        rlp_u64_enc(t.nonce),
        rlp_uint_enc(&t.max_priority_fee_per_gas),
        rlp_uint_enc(&t.max_fee_per_gas),
        rlp_u64_enc(t.gas),
        rlp_bytes(&t.to),
        rlp_uint_enc(&t.value),
        rlp_bytes(&t.data),
        rlp_list(&[]),
    ]
}

/// keccak256(0x02 || RLP(unsigned fields)): the EIP-1559 signing hash.
pub fn signing_hash(t: &TxRequest) -> [u8; 32] {
    he(&[&[0x02], &rlp_list(&fields(t))])
}

/// The address of a compressed secp256k1 public key.
pub fn address_of(pub33: &[u8]) -> [u8; 20] {
    let p = uncompressed(pub33).expect("nb2: a valid public key");
    arr(&he(&[&p])[12..])
}

/// A signer holding its key in memory.
#[derive(Clone)]
pub struct LocalKeySigner {
    key: [u8; 32],
    address: [u8; 20],
}

impl LocalKeySigner {
    pub fn new(key: &[u8]) -> Self {
        let key: [u8; 32] = arr(key);
        LocalKeySigner {
            address: address_of(&public_key(&key)),
            key,
        }
    }
}

impl core::fmt::Debug for LocalKeySigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LocalKeySigner({})", super::util::hex0x(&self.address))
    }
}

fn strip(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

impl EvmSigner for LocalKeySigner {
    fn address(&self) -> [u8; 20] {
        self.address
    }

    fn sign_transaction(&self, t: &TxRequest) -> core::result::Result<Vec<u8>, String> {
        let sig = sign_recoverable(&self.key, &signing_hash(t));
        let mut f = fields(t);
        f.push(rlp_u64_enc(sig[64] as u64));
        f.push(rlp_bytes(strip(&sig[..32])));
        f.push(rlp_bytes(strip(&sig[32..64])));
        Ok(super::util::cat(&[&[0x02], &rlp_list(&f)]))
    }
}

/// A decoded signed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTx {
    pub request: TxRequest,
    pub from: [u8; 20],
    pub hash: [u8; 32],
}

/// Decode a signed EIP-1559 transaction and recover its sender.
pub fn decode_signed_tx(raw: &[u8]) -> core::result::Result<DecodedTx, String> {
    if raw.first() != Some(&0x02) {
        return Err("nb2: not an EIP-1559 transaction".into());
    }
    let it = rlp_decode(&raw[1..]).map_err(|_| String::from("nb2: not an EIP-1559 transaction"))?;
    if !it.list || it.kids.len() != 12 {
        return Err("nb2: not an EIP-1559 transaction".into());
    }
    let k = &it.kids;
    let n = |i: usize| rlp_uint(&k[i], 32).ok_or_else(|| String::from("nb2: noncanonical integer"));
    let n64 = |i: usize| -> core::result::Result<u64, String> {
        to_u64(&n(i)?).ok_or_else(|| String::from("nb2: integer too large"))
    };
    if k[5].list || k[5].str.len() != 20 || k[7].list {
        return Err("nb2: not an EIP-1559 transaction".into());
    }
    let request = TxRequest {
        chain_id: n64(0)?,
        nonce: n64(1)?,
        max_priority_fee_per_gas: n(2)?,
        max_fee_per_gas: n(3)?,
        gas: n64(4)?,
        to: arr(k[5].str),
        value: n(6)?,
        data: k[7].str.to_vec(),
    };
    let v = n64(9)?;
    let word = |b: &[u8]| -> core::result::Result<[u8; 32], String> {
        if b.len() > 32 {
            return Err("nb2: signature word".into());
        }
        let mut w = [0u8; 32];
        w[32 - b.len()..].copy_from_slice(b);
        Ok(w)
    };
    let rs = super::util::cat(&[&word(k[10].str)?, &word(k[11].str)?]);
    if v > 1 {
        return Err("nb2: recovery id".into());
    }
    let pubk = recover(&signing_hash(&request), &rs, v as u8)
        .ok_or_else(|| String::from("nb2: signature does not recover"))?;
    Ok(DecodedTx {
        from: address_of(&pubk),
        hash: he(&[raw]),
        request,
    })
}

/// Sign `t` with `signer` and check the signed bytes before they are journaled: an external signer must return exactly this
/// request (chain ID, nonce, fees, gas, target, value, data), signed by its own address. The journaled request is the decoded one.
pub fn sign_tx(signer: &dyn EvmSigner, t: &TxRequest) -> Result<SignedTx> {
    let raw = signer.sign_transaction(t).map_err(Error::Other)?;
    let d = decode_signed_tx(&raw).map_err(|e| {
        Error::Other(alloc::format!(
            "nb2: the signer returned a transaction that does not decode: {e}"
        ))
    })?;
    if d.request != *t {
        return Err(Error::Other(
            "nb2: the signer returned another transaction than the one requested".into(),
        ));
    }
    if d.from != signer.address() {
        return Err(Error::Other(
            "nb2: the signed transaction is not from the signer's address".into(),
        ));
    }
    Ok(SignedTx {
        raw,
        hash: d.hash,
        request: d.request,
    })
}

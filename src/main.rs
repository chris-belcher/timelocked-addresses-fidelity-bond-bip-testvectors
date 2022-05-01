use std::str::FromStr;

extern crate chrono;
use chrono::{NaiveDate, NaiveDateTime};

extern crate bitcoin_wallet;
use bitcoin_wallet::mnemonic;

extern crate bitcoin;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::PublicKey;
use bitcoin::Network;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;

use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::util::misc::MessageSignature;
use bitcoin::Address;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;

//set this to true to generate a list of all addresses
const GENERATE_ALL_TIMELOCKED_ADDRESSES: bool = false;

const SEED_PHRASE: &str =
"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const EXTENSION: &str = "";
const TIMELOCKED_MPK_PATH: &str = "m/84'/0'/0'/2";


fn generate_all_timelocked_addresses(timelocked_master_private_key: &ExtendedPrivKey) {
    let secp = Secp256k1::new();

    for index in 0..960 {
        let privkey = timelocked_master_private_key
            .ckd_priv(&secp, ChildNumber::Normal { index })
            .unwrap()
            .private_key;
        let pubkey = privkey.public_key(&secp);

        let year_off = index as i32 / 12;
        let month = index % 12;
        let locktime = NaiveDate::from_ymd(2020 + year_off, 1 + month, 1)
            .and_hms(0, 0, 0)
            .timestamp();

        let redeemscript = Builder::new()
            .push_int(locktime)
            .push_opcode(opcodes::all::OP_CLTV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_key(&pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        let addr = Address::p2wsh(&redeemscript, Network::Bitcoin);
        println!(
            "{}/{:3} {} [{}]",
            TIMELOCKED_MPK_PATH,
            index,
            addr,
            NaiveDateTime::from_timestamp(locktime, 0)
                .format("%Y-%m-%d")
                .to_string()
        );
    }
}

fn generate_fidelity_bond_bip_test_vector(timelocked_master_private_key: &ExtendedPrivKey) {
    //can be from 0 to 959
    let index = 0;

    let secp = Secp256k1::new();
    let timelocked_addr_privkey = timelocked_master_private_key
        .ckd_priv(&secp, ChildNumber::Normal { index })
        .unwrap()
        .private_key;
    let timelocked_addr_pubkey = timelocked_addr_privkey.public_key(&secp);

    let year_off = index as i32 / 12;
    let month = index % 12;
    let locktime = NaiveDate::from_ymd(2020 + year_off, 1 + month, 1)
        .and_hms(0, 0, 0)
        .timestamp();

    let redeemscript = Builder::new()
        .push_int(locktime)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(&timelocked_addr_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    let addr = Address::p2wsh(&redeemscript, Network::Bitcoin);

    println!("path = {}/{}\naddr = {}", TIMELOCKED_MPK_PATH, index, addr,);
    println!(
        concat!(
            "redeemscript = {:x}\nscriptPubKey = {:x}\nunix locktime = {}",
            "\nstring locktime = {}\ntimelocked_addr_pubkey = {}\ntimelocked_addr_privkey = {}"
        ),
        redeemscript,
        addr.script_pubkey(),
        locktime,
        NaiveDateTime::from_timestamp(locktime, 0)
            .format("%Y-%m-%d")
            .to_string(),
        timelocked_addr_pubkey,
        timelocked_addr_privkey
    );

    let cert_pubkey_str = "020000000000000000000000000000000000000000000000000000000000000001";
    let cert_pubkey = PublicKey::from_str(cert_pubkey_str).unwrap();
    let cert_expiry = 375;

    println!(
        "cert_pubkey = {}\ncert_expiry = {}",
        cert_pubkey, cert_expiry
    );

    let cert_msg_str = format!("fidelity-bond-cert|{}|{}", cert_pubkey, cert_expiry);
    println!("cert_msg = {}", cert_msg_str);

    let cert_msg = cert_msg_str.as_bytes();
    let mut btc_signed_msg = Vec::<u8>::new();
    btc_signed_msg.extend("\x18Bitcoin Signed Message:\n".as_bytes());
    btc_signed_msg.push(cert_msg.len() as u8);
    btc_signed_msg.extend(cert_msg);

    let msg_hash =
        bitcoin::secp256k1::Message::from_slice(&sha256d::Hash::hash(&btc_signed_msg)).unwrap();
    let cert_sig = secp.sign(&msg_hash, &timelocked_addr_privkey.key);
    println!("cert_sig = {:?}", cert_sig);

    let verify_result = secp.verify(&msg_hash, &cert_sig, &timelocked_addr_pubkey.key);
    println!("verify result = {:?}", verify_result);

    let cert_sig_msg = secp.sign_recoverable(&msg_hash, &timelocked_addr_privkey.key);
    let cert_msg_sig_recoverable = MessageSignature {
        signature: cert_sig_msg,
        compressed: true,
    };
    println!("signmessage sig = {}", cert_msg_sig_recoverable.to_base64());

    let cert_sig_msg_std = cert_sig_msg.to_standard();
    println!("standard sig = {}", cert_sig_msg_std);

    let verify_result_recover_std =
        secp.verify(&msg_hash, &cert_sig_msg_std, &timelocked_addr_pubkey.key);
    println!(
        "verify result using recover = {:?}",
        verify_result_recover_std
    );

    let p2pkh_addr = Address::p2pkh(&timelocked_addr_pubkey, Network::Bitcoin);
    println!(
        "p2pkh address corresponding to timelocked_addr_pubkey = {}",
        p2pkh_addr
    );

    println!(
        concat!(
            "\nverify this message using the Verify Message function in most wallets:\n",
            "Message:\n{}\nAddress:\n{}\nSignature:\n{}"
        ),
        cert_msg_str,
        p2pkh_addr,
        cert_msg_sig_recoverable.to_base64()
    );
}

fn main() {
    let secp = Secp256k1::new();

    let seed = mnemonic::Mnemonic::from_str(SEED_PHRASE)
        .unwrap()
        .to_seed(Some(EXTENSION));

    let xprv = ExtendedPrivKey::new_master(Network::Bitcoin, &seed.0).unwrap();
    println!("rootpriv = {}", xprv);
    let xpub = ExtendedPubKey::from_private(&secp, &xprv);
    println!("rootpub = {}", xpub);

    let timelocked_master_private_key = &xprv
        .derive_priv(
            &secp,
            &DerivationPath::from_str(TIMELOCKED_MPK_PATH).unwrap(),
        )
        .unwrap();

    if GENERATE_ALL_TIMELOCKED_ADDRESSES {
        generate_all_timelocked_addresses(timelocked_master_private_key);
    } else {
        generate_fidelity_bond_bip_test_vector(timelocked_master_private_key);
    }
}

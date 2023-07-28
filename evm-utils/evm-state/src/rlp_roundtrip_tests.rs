use std::convert::TryInto;

use crate::{transaction_roots::EthereumReceipt, TransactionAction, UnsignedTransaction, UnsignedTransactionWithCaller, Transaction, TransactionSignature, TransactionInReceipt};

use super::types::Account;

use ethbloom::Bloom;
use evm::backend::Log;
use keccak_hash::H256;
use primitive_types::{U256, H160};
use rlp::{Decodable as DecodableOld, DecoderError as OldDecoderError, Rlp};

use triedb::rlp::{Encodable, Decodable, DecoderError};

fn decode_old<T: DecodableOld>(bytes: &[u8]) -> Result<T, OldDecoderError> {

    <T as DecodableOld>::decode(&Rlp::new(bytes))
}

 pub fn decode<'a, T: Decodable<'a>>(mut val: &'a [u8]) -> Result<T, DecoderError> {
    Decodable::decode(&mut val)
}

pub use rlp::encode as encode_old;

pub fn encode<V: Encodable>(val: &V) -> Vec<u8> {
    let mut vec_buffer = Vec::with_capacity(val.length());
    val.encode(&mut vec_buffer);
    vec_buffer
}

macro_rules! check_roundtrip {
    ($v: expr => $type: ty) => {{
        let old_rlp_raw: Vec<u8>;
        let rlp_raw;
        {
            old_rlp_raw = encode_old(&$v).to_vec();
            dbg!(hexutil::to_hex(&old_rlp_raw));
            let decoded_node: $type = decode_old(&old_rlp_raw).unwrap();
            assert_eq!(decoded_node, $v);
        }
        {
            rlp_raw = encode(&$v);
            dbg!(hexutil::to_hex(&rlp_raw));
            let decoded_node: $type = decode(&rlp_raw).unwrap();
            assert_eq!(decoded_node, $v);
        }

        {
            assert_eq!(old_rlp_raw, rlp_raw);
        }
    }};
}

#[test]
fn test_check_account_roundtrip() {
    let acc = Account {
        nonce: U256([27;4]),
        balance: U256([24;4]),
        storage_root: H256([7; 32]),
        code_hash: H256([2; 32]),
        
    };

    check_roundtrip!(acc => Account);
    let acc = Account {
        nonce: U256([21;4]),
        balance: U256([23;4]),
        storage_root: H256([8; 32]),
        code_hash: H256([123; 32]),
        
    };

    check_roundtrip!(acc => Account);
    
}

#[test]
fn test_check_log_roundtrip() {
    let acc = Log {
        address: H160([23; 20]),
        topics: vec![H256([37; 32]), H256([173;32]), H256([21; 32])],
        data: vec![0, 123, 12, 17, 19, 244],
        
    };

    check_roundtrip!(acc => Log);
    let acc = Log {
        address: H160([23; 20]),
        topics: vec![],
        data: vec![],
        
    };

    check_roundtrip!(acc => Log);
    
}
#[test]
fn test_check_bloom_roundtrip() {
    let mut acc = [10; 256];
    for i in 0..256 {
        acc[i] = i as u8;
    }
    let bloomy = Bloom(acc);

    check_roundtrip!(bloomy => Bloom);
}

#[test]
fn test_check_ethereum_receipt_roundtrip() {
    let mut acc = [10; 256];
    for i in 0..256 {
        acc[i] = i as u8;
    }
    let bloomy = Bloom(acc);
    let mut h160_special = [0; 20];
    for i in 0..20 {
        h160_special[i] = i as u8;
    }
    let log1 = Log {
        address: H160(h160_special),
        topics: vec![H256([37; 32]), H256([173;32]), H256([21; 32])],
        data: vec![0, 123, 12, 17, 19, 244],
        
    };
    let log2 = Log {
        address: H160([38; 20]),
        topics: vec![H256([27; 32]), H256([173;32]), H256([24; 32])],
        data: vec![0, 123, 12, 17, 111, 244],
        
    };

    let receipt = EthereumReceipt {
        log_bloom: bloomy,        
        logs: vec![log1, log2],
        status: 7,
        gas_used: U256([23;4]),

    };

    check_roundtrip!(receipt => EthereumReceipt);
}

#[test]
fn test_check_tranaaction_action_roundtrip() {
    let ta1 = TransactionAction::Create;


    check_roundtrip!(ta1 => TransactionAction);

    let ta2 = TransactionAction::Call(H160([56; 20]));

    check_roundtrip!(ta2 => TransactionAction);

}

#[test]
fn test_check_unsigned_transaction_roundtrip() {
    let ta2 = TransactionAction::Call(H160([56; 20]));

    let ut2 = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta2,
        value: U256([20000; 4]),
        input: vec![34, 45, 12, 123, 243],
    };
 
    check_roundtrip!(ut2 => UnsignedTransaction);
    let ta1 = TransactionAction::Create;

    let ut1 = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta1,
        value: U256([23000;4]),
        input: vec![34, 45, 12, 123, 243],
    };
    check_roundtrip!(ut1 => UnsignedTransaction);

}

#[test]
fn test_check_unsigned_transaction_with_caller_roundtrip1() {
    let ta = TransactionAction::Call(H160([56; 20]));

    let ut = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta,
        value: U256([20000; 4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c = UnsignedTransactionWithCaller {
        unsigned_tx: ut,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: true,
        
    }; 
    let old_rlp_raw: Vec<u8>;
    let rlp_raw;
    {
        old_rlp_raw = encode_old(&ut_c).to_vec();
        dbg!(hexutil::to_hex(&old_rlp_raw));
        let rlp = Rlp::new(&old_rlp_raw);
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode_old(&rlp, true).unwrap();
        assert_eq!(decoded_node, ut_c);
    }
    {
        rlp_raw = encode(&ut_c);
        dbg!(hexutil::to_hex(&rlp_raw));
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode(&mut rlp_raw.as_ref(), true).unwrap();
        assert_eq!(decoded_node, ut_c);
    }

    {
        assert_eq!(old_rlp_raw, rlp_raw);
    }
}

#[test]
fn test_check_unsigned_transaction_with_caller_roundtrip2() {
    let ta = TransactionAction::Create;

    let ut = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta,
        value: U256([23000;4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c = UnsignedTransactionWithCaller {
        unsigned_tx: ut,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: false,
        
    }; 
    let old_rlp_raw: Vec<u8>;
    let rlp_raw;
    {
        old_rlp_raw = encode_old(&ut_c).to_vec();
        dbg!(hexutil::to_hex(&old_rlp_raw));
        let rlp = Rlp::new(&old_rlp_raw);
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode_old(&rlp, false).unwrap();
        assert_eq!(decoded_node, ut_c);
    }
    {
        rlp_raw = encode(&ut_c);
        dbg!(hexutil::to_hex(&rlp_raw));
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode(&mut rlp_raw.as_ref(), false).unwrap();
        assert_eq!(decoded_node, ut_c);
    }

    {
        assert_eq!(old_rlp_raw, rlp_raw);
    }
}

#[test]
fn test_check_transaction_roundtrip() {

    let ta1 = TransactionAction::Create;
    let tx1 = Transaction{
        nonce: U256([72; 4]),
        gas_price: U256([3213;4]),
        gas_limit: U256([4324; 4]),
        action: ta1,
        value: U256([7732; 4]),
        signature: TransactionSignature {
            v: 88979,
            r: H256([34; 32]),
            s: H256([78; 32]),
        },
        input: vec![32, 31, 0, 34, 76, 173],

    };
 
    check_roundtrip!(tx1 => Transaction);

    let ta2 = TransactionAction::Call(H160([56; 20]));
    let tx2 = Transaction{
        nonce: U256([79; 4]),
        gas_price: U256([3013;4]),
        gas_limit: U256([4124; 4]),
        action: ta2,
        value: U256([7832; 4]),
        signature: TransactionSignature {
            v: 88979,
            r: H256([38; 32]),
            s: H256([76; 32]),
        },
        input: vec![32, 31, 0, 34, 76, 173],

    };
 
    check_roundtrip!(tx2 => Transaction);

}

#[test]
fn test_check_transaction_in_receipt_roundtrip1() {

    let ta = TransactionAction::Create;
    let tx = Transaction{
        nonce: U256([72; 4]),
        gas_price: U256([3213;4]),
        gas_limit: U256([4324; 4]),
        action: ta,
        value: U256([7732; 4]),
        signature: TransactionSignature {
            v: 88979,
            r: H256([34; 32]),
            s: H256([78; 32]),
        },
        input: vec![32, 31, 0, 34, 76, 173],

    };

    let tx_in_rec1 = TransactionInReceipt::Signed(tx);
 
    check_roundtrip!(tx_in_rec1 => TransactionInReceipt);

}

#[test]
fn test_check_transaction_in_receipt_roundtrip2() {
    let ta = TransactionAction::Create;

    let ut = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta,
        value: U256([23000;4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c = UnsignedTransactionWithCaller {
        unsigned_tx: ut,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: false,
        
    }; 

    let tx_in_rec2 = TransactionInReceipt::Unsigned(ut_c);

 
    check_roundtrip!(tx_in_rec2 => TransactionInReceipt);
}

#[test]
fn test_check_transaction_in_receipt_roundtrip3() {
    let ta2 = TransactionAction::Call(H160([56; 20]));

    let ut2 = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta2,
        value: U256([20000; 4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c2 = UnsignedTransactionWithCaller {
        unsigned_tx: ut2,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: true,
        
    }; 
    let tx_in_rec3 = TransactionInReceipt::Unsigned(ut_c2);

    check_roundtrip!(tx_in_rec3 => TransactionInReceipt);

}

#[test]
fn test_check_transaction_in_receipt_roundtrip4() {

    let ta = TransactionAction::Call(H160([10; 20]));
    let tx = Transaction{
        nonce: U256([72; 4]),
        gas_price: U256([3213;4]),
        gas_limit: U256([4324; 4]),
        action: ta,
        value: U256([7732; 4]),
        signature: TransactionSignature {
            v: 88979,
            r: H256([34; 32]),
            s: H256([78; 32]),
        },
        input: vec![32, 31, 0, 34, 76, 173],

    };

    let tx_in_rec1 = TransactionInReceipt::Signed(tx);
 
    check_roundtrip!(tx_in_rec1 => TransactionInReceipt);

}

#[test]
fn test_check_unsigned_transaction_with_caller_tx_id_hash() {
    let ta2 = TransactionAction::Call(H160([56; 20]));

    let ut2 = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta2,
        value: U256([20000; 4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c2 = UnsignedTransactionWithCaller {
        unsigned_tx: ut2,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: true,
        
    }; 

    let old = ut_c2.tx_id_hash_old();
    let new = ut_c2.tx_id_hash();

    assert_eq!(old, new);
}


#[test]
fn test_check_transaction_in_receipt_roundtrip5() {
    let ta_inner = hexutil::read_hex("5c44f6325198ac3d4007727211040311e9e6a1f0").unwrap();
    let r_inner = hexutil::read_hex("ed30d3b0afdffef99887e8fcba2de50f3b390286ae2047588ceb1b989ae52dbd").unwrap();
    let s_inner = hexutil::read_hex("1aa5f7e761f7866ee87381e6e1d8efbcdb02daa7f752c3c0478854da0eafc170").unwrap();
    let ta = TransactionAction::Call(H160(ta_inner.try_into().unwrap()));

    let tx = Transaction{
        nonce: U256::from_dec_str("2787").unwrap(),
        gas_price: U256::from_dec_str("3000000000").unwrap(),
        gas_limit: U256::from_dec_str("45348").unwrap(),
        action: ta,
        value: U256::from_dec_str("0").unwrap(),
        signature: TransactionSignature {
            v: 247,
            r: H256(r_inner.try_into().unwrap()),
            s: H256(s_inner.try_into().unwrap()),
        },
        input: vec![162, 44, 180, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 46, 126, 29, 14, 117, 75, 59, 62, 29, 25, 113, 208, 49, 29, 132, 62, 179, 181, 26, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],

    };

    let tx_in_rec1 = TransactionInReceipt::Signed(tx);
 
    check_roundtrip!(tx_in_rec1 => TransactionInReceipt);
    
}

#[test]
fn test_check_transaction_in_receipt_roundtrip6() {
    let ta_inner = hexutil::read_hex("c848e8767a209ec1538f7bc8a5d849ea521443dc").unwrap();

    let r_inner = hexutil::read_hex("e8f46e259e3f8586a25a0f6037e13dbeb59123d7faa7a65e8d8c9edf6338433e").unwrap();
    let s_inner = hexutil::read_hex("7316d2aaacdb75a1d25b12d3843fd30e16d11aecf68974f0c96f6d33299b6cf6").unwrap();
    let ta = TransactionAction::Call(H160(ta_inner.try_into().unwrap()));

    let tx = Transaction{
        nonce: U256::from_dec_str("975723").unwrap(),
        gas_price: U256::from_dec_str("5000000000").unwrap(),
        gas_limit: U256::from_dec_str("700000").unwrap(),
        action: ta,
        value: U256::from_dec_str("0").unwrap(),
        signature: TransactionSignature {
            v: 248,
            r: H256(r_inner.try_into().unwrap()),
            s: H256(s_inner.try_into().unwrap()),
        },
        input: vec![70,
             65,
             37,
             125],

    };

    let tx_in_rec1 = TransactionInReceipt::Signed(tx);
 
    check_roundtrip!(tx_in_rec1 => TransactionInReceipt);
    
}
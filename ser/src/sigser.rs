// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use bitcoinsuite_core::{
    error::{self, DataError},
    hash,
    hash::{Hashed, Sha256d},
    script::Script,
    ser::{BitcoinSer, CompactUint},
    tx::{
        self, Capability, CashToken, Coin, Input, OutPoint, Output, TokenData, Transaction, TxId,
    },
};

use crate::sighashtype::*;
use bytes::{Bytes, BytesMut};

fn hash_prev_outs(tx: &Transaction) -> Sha256d {
    let mut hashes = BytesMut::new();
    for input in &tx.inputs {
        hashes.extend_from_slice(input.prev_out.ser().as_ref());
    }
    Sha256d::digest(hashes.freeze())
}

fn hash_sequence(tx: &Transaction) -> Sha256d {
    let mut hashes = BytesMut::new();
    for input in &tx.inputs {
        hashes.extend_from_slice(input.sequence.ser().as_ref());
    }
    Sha256d::digest(hashes.freeze())
}

fn hash_outputs(tx: &Transaction) -> Sha256d {
    let mut hashes = BytesMut::new();
    for output in &tx.outputs {
        hashes.extend_from_slice(output.ser().as_ref());
    }
    Sha256d::digest(hashes.freeze())
}
fn hash_utxos(source_outputs: Vec<Output>) -> Sha256d {
    let mut hashes = BytesMut::new();
    for output in &source_outputs {
        hashes.extend_from_slice(output.ser().as_ref());
    }
    Sha256d::digest(hashes.freeze())
}

struct TransactionCache<'tx> {
    cache: &'tx mut Transaction,
}
/// Serialize a transaction component
pub fn signature_ser(
    idx: u32,
    src_output: Vec<Output>,
    tx: &mut Transaction,
    sig_hash_type: &SigHashType,
) -> String {
    let transaction = &TransactionCache { cache: tx };
    let input_index = &idx;

    let hash_prevouts = if sig_hash_type.input_type == SigHashTypeInputs::Fixed {
        hash_prev_outs(transaction.cache)
    } else {
        Sha256d::default()
    };
    let hash_sequence = if sig_hash_type.input_type == SigHashTypeInputs::Fixed
        && sig_hash_type.output_type == SigHashTypeOutputs::All
    {
        hash_sequence(transaction.cache)
    } else {
        Sha256d::default()
    };
    let hash_utxos: Option<Sha256d> = if sig_hash_type.utxos == SigHashTypeInputs::Utxos {
        Some(hash_utxos(src_output.clone()))
    } else {
        None
    };

    let hash_outputs = match sig_hash_type.output_type {
        SigHashTypeOutputs::All => hash_outputs(&transaction.cache),
        SigHashTypeOutputs::Single if (*input_index as usize) < transaction.cache.outputs.len() => {
            Sha256d::digest(
                transaction.cache.outputs[*input_index as usize]
                    .ser()
                    .as_ref(),
            )
        }
        _ => Sha256d::default(),
    };

    let mut preimage = BytesMut::new();
    // VERSION
    preimage.extend_from_slice(transaction.cache.version.ser().as_ref());
    //HASH PREVOUTS
    preimage.extend_from_slice(hash_prevouts.as_ref());
    //Hash UTXOS
    if hash_utxos.is_some() {
        preimage.extend_from_slice(hash_utxos.unwrap().0.ser().as_ref());
    }

    // HASH SEQUENCE
    preimage.extend_from_slice(hash_sequence.as_ref());

    // OUTPOINT TRANSACTION HASH & INDEX SER
    preimage.extend_from_slice(
        transaction.cache.inputs[*input_index as usize]
            .prev_out
            .txid
            .ser()
            .to_vec()
            .as_ref(),
    );
    // OutpointIndex
    preimage.extend_from_slice(
        transaction.cache.inputs[*input_index as usize]
            .prev_out
            .outpoint_index
            .ser()
            .to_vec()
            .as_ref(),
    );
    //TOKEN PREFIX
    preimage.extend_from_slice(src_output[idx as usize].token.ser().as_ref());
    //COVERED BYTECODE
    preimage.extend_from_slice(src_output[idx as usize].script.ser().as_ref());
    //OUTPUT VALUE
    preimage.extend_from_slice(src_output[idx as usize].value.ser().as_ref());
    //INPUT SEQUENCE already here
    preimage.extend_from_slice(
        transaction.cache.inputs[*input_index as usize]
            .sequence
            .ser()
            .to_vec()
            .as_ref(),
    );
    //HASH OUTPUTS
    preimage.extend_from_slice(hash_outputs.as_ref());
    //LOCKTIME
    preimage.extend_from_slice(transaction.cache.locktime.ser().as_ref());
    // HASH TYPE SER
    preimage.extend_from_slice(sig_hash_type.to_u32().ser().as_ref());

    hex::encode(preimage)
}

mod test {
    use super::*;
    use bitcoinsuite_core::script::{PubKey, ScriptMut};
    use bitcoinsuite_core::tx::{Commitment, NonFungibleTokenCapability, TxId};
    #[test]
    fn two_inputs() {
        let scriptpubkey =
            hex::decode("76a91457314787eafac80afd059f1f31e990d7db9b70fd88ac").unwrap();
        let script_bytecode = Bytes::from(scriptpubkey);

        let txid: TxId = Sha256d::from_be_hex(
            "687cb9d58f75f209ab1749f0beaf73257ef6441c7d5f17edf332625de8c61d0d",
        )
        .unwrap()
        .into();
        let txid2: TxId = Sha256d::from_be_hex(
            "6f57036711b6935aca5598722be81260595560a082ef963222b225cd04733234",
        )
        .unwrap()
        .into();
        // let txid = TxId::from(txid);
        let mut script_sig1 = ScriptMut::with_capacity(1 + 64 + 1 + PubKey::SIZE);
        script_sig1.put_bytecode(&[65]);
        script_sig1.put_bytecode(&[
            217, 254, 36, 145, 41, 18, 199, 123, 162, 150, 43, 66, 211, 166, 195, 98, 5, 120, 28,
            169, 5, 214, 184, 37, 169, 79, 0, 73, 98, 221, 130, 10, 47, 95, 223, 197, 211, 27, 157,
            156, 171, 166, 62, 113, 104, 149, 22, 59, 136, 108, 186, 57, 218, 117, 73, 14, 88, 108,
            4, 25, 27, 37, 9, 2, 97,
        ]);
        script_sig1.put_bytecode(&[33]);
        script_sig1.put_bytecode(&[
            3, 45, 61, 22, 117, 86, 214, 46, 51, 118, 197, 77, 184, 233, 141, 82, 240, 107, 126,
            79, 14, 2, 193, 83, 183, 166, 35, 51, 132, 122, 96, 77, 55,
        ]);
        let mut script_sig2 = ScriptMut::with_capacity(1 + 64 + 1 + PubKey::SIZE);
        script_sig2.put_bytecode(&[65]);
        script_sig2.put_bytecode(&[
            169, 109, 181, 122, 80, 93, 50, 193, 97, 172, 80, 7, 121, 194, 221, 52, 52, 62, 132,
            42, 40, 25, 71, 8, 58, 178, 42, 87, 117, 184, 235, 218, 26, 34, 4, 226, 51, 255, 203,
            23, 148, 227, 2, 191, 206, 119, 117, 111, 228, 118, 69, 108, 62, 60, 86, 56, 80, 252,
            177, 84, 110, 187, 165, 170, 97,
        ]);
        script_sig2.put_bytecode(&[33]);
        script_sig2.put_bytecode(&[
            3, 45, 61, 22, 117, 86, 214, 46, 51, 118, 197, 77, 184, 233, 141, 82, 240, 107, 126,
            79, 14, 2, 193, 83, 183, 166, 35, 51, 132, 122, 96, 77, 55,
        ]);

        let source_out1 = Output {
            script: Script::new(script_bytecode.clone()),
            token: None,
            value: 750,
        };
        let source_out2 = Output {
            script: Script::new(script_bytecode.clone()),
            token: None,
            value: 750,
        };

        let mut ctx = Transaction {
            version: 2,
            inputs: vec![
                Input {
                    prev_out: {
                        OutPoint {
                            txid: txid2,
                            outpoint_index: 0,
                        }
                    },
                    script: Script::default(),
                    sequence: 0,
                },
                Input {
                    prev_out: {
                        OutPoint {
                            txid,
                            outpoint_index: 0,
                        }
                    },
                    script: Script::default(),
                    sequence: 0,
                },
            ],
            outputs: vec![Output {
                script: Script::new(script_bytecode.clone()),
                token: None,
                value: 1500 - 500,
            }],
            locktime: 0,
        };
        // USE FOR SIGNING
        let src_outs = vec![source_out1, source_out2];
        let pre1 = signature_ser(
            0,
            src_outs.clone(),
            &mut ctx,
            &SigHashType::ALL_BIP143_UTXOS,
        );
        let pre2 = signature_ser(
            1,
            src_outs.clone(),
            &mut ctx,
            &SigHashType::ALL_BIP143_UTXOS,
        );
        println!("PREIMAGE1 \n {:?}", pre1);
        println!("PREIMAGE2 \n {:?}", pre2);
        let fin_tx = Transaction {
            version: 2,
            inputs: vec![
                Input {
                    prev_out: {
                        OutPoint {
                            txid: txid2,
                            outpoint_index: 0,
                        }
                    },
                    script: script_sig1.clone().freeze(),
                    sequence: 0,
                },
                Input {
                    prev_out: {
                        OutPoint {
                            txid,
                            outpoint_index: 0,
                        }
                    },
                    script: script_sig2.clone().freeze(),
                    sequence: 0,
                },
            ],
            outputs: vec![Output {
                script: Script::new(script_bytecode.clone()),
                token: None,
                value: 1500 - 500,
            }],
            locktime: 0,
        };

        println!("\n{:?}\n", hex::encode(fin_tx.ser().as_ref()));
    }
    #[test]
    fn create_sighash_pre() {
        let scriptpubkey =
            hex::decode("76a91457314787eafac80afd059f1f31e990d7db9b70fd88ac").unwrap();
        let script_bytecode = Bytes::from(scriptpubkey);

        let txid: TxId = Sha256d::from_be_hex(
            "95a74d011d7a600604f37bd8d2ae3066cb952429b45ce733e356b35288b9a430",
        )
        .unwrap()
        .into();
        // let txid = TxId::from(txid);
        let mut script_sig = ScriptMut::with_capacity(1 + 64 + 1 + PubKey::SIZE);
        script_sig.put_bytecode(&[65]);
        script_sig.put_bytecode(&[
            4, 124, 191, 179, 237, 251, 131, 57, 230, 160, 53, 241, 186, 178, 141, 156, 219, 84,
            50, 61, 82, 119, 93, 28, 179, 248, 131, 249, 241, 157, 45, 112, 10, 242, 26, 197, 236,
            77, 117, 120, 39, 200, 224, 106, 23, 24, 10, 181, 182, 131, 48, 126, 115, 101, 227, 66,
            175, 47, 70, 112, 53, 31, 242, 156, 97,
        ]);
        script_sig.put_bytecode(&[33]);
        script_sig.put_bytecode(&[
            3, 45, 61, 22, 117, 86, 214, 46, 51, 118, 197, 77, 184, 233, 141, 82, 240, 107, 126,
            79, 14, 2, 193, 83, 183, 166, 35, 51, 132, 122, 96, 77, 55,
        ]);
        let category_id = Sha256d::from_be_hex(
            "b2339cb47611f96bd2364a17151ed2c21a3dc0a93d9997bd73c463b5b8bbbfcf",
        )
        .unwrap();
        let source_out = Output {
            script: Script::new(script_bytecode.clone()),
            token: Some(CashToken {
                amount: CompactUint(0),
                category: TxId::from(category_id),
                nft: Some(tx::NFT {
                    capability: NonFungibleTokenCapability(Capability::Minting),
                    commitment: Commitment(Bytes::from(vec![1])), //
                }),
            }),
            value: 29874600,
        };

        let mut ctx = Transaction {
            version: 2,
            inputs: vec![Input {
                prev_out: {
                    OutPoint {
                        txid,
                        outpoint_index: 0,
                    }
                },
                script: Script::default(),
                sequence: 0,
            }],
            outputs: vec![
                Output {
                    script: Script::new(script_bytecode.clone()),
                    token: Some(CashToken {
                        amount: CompactUint(0),
                        category: TxId::from(category_id),
                        nft: Some(tx::NFT {
                            capability: NonFungibleTokenCapability(Capability::Minting),
                            commitment: Commitment(Bytes::from(vec![1])), //
                        }),
                    }),
                    value: 29864600 - 500,
                },
                Output {
                    script: Script::new(script_bytecode.clone()),
                    token: Some(CashToken {
                        amount: CompactUint(0),
                        category: TxId::from(category_id),
                        nft: Some(tx::NFT {
                            capability: NonFungibleTokenCapability(Capability::Mutable),
                            commitment: Commitment(Bytes::from(vec![1])), //
                        }),
                    }),
                    value: 10_000 - 500,
                },
            ],
            locktime: 0,
        };
        // USE FOR SIGNING
        let _x = signature_ser(
            0,
            vec![source_out],
            &mut ctx,
            &SigHashType::ALL_BIP143_UTXOS,
        );
        println!("PREIMAGE \n {:?}", _x);
        let fin_tx = Transaction {
            version: 2,
            inputs: vec![Input {
                prev_out: {
                    OutPoint {
                        txid,
                        outpoint_index: 0,
                    }
                },
                script: script_sig.freeze(),
                sequence: 0,
            }],
            outputs: vec![
                Output {
                    script: Script::new(script_bytecode.clone()),
                    token: Some(CashToken {
                        amount: CompactUint(0),
                        category: TxId::from(category_id),
                        nft: Some(tx::NFT {
                            capability: NonFungibleTokenCapability(Capability::Minting),
                            commitment: Commitment(Bytes::from(vec![1])), //
                        }),
                    }),
                    value: 29864600 - 500,
                },
                Output {
                    script: Script::new(script_bytecode.clone()),
                    token: Some(CashToken {
                        amount: CompactUint(0),
                        category: TxId::from(category_id),
                        nft: Some(tx::NFT {
                            capability: NonFungibleTokenCapability(Capability::Mutable),
                            commitment: Commitment(Bytes::from(vec![1])), //
                        }),
                    }),
                    value: 10_000 - 500,
                },
            ],
            locktime: 0,
        };

        println!("\n{:?}\n", hex::encode(fin_tx.ser().as_ref()));
    }
    #[test]
    fn preimage_test() {
        let source_out = Output {
            script: Script::new(Bytes::from(vec![0x51])),
            token: None,
            value: 12345,
        };
        let mut tx = Transaction {
            version: 1,
            inputs: vec![Input {
                prev_out: OutPoint {
                    txid: TxId::from(Sha256d::from_be_bytes([0xae; 32])),
                    outpoint_index: 0x12345678,
                },
                script: Script::default(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![Output::default()],
            locktime: 0,
        };
        let x = signature_ser(0, vec![source_out], &mut tx, &SigHashType::ALL_BIP143);
        println!("{:?}", x);
        assert_eq!(
            x,
            "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
        );
    }

    // SIGHASH TEST FROM BCHN are valid???
    #[test]
    fn test_sighash_from_json() {
        let tx_hex = "a48294bc04931bf206d60aac06255c9930656db028af7cabecc7af0c8a0686a3439f040d6303000000046363ac6a9ab255d191acf965a9ff6951965a7bca2487a533343f96fa3b67f0be57743d2dd460edcd00000000003b3e414d7aef14b7f617f0932b404dd6b645314cc133b488e00f1f992249c7f65c8bdec7010000000365ab52ffffffff1c241d9dcfd2083d9e673638fd5129eca27f0a8c932e2bf7f3316c9c14ae77f60300000005656551ab6358e801a704054847020000000005acac6365abf0f18f050000000004ac5252ab1b699d02000000000352656a65181204000000000763536a5251abab00000000";
        let sighash_reg = "8a2ca2f064f4b79aa58a987628916509f3500a8527e5949a39918dfaecd655f3";
        let src_out = Output::default();
        let mut tx = Transaction::deser(&mut Bytes::copy_from_slice(
            hex::decode(tx_hex).unwrap().to_vec().as_ref(),
        ))
        .unwrap();
        let x = signature_ser(0, vec![src_out], &mut tx, &SigHashType::SINGLE_BIP143);

        assert_eq!(sighash_reg, hex::encode(Sha256d::digest(x).0));
    }
    #[test]
    fn test_hash_utxos() {
        let expect = "020000003a231a1d6cf6540dec47f19b89c1898afcce11c3b715cc5f9da695d0a0ac849e256b777ae02b59cbe4f6476f2953b1597fda5c24a171b51b75312c3e67c271a28cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb9ad6d814fcd29f4412da661a6e1b41cef6ce46adec67abea036b06118ccc18e3200000000efcfbfbbb8b563c473bd97993da9c03d1ac2d21e15174a36d26bf91176b49c33b26201011976a91457314787eafac80afd059f1f31e990d7db9b70fd88ac9cdbc7010000000000000000ea5dc032c309f78f0c89221d52844eaf366097c5bf2051ed1b6fd528707336fa0000000061000000";

        /////////////////////////////////
        let scriptpubkey =
            hex::decode("76a91457314787eafac80afd059f1f31e990d7db9b70fd88ac").unwrap();
        let script_bytecode = Bytes::from(scriptpubkey);

        let txid: TxId = Sha256d::from_be_hex(
            "328ec1cc1861b036a0be7ac6de6ae46cef1cb4e1a661a62d41f429cd4f816dad",
        )
        .unwrap()
        .into();
        // let txid = TxId::from(txid);
        let mut script_sig = ScriptMut::with_capacity(1 + 64 + 1 + PubKey::SIZE);
        script_sig.put_bytecode(&[65]);
        script_sig.put_bytecode(&[
            65, 118, 110, 149, 18, 10, 29, 15, 85, 248, 158, 216, 179, 236, 123, 217, 232, 16, 170,
            119, 18, 17, 221, 183, 16, 37, 83, 20, 107, 83, 27, 44, 56, 107, 143, 25, 216, 192,
            149, 220, 20, 23, 156, 94, 201, 242, 93, 172, 107, 181, 236, 226, 242, 195, 123, 153,
            139, 59, 188, 156, 45, 236, 141, 147, 97,
        ]);
        script_sig.put_bytecode(&[33]);
        script_sig.put_bytecode(&[
            3, 45, 61, 22, 117, 86, 214, 46, 51, 118, 197, 77, 184, 233, 141, 82, 240, 107, 126,
            79, 14, 2, 193, 83, 183, 166, 35, 51, 132, 122, 96, 77, 55,
        ]);
        let category_id = Sha256d::from_be_hex(
            "b2339cb47611f96bd2364a17151ed2c21a3dc0a93d9997bd73c463b5b8bbbfcf",
        )
        .unwrap();
        let source_out = Output {
            script: Script::new(script_bytecode.clone()),
            token: Some(CashToken {
                amount: CompactUint(0),
                category: TxId::from(category_id),
                nft: Some(tx::NFT {
                    capability: NonFungibleTokenCapability(Capability::Minting),
                    commitment: Commitment(Bytes::from(vec![1])), //
                }),
            }),
            value: 29875100,
        };

        let mut ctx = Transaction {
            version: 2,
            inputs: vec![Input {
                prev_out: {
                    OutPoint {
                        txid,
                        outpoint_index: 0,
                    }
                },
                script: Script::default(),
                sequence: 0,
            }],
            outputs: vec![Output {
                script: Script::new(script_bytecode.clone()),
                token: Some(CashToken {
                    amount: CompactUint(0),
                    category: TxId::from(category_id),
                    nft: Some(tx::NFT {
                        capability: NonFungibleTokenCapability(Capability::Minting),
                        commitment: Commitment(Bytes::from(vec![1])), //
                    }),
                }),
                value: 29875100 - 500,
            }],
            locktime: 0,
        };
        // USE FOR SIGNING
        let _x = signature_ser(
            0,
            vec![source_out],
            &mut ctx,
            &SigHashType::ALL_BIP143_UTXOS,
        );

        let fin_tx = Transaction {
            version: 2,
            inputs: vec![Input {
                prev_out: {
                    OutPoint {
                        txid,
                        outpoint_index: 0,
                    }
                },
                script: script_sig.freeze(),
                sequence: 0,
            }],
            outputs: vec![Output {
                script: Script::new(script_bytecode.clone()),
                token: Some(CashToken {
                    amount: CompactUint(0),
                    category: TxId::from(category_id),
                    nft: Some(tx::NFT {
                        capability: NonFungibleTokenCapability(Capability::Minting),
                        commitment: Commitment(Bytes::from(vec![1])), //
                    }),
                }),
                value: 29875100 - 500,
            }],
            locktime: 0,
        };
        assert_eq!(_x, expect);
    }
    #[test]
    fn hashtype_check() {
        println!("{:?}", SigHashType::SINGLE_BIP143_UTXOS.to_u32());
        let sig_hash_type = SigHashType::SINGLE_BIP143_UTXOS;
        let sigtype = sig_hash_type.to_u32() | 0x20;
        println!("{:?}", sigtype)
    }
}

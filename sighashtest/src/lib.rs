// TODO

#[cfg(test)]
mod test {
    use ::sigser::{
        sighashtype::{self, SigHashType},
        sigser,
    };
    use bitcoinsuite_core::{
        error::{self, DataError},
        hash,
        hash::{Hashed, Sha256d},
        script::Script,
        ser::{BitcoinSer, CompactUint},
        tx::{
            self, Capability, CashToken, Coin, Commitment, Input, NonFungibleTokenCapability,
            OutPoint, Output, TokenData, Transaction, TxId,
        },
    };
    use bytes::Bytes;
    use hex;
    use serde_json::*;
    use std::io::Read;
    use std::{array, fs::File};

    #[test]
    fn sighashtest() {
        let mut file = File::open("sighash.json").expect("Could not open file");
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();

        let parsed_data: Value = from_str(&buffer).unwrap();
        let sighash_data = parsed_data.as_array().unwrap();
        println!("{:?}", sighash_data[0]);

        let tx_hex = sighash_data[1][0].as_str().unwrap();
        let tx_script = sighash_data[1][1].as_str().unwrap();
        let tx_index = sighash_data[1][2].as_i64().unwrap();
        let tx_hashtype = sighash_data[1][3].as_i64().unwrap();
        let tx_sighash_reg = sighash_data[1][4].as_str().unwrap();
        let tx_sighash_no_fork = sighash_data[1][5].as_str().unwrap();
        let tx_sighash_no_replay = sighash_data[1][6].as_str().unwrap();
        // let tx_hex = hex::decode(tx_hex);
        let hashtype_flag = &u32::to_le_bytes(tx_hashtype as u32);
        // println!("{:?}", hashtype_flag[0]);
        /*    println!(
            "tx_hex: {:?}\ntx_script:{:?}\ntx_index:{:?}\nhashtype_flag:{:?}\ntx_sighash_reg: {:?}\ntx_sighash_no_fork: {:?}\ntx_sighash_no_replay:{:?}",
            tx_hex,
            tx_script,
            tx_index,
            hashtype_flag,
            tx_sighash_reg,
            tx_sighash_no_fork,
            tx_sighash_no_replay
        ); */
        /*  println!(
            "\n\n{:#?}",
            Transaction::deser(&mut Bytes::copy_from_slice(
                hex::decode(tx_hex).unwrap().to_vec().as_ref()
            ))
        ); */

        let mut sample_tx = Transaction::deser(&mut Bytes::copy_from_slice(
            hex::decode(tx_hex).unwrap().to_vec().as_ref(),
        ))
        .unwrap();

        // let clean_inputs = sample_tx
        //     .inputs
        //     .iter()
        //     .map(|i| Input {
        //         prev_out: i.prev_out,
        //         script: Script::default(),
        //         sequence: i.sequence,
        //     })
        //     .collect();

        // let mut ctx = Transaction {
        //     version: 2,
        //     inputs: clean_inputs,
        //     outputs: sample_tx.outputs,
        //     locktime: sample_tx.locktime,
        // };
        // /*  ctx.inputs.iter().for_each(|i|{
        //     let idx = i.prev_out.outpoint_index;

        // }) */
        let source_out = Output {
            value: 0,
            script: Script::default(),
            token: None,
        };

        // let x = sigser::signature_ser(2, &source_out, &mut sample_tx, &SigHashType::ALL_BIP143);
        // println!("{:?}", i32::to_le_bytes(-1554087033));
        let input = Sha256d::digest(sample_tx.inputs[2].prev_out.ser().as_ref());
        // u32::from_be_bytes();
        // println!("preimage{:?}", x);
        // println!("RESULT{:#010x}", !0xf1);
        // fn hashtype_from_u32(flag: u32) -> u8 {
        //     flag & 0x7b | flag & 0x80 | flag & 0x03
        // }
    }
}

//MIT License
//Copyright (c) 2022 Logos Foundation

// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::fmt::Display;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

//TODO add documentation
pub struct SigHashType {
    pub variant: SigHashTypeVariant,
    pub input_type: SigHashTypeInputs,
    pub utxos: SigHashTypeInputs,
    pub output_type: SigHashTypeOutputs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigHashTypeInputs {
    Fixed,
    Utxos,
    AnyoneCanPay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigHashTypeOutputs {
    All,
    None,
    Single,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigHashTypeVariant {
    Legacy,
    Bip143,
}

impl SigHashType {
    pub const ALL_BIP143: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        utxos: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::All,
    };
    pub const ALL_BIP143_UTXOS: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        utxos: SigHashTypeInputs::Utxos,
        output_type: SigHashTypeOutputs::All,
    };
    pub const NONE_BIP143: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        utxos: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::None,
    };
    pub const NONE_BIP143_UTXOS: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        utxos: SigHashTypeInputs::Utxos,
        output_type: SigHashTypeOutputs::None,
    };
    pub const SINGLE_BIP143: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::Single,
        utxos: SigHashTypeInputs::Fixed,
    };
    pub const SINGLE_BIP143_UTXOS: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::Single,
        utxos: SigHashTypeInputs::Utxos,
    };
    pub const ALL_BIP143_ANYONECANPAY: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::AnyoneCanPay,
        output_type: SigHashTypeOutputs::All,
        utxos: SigHashTypeInputs::Fixed,
    };
    pub const NONE_BIP143_ANYONECANPAY: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::AnyoneCanPay,
        output_type: SigHashTypeOutputs::None,
        utxos: SigHashTypeInputs::Fixed,
    };
    pub const SINGLE_BIP143_ANYONECANPAY: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::AnyoneCanPay,
        output_type: SigHashTypeOutputs::Single,
        utxos: SigHashTypeInputs::Fixed,
    };

    pub fn to_u32(&self) -> u32 {
        self.input_type.to_u32()
            | self.output_type.to_u32()
            | self.variant.to_u32()
            | self.utxos.to_u32()
    }

    pub fn from_u32(flags: u32) -> Option<SigHashType> {
        if flags & 0xffff_ff00 != 0 {
            return None;
        }
        let variant = match flags & 0x7c {
            0 => SigHashTypeVariant::Legacy,
            0x40 => SigHashTypeVariant::Bip143,
            _ => return None,
        };
        let input_type = match flags & 0x80 {
            0 => SigHashTypeInputs::Fixed,
            0x80 => SigHashTypeInputs::AnyoneCanPay,
            _ => unreachable!(),
        };
        let output_type = match flags & 0x03 {
            0 => return None,
            1 => SigHashTypeOutputs::All,
            2 => SigHashTypeOutputs::None,
            3 => SigHashTypeOutputs::Single,
            _ => unreachable!(),
        };
        let utxos = match flags & 0x20 {
            0x20 => SigHashTypeInputs::Utxos,
            _ => SigHashTypeInputs::Fixed,
        };

        Some(SigHashType {
            variant,
            input_type,
            output_type,
            utxos,
        })
    }
}

impl SigHashTypeInputs {
    pub fn to_u32(&self) -> u32 {
        match self {
            SigHashTypeInputs::Fixed => 0x00,
            SigHashTypeInputs::Utxos => 0x20,
            SigHashTypeInputs::AnyoneCanPay => 0x80,
        }
    }
}

impl SigHashTypeOutputs {
    pub fn to_u32(&self) -> u32 {
        match self {
            SigHashTypeOutputs::All => 1,
            SigHashTypeOutputs::None => 2,
            SigHashTypeOutputs::Single => 3,
        }
    }
}

impl SigHashTypeVariant {
    pub fn to_u32(&self) -> u32 {
        match self {
            SigHashTypeVariant::Legacy => 0x00,
            SigHashTypeVariant::Bip143 => 0x40,
        }
    }
}

impl Display for SigHashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.output_type {
            SigHashTypeOutputs::All => write!(f, "ALL")?,
            SigHashTypeOutputs::None => write!(f, "NONE")?,
            SigHashTypeOutputs::Single => write!(f, "SINGLE")?,
        }
        if let SigHashTypeVariant::Bip143 = self.variant {
            write!(f, "|FORKID")?;
        }
        if let SigHashTypeInputs::AnyoneCanPay = self.input_type {
            write!(f, "|ANYONECANPAY")?;
        }
        Ok(())
    }
}

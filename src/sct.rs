use std::io::Write;
use byteorder::{WriteBytesExt, BigEndian};
use base64::prelude::*;

#[derive(Serialize)]
pub struct CTAddChain {
    pub chain: Vec<String>
}

#[derive(Deserialize)]
pub struct JsonSCT {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

impl JsonSCT {
    pub fn parse(&self) -> Result<SCT, ParseError> {
        if self.sct_version != 0 {
            return Err(ParseError::UnsupportedVersion)
        }

        let id: [u8; 32] = BASE64_STANDARD.decode(&self.id)
            .map_err(ParseError::Base64Error)?
            .try_into().map_err(|_| ParseError::InvalidID)?;

        Ok(SCT {
            version: self.sct_version,
            id,
            timestamp: self.timestamp,
            extensions: BASE64_STANDARD.decode(&self.extensions).map_err(ParseError::Base64Error)?,
            signature: BASE64_STANDARD.decode(&self.signature).map_err(ParseError::Base64Error)?
        })
    }
}

pub enum ParseError {
    UnsupportedVersion,
    InvalidID,
    Base64Error(base64::DecodeError)
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("Unsupported SCT version"),
            Self::InvalidID => f.write_str("Invalid log ID"),
            Self::Base64Error(e) => f.write_fmt(format_args!("Error decoding base64: {}", e))
        }
    }
}

pub struct SCT {
    version: u8,
    id: [u8; 32],
    timestamp: u64,
    extensions: Vec<u8>,
    signature: Vec<u8>,
}

pub struct SCTList(Vec<SCT>);

impl SCT {
    pub fn encode(&self) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());

        cursor.write_u8(self.version).unwrap();
        cursor.write_all(&self.id).unwrap();
        cursor.write_u64::<BigEndian>(self.timestamp).unwrap();
        cursor.write_u16::<BigEndian>(self.extensions.len() as u16).unwrap();
        cursor.write_all(&self.extensions).unwrap();
        cursor.write_all(&self.signature).unwrap();

        cursor.into_inner()
    }
}

impl SCTList {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn push(&mut self, sct: SCT) {
        self.0.push(sct)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut sct_list = std::io::Cursor::new(Vec::new());
        for sct in &self.0 {
            let sct = sct.encode();
            sct_list.write_u16::<BigEndian>(sct.len() as u16).unwrap();
            sct_list.write_all(&sct).unwrap();
        }

        let sct_list = sct_list.into_inner();
        let mut cursor = std::io::Cursor::new(Vec::new());
        cursor.write_u16::<BigEndian>(sct_list.len() as u16).unwrap();
        cursor.write_all(&sct_list).unwrap();

        cursor.into_inner()
    }

    pub fn encode_asn1(&self) -> Vec<u8> {
        let encoded = self.encode();
        let mut length = encoded.len();

        let mut cursor = std::io::Cursor::new(Vec::new());

        cursor.write_u8(0x04).unwrap();

        if length < 128 {
            cursor.write_u8(length as u8).unwrap();
        } else {
            let mut values = vec![];
            while length != 0 {
                values.push((length  & 0xff) as u8);
                length >>= 8;
            }
            values.reverse();
            cursor.write_u8(0x80 | values.len() as u8).unwrap();
            cursor.write_all(&values).unwrap();
        }

        cursor.write_all(&encoded).unwrap();

        cursor.into_inner()
    }
}
use bincode;
use std::fmt;
use std::fs::File;
use std::io::{prelude::*, BufReader, SeekFrom};
use std::mem;

mod data_structures;
mod display;

use data_structures::*;

#[derive(Debug)]
pub struct PE {
    pub dos_header: DOSHeader,
    pub nt_headers: NTHeaders,
    pub section_headers: Vec<SectionHeader>,
}

impl fmt::Display for PE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PE
            {}
            {}
            ",
            self.dos_header, self.nt_headers
        )
        .unwrap();
        for section_header in self.section_headers.iter() {
            write!(
                f,
                "{}
            ",
                section_header
            )
            .unwrap();
        }
        Ok(())
    }
}

impl PE {
    pub fn new(file: &File) -> Self {
        let mut buf_reader = BufReader::new(file);
        let mut dos_header_buf = [0u8; mem::size_of::<DOSHeader>()];
        let mut nt_headers_buf = [0u8; mem::size_of::<NTHeaders>()];

        buf_reader.read(&mut dos_header_buf).unwrap();
        let dos_header: DOSHeader = bincode::deserialize(&dos_header_buf).unwrap();
        assert_eq!(dos_header.e_magic.0, 0x5a4du16);
        buf_reader
            .seek(SeekFrom::Start(dos_header.e_lfanew.0 as u64))
            .unwrap();
        buf_reader.read(&mut nt_headers_buf).unwrap();
        let nt_headers: NTHeaders = bincode::deserialize(&nt_headers_buf).unwrap();
        assert_eq!(nt_headers.signature.0, 0x00004550u32);

        let number_of_sections = nt_headers.file_header.number_of_sections.0 as usize;

        let mut section_headers: Vec<SectionHeader> = Vec::with_capacity(number_of_sections);
        let mut section_header_buf = [0u8; mem::size_of::<SectionHeader>()];
        for _ in 0..number_of_sections {
            buf_reader.read(&mut section_header_buf).unwrap();
            let section_header: SectionHeader = bincode::deserialize(&section_header_buf).unwrap();
            section_headers.push(section_header);
        }

        Self {
            dos_header,
            nt_headers,
            section_headers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;
    use std::mem::size_of;

    #[test]
    fn test_sizes() {
        assert_eq!(size_of::<Byte>(), 1);
        assert_eq!(size_of::<Word>(), 2);
        assert_eq!(size_of::<DWord>(), 4);
        assert_eq!(size_of::<DOSHeader>(), 64);
        assert_eq!(size_of::<NTHeaders>(), 248);
        assert_eq!(size_of::<FileHeader>(), 20);
        assert_eq!(size_of::<DataDirectory>(), 8);
        assert_eq!(DataDirectoryEntry::Export as u8, 0u8);
        assert_eq!(DataDirectoryEntry::COMDescriptor as u8, 14u8);
        assert_eq!(size_of::<OptionalHeader>(), 224);
        assert_eq!(size_of::<SectionHeader>(), 40);
    }

    #[test]
    fn test_basic_conversion() {
        let byte: Byte = bincode::deserialize(&[4u8]).unwrap();
        assert_eq!(byte.0, 4u8);
        let word: Word = bincode::deserialize(&[4u8, 0u8]).unwrap();
        assert_eq!(word.0, 4u16);
        let dword: DWord = bincode::deserialize(&[0u8, 0u8, 0u8, 0b1u8]).unwrap();
        assert_eq!(dword.0, 16777216u32);
    }

    #[test]
    fn test_initialization() {
        let bytes = [
            0x4Du8, 0x5Au8, 0x90u8, 0x00u8, 0x03u8, 0x00u8, 0x00u8, 0x00u8, 0x04u8, 0x00u8, 0x00u8,
            0x00u8, 0xFFu8, 0xFFu8, 0x00u8, 0x00u8, 0xB8u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x40u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x80u8, 0x00u8, 0x00u8, 0x00u8,
        ];
        let dos_header: DOSHeader = bincode::deserialize(&bytes).unwrap();
        assert_eq!(dos_header.e_magic.0, 0x5a4d as u16);
        assert_eq!(dos_header.e_lfanew.0, 0x00000080 as u32);

        let mut bytes = [0u8; size_of::<NTHeaders>()];
        bytes[0x4] = 0xFFu8;
        bytes[0x19] = 0xFFu8;
        let nt_headers: NTHeaders = bincode::deserialize(&bytes).unwrap();
        assert_eq!(nt_headers.file_header.machine.0, 0x00FF as u16);
        assert_eq!(nt_headers.optional_header.magic.0, 0xFF00 as u16);
    }

    #[test]
    fn test_printing() {
        assert_eq!("0x0c", format!("{}", Byte(12)));
        assert_eq!("0x000c", format!("{}", Word(12)));
        assert_eq!("0x0000000c", format!("{}", DWord(12)));
    }
}

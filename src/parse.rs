use super::structs::{DOSHeader, NTHeaders, SectionHeader};
use bincode;
use std::fmt;
use std::fs::File;
use std::io::{prelude::*, BufReader, SeekFrom};
use std::mem;

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

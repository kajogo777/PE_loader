use super::data_structures::*;
use chrono::NaiveDateTime;
use std::fmt;
use std::str;

impl fmt::Display for Byte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

impl fmt::Display for DWord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl fmt::Display for DOSHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DOS_HEADER
            \tPE magic: {}
            \toffset to header: {}
            ",
            str::from_utf8(&self.e_magic.0.to_le_bytes()).unwrap(),
            self.e_lfanew
        )
    }
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FILE_HEADER
            \t\tmachine: {}
            \t\tnumber of sections: {}
            \t\ttimestamp: {}
            \t\tcharacteristics: {}
            ",
            self.machine,
            self.number_of_sections.0,
            NaiveDateTime::from_timestamp(self.time_data_stamp.0 as i64, 0),
            self.characteristics
        )
    }
}

impl fmt::Display for OptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OPTIONAL_HEADER
            ",
        )
    }
}

impl fmt::Display for NTHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "NT_HEADERS
            \tsignature: {}
            \t{}
            \t{}
            ",
            str::from_utf8(&self.signature.0.to_le_bytes()).unwrap(),
            self.file_header,
            self.optional_header,
        )
    }
}

impl fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes: Vec<u8> = self.name.iter().map(|byte| byte.0).collect();
        let flags = SectionFlag::get_flags(self.characteristics.0);

        write!(
            f,
            "SECTION_HEADER
            \tname: {}
            \tvirtual size: {}
            \tcharacteristics: {}
            ",
            str::from_utf8(&bytes).unwrap(),
            self.physical_address_or_virtual_size,
            flags
        )
    }
}

impl fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} ", self)
    }
}

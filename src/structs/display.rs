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
            \t\tpointer to symbol table: {}
            \t\tnumber of symbols: {}
            \t\tsize of optional header: {} ({} bytes)
            \t\tcharacteristics: {}
            ",
            self.machine,
            self.number_of_sections.0,
            NaiveDateTime::from_timestamp(self.time_data_stamp.0 as i64, 0),
            self.pointer_to_symbol_table,
            self.number_of_symbols.0,
            self.size_of_optional_header,
            self.size_of_optional_header.0,
            self.characteristics
        )
    }
}

impl fmt::Display for OptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OPTIONAL_HEADER
            \t\tentrypoint address: {}
            \t\timage base (preferred in mem): {}
            \t\tsection alignment (in mem): {} ({} bytes)
            \t\tfile alignment (on disk): {} ({} bytes)
            \t\tsize of image (in mem): {} ({} bytes)
            \t\tsize of headers (offset to first section on disk): {} ({} bytes)
            \t\tnumber of rva and sizes: {} ({})

            \t\tDATA_DIRECTORY
            ",
            self.address_of_entry_point,
            self.image_base,
            self.section_alignment,
            self.section_alignment.0,
            self.file_alignment,
            self.file_alignment.0,
            self.size_of_image,
            self.size_of_image.0,
            self.size_of_headers,
            self.size_of_headers.0,
            self.number_of_rva_and_size,
            self.number_of_rva_and_size.0,
        )
        .unwrap();
        for index in 0..16 {
            write!(
                f,
                "
                \t\t{}
                \t\tvirtual address: {}
                \t\tsize: {} ({} bytes)
                ",
                DATA_DIRECTORY_NAME_LOOKUP[index],
                self.data_directory[index].virtual_address,
                self.data_directory[index].size,
                self.data_directory[index].size.0
            )
            .unwrap();
        }
        Ok(())
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
            \tvirtual size (in mem): {} ({} bytes)
            \tvirtual address (in mem): {}
            \tsize of raw data (on disk): {} ({} bytes)
            \tpointer to raw data (on disk): {}
            \tcharacteristics: {}
            ",
            str::from_utf8(&bytes).unwrap(),
            self.physical_address_or_virtual_size,
            self.physical_address_or_virtual_size.0,
            self.virtual_address,
            self.size_of_raw_data,
            self.size_of_raw_data.0,
            self.pointer_to_raw_data,
            flags,
        )
    }
}

impl fmt::Display for DataDirectoryIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} ", self)
    }
}

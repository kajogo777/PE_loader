use chrono::NaiveDateTime;
use serde::Deserialize;
use std::fmt;
use std::str;

// primitives
#[derive(Deserialize, Debug)]
#[repr(transparent)]
pub struct Byte(pub u8);
#[derive(Deserialize, Debug)]
#[repr(transparent)]
pub struct Word(pub u16);
#[derive(Deserialize, Debug)]
#[repr(transparent)]
pub struct DWord(pub u32);
// type PDWord = DWord;
// type LPDWord = DWord;
// type LPByte = DWord;

// display
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

// image dos header
#[derive(Deserialize, Debug)]
pub struct DOSHeader {
    pub e_magic: Word,
    pub e_cblp: Word,
    pub e_cp: Word,
    pub e_crlc: Word,
    pub e_cparhdr: Word,
    pub e_minalloc: Word,
    pub e_maxalloc: Word,
    pub e_ss: Word,
    pub e_sp: Word,
    pub e_csum: Word,
    pub e_ip: Word,
    pub e_cs: Word,
    pub e_lfarlc: Word,
    pub e_ovno: Word,
    pub e_res: [Word; 4],
    pub e_oemid: Word,
    pub e_oeminfo: Word,
    pub e_res2: [Word; 10],
    pub e_lfanew: DWord,
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

#[derive(Deserialize, Debug)]
pub struct NTHeaders {
    pub signature: DWord,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
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

#[derive(Deserialize, Debug)]
pub struct FileHeader {
    pub machine: Word,
    pub number_of_sections: Word,
    pub time_data_stamp: DWord,
    pub pointer_to_symbol_table: DWord,
    pub number_of_symbols: DWord,
    pub size_of_optional_header: Word,
    pub characteristics: Word,
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

#[derive(Deserialize, Debug)]
pub struct OptionalHeader {
    magic: Word,
    major_linker_version: Byte,
    minor_linker_version: Byte,
    size_of_code: DWord,
    size_of_initialized_data: DWord,
    size_of_uninitialized_data: DWord,
    address_of_entry_point: DWord,
    base_of_code: DWord,
    base_of_data: DWord,
    image_base: DWord,
    section_alignment: DWord,
    file_alignment: DWord,
    major_operating_system_version: Word,
    minor_operating_system_version: Word,
    major_image_version: Word,
    minor_image_version: Word,
    major_subsystem_version: Word,
    minor_subsystem_version: Word,
    win32_version_value: DWord,
    size_of_image: DWord,
    size_of_headers: DWord,
    checksum: DWord,
    subsystem: Word,
    dll_characteristics: Word,
    size_of_stack_reserve: DWord,
    size_of_stack_commit: DWord,
    size_of_heap_reserve: DWord,
    size_of_heap_commit: DWord,
    loader_flags: DWord,
    number_of_rva_and_size: DWord,
    data_directory: [DataDirectory; 16],
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

#[derive(Deserialize, Debug)]
pub struct DataDirectory {
    virtual_address: DWord,
    size: DWord,
}

#[derive(Deserialize, Debug)]
pub struct SectionHeader {
    name: [Byte; 8],
    physical_address_or_virtual_size: DWord,
    virtual_address: DWord,
    size_of_raw_data: DWord,
    pointer_to_raw_data: DWord,
    pointer_to_relocations: DWord,
    pointer_to_linenumbers: DWord,
    number_of_relocations: Word,
    number_of_linenumbers: Word,
    characteristics: DWord,
}
impl fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes: Vec<u8> = self.name.iter().map(|byte| byte.0).collect();
        write!(
            f,
            "SECTION_HEADER
            \tname: {}
            ",
            str::from_utf8(&bytes).unwrap(),
        )
    }
}

enum DataDirectoryEntry {
    Export = 0,
    Import,
    Resource,
    Exception,
    Security,
    BaseReloc,
    Debug,
    ArchitectureReserved,
    GlobalPtr,
    TLS,
    LoadConfig,
    BoundImport,
    IAT,
    DelayImport,
    COMDescriptor,
    Reserved,
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

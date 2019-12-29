use serde::Deserialize;
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

#[derive(Deserialize, Debug)]
pub struct NTHeaders {
    pub signature: DWord,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
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

#[derive(Deserialize, Debug)]
pub struct OptionalHeader {
    pub magic: Word,
    pub major_linker_version: Byte,
    pub minor_linker_version: Byte,
    pub size_of_code: DWord,
    pub size_of_initialized_data: DWord,
    pub size_of_uninitialized_data: DWord,
    pub address_of_entry_point: DWord,
    pub base_of_code: DWord,
    pub base_of_data: DWord,
    pub image_base: DWord,
    pub section_alignment: DWord,
    pub file_alignment: DWord,
    pub major_operating_system_version: Word,
    pub minor_operating_system_version: Word,
    pub major_image_version: Word,
    pub minor_image_version: Word,
    pub major_subsystem_version: Word,
    pub minor_subsystem_version: Word,
    pub win32_version_value: DWord,
    pub size_of_image: DWord,
    pub size_of_headers: DWord,
    pub checksum: DWord,
    pub subsystem: Word,
    pub dll_characteristics: Word,
    pub size_of_stack_reserve: DWord,
    pub size_of_stack_commit: DWord,
    pub size_of_heap_reserve: DWord,
    pub size_of_heap_commit: DWord,
    pub loader_flags: DWord,
    pub number_of_rva_and_size: DWord,
    pub data_directory: [DataDirectory; 16],
}

#[derive(Deserialize, Debug)]
pub struct DataDirectory {
    pub virtual_address: DWord,
    pub size: DWord,
}

#[derive(Deserialize, Debug)]
pub struct SectionHeader {
    pub name: [Byte; 8],
    pub physical_address_or_virtual_size: DWord,
    pub virtual_address: DWord,
    pub size_of_raw_data: DWord,
    pub pointer_to_raw_data: DWord,
    pub pointer_to_relocations: DWord,
    pub pointer_to_linenumbers: DWord,
    pub number_of_relocations: Word,
    pub number_of_linenumbers: Word,
    pub characteristics: DWord,
}

pub enum DataDirectoryEntry {
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

bitflags! {
    pub struct SectionFlag: u32 {
        const MEM_EXECUTE = 0x20000000;
        const MEM_READ = 0x40000000;
        const MEM_WRITE = 0x80000000;
    }
}

impl SectionFlag {
    pub fn get_flags(value: u32) -> String {
        let mut flags = String::new();

        for flag in &[
            SectionFlag::MEM_EXECUTE,
            SectionFlag::MEM_READ,
            SectionFlag::MEM_WRITE,
        ] {
            if flag.bits & value > 0 {
                flags += &format!("{}| ", flag.to_string());
            }
        }
        flags = flags.trim().to_string();
        flags.pop();
        flags
    }
}

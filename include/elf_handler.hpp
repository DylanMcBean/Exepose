#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <stdexcept>
#include <variant>
#include <vector>

// SPEC - https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

constexpr uint8_t EI_NIDENT = 16;
constexpr uint8_t ELFMAG_SIZE = 4;
constexpr uint32_t ELFMAG = 0x464c457f; // "\x7fELF"
constexpr uint8_t ELFPAD = 0x00;
constexpr uint8_t ELFCLASS_OFFSET = 4;
constexpr uint8_t ELFDATA_OFFSET = 5;
constexpr uint8_t ELFVERSION_OFFSET = 6;
constexpr uint8_t ELFOSABI_OFFSET = 7;
constexpr uint8_t ELFABIVERSION_OFFSET = 8;
constexpr uint8_t ELFCLASS32 = 1;
constexpr uint8_t ELFCLASS64 = 2;
constexpr uint8_t ELFDATA2LSB = 1;
constexpr uint8_t ELFDATA2MSB = 2;

// Elf Definitions - Same for 32bit and 64bit
using ElfHalf = uint16_t;
using ElfWord = uint32_t;

// 32bit ELF definitions
using Elf32Addr = uint32_t;
using Elf32Off = uint32_t;

// 64bit ELF definitions
using Elf64Addr = uint64_t;
using Elf64Off = uint64_t;

// 32bit ELF header
typedef struct
{
    unsigned char e_ident[EI_NIDENT]; // ELF identification
    ElfHalf e_type;                   // Object file type
    ElfHalf e_machine;                // Machine type
    ElfWord e_version;                // Object file version
    Elf32Addr e_entry;                // Entry point address
    Elf32Off e_phoff;                 // Program header offset
    Elf32Off e_shoff;                 // Section header offset
    ElfWord e_flags;                  // Processor-specific flags
    ElfHalf e_ehsize;                 // ELF header size
    ElfHalf e_phentsize;              // Size of program header entry
    ElfHalf e_phnum;                  // Number of program header entries
    ElfHalf e_shentsize;              // Size of section header entry
    ElfHalf e_shnum;                  // Number of section header entries
    ElfHalf e_shstrndx;               // Section name string table index
} Elf32Ehdr;

// 64bit ELF header
typedef struct
{
    unsigned char e_ident[EI_NIDENT]; // ELF identification
    ElfHalf e_type;                   // Object file type
    ElfHalf e_machine;                // Machine type
    ElfWord e_version;                // Object file version
    Elf64Addr e_entry;                // Entry point address
    Elf64Off e_phoff;                 // Program header offset
    Elf64Off e_shoff;                 // Section header offset
    ElfWord e_flags;                  // Processor-specific flags
    ElfHalf e_ehsize;                 // ELF header size
    ElfHalf e_phentsize;              // Size of program header entry
    ElfHalf e_phnum;                  // Number of program header entries
    ElfHalf e_shentsize;              // Size of section header entry
    ElfHalf e_shnum;                  // Number of section header entries
    ElfHalf e_shstrndx;               // Section name string table index
} Elf64Ehdr;

enum class ElfType
{
    ELF_32 = 1, // 32-bit ELF
    ELF_64 = 2, // 64-bit ELF
    UNKNOWN = 3 // Unknown ELF
};

enum class ElfDataEncoding
{
    ELFDATA2LSB = 1, // Little-endian
    ELFDATA2MSB = 2, // Big-endian
    UNKNOWN = 3      // Unknown
};

enum class ElfOsABI
{
    ELFOSABI_NONE = 0,        // No extensions or unspecified
    ELFOSABI_HPUX = 1,        // Hewlett-Packard HP-UX
    ELFOSABI_NETBSD = 2,      // NetBSD
    ELFOSABI_LINUX = 3,       // Linux
    ELFOSABI_SOLARIS = 6,     // Sun Solaris
    ELFOSABI_AIX = 7,         // AIX
    ELFOSABI_IRIX = 8,        // IRIX
    ELFOSABI_FREEBSD = 9,     // FreeBSD
    ELFOSABI_TRU64 = 10,      // Compaq TRU64 UNIX
    ELFOSABI_MODESTO = 11,    // Novell Modesto
    ELFOSABI_OPENBSD = 12,    // Open BSD
    ELFOSABI_OPENVMS = 13,    // Open VMS
    ELFOSABI_NSK = 14,        // Hewlett-Packard Non-Stop Kernel
    ELFOSABI_AROS = 15,       // Amiga Research OS
    ELFOSABI_FENIXOS = 16,    // The FenixOS highly scalable multi-core OS
    ELFOSABI_CLOUDABI = 17,   // Nuxi CloudABI
    ELFOSABI_OPENVOS = 18,    // Stratus Technologies OpenVOS
    ELFOSABI_ARM_AEABI = 64,  // ARM EABI
    ELFOSABI_ARM = 97,        // ARM
    ELFOSABI_STANDALONE = 255 // Standalone (embedded) application
};

enum class ProgramHeaderType
{
    PT_NULL = 0,    // Unused entry
    PT_LOAD = 1,    // Loadable segment
    PT_DYNAMIC = 2, // Dynamic linking information
    PT_INTERP = 3,  // Interpreter pathname
    PT_NOTE = 4,    // Auxiliary information
    PT_SHLIB = 5,   // Reserved
    PT_PHDR = 6,    // The program header table itself
    PT_TLS = 7,     // The thread-local storage template
    PT_OS = 8,      // operating system-specific pt entry type
    PT_OROC = 9,    // processor-specific program hdr entry type
};

typedef struct ProgramHeaderFlags
{
    static constexpr uint32_t PF_X = 0x1; // Execute
    static constexpr uint32_t PF_W = 0x2; // Write
    static constexpr uint32_t PF_R = 0x4; // Read
} ProgramHeaderFlags;

// 32bit ELF program header
typedef struct
{
    ElfWord p_type;    // Type of segment
    Elf32Off p_offset; // Offset in file
    Elf32Addr p_vaddr; // Virtual address in memory
    Elf32Addr p_paddr; // Reserved
    ElfWord p_filesz;  // Size of segment in file
    ElfWord p_memsz;   // Size of segment in memory
    ElfWord p_flags;   // Segment attributes
    ElfWord p_align;   // Alignment of segment
} Elf32Phdr;

// 64bit ELF program header
typedef struct
{
    ElfWord p_type;    // Type of segment
    Elf32Off p_flags;  // Segment attributes
    Elf64Off p_offset; // Offset in file
    Elf64Addr p_vaddr; // Virtual address in memory
    Elf64Addr p_paddr; // Reserved
    Elf64Off p_filesz; // Size of segment in file
    Elf64Off p_memsz;  // Size of segment in memory
    Elf64Off p_align;  // Alignment of segment
} Elf64Phdr;

enum class SectionHeaderType
{
    SHT_NULL = 0,           // Section header table entry unused
    SHT_PROGBITS = 1,       // Program data
    SHT_SYMTAB = 2,         // Symbol table
    SHT_STRTAB = 3,         // String table
    SHT_RELA = 4,           // Relocation entries with addends
    SHT_HASH = 5,           // Symbol hash table
    SHT_DYNAMIC = 6,        // Dynamic linking information
    SHT_NOTE = 7,           // Notes
    SHT_NOBITS = 8,         // Program space with no data (bss)
    SHT_REL = 9,            // Relocation entries, no addends
    SHT_SHLIB = 10,         // Reserved
    SHT_DYNSYM = 11,        // Dynamic linker symbol table
    SHT_INIT_ARRAY = 14,    // Array of constructors
    SHT_FINI_ARRAY = 15,    // Array of destructors
    SHT_PREINIT_ARRAY = 16, // Array of pre-constructors
    SHT_GROUP = 17,         // Section group
    SHT_SYMTAB_SHNDX = 18,  // Extended section indeces
    SHT_NUM = 19,           // Number of defined types.
    SHT_OS = 20,            // Start OS-specific.
};

typedef struct SectionHeaderFlags
{
    static constexpr uint64_t SHF_WRITE = 0x1;              // Writable
    static constexpr uint64_t SHF_ALLOC = 0x2;              // Occupies memory during execution
    static constexpr uint64_t SHF_EXECINSTR = 0x4;          // Executable
    static constexpr uint64_t SHF_MERGE = 0x10;             // Might be merged
    static constexpr uint64_t SHF_STRINGS = 0x20;           // Contains nul-terminated strings
    static constexpr uint64_t SHF_INFO_LINK = 0x40;         // `sh_info' contains SHT index
    static constexpr uint64_t SHF_LINK_ORDER = 0x80;        // Preserve order after combining
    static constexpr uint64_t SHF_OS_NONCONFORMING = 0x100; // Non-standard OS specific handling required
    static constexpr uint64_t SHF_GROUP = 0x200;            // Section is member of a group
    static constexpr uint64_t SHF_TLS = 0x400;              // Section hold thread-local data
    static constexpr uint64_t SHF_MASKOS = 0x0ff00000;      // OS-specific
    static constexpr uint64_t SHF_MASKPROC = 0xf0000000;    // Processor-specific
    static constexpr uint64_t SHF_ORDERED = 0x4000000;      // Special ordering requirement (Solaris)
    static constexpr uint64_t SHF_EXCLUDE = 0x8000000; // Section is excluded unless referenced or allocated (Solaris)
} SectionHeaderFlags;

// 32bit ELF section header
typedef struct
{
    ElfWord sh_name;      // Section name (string tbl index)
    ElfWord sh_type;      // Section type
    ElfWord sh_flags;     // Section flags
    Elf32Addr sh_addr;    // Section virtual addr at execution
    Elf32Off sh_offset;   // Section file offset
    ElfWord sh_size;      // Section size in bytes
    ElfWord sh_link;      // Link to another section
    ElfWord sh_info;      // Additional section information
    ElfWord sh_addralign; // Section alignment
    ElfWord sh_entsize;   // Entry size if section holds table
} Elf32Shdr;

// 64bit ELF section header
typedef struct
{
    ElfWord sh_name;        // Section name (string tbl index)
    ElfWord sh_type;        // Section type
    Elf64Off sh_flags;      // Section flags
    Elf64Addr sh_addr;      // Section virtual addr at execution
    Elf64Off sh_offset;     // Section file offset
    Elf64Addr sh_size;      // Section size in bytes
    ElfWord sh_link;        // Link to another section
    ElfWord sh_info;        // Additional section information
    Elf64Addr sh_addralign; // Section alignment
    Elf64Addr sh_entsize;   // Entry size if section holds table
} Elf64Shdr;

// 32bit ELF symbol table entry
typedef struct
{
    ElfWord st_name;        // Symbol name (string tbl index)
    Elf32Addr st_value;     // Symbol value
    ElfWord st_size;        // Symbol size
    unsigned char st_info;  // Symbol type and binding
    unsigned char st_other; // Symbol visibility
    ElfHalf st_shndx;       // Section index
} Elf32Sym;

// 64bit ELF symbol table entry
typedef struct
{
    ElfWord st_name;        // Symbol name (string tbl index)
    unsigned char st_info;  // Symbol type and binding
    unsigned char st_other; // Symbol visibility
    ElfHalf st_shndx;       // Section index
    Elf64Addr st_value;     // Symbol value
    Elf64Addr st_size;      // Symbol size
} Elf64Sym;

class ElfHandler
{
  public:
    // Public Constructors/Destructors
    explicit ElfHandler(const std::string &fileName);

    void PrintSectionHeaders();

  private:
    // Private Data Members
    uint64_t _fileSize;
    std::variant<Elf32Ehdr, Elf64Ehdr> _elfEhdr;
    std::vector<std::variant<Elf32Phdr, Elf64Phdr>> _elfPhdrs;
    std::vector<std::variant<Elf32Shdr, Elf64Shdr>> _elfShdrs;
    std::vector<std::variant<Elf32Sym, Elf64Sym>> _elfSymtab;
    std::vector<std::variant<Elf32Sym, Elf64Sym>> _elfDynamicSymtab;
    ElfType _elfType;
    ElfDataEncoding _elfDataEncoding;
    uint8_t _elfEvCurrent = 0;
    ElfOsABI _elfOsabi;
    std::map<uint64_t, std::string> _sectionHeaderNameMap;
    std::map<uint64_t, std::string> _symbolTableMap;
    std::map<uint64_t, std::string> _dynamicSymbolTableMap;

    // Private Helper Methods
    void ReadFile(const std::string &fileName);
    template <typename T> void ReadElfHeader(std::ifstream &file);
    template <typename T1, typename T2> void ReadElfProgramHeaders(std::ifstream &file);
    template <typename T1, typename T2> void ReadElfSectionHeaders(std::ifstream &file);
    template <typename T1, typename T2, typename T3> void CreateSectionHeaderNameMap(std::ifstream &file);
    template <typename T1, typename T2, typename T3, typename T4> void ParseSymbolTable(std::ifstream &file);
    ElfOsABI MapToElfOsABI(uint16_t value);

    // Private Validation Methods
    void ValidateElfMagic(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidateElfClass(const std::array<uint8_t, EI_NIDENT> &ident, std::ifstream &file);
    void ValidateElfDataEncoding(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidateFileVersion(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidateOSABI(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidateABIVersion(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidatePAD(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidateIdent(const std::array<uint8_t, EI_NIDENT> &ident);
    void ValidateElfProgramHeaders(std::ifstream &file);
    void ValidateElfSectionHeaders(std::ifstream &file);

    // Private Methods
    void CreateSectionHeaderNameMap(std::ifstream &file);
    void ParseSymbolTable(std::ifstream &file);
};
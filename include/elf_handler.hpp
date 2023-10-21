#pragma once

#include <array>
#include <cstdint>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string.h>
#include <variant>

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
using Elf_half = uint16_t;
using Elf_word = uint32_t;

// 32bit ELF definitions
using Elf32_addr = uint32_t;
using Elf32_off = uint32_t;

// 64bit ELF definitions
using Elf64_addr = uint64_t;
using Elf64_off = uint64_t;

// 32bit ELF header
typedef struct
{
    unsigned char e_ident[EI_NIDENT]; // ELF identification
    Elf_half e_type;                  // Object file type
    Elf_half e_machine;               // Machine type
    Elf_word e_version;               // Object file version
    Elf32_addr e_entry;               // Entry point address
    Elf32_off e_phoff;                // Program header offset
    Elf32_off e_shoff;                // Section header offset
    Elf_word e_flags;                 // Processor-specific flags
    Elf_half e_ehsize;                // ELF header size
    Elf_half e_phentsize;             // Size of program header entry
    Elf_half e_phnum;                 // Number of program header entries
    Elf_half e_shentsize;             // Size of section header entry
    Elf_half e_shnum;                 // Number of section header entries
    Elf_half e_shstrndx;              // Section name string table index
} Elf32_Ehdr;

// 64bit ELF header
typedef struct
{
    unsigned char e_ident[EI_NIDENT]; // ELF identification
    Elf_half e_type;                  // Object file type
    Elf_half e_machine;               // Machine type
    Elf_word e_version;               // Object file version
    Elf64_addr e_entry;               // Entry point address
    Elf64_off e_phoff;                // Program header offset
    Elf64_off e_shoff;                // Section header offset
    Elf_word e_flags;                 // Processor-specific flags
    Elf_half e_ehsize;                // ELF header size
    Elf_half e_phentsize;             // Size of program header entry
    Elf_half e_phnum;                 // Number of program header entries
    Elf_half e_shentsize;             // Size of section header entry
    Elf_half e_shnum;                 // Number of section header entries
    Elf_half e_shstrndx;              // Section name string table index
} Elf64_Ehdr;

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

class ElfHandler
{
  public:
    // Public Constructors/Destructors
    explicit ElfHandler(const std::string &fileName);

  private:
    // Private Data Members
    std::variant<Elf32_Ehdr, Elf64_Ehdr> _elf_ehdr;
    ElfType _elf_type;
    ElfDataEncoding _elf_data_encoding;
    uint8_t _elf_ev_current = 0;
    ElfOsABI _elf_osabi;

    // Private Helper Methods
    void ReadFile(const std::string &fileName);
    template <typename T> void ReadElfHeader(std::ifstream &file);
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
};
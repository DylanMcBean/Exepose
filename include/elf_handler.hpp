#pragma once

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <array>
#include <stdexcept>
#include <variant>

// SPEC - https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

constexpr int EI_NIDENT = 16;

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
    ELF_32,
    ELF_64,
    UNKNOWN
};

class ElfHandler
{
  public:
    explicit ElfHandler(const std::string& fileName);
    ~ElfHandler();

  private:
    void ReadFile(const std::string& fileName);
    std::variant<Elf32_Ehdr, Elf64_Ehdr> _elf_ehdr;
    ElfType _elf_type;
};
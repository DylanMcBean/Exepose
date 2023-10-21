#include "elf_handler.hpp"
#include "helper.hpp"

ElfHandler::ElfHandler(const std::string& fileName)
{
    ReadFile(fileName);
}

void ElfHandler::ReadFile(const std::string& fileName)
{
    std::ifstream file(fileName, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open file");
    }

    std::array<uint8_t, EI_NIDENT> ident{};
    if (!file.readsome(reinterpret_cast<char*>(ident.data()), EI_NIDENT))
    {
        throw std::runtime_error("Incomplete ident read");
    }


    if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F')
    {
        throw std::runtime_error("Invalid ELF magic");
    }
    else if (ident[4] == 1)
    {
        _elf_type = ElfType::ELF_32;
        Elf32_Ehdr ehdr{};
        file.seekg(0);
        if (!file.readsome(reinterpret_cast<char*>(&ehdr), sizeof(Elf32_Ehdr)))
        {
            throw std::runtime_error("Incomplete 32-bit ELF header read");
        }
        _elf_ehdr = ehdr;
    }
    else if (ident[4] == 2)
    {
        _elf_type = ElfType::ELF_64;
        Elf64_Ehdr ehdr{};
        file.seekg(0);
        if (!file.readsome(reinterpret_cast<char*>(&ehdr), sizeof(Elf64_Ehdr)))
        {
            throw std::runtime_error("Incomplete 64-bit ELF header read");
        }
        _elf_ehdr = ehdr;
    }
    else
    {
        throw std::runtime_error("Unknown header value, expected 1/2 got " + std::to_string(ident[4]));
    }

    if (_elf_type == ElfType::ELF_32 && !std::holds_alternative<Elf32_Ehdr>(_elf_ehdr))
    {
        throw std::runtime_error("Invalid ELF header type");
    }
    else if (_elf_type == ElfType::ELF_64 && !std::holds_alternative<Elf64_Ehdr>(_elf_ehdr))
    {
        throw std::runtime_error("Invalid ELF header type");
    }

}

// Destructor
ElfHandler::~ElfHandler() = default;
#include "elf_handler.hpp"
#include "helper.hpp"

ElfHandler::ElfHandler(const std::string &fileName)
{
    ReadFile(fileName);
}

void ElfHandler::ReadFile(const std::string &fileName)
{
    std::ifstream file(fileName, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file: " + fileName);
    }

    std::array<uint8_t, EI_NIDENT> ident{};
    file.read(reinterpret_cast<char *>(ident.data()), EI_NIDENT);
    if (file.gcount() != EI_NIDENT)
    {
        throw std::runtime_error("Incomplete ident read from file: " + fileName);
    }

    ValidateElfMagic(ident);
    ValidateElfClass(ident, file);
    ValidateElfDataEncoding(ident);
    ValidateFileVersion(ident);
    ValidateOSABI(ident);
    ValidateABIVersion(ident);
    ValidatePAD(ident);
    ValidateIdent(ident);
    ValidateElfProgramHeaders(file);
    ValidateElfSectionHeaders(file);
}

void ElfHandler::ValidateElfMagic(const std::array<uint8_t, EI_NIDENT> &ident)
{
    if (memcmp(ident.data(), &ELFMAG, ELFMAG_SIZE) != 0)
    {
        std::string expectedMagic = Helper::toByteEncoded(reinterpret_cast<const uint8_t *>(&ELFMAG), ELFMAG_SIZE);
        std::string receivedMagic = Helper::toByteEncoded(ident.data(), ELFMAG_SIZE);

        throw std::runtime_error("Invalid ELF magic, expected: '" + expectedMagic + "', got: '" + receivedMagic + "'");
    }
}

void ElfHandler::ValidateElfClass(const std::array<uint8_t, EI_NIDENT> &ident, std::ifstream &file)
{
    switch (ident[ELFCLASS_OFFSET])
    {
    case ELFCLASS32:
        _elf_type = ElfType::ELF_32;
        ReadElfHeader<Elf32_Ehdr>(file);
        break;

    case ELFCLASS64:
        _elf_type = ElfType::ELF_64;
        ReadElfHeader<Elf64_Ehdr>(file);
        break;

    default:
        throw std::runtime_error("Invalid ELF class");
    }
}

template <typename Elf_Ehdr_Type> void ElfHandler::ReadElfHeader(std::ifstream &file)
{
    Elf_Ehdr_Type ehdr{};
    file.seekg(0);
    file.read(reinterpret_cast<char *>(&ehdr), sizeof(Elf_Ehdr_Type));
    if (file.gcount() != sizeof(Elf_Ehdr_Type))
    {
        throw std::runtime_error("Incomplete ELF header read");
    }
    _elf_ehdr = ehdr;
    _elf_ev_current = ehdr.e_version;
}

void ElfHandler::ValidateElfDataEncoding(const std::array<uint8_t, EI_NIDENT> &ident)
{
    switch (ident[ELFDATA_OFFSET])
    {
    case ELFDATA2LSB:
        _elf_data_encoding = ElfDataEncoding::ELFDATA2LSB;
        break;

    case ELFDATA2MSB:
        _elf_data_encoding = ElfDataEncoding::ELFDATA2MSB;
        break;

    default:
        throw std::runtime_error("Invalid ELF data encoding");
    }
}

void ElfHandler::ValidateFileVersion(const std::array<uint8_t, EI_NIDENT> &ident)
{
    if (ident[ELFVERSION_OFFSET] != _elf_ev_current)
    {
        throw std::runtime_error("Invalid ELF file version");
    }
}

void ElfHandler::ValidateOSABI(const std::array<uint8_t, EI_NIDENT> &ident)
{
    _elf_osabi = MapToElfOsABI(ident[ELFOSABI_OFFSET]);
}

ElfOsABI ElfHandler::MapToElfOsABI(uint16_t value)
{
    switch (value)
    {
    case 0:
        return ElfOsABI::ELFOSABI_NONE;
    case 1:
        return ElfOsABI::ELFOSABI_HPUX;
    case 2:
        return ElfOsABI::ELFOSABI_NETBSD;
    case 3:
        return ElfOsABI::ELFOSABI_LINUX;
    case 6:
        return ElfOsABI::ELFOSABI_SOLARIS;
    case 7:
        return ElfOsABI::ELFOSABI_AIX;
    case 8:
        return ElfOsABI::ELFOSABI_IRIX;
    case 9:
        return ElfOsABI::ELFOSABI_FREEBSD;
    case 10:
        return ElfOsABI::ELFOSABI_TRU64;
    case 11:
        return ElfOsABI::ELFOSABI_MODESTO;
    case 12:
        return ElfOsABI::ELFOSABI_OPENBSD;
    case 13:
        return ElfOsABI::ELFOSABI_OPENVMS;
    case 14:
        return ElfOsABI::ELFOSABI_NSK;
    case 15:
        return ElfOsABI::ELFOSABI_AROS;
    case 16:
        return ElfOsABI::ELFOSABI_FENIXOS;
    case 17:
        return ElfOsABI::ELFOSABI_CLOUDABI;
    case 18:
        return ElfOsABI::ELFOSABI_OPENVOS;
    case 64:
        return ElfOsABI::ELFOSABI_ARM_AEABI;
    case 97:
        return ElfOsABI::ELFOSABI_ARM;
    case 255:
        return ElfOsABI::ELFOSABI_STANDALONE;
    default:
        Helper::LogWarning("Unknown ELF OS ABI: %d\n", value);
        return ElfOsABI::ELFOSABI_NONE;
    }
}

void ElfHandler::ValidateABIVersion(const std::array<uint8_t, EI_NIDENT> &ident)
{
    // TODO: Implement
}

void ElfHandler::ValidatePAD(const std::array<uint8_t, EI_NIDENT> &ident)
{
    if (memcmp(ident.data() + ELFABIVERSION_OFFSET, &ELFPAD, sizeof(ELFPAD)) != 0)
    {
        // shouldnt throw an error, but should log a warning that padding is not all zero
        Helper::LogWarning("ELF padding is not all zero'd\n");
    }
}

void ElfHandler::ValidateIdent(const std::array<uint8_t, EI_NIDENT> &ident)
{
    // TODO: Implement
}

void ElfHandler::ValidateElfProgramHeaders(std::ifstream &file)
{
    switch (_elf_type)
    {
    case ElfType::ELF_32:
        ReadElfProgramHeaders<Elf32_Phdr>(file);
        break;
    case ElfType::ELF_64:
        ReadElfProgramHeaders<Elf64_Phdr>(file);
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }
}

template <typename Elf_Phdr_Type> void ElfHandler::ReadElfProgramHeaders(std::ifstream &file)
{
    uint64_t phoff = 0;
    uint64_t phnum = 0;
    switch (_elf_type)
    {
    case ElfType::ELF_32:
        phoff = std::get<Elf32_Ehdr>(_elf_ehdr).e_phoff;
        phnum = std::get<Elf32_Ehdr>(_elf_ehdr).e_phnum;
        break;
    case ElfType::ELF_64:
        phoff = std::get<Elf64_Ehdr>(_elf_ehdr).e_phoff;
        phnum = std::get<Elf64_Ehdr>(_elf_ehdr).e_phnum;
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }
    file.seekg(phoff);
    for (size_t i = 0; i < phnum; ++i)
    {
        Elf_Phdr_Type phdr{};
        file.read(reinterpret_cast<char *>(&phdr), sizeof(Elf_Phdr_Type));
        if (file.gcount() != sizeof(Elf_Phdr_Type))
        {
            throw std::runtime_error("Incomplete ELF program header read");
        }
        _elf_phdrs.push_back(phdr);
    }
}

void ElfHandler::ValidateElfSectionHeaders(std::ifstream &file)
{
    switch (_elf_type)
    {
    case ElfType::ELF_32:
        ReadElfSectionHeaders<Elf32_Shdr>(file);
        break;
    case ElfType::ELF_64:
        ReadElfSectionHeaders<Elf64_Shdr>(file);
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }
}

template <typename Elf_Shdr_Type> void ElfHandler::ReadElfSectionHeaders(std::ifstream &file)
{
    uint64_t shoff = 0;
    uint64_t shnum = 0;
    switch (_elf_type)
    {
    case ElfType::ELF_32:
        shoff = std::get<Elf32_Ehdr>(_elf_ehdr).e_shoff;
        shnum = std::get<Elf32_Ehdr>(_elf_ehdr).e_shnum;
        break;
    case ElfType::ELF_64:
        shoff = std::get<Elf64_Ehdr>(_elf_ehdr).e_shoff;
        shnum = std::get<Elf64_Ehdr>(_elf_ehdr).e_shnum;
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }
    file.seekg(shoff);
    for (size_t i = 0; i < shnum; ++i)
    {
        Elf_Shdr_Type shdr{};
        file.read(reinterpret_cast<char *>(&shdr), sizeof(Elf_Shdr_Type));
        if (file.gcount() != sizeof(Elf_Shdr_Type))
        {
            throw std::runtime_error("Incomplete ELF section header read");
        }
        _elf_shdrs.push_back(shdr);
    }
}
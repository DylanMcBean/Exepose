#include "elf_handler.hpp"
#include "helper.hpp"

/**
 * @brief Constructor for the ElfHandler class.
 * 
 * @param fileName The name of the ELF file to be read.
 */
ElfHandler::ElfHandler(const std::string &fileName)
{
    ReadFile(fileName);
}

/**
 * Reads an ELF file and validates its headers and sections.
 * @param fileName The path to the ELF file to read.
 * @throws std::runtime_error if the file cannot be opened or if any of the headers or sections are invalid.
 */
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

    CreateSectionHeaderNameMap(file);
}

/**
 * Validates the ELF magic number of the given ident array.
 * @param ident The array containing the ELF magic number.
 * @throws std::runtime_error if the magic number is invalid.
 */
void ElfHandler::ValidateElfMagic(const std::array<uint8_t, EI_NIDENT> &ident)
{
    if (memcmp(ident.data(), &ELFMAG, ELFMAG_SIZE) != 0)
    {
        std::string expectedMagic = Helper::toByteEncoded(reinterpret_cast<const uint8_t *>(&ELFMAG), ELFMAG_SIZE);
        std::string receivedMagic = Helper::toByteEncoded(ident.data(), ELFMAG_SIZE);

        throw std::runtime_error("Invalid ELF magic, expected: '" + expectedMagic + "', got: '" + receivedMagic + "'");
    }
}

/**
 * Validates the ELF class of the given file and reads the ELF header accordingly.
 * 
 * @param ident The array of bytes containing the ELF identification information.
 * @param file The input file stream to read the ELF header from.
 * @throws std::runtime_error if the ELF class is invalid.
 */
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

/**
 * @brief Reads the ELF header from the given file stream and stores it in the ElfHandler object.
 * 
 * @tparam Elf_Ehdr_Type The ELF header type to read.
 * @param file The file stream to read from.
 * @throws std::runtime_error If an incomplete ELF header is read.
 */
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

/**
 * @brief Validates the encoding of the ELF data.
 * 
 * @param ident The array of bytes containing the ELF identification information.
 * @throws std::runtime_error if the ELF data encoding is invalid.
 */
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

/**
 * @brief Validates the ELF file version.
 * 
 * @param ident The array of bytes containing the ELF file identification information.
 * @throws std::runtime_error if the ELF file version is invalid.
 */
void ElfHandler::ValidateFileVersion(const std::array<uint8_t, EI_NIDENT> &ident)
{
    if (ident[ELFVERSION_OFFSET] != _elf_ev_current)
    {
        throw std::runtime_error("Invalid ELF file version");
    }
}

/**
 * @brief Validates the OS ABI of the ELF file.
 * 
 * @param ident The array of bytes containing the ELF file identification information.
 */
void ElfHandler::ValidateOSABI(const std::array<uint8_t, EI_NIDENT> &ident)
{
    _elf_osabi = MapToElfOsABI(ident[ELFOSABI_OFFSET]);
}

/**
 * Maps a given uint16_t value to its corresponding ElfOsABI enum value.
 * @param value The uint16_t value to be mapped.
 * @return The corresponding ElfOsABI enum value.
 * If the given value is not recognized, a warning message is logged and ElfOsABI::ELFOSABI_NONE is returned.
 */
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

/**
 * Validates the Program Auxiliary Data (PAD) of an ELF file.
 * @param ident The array of bytes representing the ELF file header.
 * @return void
 */
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

/**
 * @brief Validates the program headers of an ELF file.
 * 
 * @param file The input file stream of the ELF file.
 * @throws std::runtime_error if the ELF type is invalid.
 */
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

/**
 * @brief Reads the program headers of an ELF file and stores them in a vector.
 * 
 * @tparam Elf_Phdr_Type The type of the ELF program header.
 * @param file The input file stream of the ELF file.
 * @throws std::runtime_error if the ELF type is invalid or if an incomplete ELF program header is read.
 */
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

/**
 * @brief Validates the section headers of an ELF file.
 * 
 * @param file The input file stream of the ELF file.
 * @throws std::runtime_error If the ELF type is invalid.
 */
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

/**
 * @brief Reads the section headers of an ELF file.
 * 
 * @tparam Elf_Shdr_Type The type of the ELF section header.
 * @param file The input file stream to read from.
 * @throws std::runtime_error If the ELF type is invalid or if the section header read is incomplete.
 */
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

/**
 * @brief Creates a map of section header names and their corresponding indices.
 * 
 * @param file The input file stream containing the ELF file.
 * @throws std::runtime_error if the ELF type is invalid, the section header string table index is invalid,
 * the ELF section header string table read is incomplete, or the ELF section header name offset is invalid.
 */
void ElfHandler::CreateSectionHeaderNameMap(std::ifstream &file)
{
    uint64_t shstrndx = 0;
    
    switch (_elf_type)
    {
    case ElfType::ELF_32:
        shstrndx = std::get<Elf32_Ehdr>(_elf_ehdr).e_shstrndx;
        break;
    case ElfType::ELF_64:
        shstrndx = std::get<Elf64_Ehdr>(_elf_ehdr).e_shstrndx;
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }

    if (shstrndx >= _elf_shdrs.size())
    {
        throw std::runtime_error("Invalid ELF section header string table index");
    }

    auto &shstrtab_hdr = _elf_shdrs[shstrndx];
    uint64_t shstrtab_offset = 0;
    uint64_t shstrtab_size = 0;

    switch (_elf_type)
    {
    case ElfType::ELF_32:
        shstrtab_offset = std::get<Elf32_Shdr>(shstrtab_hdr).sh_offset;
        shstrtab_size = std::get<Elf32_Shdr>(shstrtab_hdr).sh_size;
        break;
    case ElfType::ELF_64:
        shstrtab_offset = std::get<Elf64_Shdr>(shstrtab_hdr).sh_offset;
        shstrtab_size = std::get<Elf64_Shdr>(shstrtab_hdr).sh_size;
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }

    file.seekg(shstrtab_offset);

    if (shstrtab_size == 0 || shstrtab_size > (file.end - file.beg))
    {
        throw std::runtime_error("Invalid ELF section header string table size"); 
    }
    std::vector<char> shstrtab(shstrtab_size);
    file.read(shstrtab.data(), shstrtab_size);
    if (file.gcount() != static_cast<std::streamsize>(shstrtab_size))
    {
        throw std::runtime_error("Incomplete ELF section header string table read");
    }

    for (size_t i = 0; i < _elf_shdrs.size(); i++)
    {
        uint64_t name_offset = 0;

        switch (_elf_type)
        {
        case ElfType::ELF_32:
            name_offset = std::get<Elf32_Shdr>(_elf_shdrs[i]).sh_name;
            break;
        case ElfType::ELF_64:
            name_offset = std::get<Elf64_Shdr>(_elf_shdrs[i]).sh_name;
            break;
        default:
            throw std::runtime_error("Invalid ELF type");
        }

        uint16_t next_null = 0;
        while (name_offset + next_null < shstrtab_size && shstrtab[name_offset + next_null] != '\0')
        {
            next_null++;
        }

        if (name_offset >= shstrtab_size || name_offset + next_null >= shstrtab_size)
        {
            throw std::runtime_error("Invalid ELF section header name offset");
        }
        
        std::string section_name(shstrtab.data() + name_offset, next_null);
        _section_header_name_map[i] = section_name;
    }
}
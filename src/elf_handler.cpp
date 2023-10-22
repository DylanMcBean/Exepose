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
        _elfType = ElfType::ELF_32;
        ReadElfHeader<Elf32Ehdr>(file);
        break;

    case ELFCLASS64:
        _elfType = ElfType::ELF_64;
        ReadElfHeader<Elf64Ehdr>(file);
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
template <typename ElfEhdrType> void ElfHandler::ReadElfHeader(std::ifstream &file)
{
    ElfEhdrType ehdr{};
    file.seekg(0);
    file.read(reinterpret_cast<char *>(&ehdr), sizeof(ElfEhdrType));
    if (file.gcount() != sizeof(ElfEhdrType))
    {
        throw std::runtime_error("Incomplete ELF header read");
    }
    _elfEhdr = ehdr;
    _elfEvCurrent = ehdr.e_version;
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
        _elfDataEncoding = ElfDataEncoding::ELFDATA2LSB;
        break;

    case ELFDATA2MSB:
        _elfDataEncoding = ElfDataEncoding::ELFDATA2MSB;
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
    if (ident[ELFVERSION_OFFSET] != _elfEvCurrent)
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
    _elfOsabi = MapToElfOsABI(ident[ELFOSABI_OFFSET]);
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
    switch (_elfType)
    {
    case ElfType::ELF_32:
        ReadElfProgramHeaders<Elf32Phdr, Elf32Ehdr>(file);
        break;
    case ElfType::ELF_64:
        ReadElfProgramHeaders<Elf64Phdr, Elf64Ehdr>(file);
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
template <typename ElfPhdrType, typename ElfEhdr> void ElfHandler::ReadElfProgramHeaders(std::ifstream &file)
{
    uint64_t phoff = std::get<ElfEhdr>(_elfEhdr).e_phoff;
    uint64_t phnum = std::get<ElfEhdr>(_elfEhdr).e_phnum;

    file.seekg(phoff);
    for (size_t i = 0; i < phnum; ++i)
    {
        ElfPhdrType phdr{};
        file.read(reinterpret_cast<char *>(&phdr), sizeof(ElfPhdrType));
        if (file.gcount() != sizeof(ElfPhdrType))
        {
            throw std::runtime_error("Incomplete ELF program header read");
        }
        _elfPhdrs.push_back(phdr);
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
    switch (_elfType)
    {
    case ElfType::ELF_32:
        ReadElfSectionHeaders<Elf32Shdr, Elf32Ehdr>(file);
        break;
    case ElfType::ELF_64:
        ReadElfSectionHeaders<Elf64Shdr, Elf64Ehdr>(file);
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
template <typename ElfShdrType, typename ElfEhdr> void ElfHandler::ReadElfSectionHeaders(std::ifstream &file)
{
    uint64_t shoff = std::get<ElfEhdr>(_elfEhdr).e_shoff;
    uint64_t shnum = std::get<ElfEhdr>(_elfEhdr).e_shnum;

    file.seekg(shoff);
    for (size_t i = 0; i < shnum; ++i)
    {
        ElfShdrType shdr{};
        file.read(reinterpret_cast<char *>(&shdr), sizeof(ElfShdrType));
        if (file.gcount() != sizeof(ElfShdrType))
        {
            throw std::runtime_error("Incomplete ELF section header read");
        }
        _elfShdrs.push_back(shdr);
    }
}

/**
 * @brief Creates a map of section header names to their corresponding indices in the section header table.
 *
 * @param file An input file stream object representing the ELF file.
 * @return void
 * @throws std::runtime_error if the ELF type is invalid.
 */
void ElfHandler::CreateSectionHeaderNameMap(std::ifstream &file)
{

    switch (_elfType)
    {
    case ElfType::ELF_32:
        CreateSectionHeaderNameMap<Elf32Shdr, Elf32Ehdr, Elf32Shdr>(file);
        break;
    case ElfType::ELF_64:
        CreateSectionHeaderNameMap<Elf64Shdr, Elf64Ehdr, Elf64Shdr>(file);
        break;
    default:
        throw std::runtime_error("Invalid ELF type");
    }
}

/**
 * @brief Creates a map of section header names for the ELF file.
 *
 * @tparam ElfShdrType The type of the ELF section header.
 * @tparam ElfEhdr The type of the ELF header.
 * @tparam ElfShdr The type of the ELF section.
 * @param file The input file stream of the ELF file.
 * @throws std::runtime_error If the ELF section header string table index is invalid, the ELF section header string
 * table size is invalid, or the ELF section header name offset is invalid.
 */
template <typename ElfShdrType, typename ElfEhdr, typename ElfShdr>
void ElfHandler::CreateSectionHeaderNameMap(std::ifstream &file)
{
    uint64_t shstrndx = std::get<ElfEhdr>(_elfEhdr).e_shstrndx;

    if (shstrndx >= _elfShdrs.size())
    {
        throw std::runtime_error("Invalid ELF section header string table index");
    }

    ElfShdr shstrtab_hdr = std::get<ElfShdr>(_elfShdrs[shstrndx]);

    uint64_t shstrtabOffset = shstrtab_hdr.sh_offset;
    uint64_t shstrtabSize = shstrtab_hdr.sh_size;

    file.seekg(shstrtabOffset);

    if (shstrtabSize == 0 || shstrtabSize > (file.end - file.beg))
    {
        throw std::runtime_error("Invalid ELF section header string table size");
    }

    std::vector<char> shstrtab(shstrtabSize);
    file.read(shstrtab.data(), shstrtabSize);
    if (file.gcount() != static_cast<std::streamsize>(shstrtabSize))
    {
        throw std::runtime_error("Incomplete ELF section header string table read");
    }

    for (size_t i = 0; i < _elfShdrs.size(); i++)
    {
        uint64_t nameOffset = std::get<ElfShdr>(_elfShdrs[i]).sh_name;
        uint16_t nextNull = 0;
        while (nameOffset + nextNull < shstrtabSize && shstrtab[nameOffset + nextNull] != '\0')
        {
            nextNull++;
        }

        if (nameOffset >= shstrtabSize || nameOffset + nextNull >= shstrtabSize)
        {
            throw std::runtime_error("Invalid ELF section header name offset");
        }

        std::string sectionName(shstrtab.data() + nameOffset, nextNull);
        _sectionHeaderNameMap[i] = sectionName;
    }
}
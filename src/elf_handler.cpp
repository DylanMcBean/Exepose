#include "elf_handler.hpp"
#include "logger.hpp"
#include <algorithm>
#include <format>

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
    LOG(Logger::LogLevel::Debug, "Reading ELF file: %s", fileName.c_str());
    std::ifstream file(fileName, std::ios::binary);
    if (!file.is_open())
    {
        LOG_THROW(Logger::LogLevel::Error, "Failed to open file: %s", fileName.c_str());
    }

    file.seekg(0, std::ios::end);
    _fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::array<uint8_t, EI_NIDENT> ident{};
    file.read(reinterpret_cast<char *>(ident.data()), EI_NIDENT);
    if (file.gcount() != EI_NIDENT)
    {
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ident read from file: %s", fileName.c_str());
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
    ParseTables(file);
    PrintSectionHeaders();
}

/**
 * @brief Prints the section headers of an ELF file in a formatted table.
 * 
 * @details The function prints the section headers of an ELF file in a formatted table. The table consists of ten columns:
 * Name, Type, Flags, Address, Offset, Size, Link, Info, Alignment, and Entry Size. The function first creates a vector of
 * vectors to store the table data. Then, it initializes a vector of size 10 to store the maximum width of each column. The
 * function populates the table data vector with the header row and data rows. It then calculates the maximum width of each
 * column and prints the table in a formatted manner.
 * 
 * @return void
 */
void ElfHandler::PrintSectionHeaders()
{
    LOG(Logger::LogLevel::Debug, "Printing section headers");
    std::vector<std::vector<std::string>> tableData;
    std::vector<size_t> maxColumnWidths(10, 0); // Initialize with 10 columns

    // Header row
    tableData.push_back(
        {"Name", "Type", "Flags", "Address", "Offset", "Size", "Link", "Info", "Alignment", "Entry Size"});

    // Data rows
    for (size_t i = 0; i < _sectionHeaderNameMap.size(); i++)
    {
        std::vector<std::string> row;
        switch (_elfType)
        {
        case ElfType::ELF_32: {
            auto &shdr = std::get<Elf32Shdr>(_elfShdrs[i]);
            row = {_sectionHeaderNameMap[i],
                   std::format("0x{:x}h", shdr.sh_type),
                   std::format("0x{:x}h", shdr.sh_flags),
                   std::format("0x{:x}h", shdr.sh_addr),
                   std::format("0x{:x}h", shdr.sh_offset),
                   std::format("0x{:x}h", shdr.sh_size),
                   std::format("0x{:x}h", shdr.sh_link),
                   std::format("0x{:x}h", shdr.sh_info),
                   std::format("0x{:x}h", shdr.sh_addralign),
                   std::format("0x{:x}h", shdr.sh_entsize)};
        }
        break;
        case ElfType::ELF_64: {
            auto &shdr = std::get<Elf64Shdr>(_elfShdrs[i]);
            row = {_sectionHeaderNameMap[i],
                   std::format("0x{:x}h", shdr.sh_type),
                   std::format("0x{:x}h", shdr.sh_flags),
                   std::format("0x{:x}h", shdr.sh_addr),
                   std::format("0x{:x}h", shdr.sh_offset),
                   std::format("0x{:x}h", shdr.sh_size),
                   std::format("0x{:x}h", shdr.sh_link),
                   std::format("0x{:x}h", shdr.sh_info),
                   std::format("0x{:x}h", shdr.sh_addralign),
                   std::format("0x{:x}h", shdr.sh_entsize)};
        }
        break;
        default:
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF type");
        }
        tableData.push_back(row);
    }

    // Calculate max width for each column
    for (const auto &row : tableData)
    {
        for (size_t col = 0; col < row.size(); ++col)
        {
            maxColumnWidths[col] = std::max(maxColumnWidths[col], row[col].length());
        }
    }

    // Print header row
    for (size_t col = 0; col < tableData[0].size(); ++col)
    {
        printf("%-*s", static_cast<int>(maxColumnWidths[col] + 2), tableData[0][col].c_str());
    }
    printf("\n");

    // Print separator row
    for (const auto &width : maxColumnWidths)
    {
        printf("%-*s", static_cast<int>(width + 2), std::string(width + 2, '-').c_str());
    }
    printf("\n");

    // Print data rows
    for (size_t i = 1; i < tableData.size(); ++i)
    {
        for (size_t col = 0; col < tableData[i].size(); ++col)
        {
            printf("%-*s", static_cast<int>(maxColumnWidths[col] + 2), tableData[i][col].c_str());
        }
        printf("\n");
    }
}

/**
 * Validates the ELF magic number of the given ident array.
 * @param ident The array containing the ELF magic number.
 * @throws std::runtime_error if the magic number is invalid.
 */
void ElfHandler::ValidateElfMagic(const std::array<uint8_t, EI_NIDENT> &ident)
{
    LOG(Logger::LogLevel::Debug, "Validating ELF magic");
    if (memcmp(ident.data(), &ELFMAG, ELFMAG_SIZE) != 0)
    {
        std::string expectedMagic = Logger::toByteEncoded(reinterpret_cast<const uint8_t *>(&ELFMAG), ELFMAG_SIZE);
        std::string receivedMagic = Logger::toByteEncoded(ident.data(), ELFMAG_SIZE);

        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF magic, expected: '%s', got: '%s'",
                          expectedMagic.c_str(), receivedMagic.c_str());
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
    LOG(Logger::LogLevel::Debug, "Validating ELF class");
    switch (ident[ELFCLASS_OFFSET])
    {
    case ELFCLASS32:
        LOG(Logger::LogLevel::Debug, "ELF class: 32-bit");
        _elfType = ElfType::ELF_32;
        ReadElfHeader<Elf32Ehdr>(file);
        break;

    case ELFCLASS64:
        LOG(Logger::LogLevel::Debug, "ELF class: 64-bit");
        _elfType = ElfType::ELF_64;
        ReadElfHeader<Elf64Ehdr>(file);
        break;

    default:
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF class");
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
    LOG(Logger::LogLevel::Debug, "Reading ELF header");
    ElfEhdrType ehdr{};
    file.seekg(0);
    file.read(reinterpret_cast<char *>(&ehdr), sizeof(ElfEhdrType));
    if (file.gcount() != sizeof(ElfEhdrType))
    {
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF header read");
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
    LOG(Logger::LogLevel::Debug, "Validating ELF data encoding");
    switch (ident[ELFDATA_OFFSET])
    {
    case ELFDATA2LSB:
        _elfDataEncoding = ElfDataEncoding::ELFDATA2LSB;
        break;

    case ELFDATA2MSB:
        _elfDataEncoding = ElfDataEncoding::ELFDATA2MSB;
        break;

    default:
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF data encoding");
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
    LOG(Logger::LogLevel::Debug, "Validating ELF file version");
    if (ident[ELFVERSION_OFFSET] != _elfEvCurrent)
    {
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF file version");
    }
}

/**
 * @brief Validates the OS ABI of the ELF file.
 *
 * @param ident The array of bytes containing the ELF file identification information.
 */
void ElfHandler::ValidateOSABI(const std::array<uint8_t, EI_NIDENT> &ident)
{
    LOG( Logger::LogLevel::Debug, "Validating ELF OS ABI");
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
        LOG(Logger::LogLevel::Warning, "Unrecognized ELF OS ABI: %d", value);
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
    LOG(Logger::LogLevel::Debug, "Validating ELF PAD");
    if (memcmp(ident.data() + ELFABIVERSION_OFFSET, &ELFPAD, sizeof(ELFPAD)) != 0)
    {
        // shouldnt throw an error, but should log a warning that padding is not all zero
        LOG(Logger::LogLevel::Warning, "ELF PAD is not all zero");
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
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF type");
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
    LOG(Logger::LogLevel::Debug, "Reading ELF program headers");
    uint64_t phoff = std::get<ElfEhdr>(_elfEhdr).e_phoff;
    uint64_t phnum = std::get<ElfEhdr>(_elfEhdr).e_phnum;

    file.seekg(phoff);
    for (size_t i = 0; i < phnum; ++i)
    {
        ElfPhdrType phdr{};
        file.read(reinterpret_cast<char *>(&phdr), sizeof(ElfPhdrType));
        if (file.gcount() != sizeof(ElfPhdrType))
        {
            LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF program header read");
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
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF type");
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
    LOG(Logger::LogLevel::Debug, "Reading ELF section headers");
    uint64_t shoff = std::get<ElfEhdr>(_elfEhdr).e_shoff;
    uint64_t shnum = std::get<ElfEhdr>(_elfEhdr).e_shnum;

    file.seekg(shoff);
    for (size_t i = 0; i < shnum; ++i)
    {
        ElfShdrType shdr{};
        file.read(reinterpret_cast<char *>(&shdr), sizeof(ElfShdrType));
        if (file.gcount() != sizeof(ElfShdrType))
        {
            LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF section header read");
        }
        _elfShdrs.push_back(shdr);
    }

    // sort the section headers by offset in ascending order
    std::sort(_elfShdrs.begin(), _elfShdrs.end(), [](auto const &a, auto const &b) {
        return std::get<ElfShdrType>(a).sh_offset < std::get<ElfShdrType>(b).sh_offset;
    });
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
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF type");
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
    LOG(Logger::LogLevel::Debug, "Creating section header name map");
    uint64_t shstrndx = std::get<ElfEhdr>(_elfEhdr).e_shstrndx; // section header string table index

    if (shstrndx >= _elfShdrs.size())
    {
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF section header string table index");
    }

    ElfShdr shstrtab_hdr = std::get<ElfShdr>(_elfShdrs[shstrndx]); // section header string table header

    uint64_t shstrtabOffset = shstrtab_hdr.sh_offset; // section header string table offset
    uint64_t shstrtabSize = shstrtab_hdr.sh_size;    // section header string table size

    file.seekg(shstrtabOffset);

    if (shstrtabSize == 0 || shstrtabSize > _fileSize)
    {
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF section header string table size");
    }

    std::vector<char> shstrtab(shstrtabSize);
    file.read(shstrtab.data(), shstrtabSize);
    if (file.gcount() != static_cast<std::streamsize>(shstrtabSize))
    {
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF section header string table read");
    }

    uint64_t previousOffset = 0;
    uint64_t previousSize = 0;
    for (size_t i = 0; i < _elfShdrs.size(); i++)
    {
        ElfShdr shdr = std::get<ElfShdr>(_elfShdrs[i]);
        uint64_t nameOffset = shdr.sh_name;
        uint64_t shOffset = shdr.sh_offset;
        uint64_t shSize = shdr.sh_size;

        if (shOffset > _fileSize)
        {
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF section header offset, exceeds file size");
        }

        if (previousOffset + previousSize > shOffset && previousOffset != shOffset)
        {
            LOG_THROW(Logger::LogLevel::Error,
                              "Invalid ELF section header offset, overlaps with previous section");
        }

        if (previousOffset == shOffset)
        {
            LOG(Logger::LogLevel::Warning,
                "ELF section header offset is the same as previous section, will continue and hope for the best...");
        }

        uint16_t nextNull = 0;
        while (nameOffset + nextNull < shstrtabSize && shstrtab[nameOffset + nextNull] != '\0')
        {
            nextNull++;
        }

        if (nameOffset >= shstrtabSize || nameOffset + nextNull >= shstrtabSize)
        {
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF section header name offset");
        }

        std::string sectionName(shstrtab.data() + nameOffset, nextNull);
        _sectionHeaderNameMap[i] = sectionName;
        LOG(Logger::LogLevel::Debug, "Section[%d] Name: %s", i, sectionName.c_str());
        previousOffset = shOffset;
        previousSize = shSize;
    }
}

/**
 * @brief Parses the tables of the ELF file.
 * 
 * @param file The input file stream of the ELF file.
 * @tparam Elf32Shdr The ELF32 section header type.
 * @tparam Elf32Ehdr The ELF32 header type.
 * @tparam Elf64Shdr The ELF64 section header type.
 * @tparam Elf64Sym The ELF64 symbol type.
 * @throws Logger::Log with error if the ELF type is invalid.
 */
void ElfHandler::ParseTables(std::ifstream &file)
{
    switch (_elfType)
    {
    case ElfType::ELF_32:
        ParseTables<Elf32Shdr, Elf32Sym>(file);
        break;
    case ElfType::ELF_64:
        ParseTables<Elf64Shdr, Elf64Sym>(file);
        break;
    default:
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF type");
    }
}

/**
 * @brief Parses the symbol and string tables of an ELF file.
 * 
 * @tparam ElfShdr The type of the ELF section header.
 * @tparam ElfSym The type of the ELF symbol.
 * @param file The input file stream of the ELF file.
 * @throws Logger::Log if the dynamic symbol table or dynamic string table is not found.
 * @throws Logger::Log if the symbol table or string table sizes are invalid.
 * @throws Logger::Log if the read of the symbol table or string table is incomplete.
 * @throws Logger::Log if a symbol name offset is invalid.
 */

template <typename ElfShdr, typename ElfSym>
void ElfHandler::ParseTables(std::ifstream &file)
{
    LOG(Logger::LogLevel::Debug, "Parsing Tables");
    int64_t shsymtabndx = -1; // symbol table index
    int64_t shstrtabndx = -1; // string table index
    int64_t shdynsymndx = -1; // dynamic symbol table index
    int64_t shdynstrndx = -1; // dynamic string table index
    for (auto const &[key, val] : _sectionHeaderNameMap)
    {
        if      (val == ".symtab") { shsymtabndx = key; }
        else if (val == ".strtab") { shstrtabndx = key; }
        else if (val == ".dynsym") { shdynsymndx = key; }
        else if (val == ".dynstr") { shdynstrndx = key; }
    }

    // DYNAMIC TABLES FIRST
    LOG(Logger::LogLevel::Debug, "Parsing Dynamic Tables");
    // Handle Missing Dynamic Tables
    if (shdynsymndx == -1) { LOG_THROW(Logger::LogLevel::Error, "No dynamic symbol table found"); }
    if (shdynstrndx == -1) { LOG_THROW(Logger::LogLevel::Error, "No dynamic string table found"); }

    // Read Dynamic Symbol Table
    ElfShdr dynsymtab_hdr = std::get<ElfShdr>(_elfShdrs[shdynsymndx]);
    uint64_t dynsymtabSize = dynsymtab_hdr.sh_size;
    uint64_t dynsymtabOffset = dynsymtab_hdr.sh_offset;

    if (dynsymtabSize == 0 || dynsymtabSize > _fileSize)
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF dynamic symbol table size");

    if (dynsymtabSize % sizeof(ElfSym) != 0)
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF dynamic symbol table size");

    file.seekg(dynsymtabOffset);
    std::vector<ElfSym> dynsymtab(dynsymtabSize / sizeof(ElfSym));
    file.read(reinterpret_cast<char *>(dynsymtab.data()), dynsymtabSize);

    if (file.gcount() != static_cast<std::streamsize>(dynsymtabSize))
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF dynamic symbol table read");

    // Read Dynamic String Table
    ElfShdr dynstrtab_hdr = std::get<ElfShdr>(_elfShdrs[shdynstrndx]);
    uint64_t dynstrtabSize = dynstrtab_hdr.sh_size;
    uint64_t dynstrtabOffset = dynstrtab_hdr.sh_offset;

    if (dynstrtabSize == 0 || dynstrtabSize > _fileSize)
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF dynamic string table size");

    file.seekg(dynstrtabOffset);
    std::vector<char> dynstrtab(dynstrtabSize);
    file.read(dynstrtab.data(), dynstrtabSize);
    if (file.gcount() != static_cast<std::streamsize>(dynstrtabSize))
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF dynamic string table read");

    // Parse Dynamic Symbol Names
    for (size_t i = 0; i < dynsymtab.size(); i++)
    {
        uint64_t nameOffset = dynsymtab[i].st_name;
        
        if (nameOffset >= dynstrtabSize)
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF dynamic symbol name offset");
        
        size_t nextNull = strnlen(dynstrtab.data() + nameOffset, dynstrtabSize - nameOffset);

        if (nameOffset + nextNull >= dynstrtabSize)
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF dynamic symbol name offset");

        std::string dynsymbolName(dynstrtab.data() + nameOffset, nextNull);
        _dynamicSymbolTableMap[i] = dynsymbolName;
        _elfDynamicSymtab.push_back(dynsymtab[i]);
    }

    // OTHER TABLES
    LOG(Logger::LogLevel::Debug, "Parsing Regular Tables");
    // Handle Missing Tables
    if (shsymtabndx == -1 && shstrtabndx == -1)
    {
        LOG(Logger::LogLevel::Info, 
            "No symbol or string table found, possibly stripped. Skipping...");
        return;
    }
    else if (shsymtabndx == -1)
    {
        LOG(Logger::LogLevel::Warning, 
            "No symbol table found, but string table found. suggests corrupt. Skipping...");
        return;
    }
    else if (shstrtabndx == -1)
    {
        LOG(Logger::LogLevel::Warning, 
            "No string table found, but symbol table found. suggests corrupt. Skipping...");
        return;
    }

    // Read Symbol Table
    ElfShdr symtab_hdr = std::get<ElfShdr>(_elfShdrs[shsymtabndx]);
    uint64_t symtabSize = symtab_hdr.sh_size;
    uint64_t symtabOffset = symtab_hdr.sh_offset;
    
    if (symtabSize == 0 || symtabSize > _fileSize)
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF symbol table size");

    if (symtabSize % sizeof(ElfSym) != 0)
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF symbol table size");

    file.seekg(symtabOffset);
    std::vector<ElfSym> symtab(symtabSize / sizeof(ElfSym));
    file.read(reinterpret_cast<char *>(symtab.data()), symtabSize);

    if (file.gcount() != static_cast<std::streamsize>(symtabSize))
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF symbol table read");

    // Read String Table
    ElfShdr strtab_hdr = std::get<ElfShdr>(_elfShdrs[shstrtabndx]);
    uint64_t strtabSize = strtab_hdr.sh_size;
    uint64_t strtabOffset = strtab_hdr.sh_offset;

    if (strtabSize == 0 || strtabSize > _fileSize)
        LOG_THROW(Logger::LogLevel::Error, "Invalid ELF string table size");

    file.seekg(strtabOffset);
    std::vector<char> strtab(strtabSize);
    file.read(strtab.data(), strtabSize);

    if (file.gcount() != static_cast<std::streamsize>(strtabSize))
        LOG_THROW(Logger::LogLevel::Error, "Incomplete ELF string table read");

    // Parse Symbol Names
    for (size_t i = 0; i < symtab.size(); i++)
    {
        uint64_t nameOffset = symtab[i].st_name;
        
        if (nameOffset >= strtabSize)
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF symbol name offset");
        
        size_t nextNull = strnlen(strtab.data() + nameOffset, strtabSize - nameOffset);

        if (nameOffset + nextNull >= strtabSize)
            LOG_THROW(Logger::LogLevel::Error, "Invalid ELF symbol name offset");

        std::string symbolName(strtab.data() + nameOffset, nextNull);
        _symbolTableMap[i] = symbolName;
        _elfSymtab.push_back(symtab[i]);
    }
}
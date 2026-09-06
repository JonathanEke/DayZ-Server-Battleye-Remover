#include "utils.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace Utils
{
	namespace
	{
		struct ExecutableRange
		{
			BYTE* Data{};
			uint64_t Address{};
			size_t Size{};
		};

		struct SymbolTarget
		{
			uint64_t Direct{};
			uint64_t PLT{};
			uint64_t GOT{};
		};

		int Hex(char c)
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			return -1;
		}

		std::vector<size_t> FindOffsets(const BYTE* data, size_t size, std::string_view text)
		{
			std::vector<size_t> results;

			if (!data || text.empty() || text.size() > size)
				return results;

			const BYTE* needle = reinterpret_cast<const BYTE*>(text.data());

			for (size_t offset = 0; offset + text.size() <= size; ++offset)
				if (!memcmp(data + offset, needle, text.size()))
					results.push_back(offset);

			return results;
		}

		std::vector<uint64_t> FindRipReferences(const std::vector<ExecutableRange>& ranges, std::vector<uint64_t> targets)
		{
			std::vector<uint64_t> results;

			if (targets.empty())
				return results;

			std::sort(targets.begin(), targets.end());
			targets.erase(std::unique(targets.begin(), targets.end()), targets.end());

			for (const auto& range : ranges)
			{
				for (size_t i = 0; i + 7 <= range.Size; ++i)
				{
					BYTE* code = range.Data + i;

					if ((code[0] & 0xF0) != 0x40 || code[1] != 0x8D || (code[2] & 0xC7) != 0x05)
						continue;

					int32_t displacement;
					memcpy(&displacement, code + 3, sizeof(displacement));

					const uint64_t instruction = range.Address + i;
					const uint64_t target = instruction + 7 + displacement;

					if (std::binary_search(targets.begin(), targets.end(), target))
						results.push_back(instruction);
				}
			}

			return results;
		}

		bool CallsTarget(BYTE* code, uint64_t address, size_t size, const SymbolTarget& target)
		{
			if (!code)
				return false;

			for (size_t i = 0; i < size; ++i)
			{
				if (i + 5 <= size && code[i] == 0xE8)
				{
					int32_t displacement;
					memcpy(&displacement, code + i + 1, sizeof(displacement));

					const uint64_t destination = address + i + 5 + displacement;

					if ((target.Direct && destination == target.Direct) || (target.PLT && destination == target.PLT))
						return true;
				}

				if (i + 6 <= size && code[i] == 0xFF && code[i + 1] == 0x15)
				{
					int32_t displacement;
					memcpy(&displacement, code + i + 2, sizeof(displacement));

					const uint64_t slot = address + i + 6 + displacement;

					if (target.GOT && slot == target.GOT)
						return true;
				}
			}

			return false;
		}
	}

	bool ReadFileToVector(const std::string& path, std::vector<BYTE>& out)
	{
		std::ifstream file(path, std::ios::binary | std::ios::ate);

		if (!file)
			return false;

		const std::streamsize size = file.tellg();

		if (size < 0)
			return false;

		out.resize(static_cast<size_t>(size));
		file.seekg(0);

		return out.empty() || static_cast<bool>(file.read(reinterpret_cast<char*>(out.data()), size));
	}

	bool WriteVectorToFile(const std::string& path, const std::vector<BYTE>& in)
	{
		std::ofstream file(path, std::ios::binary | std::ios::trunc);

		if (!file)
			return false;

		return in.empty() || static_cast<bool>(file.write(reinterpret_cast<const char*>(in.data()), static_cast<std::streamsize>(in.size())));
	}

	uintptr_t Scan(BYTE* base, size_t size, const char* signature)
	{
		if (!base || !signature)
			return 0;

		std::vector<int> pattern;

		for (const char* p = signature; *p;)
		{
			while (*p == ' ')
				++p;

			if (!*p)
				break;

			if (*p == '?')
			{
				pattern.push_back(-1);

				while (*p == '?')
					++p;
			}
			else
			{
				const int high = Hex(p[0]);
				const int low = p[1] ? Hex(p[1]) : -1;

				if (high < 0 || low < 0)
					return 0;

				pattern.push_back((high << 4) | low);
				p += 2;
			}

			while (*p && *p != ' ')
				++p;
		}

		if (pattern.empty() || pattern.size() > size)
			return 0;

		for (size_t i = 0; i <= size - pattern.size(); ++i)
		{
			size_t j = 0;

			for (; j < pattern.size(); ++j)
				if (pattern[j] >= 0 && base[i + j] != pattern[j])
					break;

			if (j == pattern.size())
				return reinterpret_cast<uintptr_t>(base + i);
		}

		return 0;
	}

	PVOID ScanAny(std::vector<BYTE>& file, std::initializer_list<const char*> signatures)
	{
		for (const char* signature : signatures)
			if (uintptr_t address = Scan(file.data(), file.size(), signature))
				return reinterpret_cast<PVOID>(address);

		return nullptr;
	}

	PVOID Find(std::vector<BYTE>& file, std::string_view text)
	{
		if (file.empty() || text.empty() || text.size() > file.size())
			return nullptr;

		auto it = std::search(file.begin(), file.end(), reinterpret_cast<const BYTE*>(text.data()), reinterpret_cast<const BYTE*>(text.data()) + text.size());

		return it == file.end() ? nullptr : &*it;
	}

	bool Patch(std::vector<BYTE>& file, PVOID address, const void* data, size_t size)
	{
		if (!address || !data || !size || file.empty())
			return false;

		BYTE* destination = static_cast<BYTE*>(address);
		BYTE* begin = file.data();
		BYTE* end = begin + file.size();

		if (destination < begin || destination >= end || size > static_cast<size_t>(end - destination))
			return false;

		memcpy(destination, data, size);
		return true;
	}

	size_t Patch(std::vector<BYTE>& file, std::string_view find, std::string_view replace)
	{
		if (file.empty() || find.empty() || replace.size() > find.size())
			return 0;

		size_t count = 0;
		auto it = file.begin();

		while (it != file.end())
		{
			it = std::search(it, file.end(), reinterpret_cast<const BYTE*>(find.data()), reinterpret_cast<const BYTE*>(find.data()) + find.size());

			if (it == file.end())
				break;

			BYTE* destination = &*it;

			memset(destination, 0, find.size());
			memcpy(destination, replace.data(), replace.size());

			it += find.size();
			++count;
		}

		return count;
	}

	std::string FindServerExecutable(const char* fileName)
	{
		if (!fileName)
			return {};

		std::filesystem::path path;

#ifdef _WIN32
		path = std::filesystem::path(R"(C:\Program Files (x86)\Steam\steamapps\common\DayZServer)") / fileName;
#else
		path = std::filesystem::current_path() / fileName;
#endif

		if (std::filesystem::exists(path))
			return path.string();

		std::cout << "Enter path to " << fileName << ": ";

		std::string input;
		std::getline(std::cin >> std::ws, input);
		path = input;

		if (!std::filesystem::exists(path) || path.filename() != fileName)
		{
			std::cout << "Invalid " << fileName << " path.\n";
			return {};
		}

		return path.string();
	}

	bool CreateBackupFile(const std::string& path)
	{
		const std::filesystem::path source(path);

		if (!std::filesystem::exists(source))
			return false;

		auto backup = source;
		backup += ".bak";

		const bool exists = std::filesystem::exists(backup);

		std::cout << (exists ? "Backup exists. Overwrite? (y/n): " : "Create backup? (y/n): ");

		char choice{};
		std::cin >> choice;

		if (choice != 'y' && choice != 'Y')
		{
			std::cout << (exists ? "Using existing backup.\n" : "Skipping backup.\n");
			return true;
		}

		std::error_code error;
		std::filesystem::copy_file(source, backup, std::filesystem::copy_options::overwrite_existing, error);

		if (error)
		{
			std::cout << "Backup failed: " << error.message() << '\n';
			return false;
		}

		std::cout << "Created backup: " << backup << '\n';
		return true;
	}

#ifdef _WIN32

	namespace PE
	{
		Image::Image(BYTE* data, size_t size) : Data(data), Size(size)
		{
			if (!data || size < sizeof(IMAGE_DOS_HEADER))
				return;

			auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data);

			if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > size)
				return;

			NT = reinterpret_cast<IMAGE_NT_HEADERS64*>(data + dos->e_lfanew);

			if (NT->Signature != IMAGE_NT_SIGNATURE || NT->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				NT = nullptr;
				return;
			}

			Sections = IMAGE_FIRST_SECTION(NT);
			SectionCount = NT->FileHeader.NumberOfSections;

			if (reinterpret_cast<BYTE*>(Sections + SectionCount) > data + size)
			{
				NT = nullptr;
				Sections = nullptr;
				SectionCount = 0;
			}
		}

		Image::operator bool() const
		{
			return NT != nullptr;
		}

		BYTE* Image::Ptr(uint64_t rva) const
		{
			if (!NT || rva > UINT32_MAX)
				return nullptr;

			if (rva < NT->OptionalHeader.SizeOfHeaders)
				return rva < Size ? Data + rva : nullptr;

			for (WORD i = 0; i < SectionCount; ++i)
			{
				const auto& section = Sections[i];
				const uint64_t sectionSize = std::max<uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData);

				if (rva < section.VirtualAddress || rva >= section.VirtualAddress + sectionSize)
					continue;

				const uint64_t delta = rva - section.VirtualAddress;

				if (delta >= section.SizeOfRawData)
					return nullptr;

				const uint64_t offset = section.PointerToRawData + delta;

				return offset < Size ? Data + offset : nullptr;
			}

			return nullptr;
		}

		uint64_t Image::RVA(size_t offset) const
		{
			if (!NT || offset >= Size)
				return 0;

			if (offset < NT->OptionalHeader.SizeOfHeaders)
				return offset;

			for (WORD i = 0; i < SectionCount; ++i)
			{
				const auto& section = Sections[i];

				if (offset >= section.PointerToRawData && offset < static_cast<size_t>(section.PointerToRawData) + section.SizeOfRawData)
					return section.VirtualAddress + offset - section.PointerToRawData;
			}

			return 0;
		}

		namespace
		{
			std::vector<ExecutableRange> GetExecutableRanges(const Image& image)
			{
				std::vector<ExecutableRange> ranges;

				for (WORD i = 0; i < image.SectionCount; ++i)
				{
					const auto& section = image.Sections[i];

					if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE) || !section.SizeOfRawData)
						continue;

					BYTE* data = image.Ptr(section.VirtualAddress);

					if (!data)
						continue;

					size_t size = section.SizeOfRawData;

					if (section.Misc.VirtualSize && section.Misc.VirtualSize < size)
						size = section.Misc.VirtualSize;

					ranges.push_back({ data, section.VirtualAddress, size });
				}

				return ranges;
			}

			DWORD FindIAT(const Image& image, const char* name)
			{
				if (!image || !name)
					return 0;

				const auto& directory = image.NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

				if (!directory.VirtualAddress)
					return 0;

				auto descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.Ptr(directory.VirtualAddress));

				if (!descriptor)
					return 0;

				for (; descriptor->Name; ++descriptor)
				{
					const DWORD lookupRVA = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
					auto lookup = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.Ptr(lookupRVA));

					if (!lookup)
						continue;

					for (size_t i = 0; lookup[i].u1.AddressOfData; ++i)
					{
						if (IMAGE_SNAP_BY_ORDINAL64(lookup[i].u1.Ordinal))
							continue;

						auto import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image.Ptr(static_cast<DWORD>(lookup[i].u1.AddressOfData)));

						if (import && !_stricmp(reinterpret_cast<const char*>(import->Name), name))
							return descriptor->FirstThunk + static_cast<DWORD>(i * sizeof(IMAGE_THUNK_DATA64));
					}
				}

				return 0;
			}

			bool CallsIAT(const Image& image, const FunctionCandidate& function, DWORD iat)
			{
				BYTE* code = image.Ptr(function.Begin);

				if (!code || !iat || function.End <= function.Begin)
					return false;

				for (uint64_t i = 0; i + 6 <= function.End - function.Begin; ++i)
				{
					if (code[i] != 0xFF || code[i + 1] != 0x15)
						continue;

					int32_t displacement;
					memcpy(&displacement, code + i + 2, sizeof(displacement));

					if (function.Begin + i + 6 + displacement == iat)
						return true;
				}

				return false;
			}
		}

		std::vector<FunctionCandidate> FindFunctions(std::vector<BYTE>& file, std::string_view text, size_t minReferences, std::initializer_list<const char*> imports)
		{
			Image image(file.data(), file.size());

			if (!image)
				return {};

			std::vector<uint64_t> strings;

			for (size_t offset : FindOffsets(file.data(), file.size(), text))
				if (uint64_t rva = image.RVA(offset))
					strings.push_back(rva);

			auto references = FindRipReferences(GetExecutableRanges(image), strings);

			const auto& directory = image.NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

			if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
				return {};

			auto functions = reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(image.Ptr(directory.VirtualAddress));

			if (!functions)
				return {};

			const size_t functionCount = directory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
			std::vector<FunctionCandidate> candidates;

			for (uint64_t reference : references)
			{
				auto it = std::upper_bound(functions, functions + functionCount, static_cast<DWORD>(reference), [](DWORD address, const IMAGE_RUNTIME_FUNCTION_ENTRY& function)
					{
						return address < function.BeginAddress;
					});

				if (it == functions)
					continue;

				--it;

				if (reference < it->BeginAddress || reference >= it->EndAddress)
					continue;

				auto candidate = std::find_if(candidates.begin(), candidates.end(), [&](const FunctionCandidate& value)
					{
						return value.Begin == it->BeginAddress;
					});

				if (candidate != candidates.end())
					++candidate->References;
				else
					candidates.push_back({ it->BeginAddress, it->EndAddress, 1 });
			}

			std::vector<DWORD> iats;
			iats.reserve(imports.size());

			for (const char* import : imports)
			{
				DWORD iat = FindIAT(image, import);

				if (!iat)
					return {};

				iats.push_back(iat);
			}

			candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [&](const FunctionCandidate& candidate)
				{
					if (candidate.References < minReferences)
						return true;

					for (DWORD iat : iats)
						if (!CallsIAT(image, candidate, iat))
							return true;

					return false;
				}), candidates.end());

			std::sort(candidates.begin(), candidates.end(), [](const FunctionCandidate& a, const FunctionCandidate& b)
				{
					return a.References > b.References;
				});

			return candidates;
		}

		PVOID FindFunction(std::vector<BYTE>& file, std::string_view text, size_t minReferences, std::initializer_list<const char*> imports)
		{
			Image image(file.data(), file.size());

			if (!image)
				return nullptr;

			auto functions = FindFunctions(file, text, minReferences, imports);

			return functions.size() == 1 ? image.Ptr(functions[0].Begin) : nullptr;
		}
	}

#endif

	namespace ELF
	{
		constexpr BYTE ELFCLASS64 = 2;
		constexpr BYTE ELFDATA2LSB = 1;

		constexpr uint32_t PT_LOAD = 1;
		constexpr uint32_t PF_X = 1;

		constexpr uint32_t SHT_SYMTAB = 2;
		constexpr uint32_t SHT_RELA = 4;
		constexpr uint32_t SHT_DYNSYM = 11;

		constexpr BYTE STT_FUNC = 2;
		constexpr uint16_t SHN_UNDEF = 0;

		struct Ehdr
		{
			BYTE Ident[16];
			uint16_t Type;
			uint16_t Machine;
			uint32_t Version;
			uint64_t Entry;
			uint64_t ProgramOffset;
			uint64_t SectionOffset;
			uint32_t Flags;
			uint16_t HeaderSize;
			uint16_t ProgramEntrySize;
			uint16_t ProgramCount;
			uint16_t SectionEntrySize;
			uint16_t SectionCount;
			uint16_t SectionNameIndex;
		};

		struct Phdr
		{
			uint32_t Type;
			uint32_t Flags;
			uint64_t Offset;
			uint64_t VirtualAddress;
			uint64_t PhysicalAddress;
			uint64_t FileSize;
			uint64_t MemorySize;
			uint64_t Align;
		};

		struct Shdr
		{
			uint32_t Name;
			uint32_t Type;
			uint64_t Flags;
			uint64_t Address;
			uint64_t Offset;
			uint64_t Size;
			uint32_t Link;
			uint32_t Info;
			uint64_t Align;
			uint64_t EntrySize;
		};

		struct Sym
		{
			uint32_t Name;
			BYTE Info;
			BYTE Other;
			uint16_t SectionIndex;
			uint64_t Value;
			uint64_t Size;
		};

		struct Rela
		{
			uint64_t Offset;
			uint64_t Info;
			int64_t Addend;
		};

		static_assert(sizeof(Ehdr) == 64);
		static_assert(sizeof(Phdr) == 56);
		static_assert(sizeof(Shdr) == 64);
		static_assert(sizeof(Sym) == 24);
		static_assert(sizeof(Rela) == 24);

		Image::Image(BYTE* data, size_t size) : Data(data), Size(size)
		{
			if (!data || size < sizeof(Ehdr))
				return;

			Header = reinterpret_cast<Ehdr*>(data);

			if (Header->Ident[0] != 0x7F || Header->Ident[1] != 'E' || Header->Ident[2] != 'L' || Header->Ident[3] != 'F' ||
				Header->Ident[4] != ELFCLASS64 || Header->Ident[5] != ELFDATA2LSB)
			{
				Header = nullptr;
				return;
			}

			if (Header->ProgramOffset && Header->ProgramCount)
			{
				const uint64_t end = Header->ProgramOffset + static_cast<uint64_t>(Header->ProgramCount) * Header->ProgramEntrySize;

				if (Header->ProgramEntrySize != sizeof(Phdr) || end > size)
				{
					Header = nullptr;
					return;
				}

				Programs = reinterpret_cast<Phdr*>(data + Header->ProgramOffset);
				ProgramCount = Header->ProgramCount;
			}

			if (Header->SectionOffset && Header->SectionCount)
			{
				const uint64_t end = Header->SectionOffset + static_cast<uint64_t>(Header->SectionCount) * Header->SectionEntrySize;

				if (Header->SectionEntrySize != sizeof(Shdr) || end > size)
				{
					Header = nullptr;
					return;
				}

				Sections = reinterpret_cast<Shdr*>(data + Header->SectionOffset);
				SectionCount = Header->SectionCount;

				if (Header->SectionNameIndex < SectionCount)
				{
					const Shdr& names = Sections[Header->SectionNameIndex];

					if (names.Offset + names.Size <= size)
						SectionNames = reinterpret_cast<const char*>(data + names.Offset);
				}
			}
		}

		Image::operator bool() const
		{
			return Header != nullptr;
		}

		BYTE* Image::Ptr(uint64_t address) const
		{
			if (!Header)
				return nullptr;

			for (size_t i = 0; i < ProgramCount; ++i)
			{
				const Phdr& program = Programs[i];

				if (program.Type != PT_LOAD || address < program.VirtualAddress || address >= program.VirtualAddress + program.FileSize)
					continue;

				const uint64_t offset = program.Offset + address - program.VirtualAddress;

				return offset < Size ? Data + offset : nullptr;
			}

			return nullptr;
		}

		uint64_t Image::VA(size_t offset) const
		{
			if (!Header || offset >= Size)
				return 0;

			for (size_t i = 0; i < ProgramCount; ++i)
			{
				const Phdr& program = Programs[i];

				if (program.Type != PT_LOAD || offset < program.Offset || offset >= program.Offset + program.FileSize)
					continue;

				return program.VirtualAddress + offset - program.Offset;
			}

			return 0;
		}

		Shdr* Image::Section(const char* name) const
		{
			if (!Header || !Sections || !SectionNames || !name)
				return nullptr;

			for (size_t i = 0; i < SectionCount; ++i)
				if (!strcmp(SectionNames + Sections[i].Name, name))
					return &Sections[i];

			return nullptr;
		}

		namespace
		{
			const char* SectionName(const Image& image, const Shdr& section)
			{
				return image.SectionNames ? image.SectionNames + section.Name : "";
			}

			std::vector<ExecutableRange> GetExecutableRanges(const Image& image)
			{
				std::vector<ExecutableRange> ranges;

				for (size_t i = 0; i < image.ProgramCount; ++i)
				{
					const Phdr& program = image.Programs[i];

					if (program.Type != PT_LOAD || !(program.Flags & PF_X) || !program.FileSize || program.Offset + program.FileSize > image.Size)
						continue;

					ranges.push_back({ image.Data + program.Offset, program.VirtualAddress, static_cast<size_t>(program.FileSize) });
				}

				return ranges;
			}

			std::vector<FunctionCandidate> GetFunctions(const Image& image)
			{
				std::vector<FunctionCandidate> functions;

				if (!image.Sections)
					return functions;

				for (size_t sectionIndex = 0; sectionIndex < image.SectionCount; ++sectionIndex)
				{
					const Shdr& section = image.Sections[sectionIndex];

					if ((section.Type != SHT_SYMTAB && section.Type != SHT_DYNSYM) || !section.EntrySize || section.EntrySize != sizeof(Sym))
						continue;

					if (section.Offset + section.Size > image.Size || section.Link >= image.SectionCount)
						continue;

					const Shdr& strings = image.Sections[section.Link];

					if (strings.Offset + strings.Size > image.Size)
						continue;

					auto symbols = reinterpret_cast<const Sym*>(image.Data + section.Offset);
					const size_t count = section.Size / sizeof(Sym);

					for (size_t i = 0; i < count; ++i)
					{
						const Sym& symbol = symbols[i];

						if ((symbol.Info & 0x0F) != STT_FUNC || symbol.SectionIndex == SHN_UNDEF || !symbol.Value)
							continue;

						const uint64_t end = symbol.Size ? symbol.Value + symbol.Size : symbol.Value;

						auto existing = std::find_if(functions.begin(), functions.end(), [&](const FunctionCandidate& function)
							{
								return function.Begin == symbol.Value;
							});

						if (existing == functions.end())
							functions.push_back({ symbol.Value, end, 0 });
						else if (end > existing->End)
							existing->End = end;
					}
				}

				std::sort(functions.begin(), functions.end(), [](const FunctionCandidate& a, const FunctionCandidate& b)
					{
						return a.Begin < b.Begin;
					});

				for (size_t i = 0; i < functions.size(); ++i)
				{
					if (functions[i].End > functions[i].Begin)
						continue;

					if (i + 1 < functions.size() && functions[i + 1].Begin > functions[i].Begin)
						functions[i].End = functions[i + 1].Begin;
					else
						functions[i].End = functions[i].Begin + 1;
				}

				return functions;
			}

			SymbolTarget FindSymbol(const Image& image, const char* name)
			{
				SymbolTarget target{};

				if (!name || !image.Sections)
					return target;

				for (size_t sectionIndex = 0; sectionIndex < image.SectionCount; ++sectionIndex)
				{
					const Shdr& section = image.Sections[sectionIndex];

					if ((section.Type != SHT_SYMTAB && section.Type != SHT_DYNSYM) || section.EntrySize != sizeof(Sym) || section.Link >= image.SectionCount)
						continue;

					if (section.Offset + section.Size > image.Size)
						continue;

					const Shdr& strings = image.Sections[section.Link];

					if (strings.Offset + strings.Size > image.Size)
						continue;

					const char* names = reinterpret_cast<const char*>(image.Data + strings.Offset);
					auto symbols = reinterpret_cast<const Sym*>(image.Data + section.Offset);
					const size_t count = section.Size / sizeof(Sym);

					for (size_t i = 0; i < count; ++i)
					{
						if (symbols[i].Name >= strings.Size || strcmp(names + symbols[i].Name, name))
							continue;

						if (symbols[i].SectionIndex != SHN_UNDEF && symbols[i].Value)
							target.Direct = symbols[i].Value;

						for (size_t relocationIndex = 0; relocationIndex < image.SectionCount; ++relocationIndex)
						{
							const Shdr& relocationSection = image.Sections[relocationIndex];

							if (relocationSection.Type != SHT_RELA || relocationSection.Link != sectionIndex ||
								relocationSection.EntrySize != sizeof(Rela) || relocationSection.Offset + relocationSection.Size > image.Size)
								continue;

							auto relocations = reinterpret_cast<const Rela*>(image.Data + relocationSection.Offset);
							const size_t relocationCount = relocationSection.Size / sizeof(Rela);

							for (size_t r = 0; r < relocationCount; ++r)
							{
								const uint32_t symbolIndex = static_cast<uint32_t>(relocations[r].Info >> 32);

								if (symbolIndex != i)
									continue;

								target.GOT = relocations[r].Offset;

								const char* relocationName = SectionName(image, relocationSection);

								if (strstr(relocationName, ".rela.plt"))
								{
									Shdr* pltSec = image.Section(".plt.sec");
									Shdr* plt = pltSec ? pltSec : image.Section(".plt");

									if (plt)
									{
										const uint64_t entrySize = plt->EntrySize ? plt->EntrySize : 16;
										const uint64_t index = pltSec ? r : r + 1;

										target.PLT = plt->Address + index * entrySize;
									}
								}

								break;
							}
						}

						return target;
					}
				}

				return target;
			}
		}

		std::vector<FunctionCandidate> FindFunctions(std::vector<BYTE>& file, std::string_view text, size_t minReferences, std::initializer_list<const char*> symbols)
		{
			Image image(file.data(), file.size());

			if (!image)
				return {};

			std::vector<uint64_t> strings;

			for (size_t offset : FindOffsets(file.data(), file.size(), text))
				if (uint64_t address = image.VA(offset))
					strings.push_back(address);

			auto references = FindRipReferences(GetExecutableRanges(image), strings);
			auto functions = GetFunctions(image);

			if (functions.empty())
				return {};

			for (uint64_t reference : references)
			{
				auto it = std::upper_bound(functions.begin(), functions.end(), reference, [](uint64_t address, const FunctionCandidate& function)
					{
						return address < function.Begin;
					});

				if (it == functions.begin())
					continue;

				--it;

				if (reference >= it->Begin && reference < it->End)
					++it->References;
			}

			std::vector<SymbolTarget> targets;
			targets.reserve(symbols.size());

			for (const char* symbol : symbols)
			{
				SymbolTarget target = FindSymbol(image, symbol);

				if (!target.Direct && !target.PLT && !target.GOT)
					return {};

				targets.push_back(target);
			}

			functions.erase(std::remove_if(functions.begin(), functions.end(), [&](const FunctionCandidate& function)
				{
					if (function.References < minReferences || function.End <= function.Begin)
						return true;

					BYTE* code = image.Ptr(function.Begin);

					if (!code)
						return true;

					for (const SymbolTarget& target : targets)
						if (!CallsTarget(code, function.Begin, static_cast<size_t>(function.End - function.Begin), target))
							return true;

					return false;
				}), functions.end());

			std::sort(functions.begin(), functions.end(), [](const FunctionCandidate& a, const FunctionCandidate& b)
				{
					return a.References > b.References;
				});

			return functions;
		}

		PVOID FindFunction(std::vector<BYTE>& file, std::string_view text, size_t minReferences, std::initializer_list<const char*> symbols)
		{
			Image image(file.data(), file.size());

			if (!image)
				return nullptr;

			auto functions = FindFunctions(file, text, minReferences, symbols);

			return functions.size() == 1 ? image.Ptr(functions[0].Begin) : nullptr;
		}
	}
}
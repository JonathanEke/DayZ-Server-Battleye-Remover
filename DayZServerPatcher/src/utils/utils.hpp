#pragma once
#include "../pch.h"

namespace Utils
{
	struct FunctionCandidate
	{
		uint64_t Begin{}, End{};
		size_t References{};
	};

	bool ReadFileToVector(const std::string& path, std::vector<BYTE>& out);
	bool WriteVectorToFile(const std::string& path, const std::vector<BYTE>& in);

	uintptr_t Scan(BYTE* base, size_t size, const char* signature);
	PVOID ScanAny(std::vector<BYTE>& file, std::initializer_list<const char*> signatures);

	PVOID Find(std::vector<BYTE>& file, std::string_view text);

	bool Patch(std::vector<BYTE>& file, PVOID address, const void* data, size_t size);
	size_t Patch(std::vector<BYTE>& file, std::string_view find, std::string_view replace);

	std::string FindServerExecutable(const char* fileName);
	bool CreateBackupFile(const std::string& path);

#ifdef _WIN32
	namespace PE
	{
		struct Image
		{
			BYTE* Data{};
			size_t Size{};
			IMAGE_NT_HEADERS64* NT{};
			IMAGE_SECTION_HEADER* Sections{};
			WORD SectionCount{};

			Image(BYTE* data, size_t size);

			explicit operator bool() const;
			BYTE* Ptr(uint64_t rva) const;
			uint64_t RVA(size_t offset) const;
		};

		PVOID FindFunction(std::vector<BYTE>& file, std::string_view text, size_t minReferences = 1, std::initializer_list<const char*> imports = {});
		std::vector<FunctionCandidate> FindFunctions(std::vector<BYTE>& file, std::string_view text, size_t minReferences = 1, std::initializer_list<const char*> imports = {});
	}
#endif

	namespace ELF
	{
		struct Ehdr;
		struct Phdr;
		struct Shdr;

		struct Image
		{
			BYTE* Data{};
			size_t Size{};
			Ehdr* Header{};
			Phdr* Programs{};
			Shdr* Sections{};
			const char* SectionNames{};
			size_t ProgramCount{};
			size_t SectionCount{};

			Image(BYTE* data, size_t size);

			explicit operator bool() const;
			BYTE* Ptr(uint64_t address) const;
			uint64_t VA(size_t offset) const;
			Shdr* Section(const char* name) const;
		};

		PVOID FindFunction(std::vector<BYTE>& file, std::string_view text, size_t minReferences = 1, std::initializer_list<const char*> symbols = {});
		std::vector<FunctionCandidate> FindFunctions(std::vector<BYTE>& file, std::string_view text, size_t minReferences = 1, std::initializer_list<const char*> symbols = {});
	}
}
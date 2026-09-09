#ifdef _WIN32

#include "../pch.h"
#include "target.hpp"
#include "../utils/utils.hpp"

namespace
{
	PVOID FindBattleyeInit(std::vector<BYTE>& file)
	{
		if (PVOID function = Utils::PE::FindFunction(file, "BattlEye\\BEServer_x64.dll", 2, { "LoadLibraryExA", "FreeLibrary" }))
			return function;

		std::cout << "Initialize function analysis failed, using signature fallback.\n";

		return Utils::ScanAny(file, {
			"40 53 55 56 57 41 54 48 81 EC ? ? ? ? 45 33 E4 48 8B D9 44 89",
			"48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 45 33 F6 48 8B D9 44 89"
			});
	}

	PVOID FindVacCheck(std::vector<BYTE>& file)
	{
		Utils::PE::Image pe(file.data(), file.size());
		auto functions = Utils::PE::FindFunctions(file, "Cannot start authentication of player dpid %d, reason %s");

		if (functions.size() == 1)
		{
			const Utils::FunctionCandidate& fn = functions[0];
			BYTE* code = pe.Ptr(fn.Begin);

			if (code)
			{
				for (uint64_t i = 0; i + 2 <= fn.End - fn.Begin; ++i)
				{
					if (code[i] == 0x74 && code[i + 1] == 0x44)
						return code + i;
				}
			}
		}

		std::cout << "Status function analysis failed, using signature fallback.\n";

		return Utils::ScanAny(file, {
			"74 44 0F B7 C8 E8 ? ? ? ? 8B 13 44 0F B7 C0 44 89 4C 24 ? 48"
			});
	}

	bool PatchWindows(std::vector<BYTE>& file)
	{
		PVOID init = FindBattleyeInit(file);
		PVOID check = FindVacCheck(file);

		if (!init || !check)
			return false;

		const BYTE initPatch[]{ 0xB0, 0x01, 0xC3 };
		const BYTE checkPatch[]{ 0xEB };

		if (!Utils::Patch(file, "%s Console version (64bit) %s : port %d", "[BE Win] Server")) {
			std::cout << "Console title string not found.\n";
			return false;
		}

		return Utils::Patch(file, init, initPatch, sizeof(initPatch)) && Utils::Patch(file, check, checkPatch, sizeof(checkPatch));
	}
}

const char* Target::FileName()
{
	return "DayZServer_x64.exe";
}

bool Target::Patch(std::vector<BYTE>& file)
{
	return PatchWindows(file);
}

#endif
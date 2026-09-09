#ifndef _WIN32

#include "../pch.h"
#include "target.hpp"
#include "../utils/utils.hpp"

namespace
{
	PVOID FindBattleyeInit(std::vector<BYTE>& file)
	{
		//if (PVOID function = Utils::ELF::FindFunction(file, "battleye/beserver_x64.so", 2, { "LoadLibraryHelper", "GetBELaunchPath" }))
		//	return function;

	//	std::cout << "Initialize function analysis failed, using signature fallback.\n";

		return Utils::ScanAny(file, {
			"41 55 41 54 55 53 48 89 FB 48 81 EC ? ? ? ? C7 07"
			});
	}

	PVOID FindVacCheck(std::vector<BYTE>& file)
	{
		Utils::ELF::Image elf(file.data(), file.size());
		auto functions = Utils::ELF::FindFunctions(file, "Cannot start authentication of player dpid %d, reason %s");

		if (functions.size() == 1)
		{
			const auto& fn = functions[0];
			BYTE* code = elf.Ptr(fn.Begin);

			if (code)
			{
				const size_t size = static_cast<size_t>(fn.End - fn.Begin);

				if (uintptr_t address = Utils::Scan(code, size, "74 ? 89 C5 BA"))
					return reinterpret_cast<PVOID>(address);
			}
		}

		std::cout << "Check function analysis failed, using signature fallback.\n";

		return Utils::ScanAny(file, {
			"74 ? 89 C5 BA"
			});
	}

	bool PatchLinux(std::vector<BYTE>& file)
	{
		PVOID init = FindBattleyeInit(file);
		PVOID check = FindVacCheck(file);

		if (!init || !check)
			return false;

		if (!Utils::Patch(file, "%s Console version (64bit) %s : port %d", "[BE Linux] Server")) {
			std::cout << "Console title string not found.\n";
			return false;
		}

		const BYTE initPatch[]{ 0xB0, 0x01, 0xC3 };
		const BYTE checkPatch[]{ 0xEB };

		return Utils::Patch(file, init, initPatch, sizeof(initPatch)) && Utils::Patch(file, check, checkPatch, sizeof(checkPatch));
	}
}

const char* Target::FileName()
{
	return "DayZServer";
}

bool Target::Patch(std::vector<BYTE>& file)
{
	return PatchLinux(file);
}

#endif
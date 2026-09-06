#include "pch.h"
#include "utils/utils.hpp"
#include "targets/target.hpp"

int main()
{
	const std::string path = Utils::FindServerExecutable(Target::FileName());
	std::vector<BYTE> file;
	
	if (path.empty())
		return 1;

	std::cout << "Found DayZ server: " << path << '\n';

	if (!Utils::CreateBackupFile(path))
	{
		std::cout << "Backup failed.\n";
		return 1;
	}

	if (!Utils::ReadFileToVector(path, file))
	{
		std::cout << "Failed reading server binary.\n";
		return 1;
	}

	if (!Target::Patch(file))
	{
		std::cout << "Failed patching server.\n";
		return 1;
	}

	if (!Utils::WriteVectorToFile(path, file))
	{
		std::cout << "Failed writing patched server.\n";
		return 1;
	}

	std::cout << "Patch complete.\n";
	return 0;
}
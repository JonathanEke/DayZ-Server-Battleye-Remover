#pragma once
#include "../pch.h"

namespace Target
{
	const char* FileName();
	bool Patch(std::vector<BYTE>& file);
}
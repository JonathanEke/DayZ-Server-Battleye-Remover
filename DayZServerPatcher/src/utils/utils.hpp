#pragma once
#include "pch.h"

namespace Utils {
	struct PatternByte {
		PatternByte() : ignore(true), data(0) {}

		PatternByte(std::string byteString, bool ignoreThis = false) {
			data = ConvertToByte(byteString);
			ignore = ignoreThis;
		}

		bool ignore;
		BYTE data;

	private:
		BYTE ConvertToByte(std::string str) {
			std::istringstream iss(str);

			DWORD ret;
			if (iss >> std::hex >> ret) {
				return static_cast<BYTE>(ret);
			}

			return 0;
		}
	};

	bool ReadFileToVector(std::string path, std::vector<BYTE>* out);
	bool WriteVectorToFile(std::string path, std::vector<BYTE>* in);

	DWORD64 Scan(BYTE* base, DWORD size, const char* sig);
}
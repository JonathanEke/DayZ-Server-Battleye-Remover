#include "utils.hpp"

namespace Utils {
	bool ReadFileToVector(std::string path, std::vector<BYTE>* out) {
		std::ifstream infile(path, std::ios::binary);
		if (!infile)
			return false;

		out->assign((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
		infile.close();
		return true;
	}

	bool WriteVectorToFile(std::string path, std::vector<BYTE>* in) {
		std::ofstream outfile(path, std::ios::binary);
		if (!outfile)
			return false;

		outfile.write((const char*)in->data(), in->size());

		outfile.close();
		return true;
	}

	DWORD64 Scan(BYTE* base, DWORD size, const char* sig) {
		std::vector<PatternByte> p;
		std::istringstream iss(sig);
		std::string w;

		while (iss >> w) {
			if (w.data()[0] == '?') {
				p.emplace_back();
			} else if (w.length() == 2 && isxdigit(w[0]) && isxdigit(w[1])) { 
				p.emplace_back(w);
			} else {
				return NULL;
			}
		}

		for (DWORD i = 0; i < size; i++) {
			auto lpCurrentByte = (BYTE*)(base + i);

			bool found = true;

			for (size_t ps = 0; ps < p.size(); ps++) {
				if (p[ps].ignore == false && lpCurrentByte[ps] != p[ps].data) {
					found = false;
					break;
				}
			}

			if (found) {
				return (DWORD64)lpCurrentByte;
			}
		}

		return NULL;
	}
}
#include "pch.h"
#include "utils/utils.hpp"

std::string consoleTitle = "Patched version";
std::string filePath, fileBakPath;
std::vector<BYTE> fileBytes;

int main(int argc, char* argv[]) {
    if (argv[1] == nullptr || !std::filesystem::exists(argv[1])) {
        std::cout << "Start application with target file path." << std::endl;
        system("pause");
        return 0;
    }

    filePath = argv[1];
    fileBakPath = argv[1];
    fileBakPath.append(".bak");

    if (!Utils::ReadFileToVector(filePath, &fileBytes)) {
        std::cout << "Failed to copy file data." << std::endl;
        system("pause");
        return 0;
    }

    if (!Utils::WriteVectorToFile(fileBakPath, &fileBytes)) {
        std::cout << "Failed to create backup of original dayz server." << std::endl;
        system("pause");
        return 0;
    }

    std::cout << "Created backup." << std::endl;

    //40 53 55 56 57 41 54 48 81 EC ? ? ? ? 45 33 E4 48 8B D9 44 89 (old)
    //48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 45 33 F6 48 8B D9 44 89 (new)
    auto address = Utils::Scan(fileBytes.data(), fileBytes.size(), "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 45 33 F6 48 8B D9 44 89");
    if (!address) {
        std::cout << "Failed to find battleye init function." << std::endl;
        system("pause");
        return 0;
    }

    /*
       mov al, 1
       ret
    */

    BYTE retal1[] = { 0xB0, 0x01, 0xC3 }; 
    memcpy(reinterpret_cast<PVOID>(address), retal1, 3); //forcing init function to return true

    std::cout << "Patched battleye init function." << std::endl;

    //74 5C B8 ? ? ? ? 66 3B C3 75 09 E8 ? ? ? ? 84 C0 74 49 0F B7 (old)
    //74 44 0F B7 C8 E8 ? ? ? ? 8B 13 44 0F B7 C0 44 89 4C 24 ? 48 (new)
    address = Utils::Scan(fileBytes.data(), fileBytes.size(), "74 44 0F B7 C8 E8 ? ? ? ? 8B 13 44 0F B7 C0 44 89 4C 24 ? 48");
    if (!address) {
        std::cout << "Failed to find VAC check." << std::endl;
        system("pause");
        return 0;
    }

    *reinterpret_cast<BYTE*>(address) = 0xEB; //change jz to jmp

    std::cout << "Patched VAC check." << std::endl;

    address = Utils::Scan(fileBytes.data(), fileBytes.size(), "43 6F 6E 73 6F 6C 65 20 76");
    if (address) {
        memcpy(reinterpret_cast<PVOID>(address), consoleTitle.c_str(), consoleTitle.size());
        std::cout << "Patched console title." << std::endl;
    } else {
        std::cout << "Failed to find patch console title, skipping..." << std::endl;
    }

    if (!Utils::WriteVectorToFile(filePath, &fileBytes)) {
        std::cout << "Failed to write patched file." << std::endl;
        system("pause");
        return 0;
    }

    std::cout << "Wrote patched dayz server back to original file." << std::endl;

    system("pause");
}

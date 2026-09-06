# DayZ Server BattlEye Remover

C++ patcher for the DayZ dedicated server with Windows and Linux support.

This is a fork of JonathanEke's original project. I mainly updated it to work with the Linux server binary as well as Windows, and cleaned up a lot of the patch/searching code along the way.

## What changed

* Added Linux support
* Added ELF64 parsing for `DayZServer`
* Kept support for the Windows `DayZServer_x64.exe`
* Split Windows and Linux patching into separate implementations
* Improved function searching using strings, references and imports/symbols
* Added fallback signatures if the normal search fails
* Improved string searching/patching
* Added optional backups
* Added CMake support for Linux

The searching is a lot less dependent on one exact signature now, so it should hopefully survive smaller server updates without needing to be fixed every time.

## Windows

Build the project in Visual Studio as `Release x64`, then run the patcher and point it to:

```text
DayZServer_x64.exe
```

You can optionally create a backup before patching.

## Linux

Install the build tools:

```bash
sudo apt update
sudo apt install -y build-essential cmake
```

Clone and build:

```bash
git clone <repository-url>
cd DayZ-Server-Battleye-Remover

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Then run:

```bash
./build/DayZLinuxFix
```

If needed:

```bash
chmod +x build/DayZLinuxFix
```

The Linux version patches the native:

```text
DayZServer
```

binary.

## Searching

Instead of only using fixed byte signatures, the patcher now tries to locate functions using referenced strings and imports/symbols first, then falls back to signatures if needed.

This makes it a bit more reliable between DayZ updates.

## Credits

Original project by JonathanEke.

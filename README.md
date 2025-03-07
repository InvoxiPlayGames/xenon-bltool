# xenon-bltool

Work-in-progress utility for working with Xbox 360 bootloader stages, and soon more.

Licensed to you under the GNU General Public License version 2. See LICENSE for more information.

## Features so far

* Decompressing the CE/5BL base kernel.
* Extracting and updating the kernel stages. (CE/SE + CG/SE)
* (INCOMPLETE) Decrypting CB, CB_B and CD from a NAND image.

## Usage

```
xenon-bltool - https://github.com/InvoxiPlayGames/xenon-bltool

This program is free software licensed under version 2 of the GNU General
Public License. It comes with absolutely NO WARRANTY of any kind.

usage: xenon-bltool [verb] [arguments]

available verbs:
    decompress - Decompresses a CE/SE (5BL) bootloader.
      xenon-bltool decompress [path to CE] [output path]
    xboxupd - Applies an xboxupd.bin (CF+CG) patch to a base kernel or CE.
      xenon-bltool xboxupd [path to xboxupd.bin] [path to CE/base] [output_path]
    nand_extract - Extracts CB, CB_B and CD stages from a NAND image. (UNFINISHED!)
      ./xenon-bltool nand_extract [path to nand.bin] [cpu key]
```

## Compiling

**Linux, macOS, FreeBSD:** Install your distro's build tools.

**Windows:** Use MSYS2 with MINGW64.

From a terminal with GNU Make and appropriate toolchains installed, run `make`.

## Credits

Code has been used from the following libraries:

* [ExCrypt](https://github.com/emoose/ExCrypt)
    * Reimplementation of Xbox 360 cryptography functions.
    * Licensed under BSD-3-Clause license. (See 3rdparty/ExCrypt_LICENSE)
* [libmspack](https://github.com/kyz/libmspack)
    * Implementation of Microsoft's LZX compression scheme.
    * Licensed under GNU Lesser General Public License version 2.1. (see 3rdparty/libspack_LICENSE)
* [Xenia](https://github.com/xenia-project/xenia)
    * Implementation of LZX delta compression for Xbox 360 binaries.
    * Licensed under BSD license. (See 3rdparty/Xenia_LICENSE)

... and some obligatory shoutouts to some other open source Xbox 360 hacking projects:

* [libxenon](https://github.com/Free60Project/libxenon) and [xell-reloaded](https://github.com/Free60Project/xell-reloaded)
* [Xbox_360_Crypto](https://github.com/GoobyCorp/Xbox_360_Crypto)
* [J-Runner with Extras](https://github.com/Octal450/J-Runner-with-Extras)
* [Xbox-Reversing](https://github.com/TEIR1plus2/Xbox-Reversing)
* [RGLoader](https://github.com/RGLoader/RGLoader-Patches)

... and everyone involved in modding the 360. I can't name everyone here, but if you've worked on freeing this box, you've done a great job. <3

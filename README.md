# Frogminer title manager
This tool allows you to export, inject, import and boot a patched DS Download Play title with flipnote_v0 JPN.
It also copies the necessary files for the ugopwn exploit right to the SD card from RomFS.

## Instructions
https://jisagi.github.io/FrogminerGuide/ or https://3ds.hacks.guide/

## Thanks
 * [jason0597](https://github.com/jason0597) - for about 75% of the [TAD crypto code](https://github.com/jason0597/TADPole-3DS/)
 * Daniel (Nintendo Homebrew Discord #4420) - for the icon and bottom screen banner

## Libraries used
 * [Texas Instruments AES-128 CBC and AES CMAC functions](https://github.com/flexibity-team/AES-CMAC-RFC)
 * [ECDSA sect233r1 code (along with BigNum code)](http://git.infradead.org/?p=users/segher/wii.git)
 * [Nintendo 3DS key scrambler function](https://github.com/luigoalma/3ds_keyscrambler/blob/master/src/UnScrambler.c#L50)
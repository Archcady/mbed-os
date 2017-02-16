:: disable echo
@echo off

set source=%1%
set sink=%2%

for %%a in (%source%) do set BINROOT=%%~na
for %%a in (%source%) do set bindir=%%~dpa
set ABSPATH=%cd%

set tooldir=%ABSPATH%\mbed-os\targets\TARGET_Realtek\TARGET_AMEBA\sdk\soc\realtek\8195a\misc\tools
set libdir=%ABSPATH%\mbed-os\targets\TARGET_Realtek\TARGET_AMEBA\sdk\soc\realtek\8195a\misc\bsp

set SECTIONS_RAM=-j .image2.table.1 -j .image2.table.2 -j .text -j .data
set SECTIONS_DRAM=-j .sdr_text -j .sdr_rodata
set POSTFIX=stage-2
set IMAGE2=%BINROOT%-ram-%POSTFIX%
set IMAGE3=%BINROOT%-dram-%POSTFIX%
set IMAGE2_START_SYMBOL=__image2_start__
set IMAGE3_START_SYMBOL=__image3_start__

%tooldir%\objdump -d %source% > %bindir%%BINROOT%.asm
%tooldir%\nm %source% | %tooldir%\sort.exe > %bindir%%BINROOT%-%POSTFIX%.map
%tooldir%\strip -o %bindir%%BINROOT%-%POSTFIX%.elf %source%


:: generate ram.bin and dram.bin from elf file
%tooldir%\objcopy %SECTIONS_RAM% -Obinary %bindir%%BINROOT%-%POSTFIX%.elf %bindir%%IMAGE2%.bin
%tooldir%\objcopy %SECTIONS_DRAM% -Obinary %bindir%%BINROOT%-%POSTFIX%.elf %bindir%%IMAGE3%.bin

:: prepend ram2 bin and ram3 bin
::%tooldir%\sh -c "%tooldir%\..\..\prepend_header.sh %bindir%%IMAGE2%.bin %IMAGE2_START_SYMBOL% %bindir%%BINROOT%-%POSTFIX%.map"
::%tooldir%\sh %tooldir%\..\..\prepend_header.sh %bindir%%IMAGE2%.bin %IMAGE2_START_SYMBOL% %bindir%%BINROOT%-%POSTFIX%.map
::%tooldir%\sh %tooldir%\..\..\prepend_header.sh %bindir%%IMAGE3%.bin %IMAGE3_START_SYMBOL% %bindir%%BINROOT%-%POSTFIX%.map

%tooldir%\sh %tooldir%\prepend_header.sh %bindir%%IMAGE2%.bin %IMAGE2_START_SYMBOL% %bindir%%BINROOT%-%POSTFIX%.map %tooldir%
%tooldir%\sh %tooldir%\prepend_header.sh %bindir%%IMAGE3%.bin %IMAGE3_START_SYMBOL% %bindir%%BINROOT%-%POSTFIX%.map %tooldir%

:: prepare image 1
:: check ram_1.p.bin exist, copy default
if not exist %bindir%ram_1.p.bin (
	copy %libdir%\image\ram_1.p.bin %bindir%ram_1.p.bin
	::padding ram_1.p.bin to 32K+4K+4K+4K, LOADER/RSVD/SYSTEM/CALIBRATION
	%tooldir%\padding.exe 44k 0xFF %bindir%ram_1.p.bin
)

:: generate ram_all.bin
copy /b %bindir%ram_1.p.bin+%bindir%%IMAGE2%_prepend.bin+%bindir%%IMAGE3%_prepend.bin %bindir%%BINROOT%.bin

del %bindir%ram_1.p.bin

exit

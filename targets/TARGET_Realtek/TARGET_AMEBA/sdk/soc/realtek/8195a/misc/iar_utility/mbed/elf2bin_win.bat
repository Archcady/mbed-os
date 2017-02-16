echo off
::cd /D %2

set source=%1%
set sink=%2%

for %%a in (%source%) do set BINROOT=%%~na
for %%a in (%source%) do set bindir=%%~dpa
set ABSPATH=%cd%

set tooldir=%ABSPATH%\mbed-os\targets\TARGET_Realtek\TARGET_AMEBA\sdk\soc\realtek\8195a\misc\iar_utility\tools
set libdir=%ABSPATH%\mbed-os\targets\TARGET_Realtek\TARGET_AMEBA\sdk\soc\realtek\8195a\misc\bsp
set POSTFIX=stage-2
set IMAGE2=%BINROOT%-ram-%POSTFIX%
set IMAGE3=%BINROOT%-dram-%POSTFIX%
set IMAGE2_START_SYMBOL=__image2_start__
set IMAGE3_START_SYMBOL=__image3_start__

%tooldir%\objdump -d %source% > %bindir%%BINROOT%.asm
%tooldir%\nm %source% | %tooldir%\sort.exe > %bindir%%BINROOT%-%POSTFIX%.map
%tooldir%\strip -o %bindir%%BINROOT%-%POSTFIX%.elf %source%

::%toolchain%\arm-none-eabi-strip -o %builddir%\%filename%-%POSTFIX%.elf %source%

for /f "delims=" %%i in ('cmd /c "%tooldir%\grep IMAGE1 %bindir%%BINROOT%-%POSTFIX%.map | %tooldir%\grep Base | %tooldir%\gawk '{print $1}'"') do set ram1_start=0x%%i
for /f "delims=" %%i in ('cmd /c "%tooldir%\grep IMAGE2 %bindir%%BINROOT%-%POSTFIX%.map | %tooldir%\grep Base | %tooldir%\gawk '{print $1}'"') do set ram2_start=0x%%i
for /f "delims=" %%i in ('cmd /c "%tooldir%\grep SDRAM  %bindir%%BINROOT%-%POSTFIX%.map | %tooldir%\grep Base | %tooldir%\gawk '{print $1}'"') do set ram3_start=0x%%i

for /f "delims=" %%i in ('cmd /c "%tooldir%\grep IMAGE1 %bindir%%BINROOT%-%POSTFIX%.map | %tooldir%\grep Limit | %tooldir%\gawk '{print $1}'"') do set ram1_end=0x%%i
for /f "delims=" %%i in ('cmd /c "%tooldir%\grep IMAGE2 %bindir%%BINROOT%-%POSTFIX%.map | %tooldir%\grep Limit | %tooldir%\gawk '{print $1}'"') do set ram2_end=0x%%i
for /f "delims=" %%i in ('cmd /c "%tooldir%\grep SDRAM  %bindir%%BINROOT%-%POSTFIX%.map | %tooldir%\grep Limit | %tooldir%\gawk '{print $1}'"') do set ram3_end=0x%%i

::echo ram1_start=%ram1_start%
::echo ram1_end=%ram1_end%
::echo ram2_start=%ram2_start%
::echo ram2_end=%ram2_end%
::echo ram3_start=%ram3_start%
::echo ram3_end=%ram3_end%

%tooldir%\objcopy -j "A2 rw" -Obinary %bindir%%BINROOT%-%POSTFIX%.elf %bindir%ram_1.bin
%tooldir%\objcopy -j "A3 rw" -Obinary %bindir%%BINROOT%-%POSTFIX%.elf %bindir%sdram.bin

:: skip image1
:: prepend ram2 bin and ram3 bin
%tooldir%\pick %ram2_start% %ram2_end% %bindir%ram_1.bin %bindir%%IMAGE2%_prepend.bin body+reset_offset+sig
if defined %ram3_start (
%tooldir%\pick %ram3_start% %ram3_end% %bindir%sdram.bin %bindir%%IMAGE3%_prepend.bin body+reset_offset+sig
)

del %bindir%ram_1.bin
del %bindir%sdram.bin

:: prepare image 1
:: check ram_1.p.bin exist, copy default
if not exist %bindir%ram_1.p.bin (
	copy %libdir%\image\ram_1.p.bin %bindir%ram_1.p.bin
	::padding ram_1.p.bin to 32K+4K+4K+4K, LOADER/RSVD/SYSTEM/CALIBRATION
	%tooldir%\padding.exe 44k 0xFF %bindir%ram_1.p.bin
)

:: generate final bin

if defined %ram3_start (
copy /b %bindir%ram_1.p.bin+%bindir%%IMAGE2%_prepend.bin+%bindir%%IMAGE3%_prepend.bin %bindir%%BINROOT%.bin
)

if not defined %ram3_start (
copy /b %bindir%ram_1.p.bin+%bindir%%IMAGE2%_prepend.bin %bindir%%BINROOT%.bin
)
del %bindir%ram_1.p.bin

exit

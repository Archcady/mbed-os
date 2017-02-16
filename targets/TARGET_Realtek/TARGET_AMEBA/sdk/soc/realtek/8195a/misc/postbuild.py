"""
mbed SDK
Copyright (c) 2016 Realtek Semiconductor Corp.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys
import os
from sys import platform as _platform
from os.path import join, realpath
from tools.settings import GCC_ARM_PATH

def elf2bin(_elf, _binf, toolchain_name): 
    # Current work drirector
    workdir = os.getcwd()
    # Load elf2bin shell
    if _platform == "linux" or _platform == "linux2":
        tooldir = join(workdir,"mbed-os/targets/TARGET_Realtek/TARGET_AMEBA/sdk/soc/realtek/8195a/misc/gcc_utility/mbed/")
        cmd = realpath(join(tooldir,"elf2bin_linux %s %s" %(_elf, _binf)))
    elif _platform == "win32":
        elf_r = realpath(_elf)
        binf_r = realpath(_binf)
        # load  
        if toolchain_name == 'GCC_ARM':
            tooldir = join(workdir,"mbed-os\\targets\\TARGET_Realtek\\TARGET_AMEBA\\sdk\\soc\\realtek\\8195a\\misc\\gcc_utility\\mbed")
        elif toolchain_name == 'ARM_STD':
            tooldir = join(workdir,"mbed-os\\targets\\TARGET_Realtek\\TARGET_AMEBA\\sdk\\soc\\realtek\\8195a\\misc\\armcc_utility\\mbed")
        elif toolchain_name == 'IAR':
            tooldir = join(workdir,"mbed-os\\targets\\TARGET_Realtek\\TARGET_AMEBA\\sdk\\soc\\realtek\\8195a\\misc\\iar_utility\\mbed")
        # Generate command
        cmd = join(tooldir,"elf2bin_win.bat %s %s" %(elf_r, binf_r))
    elif _platform == "darwin":
        elf_r = realpath(_elf)
        binf_r = realpath(_binf)
        tooldir = join(workdir,"mbed-os/targets/TARGET_Realtek/TARGET_AMEBA/sdk/soc/realtek/8195a/misc/gcc_utility/mbed/")
        cmd = join(tooldir,"elf2bin_mac %s %s" %(elf_r, binf_r))
    
    # Execute postbuild tool
    os.system(cmd)

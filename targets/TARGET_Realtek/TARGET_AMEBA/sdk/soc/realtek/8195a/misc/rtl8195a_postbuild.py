"""
Realtek Semiconductor Corp.

RTL8195A elf2bin script
"""

import sys, array, struct, os, re, subprocess
import hashlib

#from tools.paths import TOOLS_BOOTLOADERS
#from datetime import datetime

# Constant Variables
RAM1_PATTERNS = [ 0x96969999, 0xFC66CC3F, 0x03CC33C0, 0x6231DCE5 ]
RAM1_RSVD = 0xFFFFFFFFFFFF
RAM2_RSVD = 0x3131373835393138
RAM2_VER = 0x8195FFFF00000000
RAM2_TAG = 0x81950001
RAM2_SHA = '0'

def write_fixed_width_string (value, width, output):
        # cut string to list & reverse
        line = [value[i:i+2] for i in range(0, len(value), 2)]
        output.write("".join([chr(long(b, 16)) for b in line]))

def write_fixed_width_value (value, width, output):
        # convert to string
        line = format(value, '0%dx' %(width))
        if len(line) > width:
            print "[ERROR] value 0x%s cannot fit width %d" %(line, width)
            sys.exit(-1)
        # cut string to list & reverse
        line = [line[i:i+2] for i in range(0, len(line), 2)]
        line.reverse()
        # convert to write buffer
        output.write("".join([chr(long(b, 16)) for b in line]))

def append_image_file (image, output):
    input = open (image, "rb")
    output.write(input.read())
    input.close()

def write_padding_bytes (output_name, size):
    current_size = os.stat(output_name).st_size
    padcount = size - current_size
    if padcount < 0:
        print "[ERROR] image is larger than expected size"
        sys.exit(-1)
    output = open (output_name, "ab")
    output.write('\377' * padcount)
    output.close()

# def sha256_checksum (filename, block_size=65536):
    # sha256 = hashlib.sha256()
    # with open(filename, 'rb') as f:
        # for block in iter(lambda: f.read(block_size), b''):
            # sha256.update(block)
    # return sha256.hexdigest()

# def get_version_by_time():
    # secs = int((datetime.now()-datetime(2016,11,1)).total_seconds())
    # return RAM2_VER + secs

# ----------------------------
#       main function
# ----------------------------
def prepend (image, sym_addr):

    # parse input arguments
    offset = 44
    # open output file
    output_name = image.rsplit('.', 1)
    if len (output_name) == 1:
        output_name.append('bin')

    # write output file
    output_name = output_name[0] + '_prepend.' + output_name[1]
    output = open (output_name, "wb")

    if image == "ram_1.bin":
	for pattern in RAM1_PATTERNS:
	    write_fixed_width_value (pattern, 8, output)
    write_fixed_width_value (os.stat(image).st_size, 8, output)
    write_fixed_width_value (int(sym_addr), 8, output)

    if image == "ram_1.bin":
        write_fixed_width_value (int(offset), 4, output)
        write_fixed_width_value (RAM1_RSVD, 12, output)
    else:
        #RAM2_SHA = sha256_checksum(image)
        #write_fixed_width_value (RAM2_TAG, 8, output)
        #write_fixed_width_value (get_version_by_time(), 16, output)
        #write_fixed_width_string (RAM2_SHA, 64, output)
        write_fixed_width_value (RAM2_RSVD, 16, output)

        # ota_name = os.path.join(os.path.dirname(output_name), 'ota.bin')
        # ota = open (ota_name, "wb")
        # write_fixed_width_value (os.stat(image).st_size, 8, ota)
        # write_fixed_width_value (int(sym_addr), 8, ota)
        # write_fixed_width_value (0xFFFFFFFF, 8, ota)
        ##write_fixed_width_value (get_version_by_time(), 16, ota)
        ##write_fixed_width_string (RAM2_SHA, 64, ota)
        # write_fixed_width_value (RAM2_RSVD, 16, ota)

    append_image_file (image, output)
    output.close()

    if image == "ram_1.bin":
        # write padding bytes to output file
        write_padding_bytes (output_name, 45056)
    # else:
        # append_image_file (image, ota)
        # ota.close()

# ----------------------------
#       main function
# ----------------------------
def find_symbol(image, symbol):
    ret = None
    devnull = open(os.devnull, 'w')
    if subprocess.call ("arm-none-eabi-nm --version", stdout=devnull, stderr=devnull, shell=True) == 0:
        cmd = "arm-none-eabi-nm " + image
        for line in subprocess.check_output(cmd, shell=True, universal_newlines=True).split("\n"):
            match = re.match (r'^(?P<addr>[0-9A-Fa-f]{8})\s+\w\s+' + symbol + r'$', line)
            if match:
                ret = match.group("addr")
                break
    elif subprocess.call ("fromelf.exe --vsn", stdout=devnull, stderr=devnull, shell=True) == 0:
        cmd = "fromelf.exe -s " + image
        for line in subprocess.check_output(cmd, shell=True, universal_newlines=True).split("\n"):
            match = re.match (r'^\s*\d+\s*' + symbol + r'\s+0x(?P<addr>[0-9A-Fa-f]{8})\s+.*$', line)
            if match:
                ret = match.group("addr")
                break
    else:
        print "[ERROR] arm-none-eabi-nm or fromelf is needed"
        sys.exit(-1)
    devnull.close()

    if not ret:
        return 0

    return int(ret,16)

def rtl8195a_elf2bin(image_elf, image_bin):

    image_name = os.path.splitext(image_elf)[0]

    #ram1_prepend_bin = os.path.join(TOOLS_BOOTLOADERS, "RTL8195A", "ram_1_prepend.bin")
    ram1_prepend_bin = os.path.join(os.getcwd(),"mbed-os","targets","TARGET_Realtek","TARGET_AMEBA","sdk","soc","realtek","8195a","misc","bootloaders", "ram_1_prepend.bin")
    ram2_prepend_bin = image_name + '-ram_2_prepend.bin'
    ram2_bin = image_name + '-ram_2.bin'
    ram2_addr = find_symbol(image_elf, '__image2_start__')

    devnull = open(os.devnull, 'w')
    if subprocess.call ("arm-none-eabi-objcopy --version", stdout=devnull, stderr=devnull, shell=True) == 0:
        sections = '-j .image2.table -j .text -j .data'
        cmd='arm-none-eabi-objcopy ' + sections + ' -S -Obinary ' + image_elf + ' ' + ram2_bin
    elif subprocess.call ("fromelf.exe --vsn", stdout=devnull, stderr=devnull, shell=True) == 0:
        sections = '--only=.image2.table --only=.text --only=.data'
        cmd='fromelf.exe ' + sections + ' --bin --output=' + ram2_bin + ' ' + image_elf
    else:
        print "[ERROR] arm-none-eabi-objcopy or fromelf is needed"
        sys.exit(-1)
    devnull.close()

    os.system(cmd)

    prepend(ram2_bin, ram2_addr)

    # write output file
    output = open (image_bin, "wb")
    input = open (ram1_prepend_bin, "rb")
    output.write(input.read())
    input.close()
    input = open (ram2_prepend_bin, "rb")
    output.write(input.read())
    input.close()
    output.close()



ENTRY(Reset_Handler)

INCLUDE "mbed-os/targets/TARGET_Realtek/TARGET_AMEBA/TARGET_RTL8195A/device/TOOLCHAIN_GCC_ARM/export-rom_v02.txt"
/* DATA_RAM: We cannot put Code(.text) in DATA_RAM, this region is reserved for Image1(boot loader).
   But we can put .data/.bss of Image2 in this region */
MEMORY
{
  TCM (rwx)        : ORIGIN = 0x1FFF0000, LENGTH = 0x00010000
  DATA_RAM (rwx)   : ORIGIN = 0x10002100, LENGTH = 0x10006000 - 0x10002100
  BD_RAM (rwx)     : ORIGIN = 0x10006000, LENGTH = 0x10070000 - 0x10006000
  SD_RAM (rwx)     : ORIGIN = 0x30000000, LENGTH = 2M
}

/* Linker script to place sections and symbol values. Should be used together
 * with other linker script that defines memory regions FLASH and RAM.
 * It references following symbols, which must be defined in code:
 * _reset_init : Entry of reset handler
 *
 * It defines following symbols, which code can use without definition:
 * __exidx_start
 * __exidx_end
 * __etext
 * __data_start__
 * __preinit_array_start
 * __preinit_array_end
 * __init_array_start
 * __init_array_end
 * __fini_array_start
 * __fini_array_end
 * __data_end__
 * __bss_start__
 * __bss_end__
 * __end__
 * end
 * __HeapLimit
 * __StackLimit
 * __StackTop
 * __stack
 */
ENTRY(Reset_Handler)

SECTIONS
{
    __rom_bss_start__ = 0x10000300;
    __rom_bss_end__ = 0x10000bc8;
    __ram_table_start__ = 0x10000bc8;

    .image2.table :
    {
        __image2_start__ = .;
        __image2_entry_func__ = .;
        KEEP(*(SORT(.image2.ram.data*)))
        __image2_validate_code__ = .;
        KEEP(*(.image2.validate.rodata*))
    } > BD_RAM

    .text :
    {
        . = ALIGN(4);
        *(.infra.ram.start*)
        *(.mon.ram.text*)
        *(.hal.flash.text*)
        *(.hal.sdrc.text*)
        *(.hal.gpio.text*)
        *(.text*)

        KEEP(*(.init))
        KEEP(*(.fini))

        /* .ctors */
        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)

        /* .dtors */
        *crtbegin.o(.dtors)
        *crtbegin?.o(.dtors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
        *(SORT(.dtors.*))
        *(.dtors)
	    *(.rodata*)
        KEEP(*(.eh_frame*))
    } > BD_RAM
    __etext = .;


    __data_start__ = .;
    .data :
    {
        *(vtable)
        *(.data*)

        . = ALIGN(4);
        /* preinit data */
        PROVIDE (__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE (__preinit_array_end = .);

        . = ALIGN(4);
        /* init data */
        PROVIDE (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE (__init_array_end = .);

        . = ALIGN(4);
        /* finit data */
        PROVIDE (__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE (__fini_array_end = .);

        . = ALIGN(4);

        /* All data end */
    } > BD_RAM
    __data_end__ = .;
    __image2_end__ = .;

    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > BD_RAM

    __exidx_start = .;
    .ARM.exidx :
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > BD_RAM
    __exidx_end = .;

    .bss :
    {
        __bss_start__ = .;
        *(.bss*)
        *(.bdsram.data*)
        *(COMMON)
        __bss_end__ = .;
    } > BD_RAM


    .bf_data :
    {
        __buffer_data_start__ = .;
        *(.bfsram.data*)
        __buffer_data_end__ = .;
    } > BD_RAM

    .heap :
    {
        __end__ = .;
        end = __end__;
        *(.heap*)
        __HeapLimit = .;
    } > BD_RAM

    .TCM_overlay :
    {
        *(.tcm.heap*)
    } > TCM


	.sdr_text :
	  {
	    __image3_start__ = .;
	    *(.sdram.text*)
	    *(.p2p.text*)
	    *(.wps.text*)
	    *(.websocket.text*)
	  } > SD_RAM

	.sdr_rodata :
	  {
	    *(.sdram.rodata*)
	    *(.p2p.rodata*)
	    *(.wps.rodata*)
	    *(.websocket.rodata*)
	  } > SD_RAM

	.sdr_bss :
	  {
	    __sdram_bss_start__ = .;
	    *(.sdram.bss*)
	    *(.p2p.bss*)
	    *(.wps.bss*)
	    *(.websocket.bss*)
	    __sdram_bss_end__ = .;
	  } > SD_RAM
	  
    /* .stack_dummy section doesn't contains any symbols. It is only
     * used for linker to calculate size of stack sections, and assign
     * values to stack symbols later */
    .stack_dummy :
    {
        *(.stack)
    } > BD_RAM

    /* Set stack top to end of RAM, and stack limit move down by
     * size of stack_dummy section */
    __StackTop = ORIGIN(BD_RAM) + LENGTH(BD_RAM);
    __StackLimit = __StackTop - SIZEOF(.stack_dummy);
    PROVIDE(__stack = __StackTop);

    /* Check if data + heap + stack exceeds RAM limit */
    ASSERT(__StackLimit >= __HeapLimit, "region RAM exceeds ram limit")

    .sdr_data :
    {
        __sdram_data_start__ = .;
        *(.sdram.data*)
        __sdram_data_end__ = .;
    } > SD_RAM
}


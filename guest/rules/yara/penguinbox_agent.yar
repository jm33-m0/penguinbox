/*
 * Static signatures for Linux C agent and stager artifacts.
 *
 * The rules match compiled code and ELF metadata, not banner strings. Each
 * pattern tolerates register and branch-displacement changes so a rebuild with
 * a different allocator or a small source edit still matches until the
 * underlying behavior changes.
 */

import "elf"

rule PenguinBox_LinuxAgent_LoaderCode
{
    meta:
        description = "Linux C agent ABI check and encoded maps-path decoder"
        severity = "high"
        source = "penguinbox"
    strings:
        // xor r64, C2_STAGER_ABI_MAGIC (0x53475031), with 32-bit and REX.WB forms
        $abi_xor = { 48 81 F? 31 50 47 53 }
        $abi_xor32 = { 81 F? 31 50 47 53 }
        $abi_xor_alt = { 49 81 F? 31 50 47 53 }
        // ABI check followed by the self/version predicates
        $abi_check = { 48 81 F? 31 50 47 53 4C 09 C? 49 83 F0 02 49 09 F8 40 0F 95 C7 }
        // Byte-wise XOR decoder for the runtime maps path
        $xor8 = { 80 F? 5A }
        $xor32 = { 83 F? 5A }
        $xor_al = { 34 5A }
    condition:
        elf.type == elf.ET_DYN and
        elf.machine == elf.EM_X86_64 and
        any of ($abi_xor*) and
        (#xor8 + #xor32 + #xor_al >= 3 or $abi_check)
}

rule PenguinBox_LinuxStager_LoaderCode
{
    meta:
        description = "Linux stager ABI store, vDSO syscall scanner, and maps-path decoder"
        severity = "high"
        source = "penguinbox"
    strings:
        // mov qword [reg+8], C2_STAGER_ABI_MAGIC
        $abi_store = { 48 C7 4? 08 31 50 47 53 }
        // cmp byte [reg],0x0f; cmp byte [reg+1],0x05; cmp byte [reg+2],0xc3
        $gadget_scan = { 80 3? 0F 75 ?? 80 7? 01 05 75 ?? 80 7? 02 C3 74 ?? }
        // jmp +3; syscall; ret thunk
        $gadget = { EB 03 0F 05 C3 }
        $xor8 = { 80 F? 5A }
        $xor32 = { 83 F? 5A }
        $xor_al = { 34 5A }
    condition:
        elf.type == elf.ET_DYN and
        elf.machine == elf.EM_X86_64 and
        $abi_store and
        ($gadget_scan or #gadget >= 1 or #xor8 + #xor32 + #xor_al >= 3)
}

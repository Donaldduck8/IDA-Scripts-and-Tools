from __future__ import print_function
import flare_emu
import idc
import donald_ida_utils
import ida_name

STRING_ADDRESSES = []

def instructionHook(unicornObject, address, instructionSize, userData):
    disasm_line = idc.GetDisasm(address)

    if "addresses" not in userData:
        userData["addresses"] = []

    if "offset" in disasm_line or ("mov" in disasm_line and "edx" in disasm_line and disasm_line.endswith("h")):
        # Get the encrypted string address
        if "offset" in disasm_line:
            str_name = disasm_line.split()[3]
            str_name = str_name.strip(";")
            str_addr = idc.get_name_ea_simple(str_name)
            STRING_ADDRESSES.append(str_addr)
        else:
            str_addr = int(disasm_line.split()[-1][:-1], base=16)
            STRING_ADDRESSES.append(str_addr)
    
    
if __name__ == '__main__':
    eh = flare_emu.EmuHelper()
    #uc = eh.emulateRange(0x404200, instructionHook=instructionHook)
    #uc = eh.emulateRange(startAddr=0x408D31, endAddr=0x408D6E, instructionHook=instructionHook, skipCalls=True)

    uc = eh.emulateRange(0x404240, instructionHook=instructionHook)
    uc = eh.emulateRange(startAddr=0x4087CD, endAddr=0x4088B8, instructionHook=instructionHook, skipCalls=True)

    for string_addr in STRING_ADDRESSES:
        string_addr_ptr = string_addr
        buffer = bytearray()
        decrypted_char = eh.getEmuBytes(string_addr_ptr, size=1)
        while decrypted_char != b'\x00':
            buffer += decrypted_char
            string_addr_ptr += 1
            decrypted_char = eh.getEmuBytes(string_addr_ptr, size=1)

        buffer = bytearray(buffer)
        buffer = buffer.decode(encoding="ansi")

        decrypted_string = buffer

        for ref_addr in donald_ida_utils.find_references_to(string_addr):
            # Try to tie this comment to a variable name
            orig_name = ida_name.get_ea_name(string_addr, ida_name.calc_gtn_flags(ref_addr, string_addr))
            if not orig_name:
                orig_name = hex(string_addr)
            donald_ida_utils.add_pseudocode_comment(ea=ref_addr, comment=decrypted_string, sanitize=True, prefix=f"{orig_name}: ")

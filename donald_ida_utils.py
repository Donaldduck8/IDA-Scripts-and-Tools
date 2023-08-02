from __future__ import print_function
import re
from typing import List
import flare_emu
import idc
import idautils
import idaapi
import ida_xref
import ida_search
import ida_hexrays


DEFAULT_PREFIX = "Decrypted: "


def get_all_instructions_in_line(ida_cfunc, ea) -> List[int]:
    """Return the address of every instruction that corresponds to a desired line of pseudocode."""
    insn_eas = []
    for ida_item in ida_cfunc.get_boundaries().items():
        range_set = ida_item[1]
        num_ranges = range_set.nranges()

        for i in range(num_ranges):
            boundary_start = range_set.getrange(i).start_ea
            boundary_end = range_set.getrange(i).end_ea
            range_size = boundary_end - boundary_start

            # If the boundary is hilariously large, ignore it
            if range_size > 0x100:
                continue

            if boundary_start <= ea < boundary_end:
                while boundary_end > boundary_start:
                    boundary_end = idaapi.prev_head(boundary_end, boundary_start)
                    insn_eas.append(boundary_end)

    return insn_eas


def add_pseudocode_comment(ea, comment, prefix=DEFAULT_PREFIX, quoted=True, sanitize=False, add_to_existing=True) -> None:
    """Add comment to the line of pseudocode that corresponds to the provided address."""
    ida_func = idaapi.get_func(ea)

    # Check if the function exists and has a decompiled representation
    if ida_func is None or not idaapi.init_hexrays_plugin():
        print("Error: Unable to find the function or decompiled view for address:", hex(ea))
        return

    ida_cfunc = idaapi.decompile(ida_func)

    if sanitize:
        # Carriage Return and Line Feed
        def newlines_escape(match):
            return match.group().replace("\r", "\\r").replace("\n", "\\n")

        trailing_newlines = re.compile(r"[\r\n]+?$")
        comment = trailing_newlines.sub(newlines_escape, comment)

        starting_newlines = re.compile(r"^[\r\n]+?")
        comment = starting_newlines.sub(newlines_escape, comment)

        # Control Characters
        def control_chars_to_hex(match):
            return r"\x{0:02x}".format(ord(match.group()))

        control_chars_class = re.compile(r"[\x00-\x09\x0B\x0C\x0E-\x1F]")
        comment = control_chars_class.sub(control_chars_to_hex, comment)

    if quoted:
        comment = '"' + comment + '"'

    if prefix:
        comment = prefix + comment

    insn_ea = ida_cfunc.eamap[ea][0].ea
    treeloc = idaapi.treeloc_t()
    treeloc.ea = insn_ea
    treeloc.itp = idaapi.ITP_BLOCK1 # BLOCK1 is the only reliable ITP

    if add_to_existing:
        existing_cmt = ida_cfunc.get_user_cmt(treeloc, ida_hexrays.RETRIEVE_ALWAYS)

        if existing_cmt:
            comment = existing_cmt + "\n" + comment

    print("Adding comment to", hex(insn_ea), comment)
    ida_cfunc.set_user_cmt(treeloc, comment)
    ida_cfunc.save_user_cmts()


def find_references_to(ea) -> List[int]:
    """Find Xrefs and immediate references to an address."""
    refs = []

    # Xrefs
    refs += [x.frm for x in list(idautils.XrefsTo(ea, ida_xref.XREF_ALL))]

    # References to immediate value
    found_eas = [0]
    while True:
        result_ea, result_code = ida_search.find_imm(found_eas[-1], ida_search.SEARCH_DOWN, ea)

        if (result_code == -1 or
                result_ea in found_eas or
                result_ea == 0xffffffffffffffff or
                result_ea in refs):
            break

        found_eas.append(result_ea)
        refs.append(result_ea)

    return refs


# Main function to iterate over the lines of the function and decrypt strings
def decrypt_strings_in_function(func_start):
    # Get the function end address
    func_end = idc.get_func_attr(func_start, idc.FUNCATTR_END)

    addresses = []

    # Iterate over the function instructions
    current_addr = func_start
    while current_addr < func_end:
        disasm_line = idc.GetDisasm(current_addr)

        # Check if the instruction references an offset
        if "offset" in disasm_line or ("mov" in disasm_line and "edx" in disasm_line and disasm_line.endswith("h")):
            # Get the encrypted string address
            if "offset" in disasm_line:
                str_name = disasm_line.split()[3]
                str_name = str_name.strip(";")
                str_addr = idc.get_name_ea_simple(str_name)
                addresses.append(str_addr)
            else:
                str_addr = int(disasm_line.split()[-1][:-1], base=16)
                addresses.append(str_addr)

        current_addr = idaapi.next_head(current_addr, func_end)

    addresses = list(set(addresses))

    for str_addr in addresses:
        str_addr_ptr = str_addr

        # Get view of addresses except this one
        other_addresses = [x for x in addresses if x != str_addr]

        # Calculate the maximum length this string can be
        max_length = 2356267356289636892736
        for other_address in other_addresses:
            if other_address < str_addr:
                continue

            length = other_address - str_addr

            if length < max_length:
                max_length = length

        # Read the string and apply XOR key ourselves
        char = 0
        char_dec = 0x1245
        str_buf = []
        while char_dec != 0 and len(str_buf) < max_length:

            char = ord(idc.get_bytes(str_addr_ptr, 1))
            char_dec = char ^ 0x19

            if char_dec < 0x1f and char_dec != 0x00:
                char_dec = char_dec ^ 0x20

            str_buf.append(char_dec)
            str_addr_ptr += 1

        string = "".join(bytearray(str_buf).decode(encoding="ascii")).swapcase()
        string.strip("\x00")
        string = string.replace('\x00', "")

        # Add comments
        idc.set_cmt(str_addr, string, False)

        refs = find_references_to(str_addr)

        for ref_ea in refs:
            add_pseudocode_comment(ref_ea, string)


# Example usage:
if __name__ == "__main__":
    print("------------------------")
    eh = flare_emu.EmuHelper()

    testing = False

    if testing:
        function_address = eh.analysisHelper.getNameAddr("decrypt_strings_in_memory")
        func = idaapi.get_func(function_address)
        cfunc = idaapi.decompile(func)
        print(cfunc.user_cmts)
        for item in cfunc.user_cmts.items():
            print(hex(item[0].ea), item[0].itp, item[1])
    else:
        function_address = eh.analysisHelper.getNameAddr("decrypt_strings_in_memory")

        # XOR key used to decrypt the strings
        xor_key = 0x19  # Replace this with the actual XOR key value

        # Decrypt strings in the function
        decrypt_strings_in_function(function_address)

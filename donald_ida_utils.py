import re
import envi
import idc
import idaapi
import ida_ida
import idautils
import ida_name
import ida_xref
import ida_idaapi
import ida_search
import ida_hexrays
import ida_kernwin

from typing import List


DEFAULT_PREFIX = "Decrypted: "


import ida_bytes
import ida_name
import ida_ua

def define_and_rename_global(addr, name, data_type=ida_ua.dt_dword):
    """
    Check if a global variable exists at the given address. If not, define one and then rename it.

    :param addr: Address to check and define the global variable at.
    :param name: New name for the global variable.
    :param data_type: The data type to define at the address (default is dword).
    """
    # Check if the address is unknown (i.e., not defined)
    if ida_bytes.is_unknown(ida_bytes.get_flags(addr)):
        # Define the global variable at the address with the specified data type
        if not ida_bytes.create_data(addr, data_type, ida_bytes.get_data_elsize(addr, data_type), ida_idaapi.BADADDR):
            print(f"Failed to create data at address {hex(addr)}.")
            return False
        
    # Rename the address to the specified name
    if not ida_name.set_name(addr, name, ida_name.SN_CHECK):
        print(f"Failed to rename address {hex(addr)} to {name}.")
        return False

    print(f"Successfully defined and renamed global at {hex(addr)} to {name}.")
    return True


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


def get_name_for_address(ea, ref_addr=None):
    if ref_addr == None:
        ref_addr = ida_idaapi.BADADDR
    name = ida_name.get_ea_name(ea, ida_name.calc_gtn_flags(ref_addr, ea))
    if not name:
        name = hex(ea)

    return name


def add_pseudocode_comment(ea, comment, prefix=DEFAULT_PREFIX, quoted=True, sanitize=True, add_to_existing=True) -> None:
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


def add_disassembly_comment(ea, text):
    ## Set in dissassembly
    idc.set_cmt(ea, text,0)


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


def open_synced_disassembly_view():
    # Get active view title
    pseudocode_view = ida_kernwin.get_current_viewer()
    pseudocode_view_title = ida_kernwin.get_widget_title(pseudocode_view)

    # Open disassembly view
    disasm_view_title = f"Synced Disasm ({pseudocode_view_title})"
    disasm_view = ida_kernwin.open_disasm_window(disasm_view_title)

    # Set disassembly view to text view
    ida_kernwin.set_view_renderer_type(disasm_view, ida_kernwin.TCCRT_FLAT)

    # Sync the disassembly view to the pseudocode view
    what = ida_kernwin.sync_source_t(disasm_view)
    _with = ida_kernwin.sync_source_t(pseudocode_view)
    ida_kernwin.sync_sources(what, _with, True)

    # Dock the disassembly view to the right of the pseudocode view
    ida_kernwin.set_dock_pos(pseudocode_view_title, disasm_view_title, ida_kernwin.WOPN_DP_RIGHT)


class DummyPlugin(ida_idaapi.plugin_t):
    """Dummy plugin to make IDA stop complaining when this file is in the plugins folder."""
    
    # These fields are necessary for whatever reason
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Dummy Plugin"
    help = ""
    wanted_name = "Dummy Plugin"
    wanted_hotkey = ""

    def init(self):
        return ida_idaapi.PLUGIN_UNL

    def run(self, args):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return DummyPlugin()


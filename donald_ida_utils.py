import re
import envi
import idaapi
import ida_ida
import idautils
import ida_name
import ida_xref
import ida_idaapi
import ida_search
import ida_hexrays
import ida_kernwin

import floss.main
import floss.const
import floss.strings
import floss.utils
import floss.tightstrings
import floss.string_decoder
import floss.decoding_manager
import viv_utils.idaloader

from typing import List


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


def monkey_patch_flare_floss():
    # Bypass FLOSS magic check
    def return_true():
        return True

    floss.main.is_supported_file_type = return_true

    # Add ELF files to viv-utils
    def is_elf():
        inf = idaapi.get_inf_structure()

        return inf.filetype == ida_ida.f_ELF

    original_is_exe_func = viv_utils.idaloader.is_exe
    viv_utils.idaloader.is_exe = return_true

    # Hook viv_utils.idaloader.loadWorkspaceFromIdb
    original_load_workspace_from_idb_func = viv_utils.idaloader.loadWorkspaceFromIdb

    def load_workspace_from_idb_hook():
        vw = original_load_workspace_from_idb_func()

        if original_is_exe_func():
            vw.setMeta("Platform", "windows")
            vw.setMeta("Format", "pe")
        elif is_elf():
            vw.setMeta("Platform", "unknown")
            vw.setMeta("Format", "elf")
        else:
            raise NotImplementedError("unsupported filetype")
        
        return vw
        
    viv_utils.idaloader.loadWorkspaceFromIdb = load_workspace_from_idb_hook

    # Change constants
    # TODO: Make these configurable in IDA
    DS_MAX_INSN_COUNT = 200000
    DS_MAX_ADDRESS_REVISITS_EMULATION = 300000
    TS_MAX_INSN_COUNT = 100000

    floss.const.DS_MAX_INSN_COUNT = DS_MAX_INSN_COUNT
    floss.string_decoder.DS_MAX_INSN_COUNT = DS_MAX_INSN_COUNT

    # Goofy ahh python storing kwarg defaults :skull:
    d1, d2, d3 = floss.string_decoder.decode_strings.__defaults__
    floss.string_decoder.decode_strings.__defaults__ = (DS_MAX_INSN_COUNT, d2, d3)

    floss.const.DS_MAX_ADDRESS_REVISITS_EMULATION = DS_MAX_ADDRESS_REVISITS_EMULATION
    floss.decoding_manager.DS_MAX_ADDRESS_REVISITS_EMULATION = DS_MAX_ADDRESS_REVISITS_EMULATION
    floss.tightstrings.DS_MAX_ADDRESS_REVISITS_EMULATION = DS_MAX_ADDRESS_REVISITS_EMULATION

    floss.const.TS_MAX_INSN_COUNT = TS_MAX_INSN_COUNT
    floss.tightstrings.TS_MAX_INSN_COUNT = TS_MAX_INSN_COUNT

    # Allow \r and \n in ASCII strings
    if rb"\r" not in floss.strings.ASCII_BYTE:
        floss.strings.ASCII_BYTE += rb"\r"

    if rb"\n" not in floss.strings.ASCII_BYTE:
        floss.strings.ASCII_BYTE += rb"\n"

    floss.strings.ASCII_RE_4 = re.compile(rb"([%s]{%d,})" % (floss.strings.ASCII_BYTE, 4))
    floss.strings.UNICODE_RE_4 = re.compile(rb"((?:[%s]\x00){%d,})" % (floss.strings.ASCII_BYTE, 4))

    # Do not split strings by \r or \n
    def get_referenced_strings_patch(vw, fva):
        # modified from capa
        f: viv_utils.Function = viv_utils.Function(vw, fva)
        strings = set()
        for bb in f.basic_blocks:
            for insn in bb.instructions:
                for i, oper in enumerate(insn.opers):
                    if isinstance(oper, envi.archs.i386.disasm.i386ImmOper):
                        v = oper.getOperValue(oper)
                    elif isinstance(oper, envi.archs.i386.disasm.i386ImmMemOper):
                        # like 0x10056CB4 in `lea eax, dword [0x10056CB4]`
                        v = oper.imm
                    elif isinstance(oper, envi.archs.i386.disasm.i386SibOper):
                        # like 0x401000 in `mov eax, 0x401000[2 * ebx]`
                        v = oper.imm
                    elif isinstance(oper, envi.archs.amd64.disasm.Amd64RipRelOper):
                        v = oper.getOperAddr(insn)
                    else:
                        continue

                    for v in floss.utils.derefs(vw, v):
                        try:
                            s = floss.utils.read_string(vw, v)
                        except ValueError:
                            continue
                        else:
                            # Do not split strings by \r or \n
                            strings.update([s.rstrip("\x00")])
        return strings
    
    floss.utils.get_referenced_strings = get_referenced_strings_patch


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


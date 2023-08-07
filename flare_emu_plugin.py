import ida_name
import flare_emu
import ida_idaapi
import ida_lines
import ida_moves
import ida_kernwin
import ida_hexrays
import idaapi

import floss.const
import floss.strings

import donald_ida_utils

MEM_WRITE_ADDRESSES = []

MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 2048

ADDRESS_RANGES = []


def find_continuous_ranges(nums):
    nums.sort()  # Sort the input list

    ranges = []
    start = end = nums[0]

    for num in nums[1:]:
        if num == end + 1:
            end = num
        else:
            ranges.append((start, end))
            start = end = num

    ranges.append((start, end))  # Append the last range
    return ranges


def memAccessHook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData):
    if accessType == 17 and memValue != 0:
        MEM_WRITE_ADDRESSES.append(memAccessAddress)


def emulate_and_mark_strings(eh, startAddr, endAddr):
    buffer = bytearray()
    string_addr_ptr = startAddr
    while string_addr_ptr <= endAddr:
        buffer.extend(list(eh.getEmuBytes(string_addr_ptr, size=1)))
        string_addr_ptr += 1

    decoded_strings = list(floss.strings.extract_ascii_unicode_strings(buffer, floss.const.MIN_STRING_LENGTH))

    for ds in decoded_strings:
        if len(ds.string) > MAX_STRING_LENGTH:
            continue
        startAddr += ds.offset
        for ref_addr in donald_ida_utils.find_references_to(startAddr):
            # Try to tie this comment to a variable name
            orig_name = ida_name.get_ea_name(startAddr, ida_name.calc_gtn_flags(ref_addr, startAddr)) or hex(startAddr)
            donald_ida_utils.add_pseudocode_comment(ea=ref_addr, comment=ds.string, sanitize=True, prefix=f"[FLAREEMU] {orig_name}: ")


class FLAREEMUActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)


    def activate(self, ctx):
        global MIN_STRING_LENGTH
        global MAX_STRING_LENGTH
        global MEM_WRITE_ADDRESSES

        pseudocode_view = ida_kernwin.get_current_viewer()
        selection_exists, start_addr, end_addr = ida_kernwin.read_range_selection(pseudocode_view)

        if not selection_exists:
            return

        f = flare_emu_form_t()
        f.Compile()

        # Populate fields with current settings
        f.iSTART_ADDRESS.value = start_addr
        f.iEND_ADDRESS.value = end_addr

        f.iMIN_STRING_LENGTH.value = MIN_STRING_LENGTH
        f.iMAX_STRING_LENGTH.value = MAX_STRING_LENGTH

        ok = f.Execute()

        if ok == 1:
            start_addr = f.iSTART_ADDRESS.value
            end_addr = f.iEND_ADDRESS.value
            
            MIN_STRING_LENGTH = f.iMIN_STRING_LENGTH.value
            MAX_STRING_LENGTH = f.iMAX_STRING_LENGTH.value

            MEM_WRITE_ADDRESSES = []

            if selection_exists:
                eh = flare_emu.EmuHelper()
                eh.emulateRange(startAddr=start_addr, endAddr=end_addr, memAccessHook=memAccessHook, skipCalls=True)
                mem_write_addresses_dedup = list(set(MEM_WRITE_ADDRESSES))
                mem_write_addresses_dedup.sort()
                
                mem_write_ranges = find_continuous_ranges(mem_write_addresses_dedup)

                for mem_write_range in mem_write_ranges:
                    emulate_and_mark_strings(eh, mem_write_range[0], mem_write_range[1])
            else:
                pass


    def update(self, ctx):
        # TODO: You can use the context to check for selection
        return ida_kernwin.AST_ENABLE_FOR_IDB
    

class flare_emu_form_t(ida_kernwin.Form):
    def __init__(self):
        self.invert = False
        F = ida_kernwin.Form
        F.__init__(
            self,
            """STARTITEM 0
BUTTON YES* Start
BUTTON CANCEL Cancel
FLARE Emulate Parameters

<##Emulation start address                :{iSTART_ADDRESS}>
<##Emulation end address                  :{iEND_ADDRESS}>

<##Minimum string length                  :{iMIN_STRING_LENGTH}>
<##Maximum string length                  :{iMAX_STRING_LENGTH}>
""",
            {
                "iSTART_ADDRESS": F.NumericInput(tp=F.FT_ADDR),
                "iEND_ADDRESS": F.NumericInput(tp=F.FT_ADDR),
                "iMIN_STRING_LENGTH": F.NumericInput(tp=F.FT_DEC),
                "iMAX_STRING_LENGTH": F.NumericInput(tp=F.FT_DEC),

            }
        )

    def OnFormChange(self, fid):
        pass
    

class FLAREEmuPlugin(ida_idaapi.plugin_t):
    """IDA Plugin to integrate my personal tools into the UI."""

    # These fields are necessary for whatever reason
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Donald's IDA FLARE Emulate Plugin"
    help = ""
    wanted_name = "Donald's FLARE Emulate Plugin"
    wanted_hotkey = ""

    def __init__(self):
        self.actions = []

    def init(self):
        floss_action_icon_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452000000100000001008060000001FF3FF61000001A049444154789CA4934D6813411CC57F3B9BEE74B5D5B405B7D2E0493C0822A2A8450B8A818A174150513C7A9142A5E841288A22A8A03D7B1245CCC95B4F8227117A088A20581B02E6101491C4048DFB95CDAE4C201EB2C946C883198637FFF7E03D6604436268035D6DDB10D621E45197C86E10359204B3C823BB18D95D27ACBB444E9B9CC73CBB4E265AC57A27C1E8273E85795ACDA9358BCCC622EC6464FF0DD2F77A8933E833B79978D2CDC73A38C7E6A52CA327BB728A874CBE18434C9509D617A8643FE2AFC50C1CC2AAE2EE32F16C1A6175F845B62CEF451E2B137CBEC88FB9B77AF39323342366F0017F6D15FBF156746B85A95C0AF439E4F1CB8CDF72097F5FA57AC631E5C11D339992348C034A93EA8E7087DAD21E8CC3FB902796493F98C7BCA4A1A5EE53BBB2417363FBF8E48AA669A37D3B70C1BB46F58247D438CFD8F534FAF46BECE72FB173ED3E84D89458A24281A0F088FAA23A7F2328DEA4B6D06BAE67840E72FC795A24F8F295A0F42BE171F53550C8E3BD49BAFF67F093D6F73CEEAB02FEFB4102D7F7F26114BAAD30AC0C9AFD2F0CFD1BFF060000FFFF8F6C7F6E65611B9B0000000049454E44AE426082")
        floss_action_icon = ida_kernwin.load_custom_icon(data=floss_action_icon_data, format="png")

        # Create an action
        action = ida_kernwin.action_desc_t(
            "flareemu_plugin:flareemu",
            "FLARE Emulate",
            FLAREEMUActionHandler(),
            "Ctrl+Alt+n",
            "Emulated selected instructions and extract strings",
            floss_action_icon,
        )

        self.actions.append(action)

        if not ida_kernwin.register_action(action):
            print(f"Failed to register {action.name} action")
        if not ida_kernwin.attach_action_to_menu("Edit/Other/Toggle border", action.name, ida_kernwin.SETMENU_APP):
            print(f"Failed attaching {action.name} to menu.")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        for action in self.actions:
            ida_kernwin.unregister_action(action.name)


class pseudo_line_t(object):
    def __init__(self, func_ea, line_nr):
        self.func_ea = func_ea
        self.line_nr = line_nr

    def __hash__(self):
        return hash((self.func_ea, self.line_nr))

    def __eq__(self, r):
        return self.func_ea == r.func_ea \
            and self.line_nr == r.line_nr


def _place_to_line_number(p):
    return ida_kernwin.place_t.as_simpleline_place_t(p).n


class pseudocode_lines_rendering_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self.marked_lines = {}

    def get_lines_rendering_info(self, out, widget, rin):
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu:
            entry_ea = vu.cfunc.entry_ea
            for section_lines in rin.sections_lines:
                for line in section_lines:
                    coord = pseudo_line_t(
                        entry_ea,
                        _place_to_line_number(line.at))
                    color = self.marked_lines.get(coord, None)
                    if color is not None:
                        e = ida_kernwin.line_rendering_output_entry_t(line)
                        e.bg_color = color
                        out.entries.push_back(e)


class mycv_t(ida_kernwin.simplecustviewer_t):
    def Create(self, address_ranges):
        self.address_ranges = address_ranges
        # Form the title
        title = "FLARE Emulate Pipeline"

        active_view = ida_kernwin.get_current_viewer()
        active_view_title = ida_kernwin.get_widget_title(active_view)

        if "Pseudocode" not in active_view_title:
            active_view = ida_hexrays.open_pseudocode(0, ida_hexrays.OPF_NEW_WINDOW)
            active_view_title = ida_kernwin.get_widget_title(active_view)

        self.pseudocode_view = active_view

        # Create the customviewer
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False

        for i, address_range in enumerate(address_ranges):
            self.AddLine(f"{i}: {address_range[0]} - {address_range[1]}")

        self.Show()

        ida_kernwin.set_dock_pos(title, active_view_title, ida_kernwin.WOPN_DP_RIGHT)
        ida_kernwin.activate_widget(active_view, True)

        disasm_view_title = f"Synced Disasm ({active_view_title})"
        disasm_view = ida_kernwin.open_disasm_window(disasm_view_title)
        ida_kernwin.set_view_renderer_type(disasm_view, ida_kernwin.TCCRT_FLAT)
        what = ida_kernwin.sync_source_t(disasm_view)
        _with = ida_kernwin.sync_source_t(active_view)
        ida_kernwin.sync_sources(what, _with, True)
        ida_kernwin.set_dock_pos(active_view_title, disasm_view_title, ida_kernwin.WOPN_DP_LEFT)

        self.disasm_view = disasm_view

        return True

    def OnClick(self, shift):
        """
        User clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        loc = ida_moves.lochist_entry_t()
        ida_kernwin.get_custom_viewer_location(loc, self.GetWidget())
        line_number = _place_to_line_number(loc.place())

        selected_address = self.address_ranges[line_number][0]

        ida_kernwin.jumpto(selected_address, -1, ida_kernwin.UIJMP_IDAVIEW)

        

        # Unmark all lines -> Line -> Address Range -> Move code views to range -> Mark all lines
        print("OnClick, shift=%d" % shift)
        return True

    def OnDblClick(self, shift):
        """
        User dbl-clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        word = self.GetCurrentWord()
        if not word: word = "<None>"
        print("OnDblClick, shift=%d, current word=%s" % (shift, word))
        return True

    def OnCursorPosChanged(self):
        """
        Cursor position changed.
        @return: Nothing
        """
        print("OnCurposChanged")

    def OnClose(self):
        """
        The view is closing. Use this event to cleanup.
        @return: Nothing
        """
        print("OnClose " + self.title)

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        print("OnKeydown, vk=%d shift=%d" % (vkey, shift))
        # ESCAPE?
        if vkey == 27:
            self.Close()
        # VK_DELETE
        elif vkey == 46:
            n = self.GetLineNo()
            if n is not None:
                self.DelLine(n)
                self.Refresh()
                print("Deleted line %d" % n)
        # Goto?
        elif vkey == ord('G'):
            n = self.GetLineNo()
            if n is not None:
                v = ida_kernwin.ask_long(self.GetLineNo(), "Where to go?")
                if v:
                    self.Jump(v, 0, 5)
        elif vkey == ord('R'):
            print("refreshing....")
            self.Refresh()
        elif vkey == ord('C'):
            print("refreshing current line...")
            self.RefreshCurrent()
        elif vkey == ord('A'):
            s = ida_kernwin.ask_str("NewLine%d" % self.Count(), 0, "Append new line")
            self.AddLine(s)
            self.Refresh()
        elif vkey == ord('X'):
            print("Clearing all lines")
            self.ClearLines()
            self.Refresh()
        elif vkey == ord('I'):
            n = self.GetLineNo()
            s = ida_kernwin.ask_str("InsertedLine%d" % n, 0, "Insert new line")
            self.InsertLine(n, s)
            self.Refresh()
        elif vkey == ord('E'):
            l = self.GetCurrentLine(notags=1)
            if not l:
                return False
            n = self.GetLineNo()
            print("curline=<%s>" % l)
            l = l + ida_lines.COLSTR("*", ida_lines.SCOLOR_VOIDOP)
            self.EditLine(n, l)
            self.RefreshCurrent()
            print("Edited line %d" % n)
        else:
            return False
        return True

    def OnHint(self, lineno):
        """
        Hint requested for the given line number.
        @param lineno: The line number (zero based)
        @return:
            - tuple(number of important lines, hint string)
            - None: if no hint available
        """
        return (1, "OnHint, line=%d" % lineno)

    def Show(self, *args):
        ok = ida_kernwin.simplecustviewer_t.Show(self, *args)
        if ok:
            pass
            # permanently attach actions to this viewer's popup menu
            #for av in actions_variants:
            #    actname = say_something_handler_t.compose_action_name(av)
            #    ida_kernwin.attach_action_to_popup(self.GetWidget(), None, actname)
        return ok


def PLUGIN_ENTRY():
    return FLAREEmuPlugin()


def get_decompile_coord_by_ea(cfunc, addr):
    if idaapi.IDA_SDK_VERSION >= 720:
        item = cfunc.body.find_closest_addr(addr)
        y_holder = idaapi.int_pointer()
        if not cfunc.find_item_coords(item, None, y_holder):
            return None
        y = y_holder.value()
    else:
        lnmap = {}
        for i, line in enumerate(cfunc.pseudocode):
            phead = idaapi.ctree_item_t()
            pitem = idaapi.ctree_item_t()
            ptail = idaapi.ctree_item_t()
            ret = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
            if ret and pitem.it:
                lnmap[pitem.it.ea] = i
        y = None
        closest_ea = ida_idaapi.BADADDR
        for ea,line in lnmap.items():
            if closest_ea == ida_idaapi.BADADDR or abs(closest_ea - addr) > abs(ea - addr):
                closest_ea = ea
                y = lnmap[ea]

    return y


if __name__ == "__main__":
    pseudocode_view = ida_kernwin.get_current_viewer()
    selection_exists, start_addr, end_addr = ida_kernwin.read_range_selection(pseudocode_view)

    ida_func = idaapi.get_func(start_addr)
    ida_cfunc = idaapi.decompile(ida_func)
    insn_ea = ida_cfunc.eamap[start_addr][0].ea

    x = get_decompile_coord_by_ea(ida_cfunc, insn_ea)

    address_ranges = [(start_addr, end_addr)] * 8

    x = mycv_t()
    if not x.Create(address_ranges):
        print("Failed to create!")
        # return None
    # x.Show()
    tcc = x.GetWidget()
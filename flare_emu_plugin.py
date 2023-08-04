import ida_name
import flare_emu
import ida_idaapi
import ida_kernwin

import floss.const
import floss.strings

import donald_ida_utils

MEM_WRITE_ADDRESSES = []

MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 2048


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


def PLUGIN_ENTRY():
    return FLAREEmuPlugin()

if __name__ == "__main__":
    pass
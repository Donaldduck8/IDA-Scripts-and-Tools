import ida_kernwin
import ida_idaapi
import donald_ida_utils
import floss_ida_script
import idaapi
import ida_ida

class OpenSyncedDisassemblyViewActionHandler(ida_kernwin.action_handler_t):
    """Action handler for opening a synchronized flat disassembly view."""

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        donald_ida_utils.open_synced_disassembly_view()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    

class FLOSSActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Hook floss.apply_stack_strings
        apply_stack_strings_func = floss_ida_script.apply_stack_strings

        def apply_stack_strings_hook(stack_strings, tight_strings, lvar_cmt = True, cmt = True) -> None:
            apply_stack_strings_func(stack_strings, tight_strings, lvar_cmt, cmt)
            strings = stack_strings + tight_strings

            for s in strings:
                if not s.string:
                    continue

                donald_ida_utils.add_pseudocode_comment(s.program_counter, s.string)

        floss_ida_script.apply_stack_strings = apply_stack_strings_hook

        # Hook floss.apply_decoded_strings
        apply_decoded_strings_func = floss_ida_script.apply_decoded_strings

        def apply_decoded_strings_hook(decoded_strings) -> None:
            apply_decoded_strings_func(decoded_strings)

            for ds in decoded_strings:
                for ref_addr in donald_ida_utils.find_references_to(ds.address):
                    try:
                        var_name = donald_ida_utils.get_name_for_address(ds.address, ref_addr)
                    except:
                        var_name = "Decrypted"
                    donald_ida_utils.add_pseudocode_comment(ref_addr, ds.string, prefix=var_name + ": ")

        floss_ida_script.apply_decoded_strings = apply_decoded_strings_hook

        floss_ida_script.main()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    

class DonaldPlugin(ida_idaapi.plugin_t):
    """IDA Plugin to integrate my personal tools into the UI."""

    # These fields are necessary for whatever reason
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Donald's IDA Tools Plugin"
    help = ""
    wanted_name = "Donald's Plugin"
    wanted_hotkey = ""

    def __init__(self):
        self.actions = []

    def init(self):
        sync_disasm_action_icon_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452000000100000001008060000001FF3FF61000001D249444154388D8593BF6A145114C67F77332CD19DDDCD13046B6D94B060E31BD804111163488A05216A11366A23626130240A696C02E92C6C7C047D012BD187101B33C9EECECC39F75E8BB977926556BC70389781EFCFF9CE1DB3F2F5C46316612A3055C8150A85C242194A2C88030D959FF1EDDDC000249845AE0F1690CC219943B316921924F368E6904C9142D0B1222782FFEDE1CA25E249980A92397E7EF2302921CFA128A02C4115AC05E7C0FBAA7E01CBAE26302B9FFFF8E3D53E57010B8C4BCBEB8FDF399D148808AADAE8F12EF998845C31011CEB745270BC759379C779B01EAC835B8F8F48289456003AA0DD5E40440058DFDAA6D75BA2D7EDD3EB2D31DC785083FB9713549584C2D20AE048A2AA007C38D80B8A6646D97A83752022249476C68185DA41043FD9D921EDA4A49D2E9D4E9734ED32DC5C0B0E4A8BF98783A8FC7E6FBF56565739713E3A90FF3980EDE74D071BEBD181B8B9195C9CF9EDEE41ADACEEDC45E5405DBDC648A2AA580FA317CF66B6B07AEF6178CDA62253AD085A80020648C208D6C1EE9BFD8672ECAEDE427EC69DD18FEA4B48A74D354204BF7A396A6470F77E9581F1DE375EDBE0D191FF7238ACD3B681C8FA731DEBE1DAEDA7F3096E6C1E7A7166EE7F70B17BCDF90B504392D9E40F53640000000049454E44AE426082")
        sync_disasm_action_icon = ida_kernwin.load_custom_icon(data=sync_disasm_action_icon_data, format="png")

        # Create an action
        action = ida_kernwin.action_desc_t(
            "donald_plugin:open_synced_disassembly_view",
            "Disassembly (synced)",
            OpenSyncedDisassemblyViewActionHandler(),
            "Ctrl+4",
            "Open a disassembly text view that is synchronized with the current view",
            sync_disasm_action_icon,
        )

        self.actions.append(action)

        if not ida_kernwin.register_action(action):
            print(f"Failed to register {action.name} action")
        if not ida_kernwin.attach_action_to_menu("View/Open subviews/Disassembly", action.name, ida_kernwin.SETMENU_APP):
            print(f"Failed attaching {action.name} to menu.")

        # FLOSS integration has only been confirmed to work on PE and ELF files
        inf = idaapi.get_inf_structure()

        if inf.filetype in [ida_ida.f_EXE_old, ida_ida.f_EXE, ida_ida.f_PE, ida_ida.f_W32RUN, ida_ida.f_WIN, ida_ida.f_PE, ida_ida.f_ELF]:
            floss_action_icon_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452000000100000001008060000001FF3FF61000001A049444154789CA4934D6813411CC57F3B9BEE74B5D5B405B7D2E0493C0822A2A8450B8A818A174150513C7A9142A5E841288A22A8A03D7B1245CCC95B4F8227117A088A20581B02E6101491C4048DFB95CDAE4C201EB2C946C883198637FFF7E03D6604436268035D6DDB10D621E45197C86E10359204B3C823BB18D95D27ACBB444E9B9CC73CBB4E265AC57A27C1E8273E85795ACDA9358BCCC622EC6464FF0DD2F77A8933E833B79978D2CDC73A38C7E6A52CA327BB728A874CBE18434C9509D617A8643FE2AFC50C1CC2AAE2EE32F16C1A6175F845B62CEF451E2B137CBEC88FB9B77AF39323342366F0017F6D15FBF156746B85A95C0AF439E4F1CB8CDF72097F5FA57AC631E5C11D339992348C034A93EA8E7087DAD21E8CC3FB902796493F98C7BCA4A1A5EE53BBB2417363FBF8E48AA669A37D3B70C1BB46F58247D438CFD8F534FAF46BECE72FB173ED3E84D89458A24281A0F088FAA23A7F2328DEA4B6D06BAE67840E72FC795A24F8F295A0F42BE171F53550C8E3BD49BAFF67F093D6F73CEEAB02FEFB4102D7F7F26114BAAD30AC0C9AFD2F0CFD1BFF060000FFFF8F6C7F6E65611B9B0000000049454E44AE426082")
            floss_action_icon = ida_kernwin.load_custom_icon(data=floss_action_icon_data, format="png")

            # Create an action
            action = ida_kernwin.action_desc_t(
                "donald_plugin:floss",
                "FLOSS",
                FLOSSActionHandler(),
                "Ctrl+n",
                "Run FLOSS and place comments",
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
    donald_ida_utils.monkey_patch_flare_floss()
    return DonaldPlugin()

if __name__ == "__main__":
    pass
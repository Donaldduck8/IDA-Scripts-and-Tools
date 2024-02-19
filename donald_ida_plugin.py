import ida_kernwin
import ida_idaapi
import donald_ida_utils
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
    

class OpenManageAutomaticCommentsViewActionHandler(ida_kernwin.action_handler_t):

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    

class DonaldPlugin(ida_idaapi.plugin_t):
    """IDA Plugin to integrate my personal tools into the UI."""

    # These fields are necessary for whatever reason
    flags = ida_idaapi.PLUGIN_KEEP
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

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        for action in self.actions:
            ida_kernwin.unregister_action(action.name)


def PLUGIN_ENTRY():
    return DonaldPlugin()

if __name__ == "__main__":
    pass

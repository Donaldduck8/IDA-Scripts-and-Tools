import ida_kernwin
import ida_idaapi
import donald_ida_utils

class OpenSyncedDisassemblyViewActionHandler(ida_kernwin.action_handler_t):
    """Action handler for opening a synchronized flat disassembly view."""

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        donald_ida_utils.open_synced_disassembly_view()

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
        self.action_name = ""
        self.action_label = ""
        self.action_tooltip = ""
        self.action_icon_data = b""
        self.action_icon = 0

    def init(self):
        self.action_name = "donald_plugin:open_synced_disassembly_view"
        self.action_label = "Disassembly (synced)"
        self.action_tooltip = "Open a disassembly text view that is synchronized with the current view"
        self.action_icon_data = b"".join([
                                b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52",
                                b"\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF",
                                b"\x61\x00\x00\x01\xD2\x49\x44\x41\x54\x38\x8D\x85\x93\xBF\x6A\x14",
                                b"\x51\x14\xC6\x7F\x77\x33\x2C\xD1\x9D\xDD\xCD\x13\x04\x6B\x6D\x94",
                                b"\xB0\x60\xE3\x1B\xD8\x04\x11\x11\x63\x48\x8A\x05\x21\x6A\x11\x36",
                                b"\x6A\x23\x62\x61\x30\x24\x0A\x69\x6C\x02\xE9\x2C\x6C\x7C\x04\x7D",
                                b"\x01\x2B\xD1\x87\x10\x1B\x33\xC9\xEE\xCE\xCC\x39\xF7\x5E\x8B\xB9",
                                b"\x77\x92\x65\x56\xBC\x70\x38\x97\x81\xEF\xCF\xF9\xCE\x1D\xB3\xF2",
                                b"\xF5\xC4\x63\x16\x61\x2A\x30\x55\xC8\x15\x0A\x85\xC2\x42\x19\x4A",
                                b"\x2C\x88\x03\x0D\x95\x9F\xF1\xED\xDD\xC0\x00\x24\x98\x45\xAE\x0F",
                                b"\x16\x90\xCC\x21\x99\x43\xB3\x16\x92\x19\x24\xF3\x68\xE6\x90\x4C",
                                b"\x91\x42\xD0\xB1\x22\x27\x82\xFF\xED\xE1\xCA\x25\xE2\x49\x98\x0A",
                                b"\x92\x39\x7E\x7E\xF2\x30\x29\x21\xCF\xA1\x28\xA0\x2C\x41\x15\xAC",
                                b"\x05\xE7\xC0\xFB\xAA\x7E\x01\xCB\xAE\x26\x30\x2B\x9F\xFF\xF8\xE3",
                                b"\xD5\x3E\x57\x01\x0B\x8C\x4B\xCB\xEB\x8F\xDF\x39\x9D\x14\x88\x08",
                                b"\xAA\xDA\xE8\xF1\x2E\xF9\x98\x84\x5C\x31\x01\x1C\xEB\x74\x52\x70",
                                b"\xBC\x75\x93\x79\xC7\x79\xB0\x1E\xAC\x83\x5B\x8F\x8F\x48\x28\x94",
                                b"\x56\x00\x3A\xA0\xDD\x5E\x40\x44\x00\x58\xDF\xDA\xA6\xD7\x5B\xA2",
                                b"\xD7\xED\xD3\xEB\x2D\x31\xDC\x78\x50\x83\xFB\x97\x13\x54\x95\x84",
                                b"\xC2\xD2\x0A\xE0\x48\xA2\xAA\x00\x7C\x38\xD8\x0B\x8A\x66\x46\xD9",
                                b"\x7A\x83\x75\x20\x22\x24\x94\x76\xC6\x81\x85\xDA\x41\x04\x3F\xD9",
                                b"\xD9\x21\xED\xA4\xA4\x9D\x2E\x9D\x4E\x97\x34\xED\x32\xDC\x5C\x0B",
                                b"\x0E\x4A\x8B\xF9\x87\x83\xA8\xFC\x7E\x6F\xBF\x56\x56\x57\x39\x71",
                                b"\x3E\x3A\x90\xFF\x39\x80\xED\xE7\x4D\x07\x1B\xEB\xD1\x81\xB8\xB9",
                                b"\x19\x5C\x9C\xF9\xED\xEE\x41\xAD\xAC\xEE\xDC\x45\xE5\x40\x5D\xBD",
                                b"\xC6\x48\xA2\xAA\x58\x0F\xA3\x17\xCF\x66\xB6\xB0\x7A\xEF\x61\x78",
                                b"\xCD\xA6\x22\x53\xAD\x08\x5A\x80\x02\x06\x48\xC2\x08\xD6\xC1\xEE",
                                b"\x9B\xFD\x86\x72\xEC\xAE\xDE\x42\x7E\xC6\x9D\xD1\x8F\xEA\x4B\x48",
                                b"\xA7\x4D\x35\x42\x04\xBF\x7A\x39\x6A\x64\x70\xF7\x7E\x95\x81\xF1",
                                b"\xDE\x37\x5E\xDB\xE0\xD1\x91\xFF\x72\x38\xAC\xD3\xB6\x81\xC8\xFA",
                                b"\x73\x1D\xEB\xE1\xDA\xED\xA7\xF3\x09\x6E\x6C\x1E\x7A\x71\x66\xEE",
                                b"\x7F\x70\xB1\x7B\xCD\xF9\x0B\x50\x43\x92\xD9\xE4\x0F\x53\x64\x00",
                                b"\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82"])
        self.action_icon = ida_kernwin.load_custom_icon(data=self.action_icon_data, format="png")

        # Create an action
        open_synced_disassembly_view_action = ida_kernwin.action_desc_t(
            self.action_name,
            self.action_label,
            OpenSyncedDisassemblyViewActionHandler(),
            "Ctrl+4",
            self.action_tooltip,
            self.action_icon,
        )

        # Register the action
        if ida_kernwin.register_action(open_synced_disassembly_view_action):
            print(f"{self.action_name} action registered successfully!")
        else:
            print(f"Failed to register {self.action_name} action")

        # Attach the action to the Open subview menu
        if ida_kernwin.attach_action_to_menu("View/Open subviews/Disassembly", self.action_name, ida_kernwin.SETMENU_APP):
            pass
        else:
            print(f"Failed attaching {self.action_name} to menu.")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        ida_kernwin.unregister_action(self.action_name)


def PLUGIN_ENTRY():
    return DonaldPlugin()

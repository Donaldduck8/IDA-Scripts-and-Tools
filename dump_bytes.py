import idaapi
import ida_kernwin
import ida_bytes

class DumpMemoryForm(ida_kernwin.Form):
    def __init__(self, start_address):
        self.invert = False
        form_string = """STARTITEM 0
BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
        Dump Memory

        <#Start Address         :{iStart}>
        <#Length/End Address    :{iLengthEnd}>
        <#Fixed Length          :{rFixed}>
        <#Range                 :{rRange}>{rGroup}>
        <#Dump!:{iButtonDump}>"""
        ida_kernwin.Form.__init__(self, form_string, {
            'iStart': ida_kernwin.Form.StringInput(value=start_address, swidth=20),
            'iLengthEnd': ida_kernwin.Form.StringInput(swidth=20),
            'rGroup': ida_kernwin.Form.RadGroupControl(("rFixed", "rRange")),
            'iButtonDump': ida_kernwin.Form.ButtonInput(self.on_dump)
        })


    def on_dump(self, code=0):
        
        start_addr = int(self.GetControlValue(self.iStart), 16)

        i_length_or_end = self.GetControlValue(self.iLengthEnd)

        if self.GetControlValue(self.rGroup) == 0:  # Fixed Length
            if i_length_or_end.startswith("0x"):
                length_end = int(i_length_or_end, 16)
            else:
                length_end = int(i_length_or_end, 10)
            end_addr = start_addr + length_end
            
        else:  # Range
            length_end = int(i_length_or_end, 16)
            end_addr = length_end

        if end_addr < start_addr:
            print("End address is before start address.")
            return
        
        data = ida_bytes.get_bytes(start_addr, end_addr - start_addr)

        if data is None:
            print("Failed to read memory.")
            return
        
        print(f"Dumped data from {hex(start_addr)} to {hex(end_addr)}:\n {data.hex()}")

class DumpMemoryPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Dump Bytes"
    help = "A plugin to dump bytes from the loaded sample"
    wanted_name = "DumpBytes"
    wanted_hotkey = "Ctrl+M"  # Assign Ctrl+M as the hotkey

    def init(self):
        print(f"{self.wanted_name} initialized. Hotkey: {self.wanted_hotkey}")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Get the current cursor position as the start address
        current_address = hex(idaapi.get_screen_ea())
        form = DumpMemoryForm(start_address=current_address)
        form, args = form.Compile()
        form.Execute()
        form.Free()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return DumpMemoryPlugin()

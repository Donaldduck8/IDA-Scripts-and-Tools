"""This script opens a disassembly view that is synchronized with the active pseudocode view."""

import ida_kernwin

if __name__ == "__main__":
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

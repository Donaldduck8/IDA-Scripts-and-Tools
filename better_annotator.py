from __future__ import print_function
import idaapi
import idc
import idautils
import ida_kernwin
import donald_ida_utils

import re
import json
import traceback

from capstone import (
    CS_ARCH_X86,
    CS_MODE_16,
    CS_MODE_32,
    CS_MODE_64
)
from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt


def get_selection():
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    return start, end


MAX_STRING_LENGTH = 35

def slugify(input_string):
    # Convert to lowercase
    slug = input_string.lower()
    # Replace all groups of non-alphanumeric characters with a single hyphen
    slug = re.sub(r'[^\w]+', '-', slug)
    # Remove leading, trailing, and multiple consecutive hyphens
    slug = re.sub(r'-+', '-', slug).strip('-')
    return slug

def sanitize_enum_value(original):
    return slugify(original).replace("-", "_")

def fix_duplicates(values):
    hm = []
    values_new = []

    for value in values:
        # If value exists already
        while value in hm:
            value = value + "_"

        hm.append(value)

        values_new.append(value)

    return values_new

def format_enum(enum_name, enum_data):
    sanitized_values = [sanitize_enum_value(value) for value in enum_data.values()]
    trimmed_values = [x[:MAX_STRING_LENGTH] for x in sanitized_values]
    deduplicated_values = fix_duplicates(trimmed_values)

    enum_s = f'enum {enum_name} {{\n'
    for key, value in zip(enum_data.keys(), deduplicated_values):
        enum_s += f'str_{value} = {hex(key)},\n'

    enum_s += "};"

    return enum_s, dict(zip(enum_data.keys(), deduplicated_values))



class BetterAnnotatorDialog(QtWidgets.QDialog):
    def __init__(self, parent):
        super(BetterAnnotatorDialog, self).__init__(parent)
        self.user_input = """{
    "0x18000154": "This is the decrypted string!"
}"""
        self.mode = "comments"
        self.log_widget = None
        self.data = None
        self.data_orig = None
        self.populate_form()

    def populate_form(self):
        self.setWindowTitle('Better Annotator')
        self.resize(800, 600)
        self.layout = QtWidgets.QVBoxLayout(self)
        self.top_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        # layout.addStretch()

        self.log_widget = QtWidgets.QLabel("Paste your generated JSON data here!")
        self.layout.addWidget(self.log_widget)
        self.text_edit = QtWidgets.QTextEdit()
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(10)
        self.text_edit.setFont(font)
        metrics = QtGui.QFontMetrics(font)
        self.text_edit.setTabStopWidth(4 * metrics.width(' '))
        self.text_edit.insertPlainText(self.user_input)
        self.layout.addWidget(self.text_edit)

        # Connect the textChanged signal to the on_text_changed method
        self.text_edit.textChanged.connect(self.on_text_changed)

        # Create the table and set its properties
        self.table_widget = QtWidgets.QTableWidget()
        self.table_widget.setColumnCount(2)  # Two columns
        self.table_widget.setHorizontalHeaderLabels(["Key", "Value"])
        self.table_widget.horizontalHeader().setStretchLastSection(True)
        self.layout.addWidget(self.table_widget)

        # Radio buttons group
        self.radio_group_box = QtWidgets.QGroupBox("Options")
        self.radio_layout = QtWidgets.QHBoxLayout()
        self.radio_globals = QtWidgets.QRadioButton("Globals")
        self.radio_enum = QtWidgets.QRadioButton("Enum")
        self.radio_comments = QtWidgets.QRadioButton("Comments")
        self.radio_layout.addWidget(self.radio_globals)
        self.radio_layout.addWidget(self.radio_enum)
        self.radio_layout.addWidget(self.radio_comments)
        self.radio_group_box.setLayout(self.radio_layout)
        self.layout.addWidget(self.radio_group_box)

        # Connect each radio button to a callback
        self.radio_globals.clicked.connect(self.radio_button_clicked)
        self.radio_enum.clicked.connect(self.radio_button_clicked)
        self.radio_comments.clicked.connect(self.radio_button_clicked)

        # Set "Comments" radio button checked by default
        self.radio_comments.setChecked(True)

        self.ok_btn = QtWidgets.QPushButton("OK")
        self.ok_btn.setFixedWidth(100)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.bottom_layout.addWidget(self.ok_btn)

        self.layout.addLayout(self.top_layout)
        self.layout.addLayout(self.bottom_layout)

        self.set_table()

    def on_text_changed(self):
        # This method will be called whenever the text in the QTextEdit changes.
        self.set_table()

    def set_table(self):
        text = self.text_edit.toPlainText()  # Get current text from QTextEdit

        self.data = None
        self.data_orig = None
        self.table_widget.setRowCount(0)  # Clear existing rows

        if len(text) == 0:
            self.log_widget.setText(f"Paste your generated JSON data here!")

        try:  
            # Attempt to parse the text as JSON
            data = json.loads(text)
            if not isinstance(data, dict):
                self.log_widget.setText("JSON is not an object")
                return
            
            data_new = {}
            
            for key, value in data.items():
                # Ensure every key is a number and every value is a string
                if isinstance(key, int) or (isinstance(key, str) and key.isdigit()) or key.startswith("0x"):
                    if isinstance(value, str):
                        if key.startswith("0x"):
                            data_new[int(key, 16)] = value
                        else:
                            data_new[int(key)] = value
                    else:
                        self.log_widget.setText(f"Value for key {key} is not a string")
                        return
                else:
                    self.log_widge.setText(f"Key {key} is not a number")
                    return

            data = data_new
            self.data_orig = data
            
            if self.mode == "enum" or self.mode == "globals":
                # Need to slugify and de-duplicate
                enum_s, dedup_data = format_enum("test", data)

                data = dedup_data

            if self.mode == "globals":
                data = {k:v.upper() for k,v in data.items()}

            if self.mode == "comments":
                data  = {k:"[AUTO] " + v for k,v in data.items()}

            for key,value in data.items():
                row_position = self.table_widget.rowCount()
                self.table_widget.insertRow(row_position)
                self.table_widget.setItem(row_position, 0, QtWidgets.QTableWidgetItem(hex(key)))
                self.table_widget.setItem(row_position, 1, QtWidgets.QTableWidgetItem(value))

            self.log_widget.setText(f"Parsed successfully!")

            self.data = data

        except json.JSONDecodeError as e:
            self.log_widget.setText(f"Failed to parse JSON, {e.msg}")
            self.table_widget.setRowCount(0)        

    def radio_button_clicked(self):
        if self.radio_globals.isChecked():
            self.mode = "globals"
        elif self.radio_enum.isChecked():
            self.mode = "enum"
        elif self.radio_comments.isChecked():
            self.mode = "comments"

        self.set_table()

    def ok_btn_clicked(self):
        if self.data == None:
            self.close()
            return

        if self.mode == "comments":
            for addr, value in self.data.items():
                donald_ida_utils.add_pseudocode_comment(addr, value, prefix=None)

        elif self.mode == "globals":
            for addr, value in self.data.items():
                donald_ida_utils.define_and_rename_global(addr, value)
                donald_ida_utils.add_disassembly_comment(addr, self.data_orig[addr])

        elif self.mode == "enum":
            enum_name = show_text_input_dialog()

            if enum_name == None:
                return
            
            enum_s, _ = format_enum(enum_name, self.data)

            print(enum_s)
        else:
            return
        
        self.close()


def show_text_input_dialog():
    f = TextInputForm()
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        return f.inp_str.value
    f.Free()
    return None


class TextInputForm(ida_kernwin.Form):
    def __init__(self):
        self.inp_str = ida_kernwin.Form.StringInput()
        form_str = "STARTITEM 0\nEnum Name\n\n  <##Enter the desired name:{inp_str}>"
        ida_kernwin.Form.__init__(self, form_str, {'inp_str': self.inp_str})


class BetterAnnotatorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "BetterAnnotator"
    help = "BetterAnnotator"
    wanted_name = "BetterAnnotator"
    wanted_hotkey = "Ctrl+Shift+A"
    dialog = None

    def init(self):
        print('BetterAnnotator :: Plugin Started')
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        self.dialog = BetterAnnotatorDialog(None)
        self.dialog.show()


def generic_handler(callback):
    class Handler(idaapi.action_handler_t):
            def __init__(self):
                idaapi.action_handler_t.__init__(self)

            def activate(self, ctx):
                callback()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS
    return Handler()


plugin = BetterAnnotatorPlugin()
def PLUGIN_ENTRY():
    global plugin
    return plugin

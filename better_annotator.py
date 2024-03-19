import idaapi
import ida_kernwin
import donald_ida_utils

import re
import json

from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt


SYMBOLS_TO_WORDS = {
    # ' ': '_',
    '!': 'exclamation_mark',
    '"': 'double_quote',
    '#': 'hash',
    '$': 'dollar',
    '%': 'percent',
    '&': 'ampersand',
    # "'": 'quote',
    '(': 'left_paren',
    ')': 'right_paren',
    '*': 'star',
    '+': 'plus',
    ',': 'comma',
    '-': 'dash',
    '.': 'dot',
    '/': 'slash',
    ':': 'colon',
    ';': 'semicolon',
    '<': 'less_than',
    '=': 'equals',
    '>': 'greater_than',
    '?': 'question_mark',
    '@': 'at',
    '[': 'left_bracket',
    '\\': 'backslash',
    ']': 'right_bracket',
    '^': 'caret',
    # '_': 'underscore',
    '`': 'backtick',
    '{': 'left_brace',
    '|': 'vertical_bar',
    '}': 'right_brace',
    '~': 'tilde'
}


class IDAStringFormatter:
    def __init__(
        self,
        data: dict,
        mode: str,
        maximum_string_length: int = 35,
        keep_original_capitalization: bool = False,
        transliterate_symbols: bool = False,
        comment_prefix: str = "[AUTO]",
    ):
        self.data = data
        self.mode = mode
        self.maximum_string_length = maximum_string_length
        self.keep_original_capitalization = keep_original_capitalization
        self.transliterate_symbols = transliterate_symbols
        self.comment_prefix = comment_prefix

    def transliterate_string(self, input_string: str) -> str:
        # Replace all non-alphanumeric characters with their word equivalent
        for symbol, word in SYMBOLS_TO_WORDS.items():
            input_string = input_string.replace(symbol, f"_{word}_")

        return input_string

    def sanitize_string(self, input_string: str) -> str:
        # Replace all non-alphanumeric characters with an underscore
        input_string = re.sub(r"[^\w]+", "_", input_string)

        # Remove leading, trailing, and multiple consecutive underscores
        input_string = re.sub(r"_+", "_", input_string).strip("_")

        return input_string

    def fix_duplicate_values(self, data: dict) -> dict:
        seen_values = []
        new_data = {}

        for key, value in data.items():
            if value in seen_values:
                duplicate_index = 2

                value_new = value + f"_x{duplicate_index}"

                while value_new in seen_values:
                    duplicate_index += 1
                    value_new = value + f"_x{duplicate_index}"

                value = value_new

            seen_values.append(value)
            new_data[key] = value

        return new_data

    def format_data(self):
        if self.mode == "enum":
            return self.format_enum()
        elif self.mode == "globals":
            return self.format_globals()
        elif self.mode == "comments":
            return self.format_comments()
        else:
            return None

    def format_enum(self):
        return self.format_tokens(enum=True)

    def format_globals(self):
        return self.format_tokens(enum=False)

    def format_tokens(self, enum: bool = False):
        data = self.data

        # Transliteration
        if self.transliterate_symbols:
            data = {
                k: self.transliterate_string(v) for k, v in data.items()
            }

        # Sanitize all strings
        data = {
            k: self.sanitize_string(v) for k, v in data.items()
        }

        # Fix all duplicate values
        data = self.fix_duplicate_values(data)

        # Truncate all strings to the maximum length
        data = {
            k: v[:self.maximum_string_length] for k, v in data.items()
        }

        # Convert all strings to lower-case
        if not self.keep_original_capitalization:
            if enum:
                data = {
                    k: v.lower() for k, v in data.items()
                }
            else:
                data = {
                    k: v.upper() for k, v in data.items()
                }

        return data

    def format_comments(self):
        data = self.data

        # Apply the comment prefix to all values:
        if self.comment_prefix is not None and self.comment_prefix != "":
            data = {
                k: f"{self.comment_prefix} {v}" for k, v in data.items()
            }

        return data

    def format_enum_string(self):
        data = self.format_enum()

        enum_s = "enum enum_name {\n"
        for key, value in data.items():
            enum_s += f"str_{value} = {hex(key)},\n"

        enum_s += "};"

        return enum_s


class BetterAnnotatorDialog(QtWidgets.QDialog):
    def __init__(self, parent):
        super(BetterAnnotatorDialog, self).__init__(parent)
        self.user_input = """{
    "0x18000154": "This is the decrypted string!"
}"""
        self.mode = "comments"
        self.log_widget = None
        self.data = None
        self.max_string_length = 35
        self.keep_original_capitalization = False
        self.transliterate_symbols = False
        self.comment_prefix = "[AUTO]"
        self.populate_form()

    def populate_form(self):
        self.setWindowTitle("Better Annotator")
        self.resize(800, 600)
        self.layout = QtWidgets.QVBoxLayout(self)
        self.top_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout.setAlignment(Qt.AlignRight | Qt.AlignBottom)

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
        self.text_edit.setTabStopWidth(4 * metrics.width(" "))
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
        self.radio_group_box = QtWidgets.QGroupBox("Mode")
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

        # Options group
        self.options_group_box = QtWidgets.QGroupBox("Options")
        self.options_layout = QtWidgets.QHBoxLayout()

        # Max string length
        self.max_length_label = QtWidgets.QLabel("Maximum string length:")
        self.max_length_spinbox = QtWidgets.QSpinBox()
        self.max_length_spinbox.setMinimum(1)
        self.max_length_spinbox.setMaximum(10000)
        self.max_length_spinbox.setValue(35)  # Default value
        self.max_length_spinbox.valueChanged.connect(self.on_max_string_length_changed)

        self.options_layout.addWidget(self.max_length_label)
        self.options_layout.addWidget(self.max_length_spinbox)

        # Checkbox for keeping original capitalization
        self.keep_capitalization_checkbox = QtWidgets.QCheckBox("Keep original capitalization")
        self.keep_capitalization_checkbox.stateChanged.connect(self.on_keep_capitalization_changed)
        self.options_layout.addWidget(self.keep_capitalization_checkbox)

        # Checkbox for transliterating symbols
        self.transliterate_symbols_checkbox = QtWidgets.QCheckBox("Transliterate symbols")
        self.transliterate_symbols_checkbox.stateChanged.connect(self.on_transliterate_symbols_changed)
        self.options_layout.addWidget(self.transliterate_symbols_checkbox)

        # Comment prefix text input
        self.comment_prefix_label = QtWidgets.QLabel("Comment prefix:")
        self.comment_prefix_lineedit = QtWidgets.QLineEdit()
        self.comment_prefix_lineedit.setText("[AUTO]")
        self.comment_prefix_lineedit.textChanged.connect(self.on_comment_prefix_changed)
        self.options_layout.addWidget(self.comment_prefix_label)
        self.options_layout.addWidget(self.comment_prefix_lineedit)

        self.options_group_box.setLayout(self.options_layout)
        self.layout.addWidget(self.options_group_box)

        self.ok_btn = QtWidgets.QPushButton("OK")
        self.ok_btn.setFixedWidth(100)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.bottom_layout.addWidget(self.ok_btn)

        self.layout.addLayout(self.top_layout)
        self.layout.addLayout(self.bottom_layout)

        self.set_table()

    def on_max_string_length_changed(self):
        self.max_string_length = self.max_length_spinbox.value()

        self.set_table()

    def on_keep_capitalization_changed(self):
        self.keep_original_capitalization = self.keep_capitalization_checkbox.isChecked()

        self.set_table()

    def on_transliterate_symbols_changed(self):
        self.transliterate_symbols = self.transliterate_symbols_checkbox.isChecked()

        self.set_table()

    def on_comment_prefix_changed(self):
        self.comment_prefix = self.comment_prefix_lineedit.text()

        self.set_table()

    def on_text_changed(self):
        # This method will be called whenever the text in the QTextEdit changes.
        self.set_table()

    def set_table(self):
        text = self.text_edit.toPlainText()  # Get current text from QTextEdit

        self.data = None
        self.table_widget.setRowCount(0)  # Clear existing rows

        if len(text) == 0:
            self.log_widget.setText("Paste your generated JSON data here!")

        try:
            # Attempt to parse the text as JSON
            data = json.loads(text)
            if not isinstance(data, dict):
                self.log_widget.setText("Data is not a dictionary!")
                return

            data_normalized = {}

            for key, value in data.items():
                # Ensure every key is a number and every value is a string
                if (
                    isinstance(key, int)
                    or (isinstance(key, str) and key.isdigit())
                    or key.startswith("0x")
                ):
                    if isinstance(value, str):
                        if key.startswith("0x"):
                            data_normalized[int(key, 16)] = value
                        else:
                            data_normalized[int(key)] = value
                    else:
                        self.log_widget.setText(f"Value for key {key} is not a string!")
                        return
                else:
                    self.log_widget.setText(f"Key {key} is not a number!")
                    return

            data = data_normalized

            self.formatter = IDAStringFormatter(
                data,
                self.mode,
                self.max_string_length,
                self.keep_original_capitalization,
                self.transliterate_symbols,
                self.comment_prefix,
            )

            data = self.formatter.format_data()

            for key, value in data.items():
                row_position = self.table_widget.rowCount()
                self.table_widget.insertRow(row_position)
                self.table_widget.setItem(
                    row_position, 0, QtWidgets.QTableWidgetItem(hex(key))
                )
                self.table_widget.setItem(
                    row_position, 1, QtWidgets.QTableWidgetItem(value)
                )

            self.log_widget.setText("Parsed successfully!")

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
        if self.data is None:
            self.close()
            return

        if self.mode == "comments":
            for addr, value in self.data.items():
                donald_ida_utils.add_pseudocode_comment(addr, value, prefix=None)

        elif self.mode == "globals":
            for addr, value in self.data.items():
                donald_ida_utils.define_and_rename_global(addr, value)
                donald_ida_utils.add_disassembly_comment(addr, value)

        elif self.mode == "enum":
            enum_s = self.formatter.format_enum_string()

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
        ida_kernwin.Form.__init__(self, form_str, {"inp_str": self.inp_str})


class BetterAnnotatorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "BetterAnnotator"
    help = "BetterAnnotator"
    wanted_name = "BetterAnnotator"
    wanted_hotkey = "Ctrl+Shift+A"
    dialog = None

    def init(self):
        print("BetterAnnotator :: Plugin Started")
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

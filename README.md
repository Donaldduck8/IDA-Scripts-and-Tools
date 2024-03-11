## Donald's IDA scripts and tools
I'm an aspiring reverse engineer, so in my learning process I develop my own solutions to some of the problems I encounter. This repository is a place for me to share and maintain the things I make.

### Installation
The recommended way to install these tools is to create hard links of this repository's files in: ``IDA_HOME/plugins``.

### Synchronized Disassembly View 

Pressing ``Ctrl+4`` will open a disassembly view, synchronized to your active view, and will dock it to the right.

![Synchronized Disassembly View](/img/synced_disasm_view.png)

### Dump Bytes

Pressing ``Ctrl+M`` will open a byte-dumping dialog that allows you to easily extract embedded blobs from your binaries.

![Dump Bytes Dialog](/img/dump_bytes.png)

### Better Annotator

Pressing ``Ctrl+Shift+A`` will open a dialog that allows you to import decrypted strings as a JSON object and use them to annotate your IDBs in various ways.

- "Globals" will define globals at all addresses (keys) if they do not exist, and rename them to the values provided in your JSON object.
- "Enum" will format an enum mapping all keys to the values provided in your JSON object, and print the formatted enum to the console.
- "Comments" will place pseudocode-comments at all addresses (keys).

![Better Annotator](/img/better_annotator.png)

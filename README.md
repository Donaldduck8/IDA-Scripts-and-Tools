## Donald's IDA scripts and tools
I'm an aspiring reverse engineer, so in my learning process I develop my own solutions to some of the problems I encounter. This repository is a place for me to share and maintain the things I make.

### Installation
The recommended way to install these tools is to create hard links of ``donald_ida_utils.py`` and ``donald_ida_plugin.py`` in: ``IDA_HOME/plugins``.

### Synchronized Disassembly View 

Pressing ``Ctrl+4`` will open a disassembly view, synchronized to your active view, and will dock it to the right.
![Synchronized Disassembly View](/img/synced_disasm_view.png)

### [FLOSS](https://github.com/mandiant/flare-floss)-IDA integration
> WARNING: This plugin monkey-patches the ``floss`` and ``viv-utils`` libraries. FLOSS relies on the ``vivisect`` library to navigate the binaries it analyses and from what I can see, there is no lack of support for non-PE binaries there.
>
> Instead, ``floss`` and ``viv-utils`` explicitly check for PE files and will stop analysis otherwise. This plugin circumvents those checks and forces FLOSS to analyse ELF binaries. I have only personally confirmed FLOSS to provide good results during analysis of the following LockBit ESXi/Linux sample: ``40b2724e08232e2a46f3ee36e9b0e5ee2bb49e81570abeb28035adc71db8ac99``

Under ``Edit -> Other -> FLOSS`` you will find the integrated FLOSS script. Activating it will open a window where you can customize the constants FLOSS will use during analysis.

![FLOSS Options](/img/floss_options.png)

This plugin will automatically add pseudocode comments for strings that FLOSS was able to decrypt:
![FLOSS Pseudocode Comments](/img/floss_performance.png)

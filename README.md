# GhidraScripts
Scripts that I've made for reversing stuff.

## CPS2AddReferencesToJmp.java
This script is for reversing CPS2 ROMs that have been swapped from little-endian to big-endian. It repairs jump tables that are of the format:
```asm
move.w (0x123456,PC,D0w),D1w
jmp (0x123456,PC,D1w)
```
![GIF of the script repairing a jump table](https://cdn.discordapp.com/attachments/702296783799320646/1098428194912206888/ghidra_script.gif)

First it finds the jump table base address, looks at the first byte for the length, then traverses the table, turning each entry into a WORD. Then it assigns mnemonic references to the `jmp` to the jump table's base address + the offset from the table. Then it runs `SwitchOverride.java` to repair the branching for the decompiler before finally removing the created mnemonic references (as `SwitchOverride.java` creates redundant operand mnemonics from them).

### Use
Highlight the `jmp` instruction you wish to repair and run the script. Ensure the `jmp` is inside of a function body.

### Caveats
1. Only works on jump tables whose entries are WORDs; this is most of them
2. Only works on jump tables whose first entries are the table's length; this is most of them

#2 is technically untrue; it will work on tables of any length but it may overwrite data outside of the table bounds unless it is already defined. If it is, then it's fine, but if you have yet-to-be-disassembled code after your jump table, best to be pretty sure the length of the jump table is the first WORD in it.

I plan on fixing #1 and looking into what can be done about #2. Perhaps some heuristics.

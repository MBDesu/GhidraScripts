//Fixes up a function. Useful for after adding jump tables.
//where the first byte is the length of the table, which is usually the case.
//@author MBDesu
//@category Repair
//@keybinding
//@menupath
//@toolbar

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class FixupFunction extends GhidraScript {

  @Override
  protected void run() throws Exception {
    Function function = this.getFunctionContaining(currentAddress);
    if (function != null) {
      println(String.format("Fixing up %s...", function.getName()));
      CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
    }
  }
  
}

//Copies mnemonic references to the operand
//@author MBDesu
//@category Repair
//@keybinding
//@menupat
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class CopyMnemonicReferencesToOperand extends GhidraScript {

  @Override
  protected void run() throws Exception {
    Instruction currentInstruction = currentProgram.getListing().getInstructionAt(currentAddress);
    Reference[] mnemonicReferences = currentInstruction.getMnemonicReferences();
    for (int i = 0; i < mnemonicReferences.length; i++) {
      currentInstruction.addOperandReference(0, mnemonicReferences[i].getToAddress(), RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
    }
  }

}

//Adds memory references to CPS2 jump tables that utilize the pattern move.w -> jmp
//where the first byte is the length of the table, which is usually the case.
//@author MBDesu
//@category Repair
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class CPS2AddReferencesToJmp extends GhidraScript {

  private Address getJmpTargetBaseAddress(Instruction currentInstruction) {
    Object obj = currentInstruction.getOpObjects(0)[0];
    if (obj instanceof Scalar) {
      Scalar jmpTarget = (Scalar) obj;
      try {
        return currentInstruction.getAddress().getNewAddress(jmpTarget.getValue(), true);
      } catch (AddressOutOfBoundsException e) {
        println("Instruction's first operand must be the address of the jump table");
      }
    }
    return null;
  }

  private int getBytesAsWord(byte[] bytes) {
    return ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
  }

  private void createWordAt(Address target) {
    Listing listing = currentProgram.getListing();
    Data data = listing.getDataAt(target);
    boolean isWord = data != null && data.getBaseDataType().isEquivalent(new WordDataType());
    try {
      if (data != null && !isWord) {
        removeDataAt(target);
        listing.createData(target, new WordDataType(), 2);
      } else if (data == null || !isWord) {
        listing.createData(target, new WordDataType(), 2);
      }
    } catch (Exception e) {
      println(e.getMessage());
    }
  }

  private ArrayList<Integer> getJumpTableTargetOffsets(Address jmpTargetBaseAddress) {
    ArrayList<Integer> offsets = new ArrayList<>();
    Listing listing = currentProgram.getListing();
    createWordAt(jmpTargetBaseAddress);
    try {
      int tableSize = getBytesAsWord(listing.getDataAt(jmpTargetBaseAddress).getBytes());
      offsets.add(tableSize);
      for (int i = 2; i < tableSize; i += 2) {
        Address nextWordAddr = jmpTargetBaseAddress.getNewAddress(jmpTargetBaseAddress.getOffset() + i, true);
        createWordAt(nextWordAddr);
        offsets.add(getBytesAsWord(listing.getDataAt(nextWordAddr).getBytes()));
      }
    } catch (NullPointerException | MemoryAccessException e) {
      return offsets;
    }
    return offsets;
  }

  private void addReferences(Instruction currentInstruction, Address jmpTargetBaseAddress, ArrayList<Integer> jmpTableTargetOffsets) {
    for (int i = 0; i < jmpTableTargetOffsets.size(); i++) {
      Address jmpTargetAddress = jmpTargetBaseAddress.getNewAddress(jmpTargetBaseAddress.getOffset() + jmpTableTargetOffsets.get(i));
      if (currentInstruction.getFlowType().isJump()) {
        currentInstruction.addMnemonicReference(jmpTargetAddress, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
      } else { // jsr
        currentInstruction.addOperandReference(0, jmpTargetAddress, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
      }
    }
  }

  protected void run() throws Exception {
    Instruction currentInstruction = currentProgram.getListing().getInstructionAt(currentAddress);
    if (currentInstruction == null || (!currentInstruction.getFlowType().isJump() && !currentInstruction.getFlowType().isCall()) || (!currentInstruction.getMnemonicString().equals("jmp") && !currentInstruction.getMnemonicString().equals("jsr"))) {
      println("Instruction must be a jmp or jsr");
      return;
    }
    Address jmpTargetBaseAddress = getJmpTargetBaseAddress(currentInstruction);
    if (jmpTargetBaseAddress == null) {
      println("Instruction's first operand must be the address of the jump table");
      return;
    }
    addReferences(currentInstruction, jmpTargetBaseAddress, getJumpTableTargetOffsets(jmpTargetBaseAddress));
    if (currentInstruction.getFlowType().isJump()) {
      runScript("SwitchOverride");
    }
    for(Reference r : currentInstruction.getMnemonicReferences()) {
      currentInstruction.removeMnemonicReference(r.getToAddress());
    }
  }

}

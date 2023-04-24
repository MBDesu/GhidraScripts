//Adds operand references via selecting a range of memory values.
//Select the instruction you wish to add references to and run.
//@author MBDesu
//@category Repair
//@keybinding
//@menupat
//@toolbar
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class CPS2AddOperandReferencesFromRange extends GhidraScript {

  List<RefType> REF_TYPES = Arrays.asList(new RefType[]{ RefType.COMPUTED_JUMP, RefType.COMPUTED_CALL, RefType.READ, RefType.WRITE, RefType.READ_WRITE });
  List<DataType> DATA_TYPES = Arrays.asList(new DataType[]{ ByteDataType.dataType, WordDataType.dataType, DWordDataType.dataType, QWordDataType.dataType, PointerDataType.dataType });

  private void createReferences(Instruction currentInstruction, Selections selections) {
    for (int i = 0; i <= selections.offsetDiff; i += selections.dataType.getLength()) {
      currentInstruction.addOperandReference(0, selections.startAddr.getNewAddress(selections.startAddr.getOffset() + i), selections.refType, SourceType.USER_DEFINED);
    }
  }

  private void createDataAt(Address target, DataType dataType) {
    Listing listing = currentProgram.getListing();
    Data data = listing.getDataAt(target);
    boolean isType = data != null && data.getBaseDataType().isEquivalent(dataType);
    try {
      if (data != null && !isType) {
        removeDataAt(target);
        listing.createData(target, dataType, dataType.getLength());
      } else if (data == null || !isType) {
        listing.createData(target, dataType, dataType.getLength());
      }
    } catch (Exception e) {
      println(e.getMessage());
    }
  }

  private void createData(Selections selections) {
    for (int i = 0; i <= selections.offsetDiff; i += selections.dataType.getLength()) {
      createDataAt(selections.startAddr.getNewAddress(selections.startAddr.getOffset() + i), selections.dataType);
    }
  }

  private Selections getData() throws Exception {
    Address one = askAddress("Address range", "Enter start of range:");
    Address two = askAddress("Address range", "Enter end of range:");
    Address startAddr = Address.min(one, two);
    Address endAddr = Address.max(one, two);
    long offsetDiff = endAddr.getOffset() - startAddr.getOffset();
    RefType refType = askChoice("Reference type", "Choose a reference type:", REF_TYPES, RefType.COMPUTED_JUMP);
    DataType dataType = askChoice("Data type", "Choose a data type:", DATA_TYPES, WordDataType.dataType);
    int size = dataType.getLength();
    if (offsetDiff % size != 0 || offsetDiff < size) {
      println("Range must be larger than the specified size and must contain <size * n> elements");
      return null;
    }
    println(String.format("Marking %08x to %08x as %ss (%d bytes), referenced by %08x as a %s", startAddr.getOffset(),
        endAddr.getOffset(), dataType.toString(), dataType.getLength(), currentAddress.getOffset(),
        refType.toString()));
    return new Selections(startAddr, offsetDiff, dataType, refType);
  }

  protected void run() throws Exception {
    Instruction currentInstruction = currentProgram.getListing().getInstructionAt(currentAddress);
    if (currentInstruction != null && currentInstruction.getNumOperands() > 0) {
      Selections selections = getData();
      createData(selections);
      createReferences(currentInstruction, selections);
    } else {
      println("Instruction must have an operand");
      return;
    }
  }

  private class Selections {
    Address startAddr;
    long offsetDiff;
    DataType dataType;
    RefType refType;

    Selections(Address startAddr, long offsetDiff, DataType dataType, RefType refType) {
      this.startAddr = startAddr;
      this.offsetDiff = offsetDiff;
      this.dataType = dataType;
      this.refType = refType;
    }

  }
  
}

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nsis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import nsis.file.NsisConstants;

/**
 * This analyzer finds NSIS bytecode and will try to decompile it into the
 * original NSIS script.
 */
public class NsisAnalyzer extends AbstractAnalyzer {

  public NsisAnalyzer() {
    super("NSIS script decompiler", "Decompiles NSIS bytecode into NSIS script.",
        AnalyzerType.BYTE_ANALYZER);
  }

  /**
   * Determines if the analyzer should be enabled by default
   */
  @Override
  public boolean getDefaultEnablement(Program program) {
    return true;
  }

  /**
   * Determines if this analyzer can analyze the given program.
   */
  @Override
  public boolean canAnalyze(Program program) {
    String format = program.getExecutableFormat();
    if (format.equals(NsisLoader.NE_NAME)) {
      return true;
    }
    return false;
  }

  /**
   * Registers the options provided to the user for this analyzer.
   */
  @Override
  public void registerOptions(Options options, Program program) {
  }

  /**
   * Perform analysis when things get added to the 'program'. Return true if the
   * analysis succeeded.
   */
  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    MemoryBlock entriesBlock = program.getMemory()
        .getBlock(NsisConstants.ENTRIES_MEMORY_BLOCK_NAME);
    Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
    AddressSet entriesAddressSet = new AddressSet(entriesBlock.getStart(), entriesBlock.getEnd());
    AddressSet modifiedAddrSet = disassembler.disassemble(entriesBlock.getStart(),
        entriesAddressSet);
    InstructionIterator instructions = program.getListing().getInstructions(modifiedAddrSet,
        /* forward direction */ true);
    MemoryBlock stringsBlock = program.getMemory()
        .getBlock(NsisConstants.STRINGS_MEMORY_BLOCK_NAME);
    for (Instruction instr : instructions) {
      String mnemonic = instr.getMnemonicString();
      int offset;
      try {
        switch (mnemonic) {
        case "MessageBox":
          Address parameterAddr;

          parameterAddr = stringsBlock.getStart().add(instr.getInt(NsisConstants.ARG2_OFFSET));

          instr.addOperandReference(NsisConstants.ARG2_INDEX, parameterAddr, RefType.PARAM,
              SourceType.ANALYSIS);
          break;
        case "Jmp":
          offset = instr.getInt(NsisConstants.ARG1_OFFSET);
          System.out.println(offset);
          instr.setFlowOverride(FlowOverride.BRANCH);
          instr.setFallThrough(entriesBlock.getStart().add(offset * 0x1c));
          break;
        case "Call":
          instr.setFlowOverride(FlowOverride.CALL);
          offset = instr.getInt(NsisConstants.ARG1_OFFSET);
          program.getReferenceManager().addMemoryReference(instr.getAddress(),
              entriesBlock.getStart().add(offset * 0x1c), RefType.CALL_OVERRIDE_UNCONDITIONAL,
              SourceType.ANALYSIS, 0);

          break;
        case "Return":
          instr.setFlowOverride(FlowOverride.RETURN);
          break;

        default:
          break;
        }
      } catch (AddressOutOfBoundsException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      } catch (MemoryAccessException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    }

    if (modifiedAddrSet.isEmpty()) {
      return false;
    }
    return true;
  }
}

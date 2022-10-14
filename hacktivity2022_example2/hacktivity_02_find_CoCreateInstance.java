//
//@author Gergely Revay
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;


public class hacktivity_02_find_CoCreateInstance extends GhidraScript {

	@Override
	protected void run() throws Exception {
		 
		 List<String> COMFunctions = Arrays.asList("CoInitialize",
				 "OleInitialize",
				 "CoInitializeEx", 
				 "CoUninitialize", 
				 "CoCreateInstance", 
				 "CoCreateInstanceEx", 
				 "CoGetClassObject",
				 "CoGetClassObjectEx",
				 "CoGetInstanceFromFile",
				 "CoGetInstanceFromIStorage",
				 "CreateInstance");
		 
		 SymbolTable symbolTable = currentProgram.getSymbolTable();
		 SymbolIterator symbolIter = symbolTable.getExternalSymbols();
		 printf("[-] Searching for COM related functions in %s\n\n", currentProgram.getExecutablePath());
		 
		 for(Symbol symbol: symbolIter) {
			 if (COMFunctions.contains(symbol.getName())){
				 printf("[+] COM function found: %s\n", symbol.getName());
				 if (symbol.getName().contentEquals("CoCreateInstance") || symbol.getName().contentEquals("CoCreateInstanceEx")) {
					printf("[+] Investigating %s further.\n", symbol.getName());
					printf("[+] Checking call sites.\n");
					
					// getting Xrefs to the symbol
					Reference[] references = symbol.getReferences();
					if (references.length > 0) {
						for (Reference ref: references) {
							
							// get instruction at reference address
							Instruction refInstruction = getInstructionAt(ref.getFromAddress());
							// if it is not a call reference, then go to the next ref
							if (refInstruction == null) {
								continue;
							}	
							printf("[+] XREF to %s at 0x%s.\n", symbol.getName(), ref.getFromAddress().toString());
							
							// get the basic block where the reference is located
							BasicBlockModel bm = new BasicBlockModel(currentProgram);
							// ignoring that there might be multiple basic blocks.. bad boy!
							CodeBlock[] cb = bm.getCodeBlocksContaining(ref.getFromAddress(), monitor);
							
							// get the addresses in the basic block
							AddressIterator ai = cb[0].getAddresses(true);
							
							// print the P-Code operations for every address in the basic block
							for(Address addr: ai){
								
								Instruction instruction = getInstructionAt(addr);
								// sophisticated error handling
								if (instruction == null) {
									continue;
								}							
								
								// get P-Code for the instruction
								PcodeOp[] refPcode = instruction.getPcode();
								
								// print all P-Code operation representing one instruction
								for (PcodeOp pcodeOp: refPcode) {
									printf("[+] PCode at 0x%s: %s\n", instruction.getAddress().toString() ,pcodeOp.toString());
								}
								
							}
							
						}
					} else {
						printf("[-] No cross references were found to CoCreateInstance.\n");
					}
					
				 }
			 } 
		 }
		 printf("[-] Finished, ciao.\n");
		 
	}
}

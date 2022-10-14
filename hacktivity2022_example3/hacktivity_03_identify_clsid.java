//
//@author Gergely Revay
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;

public class hacktivity_03_identify_clsid extends GhidraScript {
	
	private DecompInterface decomplib;
	
	/*
	Boilerplate: set up the decompiler
	*/
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("normalize");

		return decompInterface;
	}
	
	/*
	 * Boilerplate: decompile a function and return a HighFunction
	 */
	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;

		try {
			DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());
			
			hfunction = dRes.getHighFunction();
		}
		catch (Exception exc) {
			printf("[-] EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}
		
		return hfunction;
	}
	
	/*
	 * Returns a string representation of the UUID as a byte array.
	 */
	public static String getGuidFromByteArray(byte[] bytes) {
		// rearranging bytes, because of UUID format
		// not sure why it works this way
		
		byte[] fixedbb = new byte[16];
		for(int i=0; i<4; i++) {
			fixedbb[i] = bytes[3-i];
		}
		for(int i=4; i<6; i++) {
			fixedbb[i] = bytes[5-(i%2)];
			fixedbb[i+2] = bytes[7-(i%2)];
		}
		for(int i=8; i<16; i++) {
			fixedbb[i] = bytes[i];
		}
		ByteBuffer bb = ByteBuffer.wrap(fixedbb);
	    long high = bb.getLong();
	    long low = bb.getLong();
	    UUID uuid = new UUID(high, low);
	    return uuid.toString();
	}
	
	/*
	 * Get the UUID string from a Varnode that contains its address.
	 */
	private String loadUUID(Varnode varnode) {
		// this feels to be a hack to get an address out of varnode,
		// but varnode.getAddress did not work in getBytes()
		long addrOffset = varnode.getOffset();
		Address addr = toAddr(addrOffset);
		int size = 16; // fix UUID length
		String uuid;
		
		try {
			byte[] uuidBytes = getBytes(addr, size);
			uuid = getGuidFromByteArray(uuidBytes);
			return uuid;
			
		} catch (MemoryAccessException e) {
			printf("[-] Loading from %s did not go well", addr.toString());
			e.printStackTrace();
		}
		return null;
	}
	
	/*
	 * Recover the CLSID and IID from the call site of the CoCreateInstance call.
	 */
	public void findCLSIDandIID(Address callAddr) {
		// method to backtrack from the call to CoCreateInstance to the value of the CLSID
		printf("[+] Looking for CLSID and IID\n");
		
		// get HighFunction for the function where the call site is
		
		Function function = getFunctionContaining(callAddr);
		if (function == null) {
			printf("[-] ERROR: no function found!\n");
			return;
		}
		HighFunction hFunction = this.decompileFunction(function);
		Iterator<PcodeOpAST> PCodeOps = hFunction.getPcodeOps(callAddr);
		while(PCodeOps.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST PCodeOpAST = PCodeOps.next();
						
			if (PCodeOpAST.getOpcode() == PcodeOp.CALL) {
				printf("[+] PCode at 0x%s: %s\n", callAddr.toString() ,PCodeOpAST.toString());
				// first input is the address to jump to, thus CLSID is the second input
				Varnode clsid = PCodeOpAST.getInput(1);
				// IID is the 4th input 
				Varnode iid = PCodeOpAST.getInput(4);
				
				if (clsid.isConstant()){
					String clsidString = this.loadUUID(clsid);
					printf("[+] CLSID: %s\n", clsidString);
					
				}
				if (clsid.isConstant()){
					String iidString = this.loadUUID(iid);
					printf("[+] IID: %s\n", iidString);
					
				}
				continue;
			}	
		}	
	}

	@Override
	protected void run() throws Exception {
		
	     // preparing decompiler
		 decomplib = setUpDecompiler(currentProgram);
  	
	 	 if(!decomplib.openProgram(currentProgram)) {
				printf("Decompiler error: %s\n", decomplib.getLastMessage());
				return;
		 }
	 	 
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
							
							this.findCLSIDandIID(ref.getFromAddress());
							
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
//This script lists all imported functions used by the binary.
//@author Gergely Revay
//@category 
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class hacktivity_01_list_imports extends GhidraScript {

	@Override
	protected void run() throws Exception {
		 String format = "%-30s %-30s\n";
		 SymbolTable symbolTable = currentProgram.getSymbolTable();
		 SymbolIterator symbolIter = symbolTable.getExternalSymbols();
		 printf("[-] Imported functions of %s\n\n", currentProgram.getExecutablePath());
		 printf(format, "Function Name", "Library");
		 printf("%s\n", "-".repeat(60));
		 for(Symbol symbol: symbolIter) {
			 printf(format, symbol.getName(), symbol.getParentSymbol());
		 }
		 
	}
}

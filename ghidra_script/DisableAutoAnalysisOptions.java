//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.Map;

import ghidra.app.script.GhidraScript;

public class DisableAutoAnalysisOptions extends GhidraScript {
	private static final String STACK = "Stack";
	private static final String X86_CONST_REF_ANALYZER = "x86 Constant Reference Analyzer";
	private static final String WINDOWS_X86_PE_EXCEPTION_HANDLING = "Windows x86 PE Exception Handling";
	private static final String PDB_UNIVERSAL = "PDB Universal";
	private static final String NON_RETURN_FUNCTIONS_D = "Non-Returning Functions - Discovered";
	private static final String DECOMPILER_SWITCH_ANALYSIS = "Decompiler Switch Analysis";
	private static final String DEMANGLER_MS_ANALYZER = "Demangler Microsoft";
	private static final String DEMANGLER_GNU_ANALYZER = "Demangler GNU";
	@Override
	protected void run() throws Exception {
		//TODO: Add script code here
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		if (options.containsKey(STACK)) {
			setAnalysisOption(currentProgram, STACK, "false");
		}
		if (options.containsKey(X86_CONST_REF_ANALYZER)) {
			setAnalysisOption(currentProgram, X86_CONST_REF_ANALYZER, "false");
		}
		if (options.containsKey(WINDOWS_X86_PE_EXCEPTION_HANDLING)) {
			setAnalysisOption(currentProgram, WINDOWS_X86_PE_EXCEPTION_HANDLING, "false");
		}
		if (options.containsKey(PDB_UNIVERSAL)) {
			setAnalysisOption(currentProgram, PDB_UNIVERSAL, "false");
		}
		if (options.containsKey(NON_RETURN_FUNCTIONS_D)) {
			setAnalysisOption(currentProgram, NON_RETURN_FUNCTIONS_D, "false");
		}
		if (options.containsKey(DECOMPILER_SWITCH_ANALYSIS)) {
			setAnalysisOption(currentProgram, DECOMPILER_SWITCH_ANALYSIS, "false");
		}
		if (options.containsKey(DEMANGLER_MS_ANALYZER)) {
			setAnalysisOption(currentProgram, DEMANGLER_MS_ANALYZER, "false");
		}
	}
}

//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.graph.algo.GraphNavigator;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;

public class PrintIR extends GhidraScript {
	private DecompInterface decomplib;

	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;
		try {
			DecompileResults dRes = this.decomplib.decompileFunction(f, this.decomplib.getOptions().getDefaultTimeout(),
					this.getMonitor());
			hfunction = dRes.getHighFunction();

		} catch (Exception exc) {
			this.printf("EXCEPTION IN DECOMPILATION!\n", new Object[0]);
			exc.printStackTrace();
		}
		return hfunction;
	}
	
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		PluginTool tool = this.state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram((Plugin) null, opt, program);
			}
		}
		decompInterface.setOptions(options);
		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");
		return decompInterface;
	}
	
	
	public String toString(PcodeOp p, Language l) {
		String s;
		if (p.getOutput() != null)
			s = getUniqueName(0, l, p);
		else
			s = "";
		s += " " + p.getMnemonic() + " ";
		for (int i = 0; i < p.getNumInputs(); i++) {
			if (p.getInput(i) == null) {
				s += "null";
			} else {
				s += getUniqueName(i+1, l, p);
			}

			if (i < p.getNumInputs() - 1)
				s += " , ";
		}
		return s;
	}


	
	public void printFunction(HighFunction f) {
		try {
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
					new FileOutputStream(this.getScriptArgs()[0] + "/hlIR/" + f.getFunction().getName() + ".c")));
			ArrayList<PcodeBlockBasic> bb = f.getBasicBlocks();
			for (PcodeBlockBasic b : bb) {
				Iterator<PcodeOp> opIter = b.getIterator();
				while (opIter.hasNext()) {
					PcodeOp pcodeOp = opIter.next();
					out.write(toString(pcodeOp, currentProgram.getLanguage()) + "\n");
					}
				}
			out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected void run() throws Exception {
		this.decomplib = setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			this.printf("Decompiler error: %s\n", new Object[] { this.decomplib.getLastMessage() });
			return;
		}
 
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {

			HighFunction hfunction = decompileFunction(function);
			if (hfunction == null)
				continue;
			printFunction(hfunction);

		}
	}
	
	public String toString(Varnode key, Language language) {
		if (key.isAddress() || key.isRegister()) {
			Register reg = language.getRegister(key.getAddress(), key.getSize());
			if (reg != null) {
				return "Reg";
			}
		}
		if (key.isUnique()) {
			return "Unique";
		}
		if (key.isConstant()) {
			
			return "Const_" + Long.toHexString(key.getOffset());
		}
		return "Addr";
	}

	public String getUniqueName(int key, Language language, PcodeOp pcode) {
		Varnode v;
		if (key == 0)
			v = pcode.getOutput();
		else
			v = pcode.getInput(key-1);
		String varName = toString(v, language);
		// varName += '_' + String.valueOf(v.hashCode());
		return varName;
	}

}

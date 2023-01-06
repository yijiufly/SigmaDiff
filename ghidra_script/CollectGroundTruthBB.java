//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class CollectGroundTruthBB extends GhidraScript {
	private DecompInterface decomplib;

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

	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;
		try {
			DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());
			hfunction = dRes.getHighFunction();
		} catch (Exception exc) {
			this.printf("EXCEPTION IN DECOMPILATION!\n", new Object[0]);
			exc.printStackTrace();
		}
		return hfunction;
	}

	public void constructBBs(HighFunction hfunction) {
		ArrayList<PcodeBlockBasic> bb = hfunction.getBasicBlocks();
		Language language = hfunction.getLanguage();
		Iterator<PcodeBlockBasic> pbb = bb.iterator();
		try {
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(this.getScriptArgs()[0] + "/basicblocks.txt", true)));

			while (pbb.hasNext()) {
				PcodeBlockBasic b = pbb.next();
				Iterator<PcodeOp> ops = b.getIterator();
//			System.out.printf(b.toString() + "\n");
				HashSet<String> addrset = new HashSet<String>();
				while (ops.hasNext()) {
					PcodeOp pcodeOp = ops.next();
//				System.out.printf("%s\n", toString(pcodeOp, language));
					if (pcodeOp.getOpcode() == PcodeOp.INDIRECT || pcodeOp.getOpcode() == PcodeOp.MULTIEQUAL)
						continue;
					addrset.add(pcodeOp.getSeqnum().getTarget().toString());
				}
				out.write(addrset.toString());
				out.newLine();
			}
			out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void generateGroundTruth() {
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {
			HighFunction hfunction = this.decompileFunction(function);
			constructBBs(hfunction);
		}
	}

	@Override
	protected void run() throws Exception {
		this.decomplib = this.setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			this.printf("Decompiler error: %s\n", new Object[] { this.decomplib.getLastMessage() });
			return;
		}
		FileWriter myObj = new FileWriter(this.getScriptArgs()[0] + "/basicblocks.txt");
		myObj.close();
		generateGroundTruth();
	}
}

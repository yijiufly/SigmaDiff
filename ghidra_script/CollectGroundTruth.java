//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CollectGroundTruth extends GhidraScript {

	public void generateGroundTruth() {
		try {
			HashSet<String> funcSet = new HashSet<String>();
			HashSet<String> duplicateFuncNames = new HashSet<String>();
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				if (func.isThunk())
					continue;
				else if (!funcSet.add(func.getName())) {
		            duplicateFuncNames.add(func.getName());
		        }
			}
			FileWriter myObj = new FileWriter(this.getScriptArgs()[0] + "/addr2funcname.txt");
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				String name;
				if (func.isThunk()) {
					name = func.getName() + "_thunk";
				} else {
					name = func.getName();
				}
				if (duplicateFuncNames.contains(name))
					name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
				myObj.append(func.getEntryPoint().getOffset() + ", " + name + "\n");
			}
			myObj.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
//		BasicBlockModel bbm = new BasicBlockModel(this.currentProgram);
//		CodeBlockIterator blocks;
//		try {
//			blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY);
//			Listing listing = currentProgram.getListing();
//			FileWriter myObj = new FileWriter(this.getScriptArgs()[0] + "/basicblocks.txt");
//			while(blocks.hasNext()) {
//				CodeBlock block = blocks.next();
//				block.getDestinations(monitor);
//				myObj.append(block.getMinAddress().toString() + ", " + block.getMaxAddress().toString() + "\n");
//			}
//			myObj.close();
//		} catch (Exception e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
	}
	
	@Override
	protected void run() throws Exception {
		generateGroundTruth();
	}
}

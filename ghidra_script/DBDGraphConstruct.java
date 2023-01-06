//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicode32DataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.Unicode32DataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DBDGraphConstruct extends GhidraScript {
	private DecompInterface decomplib;
	private HashMap<String, MachineStatePartial> mstateAll = new HashMap<String, MachineStatePartial>();
	public static HashMap<Address, String> stringLocationMap = new HashMap<Address, String>();
	public static HashMap<Address, HashMap<Long, String>> stringRefLocationSet = new HashMap<Address, HashMap<Long, String>>();
	HashMap<Integer, HashSet<Integer>> edges;
	HashMap<String, Integer> cuNodes;
	HashMap<String, HashSet<Integer>> returnNodes;
	ArrayList<String> printedNodes;
	HashMap<String, Set<String>> stringNodes;

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
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	private void collectStringDataReferenceLocations() {
		DataIterator dataIter = this.currentProgram.getListing().getDefinedData(true);
		while (dataIter.hasNext() && !this.monitor.isCancelled()) {
			String stringdata;
			Data data = dataIter.next();
			DataType dt = data.getDataType();
			try {
				if (dt instanceof StringDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.US_ASCII);
				} else if (dt instanceof TerminatedStringDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.US_ASCII);
				} else if (dt instanceof StringUTF8DataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.UTF_8);
				} else if (dt instanceof TerminatedUnicodeDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.UTF_16);
				} else if (dt instanceof TerminatedUnicode32DataType) {
					stringdata = new String(data.getBytes());
				} else if (dt instanceof UnicodeDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.UTF_16);
				} else {
					if (!(dt instanceof Unicode32DataType))
						continue;
					stringdata = new String(data.getBytes());
				}
			} catch (MemoryAccessException e) {
				e.printStackTrace();
				continue;
			}
			stringLocationMap.put(data.getAddress(), stringdata);
			ReferenceIterator refIter = this.currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (!stringRefLocationSet.containsKey(ref.getFromAddress())) {
					stringRefLocationSet.put(ref.getFromAddress(), new HashMap());
				}
				stringdata = stringdata.replaceAll("\n", " ");
				stringdata = stringdata.strip();
				stringdata = stringdata.replaceAll("[^\\x20-\\x7e]", "");
				stringRefLocationSet.get(ref.getFromAddress()).put(data.getAddress().getOffset(), stringdata);
			}
		}
	}

	public static String identifyStrings(Varnode vnode) {
		if (stringRefLocationSet.containsKey(vnode.getPCAddress())
				&& stringRefLocationSet.get(vnode.getPCAddress()).containsKey(vnode.getOffset())) {
			return stringRefLocationSet.get(vnode.getPCAddress()).get(vnode.getOffset());
		}
		for (Address addr : stringLocationMap.keySet()) {
			if (!addr.getAddressSpace().toString().equals("ram:"))
				continue;
			Long startIndex = addr.getOffset();
			Address addrString = vnode.getAddress();
			Long offset = addrString.getOffset();
			Long endIndex = startIndex + (long) stringLocationMap.get(addr).length();
			if (offset >= endIndex || offset < startIndex)
				continue;
			int subIndex = (int) (offset - startIndex);
			String stringdata = stringLocationMap.get(addr);
			stringdata = stringdata.substring(subIndex);
			stringdata = stringdata.replaceAll("\n", " ");
			stringdata = stringdata.strip();
			stringdata = stringdata.replaceAll("[^\\x20-\\x7e]", "");
			if (stringRefLocationSet.containsKey(vnode.getPCAddress())) {
				stringRefLocationSet.get(vnode.getPCAddress()).put(vnode.getOffset(), stringdata);
			} else {
				HashMap<Long, String> value = new HashMap<Long, String>();
				value.put(vnode.getOffset(), stringdata);
				stringRefLocationSet.put(vnode.getPCAddress(), value);
			}
			return stringdata;
		}
		return null;
	}

	public ArrayList<Function> generateCallGraph(FunctionIterator funcs) {
		ArrayList<Function> functionList = new ArrayList<Function>();
		for (Function fun : funcs) {
			functionList.add(fun);
		}
		Object[] visited = new Boolean[functionList.size()];
		Arrays.fill(visited, Boolean.FALSE);
		ArrayList<Function> stack = new ArrayList<Function>();
		for (int i = 0; i < functionList.size(); ++i) {
			if (((Boolean) visited[i]).booleanValue())
				continue;
			this.sortFuncs(functionList, i, (Boolean[]) visited, stack);
		}
		return stack;
	}

	public void sortFuncs(ArrayList<Function> bb, int vidx, Boolean[] visited, ArrayList<Function> stack) {
		visited[vidx] = true;

		Set<Function> neighbours = bb.get(vidx).getCalledFunctions(monitor);
		for (Function callee : neighbours) {
			int dst_id = bb.indexOf(callee);
			if (callee != null && !visited[dst_id]) {
				sortFuncs(bb, dst_id, visited, stack);
			}
		}
		stack.add(0, bb.get(vidx));
	}

	@Override
	protected void run() throws Exception {
		String targetFunctionName = "FUN_00401100";
		this.decomplib = this.setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			this.printf("Decompiler error: %s\n", new Object[] { this.decomplib.getLastMessage() });
			return;
		}
		// delete the previous files
		String outputPath = this.getScriptArgs()[0] + "/" + currentProgram.getName();
		try {
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_nodelabel.txt")));
			BufferedWriter outCorpus = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_corpus.txt")));
			BufferedWriter outEdges = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_edges.txt")));
			out.close();
			outCorpus.close();
			outEdges.close();
		} catch (Exception e) {

		}
		this.printedNodes = new ArrayList<String>();
		this.cuNodes = new HashMap<String, Integer>();
		this.returnNodes = new HashMap<String, HashSet<Integer>>();
		this.stringNodes = new HashMap<String, Set<String>>();
		this.edges = new HashMap<Integer, HashSet<Integer>>();
		this.collectStringDataReferenceLocations();

		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		ArrayList<Function> funcList = this.generateCallGraph(functionManager);
		boolean skipped = false;
		for (int i = funcList.size() - 1; i >= 0; --i) {
			Function function = funcList.get(i);
			
			if (i != 0 && function.getName().equals(funcList.get(i - 1).getName())) {
				skipped = true;
				continue;
			}
//			if (!function.getName().equals(targetFunctionName)) {
//				continue;
//			}
			printf("Found target function %s @ 0x%x %s, %.2f\n",
					new Object[] { function.getName(), function.getEntryPoint().getOffset(),
							this.currentProgram.getName(),
							(double) (funcList.size() - i) * 1.0 / (double) funcList.size() });
			println(String.valueOf(printedNodes.size()));
			analyzeFunction(function, skipped);
			skipped = false;
		}
		printGraph();

	}

	public void printGraph() {

		String outputPath = this.getScriptArgs()[0] + "/" + currentProgram.getName();
		try {
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_nodelabel.txt")));
			for (int i = 0; i < printedNodes.size(); i++) {
				String line = printedNodes.get(i);
				out.write(line);
				out.newLine();
			}
			out.close();

			out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_edges.txt")));
			for (int i = 0; i < printedNodes.size(); i++) {
				if (edges.containsKey(i)) {
					for (int j : edges.get(i)) {
						String e = String.valueOf(i) + ", " + String.valueOf(j);
						out.write(e);
						out.newLine();
					}
				}

			}
			out.close();

			out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_strings.txt")));
			for (String s : stringNodes.keySet()) {
				out.write(s + "|&|" + String.join("|&|", stringNodes.get(s)));
				out.newLine();
			}
			out.close();

			out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_funcs.txt")));
			for (String s : cuNodes.keySet()) {
				out.write(s + " " + String.valueOf(cuNodes.get(s)));
				out.newLine();
			}
			out.close();
		} catch (Exception e) {

		}
	}

	public DecompileResults decompileFunction(Function f) {
		DecompileResults dRes = null;

		try {
			dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());
		} catch (Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return dRes;
	}

	public void analyzeFunction(Function f, boolean skipped) {
		long start = System.currentTimeMillis();

		DecompileResults dRes = decompileFunction(f);
		HighFunction hfunction = dRes.getHighFunction();
		ClangTokenGroup ccode = dRes.getCCodeMarkup();

		// currentProgram.getListing().
		Language language = currentProgram.getLanguage();
		if (hfunction == null) {
			printf("ERROR: Failed to decompile function!\n");
			return;
		}

		printf("number of parameters %d\n", hfunction.getFunctionPrototype().getNumParams());
		String output = this.getScriptArgs()[0];

		ArrayList<PcodeBlockBasic> bb = hfunction.getBasicBlocks();

		if (bb.size() == 0)
			return;

		Queue<PcodeBlockBasic> workList = new LinkedList<>();
		HashSet<PcodeBlockBasic> visited = new HashSet<PcodeBlockBasic>();
		HashMap<PcodeBlockBasic, Integer> bbStartingNodes = new HashMap<PcodeBlockBasic, Integer>();
		HashMap<PcodeBlockBasic, Integer> bbEndingNodes = new HashMap<PcodeBlockBasic, Integer>();
		HashMap<Integer, PcodeBlockBasic> callsite = new HashMap<Integer, PcodeBlockBasic>();
		workList.add(bb.get(0));
		visited.add(bb.get(0));

		int firstPcodeIdx = printedNodes.size();
		cuNodes.put(f.toString(), firstPcodeIdx);
		returnNodes.put(f.toString(), new HashSet<Integer>());

		// first go over all the basic blocks, collect starting nodes, ending nodes,
		// callsite, connect PCode inside
		while (!workList.isEmpty()) {
			PcodeBlockBasic b = workList.remove();
			Iterator<PcodeOp> ops = b.getIterator();
			System.out.printf(b.toString() + "\n");
			int firstIdx = printedNodes.size();
			PcodeOp pcodeOp;
			ArrayList<PcodeOp> opsList = new ArrayList<PcodeOp>();
			while (ops.hasNext()) {
				pcodeOp = ops.next();
				if (pcodeOp.getOpcode() == PcodeOp.INDIRECT || pcodeOp.getOpcode() == PcodeOp.MULTIEQUAL)
					continue;
				opsList.add(pcodeOp);
			}
			for (int i = 0; i < opsList.size(); i++) {
				pcodeOp = opsList.get(i);
//				System.out.printf("%s\n", toString(pcodeOp, language));
				printedNodes.add(toString(pcodeOp, language));
				int currentIdx = printedNodes.size() - 1;
				if (currentIdx != firstIdx) {
					if (!edges.containsKey(currentIdx - 1))
						edges.put(currentIdx - 1, new HashSet<Integer>());
					edges.get(currentIdx - 1).add(currentIdx);
				} else {
					// first node in the bb
					bbStartingNodes.put(b, currentIdx);
				}

				if (i == opsList.size() - 1) {
					bbEndingNodes.put(b, currentIdx);
				}

				if (skipped) {
					// if it's a external function, we only want to use one node to represent it
					returnNodes.get(f.toString()).add(currentIdx);
					return;
				}

				// handle inter-procedural edges
				if (pcodeOp.getOpcode() == PcodeOp.CALL || pcodeOp.getOpcode() == PcodeOp.CALLIND) {
					Function calleef = this.currentProgram.getFunctionManager()
							.getFunctionAt(pcodeOp.getInput(0).getAddress());
					if (calleef == null)
						continue;
					if (calleef.isThunk() && calleef.getName().equals(f.getName()))
						continue;
					if (cuNodes.containsKey(calleef.toString())) {
						if (!edges.containsKey(currentIdx))
							edges.put(currentIdx, new HashSet<Integer>());
						// from the callsite to the starting node of target function
						edges.get(currentIdx).add(cuNodes.get(calleef.toString()));

						// the return edges
						if (i < opsList.size() - 1) {
							for (int retIdx : returnNodes.get(calleef.toString())) {
								if (!edges.containsKey(retIdx))
									edges.put(retIdx, new HashSet<Integer>());
								edges.get(retIdx).add(currentIdx + 1);
							}
						}
						else {
							// collect the return edges
							for (int retIdx : returnNodes.get(calleef.toString())) {
								for (int k=0 ; k < b.getOutSize(); k++)
									callsite.put(retIdx, (PcodeBlockBasic)b.getOut(k));
							}
						}

					}
				}
				
				if (pcodeOp.getOpcode() == PcodeOp.RETURN) {
					returnNodes.get(f.toString()).add(currentIdx);
				}
				for (int j = 0; j < pcodeOp.getNumInputs(); j++) {
					String s = identifyStrings(pcodeOp.getInput(j));
					if (s != null) {
						if (!stringNodes.containsKey(s)) {
							stringNodes.put(s, new LinkedHashSet<String>());
						}
						stringNodes.get(s).add(String.valueOf(currentIdx));
					}
				}
			}
			
			for (int i = 0; i < b.getOutSize(); i++) {
				if (!visited.contains(b.getOut(i))) {
					workList.add((PcodeBlockBasic) b.getOut(i));
					visited.add((PcodeBlockBasic) b.getOut(i));
				}
			}
		}
		
		// connect between basic blocks, add the remaining call return edges
		for (PcodeBlockBasic b : bb) {
			for (int i = 0; i < b.getOutSize(); i++) {
				if (!bbEndingNodes.containsKey(b) || !bbStartingNodes.containsKey(b.getOut(i)) )
					continue;
				int lastIdxOfB = bbEndingNodes.get(b);
				int firstIdxOfNextB = bbStartingNodes.get(b.getOut(i));
				if (!edges.containsKey(lastIdxOfB))
					edges.put(lastIdxOfB, new HashSet<Integer>());
				edges.get(lastIdxOfB).add(firstIdxOfNextB);
			}
		}
		
		for (int i : callsite.keySet()) {
			PcodeBlockBasic retB = callsite.get(i);
			if (!bbStartingNodes.containsKey(retB))
				continue;
			int firstIdxOfRetB = bbStartingNodes.get(retB);
			if (!edges.containsKey(i))
				edges.put(i, new HashSet<Integer>());
			edges.get(i).add(firstIdxOfRetB);
		}

	}

	public String toString(Varnode v, Language language) {
		if (v.isAddress() || v.isRegister()) {
			Register reg = language.getRegister(v.getAddress(), v.getSize());
			if (reg != null) {
				return reg.getName();
			}
		}
		if (v.isUnique()) {
			return "uniq";
		}
		if (v.isConstant()) {
			return "imme";
		}
		return "addr";
	}

	public String toString(PcodeOp p, Language l) {
		String s = "";
		s += p.getMnemonic() + " ";
		for (int i = 0; i < p.getNumInputs(); i++) {
			if (p.getInput(i) == null) {
				s += "null";
			} else {
				s += toString(p.getInput(i), l);
			}

			if (i < p.getNumInputs() - 1)
				s += " ";
		}
		if (p.getOutput() != null)
			s += " " + toString(p.getOutput(), l);
		s += " " + Long.toHexString(p.getSeqnum().getTarget().getOffset());
		return s;
	}
}

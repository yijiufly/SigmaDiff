import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// 
// Decompiled by Procyon v0.5.36
// 

public class ConstructDDG extends GhidraScript {
	private DecompInterface decomplib;
	private HashMap<ClangLine, HashSet<PcodeOp>> mapping;

	public ConstructDDG(DecompInterface decomplib, TaskMonitor monitor, ClangTokenGroup ccode) {
		super();
		this.decomplib = decomplib;
		this.monitor = monitor;
//		mapPcodeOpToClangLine(ccode);
	}

	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;
		try {
			DecompileResults dRes = this.decomplib.decompileFunction(f, this.decomplib.getOptions().getDefaultTimeout(),
					this.getMonitor());
			hfunction = dRes.getHighFunction();
			ClangTokenGroup ccode = dRes.getCCodeMarkup();
			mapPcodeOpToClangLine(ccode);
		} catch (Exception exc) {
			this.printf("EXCEPTION IN DECOMPILATION!\n", new Object[0]);
			exc.printStackTrace();
		}
		return hfunction;
	}

	public void mapPcodeOpToClangLine(ClangTokenGroup ccode) {
		List<ClangNode> lst = new ArrayList<ClangNode>();
		ccode.flatten(lst);
		ArrayList<ClangLine> lines = DecompilerUtils.toLines(ccode);
		mapping = new HashMap<ClangLine, HashSet<PcodeOp>>();

		for (ClangLine l : lines) {
//			println(l.toString());
			for (ClangToken c : l.getAllTokens()) {
				if (c.getPcodeOp() != null) {
					if (!mapping.containsKey(l)) {
						mapping.put(l, new HashSet<PcodeOp>());
					}
//					println(c.toString() + " " + c.getPcodeOp().toString());
					mapping.get(l).add(c.getPcodeOp());
				}
			}
		}
	}
	
	public HashSet<PcodeOp> getRealDef(Varnode vnode, HashSet<PcodeOp> visited) {
		if (vnode.getDef() == null || visited.contains(vnode.getDef()))
			return null;
		HashSet<PcodeOp> ret = new HashSet<PcodeOp>();
		visited.add(vnode.getDef());
		if (vnode.getDef().getOpcode() != PcodeOp.INDIRECT && vnode.getDef().getOpcode() != PcodeOp.MULTIEQUAL) {
			ret.add(vnode.getDef());
		} else {
			for (int i = 0; i < vnode.getDef().getNumInputs(); i++) {
				HashSet<PcodeOp> parentdef = getRealDef(vnode.getDef().getInput(i), visited);
				if (parentdef != null)
					ret.addAll(parentdef);
			}
		}
		return ret;
	}

	public void constructDDG(HighFunction hfunction, HashMap<PcodeOp, HashSet<PcodeOp>> graph) {
		ArrayList<PcodeBlockBasic> bb = hfunction.getBasicBlocks();
		Language language = hfunction.getLanguage();
		Iterator<PcodeBlockBasic> pbb = bb.iterator();
		while (pbb.hasNext()) {
			PcodeBlockBasic b = pbb.next();
			Iterator<PcodeOp> ops = b.getIterator();
			
//			System.out.printf(b.toString() + "\n");
			while (ops.hasNext()) {
				PcodeOp pcodeOp = ops.next();
//				System.out.printf("%s\n", toString(pcodeOp, language));
				if (pcodeOp.getOpcode() == PcodeOp.INDIRECT || pcodeOp.getOpcode() == PcodeOp.MULTIEQUAL)
					continue;
				
				HashSet<PcodeOp> def = new HashSet<PcodeOp>();
				for (int i = 0; i < pcodeOp.getNumInputs(); ++i) {
					HashSet<PcodeOp> visited = new HashSet<PcodeOp>();
					visited.add(pcodeOp);
					HashSet<PcodeOp> inputDef = getRealDef(pcodeOp.getInput(i), visited);
					if (inputDef != null) {
						def.addAll(inputDef);
//						this.printf("defs: %s", toString(pcodeOp.getInput(i).getDef(), language));
					}
				}

				graph.put(pcodeOp, def);
			}
		}
	}

	public void analyzeBackwards(Function f, HashMap<PcodeOp, HashSet<PcodeOp>> graph) {
		HighFunction hfunction = this.decompileFunction(f);
		Language language = hfunction.getLanguage();
		Iterator<PcodeOpAST> pcode = hfunction.getPcodeOps();
		this.printf("number of parameters %d", new Object[] { hfunction.getFunctionPrototype().getNumParams() });
		ArrayList<PcodeOp> list = new ArrayList<PcodeOp>();
		while (pcode.hasNext() && !this.monitor.isCancelled()) {
			PcodeOpAST pcodeOp = pcode.next();
			if (pcodeOp.getSeqnum().getOrder() == 12
					&& Long.toHexString(pcodeOp.getSeqnum().getTarget().getOffset()).equals("100d40")) {
				list.add(pcodeOp);
				this.printf("Found target\n", new Object[0]);
				break;
			}
		}
		ArrayList<PcodeOp> visited = new ArrayList<PcodeOp>();
		while (!list.isEmpty()) {
			PcodeOp pcodeOp2 = list.get(0);
			visited.add(pcodeOp2);
			list.remove(0);
			HashSet<PcodeOp> def = new HashSet<PcodeOp>();
			this.printf("current op: %s", new Object[] { this.toString(pcodeOp2, language) });
			for (int i = 0; i < pcodeOp2.getNumInputs(); ++i) {
				if (pcodeOp2.getInput(i).getDef() != null) {
					def.add(pcodeOp2.getInput(i).getDef());
					if (!visited.contains(pcodeOp2.getInput(i).getDef())) {
						list.add(pcodeOp2.getInput(i).getDef());
					}
					this.printf("defs: %s", new Object[] { this.toString(pcodeOp2.getInput(i).getDef(), language) });
				}
			}
			graph.put(pcodeOp2, def);
		}
		try {
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("g.dot")));
			out.write("digraph {");
			out.newLine();
			for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); i++) {
				Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
				Iterator<PcodeOp> desc = key.getDescendants();
				while (desc.hasNext()) {
					PcodeOp use = desc.next();
					if (graph.containsKey(use)) {
						out.write("\"ARG" + String.valueOf(i + 1) + "\" -> \"" + toString(use, language) + "\"");
						out.newLine();
					}
				}
			}
			for (PcodeOp cur : graph.keySet()) {
				for (PcodeOp def : graph.get(cur)) {
					out.write("\"" + toString(def, language) + "\" -> \"" + toString(cur, language) + "\"");
					out.newLine();
				}
			}
			out.write("}");
			out.close();
		} catch (Exception e) {

		}
	}

	public String toString(PcodeOp p, Language l) {
		String s;
		if (p.getOutput() != null)
			s = p.getOutput().toString(l);
		else
			s = " --- ";
		s += " " + p.getMnemonic() + " ";
		for (int i = 0; i < p.getNumInputs(); i++) {
			if (p.getInput(i) == null) {
				s += "null";
			} else {
				s += p.getInput(i).toString(l);
			}

			if (i < p.getNumInputs() - 1)
				s += " , ";
		}
		s += " " + p.getSeqnum().toString();
		return s;
	}

	/**
	 * Convert this varnode to an alternate String representation based on a
	 * specified language.
	 * 
	 * @param language
	 * @return string representation
	 */
	public String toString(Varnode v, Language language) {
		if (v.isAddress() || v.isRegister()) {
			Register reg = language.getRegister(v.getAddress(), v.getSize());
			if (reg != null) {
				return reg.getName();
			}
		}
		if (v.isUnique()) {
			return "u_" + Long.toHexString(v.getOffset()) + ":" + v.getSize();
		}
		if (v.isConstant()) {
			return "0x" + Long.toHexString(v.getOffset());
		}
		return "A_" + v.getAddress() + ":" + v.getSize();
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

	public void run() throws Exception {
		String targetFunctionName = "FUN_004038f0";
		this.decomplib = this.setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			this.printf("Decompiler error: %s\n", new Object[] { this.decomplib.getLastMessage() });
			return;
		}
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		BasicBlockModel bbm = new BasicBlockModel(this.currentProgram);
		ControlDependencyRunner cdrunner = new ControlDependencyRunner(this.currentProgram, this.monitor, bbm);
		for (Function function : functionManager) {
			if (!function.getName().equals(targetFunctionName)) {
				continue;
			}
			this.printf("Found target function %s @ 0x%x\n",
					new Object[] { function.getName(), function.getEntryPoint().getOffset() });

			HighFunction hfunction = this.decompileFunction(function);
			if (hfunction == null) {
				this.printf("ERROR: Failed to decompile function!\n", new Object[0]);
				return;
			}
			HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph = new HashMap<PcodeOp, HashSet<PcodeOp>>();
			HashMap<Address, HashSet<Address>> cdgraph = new HashMap<Address, HashSet<Address>>();
			this.constructDDG(hfunction, ddgraph);
			PcodeBlockBasic entry = getPcodeBlockContaining(hfunction.getBasicBlocks(),hfunction.getFunction().getEntryPoint());
			
			cdrunner.generateCDG(hfunction.getBasicBlocks(), cdgraph, entry);
			toDot(hfunction, ddgraph, cdgraph, cdrunner.entryEdges);
		}
	}
	
	public PcodeBlockBasic getPcodeBlockContaining(ArrayList<PcodeBlockBasic> blocks, Address entry) {
		for (PcodeBlockBasic b : blocks) {
			if (b.contains(entry))
				return b;
			if (b.contains(entry.add(4))) //clang binaries
				return b;
		}
		return null;
	}

	public void genPDG(Program program, HighFunction hfunction, HashMap<Varnode, HashSet<ClangLine>> entryDDEdgesLine,
			HashSet<ClangLine> entryCDEdgesLine, HashMap<ClangLine, HashSet<ClangLine>> cdEdgesLine,
			HashMap<ClangLine, HashSet<ClangLine>> ddEdgesLine) {
		HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph = new HashMap<PcodeOp, HashSet<PcodeOp>>();
		HashMap<Address, HashSet<Address>> cdgraph = new HashMap<Address, HashSet<Address>>();
		this.constructDDG(hfunction, ddgraph);
		BasicBlockModel bbm = new BasicBlockModel(program);
		ControlDependencyRunner cdrunner = new ControlDependencyRunner(program, this.monitor, bbm);
		PcodeBlockBasic entry = getPcodeBlockContaining(hfunction.getBasicBlocks(),hfunction.getFunction().getEntryPoint());
		cdrunner.generateCDG(hfunction.getBasicBlocks(), cdgraph, entry);
		this.toDecompiledStmtDot(hfunction, ddgraph, cdgraph, cdrunner.entryEdges, entryDDEdgesLine, entryCDEdgesLine,
				cdEdgesLine, ddEdgesLine);
		toDot(ddEdgesLine, cdEdgesLine, entryDDEdgesLine, entryCDEdgesLine);
	}
	
	public void genPDGIR(Program program, HighFunction hfunction, HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph, HashMap<Varnode, HashSet<PcodeOp>> entryDDEdgesLine,
			HashSet<PcodeOp> entryCDEdgesLine, HashMap<PcodeOp, HashSet<PcodeOp>> cdEdgesLine, HashMap<PcodeOpAST, HashMap<Address, TreeSet<String>>> switchEdges) {
		HashMap<Address, HashSet<Address>> cdgraph = new HashMap<Address, HashSet<Address>>();
		this.constructDDG(hfunction, ddgraph);
		BasicBlockModel bbm = new BasicBlockModel(program);
		ControlDependencyRunner cdrunner = new ControlDependencyRunner(program, this.monitor, bbm);
		PcodeBlockBasic entry = getPcodeBlockContaining(hfunction.getBasicBlocks(),hfunction.getFunction().getEntryPoint());
		cdrunner.generateCDG(hfunction.getBasicBlocks(), cdgraph, entry);
		toIRDot(hfunction, ddgraph, cdgraph, cdrunner.entryEdges, entryDDEdgesLine, entryCDEdgesLine, cdEdgesLine, switchEdges);
	}
	
	public void toIRDot(HighFunction hfunction, HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph,
			HashMap<Address, HashSet<Address>> cdgraph, HashSet<Address> entryEdges,
			HashMap<Varnode, HashSet<PcodeOp>> entryDDEdges, HashSet<PcodeOp> entryCDEdges,
			HashMap<PcodeOp, HashSet<PcodeOp>> cdEdges, HashMap<PcodeOpAST, HashMap<Address, TreeSet<String>>> switchEdges) {
		for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); ++i) {
			if (hfunction.getFunctionPrototype().getParam(i).getHighVariable() == null)
				continue;
			Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
			Iterator<PcodeOp> desc = key.getDescendants();
//			entryDDEdges.put(key, new HashSet<PcodeOp>());
			while (desc.hasNext()) {
				PcodeOp use = desc.next();
				if (use.getOpcode() == PcodeOp.INDIRECT || use.getOpcode() == PcodeOp.MULTIEQUAL)
					continue;
				entryDDEdges.get(key).add(use);
			}
		}

		for (Address cur : entryEdges) {
			Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
			while (itr.hasNext()) {
				PcodeOpAST pcode = itr.next();
				if (pcode.getOpcode() == PcodeOp.INDIRECT || pcode.getOpcode() == PcodeOp.MULTIEQUAL)
					continue;
				entryCDEdges.add(pcode);
			}
		}

		HashMap<Address, TreeSet<String>> switchCaseLabel = new HashMap<Address, TreeSet<String>>();
		// one address can be mapped with multiple case label
		if (hfunction.getJumpTables() != null) {
			JumpTable[] jp = hfunction.getJumpTables();
			for (int i = 0; i < jp.length; i++) {
				Address[] cases = jp[i].getCases();
				for (int j = 0; j < cases.length; j++) {
					if (!switchCaseLabel.containsKey(cases[j]))
						switchCaseLabel.put(cases[j], new TreeSet<String>());
					if (j < jp[i].getLabelValues().length) {
						switchCaseLabel.get(cases[j]).add(String.valueOf(jp[i].getLabelValues()[j]));
					} else {
						switchCaseLabel.get(cases[j]).add("-1");
					}
				}
			}
		}
		for (Address cur : cdgraph.keySet()) {
			Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
			PcodeOpAST last = null;
			int order = -1;
			// itr is not sorted
			while (itr.hasNext()) {
				PcodeOpAST tmp = itr.next();
				if (tmp.getOpcode() != PcodeOp.CBRANCH && tmp.getOpcode() != PcodeOp.BRANCHIND && tmp.getOpcode() != PcodeOp.BRANCH) {
					continue;
				}
				if (tmp.getSeqnum().getOrder() > order) {
					last = tmp;
					order = tmp.getSeqnum().getOrder();
				}
			}
			if (last != null) {
				HashSet<PcodeBlockBasic> bbSet = new HashSet<PcodeBlockBasic>(); 
				cdEdges.put(last, new HashSet<PcodeOp>());
				for (Address dep : cdgraph.get(cur)) {
					Iterator<PcodeOpAST> itr2 = hfunction.getPcodeOps(dep);
					while (itr2.hasNext()) {
						PcodeOpAST pcode2 = itr2.next();
						bbSet.add(pcode2.getParent());
						if (pcode2.getOpcode() == PcodeOp.INDIRECT || pcode2.getOpcode() == PcodeOp.MULTIEQUAL)
							continue;
						if (last.getOpcode() != PcodeOp.BRANCHIND) 
							cdEdges.get(last).add(pcode2);
					}
				}
				// handle each case of the switch separately
				if (last.getOpcode() == PcodeOp.BRANCHIND) {
					HashMap<Address, TreeSet<String>> caseLabel = new HashMap<Address, TreeSet<String>>();
					for (Address dep : cdgraph.get(cur)) {
						caseLabel.put(dep, new TreeSet<String>());
					}
					for (PcodeBlockBasic bb : bbSet) {
						if (switchCaseLabel.containsKey(bb.getStart())) {
							TreeSet<String> labels = switchCaseLabel.get(bb.getStart());
							ArrayList<PcodeBlockBasic> queue = new ArrayList<PcodeBlockBasic>();
							HashSet<PcodeBlockBasic> visited = new HashSet<PcodeBlockBasic>();
							queue.add(bb);
							visited.add(bb);
							// go over each block from the case entry, add match from case label to this address
							while(queue.size() > 0) {
								PcodeBlockBasic tmp = queue.remove(0);
								if (!caseLabel.containsKey(tmp.getStart()))
									continue;
								Iterator<PcodeOp> iter = tmp.getIterator();
								while (iter.hasNext()) {
									PcodeOp n = iter.next();
									if (!caseLabel.containsKey(n.getSeqnum().getTarget()))
										continue;
									caseLabel.get(n.getSeqnum().getTarget()).addAll(labels);
								}
								
								for (int i = 0; i < tmp.getOutSize(); i++) {
									PcodeBlockBasic out = (PcodeBlockBasic)tmp.getOut(i);
									if (!visited.contains(out)) {
										queue.add(out);
										visited.add(out);
									}
								}
							}
						}
						
					}
//					System.out.println(caseLabel.toString());
					switchEdges.put(last, caseLabel);
					
				}
			}
		}

	}

	public void toDecompiledStmtDot(HighFunction hfunction, HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph,
			HashMap<Address, HashSet<Address>> cdgraph, HashSet<Address> entryEdges,
			HashMap<Varnode, HashSet<ClangLine>> entryDDEdgesLine, HashSet<ClangLine> entryCDEdgesLine,
			HashMap<ClangLine, HashSet<ClangLine>> cdEdgesLine, HashMap<ClangLine, HashSet<ClangLine>> ddEdgesLine) {
		HashMap<Varnode, HashSet<PcodeOp>> entryDDEdges = new HashMap<Varnode, HashSet<PcodeOp>>();
		HashSet<PcodeOp> entryCDEdges = new HashSet<PcodeOp>();
		HashMap<PcodeOp, HashSet<PcodeOp>> cdEdges = new HashMap<PcodeOp, HashSet<PcodeOp>>();
		for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); ++i) {
			if (hfunction.getFunctionPrototype().getParam(i).getHighVariable() == null)
				continue;
			Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
			Iterator<PcodeOp> desc = key.getDescendants();
			entryDDEdges.put(key, new HashSet<PcodeOp>());
			while (desc.hasNext()) {
				PcodeOp use = desc.next();
				entryDDEdges.get(key).add(use);
			}
		}

		for (Address cur : entryEdges) {
			Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
			while (itr.hasNext()) {
				PcodeOpAST pcode = itr.next();
				entryCDEdges.add(pcode);
			}
		}

		for (Address cur : cdgraph.keySet()) {
			Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
			PcodeOpAST last = null;
			while (itr.hasNext()) {
				last = itr.next();
			}
			if (last != null) {
				if (last.getOpcode() != 5) {
					continue;
				}
				cdEdges.put(last, new HashSet<PcodeOp>());
				for (Address dep : cdgraph.get(cur)) {
					Iterator<PcodeOpAST> itr2 = hfunction.getPcodeOps(dep);
					while (itr2.hasNext()) {
						PcodeOpAST pcode2 = itr2.next();
						cdEdges.get(last).add(pcode2);
					}
				}
			}
		}

		// merge nodes
		HashMap<PcodeOp, ClangLine> reverseMapping = new HashMap<PcodeOp, ClangLine>();
		for (ClangLine line : mapping.keySet()) {
			HashSet<PcodeOp> mergedNodes = mapping.get(line);
			for (PcodeOp n : mergedNodes) {
				reverseMapping.put(n, line);
			}
		}
		HashMap<Integer, ClangLine> linenumber = new HashMap<Integer, ClangLine>();
		for (ClangLine line : mapping.keySet()) {
			linenumber.put(line.getLineNumber(), line);
			HashSet<PcodeOp> mergedNodes = mapping.get(line);
			for (Varnode key : entryDDEdges.keySet()) {
				if (hasIntersection(mergedNodes, entryDDEdges.get(key))) {
					entryDDEdgesLine.get(key).add(line);
				}
			}
			if (hasIntersection(mergedNodes, entryCDEdges)) {
				entryCDEdgesLine.add(line);
			}
			cdEdgesLine.put(line, new HashSet<ClangLine>());
			ddEdgesLine.put(line, new HashSet<ClangLine>());
			for (PcodeOp n : mergedNodes) {
				if (cdEdges.containsKey(n)) {
					for (PcodeOp n2 : cdEdges.get(n))
						cdEdgesLine.get(line).add(reverseMapping.get(n2));
				}

				for (PcodeOp src : cdEdges.keySet()) {
					HashSet<PcodeOp> des = cdEdges.get(src);
					if (hasIntersection(des, mergedNodes)) {
						ClangLine srcLine = reverseMapping.get(src);
						if (!cdEdgesLine.containsKey(srcLine))
							cdEdgesLine.put(srcLine, new HashSet<ClangLine>());
						cdEdgesLine.get(srcLine).add(line);
					}
				}

				if (ddgraph.containsKey(n)) {
					for (PcodeOp n2 : ddgraph.get(n)) {
						ClangLine desLine = reverseMapping.get(n2);
						if (desLine != null && !line.equals(desLine)) {
							if (!ddEdgesLine.containsKey(desLine))
								ddEdgesLine.put(desLine, new HashSet<ClangLine>());
							ddEdgesLine.get(desLine).add(line);
						}
					}
				}

				for (PcodeOp src : ddgraph.keySet()) {
					// src is dependent on des
					HashSet<PcodeOp> des = ddgraph.get(src);
					if (hasIntersection(des, mergedNodes)) {
						ClangLine srcLine = reverseMapping.get(src);
						if (srcLine != null && srcLine.equals(line))
							continue;
						if (!ddEdgesLine.containsKey(line))
							ddEdgesLine.put(line, new HashSet<ClangLine>());
						ddEdgesLine.get(line).add(srcLine);
					}
				}
			}
		}
		for (int i : linenumber.keySet()) {
			if (linenumber.containsKey(i+1)) {
				if (!ddEdgesLine.containsKey(linenumber.get(i)))
					ddEdgesLine.put(linenumber.get(i), new HashSet<ClangLine>());
				ddEdgesLine.get(linenumber.get(i)).add(linenumber.get(i+1));
			}
		}
	}

	public boolean hasIntersection(HashSet<PcodeOp> s1, HashSet<PcodeOp> s2) {
		for (PcodeOp s : s1) {
			if (s2.contains(s))
				return true;
		}
		return false;
	}

	public void toDot(HashMap<ClangLine, HashSet<ClangLine>> ddgraph, HashMap<ClangLine, HashSet<ClangLine>> cdgraph,
			HashMap<Varnode, HashSet<ClangLine>> ddentryEdges, HashSet<ClangLine> cdentryEdges) {
		try {
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("g.dot")));
			out.write("digraph {");
			out.newLine();

			for (HashSet<ClangLine> cur : ddentryEdges.values()) {
				for (ClangLine c : cur) {
					out.write("\"" + "Entry" + "\" -> \"" + c.toString() + "\"");
					out.newLine();
				}
			}

			for (ClangLine cur : cdentryEdges) {
				out.write("\"" + "Entry" + "\" -> \"" + cur.toString() + "\"[style=dotted]");
				out.newLine();

			}
			for (ClangLine cur2 : ddgraph.keySet()) {
				for (ClangLine def : ddgraph.get(cur2)) {
					if (cur2 != null && def != null) {
						out.write("\"" + cur2.toString() + "\" -> \"" + def.toString() + "\"");
						out.newLine();
					}
				}
			}
			for (ClangLine cur2 : cdgraph.keySet()) {
				for (ClangLine def : cdgraph.get(cur2)) {
					if (cur2 != null && def != null) {
						out.write("\"" + cur2.toString() + "\" -> \"" + def.toString() + "\"[style=dotted]");
						out.newLine();
					}
				}
			}
			out.write("}");
			out.close();
		} catch (Exception e) {

		}
	}
	
	

	public void toDot(HighFunction hfunction, HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph,
			HashMap<Address, HashSet<Address>> cdgraph, HashSet<Address> entryEdges) {
		try {
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("g.dot")));
			out.write("digraph {");
			out.newLine();
			Language language = hfunction.getLanguage();
			for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); ++i) {
				Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
				Iterator<PcodeOp> desc = key.getDescendants();
				while (desc.hasNext()) {
					PcodeOp use = desc.next();
					out.write("\"" + "Entry" + "\" -> \"" + toString(use, language) + "\"");
					out.newLine();
				}
			}
			for (Address cur : entryEdges) {
				Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
				while (itr.hasNext()) {
					PcodeOpAST pcode = itr.next();
					out.write("\"" + "Entry" + "\" -> \"" + toString(pcode, language) + "\"[style=dotted]");
					out.newLine();
				}
			}
			for (PcodeOp cur2 : ddgraph.keySet()) {
				for (PcodeOp def : ddgraph.get(cur2)) {
					out.write("\"" + toString(def, language) + "\" -> \"" + toString(cur2, language) + "\"");
					out.newLine();
				}
			}
			for (Address cur : cdgraph.keySet()) {
				Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
				PcodeOpAST last = null;
				while (itr.hasNext()) {
					last = itr.next();
				}
				if (last != null) {
					if (last.getOpcode() != 5) {
						continue;
					}
					for (Address dep : cdgraph.get(cur)) {
						Iterator<PcodeOpAST> itr2 = hfunction.getPcodeOps(dep);
						while (itr2.hasNext()) {
							PcodeOpAST pcode2 = itr2.next();
							out.write("\"" + toString(last, language) + "\" -> \"" + toString(pcode2, language)
									+ "\"[style=dotted]");
							out.newLine();
						}
					}
				}
			}
			out.write("}");
			out.close();
		} catch (Exception ex) {
		}
	}
}

class PcodeBlockBasicEdge extends DefaultGEdge<PcodeBlockVertex> {

	public PcodeBlockBasicEdge(PcodeBlockVertex start, PcodeBlockVertex end) {
		super(start, end);
		// TODO Auto-generated constructor stub
	}

}

class PcodeBlockVertex {
	private final PcodeBlockBasic codeBlock;
	private final String name;

	/**
	 * Constructor.
	 * 
	 * @param codeBlock the code block for this vertex
	 */
	public PcodeBlockVertex(PcodeBlockBasic codeBlock, String name) {
		this.codeBlock = codeBlock;
		this.name = name;
	}

	/**
	 * A constructor that allows for the creation of dummy nodes. This is useful in
	 * graphs where multiple entry or exit points need to be parented by a single
	 * vertex.
	 * 
	 * @param name the name of this vertex
	 */
	public PcodeBlockVertex(String name) {
		this.codeBlock = null;
		this.name = name;
	}

	public PcodeBlockBasic getCodeBlock() {
		return codeBlock;
	}

	public String getName() {
		return name;
	}
}

class ControlDependencyRunner {
	private Program currentProgram;
	private TaskMonitor monitor;
	private BasicBlockModel bbm;
	private PcodeBlockVertex stopCB;
	HashSet<Address> entryEdges;
	Map<PcodeBlockBasic, PcodeBlockVertex> instanceMap;

	public ControlDependencyRunner(Program currentProgram, TaskMonitor monitor, BasicBlockModel bbm) {
		this.currentProgram = currentProgram;
		this.monitor = monitor;
		this.bbm = bbm;
	}

	public static <T> T getLastElement(Iterator<T> iterator) {
		T lastElement = null;
		while (iterator.hasNext()) {
			lastElement = iterator.next();
		}
		return lastElement;
	}

	public void generateCDG(ArrayList<PcodeBlockBasic> blocks, HashMap<Address, HashSet<Address>> graph, PcodeBlockBasic entry) {
		try {
			this.stopCB = new PcodeBlockVertex("STOP");
			this.entryEdges = new HashSet<Address>();
			this.instanceMap = new HashMap<PcodeBlockBasic, PcodeBlockVertex>();
			GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> rcfg = this.createReverseCFG(blocks);
			GDirectedGraph<PcodeBlockVertex, GEdge<PcodeBlockVertex>> postDominanceTree = GraphAlgorithms
					.findDominanceTree(rcfg, this.monitor);
			for (PcodeBlockBasicEdge edge : rcfg.getEdges()) {
				PcodeBlockVertex desBB = edge.getStart();
				PcodeBlockVertex srcBB = edge.getEnd();
				if (!GraphAlgorithms.findDominance(rcfg, desBB, this.monitor).contains(srcBB)) {
					Iterator<PcodeOp> iter = srcBB.getCodeBlock().getIterator();
					Address terminator = getLastElement(iter).getSeqnum().getTarget();
					this.addControlDepFromDominatedBlockToDominator(terminator, srcBB, desBB, postDominanceTree, graph);
				}
			}
			this.addControlDepFromDominatedBlockToEntry(this.instanceMap.get(entry), postDominanceTree);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	private PcodeBlockVertex containsAny(Collection<PcodeBlockVertex> srcBB, Collection<PcodeBlockVertex> desBB) {
		for (PcodeBlockVertex des : desBB) {
			if (srcBB.contains(des)) {
				return des;
			}
		}
		return null;
	}

	public void addControlDepFromDominatedBlockToEntry(PcodeBlockVertex entryBB,
			GDirectedGraph<PcodeBlockVertex, GEdge<PcodeBlockVertex>> postDominanceTree) {
		Collection<PcodeBlockVertex> dominatedBlock = new HashSet<PcodeBlockVertex>();
		dominatedBlock.add(entryBB);
		while (true) {
			Collection<PcodeBlockVertex> newDominatedBlock = new HashSet<PcodeBlockVertex>();
			for (PcodeBlockVertex pd : dominatedBlock) {
				if (pd == null)
					break;
				if (postDominanceTree.getPredecessors(pd) == null)
					newDominatedBlock.add(this.stopCB);
				else
					newDominatedBlock.addAll(postDominanceTree.getPredecessors(pd));
				PcodeBlockBasic block = pd.getCodeBlock();
				Iterator<PcodeOp> ins_iter = block.getIterator();
				while (ins_iter.hasNext()) {
					PcodeOp pcode = ins_iter.next();
					this.entryEdges.add(pcode.getSeqnum().getTarget());

				}
			}
			if (newDominatedBlock.contains(this.stopCB) || newDominatedBlock.isEmpty()) {
				break;
			}
			dominatedBlock = newDominatedBlock;
		}
	}

	public void addControlDepFromDominatedBlockToDominator(Address node, PcodeBlockVertex srcBB, PcodeBlockVertex desBB,
			GDirectedGraph<PcodeBlockVertex, GEdge<PcodeBlockVertex>> postDominanceTree,
			HashMap<Address, HashSet<Address>> graph) {
		Collection<PcodeBlockVertex> pdOfSrc = postDominanceTree.getPredecessors(srcBB);
		Collection<PcodeBlockVertex> dominatedBlock = new HashSet<PcodeBlockVertex>();
		dominatedBlock.add(desBB);
		PcodeBlockVertex nearestCommonDominator;
		// walk up along the Post Dominance Tree, start from desBB
		while (true) {
			Collection<PcodeBlockVertex> newDominatedBlock = new HashSet<PcodeBlockVertex>();
			for (PcodeBlockVertex pd : dominatedBlock) {
				newDominatedBlock.addAll(postDominanceTree.getPredecessors(pd));
				this.addControlDepFromNodeToBB(node, pd.getCodeBlock(), graph);
			}
			nearestCommonDominator = this.containsAny(pdOfSrc, newDominatedBlock);
			if (nearestCommonDominator != null) {
				break;
			}
			dominatedBlock = newDominatedBlock;
		}
		if (nearestCommonDominator.equals(srcBB)) {
			this.addControlDepFromNodeToBB(node, srcBB.getCodeBlock(), graph);
		}
	}

	public void addControlDepFromNodeToBB(Address node, PcodeBlockBasic block,
			HashMap<Address, HashSet<Address>> graph) {
		Iterator<PcodeOp> ins_iter = block.getIterator();
		if (!graph.containsKey(node)) {
			graph.put(node, new HashSet<Address>());
		}
		HashSet<Address> control = graph.get(node);
		while (ins_iter.hasNext()) {
			PcodeOp p = ins_iter.next();
			control.add(p.getSeqnum().getTarget());

		}
	}

	public void DFSUtil(GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> graph, PcodeBlockVertex vertex, HashSet<PcodeBlockVertex> visited)
    {
        visited.add(vertex);                         //mark the node as explored
        
        for (PcodeBlockVertex succ : graph.getSuccessors(vertex))  //iterate through the linked list and then propagate to the next few nodes
            {
                if (!visited.contains(succ))                    //only propagate to next nodes which haven't been explored
                {
                    DFSUtil(graph, succ, visited);
                }
            }  
    }

	protected GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> createReverseCFG(ArrayList<PcodeBlockBasic> blocks)
			throws CancelledException {
		GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> graph = GraphFactory.createDirectedGraph();

		PcodeBlockBasic block = null;
		while (!blocks.isEmpty()) {
			block = blocks.remove(0);
			PcodeBlockVertex fromVertex = this.instanceMap.get(block);
			if (fromVertex == null) {
				fromVertex = new PcodeBlockVertex(block, block.toString());
				this.instanceMap.put(block, fromVertex);
				graph.addVertex(fromVertex);
			}
			this.addEdgesForDestinations(graph, fromVertex, block, blocks);
		}
		if (block != null && !graph.containsVertex(this.stopCB))
			graph.addEdge(new PcodeBlockBasicEdge(this.stopCB, this.instanceMap.get(block)));

		HashSet<PcodeBlockVertex> visited = new HashSet<PcodeBlockVertex>();
		DFSUtil(graph, this.stopCB, visited);
		for (PcodeBlockVertex v : graph.getVertices()) {
			if (!visited.contains(v)) {
				graph.addEdge(new PcodeBlockBasicEdge(this.stopCB, v));
			}
		}
		return graph;
	}

	private void addEdgesForDestinations(GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> graph,
			PcodeBlockVertex fromVertex, PcodeBlockBasic sourceBlock, ArrayList<PcodeBlockBasic> blocks)
			throws CancelledException {
		boolean noDes = true;
		for (int i = 0; i < sourceBlock.getOutSize(); i++) {
			PcodeBlockBasic targetBlock = (PcodeBlockBasic) sourceBlock.getOut(i);
			if (targetBlock == null) {
				continue;
			}
//			Address start = targetBlock.getFirstStartAddress();
//			Symbol symbol = this.currentProgram.getSymbolTable().getPrimarySymbol(start);
//			if (symbol != null && !symbol.getName().startsWith("LAB_")) {
//				continue;
//			}
			PcodeBlockVertex targetVertex = this.instanceMap.get(targetBlock);
			if (targetVertex == null) {
				targetVertex = new PcodeBlockVertex(targetBlock, targetBlock.toString());
				this.instanceMap.put(targetBlock, targetVertex);
//				blocks.add(targetBlock);
			}
			if (!graph.containsVertex(targetVertex))
				graph.addVertex(targetVertex);
			if (targetVertex != fromVertex)
				noDes = false;
			if (graph.containsEdge(targetVertex, fromVertex)) {
				continue;
			}
			graph.addEdge(new PcodeBlockBasicEdge(targetVertex, fromVertex));
		}
		if (noDes) {
			graph.addEdge(new PcodeBlockBasicEdge(this.stopCB, fromVertex));
		}
	}
}
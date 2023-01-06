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

public class ConstructGraph extends GhidraScript {
	private DecompInterface decomplib;
	private HashMap<Varnode, Integer> nodeLabel;
	private int[] instCount;
	private HashMap<HighSymbol, HashSet<Varnode>> symbolMap;
	private HashSet<String> graph;
	private HashMap<Integer, String> pcodeOpMap;
	private Machine mstate;
	private ArrayList<Facts> factCollection;
	private HashMap<Varnode, ArrayList<Integer>> varNameStack;
	private HashMap<Varnode, Integer> nameCount;
	private BasicBlockModel bbm;
	private CodeBlockVertex stopCB;
	private HashSet<String> usedVarnode;
	HashSet<Address> entryEdges;
	Map<CodeBlock, CodeBlockVertex> instanceMap;
	HashMap<Varnode, HashSet<SequenceNumber>> collectedVarnodes;
	HashMap<CodeBlockVertex, HashMap<Varnode, ArrayList<Integer>>> phiNodeInserted;
	HashMap<SequenceNumber, ArrayList<Integer>> newNameID;

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
	
	protected GDirectedGraph<CodeBlockVertex, CodeBlockEdge> createCFG(CodeBlock entry)
			throws CancelledException {
		this.stopCB = new CodeBlockVertex("STOP");
		this.entryEdges = new HashSet<Address>();
		this.instanceMap = new HashMap<CodeBlock, CodeBlockVertex>();
		
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph = GraphFactory.createDirectedGraph();
		ArrayList<CodeBlock> blocks = new ArrayList<CodeBlock>();
		blocks.add(entry);
		while (!blocks.isEmpty()) {
			CodeBlock block = blocks.remove(0);
			CodeBlockVertex fromVertex = this.instanceMap.get(block);
			if (fromVertex == null) {
				fromVertex = new CodeBlockVertex(block);
				this.instanceMap.put(block, fromVertex);
				graph.addVertex(fromVertex);
			}
			this.addEdgesForDestinations(graph, fromVertex, block, blocks);
		}
		return graph;
	}

	private void addEdgesForDestinations(GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph,
			CodeBlockVertex fromVertex, CodeBlock sourceBlock, ArrayList<CodeBlock> blocks) throws CancelledException {
		CodeBlockReferenceIterator iterator = sourceBlock.getDestinations(this.monitor);
		boolean noDes = true;
		while (iterator.hasNext()) {
			this.monitor.checkCanceled();
			CodeBlockReference destination = iterator.next();
			CodeBlock targetBlock = this.getDestinationBlock(destination);
			if (targetBlock == null) {
				continue;
			}
			Address start = targetBlock.getFirstStartAddress();
			Symbol symbol = this.currentProgram.getSymbolTable().getPrimarySymbol(start);
			if (symbol != null && !symbol.getName().startsWith("LAB_")) {
				continue;
			}
			CodeBlockVertex targetVertex = this.instanceMap.get(targetBlock);
			if (targetVertex == null) {
				targetVertex = new CodeBlockVertex(targetBlock);
				this.instanceMap.put(targetBlock, targetVertex);
				blocks.add(targetBlock);
			}
			graph.addVertex(targetVertex);
			noDes = false;
			if (graph.containsEdge(fromVertex, targetVertex)) {
				continue;
			}
			graph.addEdge(new CodeBlockEdge(fromVertex, targetVertex));
		}
//		if (noDes) {
//			graph.addEdge(new CodeBlockEdge(fromVertex, this.stopCB));
//		}
	}

	private CodeBlock getDestinationBlock(CodeBlockReference destination) throws CancelledException {
		Address targetAddress = destination.getDestinationAddress();
		CodeBlock targetBlock = this.bbm.getFirstCodeBlockContaining(targetAddress, this.monitor);
		if (targetBlock == null) {
			return null;
		}
		return targetBlock;
	}

	
	private void getDominanceFrontier(GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg, HashMap<CodeBlockVertex, HashSet<CodeBlockVertex>> dFMap) {
		
		try {
			GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> dominanceTree = GraphAlgorithms.findDominanceTree(cfg, monitor);
			List<CodeBlockVertex> verticesInPostOrder = GraphAlgorithms.getVerticesInPostOrder(dominanceTree, GraphNavigator.topDownNavigator());
			for (CodeBlockVertex v : verticesInPostOrder) {
				dFMap.put(v, new HashSet<CodeBlockVertex>());
				for (CodeBlockVertex succ: cfg.getSuccessors(v)) {
					if (!dominanceTree.getPredecessors(succ).contains(v)) {
						dFMap.get(v).add(succ);
					}
				}
				
//				Collection<CodeBlockVertex> collection = new ArrayList<CodeBlockVertex>();
//				collection.add(v);
				
//				Set<CodeBlockVertex> children = GraphAlgorithms.getDescendants(dominanceTree, collection);
				for (CodeBlockVertex child: dominanceTree.getSuccessors(v)) {
					if (!dFMap.containsKey(child))
						continue;
					for (CodeBlockVertex dF : dFMap.get(child)) {
						if (!dominanceTree.getPredecessors(dF).contains(v)) {
							dFMap.get(v).add(dF);
						}
					}
				}
			}
			
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void placeMultiequals(HashMap<CodeBlockVertex, HashSet<CodeBlockVertex>> dFMap, GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg) {	
		for (Varnode v : collectedVarnodes.keySet()) {
			HashSet<CodeBlockVertex> hasAlready = new HashSet<CodeBlockVertex>();
			HashSet<CodeBlockVertex> everOnWorkList = new HashSet<CodeBlockVertex>();
			ArrayList<CodeBlockVertex> workList = new ArrayList<CodeBlockVertex>();
			for (SequenceNumber x : collectedVarnodes.get(v)) {
				CodeBlock targetBlock;
				try {
					targetBlock = this.bbm.getFirstCodeBlockContaining(x.getTarget(), this.monitor);
					CodeBlockVertex targetBlockV = this.instanceMap.get(targetBlock);
					everOnWorkList.add(targetBlockV);
					workList.add(targetBlockV);
				} catch (CancelledException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} // TODO: any replacement methods?
				
			}
			while (!workList.isEmpty()) {
				CodeBlockVertex x = workList.remove(0);
					
				for (CodeBlockVertex y: dFMap.get(x)){
					if (!hasAlready.contains(y)) {
						if (!phiNodeInserted.containsKey(y))
							phiNodeInserted.put(y, new HashMap<Varnode, ArrayList<Integer>>());
						phiNodeInserted.get(y).put(v, new ArrayList<Integer>(Collections.nCopies(cfg.getInEdges(y).size()+1, 0)));
						hasAlready.add(y);
						if (!everOnWorkList.contains(y)) {
							everOnWorkList.add(y);
							workList.add(y);
						}
					}
				}
				
			}
		}
	}
	
	private int genName(Varnode v) {
		if (!nameCount.containsKey(v))
			nameCount.put(v, 1);
		int i = nameCount.get(v);
		if (!varNameStack.containsKey(v))
			varNameStack.put(v, new ArrayList<Integer>());
		varNameStack.get(v).add(i);
		nameCount.put(v, i + 1);
		return i;
	}
	
	private void rename(CodeBlockVertex bb, GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg, HashSet<CodeBlockVertex> visited) {
		if (visited.contains(bb))
			return;
		visited.add(bb);
		if (phiNodeInserted.containsKey(bb)) {
			for (Varnode v : phiNodeInserted.get(bb).keySet()) {
				int i = genName(v);
				//set the output index of this phi node
				phiNodeInserted.get(bb).get(v).set(0, i);
			}
		}
		
		Iterator<Instruction> iter = currentProgram.getListing().getInstructions(bb.getCodeBlock(), true);
		ArrayList<Varnode> definedVars = new ArrayList<Varnode>();
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			PcodeOp[] rawPcode = inst.getPcode();
			for (PcodeOp p : rawPcode) {
				newNameID.put(p.getSeqnum(), new ArrayList<Integer>(Collections.nCopies(p.getNumInputs()+1, 0)));
				for (int i = 0 ; i < p.getNumInputs(); i++) {
					if (varNameStack.containsKey(p.getInput(i))) {
						ArrayList<Integer> stack = varNameStack.get(p.getInput(i));
						if (stack == null || stack.size() == 0)
							continue;
						int id = stack.get(stack.size()-1);
						newNameID.get(p.getSeqnum()).set(i+1, id);
					}
				}
				if (p.getOutput() != null) {
					int id = genName(p.getOutput());
					newNameID.get(p.getSeqnum()).set(0, id);
					definedVars.add(p.getOutput());
				}
			}
		}
		
		for (CodeBlockVertex succ : cfg.getSuccessors(bb)) {
			if (!phiNodeInserted.containsKey(succ))
				continue;
			Object[] pred = cfg.getPredecessors(succ).toArray();
			Arrays.sort(pred); //TODO: check whether we need to sort pred
			int id = -1;
			for (int j = 0 ; j < pred.length; j++) {
				if (pred[j].equals(bb)) {
					id = j+1;
					break;
				}
			}
			if (id==-1)
				continue;
			for (Varnode v : phiNodeInserted.get(succ).keySet()) {
				ArrayList<Integer> stack = varNameStack.get(v);
				if (stack == null || stack.size() == 0) {
					// this means the current path didn't redefine the variable v, so we want to use it's original name
//					phiNodeInserted.get(succ).get(v).set(id, 0);
					continue;
				}
				int i = stack.get(stack.size()-1);
				ArrayList<Integer> phinodeID = phiNodeInserted.get(succ).get(v);
				phinodeID.set(id, i);
			}
		}
		
		Collection<CodeBlockVertex> collection = new ArrayList<CodeBlockVertex>();
		collection.add(bb);
		
		Set<CodeBlockVertex> children = GraphAlgorithms.getDescendants(cfg, collection);
		for (CodeBlockVertex child: children) {
			rename(child, cfg, visited);
		}
		
		if (phiNodeInserted.containsKey(bb)) {
			for (Varnode v : phiNodeInserted.get(bb).keySet()) {
				varNameStack.get(v).remove(varNameStack.get(v).size()-1);
			}
		}
		
		for (Varnode v : definedVars) {
			varNameStack.get(v).remove(varNameStack.get(v).size()-1);
		}
	}
	
	/**
	 * The SSA transform algorithm is adopted from the following paper:
	 * Efficiently Computing Static Single Assignment Form and the Control Dependence Graph
	 * @param function
	 */
	private void transformSSA(Function function) {
		InstructionIterator iter = currentProgram.getListing().getInstructions(function.getBody(), true);
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			PcodeOp[] rawPcode = inst.getPcode();
			for (PcodeOp pcodeOp : rawPcode) {
				if (pcodeOp.getOutput() != null) {
					if (collectedVarnodes.containsKey(pcodeOp.getOutput())) {
						collectedVarnodes.get(pcodeOp.getOutput()).add(pcodeOp.getSeqnum());
					} else {
						collectedVarnodes.put(pcodeOp.getOutput(), new HashSet<SequenceNumber>());
						collectedVarnodes.get(pcodeOp.getOutput()).add(pcodeOp.getSeqnum());
					}
				}
			}
		}
		
		CodeBlock entryBlock;
		try {
			entryBlock = bbm.getFirstCodeBlockContaining(function.getEntryPoint(), this.monitor);
			GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg = createCFG(entryBlock);
			HashMap<CodeBlockVertex, HashSet<CodeBlockVertex>> dFMap = new HashMap<CodeBlockVertex, HashSet<CodeBlockVertex>>();
			getDominanceFrontier(cfg, dFMap);
			placeMultiequals(dFMap, cfg);
			HashSet<CodeBlockVertex> visited = new HashSet<CodeBlockVertex>();
			rename(this.instanceMap.get(entryBlock), cfg, visited);
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
	
	/**
	 * Recursive toplogical sort
	 * 
	 * @param bb
	 * @param v
	 * @param visited
	 * @param stack
	 */
	public void toplogicalSort(ArrayList<CodeBlock> bb, CodeBlock v, Boolean[] visited,
			ArrayList<CodeBlock> stack) {
		int vidx = bb.indexOf(v);
		visited[vidx] = true;

		CodeBlockReferenceIterator iter;
		try {
			iter = v.getDestinations(monitor);
			while (iter.hasNext()) {
				CodeBlock n = iter.next().getDestinationBlock();
				int dst_id = bb.indexOf(n);
				if (n != null && !visited[dst_id]) {
					toplogicalSort(bb, bb.get(dst_id), visited, stack);
				}
			}
			stack.add(0, v);
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private String toStackStr(Node n) {
		if (n.getLeft() == null || n.getRight() == null) {
			if (n.toString().contains("RSP") || n.toString().contains("RBP")) {
				return n.toString();
			} else {
				return null;
			}
		}
		if (n.getLeft().getOperation().equals("RSP") && n.getRight().isConstant()) {
			long offset = Node.parseLong(n.getRight().getOperation());
			if(offset < 0)
				return "A_Stack[" + "-0x" + Long.toHexString(-offset) + "]";
			else
				return "A_Stack[" + "0x" + Long.toHexString(offset) + "]";
		}
		return null;
	}
	
	private void findStackAlias(Function f) {
		CodeBlockIterator blocks; 
		try {
			String outputPath = currentProgram.getExecutablePath() + "_" + f.getName();
			BufferedWriter outBuf = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_fact.txt")));
			outBuf.close();
			blocks = this.bbm.getCodeBlocksContaining(f.getBody(), monitor);
			ArrayList<CodeBlock> bb = new ArrayList<CodeBlock>();
			while(blocks.hasNext()) {
				bb.add(blocks.next());
			}
			Boolean[] visited = new Boolean[bb.size()];
			Arrays.fill(visited, Boolean.FALSE);
			ArrayList<CodeBlock> stack = new ArrayList<CodeBlock>();
			for (int i = 0; i < bb.size(); i++) {
				if (!visited[i]) {
					toplogicalSort(bb, bb.get(i), visited, stack);
				}
			}

			Queue<CodeBlock> workList = new LinkedList<>();
			workList.addAll(stack);
			Language l = currentProgram.getLanguage();

			while (!workList.isEmpty() && !monitor.isCancelled()) {
				CodeBlock b = workList.remove();
				InstructionIterator iter = currentProgram.getListing().getInstructions(b, true);
				while (iter.hasNext()) {
					Instruction inst = iter.next();
					PcodeOp[] rawPcode = inst.getPcode();
					for (int i = 0; i < rawPcode.length; i++) {
						PcodeOp p = rawPcode[i];
						if (p.getOutput() != null) {
							String out = getUniqueName(0, l, p);
							Node input1;
							Node input2;
							String stackAddr = null;
							switch (p.getOpcode()) {
							case PcodeOp.COPY:
								input1 = mstate.getStackNode(getUniqueName(1, l, p), p.getInput(0));
								if (input1 != null) {
									mstate.setStackNode(out, input1);
									stackAddr = toStackStr(mstate.getStackNode(out, null));
								}
								break;
							case PcodeOp.INT_ADD:
								input1 = mstate.getStackNode(getUniqueName(1, l, p), p.getInput(0));
								input2 = mstate.getStackNode(getUniqueName(2, l, p), p.getInput(1));
								if (input1 != null && input2 != null) {
									mstate.setStackNode(out, input1.add(input2));
									stackAddr = toStackStr(mstate.getStackNode(out, null));
								}
								break;
							case PcodeOp.INT_SUB:
								input1 = mstate.getStackNode(getUniqueName(1, l, p), p.getInput(0));
								input2 = mstate.getStackNode(getUniqueName(2, l, p), p.getInput(1));
								if (input1 != null && input2 != null) {
									mstate.setStackNode(out, input1.sub(input2));
									stackAddr = toStackStr(mstate.getStackNode(out, null));
								}
								break;
							default:
							
							}
							if (stackAddr!=null) {
								printf(out + " points to " + stackAddr);
								outBuf = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_fact.txt", true)));
								outBuf.write("PointsTo(" + out + "," + stackAddr + ")");
								outBuf.newLine();
								outBuf.close();
							}
					
						}
						for (int j = 0; j < p.getNumInputs(); j++) {
							usedVarnode.add(getUniqueName(j+1, l, p));
						}
					}
				}
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public String toString(PcodeOp p, Language l) {
		String s;
		if (p.getOutput() != null)
			s = getUniqueName(0, l, p);
		else
			s = " --- ";
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
		s += " " + p.getSeqnum().toString();
		return s;
	}

	public void addSizeFacts(int[] vnode, int size, PcodeOp pcode) {
		int factType;
		switch (size) {
		case 64:
			factType = Facts.Reg64_t;
			break;
		case 32:
			factType = Facts.Reg32_t;
			break;
		case 16:
			factType = Facts.Reg16_t;
			break;
		case 8:
			factType = Facts.Reg8_t;
			break;
		default:
			factType = Facts.Reg1_t;
		}
		for (int v : vnode) {
			Varnode vn;
			if (v == 0)
				vn = pcode.getOutput();
			else
				vn = pcode.getInput(v-1);
			if (size == 32 && vn.isConstant()) {
				factType = Facts.Num32_t;
			}
			if (size == 64 && vn.isConstant()) {
				factType = Facts.Num64_t;
			}
			int[] vList = new int[] { v };
//			v.isConstant()
			factCollection.add(new Facts(factType, vList, pcode));
		}
	}

	public void extractFacts(PcodeOp pcodeOp) {
		printf(toString(pcodeOp, currentProgram.getLanguage()));
		
		// find dead code
		if (pcodeOp.getOutput() != null) {
			String outStr = getUniqueName(0, currentProgram.getLanguage(), pcodeOp);
			if (!usedVarnode.contains(outStr)) {
//				printf("skip " + toString(pcodeOp, currentProgram.getLanguage()));
				return;
			}
		}

		collectRegisters(pcodeOp);
		int[] v;
		Facts newFact;
		switch (pcodeOp.getOpcode()) {
		case PcodeOp.LOAD:
			v = new int[] { 2 };
			factCollection.add(new Facts(Facts.Pointer, v, pcodeOp));
			v = new int[] {2, 0};
			factCollection.add(new Facts(Facts.Load, v, pcodeOp));
			break;
		case PcodeOp.STORE:
			v = new int[] { 2 };
			factCollection.add(new Facts(Facts.Pointer, v, pcodeOp));
			v = new int[] {2, 3};
			factCollection.add(new Facts(Facts.Store, v, pcodeOp));
			break;
		case PcodeOp.INT_ADD:
		case PcodeOp.INT_SUB:
			v = new int[] {0, 1, 2 };
			factCollection.add(new Facts(Facts.Addition, v, pcodeOp));
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);

			} else if (pcodeOp.getInput(1).isConstant()) {
				int size = pcodeOp.getInput(1).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize3, v, pcodeOp));
			}
			break;
		case PcodeOp.INT_2COMP:
		case PcodeOp.INT_NEGATE:
		case PcodeOp.INT_XOR:
		case PcodeOp.INT_AND:
		case PcodeOp.INT_OR:
		case PcodeOp.INT_MULT:
		case PcodeOp.INT_DIV:
		case PcodeOp.INT_REM:
			v = new int[] {0, 1, 2 };
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;

				addSizeFacts(v, size, pcodeOp);

			} else if (pcodeOp.getInput(1).isConstant()) {
				int size = pcodeOp.getInput(1).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize3, v, pcodeOp));
			}
			break;
		case PcodeOp.FLOAT_ADD:
		case PcodeOp.FLOAT_SUB:
		case PcodeOp.FLOAT_MULT:
		case PcodeOp.FLOAT_DIV:
			v = new int[] {0, 1, 2 };
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else if (pcodeOp.getInput(1).isConstant()) {
				int size = pcodeOp.getInput(1).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize3, v, pcodeOp));
			}
			v = new int[] {1};
			factCollection.add(new Facts(Facts.FloatingPoint, v, pcodeOp));
			v = new int[] {2};
			factCollection.add(new Facts(Facts.FloatingPoint, v, pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.FloatingPoint, v, pcodeOp));
			break;
		case PcodeOp.FLOAT_NEG:
		case PcodeOp.FLOAT_ABS:
		case PcodeOp.FLOAT_SQRT:
		case PcodeOp.FLOAT_CEIL:
		case PcodeOp.FLOAT_FLOOR:
		case PcodeOp.FLOAT_ROUND:
			v = new int[] {0, 1};
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize2, v,  pcodeOp));
			}
			v = new int[] {1};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp));
			break;
		case PcodeOp.FLOAT_NAN:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			break;
		case PcodeOp.FLOAT_INT2FLOAT:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.IsSigned, v,  pcodeOp)); // not sure input0 should be integers or not
			v = new int[] {0};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp));
			break;
		case PcodeOp.FLOAT_FLOAT2FLOAT:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp)); // with different size
			break;
		case PcodeOp.FLOAT_TRUNC:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.FloatingPoint, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.IsSigned, v,  pcodeOp)); // not sure if it should be an integer or not
			break;
		case PcodeOp.COPY:
			v = new int[] {0, 1};
			newFact = new Facts(Facts.AssignStmt, v,  pcodeOp);
			factCollection.add(newFact);
			break;
		case PcodeOp.CBRANCH:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.Pointer, v,  pcodeOp));
			v = new int[] {2};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			break;
		case PcodeOp.BRANCHIND:
		case PcodeOp.BRANCH:
		case PcodeOp.CALLIND:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.Pointer, v,  pcodeOp));
			break;
		case PcodeOp.RETURN:
			v = new int[] {1};
			factCollection.add(new Facts(Facts.Pointer, v,  pcodeOp));
			// TODO: reasoning about the return varnode, and record it in order to perfrom
			// inter-procedural analysis
			break;
		case PcodeOp.CALL:
			Function f = this.currentProgram.getFunctionManager().getFunctionAt(pcodeOp.getInput(0).getAddress());

			if (f == null)
				break;
			if (f.isThunk()) {
				for (int i = 0; i < f.getParameters().length; i++) {
					String type = f.getParameter(i).getDataType().toString();
					// TODO: find arguments for this callsite, then assign types to the arguments
					// varnodes
					v = new int[] { mstate.registers[i] };
					newFact = new Facts(type, v,  mstate.pcode[i]);
					factCollection.add(newFact);
				}
			} else {
				// TODO: add facts that relates arguments type to callee function's arguments
				// type
			}
			break;
		case PcodeOp.INT_LESS:
		case PcodeOp.INT_LESSEQUAL:
			v = new int[] {1, 2};
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else if (pcodeOp.getInput(1).isConstant()) {
				int size = pcodeOp.getInput(1).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize2, v,  pcodeOp));
			}
			v = new int[] {1};
			factCollection.add(new Facts(Facts.Unsigned, v,  pcodeOp));
			v = new int[] {2};
			factCollection.add(new Facts(Facts.Unsigned, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			break;
		case PcodeOp.INT_SLESS:
		case PcodeOp.INT_SLESSEQUAL:
			v = new int[] {1, 2};
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else if (pcodeOp.getInput(1).isConstant()) {
				int size = pcodeOp.getInput(1).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize2, v,  pcodeOp));
			}
			v = new int[] {1};
			factCollection.add(new Facts(Facts.IsSigned, v,  pcodeOp));
			v = new int[] {2};
			factCollection.add(new Facts(Facts.IsSigned, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			break;
		case PcodeOp.INT_NOTEQUAL:
		case PcodeOp.INT_EQUAL:
		case PcodeOp.INT_SCARRY:
		case PcodeOp.INT_CARRY:
		case PcodeOp.INT_SBORROW:
		case PcodeOp.FLOAT_EQUAL:
		case PcodeOp.FLOAT_NOTEQUAL:
		case PcodeOp.FLOAT_LESS:
		case PcodeOp.FLOAT_LESSEQUAL:
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			v = new int[] {1, 2};
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else if (pcodeOp.getInput(1).isConstant()) {
				int size = pcodeOp.getInput(1).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize2, v,  pcodeOp));
			}
			break;
		case PcodeOp.INT_ZEXT:
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Unsigned, v,  pcodeOp));
			break;
		case PcodeOp.INT_SEXT:
			v = new int[] {0};
			factCollection.add(new Facts(Facts.IsSigned, v,  pcodeOp));
			break;
		case PcodeOp.INT_LEFT:
		case PcodeOp.INT_RIGHT:
			v = new int[] {0, 1};
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize2, v,  pcodeOp));
			}
			break;
		case PcodeOp.INT_SRIGHT:
		case PcodeOp.INT_SDIV:
		case PcodeOp.INT_SREM:
			v = new int[] {0, 1};
			if (pcodeOp.getInput(0).isConstant()) {
				int size = pcodeOp.getInput(0).getSize() * 8;
				addSizeFacts(v, size, pcodeOp);
			} else {
				factCollection.add(new Facts(Facts.EqualSize2, v,  pcodeOp));
			}
			v = new int[] {0};
			factCollection.add(new Facts(Facts.IsSigned, v,  pcodeOp));
			break;
		case PcodeOp.BOOL_AND:
		case PcodeOp.BOOL_OR:
		case PcodeOp.BOOL_NEGATE:
		case PcodeOp.BOOL_XOR:
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			v = new int[] {0};
			factCollection.add(new Facts(Facts.Reg1_t, v,  pcodeOp));
			break;
		default:
			break;
		}
	}

	public void collectRegisters(PcodeOp pcodeOp) {
		if (pcodeOp.getOutput() != null) {
			String register = pcodeOp.getOutput().toString(currentProgram.getLanguage());
			int index = -1;
			if (register.equals("RDI"))
				index = 0;
			else if (register.equals("RSI"))
				index = 1;
			else if (register.equals("RDX"))
				index = 2;
			else if (register.equals("RCX"))
				index = 3;
			else if (register.equals("R8"))
				index = 4;
			else if (register.equals("R9"))
				index = 5;
			if (index != -1) {
				mstate.registers[index] = 0;
				mstate.pcode[index] = pcodeOp;
			}
		}
		for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
			if (pcodeOp.getInput(i) != null) {
				String register = pcodeOp.getInput(i).toString(currentProgram.getLanguage());
				int index = -1;
				if (register.equals("RDI"))
					index = 0;
				else if (register.equals("RSI"))
					index = 1;
				else if (register.equals("RDX"))
					index = 2;
				else if (register.equals("RCX"))
					index = 3;
				else if (register.equals("R8"))
					index = 4;
				else if (register.equals("R9"))
					index = 5;
				if (index != -1) {
					mstate.registers[index] = i + 1;
					mstate.pcode[index] = pcodeOp;
				}
			}
		}
		
		for (int i = 0; i < mstate.registers.length; i++) {
			if (mstate.pcode[i] != null && mstate.initialPcode[i] == null) {
				mstate.initialRegisters[i] = mstate.registers[i];
				mstate.initialPcode[i] = pcodeOp;
			}
		}
	}

	public void constructKG(Function f) {
		InstructionIterator iter = currentProgram.getListing().getInstructions(f.getBody(), true);
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			PcodeOp[] rawPcode = inst.getPcode();
			for (PcodeOp p : rawPcode) {
				extractFacts(p);
			}
		}
	}
	
	public void printFunction(Function f) {
		try {
			CodeBlockIterator blocks = this.bbm.getCodeBlocksContaining(f.getBody(), monitor);
			while(blocks.hasNext()) {
				CodeBlock b = blocks.next();
				CodeBlockVertex bbv = this.instanceMap.get(b);
				printf(b.getName()+'\n');
				if (phiNodeInserted.containsKey(bbv)) {
					for (Varnode v : phiNodeInserted.get(bbv).keySet()) {
						ArrayList<Integer> ids = phiNodeInserted.get(bbv).get(v);
						String varname = toString(v, currentProgram.getLanguage());
						if (ids.get(0) != 0) {
							String factName = varname + "_" + String.valueOf(ids.get(0)) + " = Multiequal(";
							for (int i = 1; i < ids.size(); i++) {
								if (ids.get(i) != 0)
									factName += varname + "_" + String.valueOf(ids.get(i)) + ",";
								else
									factName += varname + ",";
							}
							factName = factName.substring(0, factName.length()-1) + ")";
							printf(factName + "\n");
						}
					}
				}
				InstructionIterator iter = currentProgram.getListing().getInstructions(b, true);
				while (iter.hasNext()) {
					Instruction inst = iter.next();
					PcodeOp[] rawPcode = inst.getPcode();
					for (PcodeOp p : rawPcode) {
						printf(toString(p, currentProgram.getLanguage()) + "\n");
					}
				}
			}
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	@Override
	protected void run() throws Exception {
		// TODO: Add script code here
		this.decomplib = setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			this.printf("Decompiler error: %s\n", new Object[] { this.decomplib.getLastMessage() });
			return;
		}

		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {

			if (!function.getName().equals("fact"))
				continue;

			graph = new HashSet<String>();
			nodeLabel = new HashMap<Varnode, Integer>();
			instCount = new int[PcodeOp.PCODE_MAX];
			pcodeOpMap = new HashMap<Integer, String>();
			bbm = new BasicBlockModel(currentProgram);
			factCollection = new ArrayList<Facts>();
			HighFunction hfunction = decompileFunction(function);
			mstate = new Machine(hfunction.getFunctionPrototype().getNumParams(),
					hfunction.getFunctionPrototype().hasNoReturn(), hfunction.getLanguage());
			collectedVarnodes = new HashMap<Varnode, HashSet<SequenceNumber>>();
			phiNodeInserted = new HashMap<CodeBlockVertex, HashMap<Varnode, ArrayList<Integer>>>();
			newNameID = new HashMap<SequenceNumber, ArrayList<Integer>>();
			varNameStack = new HashMap<Varnode, ArrayList<Integer>>();
			nameCount = new HashMap<Varnode, Integer>();
			usedVarnode = new HashSet<String>();

			
			transformSSA(function);
			findStackAlias(function);
			constructKG(function);
//			printFunction(function);
			toGraphFiles(function);

		}
	}
	
	public String toString(Varnode key, Language language) {
		if (key.isAddress() || key.isRegister()) {
			Register reg = language.getRegister(key.getAddress(), key.getSize());
			if (reg != null) {
				return reg.getName();
			}
		}
		if (key.isUnique()) {
			return "u_" + Long.toHexString(key.getOffset());
		}
		if (key.isConstant()) {
			
			return "Const_" + Long.toHexString(key.getOffset()) + "_" + String.valueOf(key.hashCode());
		}
		return "A_" + key.getAddress();
	}

	public String getUniqueName(int key, Language language, PcodeOp pcode) {
		Varnode v;
		if (key == 0)
			v = pcode.getOutput();
		else
			v = pcode.getInput(key-1);
		String varName = toString(v, language);
//		varName += '_' + String.valueOf(key.hashCode());
		if (newNameID.containsKey(pcode.getSeqnum())) {
			ArrayList<Integer> ids = newNameID.get(pcode.getSeqnum());
			if (key < ids.size() && ids.get(key) != 0)
				varName += '_' + String.valueOf(ids.get(key));
		}
		return varName;
	}

	public void toGraphFiles(Function function) {
		String outputPath = currentProgram.getExecutablePath() + "_" + function.getName();
		Language language = currentProgram.getLanguage();

		try {
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_query.txt")));
			HashSet<Varnode> args = new HashSet<Varnode>();
			// add query for parameters
			for (int i = 0; i < mstate.getParamNum(); ++i) {
				int key = mstate.initialRegisters[i];
				for (int j = Facts.IntVar; j <= Facts.Void; j++) {
					String factName = Facts.getFactName(j);
					out.write(factName + "(" + getUniqueName(key, language, mstate.initialPcode[i]) + ")");
					out.newLine();
				}
			}
			for (Variable v : function.getLocalVariables()) {
				Varnode key = v.getFirstStorageVarnode();
				for (int j = Facts.IntVar; j <= Facts.Void; j++) {
					String factName = Facts.getFactName(j);
					out.write(factName + "(" + toString(key, language) + ")");
					out.newLine();
				}
			}
			out.close();

			out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_fact.txt", true)));
			HashSet<String> facts = new HashSet<String>();
			for (Facts fact : factCollection) {
				String factName = Facts.getFactName(fact.getOpcode()) + "(";
				for (int i = 0; i < fact.getNumInputs(); i++) {
					factName += getUniqueName(fact.getInput(i), language, fact.getPcode());
					if (i != fact.getNumInputs() - 1)
						factName += ",";
				}
				factName += ")";
				facts.add(factName);
			}
			
			for (HashMap<Varnode, ArrayList<Integer>> multiequal : phiNodeInserted.values()) {
				for (Varnode v : multiequal.keySet()) {
					ArrayList<Integer> ids = multiequal.get(v);
					String varname = toString(v, language);
					if (ids.get(0) != 0) {
						String factName = "Multiequal(";
						for (int i = 0; i < ids.size(); i++) {
							if (ids.get(i) != 0)
								factName += varname + "_" + String.valueOf(ids.get(i)) + ",";
							else
								factName += varname + ",";
						}
						factName = factName.substring(0, factName.length()-1) + ")";
						facts.add(factName);
					}
				}
			}
			
			for (String factName : facts) {
				out.write(factName);
				out.newLine();
			}
			out.close();
		} catch (Exception exception) {
			exception.printStackTrace();
		}

	}
}

class Machine {
	public int[] registers;
	public int[] initialRegisters;
	public PcodeOp[] pcode;
	public PcodeOp[] initialPcode;
	private int paramNum;
	private Language language;
	private boolean hasNoReturn;
	private HashMap<String, Node> m_stack;

	public Machine(int paramNum, boolean hasNoReturn, Language l) {
		super();
		this.registers = new int[6];
		this.initialRegisters = new int[6];
		this.initialPcode = new PcodeOp[6];
		this.pcode = new PcodeOp[6];
		this.paramNum = paramNum;
		this.hasNoReturn = hasNoReturn;
		this.language = l;
		m_stack = new HashMap<String, Node>();
	}
	
	public Node getStackNode(String name, Varnode v) {

		if (name.equals("RSP"))
			return new Node(null, null, "RSP", v.getSize());
		if (name.equals("RBP"))
			return new Node(null, null, "RBP", v.getSize());
		if (v != null && v.isConstant()) {
			return new Node(null, null,
					String.valueOf(Node.parseLong((String) v.toString(this.language))),
					v.getSize());
		} else if (m_stack.containsKey(name)){
			return m_stack.get(name);
		}
		return null;
	}
	
	public void setStackNode(String name, Node n) {
		if (n != null)
			m_stack.put(name, n);
	}

	public void setParamNum(int paramNum) {
		this.paramNum = paramNum;
	}

	public int getParamNum() {
		return paramNum;
	}

	public void setReturn(boolean hasNoReturn) {
		this.hasNoReturn = hasNoReturn;
	}

}

class Facts {
	public static final int Access = 1;  // Access
	public static final int BaseAddr = 2;  //BaseAddr
	public static final int MemCopy = 3;   //MemCopy
	public static final int Addition = 4;  //Addition(variable, variable, variable)
	public static final int AssignStmt = 5; //AssignStmt(variable, variable) input->output
	public static final int GoToStmt = 6;  // GoToStmt(variable)
	public static final int EqualSize2 = 7; //EqualSize2(variable, variable)
	public static final int EqualSize3 = 8; //EqualSize3(variable, variable, variable)
	public static final int SubType = 9;    //SubType(variable, variable)
	public static final int IntVar = 10;    // IntVar(variable)
	public static final int UIntVar = 11;   // UIntVar(variable)
	public static final int LongVar = 12;   // LongVar(variable)
	public static final int ULongVar = 13;  // ULongVar(variable)
	public static final int ShortVar = 14;  // ShortVar(variable)
	public static final int UShortVar = 15; // UShortVar(variable)
	public static final int BoolVar = 16;   // BoolVar(variable)
	public static final int CharVar = 17;   // CharVar(variable)
	public static final int UCharVar = 18;  // UCharVar(variable)
	public static final int FloatVar = 19;  // FloatVar(variable)
	public static final int FloatingPoint = 20; // FloatingPoint(variable)
	public static final int DoubleVar = 21; // DoubleVar(variable)
	public static final int Pointer = 22;   // Pointer(variable)
	public static final int Void = 23;      // Void(variable)
	public static final int IsSigned = 24;  // IsSigned(variable)
	public static final int Unsigned = 25;  // Unsigned(variable)
	public static final int Reg64_t = 26;   // Reg64_t(variable)
	public static final int Reg32_t = 27;   // Reg32_t(variable)
	public static final int Reg16_t = 28;   // Reg16_t(variable)
	public static final int Reg8_t = 29;    // Reg8_t(variable)
	public static final int Reg1_t = 30;    // Reg1_t(variable)
	public static final int Num32_t = 31;   // Num32_t(variable)
	public static final int Num64_t = 32;   // Num64_t(variable)
	public static final int Load = 33;
	public static final int Store = 34;
	private int factOp;
	private int[] input;
	private PcodeOp pcode;
	
	/**
	Type Lattice (64bits):
	------ reg64_t
		|----num64_t
			|---- unsigned long
			|---- long
		|---- double
     |---- reg32_t
     	|---- num32_t
   			|---- int32_t (int)
			|---- uint32_t (uint)
		|---- ptr
		|---- code_t?
		|---- float
     |---- reg16_t
		|---- int16_t (short)
		|---- uint16_t (ushort)
     |---- reg8_t
		|---- int8_t (char)
		|---- uint8_t (uchar)
     |---- reg1_t (bool)

	
	Rules:
	1.0 !EqualSize3(v1, v2, v3) v EqualSize2(v1, v2)
	1.0 !EqualSize3(v1, v2, v3) v EqualSize2(v2, v3)
	1.0 !EqualSize3(v1, v2, v3) v EqualSize2(v1, v3)
	1.0 !EqualSize2(v1, v2) v EqualSize2(v2, v1)
	1.0 !EqualSize2(v1, v2) v !Reg64_t(v1) v Reg64_t(v2)
	1.0 !EqualSize2(v1, v2) v !Reg32_t(v1) v Reg32_t(v2)
	1.0 !EqualSize2(v1, v2) v !Reg16_t(v1) v Reg16_t(v2)
	1.0 !EqualSize2(v1, v2) v !Reg8_t(v1) v Reg8_t(v2)
	1.0 !EqualSize2(v1, v2) v !Reg1_t(v1) v Reg1_t(v2)
	
	1.0 !Reg1_t(v1) v BoolVar(v1)
	1.0 !Reg8_t(v1) v !IsSigned(v1) v CharVar(v1)
	1.0 !Reg8_t(v1) v !Unsigned(v1) v UCharVar(v1)
	1.0 !Reg16_t(v1) v !IsSigned(v1) v ShortVar(v1)
	1.0 !Reg16_t(v1) v !Unsigned(v1) v UShortVar(v1)
	1.0 !Reg32_t(v1) v !IsSigned(v1) v Pointer(v1) v IntVar(v1)
	1.0 !Reg32_t(v1) v !Unsigned(v1) v Pointer(v1) v UIntVar(v1)
	1.0 !Num32_t(v1) v !IsSigned(v1) v IntVar(v1)
	1.0 !Num32_t(v1) v !Unsigned(v1) v UIntVar(v1)
	1.0 !Reg32_t(v1) v !FloatingPoint(v1) v FloatVar(v1)
	1.0 !Reg64_t(v1) v !IsSigned(v1) v LongVar(v1)
	1.0 !Reg64_t(v1) v !Unsigned(v1) v ULongVar(v1)
	1.0 !Num64_t(v1) v !IsSigned(v1) v LongVar(v1)
	1.0 !Num64_t(v1) v !Unsigned(v1) v ULongVar(v1)
	1.0 !Reg64_t(v1) v !FloatingPoint(v1) v DoubleVar(v1)
	
	1.0 !BoolVar(v1) v Reg1_t(v1)
	1.0 !CharVar(v1) v IsSigned(v1)
	1.0 !CharVar(v1) v Reg8_t(v1)
	1.0 !UCharVar(v1) v Unsigned(v1)
	1.0 !UCharVar(v1) v Reg8_t(v1)
	1.0 !ShortVar(v1) v IsSigned(v1)
	1.0 !ShortVar(v1) v Reg16_t(v1)
	1.0 !UShortVar(v1) v Unsigned(v1)
	1.0 !UShortVar(v1) v Reg16_t(v1)
	1.0 !IntVar(v1) v Num32_t(v1)
	1.0 !UIntVar(v1) v Num32_t(v1)
	1.0 !IntVar(v1) v IsSigned(v1)
	1.0 !UIntVar(v1) v Unsigned(v1)
	1.0 !Num32_t(v1) v Reg32_t(v1)
	1.0 !Pointer(v1) v Reg32_t(v1)
	1.0 !FloatVar(v1) v FloatingPoint(v1)
	1.0 !FloatVar(v1) v Reg32_t(v1)
	1.0 !LongVar(v1) v Num64_t(v1)
	1.0 !LongVar(v1) v IsSigned(v1)
	1.0 !ULongVar(v1) v Num64_t(v1)
	1.0 !ULongVar(v1) v Unsigned(v1)
	1.0 !Num64_t(v1) v Reg64_t(v1)
	1.0 !DoubleVar(v1) v FloatingPoint(v1)
	1.0 !DoubleVar(v1) v Reg64_t(v1)
	
	1.0 !AssignStmt(v1, v2) v !BoolVar(v1) v BoolVar(v2)
	1.0 !AssignStmt(v1, v2) v !CharVar(v1) v CharVar(v2)
	1.0 !AssignStmt(v1, v2) v !UCharVar(v1) v UCharVar(v2)
	1.0 !AssignStmt(v1, v2) v !ShortVar(v1) v ShortVar(v2)
	1.0 !AssignStmt(v1, v2) v !UShortVar(v1) v UShortVar(v2)
	1.0 !AssignStmt(v1, v2) v !Pointer(v1) v Pointer(v2)
	1.0 !AssignStmt(v1, v2) v !FloatVar(v1) v FloatVar(v2)
	1.0 !AssignStmt(v1, v2) v !DoubleVar(v1) v DoubleVar(v2)
	1.0 !AssignStmt(v1, v2) v !IntVar(v1) v IntVar(v2)
	1.0 !AssignStmt(v1, v2) v !UIntVar(v1) v UIntVar(v2)
	1.0 !AssignStmt(v1, v2) v !Num32_t(v1) v Num32_t(v2)
	1.0 !AssignStmt(v1, v2) v !LongVar(v1) v LongVar(v2)
	1.0 !AssignStmt(v1, v2) v !ULongVar(v1) v ULongVar(v2)
	1.0 !AssignStmt(v1, v2) v !Num64_t(v1) v Num64_t(v2)
	
	1.0 !Addition(v1, v2, v3) v !IntVar(v1) v !Pointer(v2) v Pointer(v3)
	1.0 !Addition(v1, v2, v3) v !UIntVar(v1) v !Pointer(v2) v Pointer(v3)
	1.0 !Addition(v1, v2, v3) v !Num32_t(v1) v !Pointer(v2) v Pointer(v3)
	1.0 !Addition(v1, v2, v3) v !IntVar(v2) v !Pointer(v1) v Pointer(v3)
	1.0 !Addition(v1, v2, v3) v !UIntVar(v2) v !Pointer(v1) v Pointer(v3)
	1.0 !Addition(v1, v2, v3) v !Num32_t(v2) v !Pointer(v1) v Pointer(v3)
	1.0 !Addition(v1, v2, v3) v !IntVar(v1) v !IntVar(v2) v IntVar(v3)
	1.0 !Addition(v1, v2, v3) v !UIntVar(v1) v !UIntVar(v2) v UIntVar(v3)
	1.0 !Addition(v1, v2, v3) v !LongVar(v1) v !LongVar(v2) v LongVar(v3)
	1.0 !Addition(v1, v2, v3) v !ULongVar(v1) v !ULongVar(v2) v ULongVar(v3)
	 */

	public Facts(int factNum, int[] input, PcodeOp pcode) {
		this.factOp = factNum;
		this.input = input;
		this.pcode = pcode;
	}

	public Facts(String type, int[] input, PcodeOp pcode) {
		if (type.equals("int")) {
			this.factOp = IntVar;
		} else if (type.equals("unsigned int")) {
			this.factOp = UIntVar;
		} else if (type.equals("long")) {
			this.factOp = LongVar;
		} else if (type.equals("long unsigned int")) {
			this.factOp = ULongVar;
		} else if (type.equals("short")) {
			this.factOp = ShortVar;
		} else if (type.equals("short unsigned")) {
			this.factOp = UShortVar;
		} else if (type.equals("bool")) {
			this.factOp = BoolVar;
		} else if (type.equals("char")) {
			this.factOp = CharVar;
		} else if (type.equals("float")) {
			this.factOp = FloatVar;
		} else if (type.equals("double")) {
			this.factOp = DoubleVar;
		} else if (type.contains("typedef")) {

		} else if (type.contains("*")) {
			this.factOp = Pointer;
		}// TODO: other types
		this.input = input;
		this.pcode = pcode;
	}

	public final static String getFactName(int op) {
		switch (op) {
		case Access:
			return "Access";
		case BaseAddr:
			return "BaseAddr";
		case MemCopy:
			return "MemCopy";
		case Addition:
			return "Addition";
		case AssignStmt:
			return "AssignStmt";
		case GoToStmt:
			return "GoToStmt";
		case EqualSize2:
			return "EqualSize2";
		case EqualSize3:
			return "EqualSize3";
		case SubType:
			return "SubType";
		case IntVar:
			return "IntVar";
		case UIntVar:
			return "UIntVar";
		case LongVar:
			return "LongVar";
		case ULongVar:
			return "ULongVar";
		case ShortVar:
			return "ShortVar";
		case UShortVar:
			return "UShortVar";
		case BoolVar:
			return "BoolVar";
		case CharVar:
			return "CharVar";
		case UCharVar:
			return "UCharVar";
		case FloatVar:
			return "FloatVar";
		case FloatingPoint:
			return "FloatingPoint";
		case DoubleVar:
			return "DoubleVar";
		case Pointer:
			return "Pointer";
		case Void:
			return "Void";
		case IsSigned:
			return "IsSigned";
		case Unsigned:
			return "Unsigned";
		case Reg64_t:
			return "Reg64_t";
		case Reg32_t:
			return "Reg32_t";
		case Reg16_t:
			return "Reg16_t";
		case Reg8_t:
			return "Reg8_t";
		case Reg1_t:
			return "Reg1_t";
		case Num32_t:
			return "Num32_t";
		case Num64_t:
			return "Num64_t";
		case Load:
			return "Load";
		case Store:
			return "Store";
		default:
			return "INVALID_OP" + String.valueOf(op);

		}
	}

	/**
	 * @return pcode operation code
	 */
	public final int getOpcode() {
		return factOp;
	}
	
	public final PcodeOp getPcode() {
		return pcode;
	}

	/**
	 * @return number of input varnodes
	 */
	public final int getNumInputs() {
		if (input == null) {
			return 0;
		}
		return input.length;
	}

	/**
	 * @return get input varnodes
	 */
	public final int[] getInputs() {
		return input;
	}

	/**
	 * @param i the i'th input varnode
	 * @return the i'th input varnode
	 */
	public final int getInput(int i) {
		if (i >= input.length || i < 0) {
			return -1;
		}
		return input[i];
	}

}

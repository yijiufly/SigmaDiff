/*
 * SPDX-License-Identifier: Apache-1.1
 *
 * ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 1999-2003 The Apache Software Foundation.
 * Copyright (c) 2010 Dmitry Naumenko (dm.naumenko@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution, if
 *    any, must include the following acknowledgement:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgement may appear in the software itself,
 *    if and wherever such third-party acknowledgements normally appear.
 *
 * 4. The names "The Jakarta Project", "Commons", and "Apache Software
 *    Foundation" must not be used to endorse or promote products derived
 *    from this software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

package diffutils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;

import difflib.DiffUtils;

/**
 * class for ground truth collection
 * @author yueduan
 *
 */
public class gtc {
    
	// stores the identical and modified source files
	public static LinkedHashMap<String, String> identicalFiles = new LinkedHashMap<String, String>();
	public static LinkedHashMap<String, String> modifiedFiles = new LinkedHashMap<String, String>();
	
	
//	// stores all the modified CUs
//	private static LinkedList<String> modifiedCUs = new LinkedList<String>();
//	// stores all the identical CUs
//	private static LinkedList<String> identicalCUs = new LinkedList<String>();
	
	
	// extract snake information from Myer's algorithm
	public static LinkedList<Pair<Integer, Integer>> snakes = new LinkedList<Pair<Integer, Integer>>();
	
	
	// store potential mappings between source files of original and revised
	// <compile unit,  >
	private static LinkedHashMap<String, LinkedHashMap<Integer, LinkedList<Integer>>> mappings = 
			new LinkedHashMap<String, LinkedHashMap<Integer, LinkedList<Integer>>>();
	
	
	// mappings + snakes to infer the real mapping
	// <compile unit, pair<line in old, line in new> >
	private static LinkedHashMap<String, LinkedList<Pair<Integer, Integer>>> realMapping = 
			new LinkedHashMap<String, LinkedList<Pair<Integer, Integer>>>();
	
	
	// <compile unit, pair<debug_info_old, debug_info_new> >
	private static LinkedHashMap<String, Pair<LinkedHashMap<Integer, LinkedList<Long>>, LinkedHashMap<Integer, LinkedList<Long>>>> debug_info = 
			new LinkedHashMap<String, Pair<LinkedHashMap<Integer, LinkedList<Long>>, LinkedHashMap<Integer, LinkedList<Long>>>>();
	
	
//	private static LinkedHashMap<Long, LinkedList<Long>> addressMapping = new LinkedHashMap<Long, LinkedList<Long>>();

	static String ORIGINAL_DIR = "";
	static String REVISED_DIR = "";
	
	static String ORIGINAL = "";
	static String RIVISED = "";
	public static String CURRENT_CU = "";
	
	static String DIFF_FILE = "";

	
	static String OLD_DEBUG_INFO = "";
	static String NEW_DEBUG_INFO = "";
	
	
	static String output_file = "addrMapping";
	static String OUTPUT_PATH = "";
	
	final static String CU = "CU: ";
	
			
    public static void main(String[] args) {
    	if(args.length != 5) {
    		System.err.println("wrong arguments!");
    		System.err.println("Format: diffing_result_file original_debug_info revised_debug_info original_dir revised_dir");
    		return;
    	}
    	DIFF_FILE = args[0];
    	OLD_DEBUG_INFO = args[1];
    	NEW_DEBUG_INFO = args[2];
    	ORIGINAL_DIR = args[3];
    	REVISED_DIR = args[4];
    	
    	File directory = new File(".");
    	String BIN_DIR = directory.getAbsolutePath();
    	OUTPUT_PATH = BIN_DIR + "/../" + output_file;
    	
    	// parse the diffing result file to collect modified and 
    	parseDiffResult(DIFF_FILE);
 
    	// extract debug info from the two files
//    	extractDebugInfo(OLD_DEBUG_INFO, true);
//        extractDebugInfo(NEW_DEBUG_INFO, false);
        
    	
        // go through each modified file pair and use myers diffing algorithm to compare
        LinkedHashMap<String, String> allFiles = new LinkedHashMap<String, String>();
        allFiles.putAll(modifiedFiles);
        allFiles.putAll(identicalFiles);
        
    	for(String old: allFiles.keySet()) {
    		ORIGINAL = old;
    		RIVISED = allFiles.get(old);

    		CURRENT_CU = ORIGINAL.replace(ORIGINAL_DIR, "");
    		
            List<String> original = fileToLines(ORIGINAL);
            List<String> revised  = fileToLines(RIVISED);

            // Compute diff. Get the Patch object. Patch is the container for computed deltas.
//            Patch<String> patch = DiffUtils.diff(original, revised);
            DiffUtils.diff(original, revised);
            
            
//            for (Delta<String> delta: patch.getDeltas()) {
//                System.out.println(delta);
//            }
    	}
    	
    	
    	
    	
    	// extract the real line mapping between two programs
//        extractPreciseMapping();
        
        // based on the line mapping + address info, extract address mapping
        try {
			extractAddressMapping();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.err.println("Error during extracting and dumpping address mapping: " + e.getMessage());
		}
    }
    



	private static void parseDiffResult(String diffResult) {
		try {

			BufferedReader reader = new BufferedReader(new FileReader(diffResult));
			
			String line = "";
			while ((line = reader.readLine())!= null) {
				
				String oldFile = "";
				String newFile = "";
				boolean differ = line.endsWith("differ");
				boolean identical = line.endsWith(" are identical");
				
				if(differ || identical) {
					String[] strs = line.split(" ");
					for(String str: strs) {
						if(str.endsWith(".c") || str.endsWith(".cpp")) {
							if(oldFile.equals(""))
								oldFile = str;
							else
								newFile = str;
						}
					}
					
					if(!oldFile.isEmpty()) {
//						oldFile = oldFile.replace("/home/administrator/Downloads/Lian/PseudocodeDiffing/Dataset_for_BinDiff/diffutils/sources/", "/Users/JennyGao/Desktop/gtc/");
//						newFile = newFile.replace("/home/administrator/Downloads/Lian/PseudocodeDiffing/Dataset_for_BinDiff/diffutils/sources/", "/Users/JennyGao/Desktop/gtc/");
						if(differ) {
							modifiedFiles.put(oldFile, newFile);
						}
						else if(identical)
							identicalFiles.put(oldFile, newFile);
					}
				}// end if line endsWith "differ" or "identical"
			}
			reader.close();
		} catch (Exception e) {
			System.err.println("Error during parsing diff file: " + e.getMessage());
		}
	}
    




	private static void extractDebugInfo(String file, boolean orig) {
//		if(!debug_info.containsKey(sourceFileName))
//			debug_info.put(sourceFileName, new LinkedHashMap<Integer, LinkedList<Long>>());
		
//		LinkedHashMap<Integer, LinkedList<Long>> pairs = debug_info.get(sourceFileName);
		
		try {
			String line = "";
			BufferedReader br = new BufferedReader(new FileReader(file));

			String cuName = "";
			while ((line = br.readLine()) != null) {
				if(line.startsWith(CU)) {
					
					String[] strs = line.split(CU);
					int len = strs[1].length();
					cuName = strs[1].substring(0, len - 1);
					cuName = cuName.replaceAll("\\./", "");
					cuName = cuName.replaceAll("//", "/");
					processCU(cuName, br, orig);
				}
			}
			
			br.close();
		} catch (Exception e) {
			System.err.println("Error during reading the elf file: " + e.getMessage());
		}
	}
	
	
	/**
	 * For each CU in the debug_info file, we process the line number + address mapping information
	 * @param cuName: the given CU name
	 * @param br
	 * @param orig: true if the CU is in the original program. false if in the revised one
	 * @return
	 * @throws IOException
	 */
	static BufferedReader processCU(String cuName, BufferedReader br, boolean orig) throws IOException {		
		String[] strs = cuName.split("/");
		String fileName = strs[strs.length - 1];
		
		if(!debug_info.containsKey(cuName)) {
			LinkedHashMap<Integer, LinkedList<Long>> oldFileDebugInfo = new LinkedHashMap<Integer, LinkedList<Long>>();
			LinkedHashMap<Integer, LinkedList<Long>> newFileDebugInfo = new LinkedHashMap<Integer, LinkedList<Long>>();
			Pair<LinkedHashMap<Integer, LinkedList<Long>>, LinkedHashMap<Integer, LinkedList<Long>>> pair = 
					new Pair<LinkedHashMap<Integer, LinkedList<Long>>, LinkedHashMap<Integer, LinkedList<Long>>>(oldFileDebugInfo, newFileDebugInfo);
			debug_info.put(cuName, pair);
		}
		LinkedHashMap<Integer, LinkedList<Long>> debugInfo = orig ? debug_info.get(cuName).getFirst(): debug_info.get(cuName).getSecond();
		
		
		String line = "";
		while ((line = br.readLine()) != null) {
			
			// do not break directly, need to tolerate the case where there exists an empty line in the middle of a CU
			if(line.isEmpty()) {
				br.mark(1000);
				while(line != null && line.isEmpty()) {
					line = br.readLine();
				}
				if (line == null)
					break;
				if(line.startsWith(CU)) {
					br.reset();
					break;
				}
			}
				
			if(!line.startsWith(fileName))
				continue;

			strs = line.trim().split("\\s+");
			
			int lineNum = Integer.parseInt(strs[1]);
			long addr = Long.parseLong(strs[2].substring(2), 16);
			
			if(debugInfo.containsKey(lineNum)) {
				LinkedList<Long> prevAddrs = debugInfo.get(lineNum);
				if(!prevAddrs.contains(addr)) {
					prevAddrs.add(addr);
				}
			}
			else {
				LinkedList<Long> prevAddrs = new LinkedList<Long>();
				prevAddrs.add(addr);
				debugInfo.put(lineNum, prevAddrs);
			}
		}
		
		return br;
	}
    

	/**
     * Extract precise mapping between original and revised based on the mapping information and the snakes
     */
    private static void extractPreciseMapping() {
    	for(String cu: mappings.keySet()) {
    		
    		LinkedHashMap<Integer, LinkedList<Integer>> mapping = mappings.get(cu);
    		
    		for(int oldline : mapping.keySet()) {
        		Pair<Integer, Integer> snake = findNextSnake(oldline);
        		if(snake == null)
        			continue;
        		
        		int newline = snake.getSecond() - (snake.getFirst() - oldline);
        		LinkedList<Integer> list = mapping.get(oldline);
        		if(list.contains(newline)) {
        			if(!realMapping.containsKey(cu))
        				realMapping.put(cu, new LinkedList<Pair<Integer, Integer>>());
        			realMapping.get(cu).add(new Pair<Integer, Integer>(oldline, newline));
        		}
        	}
    	}

    	
    	
	}
    
    
    
	private static void extractAddressMapping() throws IOException {
		BufferedWriter writer = new BufferedWriter(new FileWriter(OUTPUT_PATH));
	    
	    
		for(String cu: mappings.keySet()) {
			
//			System.err.println("cu in realMapping: " + cu);
			
//			if(!debug_info.containsKey(cu)) {
//				System.err.println("\tno debug_info");
//				continue;
//			}
//			
//			LinkedHashMap<Integer, LinkedList<Long>> old_debug_info = debug_info.get(cu).getFirst();
//			LinkedHashMap<Integer, LinkedList<Long>> new_debug_info = debug_info.get(cu).getSecond();
//			
			for(Integer oldLine: mappings.get(cu).keySet()) {
				for (Integer newLine : mappings.get(cu).get(oldLine))
					writer.write("[" + cu + ":" + String.valueOf(oldLine) + "] [" + cu + ":" + String.valueOf(newLine) + "]\n");
			}
		}
		
		writer.close();
		
	}
	
	



	private static Pair<Integer, Integer> findNextSnake(int oldline) {
		Pair<Integer, Integer> curr = null;
		int currFirst = Integer.MAX_VALUE;
		
		for(Pair<Integer, Integer> pair : snakes) {
			if(oldline < pair.getFirst() && pair.getFirst() < currFirst) {
				curr = pair;
				currFirst = pair.getFirst();
			}
		}
		
		return curr;
	}



	/**
	 * Called by Myers algorithm to collect potential mapping information
	 * @param cu
	 * @param oldLine
	 * @param newLine
	 */
	public static void addMapping(String cu, int oldLine, int newLine) {
    	if(!mappings.containsKey(cu)) {
    		LinkedHashMap<Integer, LinkedList<Integer>> mapping = new LinkedHashMap<Integer, LinkedList<Integer>>();
    		mappings.put(cu, mapping);
    	}
    	if(!mappings.get(cu).containsKey(oldLine)) {
    		mappings.get(cu).put(oldLine, new LinkedList<Integer>());
    	}
    	LinkedList<Integer> list = mappings.get(cu).get(oldLine);
    	if(!list.contains(newLine))
    		list.add(newLine);
    }
    

    
    
    
    private static List<String> fileToLines(String filename) {
		List<String> lines = new LinkedList<String>();
		String line = "";
		BufferedReader in = null;
		try {
			in = new BufferedReader(new FileReader(filename));
			while ((line = in.readLine()) != null) {
				lines.add(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					// ignore ... any errors should already have been
					// reported via an IOException from the final flush.
				}
			}
		}
		return lines;
	}
}

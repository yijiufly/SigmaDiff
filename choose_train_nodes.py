from ast import dump
from operator import add, truediv
import os
import subprocess
import errno
import shutil
from collections import defaultdict

from numpy.lib.arraysetops import unique

def load_ast_nodes(file_path):
    node_features = dict()
    with open(file_path, "r") as f:
        lines = f.readlines()
    funcname = None
    func_features = None
    func_nodenames = None
    func_nodes = {}
    node_features_full = {}
    node_names_full = {}
    new_lines = []
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            funcname = line[1:]
            func_features = defaultdict(set)
            func_nodenames = defaultdict(set)
        else:
            features = line.split("|&|")
            if funcname not in func_nodes:
                func_nodes[funcname] = features[0]
            if features[3] != "null":
                if "@@" in features[3]:
                    seg = features[3].split("@@")
                    if seg[0] in ['BOOL_AND', 'BOOL_OR', 'FLOAT_EQUAL', 'FLOAT_NOTEQUAL', 'FLOAT_LESS', 'FLOAT_LESSEQUAL', 'INT_EQUAL', 'INT_NOTEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL', 'INT_LESS', 'INT_LESSEQUAL']:
                        features[3] = "CMP@@"+seg[1]
                func_features[features[3]].add(features[0])
            func_nodenames[features[1]].add(features[0])
            node_features_full[features[0]] = features[1:]

        node_features[funcname] = func_features
        node_names_full[funcname] = func_nodenames

    return node_features, func_nodes, node_features_full, node_names_full

def add_attr_ast_nodes(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()
    
    with open(file_path, "w") as f:
        for line in lines:
            if line.startswith("#"):
                f.write(line)
            else:
                line = line.strip()
                features = line.split("|&|")
                if features[3].find("@@") != -1:
                    seg = features[3].split("@@")
                    if seg[0] in ['BOOL_AND', 'BOOL_OR', 'FLOAT_EQUAL', 'FLOAT_NOTEQUAL', 'FLOAT_LESS', 'FLOAT_LESSEQUAL', 'INT_EQUAL', 'INT_NOTEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL', 'INT_LESS', 'INT_LESSEQUAL']:
                        features[3] = "CMP"
                    else:
                        features[3] = features[3].split("@@")[0]

                f.write("|&|".join(features) + '\n')


def parse_readelf_dump_file(dumpfile):
    with open(dumpfile, "r") as f:
        dumpinfo = f.readlines()
    addr2file = {}
    for line in dumpinfo:
        if len(line) < 62:
            continue
        filename = line[:44].strip()
        linenumber = line[44:60].strip()
        address = line[62:].strip()
        addr2file[address] = ":".join((filename, linenumber))

    return addr2file

def get_source_lines(bin_file, outputfile, node_features_full):
    addresses_query = []
    for nodeid in node_features_full:
        addresses = node_features_full[nodeid][-1].split("##")
        for addr in addresses:
            if len(addr) > 2 and addr != "null":
                addr = int(addr, 16) - 0x10000
                addresses_query.append(hex(addr)[2:])

    addr2file = outputDebugInfo(bin_file, outputfile, addresses_query)
    return addr2file


def outputDebugInfo(bin_file, output_file, addresses_query):
    f = open(output_file, 'w')
    f.close()

    for i in range((len(addresses_query) + 500 - 1) // 500):
        cmd = 'addr2line -e {} -a {}'.format(bin_file, " ".join(addresses_query[i * 500:(i + 1) * 500]))
        if not os.path.exists(os.path.dirname(output_file)):
            try:
                os.makedirs(os.path.dirname(output_file))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        with open(output_file, 'a') as debugInfo:
            p = subprocess.Popen(cmd, shell=True, stdout=debugInfo, close_fds=True)
            p.wait()
    
    with open(output_file, "r") as f:
        dumpinfo = f.readlines()
    addr2file = {}
    for i, addr in enumerate(addresses_query):
        file_info = dumpinfo[(i+1)*2-1]
        addr = int(addr, 16) + 0x10000
        addr2file[hex(addr)[2:]] = file_info.strip()

    return addr2file

def get_source_lines2(bin_file, outputfile, node_features_full):
    addresses_query = []
    for nodeid in node_features_full:
        addresses = node_features_full[nodeid][-1].split("##")
        for addr in addresses:
            if len(addr) > 2 and addr != "null":
                addr = addr.lstrip("0")
                addresses_query.append(addr)

    addr2file = outputDebugInfo2(bin_file, outputfile, addresses_query)
    return addr2file


def outputDebugInfo2(bin_file, output_file, addresses_query):
    f = open(output_file, 'w')
    f.close()

    for i in range((len(addresses_query) + 500 - 1) // 500):
        cmd = 'addr2line -e {} -a {}'.format(bin_file, " ".join(addresses_query[i * 500:(i + 1) * 500]))
        if not os.path.exists(os.path.dirname(output_file)):
            try:
                os.makedirs(os.path.dirname(output_file))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        with open(output_file, 'a') as debugInfo:
            p = subprocess.Popen(cmd, shell=True, stdout=debugInfo, close_fds=True)
            p.wait()
    
    with open(output_file, "r") as f:
        dumpinfo = f.readlines()
    addr2file = {}
    for i, addr in enumerate(addresses_query):
        file_info = dumpinfo[(i+1)*2-1]
        addr2file[addr] = file_info.strip()

    return addr2file



def filter_different_lines(map1, map2):
    keys1 = [k for k in map1.keys() if map1[k] in set(map1.values())-set(map2.values())]
    keys2 = [k for k in map2.keys() if map2[k] in set(map2.values())-set(map1.values())]
    [map1.pop(k) for k in keys1]
    [map2.pop(k) for k in keys2]

def load_edges(file):
    with open(file, "r") as f:
        lines = f.readlines()
    graph = defaultdict(set)
    graph_reverse = defaultdict(set)
    for line in lines:
        line = line.strip()
        src, des, type = line.split(", ")
        if type == '1':
            graph[src].add(des)
            graph_reverse[des].add(src)

    return graph, graph_reverse

def add_training_nodes(file1, node_features_full1, file2, node_features_full2, matched_pair):
    g1, gr1 = load_edges(file1)
    g2, gr2 = load_edges(file2)
    added_pairs = []
    for n1, n2 in matched_pair:
        parent1 = gr1[n1]
        parent2 = gr2[n2]
        if len(parent1) == 1 and len(parent2) == 1:
            parent1 = list(parent1)[0]
            parent2 = list(parent2)[0]
            if node_features_full1[parent1][1] == "ClangStatement" and node_features_full2[parent2][1] == "ClangStatement":
                added_pairs.append((parent1, parent2))

    return added_pairs

def merge(dict1, dict2):
    for key in dict2.keys():
        dict1[key].update(dict2[key])


def test_two_binaries():
    bin_name = "chown"
    bin_dir1 = '/home/yijiufly/Downloads/projects/PseudocodeDiffing/Dataset_for_BinDiff/coreutils/binaries/coreutils-5.93-O1/'
    bin_dir2 = '/home/yijiufly/Downloads/projects/PseudocodeDiffing/Dataset_for_BinDiff/coreutils/binaries/coreutils-5.93-O2/'
    # bin_name = "xargs"
    # bin_dir1 = "/home/yijiufly/Downloads/projects/PseudocodeDiffing/Dataset_for_BinDiff/findutils/binaries/findutils-4.233-O1/"
    # bin_dir2 = "/home/yijiufly/Downloads/projects/PseudocodeDiffing/Dataset_for_BinDiff/findutils/binaries/findutils-4.233-O2/"
    node_file1 = "/home/yijiufly/" + bin_name + "-O1/" + bin_name + "_stripped_nodelabel.txt"
    node_file2 = "/home/yijiufly/" + bin_name + "-O2/" + bin_name + "_stripped_nodelabel.txt"
    edge_file1 = "/home/yijiufly/" + bin_name + "-O1/" + bin_name + "_stripped_edges.txt"
    edge_file2 = "/home/yijiufly/" + bin_name + "-O2/" + bin_name + "_stripped_edges.txt"
    shutil.copy(node_file1, "training/" + bin_name + "/O1_nodelabel.txt")
    shutil.copy(node_file2, "training/" + bin_name + "/O2_nodelabel.txt")
    shutil.copy(edge_file1, "training/" + bin_name + "/O1_edges.txt")
    shutil.copy(edge_file2, "training/" + bin_name + "/O2_edges.txt")
    shutil.copy("matched_functions.txt", "training/" + bin_name + "/matched_functions.txt")
    shutil.copy("/home/yijiufly/" + bin_name + "-O1/" + bin_name + "_stripped_corpus.txt", "training/" + bin_name + "/O1_corpus.txt")
    shutil.copy("/home/yijiufly/" + bin_name + "-O2/" + bin_name + "_stripped_corpus.txt", "training/" + bin_name + "/O2_corpus.txt")
    
    select_training_node(node_file1, node_file2, "matched_functions.txt", "training/" + bin_name + "/training_nodes.txt", '/home/yijiufly/' + bin_name + '-O1/debug_info', '/home/yijiufly/' + bin_name + '-O2/debug_info', "training/" + bin_name + "/O1_nodelabel.txt", "training/" + bin_name + "/O2_nodelabel.txt", os.path.join(bin_dir1, bin_name), os.path.join(bin_dir2, bin_name))

def add_func_summary(nodefile_path, callgraph_path, edge_path, node_features_full):
    edges = []
    with open(nodefile_path, "r") as f:
        lines = f.readlines()
    funcname = None
    func_summary = {}
    lastline = lines[-1].split("|&|")[0]
    count_id = len(node_features_full)
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            funcname = line[1:]
            func_summary[funcname] = count_id
            count_id += 1
        else:
            features = line.split("|&|")
            edges.append((func_summary[funcname], features[0]))

    with open(nodefile_path, "a") as f:
        for func in func_summary:
            f.write(str(func_summary[func]) + "|&|" + func + "|&|FunctionSummary|&|null|&|null\n")

    with open(callgraph_path, "r") as f:
        lines = f.readlines()
    

    with open(edge_path, "w") as f:
        for l in lines:
            src = l.split(", ")[0]
            des = l[len(src)+2:].strip()
            if src == des:
                continue
            if src in func_summary.keys() and des in func_summary.keys():
                f.write(str(func_summary[src]) + ", " + str(func_summary[des]) + "\n")

        for src, des in edges:
            f.write(str(src) + ", " + str(des) + "\n")

    return func_summary



def select_training_node(node_file1, node_file2, matched_functions, training_node_path, node_file_new1, node_file_new2, callgraph_path1, edge_path1, callgraph_path2, edge_path2):
    node_features1, func_nodes1, node_features_full1, node_names_full1 = load_ast_nodes(node_file1)
    node_features2, func_nodes2, node_features_full2, node_names_full2 = load_ast_nodes(node_file2)

    with open(matched_functions, "r") as f:
        func_list = f.readlines()
        matched1 = set()
        matched2 = set()
        for func_pair in func_list:
            func1 = func_pair.split(" ")[0]
            func2 = func_pair.split(" ")[1].strip()
            matched1.add(func1)
            matched2.add(func2)
    
    # func_summary1 = add_func_summary(node_file_new1, callgraph_path1, edge_path1, node_features_full1)
    # func_summary2 = add_func_summary(node_file_new2, callgraph_path2, edge_path2, node_features_full2)
    with open(training_node_path, "w") as f:
        matched_pair = []
        for func_pair in func_list:
            func1 = func_pair.split(" ")[0]
            func2 = func_pair.split(" ")[1].strip()
            if func1 in func_nodes1 and func2 in func_nodes2:
                f.write(func_nodes1[func1] + " " + func_nodes2[func2] + "\n")
            else:
                continue
            # if func1 in func_summary1 and func2 in func_summary2:
            #     f.write(str(func_summary1[func1]) + " " + str(func_summary2[func2]) + "\n")
            # node text that are unique
            features1 = node_names_full1[func1]
            features2 = node_names_full2[func2]
            unique1 = set([i for i in features1.keys() if len(features1[i]) == 1])
            unique2 = set([i for i in features2.keys() if len(features2[i]) == 1])

            for feat in unique1.intersection(unique2):
                # f.write(list(features1[feat])[0] + " " + list(features2[feat])[0] + "\n")
                matched_pair.append((list(features1[feat])[0], list(features2[feat])[0]))

            # vsa values that are unique
            if func1 not in node_features1 or func2 not in node_features2:
                continue
            features1 = node_features1[func1]
            features2 = node_features2[func2]
            unique1 = set([i for i in features1.keys() if len(features1[i]) == 1])
            unique2 = set([i for i in features2.keys() if len(features2[i]) == 1])

            for feat in unique1.intersection(unique2):
                # f.write(list(features1[feat])[0] + " " + list(features2[feat])[0] + "\n")
                matched_pair.append((list(features1[feat])[0], list(features2[feat])[0]))
        
        matched_result = defaultdict(set)
        for pair in matched_pair:
            i, j  = pair
            matched_result[i].add(j)

        for i in matched_result:
            if len(matched_result[i])==1:
                f.write(i + " " + list(matched_result[i])[0] + "\n")

        print(len(set(matched_pair)) / len(node_features_full1.keys()))

    add_attr_ast_nodes(node_file_new1)
    add_attr_ast_nodes(node_file_new2)

def process_two_files(output1, output2, compare_out):
    filename1 = output1.split('/')[-1].split('_')[-1]
    filename2 = output2.split('/')[-1].split('_')[-1]
    node_file1 = os.path.join(output1, filename1+"_nodelabel.txt")
    node_file2 = os.path.join(output2, filename2+"_nodelabel.txt")
    edge_file1 = os.path.join(output1, filename1+"_edges.txt")
    edge_file2 = os.path.join(output2, filename2+"_edges.txt")
    corpus_file1 = os.path.join(output1, filename1+"_corpus.txt")
    corpus_file2 = os.path.join(output2, filename2+"_corpus.txt")
    callgraph_path1 = os.path.join(output1, "callgraph.txt")
    callgraph_path2 = os.path.join(output2, "callgraph.txt")
    matched_functions = os.path.join(compare_out, "matched_functions.txt")
    training_node_path = os.path.join(compare_out, "training_nodes.txt")
    filename1 = output1.split('/')[-1]
    filename2 = output2.split('/')[-1]
    node_file_new1 = os.path.join(compare_out, filename1 + "_nodelabel.txt")
    node_file_new2 = os.path.join(compare_out, filename2 + "_nodelabel.txt")
    edge_file_new1 = os.path.join(compare_out, filename1 + "_edges.txt")
    edge_file_new2 = os.path.join(compare_out, filename2 + "_edges.txt")
    corpus_file_new1 = os.path.join(compare_out, filename1 + "_corpus.txt")
    corpus_file_new2 = os.path.join(compare_out, filename2 + "_corpus.txt")
    edge_path1 = os.path.join(compare_out, filename1 + "_callgraphedges.txt")
    edge_path2 = os.path.join(compare_out, filename2 + "_callgraphedges.txt")

    shutil.copy(node_file1, node_file_new1)
    shutil.copy(node_file2, node_file_new2)
    shutil.copy(edge_file1, edge_file_new1)
    shutil.copy(edge_file2, edge_file_new2)
    shutil.copy(corpus_file1, corpus_file_new1)
    shutil.copy(corpus_file2, corpus_file_new2)
    select_training_node(node_file1, node_file2, matched_functions, training_node_path, node_file_new1, node_file_new2, callgraph_path1, edge_path1, callgraph_path2, edge_path2)

if __name__ == "__main__":
    binary_group = 'coreutils'
    path = 'Dataset_for_BinDiff/' + binary_group + '/output_others/'
    bindir = 'Dataset_for_BinDiff/' + binary_group + '/binaries_'
    ver = ['2.8', '3.1', '3.4', '3.6']
    opt = ['O3']
    versions_all = [['clang', 'x86']]
    # for v in ver:
    #     for o in opt[:-1]:
    #         versions_all.append(['-'.join([binary_group, v, o]), '-'.join([binary_group, v, opt[-1]])])
    
    
    # for o in opt:
    #     for v in ver[:-1]:
    #         versions_all.append(['-'.join([binary_group, v, o]), '-'.join([binary_group, ver[-1], o])])
    # versions = ['coreutils-5.93-O2', 'coreutils-6.4-O2']
    for versions in versions_all:
        for i, v1 in enumerate(versions):
            for j, v2 in enumerate(versions):
                if not os.path.exists(os.path.join(path, v1 + "_vs_" + v2)):
                    continue
                for binary in os.listdir(os.path.join(path, v1 + "_vs_" + v2)):
                    # if binary != "xargs":
                    #     continue
                    currentdir = os.path.join(path, v1 + "_vs_" + v2, binary)
                    node_file1 = os.path.join(path, v1, binary+"_stripped", binary+"_stripped_nodelabel.txt")
                    node_file2 = os.path.join(path, v2, binary+"_stripped", binary+"_stripped_nodelabel.txt")
                    edge_file1 = os.path.join(path, v1, binary+"_stripped", binary+"_stripped_edges.txt")
                    edge_file2 = os.path.join(path, v2, binary+"_stripped", binary+"_stripped_edges.txt")
                    corpus_file1 = os.path.join(path, v1, binary+"_stripped", binary+"_stripped_corpus.txt")
                    corpus_file2 = os.path.join(path, v2, binary+"_stripped", binary+"_stripped_corpus.txt")
                    callgraph_path1 = os.path.join(path, v1, binary+"_stripped", "callgraph.txt")
                    callgraph_path2 = os.path.join(path, v2, binary+"_stripped", "callgraph.txt")
                    matched_functions = os.path.join(currentdir, "matched_functions.txt")
                    training_node_path = os.path.join(currentdir, "training_nodes.txt")
                    debug_info1 = os.path.join(path, v1, binary+"_stripped", binary+"_debuginfo.txt")
                    debug_info2 = os.path.join(path, v2, binary+"_stripped", binary+"_debuginfo.txt")
                    node_file_new1 = os.path.join(currentdir, v1 + "_" + binary + "_nodelabel.txt")
                    node_file_new2 = os.path.join(currentdir, v2 + "_" + binary + "_nodelabel.txt")
                    edge_file_new1 = os.path.join(currentdir, v1 + "_" + binary + "_edges.txt")
                    edge_file_new2 = os.path.join(currentdir, v2 + "_" + binary + "_edges.txt")
                    corpus_file_new1 = os.path.join(currentdir, v1 + "_" + binary + "_corpus.txt")
                    corpus_file_new2 = os.path.join(currentdir, v2 + "_" + binary + "_corpus.txt")
                    edge_path1 = os.path.join(currentdir, v1 + "_" + binary + "_callgraphedges.txt")
                    edge_path2 = os.path.join(currentdir, v2 + "_" + binary + "_callgraphedges.txt")
                    bin_path1 = os.path.join(bindir+v1, v1, binary)
                    bin_path2 = os.path.join(bindir+v2, v2, binary)

                    shutil.copy(node_file1, node_file_new1)
                    shutil.copy(node_file2, node_file_new2)
                    shutil.copy(edge_file1, edge_file_new1)
                    shutil.copy(edge_file2, edge_file_new2)
                    shutil.copy(corpus_file1, corpus_file_new1)
                    shutil.copy(corpus_file2, corpus_file_new2)
                    print(binary, v1, v2)
                    select_training_node(node_file1, node_file2, matched_functions, training_node_path, debug_info1, debug_info2, node_file_new1, node_file_new2, bin_path1, bin_path2, callgraph_path1, edge_path1, callgraph_path2, edge_path2)
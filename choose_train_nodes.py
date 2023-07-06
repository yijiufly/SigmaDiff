from ast import dump
from operator import add, truediv
import os
import subprocess
import errno
import shutil
from collections import defaultdict

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


def add_attr_ast_nodes(file_path, addrmap):
    node_features = dict()
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
                if features[-1] != "null":
                    addr_set = [a for a in features[-1].split("##") if a !=""]
                    src_line_set = set()
                    for addr in addr_set:
                        addr = addr.lstrip("0")
                        if not addrmap is None and addr in addrmap:
                            if addrmap[addr].startswith("??") or addrmap[addr].endswith("?"):
                                continue
                            if addrmap[addr].split("/")[-2] == '.':
                                src_line = "/".join([addrmap[addr].split("/")[-3],addrmap[addr].split("/")[-1]])
                            else:
                                src_line = "/".join(addrmap[addr].split("/")[-2:])
                            if src_line.endswith(")"):
                                ind = src_line.rfind("(")
                                src_line = src_line[:ind-1]
                            src_line_set.add(src_line)
                        else:
                            continue
                    if len(src_line_set) == 0:
                        features.append("null")
                        f.write("|&|".join(features) + '\n')
                    else:
                        features.append("##".join(src_line_set))
                        f.write("|&|".join(features) + '\n')
                else:
                    f.write(line + '|&|null\n')


def get_base_address(bin_path):
    cmd = "readelf -l " + bin_path + " | grep LOAD"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    base = str(out).split()[3]
    return int(base, 16)


def get_source_lines(bin_file, outputfile, node_features_full):
    offset = get_base_address(bin_file)
    addresses_query = []
    for nodeid in node_features_full:
        addresses = node_features_full[nodeid][-1].split("##")
        for addr in addresses:
            if len(addr) > 2 and addr != "null":
                addr = int(addr, 16) + offset
                addresses_query.append(hex(addr)[2:])

    addr2file = outputDebugInfo(bin_file, outputfile, addresses_query, offset)
    return addr2file


def outputDebugInfo(bin_file, output_file, addresses_query, offset):
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
        addr = int(addr, 16) - offset  # need to substract the offset added when query addr2line
        addr2file[hex(addr)[2:]] = file_info.strip()

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


def select_training_node(node_file1, node_file2, matched_functions, training_node_path, node_file_new1, node_file_new2, bin_path1, bin_path2, debug_info1, debug_info2, with_gt):
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
    
    with open(training_node_path, "w") as f:
        matched_pair = []
        for func_pair in func_list:
            func1 = func_pair.split(" ")[0]
            func2 = func_pair.split(" ")[1].strip()
            if func1 in func_nodes1 and func2 in func_nodes2:
                f.write(func_nodes1[func1] + " " + func_nodes2[func2] + "\n")
            else:
                continue

            # node text that are unique
            features1 = node_names_full1[func1]
            features2 = node_names_full2[func2]
            unique1 = set([i for i in features1.keys() if len(features1[i]) == 1])
            unique2 = set([i for i in features2.keys() if len(features2[i]) == 1])

            for feat in unique1.intersection(unique2):
                matched_pair.append((list(features1[feat])[0], list(features2[feat])[0]))

            # vsa values that are unique
            if func1 not in node_features1 or func2 not in node_features2:
                continue
            features1 = node_features1[func1]
            features2 = node_features2[func2]
            unique1 = set([i for i in features1.keys() if len(features1[i]) == 1])
            unique2 = set([i for i in features2.keys() if len(features2[i]) == 1])

            for feat in unique1.intersection(unique2):
                matched_pair.append((list(features1[feat])[0], list(features2[feat])[0]))
        
        matched_result = defaultdict(set)
        for pair in matched_pair:
            i, j  = pair
            matched_result[i].add(j)

        for i in matched_result:
            if len(matched_result[i])==1:
                f.write(i + " " + list(matched_result[i])[0] + "\n")

        print(len(set(matched_pair)) / len(node_features_full1.keys()))

    if with_gt:
        map1 = get_source_lines(bin_path1, debug_info1, node_features_full1)
        map2 = get_source_lines(bin_path2, debug_info2, node_features_full2)
        add_attr_ast_nodes(node_file_new1, map1)
        add_attr_ast_nodes(node_file_new2, map2)
    else:
        add_attr_ast_nodes(node_file_new1, None)
        add_attr_ast_nodes(node_file_new2, None)


def process_two_files(bin_path1, bin_path2, output1, output2, compare_out, with_gt):
    filename1 = output1.split('/')[-1].split('_')[-1]
    filename2 = output2.split('/')[-1].split('_')[-1]
    node_file1 = os.path.join(output1, filename1+"_nodelabel.txt")
    node_file2 = os.path.join(output2, filename2+"_nodelabel.txt")
    edge_file1 = os.path.join(output1, filename1+"_edges.txt")
    edge_file2 = os.path.join(output2, filename2+"_edges.txt")
    corpus_file1 = os.path.join(output1, filename1+"_corpus.txt")
    corpus_file2 = os.path.join(output2, filename2+"_corpus.txt")
    debug_info1 = os.path.join(output1, filename1+"_debuginfo.txt")
    debug_info2 = os.path.join(output2, filename2+"_debuginfo.txt")
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

    shutil.copy(node_file1, node_file_new1)
    shutil.copy(node_file2, node_file_new2)
    shutil.copy(edge_file1, edge_file_new1)
    shutil.copy(edge_file2, edge_file_new2)
    shutil.copy(corpus_file1, corpus_file_new1)
    shutil.copy(corpus_file2, corpus_file_new2)
    if with_gt:
        bin_path1 = bin_path1[:-8] # get rid of the stripped suffix
        bin_path2 = bin_path2[:-8]
    select_training_node(node_file1, node_file2, matched_functions, training_node_path, node_file_new1, node_file_new2, bin_path1, bin_path2, debug_info1, debug_info2, with_gt)


from collections import defaultdict
import collections
import shutil
import os
import numpy as np
import re
import traceback
import subprocess
import errno

def load_nodelabel(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()
    addrs = {}
    nodelines = {}
    funcname = None
    func_features = defaultdict(set)
    node2func = dict()
    addr2file = defaultdict(set)
    func_nodes = {}
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            funcname = line[1:] 
        else:
            features = line.split("|&|")
            addrs[features[0]] = features[-2]
            nodelines[features[0]] = features[1:]
            func_features[funcname].add(features[0])
            node2func[features[0]] = funcname
            if features[-2] != 'null' and features[-1] != 'null':
                addr = features[-2][:-2]
                addr2file[addr].add(features[-1])

    return addrs, nodelines, addr2file

def getIndex(ranges, a):
    r = [i for i,r in enumerate(ranges) if np.logical_and(a>=r[0], a<r[1])]    
    return r[0] if r else -1

def getIndex2(bb_ranges, a):
    for i, lst in enumerate(bb_ranges):
        if a in lst:
            return i
    return -1

def get_base_address(bin_path):
    cmd = "readelf -l " + bin_path + " | grep LOAD"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    base = str(out).split()[3]
    return int(base, 16)


def calculate_tokens_in_bb(bb_list, start, end, nodelabelpath, offset=0):
    address1, nodelines1, addr2file = load_nodelabel(nodelabelpath)
    addr2tokennum = defaultdict(int)
    for k, a in address1.items():
        if a == 'null':
            continue
        if offset == 0:
            a = int(a[2:], 16)
            a = hex(a)
        token = nodelines1[k][-2].split('@*@')
        addr2tokennum[a] += len(token)//2

    return addr2tokennum, addr2file


def readNodeInfo(node2addr_file):
    bb_list = defaultdict(list)
    # read the instructions and address
    with open(node2addr_file) as f:
        lines = f.readlines()
        for idx, line in enumerate(lines):
            if idx == 0:
                node_in_bin1, node_in_bin2 = int(line.split()[0]), int(line.split()[1])
            elif idx % 3 == 2:
                bb_addr_vec = []
                bb_op_vec = []
                line_vec = re.findall('<(.*?)>', line)
                bb_op_vec.append(int(lines[idx-1][:-2]))
                bb_addr_vec.append(int(lines[idx-1][:-2]))
                id = int(lines[idx-1][:-2])

                for ins in line_vec:
                    bb_op_vec.append(ins.split()[1])
                    # need to match the base address of the image for ghidra and angr
                    i = int(ins.split()[-1], 16)# - 4194304
                    bb_addr_vec.append(hex(i))
                    bb_list[str(id)].append(hex(i))

    return node_in_bin1, node_in_bin2, bb_list


def evaluate_dbd_token(output_dir, binary_name, node_file1, node_file2, addrMap):
    nodeidx = output_dir + "/nodeIndexToCode"
    result = output_dir + "/log_" + binary_name
    if not os.path.exists(result):
        return None, None, 0, 0, 0
    with open(result, "r") as f:
        match = f.readlines()
        match_result = None
        for i, line in enumerate(match):
            if line.startswith("matched pairs:"):
                match_result = match[i+1].strip().replace("[", "")
        
        if match_result is None:
            return [None]*5
        node_in_bin1, node_in_bin2, bb_list = readNodeInfo(nodeidx)
        match = match_result.replace("]", "").split(", ")
        match = np.array(match).reshape(-1, 2)
        
        addr2tokennum1, addr2file1 = calculate_tokens_in_bb(bb_list, 0, node_in_bin1, node_file1)
        addr2tokennum2, addr2file2 = calculate_tokens_in_bb(bb_list, node_in_bin1, node_in_bin1 + node_in_bin2, node_file2)

        srclines_set2 = set()
        for id in range(node_in_bin1, node_in_bin1 + node_in_bin2):
            if len(bb_list[str(id)]) == 0:
                continue
            src_line2 = addr2file2[bb_list[str(id)][0]]
            if src_line2.startswith("??") or src_line2.endswith("?"):
                continue
            srclines_set2.add(src_line2)

        for addr in addr2tokennum2:
            src_line2 = addr2file2[addr]
            if src_line2.startswith("??") or src_line2.endswith("?"):
                continue
            srclines_set2.add(src_line2)

        tp_set = set()
        fp_set = set()
        tp = 0
        fp = 0
        total_set = set()
        total_token = 0
        not_found = set()
        for id1, id2 in match:
            if bb_list[id1][0] not in addr2file1 or bb_list[id2][0] not in addr2file2:
                continue
            
            file1 = addr2file1[bb_list[id1][0]]
            file2 = addr2file2[bb_list[id2][0]]
            if file1.startswith("??") or file1.endswith("?"):
                continue
            if file2.startswith("??") or file2.endswith("?"):
                continue
            src_line1 = file1
            src_line2 = file2
            
            if addrMap is None:
                if src_line1 not in srclines_set2:
                    continue
                if src_line1 == src_line2:
                    tp_set.update(set(bb_list[id1]))
                else:
                    fp_set.update(set(bb_list[id1]))
            else:
                if src_line1 not in addrMap:
                    continue
                elif src_line2 in addrMap[src_line1]:
                    tp_set.update(set(bb_list[id1]))
                else:
                    fp_set.update(set(bb_list[id1]))

        for addr in tp_set:
            if addr in fp_set:
                continue
            if addr == 'null' or addr not in addr2file1:
                continue
            file1 = addr2file1[addr]
            if file1.startswith("??") or file1.endswith("?"):
                continue
            src_line1 = file1
            if addrMap is None:
                if src_line1 not in srclines_set2:
                    continue
            else:
                if src_line1 not in addrMap:
                    continue
            tp += addr2tokennum1[addr]

        for addr in fp_set:
            if addr == 'null' or addr not in addr2file1:
                continue
            file1 = addr2file1[addr]
            if file1.startswith("??") or file1.endswith("?"):
                continue
            src_line1 = file1
            if addrMap is None:
                if src_line1 not in srclines_set2:
                    continue
            else:
                if src_line1 not in addrMap:
                    continue
            fp += addr2tokennum1[addr]

        
        for addr in addr2tokennum1:
            if addr == 'null' or addr not in addr2file1:
                continue
            file1 = addr2file1[addr]
            if file1.startswith("??") or file1.endswith("?"):
                continue
            src_line1 = file1
            if addrMap is None:
                if src_line1 not in srclines_set2:
                    continue
            else:
                if src_line1 not in addrMap:
                    continue
            total_token += addr2tokennum1[addr]
            total_set.add(addr)

        prec = tp/(tp+fp)
        recall = tp/total_token
        f1 = 2*prec*recall/(prec+recall)
        print(binary_name, v1, v2, tp, fp, total_token, prec, recall, f1)

        return addr2file1, addr2file2, prec, recall, f1


if __name__ == "__main__":
    dbd_outdir = "DeepBinDiff_out"
    binary_name = 'basenamestripped'
    v1 = 'coreutils-5.93-O0'
    v2 = 'coreutils-5.93-O3'
    sigmadiff_outdir = 'out'
    comp_folder = v1 + "_vs_"+ v2
    dbd_out = os.path.join(dbd_outdir, comp_folder, binary_name)
    node_file_new1 = os.path.join(sigmadiff_outdir, v1 + "_vs_" + v2, v1 + "_nodelabel.txt")
    node_file_new2 = os.path.join(sigmadiff_outdir, v1 + "_vs_" + v2, v2 + "_nodelabel.txt")
    evaluate_dbd_token(dbd_out, binary_name, node_file_new1, node_file_new2, None)
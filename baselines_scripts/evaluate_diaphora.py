import os
import sys
import difflib
import re
import shutil
from collections import defaultdict

def load_nodelabel(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()
    groundtruth = {}
    nodetokens = {}
    funcname = None
    func_features = defaultdict(set)
    func_tokens = {}
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            if not funcname is None:
                nodetokens[funcname] = func_tokens
            funcname = line[1:]
            func_tokens = {}
        else:
            features = line.split("|&|")
            groundtruth[features[0]] = features[-1]
            toklst = features[-3].split('@*@')
            if features[-1] == "null":
                continue
            for i in range(0, len(toklst), 2):
                if i + 1 < len(toklst):
                    line_num, col_num = toklst[i].split(':')
                    length = len(toklst[i+1])
                    func_tokens[(line_num, col_num, str(int(col_num) + length))] = features[-1]

            func_features[funcname].add(features[0])
        nodetokens[funcname] = func_tokens
    return groundtruth, nodetokens, func_features

def read_decompiled_lines(path, filename):
    with open(path, 'r') as f:
        lines = f.readlines()
    filted_lines = []

    if lines[0].startswith("#include"):
        i = 1
        for line in lines[3:]:
            line = line.strip()
            filted_lines.append(line)
    else:
        for i, line in enumerate(lines):
            idx = line.find(': ')
            filted_lines.append(line[idx+1:].strip())
    return filted_lines


def get_matched_token(ltxt, rtxt, col_begin, col_end):
    added_or_deleted_index = []
    added_or_deleted_index_right = []
    changed_index_left = []
    changed_index_right = []
    changed_index = []
    changed_index_r = []
    # find the index of added or deleted code ranges for ltxt and rtxt
    for m in re.finditer('\x00\+.*?\x01', ltxt):
        added_or_deleted_index.extend(list(range(m.start(0), m.end(0))))
    
    for m in re.finditer('\x00\-.*?\x01', ltxt):
        added_or_deleted_index.extend(list(range(m.start(0), m.end(0))))

    for m in re.finditer('\x00\+.*?\x01', rtxt):
        added_or_deleted_index_right.extend(list(range(m.start(0), m.end(0))))
    
    for m in re.finditer('\x00\-.*?\x01', rtxt):
        added_or_deleted_index_right.extend(list(range(m.start(0), m.end(0))))

    for m in re.finditer('\x00\^.*?\x01', ltxt):
        changed_index_left.append(list(range(m.start(0), m.end(0))))
        changed_index.extend(list(range(m.start(0), m.end(0))))

    for m in re.finditer('\x00\^.*?\x01', rtxt):
        changed_index_right.append(list(range(m.start(0), m.end(0))))
        changed_index_r.extend(list(range(m.start(0), m.end(0))))

    # get the mappings of changed index from ltxt to rtxt, assume the first token in ltxt changes maps to the first in rtxt changes,
    # the rest tokens in ltxt changes map to the last token in rtxt changes, since the lengths could be different
    changed_match = {}
    for i, l in enumerate(changed_index_left):
        r = changed_index_right[i]
        changed_match[l[0]] = r[0]
        for j in l[1:]:
            changed_match[j] = r[-2]


    # if it's add or delete, no match
    # if it's the same or changed item, return the match col_begin and end
    # here we ignore the attribute tokens, and get a mapping between index in ltxt and real index
    # real_index_map_reverse maps from real_index to index in ltxt
    real_index_map = {}
    real_index_map_reverse = {}
    real_index = 0
    for i, c in enumerate(ltxt):
        real_index_map[i] = real_index
        real_index_map_reverse[real_index] = i
        if ltxt[i:i+2] == '\x00+' or ltxt[i:i+2] == '\x00-' or ltxt[i:i+2] == '\x00^' or c == '\x01':
            continue
        elif i>0 and (ltxt[i-1:i+1] == '\x00+' or ltxt[i-1:i+1] == '\x00-' or ltxt[i-1:i+1] == '\x00^'):
            continue
        real_index += 1

    # do the same thing on rtxt
    real_index_map_right = {}
    real_index_map_reverse_right = {}
    real_index = 0
    for i, c in enumerate(rtxt):
        real_index_map_right[i] = real_index
        real_index_map_reverse_right[real_index] = i # last i that matched to real_index
        if rtxt[i:i+2] == '\x00+' or rtxt[i:i+2] == '\x00-' or rtxt[i:i+2] == '\x00^' or c == '\x01':
            continue
        elif i>0 and (rtxt[i-1:i+1] == '\x00+' or rtxt[i-1:i+1] == '\x00-' or rtxt[i-1:i+1] == '\x00^'):
            continue
        real_index += 1

    # col_begin is a real_index
    if col_begin not in real_index_map_reverse:
        return -1, -1
    
    # all tokens are added or deleted means it has no match
    for i in range(col_begin, col_end):
        if real_index_map_reverse[i] not in added_or_deleted_index:
            break
        elif i == col_end - 1:
            return None, None

    # get matching index
    match_results = dict()
    j = 0
    for i, c in enumerate(ltxt):
        if i in added_or_deleted_index:
            continue
        if i in changed_index:
            while j in changed_index_r:
                j += 1
            while i in changed_index:
                i += 1
            continue
        while j in added_or_deleted_index_right:
            j += 1
        if j >= len(rtxt):
            j = len(rtxt)-1
        match_results[i] = j
        j += 1

    # get the matching index for col_begin and col_end
    ret_col_begin = None
    ret_col_end = None
    if real_index_map_reverse[col_begin] in match_results:
        ret_col_begin = match_results[real_index_map_reverse[col_begin]]
    elif real_index_map_reverse[col_begin] in changed_match:
        ret_col_begin = changed_match[real_index_map_reverse[col_begin]]
    else:
        return None, None

    if col_end > len(real_index_map_reverse):
        col_end = len(real_index_map_reverse)
    if real_index_map_reverse[col_end-1] in match_results:
        ret_col_end = match_results[real_index_map_reverse[col_end-1]]
    elif real_index_map_reverse[col_end-1] in changed_match:
        ret_col_end = changed_match[real_index_map_reverse[col_end-1]]
    else:
        return None, None
    
    return str(real_index_map_right[ret_col_begin]), str(real_index_map_right[ret_col_end]+1)


def filter_out_some_tokens(nodetokens1, nodetokens2):
    ground_truth_set = set([nodetokens2[func][key] for func in nodetokens2 for key in nodetokens2[func]])
    newnodetokens = dict()
    for func in nodetokens1:
        tokens = dict()
        for key in nodetokens1[func]:
            if nodetokens1[func][key] in ground_truth_set:
                tokens[key]=nodetokens1[func][key]
        newnodetokens[func]=tokens
    return newnodetokens

def addr2funcname(path):
    f=open(path, 'r')
    addr2funcname = {}
    for line in f.readlines():
        a, b = line.split(', ')
        addr = '00' + hex(int(a))[2:]
        addr2funcname[addr] = b.strip()

    return addr2funcname

def evaluate_token_level(v1, v2, binname, output_sigmadiff, output_diaphora):
    result_file = binname + '_' + v1 + '_vs_' + v2 + '.csv'
    if not os.path.exists(os.path.join(output_diaphora, result_file)):
        return
    v1 += '_' + binname
    v2 += '_' + binname
    folder1 = os.path.join(output_sigmadiff, v1, 'decompiled')
    folder2 = os.path.join(output_sigmadiff, v2, 'decompiled')
    addr2funcname_stripped1 = os.path.join(output_sigmadiff, v1, 'addr2funcname_stripped.txt')
    addr2funcname_stripped2 = os.path.join(output_sigmadiff, v2, 'addr2funcname_stripped.txt')
    addr2funcname1 = addr2funcname(addr2funcname_stripped1)
    addr2funcname2 = addr2funcname(addr2funcname_stripped2)
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return
    
    node_file_new1 = os.path.join(output_sigmadiff, v1 + "_vs_" + v2, v1 + "_nodelabel.txt")
    node_file_new2 = os.path.join(output_sigmadiff, v1 + "_vs_" + v2, v2 + "_nodelabel.txt")
    try:
        groundtruth1, nodetokens1, func_features1 = load_nodelabel(node_file_new1)
        groundtruth2, nodetokens2, func_features2 = load_nodelabel(node_file_new2)
    except:
        return
        
    # filter out tokens that don't have a matching
    nodetokens1 = filter_out_some_tokens(nodetokens1, nodetokens2)

    # load diaphora results
    with open(os.path.join(output_diaphora, result_file), 'r') as f:
        lines = f.readlines()

    tp = 0
    fp = 0
    fn = 0
    matched_funcs = set()
    funcs_not_found = set()
    for line in lines:
        line = line.strip()
        func1, func2 = line.split(', ')

        # need to check the base address of the image and make them match
        # because the base address of ghidra and ida pro may be different
        func1 = '00' + hex(int(func1, 16) + 0x100000)[2:]
        func2 = '00' + hex(int(func2, 16) + 0x100000)[2:]

        if func1 not in addr2funcname1:
            funcs_not_found.add('FUN_' + func1)
            continue
        func1 = addr2funcname1[func1]
        
        if func1 + '.c'not in os.listdir(folder1):
            funcs_not_found.add(func1)

        if func2 not in addr2funcname2:
            continue
        func2 = addr2funcname2[func2]
        if func1.endswith('thunk') or func2.endswith('thunk'):
            continue
        if func1 + '.c' in os.listdir(folder1) and func2 + '.c' in os.listdir(folder2):
            decompiled1 = read_decompiled_lines(os.path.join(folder1, func1 + '.c'), func1)
            decompiled2 = read_decompiled_lines(os.path.join(folder2, func2 + '.c'), func2)
            matched_results_l = {}
            matched_results_r = {}
            match_lines = {}
            # get the diffing results (the same algorithm as diaphora)
            for left, right, changed in difflib._mdiff(decompiled1, decompiled2):
                lno, ltxt = left
                rno, rtxt = right
                matched_results_l[lno] = ltxt
                matched_results_r[rno] = rtxt
                match_lines[lno] = rno

            if func1 not in nodetokens1 or func2 not in nodetokens2:
                continue
            tokens1 = nodetokens1[func1]
            tokens2 = nodetokens2[func2]
            matched_funcs.add(func1)
            for token in tokens1:
                line_num, col_begin, col_end = token
                r_line_num = match_lines[int(line_num)]
                r_col_begin, r_col_end = get_matched_token(matched_results_l[int(line_num)], matched_results_r[r_line_num], int(col_begin), int(col_end))
                if (str(r_line_num), r_col_begin, r_col_end) in tokens2:
                    if tokens2[(str(r_line_num), r_col_begin, r_col_end)] == tokens1[token]:
                        tp += 1
                    else: # matched to wrong token
                        fp += 1
                elif r_col_begin == -1: # invalid situation, don't consider
                    continue
                elif r_col_begin is None: # misidentified as add or delete
                    fn += 1
                else: # matched to wrong token
                    fp += 1

    for func in nodetokens1.keys():
        if func in matched_funcs or func in funcs_not_found:
            continue
        fn += len(nodetokens1[func])
        matched_funcs.add(func)
    
    available_funcs_f = open(os.path.join(output_sigmadiff, v1 + "_vs_" + v2, "avail_func.txt"), "w")
    for func in matched_funcs:
        available_funcs_f.write(func + '\n')
    available_funcs_f.close()
    if tp+fp == 0:
        prec = 0
        recall = 0
    else:
        prec = tp/(tp+fp)
        recall = tp/(tp+fn+fp)
        print(binname, tp, fp, tp+fn+fp, prec, recall, 2*prec*recall/(prec+recall))
        
if __name__ == "__main__":
    v1 = 'coreutils-5.93-O0'
    v2 = 'coreutils-5.93-O3'
    binname = 'chownstripped'
    output_sigmadiff = 'out'
    output_diaphora = 'diaphoraresults'
    evaluate_token_level(v1, v2, binname, output_sigmadiff, output_diaphora)
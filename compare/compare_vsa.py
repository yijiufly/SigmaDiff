import json
import os
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import torch
from model import Model

def match_weighted_sim(array1, array2, call1, call2):
    if len(array1) == 0 and len(array2) == 0:
        return 1
    set1 = set(array1)
    set2 = set(array2)
    matched = 0
    for str_common in set1.intersection(set2):
        matched += 1/len(call1[str_common])
    unmatched = 0
    for str_unique in set1 - set2:
        unmatched += 1/len(call1[str_unique])
    for str_unique in set2 - set1:
        unmatched += 1/len(call2[str_unique])
    return matched/(matched + unmatched)

def match_two_string_array(array1, array2, feature_type=None):
    if len(array1) == 0 and len(array2) == 0:
        return 1
    set1 = set(array1)
    set2 = set(array2)
    return len(set1.intersection(set2))/len(set1.union(set2))
    # not_matched = 0
    # matched = 0
    # not_visited = list(array2)
    # if len(array1) == 0 and len(array2) == 0:
    #     return 1
    
    # for s1 in array1:
    #     found_match = False
    #     for s2 in array2:
    #         if compare_side_effect(s1, s2, feature_type):
    #             try:
    #                 not_visited.remove(s2)
    #             except:
    #                 pass
    #             found_match = True
    #             break
                
    #     if not found_match:
    #         # print(s1)
    #         not_matched += 1
    #     else:
    #         matched += 1

    # for o in not_visited:
    #     found_match = False
    #     for o1 in array1:
    #         if compare_side_effect(o, o1, feature_type):
    #             found_match = True
    #             break
                
    #     if not found_match:
    #         # print(o)
    #         not_matched += 1
    #     else:
    #         matched += 1

    # return matched/(matched + not_matched)




def match_two_structs(arg1, arg2):
    matched = 0
    not_matched = 0
    off1 = arg1["offsets"]
    off2 = arg2["offsets"]
    isArray1 = arg1["isArray"]
    isArray2 = arg2["isArray"]
    if isArray1 or isArray2:
        return 1, 0
    for i in range(0, len(off1)):
        if off1[i] in off2:
            matched += 1
        elif off1[i] in arg2.keys() and arg2[off1[i]]["isArray"] == True:
            matched += 1
        else:
            not_matched += 1
            
    for i in range(0, len(off2)):
        if off2[i] in off1:
            matched += 1
        elif off2[i] in arg1.keys() and arg1[off2[i]]["isArray"] == True:
            matched += 1
        else:
            not_matched += 1

    # check embeded structs
    if arg1.keys()!= arg2.keys():
        not_matched += len(set(arg1.keys()).union(set(arg2.keys())) - set(arg1.keys()).intersection(set(arg2.keys())))
    for s in arg1.keys():
        if s == "isArray" or s == "offsets" or s not in arg2.keys():
            continue
        m, n = match_two_structs(arg1[s], arg2[s])
        matched += m
        not_matched += n
                
    return matched, not_matched

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')       
model_sim = Model().to(device)
model_sim.load_state_dict(torch.load('compare/model.dat'))
model_sim.eval()
# mode 5: compare sideeffect, return, and data structure
# mode 0: compare sideeffect
# mode -1: compare sideeffect (including callee's)
# mode 1: compare returns
# mode 2: compare data structure
# mode 3: compare data structure and other argument types
def compare_two_functions(file1, file2, call1, call2, mode=5):
    try:
        t = time.time()
        with open(file1, "r") as f:
            json_object1 = json.load(f)
        with open(file2, "r") as f:
            json_object2 = json.load(f)
        is_leaf = False
        features_num1 = 0
        features_num2 = 0
        features_num3 = 0
        features_num4 = 0
        features_num5 = 0
        if mode == 0 or mode == -1 or mode == 5:
            sideeffect1 = json_object1["sideeffect"]
            if mode == -1 or mode == 5:
                for callee in json_object1["calleesideeffect"].keys():
                    sideeffect1.extend(json_object1["calleesideeffect"][callee])

            sideeffect2 = json_object2["sideeffect"]
            if mode == -1 or mode == 5:
                for callee in json_object2["calleesideeffect"].keys():
                    sideeffect2.extend(json_object2["calleesideeffect"][callee])

            if len(json_object1["calleesideeffect"].keys()) == 0 and len(json_object2["calleesideeffect"].keys()) == 0:
                is_leaf = True
            # print("side effect score")
            # print(match_two_string_array(sideeffect1, sideeffect2, "sideeffect"))
            sim1 = match_two_string_array(sideeffect1, sideeffect2, "sideeffect")
            features_num1 += len(sideeffect1)
            features_num1 += len(sideeffect2)
        elapsed = time.time() - t
        # print("sideeffect: " + str(elapsed))
        t = time.time()
        # returns
        if mode == 1 or mode == 5:
            # print("returns")
            # print(match_two_string_array(json_object1["return"], json_object2["return"], "return"))
            sim2 = match_two_string_array(json_object1["return"], json_object2["return"], "return")
            features_num2 += len(json_object1["return"])
            features_num2 += len(json_object2["return"])
        elapsed = time.time() - t
        # print("returns: " + str(elapsed))

        # strings and library calls
        if mode == 5:
            # sim3 = match_weighted_sim(json_object1["stringsAndLibcalls"], json_object2["stringsAndLibcalls"], call1, call2)
            sim3 = match_two_string_array(json_object1["stringsAndLibcalls"], json_object2["stringsAndLibcalls"])
            features_num3 += len(json_object1["stringsAndLibcalls"])
            features_num3 += len(json_object2["stringsAndLibcalls"])
        t = time.time()
                
        # structs
        if mode == 2 or mode == 3 or mode == 5:
            not_matched = 0
            matched = 0
            numArg = json_object1["numargs"]
            numArg2 = json_object2["numargs"]
            for i in range(1, max(numArg, numArg2) + 1):
                if not "arg" + str(i) in json_object1.keys() and not "arg" + str(i) in json_object2.keys() :
                    continue
                elif "arg" + str(i) in json_object1.keys() and "arg" + str(i) in json_object2.keys():
                    arg1 = json_object1["arg" + str(i)]
                    arg2 = json_object2["arg" + str(i)]
                    if isinstance(arg1, dict)  and isinstance(arg2, dict):
                        m, n = match_two_structs(arg1, arg2)
                        not_matched += n
                        matched += m
                            
                    elif mode == 3 or mode == 5:
                        if not arg1 == arg2:
                            not_matched += 1
                        else:
                            matched += 1
                            
                else:
                    not_matched += 1
            if max(matched, not_matched) == 0:
                sim4 = 1
            else:
                sim4 = matched/(matched + not_matched)
            features_num4 += matched
            features_num4 += not_matched

        if mode == 5:
            loads1 = json_object1["loads"]
            if mode == -1 or mode == 5:
                for callee in json_object1["calleeloads"].keys():
                    loads1.extend(json_object1["calleeloads"][callee])

            loads2 = json_object2["loads"]
            if mode == -1 or mode == 5:
                for callee in json_object2["calleeloads"].keys():
                    loads2.extend(json_object2["calleeloads"][callee])

            sim5 = match_two_string_array(loads1, loads2, "loads")
            features_num5 += len(loads1)
            features_num5 += len(loads2)
        t = time.time()
        elapsed = time.time() - t
        return (sim1 + sim2 + sim3 + sim4 + sim5 * 0.5)/4.5, features_num1 + features_num2 + features_num3 + features_num4 + features_num5
        # diff = (sim1, sim2, sim3, sim4, sim5)
        # data = [(*diff, features_num1, features_num2, features_num3, features_num4, features_num5)]
        # data = torch.as_tensor(data, dtype=torch.float, device=device)
        # sim = model_sim(data).sigmoid()
        # return sim.item(), features_num1 + features_num2 + features_num3 + features_num4 + features_num5
    except:
        # print(traceback.format_exc())
        return 0, 0

def compare_side_effect(s1, s2, feature_type):
    if feature_type == "sideeffect":
        splits1 = s1.split(": ")
        key_f = splits1[0]
        key = splits1[1]
        value = splits1[2].strip()

        splits2 = s2.split(": ")
        key_f2 = splits2[0]
        key2 = splits2[1]
        value2 = splits2[2].strip()

        if 'f(' in key or 'f(' in key2:
            return key_f == key_f2 and value == value2
        else:
            return key == key2 and value == value2
    elif feature_type == "return":
        return s1 == s2


def compare_nodes(s1, s2):
    splits1 = s1.split(": ")
    addr_f = splits1[0]
    addr = splits1[1].strip()

    splits2 = s2.split(": ")
    addr_f2 = splits2[0]
    addr2 = splits2[1].strip()

    if 'f(' in addr or 'f(' in addr2:
        return addr_f == addr_f2
    else:
        return addr == addr2

def collect_features(file):
    try:
        with open(file, "r") as f:
            json_object = json.load(f)
            sideeffect = json_object["sideeffect"]
            loads = json_object["loads"]
            calleesideeffect = json_object["calleesideeffect"]
            calleeloads = json_object["calleeloads"]
            strlibs = json_object["stringsAndLibcalls"]
        return sideeffect, loads, calleesideeffect, calleeloads, strlibs
    except:
        pass
    return None

def infer_inlining(ea1, features1, addr2funcname1, ea2, features2, addr2funcname2):
    inlined1 = set()
    inlined2 = set()
    calleesideeffect1 = {}
    calleesideeffect2 = {}
    try:
        for key in features1:
            if key == "self_features":
                sideeffect1 = features1["self_features"]
            else:
                calleesideeffect1[key] = features1[key]
        for key in features2:
            if key == "self_features":
                sideeffect2 = features2["self_features"]
            else:
                calleesideeffect2[key] = features2[key]
        
        notVisited1 = list(sideeffect1 - sideeffect2)
        notVisited2 = list(sideeffect2 - sideeffect1)

        if len(notVisited1) > 0:
            # find unique se of each callee
            uniquecalleese2 = dict()
            for callee in calleesideeffect2.keys():
                se = set(calleesideeffect2[callee])
                for callee2 in calleesideeffect2.keys():
                    if callee2 == callee:
                        continue
                    se = se - calleesideeffect2[callee2]
                uniquecalleese2[callee] = se
            for s1 in notVisited1:
                foundMatch = False
                for callee in uniquecalleese2.keys():
                    for s2 in uniquecalleese2[callee]:
                        if s1 == s2:
                            if ea1.startswith("FUN_"):
                                addr = ea1.split("_")[1]
                                funcname1 = addr2funcname1[str(int(addr, 16))]
                            if callee.startswith("FUN_"):
                                addr = callee.split("_")[1]
                                funcname2 = addr2funcname2[str(int(addr, 16))]
                            with open("inline_infer.txt", "a") as f:
                                f.write("v1 " + funcname1 + " inlined function " + funcname2 + " evidence: " + s1 + "\n")
                            inlined1.add(callee)

        if len(notVisited2) > 0:
            # find unique se of each callee
            uniquecalleese1 = dict()
            for callee in calleesideeffect1.keys():
                se = set(calleesideeffect1[callee])
                for callee2 in calleesideeffect1.keys():
                    if callee2 == callee:
                        continue
                    se = se - calleesideeffect1[callee2]
                uniquecalleese1[callee] = se
            for s1 in notVisited2:
                foundMatch = False
                for callee in uniquecalleese1.keys():
                    for s2 in uniquecalleese1[callee]:
                        if s1 == s2:
                            if ea2.startswith("FUN_"):
                                addr = ea2.split("_")[1]
                                funcname1 = addr2funcname2[str(int(addr, 16))]
                            if callee.startswith("FUN_"):
                                addr = callee.split("_")[1]
                                funcname2 = addr2funcname1[str(int(addr, 16))]
                            with open("inline_infer.txt", "a") as f:
                                f.write("v2 " + funcname1 + " inlined function " + funcname2 + " evidence: " + s1 + "\n")
                            inlined2.add(callee)
    except:
        pass
    return inlined1, inlined2


def load_functions(path1, path2):
    addr2funcname1 = dict()
    addr2funcname2 = dict()
    with open(os.path.join(path1, "addr2funcname.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        name = l.split(", ")[1].strip()
        addr2funcname1[l.split(", ")[0]] = name

    with open(os.path.join(path2, "addr2funcname.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        name = l.split(", ")[1].strip()
        addr2funcname2[l.split(", ")[0]] = name

    strippedname2realname1 = {}
    strippedname2realname2 = {}
    with open(os.path.join(path1, "addr2funcname_stripped.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = l.split(", ")[0]
        name = l.split(", ")[1].strip()
        strippedname2realname1[name] = addr2funcname1[addr]
    with open(os.path.join(path2, "addr2funcname_stripped.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = l.split(", ")[0]
        name = l.split(", ")[1].strip()
        strippedname2realname2[name] = addr2funcname2[addr]
    return strippedname2realname1, strippedname2realname2

def load_funcnames(path1, path2):
    
    addr2strippedname1 = dict()
    addr2strippedname2 = dict()
    with open(os.path.join(path1, "addr2funcname_stripped.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = l.split(", ")[0]
        name = l.split(", ")[1].strip()
        addr2strippedname1[addr] = name
    with open(os.path.join(path2, "addr2funcname_stripped.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = l.split(", ")[0]
        name = l.split(", ")[1].strip()
        addr2strippedname2[addr] = name
    

    funcname2addr1 = dict()
    funcname2addr2 = dict()
    with open(os.path.join(path1, "addr2funcname.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = l.split(", ")[0]
        name = l.split(", ")[1].strip()
        funcname2addr1[name] = addr

    with open(os.path.join(path2, "addr2funcname.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = l.split(", ")[0]
        name = l.split(", ")[1].strip()
        funcname2addr2[name] = addr

    realname2funcname1 = {func:addr2strippedname1[funcname2addr1[func]] for func in funcname2addr1.keys() if funcname2addr1[func] in addr2strippedname1}
    realname2funcname2 = {func:addr2strippedname2[funcname2addr2[func]] for func in funcname2addr2.keys() if funcname2addr2[func] in addr2strippedname2}
    strippedname2realname1 = {v:k for k, v in realname2funcname1.items()}
    strippedname2realname2 = {v:k for k, v in realname2funcname2.items()}
    return realname2funcname1, realname2funcname2, strippedname2realname1, strippedname2realname2 

def test_infer_inlining(path1, path2):
    realname2funcname1, realname2funcname2, strippedname2realname1, strippedname2realname2 = load_funcnames(path1, path2)

    infered_inlining = set()
    with open("inlined_funcsO3.txt", "r") as f:
        inlined_funcs = f.readlines()
    inlined_funcsO3 = [(s.strip('\n').split(' ')[0], s.strip('\n').split(' ')[1]) for s in inlined_funcs]
    with open("inlined_funcsO1.txt", "r") as f:
        inlined_funcs = f.readlines()
    inlined_funcsO1 = [(s.strip('\n').split(' ')[0], s.strip('\n').split(' ')[1]) for s in inlined_funcs]
    tp_new = []
    fp_new = []
    for func in realname2funcname1.keys():
        if func.endswith("_thunk"):
            continue
        if func in realname2funcname2.keys():
            inlined1, inlined2 = infer_inlining(os.path.join(path1, realname2funcname1[func] + '.json'), os.path.join(path2, realname2funcname2[func] + '.json'))
            for callee in inlined1:
                callee = strippedname2realname2[callee]
                if callee.endswith("#2"):
                    callee = callee[:-2]
                if callee.endswith("_thunk"):
                    callee = callee[:-6]
                if func.endswith("#2"):
                    func = func[:-2]
                infered_inlining.add(("O1", func, callee)) # in O2 func inlined callee
                fp_new.append(("O1", func, callee))
            for callee in inlined2:
                callee = strippedname2realname1[callee]
                if callee.endswith("#2"):
                    callee = callee[:-2]
                if callee.endswith("_thunk"):
                    callee = callee[:-6]
                if func.endswith("#2"):
                    func = func[:-2]
                infered_inlining.add(("O3", func, callee))
                if (func, callee) in set(inlined_funcsO3) - set(inlined_funcsO1):
                    tp_new.append(("O3", func, callee))
                else:
                    fp_new.append(("O3", func, callee))

    print(len(tp_new), len(fp_new), len(set(inlined_funcsO3) - set(inlined_funcsO1)))
    for fp_inline in fp_new:
        print(fp_inline)

def test_filter(path1, path2):
    strippedname2realname1, strippedname2realname2 = load_functions(path1, path2)
    # count = 0
    # total = 0
    # for func in funcname1:
    #     if func in funcname2:
    #         total += 1
            
    #         conflict = compare_two_functions(os.path.join(path1, funcname2addr1[func] + '.json'), os.path.join(path2, funcname2addr2[func] + '.json'))
    #         if conflict < 0.7:
    #             count += 1
    #         if conflict < 0.1:
    #             print(func, funcname2addr1[func], funcname2addr2[func], conflict)

    # print(count, total)
    same_distribute = []
    different_distribute = []
    for func in strippedname2realname1.keys():
        for func2 in strippedname2realname2.keys():
            if strippedname2realname1[func] != strippedname2realname2[func2]:
                continue
            conflict, is_leaf = compare_two_functions(os.path.join(path1, func + '.json'), os.path.join(path2, func2 + '.json'))

            if conflict < 0.6:
                print(strippedname2realname1[func], func, func2, conflict)
            if strippedname2realname1[func] == strippedname2realname2[func2]:
                same_distribute.append(conflict)
            else:
                different_distribute.append(conflict)

    plt.hist(same_distribute, bins=100, range=(0, 1))
    # plt.hist(different_distribute, bins=100, range=(0, 1))
    plt.xlabel('similarity')
    plt.ylabel('number of pairs')
    plt.show()
    


if __name__ == "__main__":
    # path1 = '/home/yijiufly/Downloads/projects/lineage_inference/data/testfilter/libjpeg/libjpeg-v7/O2/json/'
    # path2 = '/home/yijiufly/Downloads/projects/lineage_inference/data/testfilter/libjpeg/libjpeg-v7/O3/json/'
    # path1 = '/home/yijiufly/Downloads/projects/diaphora/binaries/OpenSSL_1_0_1g_O0/bin/json/'
    # path2 = '/home/yijiufly/Downloads/projects/diaphora/binaries/OpenSSL_1_0_1g_O3/bin/json/'
    path1 = '/home/yijiufly/Downloads/projects/PseudocodeDiffing/Dataset_for_BinDiff/binutils/output/binutils-2.13-O1/addr2line_stripped/'
    path2 = '/home/yijiufly/Downloads/projects/PseudocodeDiffing/Dataset_for_BinDiff/binutils/output/binutils-2.13-O3/addr2line_stripped/'
    # test_filter(path1, path2)
    # compare_two_functions('Dataset_for_BinDiff/binutils/output/binutils-2.13-O1/addr2line_stripped/FUN_00404944.json', 'Dataset_for_BinDiff/binutils/output/binutils-2.13-O2/addr2line_stripped/FUN_00405460.json', None, None)
    test_infer_inlining(path1, path2)


#!/usr/bin/python3

import os
from subprocess import call
import sys
import time
import threading
import sys
sys.path.append('compare')
import compare_vsa
from collections import defaultdict
import tracemalloc
from queue import PriorityQueue

from scipy.optimize import linear_sum_assignment
import numpy as np
import pickle
from tarjan_sort import robust_topological_sort
from load_emb import load_file, load_file_with_debug

def log(msg):
    if isinstance(threading.current_thread(), threading._MainThread):
        print(("[%s] %s" % (time.asctime(), msg)))


def log_refresh(msg, show=False, do_log=True):
    log(msg)


class CBinDiff:
    def __init__(self, db_name):
        self.names = dict()
        self.db_name = db_name
        self.dbs_dict = {}
        self.db = None # Used exclusively by the exporter!
        self.last_diff_db = None
        self.matched1 = []
        self.matched2 = []
        self.mapping = {}
        self.initials = []
        self.func_semantic_sim = None
        self.neighbor_sim = None
        self.func2id1 = dict()
        self.func2id2 = dict()
        

    def diff(self):
        try:
            t0 = time.time()
            self.find_initial_matches()
            tracemalloc.start()
            self.match_the_rest(self.nocaller1 - self.isolate_funcs1, self.nocaller2 - self.isolate_funcs2)
            print(tracemalloc.get_traced_memory())
            log_refresh("Find matches along the callgraph...")
            self.match_along_callgraph_nhop(1)
            self.match_the_rest(self.isolate_funcs1, self.isolate_funcs2)
            self.match_the_rest(self.nocaller1 - self.isolate_funcs1, self.nocaller2 - self.isolate_funcs2)
            self.match_the_rest(self.functions1 - self.nocaller1, self.functions2 - self.nocaller2)
            self.match_the_rest(self.functions1, self.nocaller2)
            self.match_the_rest(self.nocaller1, self.functions2)
            self.match_the_rest(self.functions1 - self.isolate_funcs1, self.functions2 - self.isolate_funcs2, 'ag')
            total_time = time.time() - t0
            log("Done. Took {} seconds.".format(total_time))
        finally:
            pass
        return total_time


    def propagate_features(self, features, callgraph, callgraph_reverse, path1, matched):
        filted_callgraph = {}
        for key in callgraph.keys():
            filted_callgraph[key] = [i for i in callgraph[key] if not i.startswith("string::") and not i.endswith("_thunk")]
        order = robust_topological_sort(filted_callgraph)
        order.reverse()
        for func in order:
            features[func] = defaultdict(set)
            ret = compare_vsa.collect_features(os.path.join(path1, func + ".json"))
            if ret is None:
                continue
            sideeffect, loads, calleesideeffect, calleeloads, strlibs = ret
            features[func]["self_features"].update(set(["sideeffect__" + i.split(":")[0] + ":" + i.split(":")[2] for i in sideeffect]))
            features[func]["self_features"].update(set(["loads__" + i.split(":")[0] for i in loads]))
            features[func]["self_features"].update(set(["strlibs__" + i for i in strlibs]))
            for key in calleesideeffect.keys():
                features[func][key.split("@")[0]].update(set(["sideeffect__" + i.split(":")[0] + ":" + i.split(":")[2] for i in calleesideeffect[key]]))
            
            for key in calleeloads.keys():
                features[func][key.split("@")[0]].update(set(["loads__" + i.split(":")[0] for i in calleeloads[key]]))
        
            matched_neighbors = set(filted_callgraph[func]).intersection(set(matched))
            # matched_neighbors.update(set(callgraph_reverse[func]).intersection(set(matched)))
            matched_neighbors_id = set(["func_" + str(matched.index(i)) for i in matched_neighbors])
            features[func]["self_features"].update(matched_neighbors_id)
            for callee in filted_callgraph[func]:
                if callee in features:
                    for key in features[callee].keys():
                        features[func][callee].update(set([i for i in features[callee][key] if not i.startswith("sideeffect__") and not i.startswith("loads__")]))


    def find_initial_matches(self):
        candidates = self.functions1.intersection(self.functions2)
        for func in candidates:
            if func.startswith("FUN_"):
                continue
            self.matched1.append(func)
            self.matched2.append(func)
            self.mapping[func] = func
            self.initials.append(func)


    def load_callgraph(self, path1, path2, load_gt):
        self.path1 = path1
        self.path2 = path2
        self.callgraph1 = defaultdict(list)
        self.callgraph2 = defaultdict(list)
        self.callgraph_reverse1 = defaultdict(list)
        self.callgraph_reverse2 = defaultdict(list)
        self.functions1 = set()
        self.functions2 = set()
        self.calleeset1 = set()
        self.calleeset2 = set()
        with open(os.path.join(path1, "callgraph.txt"), "r") as f:
            lines = f.readlines()
        for l in lines:
            src = l.split(", ")[0]
            des = l[len(src)+2:].strip()
            if src == des:
                continue
            self.callgraph1[src].append(des)
            self.callgraph_reverse1[des].append(src)
            self.functions1.add(src)
            self.functions1.add(des)
            self.calleeset1.add(des)

        with open(os.path.join(path2, "callgraph.txt"), "r") as f:
            lines = f.readlines()
        for l in lines:
            src = l.split(", ")[0]
            des = l[len(src)+2:].strip()
            if src == des:
                continue
            self.callgraph2[src].append(des)
            self.callgraph_reverse2[des].append(src)
            self.functions2.add(src)
            self.functions2.add(des)
            self.calleeset2.add(des)


        self.strippedname2addr1 = dict()
        self.strippedname2addr2 = dict()
        with open(os.path.join(path1, "addr2funcname_stripped.txt"), "r") as f:
            lines = f.readlines()
        for l in lines:
            addr = l.split(", ")[0]
            name = l.split(", ")[1].strip()
            self.strippedname2addr1[name] = addr
        self.isolate_funcs1 = set(self.strippedname2addr1.keys()) - self.functions1
        self.nocaller1 = set(self.strippedname2addr1.keys()) - self.calleeset1
        self.functions1.update(set(self.strippedname2addr1.keys()))
        with open(os.path.join(path2, "addr2funcname_stripped.txt"), "r") as f:
            lines = f.readlines()
        for l in lines:
            addr = l.split(", ")[0]
            name = l.split(", ")[1].strip()
            self.strippedname2addr2[name] = addr
        self.isolate_funcs2 = set(self.strippedname2addr2.keys()) - self.functions2
        self.nocaller2 = set(self.strippedname2addr2.keys()) - self.calleeset2
        self.functions2.update(set(self.strippedname2addr2.keys()))
        
        i = 0
        for func in self.functions1:
            self.func2id1[func] = i
            i += 1

        i = 0
        for func in self.functions2:
            self.func2id2[func] = i
            i += 1

        self.addr2funcname1 = dict()
        self.addr2funcname2 = dict()
        if load_gt:
            with open(os.path.join(path1, "addr2funcname.txt"), "r") as f:
                lines = f.readlines()
            for l in lines:
                addr = l.split(", ")[0]
                name = l.split(", ")[1].strip()
                self.addr2funcname1[addr] = name

            with open(os.path.join(path2, "addr2funcname.txt"), "r") as f:
                lines = f.readlines()
            for l in lines:
                addr = l.split(", ")[0]
                name = l.split(", ")[1].strip()
                self.addr2funcname2[addr] = name

        name1 = self.path1.split('_')[-1]
        name2 = self.path2.split('_')[-1]

        if os.path.exists(os.path.join(self.path1, name1 + ".dat")):
            self.emb1 = load_file_with_debug(os.path.join(self.path1, name1 + ".dat"), self.strippedname2addr1)
        elif os.path.exists(os.path.join(self.path1, name1 + ".npy")):
            self.emb1 = load_file(os.path.join(self.path1, name1 + ".npy"), os.path.join(self.path1, name1 + ".addr.npy"), self.strippedname2addr1)
        else:
            self.emb1 = None

        if os.path.exists(os.path.join(self.path2, name2 + ".dat")):
            self.emb2 = load_file_with_debug(os.path.join(self.path2, name2 + ".dat"), self.strippedname2addr2)
        elif os.path.exists(os.path.join(self.path2, name2 + ".npy")):
            self.emb2 = load_file(os.path.join(self.path2, name2 + ".npy"), os.path.join(self.path2, name2 + ".addr.npy"), self.strippedname2addr2)
        else:
            self.emb2 = None


    def realname2strippedname(self):
        self.realname2strippedname1 = {}
        for addr, name in self.addr2funcname1.items():
            for strippedname, addr2 in self.strippedname2addr1.items():
                if addr2 == addr:
                    self.realname2strippedname1[name] = strippedname
                    break
        self.realname2strippedname2 = {}
        for addr, name in self.addr2funcname2.items():
            for strippedname, addr2 in self.strippedname2addr2.items():
                if addr2 == addr:
                    self.realname2strippedname2[name] = strippedname
                    break


    def evaluate(self, matched_functions, with_gt):
        if with_gt:
            tp = set()
            fp = set()
            self.realname2strippedname()
            for func1, func2 in zip(self.matched1, self.matched2):
                if func1.startswith("string::"):
                    continue
                if func1.startswith("FUN_"):
                    addr = func1.split("_")[1]
                    if str(int(addr, 16)) not in self.addr2funcname1:
                        continue
                    func1 = self.addr2funcname1[str(int(addr, 16))]

                if func2.startswith("FUN_"):
                    addr = func2.split("_")[1]
                    func2 = self.addr2funcname2[str(int(addr, 16))]
                    if str(int(addr, 16)) not in self.addr2funcname2:
                        continue

                if func1 != func2:
                    fp.add((func1, func2))
                else:
                    tp.add((func1, func2))

            total = set(self.addr2funcname1.values()).intersection(set(self.addr2funcname2.values()))
            with open(matched_functions, "w") as f:
                for func1, func2 in tp.union(fp):
                    if not func1.endswith("_thunk") and func1 in self.realname2strippedname1 and not func2.endswith("_thunk") and func2 in self.realname2strippedname2:
                        f.write(self.realname2strippedname1[func1] + " " +  self.realname2strippedname2[func2] + "\n")

            log("tp: {} fp {} total {} precision {} recall {}.".format(len(tp), len(fp), len(total), len(tp)/(len(tp) + len(fp)), len(tp)/len(total)))
            # self.export_graph(tp, fp)
            return len(tp)/(len(tp) + len(fp)), len(tp)/len(total)
        else:
            results = set()
            for func1, func2 in zip(self.matched1, self.matched2):
                if func1.startswith("string::") or func1.endswith("_thunk"):
                    continue
                if func2.startswith("string::") or func2.endswith("_thunk"):
                    continue
                results.add((func1, func2))
            with open(matched_functions, "w") as f:
                for func1, func2 in results:
                    f.write(func1 + " " +  func2 + "\n")


    def find_matched_neighbors(self, name1, name2):
        if self.neighbor_sim is None:
            return 0
        id1 = self.func2id1[name1]
        id2 = self.func2id2[name2]
        if self.neighbor_sim[id1][id2] is not None:
            return self.neighbor_sim[id1][id2]
        callee1 = set(self.callgraph1[name1]).intersection(set(self.matched1))
        callee2 = set(self.callgraph2[name2]).intersection(set(self.matched2))
        count = 0
        for c1 in callee1:
            matched_c2 = self.mapping[c1]
            if matched_c2 in callee2:
                count += 1
        caller1 = set(self.callgraph_reverse1[name1]).intersection(set(self.matched1))
        caller2 = set(self.callgraph_reverse2[name2]).intersection(set(self.matched2))
        for c1 in caller1:
            matched_c2 = self.mapping[c1]
            if matched_c2 in caller2:
                count += 1
        
        if (len(callee1) + len(callee2) + len(caller1) + len(caller2)) == 0:
            count = 0
        else:
            count = count / (len(callee1) + len(callee2) + len(caller1) + len(caller2))
        self.neighbor_sim[id1][id2] = 1 - count
        return 1 - count


    def check_semantic_conflict_emb(self, ea, ea2):
        if ea not in self.emb1 or ea2 not in self.emb2:
            return 0, 0
        e1 = self.emb1[ea]
        e2 = self.emb2[ea2]
        sim = np.inner(e1, e2) / (np.linalg.norm(e1) * np.linalg.norm(e2))
        return sim, 10


    def check_semantic_conflict(self, ea, ea2):
        id1 = self.func2id1[ea]
        id2 = self.func2id2[ea2]
        if self.func_semantic_sim is not None and self.func_semantic_sim[id1][id2] is not None:
            return self.func_semantic_sim[id1][id2]
        else:
            sim, features = compare_vsa.compare_two_functions(os.path.join(self.path1, ea + ".json"), os.path.join(self.path2, ea2 + ".json"), self.callgraph_reverse1, self.callgraph_reverse2, 5)
            if sim == 0 and ea == ea2:
                sim = 1
                features = 10
            if self.func_semantic_sim is not None:
                self.func_semantic_sim[id1][id2] = (sim, features)
            return (sim, features)


    def match_aggressively(self, matrix, confidence, name_list1, name_list2):
        row_ind = []
        col_ind = []
        rid = np.arange(len(name_list1))
        cid = np.arange(len(name_list2))
        name_list1 = np.array(name_list1)
        name_list2 = np.array(name_list2)
        while len(name_list1) > 0 and len(name_list2) > 0:
            ind = self.find_one_pair(matrix, confidence, name_list1, name_list2)
            if ind is None:
                break
            row_ind.extend(list(rid[ind[0]]))
            col_ind.extend(list(cid[ind[1]]))
            # update the matrix and other lists
            matrix = np.delete(matrix, ind[0], axis=0)
            matrix = np.delete(matrix, ind[1], axis=1)
            confidence = np.delete(confidence, ind[0], axis=0)
            confidence = np.delete(confidence, ind[1], axis=1)
            name_list1 = np.delete(name_list1, ind[0])
            name_list2 = np.delete(name_list2, ind[1])
            rid = np.delete(rid, ind[0])
            cid = np.delete(cid, ind[1])
        return row_ind, col_ind
        

    # find the most matched function pairs in the name lists
    # 1. find the function pairs that has most similar semantic features
    # 2. find the function pairs that already have some other matched neighbors
    # 3. find the function pairs that have larger confidence
    def find_one_pair(self, matrix, confidence, name_list1, name_list2):
        min_value = np.amin(matrix)
        row_ind, col_ind = np.where(matrix == min_value)
        if len(row_ind) > 1:
            conf = confidence[row_ind, col_ind]
            max_conf = np.amax(conf)
            row_ind = [row_ind[i] for i, j in enumerate(conf) if j == max_conf]
            col_ind = [col_ind[i] for i, j in enumerate(conf) if j == max_conf]
            if min_value > 0.5:
                return None
        return (row_ind, col_ind)


    def match_callees(self, callee1, callee2, caller, callerdiff, n):
        if len(callee1) == 0 or len(callee2) == 0 or len(callee1) > 1000 or len(callee2) > 1000:
            return
        if not caller.startswith('FUN') and len(callee1) == 1 and len(callee2) == 1:
            f1 = list(callee1)[0]
            f2 = list(callee2)[0]
            if f2.endswith('thunk'):
                return
            self.matched1.append(f1)
            self.matched2.append(f2)
            self.mapping[f1] = f2
            callee1, callee2 = self.get_n_hop_neighbors(f1, f2, "callee", n)
            caller1, caller2 = self.get_n_hop_neighbors(f1, f2, "caller", n)
            self.worklist.put(((len(callee1) + len(callee2)), ((f1, f2), "callee")))
            self.worklist.put(((len(caller1) + len(caller2)), ((f1, f2), "caller")))
            return

        callee_list1 = [m for m in callee1 if os.path.exists(os.path.join(self.path1, m + ".json"))]
        callee_list2 = [m for m in callee2 if os.path.exists(os.path.join(self.path2, m + ".json"))]

        matrix = np.ones(shape=(len(callee_list1), len(callee_list2)))
        confidence = np.zeros(shape=(len(callee_list1), len(callee_list2)))
        for i, func1 in enumerate(callee_list1):
            for j, func2 in enumerate(callee_list2):
                (sim, features) = self.check_semantic_conflict(func1, func2)
                matrix[i, j] = 1 - sim
                confidence[i, j] = features
        
        # delete functions that have no features
        ind = np.where(confidence <= 1)
        matrix = np.delete(matrix, ind[0], axis=0)
        matrix = np.delete(matrix, ind[1], axis=1)
        confidence = np.delete(confidence, ind[0], axis=0)
        confidence = np.delete(confidence, ind[1], axis=1)
        callee_list1 = np.delete(callee_list1, ind[0])
        callee_list2 = np.delete(callee_list2, ind[1])
        row_ind, col_ind = linear_sum_assignment(matrix)
        # row_ind, col_ind = self.match_aggressively(matrix, confidence, callee_list1, callee_list2)
        for r, c in zip(row_ind, col_ind):
            if callee_list1[r] in self.matched1 or callee_list2[c] in self.matched2:
                continue
            if matrix[r, c] > 0.2 or confidence[r, c] < 1:
                continue
            if callee_list1[r].startswith("string::") or callee_list2[c].startswith("string::"):
                continue
            if len(np.where(matrix[r,:] < matrix[r, c])[0]) > 0:
                continue
            self.matched1.append(callee_list1[r])
            self.matched2.append(callee_list2[c])
            self.mapping[callee_list1[r]] = callee_list2[c]

            callee1, callee2 = self.get_n_hop_neighbors(callee_list1[r], callee_list2[c], "callee", n)
            caller1, caller2 = self.get_n_hop_neighbors(callee_list1[r], callee_list2[c], "caller", n)
            self.worklist.put(((len(callee1) + len(callee2)), ((callee_list1[r], callee_list2[c]), "callee")))
            self.worklist.put(((len(caller1) + len(caller2)), ((callee_list1[r], callee_list2[c]), "caller")))


    def match_the_rest(self, set1, set2, method='la'):
        unmatched1 = set1 - set(self.matched1)
        unmatched2 = set2 - set(self.matched2)
        unmatched_list1 = [m for m in unmatched1 if m.startswith("FUN_") and os.path.exists(os.path.join(self.path1, m + ".json"))]
        unmatched_list2 = [m for m in unmatched2 if m.startswith("FUN_") and os.path.exists(os.path.join(self.path2, m + ".json"))]
        matrix = np.ones(shape=(len(unmatched_list1), len(unmatched_list2)))
        confidence = np.zeros(shape=(len(unmatched_list1), len(unmatched_list2)))
        for i, func1 in enumerate(unmatched_list1):
            for j, func2 in enumerate(unmatched_list2):
                (sim, features) = self.check_semantic_conflict(func1, func2)
                neighbor = self.find_matched_neighbors(func1, func2)
                confidence[i, j] = features
                if confidence[i, j] <= 1:
                    matrix[i, j] = neighbor
                else:
                    matrix[i, j] = (1 - sim) * 0.7 + neighbor * 0.3
        
        if method == 'la':  # for functions that have features, combine features sim with neighbor sim
            # delete functions that have no features
            ind = np.where(confidence <= 1)
            matrix = np.delete(matrix, ind[0], axis=0)
            matrix = np.delete(matrix, ind[1], axis=1)
            confidence = np.delete(confidence, ind[0], axis=0)
            confidence = np.delete(confidence, ind[1], axis=1)
            unmatched_list1 = np.delete(unmatched_list1, ind[0])
            unmatched_list2 = np.delete(unmatched_list2, ind[1])
            row_ind, col_ind = linear_sum_assignment(matrix)
        else:  # for the rest of functions, match according to neighbor
            row_ind, col_ind = self.match_aggressively(matrix, confidence, unmatched_list1, unmatched_list2)
        for r, c in zip(row_ind, col_ind):
            if unmatched_list1[r] in self.matched1 or unmatched_list2[c] in self.matched2:
                continue
            if matrix[r, c] > 0.2:
                # print("features not matched")
                continue
            # if len(np.where(matrix[r,:] < matrix[r, c])[0]) > 0:
            #     continue
            self.matched1.append(unmatched_list1[r])
            self.matched2.append(unmatched_list2[c])
            self.mapping[unmatched_list1[r]] = unmatched_list2[c]
            

    def match_along_callgraph_nhop(self, n):
        self.worklist = PriorityQueue()
        for func1 in self.initials:
            func2 = func1
            if func1.endswith('_thunk'):
                continue
            callee1, callee2 = self.get_n_hop_neighbors(func1, func2, "callee", n)
            caller1, caller2 = self.get_n_hop_neighbors(func1, func2, "caller", n)

            self.worklist.put(((len(callee1) + len(callee2)), ((func1, func2), "callee")))
            self.worklist.put(((len(caller1) + len(caller2)), ((func1, func2), "caller")))

            while not self.worklist.empty():
                item = self.worklist.get()
                ea1 = item[1][0][0] # ea1
                ea2 = item[1][0][1] # ea2
                neighbortype = item[1][1]
                neighbor1, neighbor2 = self.get_n_hop_neighbors(ea1, ea2, neighbortype, n)
                self.match_callees(neighbor1, neighbor2, ea1, ea2, n)


    def get_n_hop_neighbors(self, name1, name2, neighbortype, n):
        if neighbortype == "callee":
            callee1 = [c for c in self.callgraph1[name1] if c not in self.matched1]
            callee2 = [c for c in self.callgraph2[name2] if c not in self.matched2]
            if n == 1:
                return set(callee1), set(callee2)

            for n1 in self.callgraph1[name1]:
                for n2 in self.callgraph1[n1]:
                    if n2 in self.matched1:
                        continue
                    callee1.append(n2)

            for n1 in self.callgraph2[name2]:
                for n2 in self.callgraph2[n1]:
                    if n2 in self.matched2:
                        continue
                    callee2.append(n2)
            return set(callee1), set(callee2)

        if neighbortype == "caller":
            caller1 = [c for c in self.callgraph_reverse1[name1] if c not in self.matched1]
            caller2 = [c for c in self.callgraph_reverse2[name2] if c not in self.matched2]
            if n == 1:
                return set(caller1), set(caller2)

            for n1 in self.callgraph_reverse1[name1]:
                for n2 in self.callgraph_reverse1[n1]:
                    if n2 in self.matched1:
                        continue
                    caller1.append(n2)

            for n1 in self.callgraph_reverse2[name2]:
                for n2 in self.callgraph_reverse2[n1]:
                    if n2 in self.matched2:
                        continue
                    caller2.append(n2)
            return set(caller1), set(caller2)
    

def diff_two_files(db1, db2, out, with_gt):
    print(db1, db2, out, with_gt)
    bd = CBinDiff(db1)
    bd.load_callgraph(db1, db2, with_gt)
    bd.diff()
    if not (os.path.exists(out)):
        os.mkdir(out)
    bd.evaluate(os.path.join(out, "matched_functions.txt"), with_gt)
    

if __name__ == "__main__":
    diff_two_files("/mnt/sata/lian/github/SigmaDiff/out/diffutils-2.8-O0_sdiffstripped", "/mnt/sata/lian/github/SigmaDiff/out/diffutils-2.8-O3_sdiffstripped", "/mnt/sata/lian/github/SigmaDiff/out/diffutils-2.8-O0_sdiffstripped_vs_diffutils-2.8-O3_sdiffstripped", True)
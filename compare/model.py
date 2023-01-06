from cProfile import label
import glob
import pickle
from typing import Dict
import json
import random
import numpy as np
import os

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


class Model(nn.Module):
    def __init__(self):
        super().__init__()
        # diff 5 + sum const len + sum_mem + sum_imported + sum_string + max sig len
        self.l1 = nn.Linear(10, 64)
        self.l2 = nn.Linear(64, 64)
        self.l3 = nn.Linear(64, 1)
        self.dropout = nn.Dropout(0.5)

    def forward(self, x):
        x = self.l1(x)
        x = self.dropout(x)
        x = F.elu(x)

        x = self.l2(x)
        x = self.dropout(x)
        x = F.elu(x)

        x = self.l3(x)
        return x.squeeze(dim=-1)


def gen_training_item(file1, file2):
    diff, features_num1, features_num2, features_num3, features_num4, features_num5 = compare_two_functions(file1, file2)
    if features_num1 is None:
        return None
    return (*diff, features_num1, features_num2, features_num3, features_num4, features_num5)


def compare_two_functions(file1, file2, mode=5):
    from compare_vsa import match_two_string_array, match_two_structs
    try:
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
            
            sim1 = match_two_string_array(sideeffect1, sideeffect2, "sideeffect")
            features_num1 += len(sideeffect1)
            features_num1 += len(sideeffect2)
        # returns
        if mode == 1 or mode == 5:
            sim2 = match_two_string_array(json_object1["return"], json_object2["return"], "return")
            features_num2 += len(json_object1["return"])
            features_num2 += len(json_object2["return"])

        # strings and library calls
        if mode == 5:
            # sim3 = match_weighted_sim(json_object1["stringsAndLibcalls"], json_object2["stringsAndLibcalls"], call1, call2)
            sim3 = match_two_string_array(json_object1["stringsAndLibcalls"], json_object2["stringsAndLibcalls"])
            features_num3 += len(json_object1["stringsAndLibcalls"])
            features_num3 += len(json_object2["stringsAndLibcalls"])
                
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
        return (sim1, sim2, sim3, sim4, sim5), features_num1, features_num2, features_num3, features_num4, features_num5
    except:
        # print(traceback.format_exc())
        return 0, None, None, None, None, None

def get_funcname(path1, path2):
    addr2funcname1 = dict()
    funcname2addr2 = dict()
    with open(os.path.join(path1, "addr2funcname.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = int(l.split(", ")[0])
        filename = 'FUN_00' + hex(addr)[2:] + '.json'
        name = l.split(", ")[1].strip()
        addr2funcname1[filename] = name

    with open(os.path.join(path2, "addr2funcname.txt"), "r") as f:
        lines = f.readlines()
    for l in lines:
        addr = int(l.split(", ")[0])
        filename = 'FUN_00' + hex(addr)[2:] + '.json'
        name = l.split(", ")[1].strip()
        funcname2addr2[name] = filename
    
    return addr2funcname1, funcname2addr2


def gen_pairs():
    v1 = '/home/administrator/Downloads/Lian/PseudocodeDiffing/Dataset_for_BinDiff/coreutils/output_backup/coreutils-5.93-O1'
    v2 = '/home/administrator/Downloads/Lian/PseudocodeDiffing/Dataset_for_BinDiff/coreutils/output_backup/coreutils-5.93-O3'
    data_all = []
    for bin in os.listdir(v1):
        if os.path.exists(os.path.join(v2, bin)):
            data = []
            label = []
            file2n_list = [f for f in os.listdir(os.path.join(v2, bin)) if f.endswith('.json')]
            for file1 in os.listdir(os.path.join(v1, bin)):
                if file1.endswith('.json'):
                    map1, map2 = get_funcname(os.path.join(v1, bin), os.path.join(v2, bin))
                    if file1 in map1 and map1[file1] in map2:
                        file2 = map2[map1[file1]]
                        data.append(gen_training_item(os.path.join(v1, bin, file1), os.path.join(v2, bin, file2)))
                        label.append(1)
                        idx = 10
                        while idx:
                            file2n = random.choice(file2n_list)
                            if file2n != file2:
                                data.append(gen_training_item(os.path.join(v1, bin, file1), os.path.join(v2, bin, file2n)))
                                label.append(0)
                                idx -= 1
            data = torch.as_tensor(data, dtype=torch.float, device=device)
            label = torch.as_tensor(label, dtype=torch.float, device=device)
            data_all.append([data, label])
    return data_all


def train():
    model = Model().to(device)
    optimizer = optim.AdamW(model.parameters())
    step = 0
    while True:
        for data, label in gen_pairs():
            optimizer.zero_grad()
            output = model(data)
            loss = F.binary_cross_entropy_with_logits(output, label)
            loss.backward()
            optimizer.step()
            step += 1
            if step % 10 == 0:
                # evaluate(model)
                print(step, loss.data)
                torch.save(model.state_dict(), 'model.dat')



@torch.no_grad()
def eval():
    model = Model().to(device)
    model.load_state_dict(torch.load('compare/model.dat'))
    model.eval()
    eval_data = []
    eval_label = []
    for data, label in gen_pairs():
        output = model(data).sigmoid()
        same_func = output > 0.5
        correct = same_func == label

        print(torch.sum(correct).item() / len(correct))


if __name__ == '__main__':
    # train()
    eval()

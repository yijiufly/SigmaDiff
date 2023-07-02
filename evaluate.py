from collections import defaultdict
from sys import prefix
import os
import re
import traceback
import shutil
import numpy as np
def load_nodelabel(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()
    groundtruth = {}
    nodelines = {}
    funcname = None
    func_features = defaultdict(set)
    node2func = dict()
    func_nodes = {}
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            funcname = line[1:] 
        else:
            features = line.split("|&|")
            groundtruth[features[0]] = features[-1]
            nodelines[features[0]] = features[1:]
            func_features[funcname].add(features[0])
            node2func[features[0]] = funcname

    return groundtruth, nodelines, node2func


def evaluate_precision_recall_cross_version_token(out_dir, filepath1, filepath2, src_dir, filter=True):
    filename1 = '_'.join(filepath1.split('/')[-2:])
    filename2 = '_'.join(filepath2.split('/')[-2:])
    comp_folder = filename1 + '_vs_' + filename2
    result_dir = os.path.join(out_dir, comp_folder + "_Finetuned-results")
    v1 = filename1.split("_")[0]
    v2 = filename2.split("_")[0]
    binary_name = filename1.split("_")[1]
    
    for result in os.listdir(result_dir):
        try:
            if filter:
                suffix = "-match_result.txt"
            else:
                suffix = "-Initial_match_result.txt"
            
            if result.endswith(suffix):
                currentdir = os.path.join(out_dir, comp_folder)
                
                srclines1, nodefeatures1, node2func1 = load_nodelabel(os.path.join(out_dir, comp_folder, v1 + "_" + binary_name + "_nodelabel.txt"))
                srclines2, nodefeatures2, node2func2 = load_nodelabel(os.path.join(out_dir, comp_folder, v2 + "_" + binary_name + "_nodelabel.txt"))
                
                # print("Building ground truth...")
                # print(result)
                addrmap_path = os.path.join(out_dir, v1 + '_vs_' + v2 + '_addrMapping')
                if os.path.exists(addrmap_path):
                    shutil.copyfile(addrmap_path, os.path.join(currentdir, 'addrMapping'))
                    ground_truth = os.path.join(currentdir, 'addrMapping')
                elif not os.path.exists(os.path.join(currentdir, 'addrMapping')):
                    groundTruthCollector = './gtc.py'
                    cmd_gtc = "python " + groundTruthCollector + \
                            ' --old_dir ' + os.path.join(src_dir, v1) + \
                            ' --new_dir ' + os.path.join(src_dir, v2) + \
                            ' --old_bin ' + filepath1[:-8] + \
                            ' --new_bin ' + filepath2[:-8] + \
                            ' --output_dir ' + currentdir
                    # print(cmd_gtc)
                    os.system(cmd_gtc)
                    shutil.copyfile('addrMapping', addrmap_path)
                    shutil.copyfile('addrMapping', os.path.join(currentdir, 'addrMapping'))
                    # then read the ground truth
                    ground_truth = os.path.join(currentdir, 'addrMapping')
                else:
                    ground_truth = os.path.join(currentdir, 'addrMapping')
                addrMapping = {}

                with open(ground_truth) as f:
                    for line in f.readlines():
                        pair = re.findall('\[(.*?)\]', line)
                        assert len(pair) == 2
                        original_addr_list = pair[0].split(', ')
                        mod_addr_list = pair[1].split(', ')
                        for addr1 in original_addr_list:
                            for addr2 in mod_addr_list:
                                if len(addr1.split('/')) > 2:
                                    addr1 = '/'.join(addr1.split('/')[-2:])
                                if len(addr2.split('/')) > 2:
                                    addr2 = '/'.join(addr2.split('/')[-2:])
                                if addr1 not in addrMapping:
                                    addrMapping[addr1]=set()
                                addrMapping[addr1].add(addr2)
                
                tp = 0
                fp = 0
                not_found = set()
                total1 = []
                with open(os.path.join(result_dir, result), "r") as f:
                    match_results = f.readlines()
                    for line in match_results:
                        line = line.strip()
                        n1, n2, gtline1, gtline2, correct, sim = line.split(",")

                        if gtline1 == "null":
                            continue
                        if float(sim) < 0.1:
                            continue
                        toklst = nodefeatures1[n1][-3].split('@*@')
                        num_tokens = len(toklst)//2
                        if gtline1 not in addrMapping:
                            not_found.add(n1)
                            continue
                        elif gtline2 in addrMapping[gtline1]:
                            tp += num_tokens
                        else:
                            fp += num_tokens
                        total1.append(n1)
                
                total = 0
                for key in srclines1:
                    if key not in total1 and srclines1[key] not in addrMapping:
                        continue
                    if srclines1[key] != "null" and key not in not_found:
                        toklst = nodefeatures1[key][-3].split('@*@')
                        num_tokens = len(toklst)//2
                        total += num_tokens
                prec = tp/(tp+fp)
                recall = tp/(total)
                print(binary_name, tp, fp, total, recall, prec, 2*prec*recall/(prec+recall))
                return (prec, recall, 2*prec*recall/(prec+recall))    
        except:
            print(binary_name)
            print(traceback.format_exc())
            return None
        
    return None


def evaluate_precision_recall_cross_optlevel_token(out_dir, filepath1, filepath2, filter=True):
    filename1 = '_'.join(filepath1.split('/')[-2:])
    filename2 = '_'.join(filepath2.split('/')[-2:])
    comp_folder = filename1 + '_vs_' + filename2
    result_dir = os.path.join(out_dir, comp_folder + "_Finetuned-results")
    v1 = filename1.split("_")[0]
    v2 = filename2.split("_")[0]
    binary_name = filename1.split("_")[1]

    for result in os.listdir(result_dir):
        try:
            if filter:
                suffix = "-match_result.txt"
            else:
                suffix = "-Initial_match_result.txt"
            if result.endswith(suffix):
                currentdir = os.path.join(out_dir, comp_folder)
                
                srclines1, nodefeatures1, node2func1 = load_nodelabel(os.path.join(out_dir, comp_folder, v1 + "_" + binary_name + "_nodelabel.txt"))
                srclines2, nodefeatures2, node2func2 = load_nodelabel(os.path.join(out_dir, comp_folder, v2 + "_" + binary_name + "_nodelabel.txt"))

                srclines_set2 = set()

                for key in srclines2:
                    srclines_set2.add(srclines2[key])
                # print("Building ground truth...")
                # print(result)
                tp = 0
                fp = 0
                not_found = set()
                tp_set = set()
                fp_set = set()
                matched = set()
                with open(os.path.join(result_dir, result), "r") as f:
                    match_results = f.readlines()
                    for line in match_results:
                        line = line.strip()
                        n1, n2, gtline1, gtline2, correct, sim = line.split(",")
                        if n1 in matched and int(n1) < 100:
                            tp_set.clear()
                            fp_set.clear()
                            matched.clear()
                        else:
                            matched.add(n1)
                        if float(sim) < 0.1:
                            continue
                        if gtline1 == "null":
                            continue
                        if gtline1 not in srclines_set2:
                            not_found.add(n1)
                            continue
                        toklst = nodefeatures1[n1][-3].split('@*@')
                        num_tokens = len(toklst)//2
                        if gtline1 == gtline2:
                            tp_set.add(n1)
                        else:
                            fp_set.add(n1)
                for n1 in tp_set:
                    toklst = nodefeatures1[n1][-3].split('@*@')
                    num_tokens = len(toklst)//2
                    tp += num_tokens

                for n1 in fp_set:
                    toklst = nodefeatures1[n1][-3].split('@*@')
                    num_tokens = len(toklst)//2
                    fp += num_tokens

                total = 0
                for key in srclines1:
                    if srclines1[key] != "null" and key not in not_found:
                        toklst = nodefeatures1[key][-3].split('@*@')
                        num_tokens = len(toklst)//2
                        total += num_tokens

                prec = tp/(tp+fp)
                recall = tp/total
                print(binary_name, tp, fp, total, prec, recall, 2*prec*recall/(prec+recall))
                return (prec, recall, 2*prec*recall/(prec+recall))  
        except:
            print(traceback.format_exc())
            return None
        
    return None


if __name__ == "__main__":
    evaluate_precision_recall_cross_version_token("/mnt/sata/lian/github/SigmaDiff/out", "/mnt/sata/lian/github/SigmaDiff/data/binaries/diffutils-2.8-O2/cmpstripped", "/mnt/sata/lian/github/SigmaDiff/data/binaries/diffutils-3.6-O2/cmpstripped", "/mnt/sata/lian/github/SigmaDiff/data/sources")


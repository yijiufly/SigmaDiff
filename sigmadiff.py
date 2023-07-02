import os
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from diffing import diff_two_files
from choose_train_nodes import process_two_files
import shutil
import sys
import time
from load_emb import Function
from evaluate import evaluate_precision_recall_cross_optlevel_token, evaluate_precision_recall_cross_version_token
sys.path.append('deep-graph-matching-consensus-batch-decompile')
from TestOwnDataUseModel import processDGMC

def extract_features(filepath, output, ghidra_home, ghidra_proj_name, with_gt=True):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    script_dir = os.path.join(current_dir, 'ghidra_script')
    tmp_dir = os.path.join(current_dir, 'tmp')
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    if not os.path.exists(output):
        os.makedirs(output)
    elif os.path.exists(output+'/addr2funcname.txt'):
        return
    
    if not os.path.exists(os.path.join(output, 'decompiled')):
        os.makedirs(os.path.join(output, 'decompiled'))

    # get ground truth
    if with_gt:
        vsa_command = ghidra_home + "/support/analyzeHeadless " + tmp_dir + " " + ghidra_proj_name + " -import " + filepath[:-8] + " -overwrite -scriptPath " + script_dir + " -postScript CollectGroundTruth.java " + output
        # print(vsa_command)
        os.system(vsa_command)

    # run preprocessing
    print("run scripts: " + time.strftime("%H:%M:%S", time.localtime()))
    vsa_command = ghidra_home + "/support/analyzeHeadless " + tmp_dir + " " + ghidra_proj_name + " -import " + filepath + " -overwrite -scriptPath " + script_dir + " -postScript VSAPCode.java " + output
    # print(vsa_command)
    os.system(vsa_command)
    

def compare_two_bins(filepath1, filepath2, args):
    with_gt = args.with_gt
    output_dir = args.output_dir
    ghidra_home = args.ghidra_home
    src_dir = args.src_dir
    ghidra_proj_name = args.ghidra_proj_name

    if with_gt:
        if "arm" in filepath1:
            os.system("arm-linux-gnueabi-strip -s " + filepath1 + " -o " + filepath1 + "stripped")
        else:
            os.system("strip -s " + filepath1 + " -o " + filepath1 + "stripped")
        if "arm" in filepath2:
            os.system("arm-linux-gnueabi-strip -s " + filepath2 + " -o " + filepath2 + "stripped")
        else:
            os.system("strip -s " + filepath2 + " -o " + filepath2 + "stripped")
        filepath1 += "stripped"
        filepath2 += "stripped"

    filename1 = '_'.join(filepath1.split('/')[-2:]) # e.g., diffutils-2.8-O0_cmpstripped
    filename2 = '_'.join(filepath2.split('/')[-2:])

    output1 = os.path.join(output_dir, filename1)
    output2 = os.path.join(output_dir, filename2)
    compare_out = os.path.join(output_dir, filename1 + '_vs_' + filename2)
    if not os.path.exists(output1):
        os.makedirs(output1)
    if not os.path.exists(output2):
        os.makedirs(output2)

    t0 = time.time()

    # preprocess
    extract_features(filepath1, output1, ghidra_home, ghidra_proj_name, with_gt)
    extract_features(filepath2, output2, ghidra_home, ghidra_proj_name, with_gt)

    # function level diffing
    diff_two_files(output1, output2, compare_out, with_gt)

    # choose training node
    process_two_files(filepath1, filepath2, output1, output2, compare_out, with_gt)

    # run DGMC model
    processDGMC(output_dir, filename1, filename2, args)

    total_time = time.time() - t0

    # evaluate
    if with_gt:
        version1 = filename1.split('_')[0].split('-')[1]
        version2 = filename2.split('_')[0].split('-')[1]
        if version1 == version2:
            prec, recall, f1 = evaluate_precision_recall_cross_optlevel_token(output_dir, filename1, filename2)
        else:
            if src_dir is None:
                print("the directory of source code is needed for cross-version evaluation")
                return None
            prec, recall, f1 = evaluate_precision_recall_cross_version_token(output_dir, filepath1, filepath2, src_dir)
            
        return prec, recall, f1, total_time


if __name__ == "__main__":
    # parse arguments
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='The path of input bin file 1 or a group of bin files')
    parser.add_argument('--input2', required=True, help='The path of input bin file 2 or a group of bin files')
    parser.add_argument('--with_gt', required=True, help='True or False, whether the input has ground truth or not')
    parser.add_argument('--src_dir', required=False, help='The home directory of source code, used for cross-version diffing evaluation')
    parser.add_argument('--ghidra_home', required=True, help='Home directory of Ghidra')
    parser.add_argument('--output_dir', required=True, help='Specify the output directory') 
    parser.add_argument('--ghidra_proj_name', required=True)
    parser.add_argument('--dim', type=int, default=128)
    parser.add_argument('--rnd_dim', type=int, default=32)
    parser.add_argument('--num_layers', type=int, default=3)
    parser.add_argument('--num_steps', type=int, default=5)
    parser.add_argument('--k', type=int, default=25)
    parser.add_argument('--in_channels', type=int, default=128)
    args = parser.parse_args()

    path1 = args.input1
    path2 = args.input2

    # diff a group of binaries
    if os.path.isdir(path1) and os.path.isdir(path2):
        prec_average = []
        recall_average = []
        f1_average = []
        time_average = []
        f = open(os.path.join(args.output_dir, 'finalresults.txt'), 'a')
        path2bin = set(os.listdir(path2))
        for binary in os.listdir(path1):
            if not binary.endswith("stripped") and binary in path2bin:
                ret = compare_two_bins(os.path.join(path1, binary), os.path.join(path2, binary), args)
                if ret is not None:
                    prec, recall, f1, t = ret
                    prec_average.append(prec)
                    recall_average.append(recall)
                    f1_average.append(f1)
                    time_average.append(t)
        print(path1.split('/')[-1] +'_vs_' + path2.split('/')[-1], sum(prec_average)/len(prec_average), sum(recall_average)/len(recall_average), sum(f1_average)/len(f1_average))
        f.write(','.join([path1.split('/')[-1] +'_vs_' + path2.split('/')[-1], str(sum(prec_average)/len(prec_average)), str(sum(recall_average)/len(recall_average)), str(sum(f1_average)/len(f1_average)), str(sum(time_average)/len(time_average))]) + '\n')
        f.close()

    # diff two binaries
    if os.path.isfile(path1) and os.path.isfile(path2):
        compare_two_bins(path1, path2, args)
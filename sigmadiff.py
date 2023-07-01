import os
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from diffing import diff_two_files
from choose_train_nodes import process_two_files
import shutil
import sys
import time
from load_emb import Function
sys.path.append('deep-graph-matching-consensus-batch-decompile')
from TestOwnDataUseModel import processDGMC

def extract_features(filepath, output, ghidra_home, with_gt=True):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    script_dir = os.path.join(current_dir, 'ghidra_script')
    # script_dir = "/home/administrator/ghidra_script"
    tmp_dir = os.path.join(current_dir, 'tmp')
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    if not os.path.exists(output):
        os.makedirs(output)
    if not os.path.exists(os.path.join(output, 'decompiled')):
        os.makedirs(os.path.join(output, 'decompiled'))

    # get ground truth
    if with_gt:
        vsa_command = ghidra_home + "/support/analyzeHeadless " + tmp_dir + " utils -import " + filepath[:-8] + " -overwrite -scriptPath " + script_dir + " -postScript CollectGroundTruth.java " + output
        # print(vsa_command)
        os.system(vsa_command)

    # run preprocessing
    print("run scripts: " + time.strftime("%H:%M:%S", time.localtime()))
    vsa_command = ghidra_home + "/support/analyzeHeadless " + tmp_dir + " utils -import " + filepath + " -overwrite -scriptPath " + script_dir + " -postScript VSAPCode.java " + output
    # print(vsa_command)
    os.system(vsa_command)
    

def main():
    # parse arguments
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    parser.add_argument('--input2', required=True, help='Input bin file 2')
    parser.add_argument('--with_gt', required=True, help='True or False, whether the input has ground truth or not')
    parser.add_argument('--ghidra_home', required=True, help='Home directory of Ghidra')
    parser.add_argument('--output_dir', required=True, help='Specify the output directory') 
    parser.add_argument('--dim', type=int, default=128)
    parser.add_argument('--rnd_dim', type=int, default=32)
    parser.add_argument('--num_layers', type=int, default=3)
    parser.add_argument('--num_steps', type=int, default=5)
    parser.add_argument('--k', type=int, default=25)
    parser.add_argument('--in_channels', type=int, default=128)
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    with_gt = args.with_gt
    output_dir = args.output_dir
    ghidra_home = args.ghidra_home


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

    filename1 = '_'.join(filepath1.split('/')[-2:])
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
    # extract_features(filepath1, output1, ghidra_home, with_gt)
    # extract_features(filepath2, output2, ghidra_home, with_gt)

    # function level diffing
    # diff_two_files(output1, output2, compare_out, with_gt)

    # choose training node
    # process_two_files(filepath1, filepath2, output1, output2, compare_out, with_gt)

    # run DGMC model
    processDGMC(output_dir, filename1, filename2, args)

    # total_time = time.time() - t0
    # with open(os.path.join(compare_out, 'elapsedtime.txt'), 'w') as f:
    #     f.write(str(total_time))

if __name__ == "__main__":
    main()
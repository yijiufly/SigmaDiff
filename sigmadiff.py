import os
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from diffing import diff_two_files, get_subgraph_funcs
from choose_train_nodes import process_two_files
import shutil
import sys
import time
from load_emb import Function
sys.path.append('deep-graph-matching-consensus-batch-decompile')
from TestOwnDataUseModel import processDGMC

def extract_features(filepath, output, ghidra_home, large_bin=False):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    script_dir = os.path.join(current_dir, 'ghidra_script')
    # script_dir = "/home/administrator/ghidra_script"
    tmp_dir = os.path.join(current_dir, 'tmp')
    # tmp_dir = "/home/administrator/ghidra"
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    else:
        for files in os.listdir(tmp_dir):
            path = os.path.join(tmp_dir, files)
            try:
                shutil.rmtree(path)
            except OSError:
                os.remove(path)
    if not os.path.exists(output):
        os.makedirs(output)
    if not os.path.exists(os.path.join(output, 'decompiled')):
        os.makedirs(os.path.join(output, 'decompiled'))
    t0 = time.time()
    print("run scripts: " + time.strftime("%H:%M:%S", time.localtime()))
    usePreScript = False
    if usePreScript:
        vsa_command = ghidra_home + "/support/analyzeHeadless " + tmp_dir + " utils -import " + filepath + " -scriptPath " + script_dir + " -preScript DisableAutoAnalysisOptions.java -postScript VSAPCode.java " + output + " " + str(large_bin)
    else:
        vsa_command = ghidra_home + "/support/analyzeHeadless " + tmp_dir + " utils -import " + filepath + " -scriptPath " + script_dir + " -postScript VSAPCode.java " + output + " " + str(large_bin)
    os.system(vsa_command)
    total_time = time.time() - t0
    with open(os.path.join(output, 'elapsedtime.txt'), 'w') as f:
        f.write(str(total_time))

def main():
    # example args: ["--input1", "/home/administrator/Downloads/Lian/SigmaDiff/data/Zoom-5.9.31911/libturbojpegstripped.so", "--input2", "/home/administrator/Downloads/Lian/SigmaDiff/data/turbojpeg-2.1.2/libturbojpegstripped.so", "--ghidra_home", "/home/administrator/Downloads/Lian/ghidra_9.2.2_PUBLIC", "--output_dir", "/home/administrator/Downloads/Lian/SigmaDiff/out"]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    parser.add_argument('--input2', required=True, help='Input bin file 2')
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
    output_dir = args.output_dir
    ghidra_home = args.ghidra_home
    large_bin = False
    
    filename1 = '_'.join(filepath1.split('/')[-2:])
    filename2 = '_'.join(filepath2.split('/')[-2:])
    output1 = os.path.join(output_dir, filename1)
    output2 = os.path.join(output_dir, filename2)
    compare_out = os.path.join(output_dir, filename1 + '_vs_' + filename2)
    if not os.path.exists(output1):
        os.makedirs(output1)
    if not os.path.exists(output2):
        os.makedirs(output2)
    # if large_bin:
    #     get_subgraph_funcs(output1, output2, os.path.join(output1, filename1.split('_')[-1]), os.path.join(output2, filename2.split('_')[-1]))
    # extract features
    # if not filepath1.endswith('zoom'):
    extract_features(filepath1, output1, ghidra_home, large_bin)
    extract_features(filepath2, output2, ghidra_home)

    # function level diffing
    # large_bin = True
    diff_two_files(output1, output2, compare_out, large_bin)

    # choose training node
    process_two_files(output1, output2, compare_out)

    # run DGMC model
    processDGMC(output_dir, filename1, filename2, args)

if __name__ == "__main__":
    main()
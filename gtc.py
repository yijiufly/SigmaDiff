import os
import errno
import ntpath
import subprocess

identicalFiles = {}
differFiles = {}


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def doDiff(old_dir, new_dir, output_file):
    cmd = 'diff -q -s -r {} {}'.format(old_dir, new_dir)
    # print(cmd)
    if not os.path.exists(os.path.dirname(output_file)):
        try:
            os.makedirs(os.path.dirname(output_file))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    with open(output_file, 'w+') as diffResult:
        p = subprocess.Popen(cmd, shell=True, stdout=diffResult, close_fds=True)
        p.wait()
    return output_file



def outputDebugInfo(bin_file, output_file):
    cmd = 'readelf --debug-dump=decodedline {}'.format(bin_file)
    if not os.path.exists(os.path.dirname(output_file)):
        try:
            os.makedirs(os.path.dirname(output_file))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    with open(output_file, 'w+') as debugInfo:
        p = subprocess.Popen(cmd, shell=True, stdout=debugInfo, close_fds=True)
        p.wait()
    return output_file


def invokeJava(diffResult, old_debug_info, new_debug_info, old_dir, new_dir):
    cmd = 'cd ./bin/; java diffutils.gtc {} {} {} {} {}'.format(diffResult, old_debug_info, new_debug_info, old_dir, new_dir)
    # print(cmd)
    # f = open("debug.txt", "w")
    # subprocess.Popen(cmd, shell=True, close_fds=True)
    # f.close()
    os.system(cmd)


def isDifforIdentical(diff):
    differ = " differ"
    identical = " are identical"
    dif = diff.endswith(differ)
    iden = diff.endswith(identical)
    return dif, iden

def processDiff(diff):
    old = ''
    new = ''
    strs = diff.split(' ')
    # print('str: ' + diff)
    for strr in strs:
        if strr.endswith('.c') is True or strr.endswith('.cpp') is True:
            if old == '':
                old = strr
            elif new == '':
                new =strr
    return old, new
    


if __name__ == "__main__":
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    #Example: python gtc.py --old_dir ~/yueduan/groundTruthCollection/input/minieap-0.91/ --new_dir ~/yueduan/groundTruthCollection/input/minieap-0.92.1/ --old_bin ~/yueduan/groundTruthCollection/input/minieap_91 --new_bin ~/yueduan/groundTruthCollection/input/minieap_92 --output_dir ~/yueduan/groundTruthCollection/output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--old_dir', required=True, help='Input old source code directory')                        
    parser.add_argument('--new_dir', required=True, help='Input new source code directory')
    parser.add_argument('--old_bin', required=True, help='Specify the path to old binary')
    parser.add_argument('--new_bin', required=True, help='Specify the path to new binary')
    parser.add_argument('--output_dir', required=True, help='Specify the path to output binary')
    args = parser.parse_args()
    old_dir = args.old_dir
    new_dir = args.new_dir
    old_bin = args.old_bin
    new_bin = args.new_bin
    output_dir = args.output_dir

    if old_dir.endswith('/') is False:
        old_dir = old_dir + '/'

    if new_dir.endswith('/') is False:
        new_dir = new_dir + '/'

    if output_dir.endswith('/') is False:
        output_dir = output_dir + '/'

    diffResult = doDiff(old_dir, new_dir, output_dir + 'diffResult')
    old_debug_info = outputDebugInfo(old_bin, output_dir + 'old_debug_info')
    new_debug_info = outputDebugInfo(new_bin, output_dir + 'new_debug_info')
    invokeJava(diffResult, old_debug_info, new_debug_info, old_dir, new_dir)
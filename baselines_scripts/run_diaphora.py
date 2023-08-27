# This script run diaphora automatically and stores the function level results in sqlite files
# It runs on windows system
import os
import time
import shutil

DIAPHORA_PATH = "python C:\\Users\\yijiufly\\Desktop\\Diaphora\\diaphora-master\\diaphora-master\\diaphora.py"
OUTPATH_BASE = 'C:\\Users\\yijiufly\\Desktop\\Diaphora\\archive\\diff_'
BIN_PATH = 'C:\\Users\\yijiufly\\Desktop\\Diaphora\\archive\\'
IDAPro_PATH = 'C:\\Users\\yijiufly\\Desktop\\IDAPro7.5_installer\\idat64.exe'
bin_lst = ["[", "chown", "df", "factor", "join", "mknod", "paste", "realpath", "sha512sum", "sum", "true", "users",
          "b2sum", "chroot", "dir", "false", "kill", "mktemp", "pathchk", "rm", "shred", "sync", "truncate", "vdir",
          "base32", "cksum", "dircolors", "fmt", "link", "mv", "pinky", "rmdir", "shuf", "tac", "tsort", "wc",
          "base64", "comm", "dirname", "fold", "ln", "nice", "pr", "runcon", "sleep", "tail", "tty", "who",
          "basename", "cp", "du", "groups", "logname", "nl", "printenv", "seq", "sort", "tee", "uname", "whoami", "cat", "csplit", "echo", "head", "ls", "nohup", "printf", "sha1sum", "split", "test", "unexpand", "yes",
          "chcon", "cut", "env", "hostid", "md5sum", "nproc", "ptx", "sha224sum", "stat", "timeout", "uniq",
          "chgrp", "date", "expand", "id", "mkdir", "numfmt", "pwd", "sha256sum", "stdbuf", "touch", "unlink",
          "chmod", "dd", "expr", "install", "mkfifo", "od", "readlink", "sha384sum", "stty", "tr", "uptime", "getlimits", "ginstall"]

group_names = ['coreutils']
for group_name in group_names:
    OUTPATH = OUTPATH_BASE + group_name
    if not os.path.exists(OUTPATH):
        os.mkdir(OUTPATH)
    start = time.time()
    timecsv=open('time.csv','a')
    for parent, subdirs, files in os.walk(BIN_PATH + group_name):
        if files:
            for f in files:
                if f.endswith('_stripped'):
                    shutil.move(os.path.join(parent, f), os.path.join(parent, f[:-9]))
                    f = f[:-9]
                if f in bin_lst:
                    cmd = IDAPro_PATH + ' -B ' + os.path.abspath(os.path.join(parent, f))
                    if not os.path.exists(os.path.abspath(os.path.join(parent, f+'.i64'))):
                        os.system(cmd)
                        print(cmd)
                        timecsv.write('Preprocess1,'+f+','+str(time.time()-start)+'\n')
                        timecsv.flush()

    # need to replace the paths to ida pro and diaphora
    run_diaphora = '''export DIAPHORA_AUTO=1
    export DIAPHORA_EXPORT_FILE={}
    export DIAPHORA_USE_DECOMPILER=1 # optionally, use the decompiler
    echo $DIAPHORA_EXPORT_FILE
    C:\\\\Users\\\\yijiufly\\\\Desktop\\\\IDAPro7.5_installer\\\\ida64.exe -A -SC:\\\\Users\\\\yijiufly\\\\Desktop\\\\Diaphora\\\\diaphora-master\\\\diaphora-master\\\\diaphora.py {}
    '''

    bin_dic = {}
    start = time.time()
    for parent, subdirs, files in os.walk(BIN_PATH + group_name):
        if files:
            for f in files:
                if os.path.splitext(f)[0] in bin_lst:
                    if os.path.splitext(f)[-1][1:] == 'i64':
                        exportfile = os.path.abspath(os.path.join(parent, f[:-3] + 'sqlite')).replace('\\', '\\\\')
                        if os.path.exists(os.path.abspath(os.path.join(parent, f[:-3] + 'sqlite'))):
                            continue
                        file_content = run_diaphora.format(exportfile, os.path.abspath(os.path.join(parent, f)).replace('\\', '\\\\'))
                        with open('runDiaphora.sh','w') as f2:
                            f2.write(file_content)
                        cmd = '.\\runDiaphora.sh'
                        start = time.time()
                        os.system(cmd)
                        print(exportfile)
                        timecsv.write('Preprocess2,'+f+','+str(time.time()-start)+'\n')
                        timecsv.flush()

    for parent, subdirs, files in os.walk(BIN_PATH + group_name):
        if files:
            for f in files:
                if os.path.splitext(f)[0] in bin_lst:
                    if os.path.splitext(f)[-1][1:] == 'sqlite':
                        bin_name = os.path.splitext(f)[0]
                        if bin_name in bin_dic:
                            bin_dic[bin_name].append(os.path.abspath(os.path.join(parent, f)))
                        else:
                            bin_dic[bin_name] = [os.path.abspath(os.path.join(parent, f))]
    print(bin_dic)

    for binary, lst in bin_dic.items():
        for path in lst[:-1]:
            dir_name = "_".join([path.split('\\')[-2], binary]) + '_' + "_".join([lst[-1].split('\\')[-2], binary])
            if not os.path.exists(os.path.join(OUTPATH, dir_name)):
                os.mkdir(os.path.join(OUTPATH, dir_name))
            print(os.path.join(OUTPATH, dir_name, binary + '_vs_' + binary + '.diaphora'))
            if os.path.exists(os.path.join(OUTPATH, dir_name, binary + '_vs_' + binary + '.diaphora')):
                continue
            cmd = DIAPHORA_PATH + ' ' + path + ' ' + lst[-1] + ' -o ' + os.path.join(OUTPATH, dir_name, binary + '_vs_' + binary + '.diaphora')
            start = time.time()
            os.system(cmd)
            print(cmd)
            timecsv.write(cmd+','+str(time.time()-start)+'\n')
            timecsv.flush()
	
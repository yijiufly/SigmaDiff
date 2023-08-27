import os
import sqlite3
import pandas as pd
import errno
import subprocess
import traceback
TARGETDB = 'diaphora'

def evaluate_function_level_match():
    root_path = 'diaphoraresults/'
    bindiff_lst = []
    for parent, subdir, files in os.walk(root_path + 'diff_coreutils'):
        if files:
            for f in files:
                if f.endswith(TARGETDB):
                    bindiff_lst.append(os.path.abspath(os.path.join(parent, f)))

    for bindiff_file in bindiff_lst:
        paras = bindiff_file.split('/')[-2].split('_')

        if len(paras) == 4:
            version1 = paras[0]
            version2 = paras[2]
            file1 = paras[1]
        if len(paras) > 4:
            length = len(paras)
            version1 = paras[0]
            version2 = paras[length//2]
            file1 = '_'.join(paras[1:length//2])
        if os.path.exists(root_path + file1 + '_' + version1 + '_vs_' + version2 + '.csv'):
            continue
        # # bindiff
        # if TARGETDB == 'BinDiff':
        #     conn = sqlite3.connect(bindiff_file)
        #     cursor = conn.cursor()
        #     values = cursor.execute("SELECT address1, address2 FROM function")
        #     dataFrame = pd.DataFrame.from_records(cursor.fetchall(), columns=['address1', 'address2'])
        #     bindiff_lst = [list(i) for i in dataFrame.get_values()]
        #     conn.close()

        # diaphora
        if TARGETDB == 'diaphora':
            try:
                conn = sqlite3.connect(bindiff_file)
                print(bindiff_file)
                cursor = conn.cursor()
                values = cursor.execute("SELECT address, address2 FROM results")
                dataFrame = pd.DataFrame.from_records(cursor.fetchall(), columns=['address', 'address2'])
                # bindiff_lst = [list(i) for i in dataFrame.get_values()]
                bindiff_lst = [list(i) for i in list(dataFrame.to_numpy())]

                conn.close()
            except:
                print(traceback.format_exc())
                print("no results file")
                continue

        with open(root_path + file1 + '_' + version1 + '_vs_' + version2 + '.csv', 'w') as f:
            for addr1, addr2 in bindiff_lst:
                f.write(addr1 + ', ' + addr2 + '\n')

if __name__ == "__main__":
    evaluate_function_level_match()
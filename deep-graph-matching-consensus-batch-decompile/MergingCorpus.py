import os

def MergingCorpus(subject_path,subject,conf_1,conf_2):

    corpus_file=open(subject_path+'ALLCorpus.txt','w')

    # file_1=open(subject_path+"coreutils-5.93-O1_"+subject+'_corpus.txt','r')
    # file_2=open(subject_path+"coreutils-5.93-O2_"+subject+'_corpus.txt','r')

    # file_1=open(subject_path+"coreutils-5.93-O1_"+subject+'_corpus.txt','r')
    # file_2=open(subject_path+"coreutils-5.93-O3_"+subject+'_corpus.txt','r')

    # file_1=open(subject_path+"coreutils-5.93-O0_"+subject+'_corpus.txt','r')
    # file_2=open(subject_path+"coreutils-5.93-O3_"+subject+'_corpus.txt','r')

    # file_1=open(subject_path+"coreutils-5.93-O2_"+subject+'_corpus.txt','r')
    # file_2=open(subject_path+"coreutils-6.4-O2_"+subject+'_corpus.txt','r')

    file_1=open(subject_path+conf_1+"_"+subject+'_corpus.txt','r')
    file_2=open(subject_path+conf_2+"_"+subject+'_corpus.txt','r')

    lines=file_1.readlines()
    for each_line in lines:
        corpus_file.write(each_line)

    lines=file_2.readlines()
    for each_line in lines:
        corpus_file.write(each_line)


    # subjects=os.listdir(subject_dir)
    # for subject in subjects:
    #     subject_path=subject_dir+'/'+subject+'/'

    #     file_1=open(subject_path+"coreutils-5.93-O2_"+subject+'_corpus.txt','r')
    #     file_2=open(subject_path+"coreutils-5.93-O3_"+subject+'_corpus.txt','r')

    #     lines=file_1.readlines()
    #     for each_line in lines:
    #         corpus_file.write(each_line)

    #     lines=file_2.readlines()
    #     for each_line in lines:
    #         corpus_file.write(each_line)

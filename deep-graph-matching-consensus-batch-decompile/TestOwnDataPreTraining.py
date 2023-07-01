import os
from data_utils_doc2vec import Corpus
from MergingCorpus import *
from Doc2Vec import *
from pytorchtools import EarlyStopping

import torch
import torch.nn as nn

from dgmc.models import DGMC, RelCNN
import argparse

corpus_dir="casestudy"
configs=os.listdir(corpus_dir)

# subject_dir="coreutils-5.93-O1_vs_coreutils-5.93-O2"
# subject_dir="coreutils-5.93-O1_vs_coreutils-5.93-O3"
# subject_dir="coreutils-5.93-O2_vs_coreutils-6.4-O2"
# subject_dir="coreutils-5.93-O0_vs_coreutils-5.93-O3"

for each_conf in configs:
    subject_dir=corpus_dir+'/'+each_conf

    print(each_conf)
    
    if (each_conf!='llvm_3_7_0_vs_llvm_3_8_1'):
       continue

    conf_1=each_conf.split('_vs_')[0]
    conf_2=each_conf.split('_vs_')[1]

    subjects=os.listdir(subject_dir)

    time_1=datetime.datetime.now()
    date_string=time_1.strftime('%b--%d')

    result_file=open(subject_dir.replace('/','--')+'-'+date_string+'_PreTraining_Results.csv','w')
    result_file.write('System,TrainingNodePercent,FinalAccuracy,Time,EarlyStop\n')
    result_file.flush()

    # size_file=open('Subject_Size.csv','w')

    for index,subject in enumerate(subjects):

        if(not subject=='not'):
            continue

        start_time=datetime.datetime.now()

        subject_path=subject_dir+'/'+subject+'/'

        print(subject)

        MergingCorpus(subject_path,subject,conf_1,conf_2)
        Doc2VecModelBuilding(subject_path)
        
        node_label_file_1=subject_path+conf_1+"_"+subject+"_nodelabel.txt"
        edge_file_1=subject_path+conf_1+"_"+subject+"_edges.txt"
        node_label_file_2=subject_path+conf_2+"_"+subject+"_nodelabel.txt"
        edge_file_2=subject_path+conf_2+"_"+subject+"_edges.txt"
        training_file=subject_path+"training_nodes.txt"
        func_matching_file=subject_path+"matched_functions.txt"
        ###############################################################

        device = 'cuda' if torch.cuda.is_available() else 'cpu'

        parser = argparse.ArgumentParser()
        parser.add_argument('--dim', type=int, default=128)
        parser.add_argument('--rnd_dim', type=int, default=32)
        parser.add_argument('--num_layers', type=int, default=3)
        parser.add_argument('--num_steps', type=int, default=10)
        parser.add_argument('--k', type=int, default=25)
        parser.add_argument('--in_channels', type=int, default=128)
        args = parser.parse_args()

        corpus = Corpus()
        
        ids_1,edges_1,ids_2,edges_2,train_y,source_type_list,dst_type_list,source_lineNum_list,dst_lineNum_list,func_matching_dict,src_func_dict,des_func_dict,source_value_dict,dst_value_dict,source_decompile_dict,dst_decompile_dict,un_matched_list, node_mapping1, node_mapping2 = corpus.get_data(node_label_file_1,edge_file_1,node_label_file_2,edge_file_2,training_file,func_matching_file,subject_path)
        vocab_size = len(corpus.dictionary)

        print(ids_1.size())

        all_nodes=float(ids_1.size()[0])
        training_nodes=float(train_y.size()[0])
        print(all_nodes)
        print(training_nodes)
        print(float(training_nodes)/all_nodes)

        # size_file.write(subject+','+str(all_nodes)+','+str(training_nodes)+'\n')
        # size_file.flush()

        print(edges_1.size())
        print(ids_2.size())
        print(edges_2.size())


        edge_index_1=edges_1.t()
        print(edge_index_1.size())

        edge_index_2=edges_2.t()
        train_y=train_y.t()
        print(train_y.size())

        if node_mapping1 is None:
            node_mapping1 = {ids:ids for ids in range(len(ids_1))}
            node_mapping2 = {ids:ids for ids in range(len(ids_2))}
        else:
            node_mapping1 = {node_mapping1[key]:key for key in node_mapping1.keys()}
            node_mapping2 = {node_mapping2[key]:key for key in node_mapping2.keys()}

        ids_1=ids_1.to(device)
        edge_index_1=edge_index_1.to(device)
        ids_2=ids_2.to(device)
        edge_index_2=edge_index_2.to(device)
        train_y=train_y.to(device)
        

        psi_1 = RelCNN(args.in_channels, args.dim, args.num_layers, batch_norm=False,
                    cat=True, lin=True, dropout=0.5, further_propogate=True)
        psi_2 = RelCNN(args.rnd_dim, args.rnd_dim, args.num_layers, batch_norm=False,
                    cat=True, lin=True, dropout=0.0, further_propogate=False)
        model = DGMC(psi_1, psi_2, num_steps=None, vocab_size=vocab_size, k=args.k).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

        result_dir=subject_dir.replace('/','--')+'_Pretrain'

        patience = 50	# 当验证集损失在连续50次训练周期中都没有得到降低时，停止模型训练，以防止模型过拟合
        early_stopping = EarlyStopping(patience, verbose=True)

        def train():
            model.train()
            optimizer.zero_grad()
            
            _, S_L = model(ids_1, edge_index_1, None, None, ids_2,
                        edge_index_2, None, None, train_y)

            loss = model.loss(S_L, train_y, source_type_list, dst_type_list, source_value_dict, dst_value_dict, source_decompile_dict, dst_decompile_dict, source_lineNum_list, dst_lineNum_list)

            loss.backward()
            optimizer.step()
            return loss

        @torch.no_grad()
        def test(final=False):
            model.eval()
            _, S_L = model(ids_1, edge_index_1, None, None, ids_2,
                        edge_index_2, None, None)

            accuracy = model.accdiff(S_L, source_lineNum_list,dst_lineNum_list,func_matching_dict,src_func_dict,des_func_dict,source_type_list,dst_type_list,un_matched_list,source_value_dict,dst_value_dict,subject_path,result_dir, node_mapping1, node_mapping2, final)
            return accuracy


        print('Optimize initial feature matching...')
        model.num_steps = 0
        for epoch in range(1, 1201):

            if epoch == 1001:
                print('Refine correspondence matrix...')
                model.num_steps = args.num_steps
                model.detach = True
                end_time=datetime.datetime.now()
                accuracy=test(final=True)
                result_file.write(subject+','+str(float(training_nodes)/all_nodes)+','+str(accuracy)+','+str((end_time-start_time).total_seconds())+',Yes\n')
                result_file.flush()

                f_model=open(each_conf+'_Trained_Model.pkl','wb')
                pickle.dump(model, f_model, protocol = 4)

            loss = train()
            early_stopping(loss, model)
            # 若满足 early stopping 要求
            if early_stopping.early_stop:
                print("Early stopping")
                # 结束模型训练
                end_time=datetime.datetime.now()
                accuracy=test(final=True)
                result_file.write(subject+','+str(float(training_nodes)/all_nodes)+','+str(accuracy)+','+str((end_time-start_time).total_seconds())+',Yes\n')
                result_file.flush()

                f_model=open(each_conf+'_Trained_Model.pkl','wb')
                pickle.dump(model, f_model, protocol = 4)
                break

            if epoch == 1200:
                accuracy=test(final=True)
                end_time=datetime.datetime.now()
                result_file.write(subject+','+str(float(training_nodes)/all_nodes)+','+str(accuracy)+','+str((end_time-start_time).total_seconds())+',No\n')
                result_file.flush()

                f_model=open(each_conf+'_Trained_Model.pkl','wb')
                pickle.dump(model, f_model, protocol = 4)
                break

            if epoch % 10 == 0:
                accuracy=test()
                print(subject_path+':'+(f'{epoch:03d}: Loss: {loss:.4f}'))
                end_time=datetime.datetime.now()
                result_file.write(subject+','+str(float(training_nodes)/all_nodes)+','+str(accuracy)+','+str((end_time-start_time).total_seconds())+',Yes\n')
                result_file.flush()
                f_model=open(each_conf+'_Trained_Model.pkl','wb')
                pickle.dump(model, f_model, protocol = 4)
            
        
        del model
        del ids_1,edges_1,ids_2,edges_2
        del early_stopping
        torch.cuda.empty_cache()

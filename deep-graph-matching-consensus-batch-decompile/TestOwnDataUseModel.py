import os
# from data_utils import Corpus
# from data_utils_word2vec import Corpus
# from data_utils_doc2vec import Corpus
from data_utils_doc2vec_usemodel import Corpus
from MergingCorpus import *
from Doc2Vec import *
from pytorchtools import EarlyStopping

import torch
import torch.nn as nn

from dgmc.models import DGMC, RelCNN


model_path = 'llvm_3_7_0_vs_llvm_3_8_1'

def processDGMC(dir, filename1, filename2, args):
    print(dir, filename1, filename2, args)
    
    each_conf =  filename1 + '_vs_' + filename2
    subject_dir=dir+'/'+each_conf

    print(each_conf)

    # if(not os.path.exists(each_conf+'_Trained_Model.pkl')):
    #     continue

    time_1=datetime.datetime.now()
    date_string=time_1.strftime('%b--%d')

    # result_file=open(subject_dir+'-'+date_string+'_UseModel_Results.csv','w')
    # result_file=open(subject_dir.replace('/','--')+'-'+date_string+'_UseModel_FurtherTraining_Results.csv','w')
    # result_file.write('System,TrainingNodePercent,FinalAccuracy,Time,EarlyStop\n')
    # result_file.flush()

    start_time=datetime.datetime.now()

    subject_path=subject_dir+'/'
    
    ###############################################################
    node_label_file_1= os.path.join(subject_path, filename1 + "_nodelabel.txt")
    edge_file_1= os.path.join(subject_path, filename1 + "_edges.txt")
    node_label_file_2= os.path.join(subject_path, filename2 + "_nodelabel.txt")
    edge_file_2= os.path.join(subject_path, filename2 + "_edges.txt")
    training_file=subject_path+"training_nodes.txt"
    func_matching_file=subject_path+"matched_functions.txt"
    ###############################################################

    device = 'cuda' if torch.cuda.is_available() else 'cpu'

    # use pretrained doc2vec
    corpus = Corpus()
    current_dir = os.path.dirname(os.path.realpath(__file__))
    pretrained_subject = os.path.join(current_dir, 'casestudy/llvm_3_7_0_vs_llvm_3_8_1/not')
    ids_1_list,edges_1_list,ids_2_list,edges_2_list,train_y_list,source_type_list_list,dst_type_list_list,source_lineNum_list_list,dst_lineNum_list_list,func_matching_dict_list,src_func_dict_list,des_func_dict_list,source_value_dict_list,dst_value_dict_list,source_decompile_dict_list,dst_decompile_dict_list, node_mapping1_list, node_mapping2_list = corpus.get_data(node_label_file_1,edge_file_1,node_label_file_2,edge_file_2,training_file,func_matching_file,subject_dir,pretrained_subject)
    vocab_size = len(corpus.dictionary)
    subject_name=subject_path.strip('/').replace('/','-')
    result_dir=subject_dir+'_Finetuned-results'

    if(not os.path.exists(result_dir)):
        os.mkdir(result_dir)

    match_file=open(result_dir+'/'+subject_name+'-match_result.txt','w')
    before_filtering_match=open(result_dir+'/'+subject_name+'-Initial_match_result.txt','w')
    match_file.close()
    before_filtering_match.close()
    indexes = list(range(len(ids_1_list)))
    indexes.reverse()
    for i in indexes:
        ids_1 = ids_1_list[i]
        edges_1 = edges_1_list[i]
        ids_2 = ids_2_list[i]
        edges_2 = edges_2_list[i]
        train_y = train_y_list[i]
        source_type_list = source_type_list_list[i]
        dst_type_list = dst_type_list_list[i]
        source_lineNum_list = source_lineNum_list_list[i]
        dst_lineNum_list = dst_lineNum_list_list[i]
        func_matching_dict = func_matching_dict_list[i]
        src_func_dict = src_func_dict_list[i]
        des_func_dict = des_func_dict_list[i]
        source_value_dict = source_value_dict_list[i]
        dst_value_dict = dst_value_dict_list[i]
        source_decompile_dict = source_decompile_dict_list[i]
        dst_decompile_dict = dst_decompile_dict_list[i]
        
        if node_mapping1_list is None:
            node_mapping1 = {ids:ids for ids in range(len(ids_1))}
            node_mapping2 = {ids:ids for ids in range(len(ids_2))}
        else:
            node_map1 = node_mapping1_list[i]
            node_map2 = node_mapping2_list[i]
            node_mapping1 = {node_map1[key]:key for key in node_map1.keys()}
            node_mapping2 = {node_map2[key]:key for key in node_map2.keys()}
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

            accuracy = model.accdiff(S_L, source_lineNum_list,dst_lineNum_list,func_matching_dict,src_func_dict,des_func_dict,source_type_list,dst_type_list,None,source_value_dict,dst_value_dict,subject_path,result_dir, node_mapping1, node_mapping2,final)
            return accuracy

        print(ids_1.size())
        print(ids_2.size())

        all_nodes=float(ids_1.size()[0])
        training_nodes=float(train_y.size()[0])
        print(all_nodes)
        print(training_nodes)
        print(float(training_nodes)/all_nodes)

        print(edges_1.size())
        print(ids_2.size())
        print(edges_2.size())

        edge_index_1=edges_1.t()
        print(edge_index_1.size())

        edge_index_2=edges_2.t()
        train_y=train_y.t()
        print(train_y.size())

        ids_1=ids_1.to(device)
        edge_index_1=edge_index_1.to(device)
        ids_2=ids_2.to(device)
        edge_index_2=edge_index_2.to(device)
        train_y=train_y.to(device)

        f_model=open(os.path.join(current_dir, model_path+'_Trained_Model.pkl'),'rb')
        model = pickle.load(f_model)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

        patience = 30	# 当验证集损失在连续30次训练周期中都没有得到降低时，停止模型训练，以防止模型过拟合
        early_stopping = EarlyStopping(patience, verbose=True)

        result_dir=subject_dir+'_Finetuned'

        print('Optimize initial feature matching...')
        model.num_steps = 0
        model.detach = False
        for epoch in range(1, 161):
            if epoch == 140:
                print('Refine correspondence matrix...')
                model.num_steps = args.num_steps
                model.detach = True


            loss = train()
            early_stopping(loss, model)
            # 若满足 early stopping 要求
            if early_stopping.early_stop:
                print("Early stopping")
                # 结束模型训练
                # end_time=datetime.datetime.now()
                accuracy=test(final=True)
                # result_file.write(each_conf+','+str(float(training_nodes)/all_nodes)+','+str(accuracy)+','+str((end_time-start_time).total_seconds())+',Yes\n')
                # result_file.flush()
                break

            if epoch == 160:
                # end_time=datetime.datetime.now()

                accuracy=test(final=True)
                # result_file.write(each_conf+','+str(float(training_nodes)/all_nodes)+','+str(accuracy)+','+str((end_time-start_time).total_seconds())+',No\n')
                # result_file.flush()

                f_model=open('Trained_Model.pkl','wb')
                pickle.dump(model, f_model, protocol = 4)

            if epoch % 10 == 0 or epoch > 160:
                accuracy=test()
                print(subject_path+':'+(f'{epoch:03d}: Loss: {loss:.4f}'))
        
        del model
        del ids_1,edges_1,ids_2,edges_2
        del early_stopping
        torch.cuda.empty_cache()

if __name__ == "__main__":
    processDGMC("/mnt/sata/lian/github/SigmaDiff/out", "diffutils-2.8-O0_cmpstripped", "diffutils-2.8-O3_cmpstripped", None)
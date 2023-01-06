from networkx.classes import graph
import torch
import os
import numpy as np
import pickle
from collections import defaultdict

class Dictionary(object):
    def __init__(self):
        self.word2idx = {}
        self.idx2word = {}
        self.idx = 0
    
    def add_word(self, word):
        if not word in self.word2idx:
            self.word2idx[word] = self.idx
            self.idx2word[self.idx] = word
            self.idx += 1
    
    def __len__(self):
        return len(self.word2idx)


class Corpus(object):
    def __init__(self):
        self.dictionary = Dictionary()

    def get_data(self, node_label_file_1,edge_file_1,node_label_file_2,edge_file_2,training_file,func_matching_file,subject_path):

        f_model=open(subject_path+'Doc2Vec_Model.pkl','rb')
        model = pickle.load(f_model)

        func_matching=open(func_matching_file,'r')
        lines=func_matching.readlines()
        func_matching_dict={}
        func_matching_list = []
        for each_line in lines:
            records=each_line.strip().split(' ')
            func_matching_dict[records[0]]=records[1]
            func_matching_list.append((records[0], records[1]))



        last_node_seq_1=0
        last_node_seq_2=0

        # embedding_seq_1=[]
        # embedding_seq_2=[]

        src_func_node_list=defaultdict(list)
        des_func_node_list=defaultdict(list)
        src_func_dict={}
        des_func_dict={}
        this_func=''

        label_file=open(node_label_file_1,'r')
        lines=label_file.readlines()
        for each_line in lines:
            if(each_line.startswith('#')):
                this_func=each_line.strip().strip('#')
                continue
            records=each_line.strip().split('|&|')

            node_seq=int(records[0])
            src_func_dict[node_seq]=this_func
            src_func_node_list[this_func].append(node_seq)

            if(node_seq>last_node_seq_1):
                last_node_seq_1=node_seq

            token=records[1]
            token_type=records[2]

            # token_list=token.split(' ')
            # this_embedding=model.infer_vector(token_list)
            # embedding_seq_1.append(this_embedding)

        label_file=open(node_label_file_2,'r')
        lines=label_file.readlines()
        for each_line in lines:
            if(each_line.startswith('#')):
                this_func=each_line.strip().strip('#')
                continue
            records=each_line.strip().split('|&|')

            node_seq=int(records[0])
            des_func_dict[node_seq]=this_func
            des_func_node_list[this_func].append(node_seq)

            if(node_seq>last_node_seq_2):
                last_node_seq_2=node_seq

            token=records[1]
            token_type=records[2]

            # token_list=token.split(' ')
            # this_embedding=model.infer_vector(token_list)
            # embedding_seq_2.append(this_embedding)
        
        embedding_seq_1=[0.0 for x in range(0,last_node_seq_1+1)]
        embedding_seq_2=[0.0 for x in range(0,last_node_seq_2+1)]
        
        source_type_list={}
        source_lineNum_list={}
        source_value_dict={}
        source_decompile_dict={}

        label_file=open(node_label_file_1,'r')
        lines=label_file.readlines()


        for index,each_line in enumerate(lines):
            records=each_line.strip().split(', ')
            
            if(each_line.startswith('#')):
                continue
            records=each_line.strip().split('|&|')

            node_seq=int(records[0])

            token=records[1]
            token_type=records[2]

            token_list=token.split(' ')
            this_embedding=model.infer_vector(token_list)
            embedding_seq_1[node_seq]=this_embedding

            if(token_type=='null'):
                this_line_type=set()
                source_type_list[node_seq]=this_line_type
            else:
                this_line_type=set()
                types=token_type.split('##')
                for each_type in types:
                    if(not each_type==''):
                        this_line_type.add(each_type)
                source_type_list[node_seq]=this_line_type

            token_value=records[3]
            if(token_value=='null'):
                this_line_type=set()
                source_value_dict[node_seq]=this_line_type
            else:
                this_line_type=set()
                types=token_value.split('##')
                for each_type in types:
                    if(not each_type==''):
                        this_line_type.add(each_type)
                source_value_dict[node_seq]=this_line_type

            decompile_code=records[4]
            source_decompile_dict[node_seq]=decompile_code

            lineNum=records[5]
            source_lineNum_list[node_seq]=lineNum

        label_file=open(node_label_file_2,'r')
        lines=label_file.readlines()

        dst_type_list={}
        dst_lineNum_list={}
        dst_value_dict={}
        dst_decompile_dict={}

        for index,each_line in enumerate(lines):
            records=each_line.strip().split(', ')

            if(each_line.startswith('#')):
                continue
            records=each_line.strip().split('|&|')

            node_seq=int(records[0])

            token=records[1]
            token_type=records[2]

            token_list=token.split(' ')
            this_embedding=model.infer_vector(token_list)
            embedding_seq_2[node_seq]=this_embedding

            if(token_type=='null'):
                this_line_type=set()
                dst_type_list[node_seq]=this_line_type
            else:
                this_line_type=set()
                types=token_type.split('##')
                for each_type in types:
                    if(not each_type==''):
                        this_line_type.add(each_type)
                dst_type_list[node_seq]=this_line_type

            token_value=records[3]
            if(token_value=='null'):
                this_line_type=set()
                dst_value_dict[node_seq]=this_line_type
            else:
                this_line_type=set()
                types=token_value.split('##')
                for each_type in types:
                    if(not each_type==''):
                        this_line_type.add(each_type)
                dst_value_dict[node_seq]=this_line_type

            decompile_code=records[4]
            dst_decompile_dict[node_seq]=decompile_code

            lineNum=records[5]
            dst_lineNum_list[node_seq]=lineNum
            # print('#######')
            # print(node_seq)
            # print(len(dst_lineNum_list))
            # print('#######')

        # print('##########################################')
        # print(dst_lineNum_list[935])

        edges_1=[]
        edges1_dict = defaultdict(list)
        graph_edge_file=open(edge_file_1,'r')
        lines=graph_edge_file.readlines()
        for each_line in lines:
            records=each_line.strip().split(', ')
            float_list=list(map(float,[records[0],records[1]]))
            ndarray=np.array(float_list)
            ndarray=ndarray.astype(int)
            edges_1.append(ndarray)
            edges1_dict[int(records[0])].append(int(records[1]))

            # float_list=list(map(float,[records[1],records[0]]))
            # ndarray=np.array(float_list)
            # ndarray=ndarray.astype(int)
            # edges_1.append(ndarray)

        edges_2=[]
        edges2_dict = defaultdict(list)
        graph_edge_file=open(edge_file_2,'r')
        lines=graph_edge_file.readlines()
        for each_line in lines:
            records=each_line.strip().split(', ')
            float_list=list(map(float,[records[0],records[1]]))
            ndarray=np.array(float_list)
            ndarray=ndarray.astype(int)
            edges_2.append(ndarray)
            edges2_dict[int(records[0])].append(int(records[1]))

            # float_list=list(map(float,[records[1],records[0]]))
            # ndarray=np.array(float_list)
            # ndarray=ndarray.astype(int)
            # edges_2.append(ndarray)

        train_y=[]
        graph_edge_file=open(training_file,'r')
        lines=graph_edge_file.readlines()
        trainy_dict = defaultdict(list)
        for each_line in lines:
            records=each_line.strip().split(' ')

            float_list=list(map(float,records))
            # float_list=list(map(float,[records[1],records[0]]))
            ndarray=np.array(float_list)
            ndarray=ndarray.astype(int)
            train_y.append(ndarray)
            trainy_dict[int(records[0])].append(int(records[1]))

        edges_1=torch.tensor(edges_1)
        edges_2=torch.tensor(edges_2)
        train_y=torch.tensor(train_y)

        embedding_1=torch.tensor(embedding_seq_1)
        embedding_2=torch.tensor(embedding_seq_2)

        #if(source_type_list[each_line]==dst_type_list[dst_line]):

        un_matched_list=[]
        # for each_line in source_lineNum_list:
        #     exist=False
        #     for dst_line in dst_lineNum_list:
        #         if(source_value_dict[each_line]==dst_value_dict[dst_line]):
        #             if(source_lineNum_list[each_line]==dst_lineNum_list[dst_line]):
        #                 exist=True
        #             else:
        #                 source_set=set(source_lineNum_list[each_line].split('##'))
        #                 dst_set=set(dst_lineNum_list[dst_line].split('##'))
        #                 if(source_set<dst_set or dst_set<source_set or source_set==dst_set):
        #                     exist=True
        #     if(not exist):
        #         un_matched_list.append(each_line)

        print(len(un_matched_list))
        if last_node_seq_1 < 50000 and last_node_seq_2 < 50000:
            return embedding_1,edges_1,embedding_2,edges_2,train_y,source_type_list,dst_type_list,source_lineNum_list,dst_lineNum_list,func_matching_dict,src_func_dict,des_func_dict,source_value_dict,dst_value_dict,source_decompile_dict,dst_decompile_dict,un_matched_list, None, None
        else:
            remove_idx1 = []
            remove_idx2 = []
            small_func_pairs = []
            # slice some matched functions
            while True:
                if last_node_seq_1 - len(remove_idx1) > 50000 and last_node_seq_2 - len(remove_idx2) > 50000 and len(func_matching_list) > 0:
                    func_pair1, func_pair2 = func_matching_list.pop(0)
                    node_ids1 = src_func_node_list[func_pair1]
                    node_ids2 = des_func_node_list[func_pair2]
                    if len(node_ids1) < 25 or len(node_ids2) < 25:
                        small_func_pairs.append((func_pair1, func_pair2))
                        continue
                    node_ids1.sort()
                    node_ids2.sort()
                    source_line_set = set([source_lineNum_list[id] for id in node_ids1])
                    dst_line_set = set([dst_lineNum_list[id] for id in node_ids2])
                    if len(source_line_set) == 1 or len(dst_line_set) == 1:
                        continue
                    remove_idx1.extend(node_ids1[1:])
                    remove_idx2.extend(node_ids2[1:])
                    func_matching_dict.pop(func_pair1)
                    continue
                elif last_node_seq_1 - len(remove_idx1) > 50000 and last_node_seq_2 - len(remove_idx2) > 50000 and len(func_matching_list) == 0 and len(small_func_pairs) > 0:
                    node_ids1 = []
                    node_ids2 = []
                    while len(small_func_pairs) > 0 and len(node_ids1) < 4000:
                        func_pair1, func_pair2 = small_func_pairs.pop(0)
                        node_ids1.extend(src_func_node_list[func_pair1])
                        node_ids2.extend(des_func_node_list[func_pair2])
                        remove_idx1.extend(src_func_node_list[func_pair1][1:])
                        remove_idx2.extend(des_func_node_list[func_pair2][1:])
                        func_matching_dict.pop(func_pair1)
                    continue
                
                node_ids1 = list(set(source_type_list.keys())-set(remove_idx1))
                node_ids2 = list(set(dst_type_list.keys())-set(remove_idx2))
                node_ids1.sort()
                node_ids2.sort()

                node_mapping1 = {n:i for i, n in enumerate(node_ids1)}
                node_mapping2 = {n:i for i, n in enumerate(node_ids2)}
                embedding_1 = torch.tensor([embedding_seq_1[i] for i in node_ids1])
                embedding_2 = torch.tensor([embedding_seq_2[i] for i in node_ids2])
                edges_1 = [[node_mapping1[e1], node_mapping1[e2]] for e1 in node_ids1 for e2 in edges1_dict[e1] if e2 in node_ids1]
                edges_2 = [[node_mapping2[e1], node_mapping2[e2]] for e1 in node_ids2 for e2 in edges2_dict[e1] if e2 in node_ids2]
                edges_1=torch.tensor(edges_1)
                edges_2=torch.tensor(edges_2)
                trainy = [[node_mapping1[e1], node_mapping2[e2]] for e1 in node_ids1 for e2 in trainy_dict[e1] if e2 in node_ids2]
                train_y = torch.tensor(trainy)
                source_type = {node_mapping1[id]:source_type_list[id] for id in node_ids1}
                dst_type = {node_mapping2[id]:dst_type_list[id] for id in node_ids2}
                source_line = {node_mapping1[id]:source_lineNum_list[id] for id in node_ids1}
                dst_line = {node_mapping2[id]:dst_lineNum_list[id] for id in node_ids2}
                source_value = {node_mapping1[id]:source_value_dict[id] for id in node_ids1}
                dst_value = {node_mapping2[id]:dst_value_dict[id] for id in node_ids2}
                source_decompile = {node_mapping1[id]:source_decompile_dict[id] for id in node_ids1}
                dst_decompile = {node_mapping2[id]:dst_decompile_dict[id] for id in node_ids2}
                source_func = {node_mapping1[id]:src_func_dict[id] for id in node_ids1}
                dst_func = {node_mapping2[id]:des_func_dict[id] for id in node_ids2}
                break
            return embedding_1,edges_1,embedding_2,edges_2,train_y,source_type,dst_type,source_line,dst_line,func_matching_dict,source_func,dst_func,source_value,dst_value,source_decompile,dst_decompile,un_matched_list, node_mapping1, node_mapping2

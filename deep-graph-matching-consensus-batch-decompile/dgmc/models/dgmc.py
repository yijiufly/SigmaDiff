import torch
from torch.nn import Sequential as Seq, Linear as Lin, ReLU
from torch_scatter import scatter_add
from torch_geometric.utils import to_dense_batch
from torch_geometric.nn.inits import reset
import torch.nn as nn
import numpy as np
import math
import os
import datetime
from torch.utils.checkpoint import checkpoint_sequential
try:
    from pykeops.torch import LazyTensor
except ImportError:
    LazyTensor = None

EPS = 1e-8
device = 'cuda' if torch.cuda.is_available() else 'cpu'


def masked_softmax(src, mask, dim=-1):
    out = src.masked_fill(~mask, float('-inf'))
    out = torch.softmax(out, dim=dim)
    out = out.masked_fill(~mask, 0)
    return out


def to_sparse(x, mask):
    return x[mask]


def to_dense(x, mask):
    out = x.new_zeros(tuple(mask.size()) + (x.size(-1), ))
    out[mask] = x
    return out


class DGMC(torch.nn.Module):
    r"""The *Deep Graph Matching Consensus* module which first matches nodes
    locally via a graph neural network :math:`\Psi_{\theta_1}`, and then
    updates correspondence scores iteratively by reaching for neighborhood
    consensus via a second graph neural network :math:`\Psi_{\theta_2}`.

    .. note::
        See the `PyTorch Geometric introductory tutorial
        <https://pytorch-geometric.readthedocs.io/en/latest/notes/
        introduction.html>`_ for a detailed overview of the used GNN modules
        and the respective data format.

    Args:
        psi_1 (torch.nn.Module): The first GNN :math:`\Psi_{\theta_1}` which
            takes in node features :obj:`x`, edge connectivity
            :obj:`edge_index`, and optional edge features :obj:`edge_attr` and
            computes node embeddings.
        psi_2 (torch.nn.Module): The second GNN :math:`\Psi_{\theta_2}` which
            takes in node features :obj:`x`, edge connectivity
            :obj:`edge_index`, and optional edge features :obj:`edge_attr` and
            validates for neighborhood consensus.
            :obj:`psi_2` needs to hold the attributes :obj:`in_channels` and
            :obj:`out_channels` which indicates the dimensionality of randomly
            drawn node indicator functions and the output dimensionality of
            :obj:`psi_2`, respectively.
        num_steps (int): Number of consensus iterations.
        k (int, optional): Sparsity parameter. If set to :obj:`-1`, will
            not sparsify initial correspondence rankings. (default: :obj:`-1`)
        detach (bool, optional): If set to :obj:`True`, will detach the
            computation of :math:`\Psi_{\theta_1}` from the current computation
            graph. (default: :obj:`False`)
    """
    def __init__(self, psi_1, psi_2, num_steps, vocab_size=100, k=-1, detach=False):
        super(DGMC, self).__init__()

        # self.embed = nn.Embedding(vocab_size, psi_1.in_channels)

        self.psi_1 = psi_1
        self.psi_2 = psi_2
        self.num_steps = num_steps
        self.k = k
        self.detach = detach
        self.backend = 'auto'

        self.mlp = Seq(
            Lin(psi_2.out_channels, psi_2.out_channels),
            ReLU(inplace=True),
            Lin(psi_2.out_channels, 1),
        )

    def reset_parameters(self):
        self.psi_1.reset_parameters()
        self.psi_2.reset_parameters()
        reset(self.mlp)

    def __top_k__(self, x_s, x_t):  # pragma: no cover
        r"""Memory-efficient top-k correspondence computation."""
        if LazyTensor is not None:

            # print(x_s.size())

            x_s = x_s.unsqueeze(-2)  # [..., n_s, 1, d]

            # print(x_s.size())

            x_t = x_t.unsqueeze(-3)  # [..., 1, n_t, d]
            x_s, x_t = LazyTensor(x_s), LazyTensor(x_t)
            S_ij = (-x_s * x_t).sum(dim=-1)
            return S_ij.argKmin(self.k, dim=2, backend=self.backend)#k's default value is 10.
        else:
            x_s = x_s  # [..., n_s, d]
            x_t = x_t.transpose(-1, -2)  # [..., d, n_t]
            
            if x_s.size()[1] > 20000:
                # calculate in chunks
                x_s = torch.split(x_s, 100, dim=1)
                chunks = []

                for x in x_s:
                    S_ij = x @ x_t
                    chunks.append(S_ij.topk(self.k, dim=2)[1])
                    del S_ij
                
                return torch.cat(chunks,dim=1)
            else:
                S_ij = x_s @ x_t
                return S_ij.topk(self.k, dim=2)[1]

    def __include_gt__(self, S_idx, s_mask, y):
        r"""Includes the ground-truth values in :obj:`y` to the index tensor
        :obj:`S_idx`."""
        (B, N_s), (row, col), k = s_mask.size(), y, S_idx.size(-1)

        gt_mask = (S_idx[s_mask][row] != col.view(-1, 1)).all(dim=-1)

        sparse_mask = gt_mask.new_zeros((s_mask.sum(), ))
        sparse_mask[row] = gt_mask

        dense_mask = sparse_mask.new_zeros((B, N_s))
        dense_mask[s_mask] = sparse_mask
        last_entry = torch.zeros(k, dtype=torch.bool, device=gt_mask.device)
        last_entry[-1] = 1
        dense_mask = dense_mask.view(B, N_s, 1) * last_entry.view(1, 1, k)

        return S_idx.masked_scatter(dense_mask, col[gt_mask])

    def forward(self, x_s, edge_index_s, edge_attr_s, batch_s, x_t,
                edge_index_t, edge_attr_t, batch_t, y=None):
        r"""
        Args:
            x_s (Tensor): Source graph node features of shape
                :obj:`[batch_size * num_nodes, C_in]`.
            edge_index_s (LongTensor): Source graph edge connectivity of shape
                :obj:`[2, num_edges]`.
            edge_attr_s (Tensor): Source graph edge features of shape
                :obj:`[num_edges, D]`. Set to :obj:`None` if the GNNs are not
                taking edge features into account.
            batch_s (LongTensor): Source graph batch vector of shape
                :obj:`[batch_size * num_nodes]` indicating node to graph
                assignment. Set to :obj:`None` if operating on single graphs.
            x_t (Tensor): Target graph node features of shape
                :obj:`[batch_size * num_nodes, C_in]`.
            edge_index_t (LongTensor): Target graph edge connectivity of shape
                :obj:`[2, num_edges]`.
            edge_attr_t (Tensor): Target graph edge features of shape
                :obj:`[num_edges, D]`. Set to :obj:`None` if the GNNs are not
                taking edge features into account.
            batch_s (LongTensor): Target graph batch vector of shape
                :obj:`[batch_size * num_nodes]` indicating node to graph
                assignment. Set to :obj:`None` if operating on single graphs.
            y (LongTensor, optional): Ground-truth matchings of shape
                :obj:`[2, num_ground_truths]` to include ground-truth values
                when training against sparse correspondences. Ground-truths
                are only used in case the model is in training mode.
                (default: :obj:`None`)

        Returns:
            Initial and refined correspondence matrices :obj:`(S_0, S_L)`
            of shapes :obj:`[batch_size * num_nodes, num_nodes]`. The
            correspondence matrix are either given as dense or sparse matrices.
        """

        # x_s = self.embed(x_s)
        # x_t = self.embed(x_t)
        # print(torch.cuda.memory_reserved(0)-torch.cuda.memory_allocated(0))
        h_s = self.psi_1(x_s, edge_index_s, edge_attr_s)#s,t:source and target. This is the first gnn's propogation process.
        h_t = self.psi_1(x_t, edge_index_t, edge_attr_t)

        h_s, h_t = (h_s.detach(), h_t.detach()) if self.detach else (h_s, h_t)#self.detach default is false.

        # print(x_s.size())#[19388, 300]
        # print(edge_index_s.size())#[2, 70414]
        # print(edge_index_s)
        # print(h_s.size())#[19388, 256]

        h_s, s_mask = to_dense_batch(h_s, batch_s, fill_value=0)
        h_t, t_mask = to_dense_batch(h_t, batch_t, fill_value=0)

        # print(h_s.size())#[1, 19388, 256]
        # print(h_t.size())#[1, 19572, 256]

        assert h_s.size(0) == h_t.size(0), 'Encountered unequal batch-sizes'
        (B, N_s, C_out), N_t = h_s.size(), h_t.size(1)
        R_in, R_out = self.psi_2.in_channels, self.psi_2.out_channels

        # print(R_in,R_out)#32,32

        if self.k < 1:
            # ------ Dense variant ------ #
            S_hat = h_s @ h_t.transpose(-1, -2)  # [B, N_s, N_t, C_out]
            S_mask = s_mask.view(B, N_s, 1) & t_mask.view(B, 1, N_t)
            S_0 = masked_softmax(S_hat, S_mask, dim=-1)[s_mask]

            for _ in range(self.num_steps):
                S = masked_softmax(S_hat, S_mask, dim=-1)
                r_s = torch.randn((B, N_s, R_in), dtype=h_s.dtype,
                                  device=h_s.device)
                r_t = S.transpose(-1, -2) @ r_s

                r_s, r_t = to_sparse(r_s, s_mask), to_sparse(r_t, t_mask)
                o_s = self.psi_2(r_s, edge_index_s, edge_attr_s)
                o_t = self.psi_2(r_t, edge_index_t, edge_attr_t)
                o_s, o_t = to_dense(o_s, s_mask), to_dense(o_t, t_mask)

                D = o_s.view(B, N_s, 1, R_out) - o_t.view(B, 1, N_t, R_out)
                S_hat = S_hat + self.mlp(D).squeeze(-1).masked_fill(~S_mask, 0)

            S_L = masked_softmax(S_hat, S_mask, dim=-1)[s_mask]

            return S_0, S_L
        else:
            # ------ Sparse variant ------ #
            S_idx = self.__top_k__(h_s, h_t)  # [B, N_s, k]
            # print(torch.cuda.memory_reserved(0)-torch.cuda.memory_allocated(0))
            # print(S_idx.size())
            # print(s_mask.size())
            # In addition to the top-k, randomly sample negative examples and
            # ensure that the ground-truth is included as a sparse entry.
            if self.training and y is not None:
                rnd_size = (B, N_s, min(self.k, N_t - self.k))
                S_rnd_idx = torch.randint(N_t, rnd_size, dtype=torch.long,
                                          device=S_idx.device).detach()
                S_idx = torch.cat([S_idx, S_rnd_idx], dim=-1)
                S_idx = self.__include_gt__(S_idx, s_mask, y)
                del S_rnd_idx

            # print(torch.cuda.memory_reserved(0)-torch.cuda.memory_allocated(0))
            k = S_idx.size(-1)
            tmp_s = h_s.view(B, N_s, 1, C_out)
            idx = S_idx.view(B, N_s * k, 1).expand(-1, -1, C_out)

            oom = False
            try:
                ### original code
                tmp_t = torch.gather(h_t.view(B, N_t, C_out), -2, idx)
                S_hat = (tmp_s * tmp_t.view(B, N_s, k, C_out)).sum(dim=-1)
            except RuntimeError:
                oom = True
                
            if oom:
                # calculate in chunks
                tmp_s = torch.split(tmp_s, 100, dim=1)
                idx = torch.split(idx, 100 * k, dim=1)
                chunks = []

                for i in range(len(tmp_s)):
                    x = tmp_s[i]
                    idx_tmp = idx[i]
                    tmp_t = torch.gather(h_t.view(B, N_t, C_out), -2, idx_tmp)
                    S_hat_tmp = (x * tmp_t.view(B, x.size()[1], k, C_out)).sum(dim=-1)
                    chunks.append(S_hat_tmp)
                S_hat = torch.cat(chunks,dim=1)

            
            S_0 = S_hat.softmax(dim=-1)[s_mask]

            # print('The value of num_steps:')
            # print(self.num_steps)

            for _ in range(self.num_steps):
                S = S_hat.softmax(dim=-1)
                r_s = torch.randn((B, N_s, R_in), dtype=h_s.dtype,
                                  device=h_s.device)

                tmp_t = r_s.view(B, N_s, 1, R_in) * S.view(B, N_s, k, 1)
                tmp_t = tmp_t.view(B, N_s * k, R_in)
                idx = S_idx.view(B, N_s * k, 1)
                r_t = scatter_add(tmp_t, idx, dim=1, dim_size=N_t)
                r_s, r_t = to_sparse(r_s, s_mask), to_sparse(r_t, t_mask)
                o_s = self.psi_2(r_s, edge_index_s, edge_attr_s)
                o_t = self.psi_2(r_t, edge_index_t, edge_attr_t)
                o_s, o_t = to_dense(o_s, s_mask), to_dense(o_t, t_mask)

                oom = True
                o_s = o_s.view(B, N_s, 1, R_out).expand(-1, -1, k, -1)
                idx = S_idx.view(B, N_s * k, 1).expand(-1, -1, R_out)
                tmp_t = torch.gather(o_t.view(B, N_t, R_out), -2, idx)
                D = o_s - tmp_t.view(B, N_s, k, R_out)
                # S_hat = S_hat + checkpoint_sequential(self.mlp, 2, D).squeeze(-1)
                S_hat = S_hat + self.mlp(D).squeeze(-1)

            S_L = S_hat.softmax(dim=-1)[s_mask]
            S_idx = S_idx[s_mask]

            # Convert sparse layout to `torch.sparse_coo_tensor`.
            row = torch.arange(x_s.size(0), device=S_idx.device)
            row = row.view(-1, 1).repeat(1, k)
            idx = torch.stack([row.view(-1), S_idx.view(-1)], dim=0)
            size = torch.Size([x_s.size(0), N_t])

            S_sparse_0 = torch.sparse_coo_tensor(
                idx, S_0.view(-1), size, requires_grad=S_0.requires_grad)
            S_sparse_0.__idx__ = S_idx
            S_sparse_0.__val__ = S_0

            S_sparse_L = torch.sparse_coo_tensor(
                idx, S_L.view(-1), size, requires_grad=S_L.requires_grad)
            S_sparse_L.__idx__ = S_idx
            S_sparse_L.__val__ = S_L

            return S_sparse_0, S_sparse_L

    def check_set_compatibility(self, set1, set2):
        diff1 = set1 - set2
        diff2 = set2 - set1
        for type in diff1:
            found = False
            for type2 in set2:
                if self.check_compatibility(type, type2):
                    found = True
                    break
            if not found:
                return False

        for type in diff2:
            found = False
            for type2 in set1:
                if self.check_compatibility(type, type2):
                    found = True
                    break
            if not found:
                return False
        return True

    def check_compatibility(self, type1, type2):
        compatible_dict = dict()
        compatible_dict["undefined8"] = set(["long", "ulong", "double", "size_t"])
        compatible_dict["undefined4"] = set(["float", "int", "wchar_t", "uint"])
        compatible_dict["undefined2"] = set(["short", "ushort"])
        compatible_dict["byte"] = set(["char"])
        compatible_dict["long"] = set(["ulong"])
        compatible_dict["short"] = set(["ushort"])
        compatible_dict["int"] = set(["uint"])
        # undefined, void * is compatible with all of the other types
        if type1 == "undefined" or type2 == "undefined" or type1 == "undefined *"  or type2 == "undefined *":
            return True
        if type1 == "void *" or type2 == "void *":
            return True
        if type1 in compatible_dict.keys():
            if type2 in compatible_dict[type1]:
                return True
        if type2 in compatible_dict.keys():
            if type1 in compatible_dict[type2]:
                return True
        # two pointers could be compatible with each other
        if type1.endswith("*") and type2.endswith("*"):
            return True
        if type1 == type2:
            return True
        return False
    
    def check_compatibility_IR(self, type1, type2):
        if type1 == type2:
            return True
        cset1 = set(['INT_ADD', 'INT_SUB', 'PTRSUB', 'PTRADD'])
        cset2 = set(['INT_NOTEQUAL', 'INT_EQUAL'])
        cset3 = set(['COPY','INT_ZEXT'])
        if type1 in cset1 and type2 in cset1:
            return True
        if type1 in cset2 and type2 in cset2:
            return True
        return False
    
    
    
    def loss(self, S, y, source_type_list, dst_type_list, source_value_dict, dst_value_dict, source_decompile_dict, dst_decompile_dict, source_lineNum_list, dst_lineNum_list, reduction='mean'):
        r"""Computes the negative log-likelihood loss on the correspondence
        matrix.

        Args:
            S (Tensor): Sparse or dense correspondence matrix of shape
                :obj:`[batch_size * num_nodes, num_nodes]`.
            y (LongTensor): Ground-truth matchings of shape
                :obj:`[2, num_ground_truths]`.
            reduction (string, optional): Specifies the reduction to apply to
                the output: :obj:`'none'|'mean'|'sum'`.
                (default: :obj:`'mean'`)
        """
        assert reduction in ['none', 'mean', 'sum']

        Type_Constraint=True

        if not S.is_sparse:

            val = S[y[0], y[1]]
        else:
            assert S.__idx__ is not None and S.__val__ is not None

            # print(S.__idx__[y[0]])
            # print(y[1].view(-1, 1))
            # print(S.__idx__.size())
            # print(S.__val__.size())

            src_list=[]
            des_list=[]
            type_penalty=[]
            value_penalty=[]
            decompile_penalty=[]
            total=0
            unmatch=0
            type_total=0
            type_unmatch=0
            for src_index in range(0,S.__idx__.size(0)):

                source_line=source_lineNum_list[src_index]
                dst_val_index = S.__val__[src_index].argmax(dim=-1) # corresponds to 0
                dst_index=S.__idx__[src_index, dst_val_index].item()
                dst_line=dst_lineNum_list[dst_index]
                # if(not source_line=='null' and not dst_line=='null'):
                if(True):

                    source_type=source_type_list[src_index]
                    des_type=dst_type_list[dst_index]
                    src_list.append(source_type)
                    des_list.append(des_type)

                    # print(S.__val__[src_index].argmax(dim=-1))
                    source_value=source_value_dict[src_index]
                    des_value=dst_value_dict[dst_index]

                    source_decompile=source_decompile_dict[src_index]
                    des_decompile=dst_decompile_dict[dst_index]

                    if(not source_decompile=='null' and not des_decompile=='null'):
                        if(source_decompile==des_decompile):
                            decompile_penalty.append(src_index)
                    # print('##########')
                    # print(source_type)
                    # print(des_type)
                    # print('##########')
                    # if(source_type==des_type):
                    #     type_penalty.append(0)
                    # else:
                    #     type_penalty.append(1)
                    if(source_type and des_type):
                        type_total=type_total+1

                        if(len(source_type)==1 and len(des_type)==1):
                            source_one=list(source_type)[0]
                            des_one=list(des_type)[0]
                            if(not source_one==des_one):
                                if(not self.check_compatibility(source_one,des_one)):
                                    type_unmatch=type_unmatch+1
                                    type_penalty.append(src_index)
                        elif(not self.check_set_compatibility(set(source_type), set(des_type))):
                            # print('##########')
                            # print(source_type)
                            # print(des_type)
                            # print('##########')
                            type_unmatch=type_unmatch+1
                            type_penalty.append(src_index)

                    if(source_value and des_value):
                        total=total+1
                        # if(len(source_type.intersection(des_type)) == 0):
                        #     value_penalty.append(src_index)
                        if(not source_value==des_value):
                            if (not self.check_compatibility_IR(source_value, des_value)):
                                # print('##########')
                                # print(source_value)
                                # print(des_value)
                                # print('##########')
                                unmatch=unmatch+1
                                value_penalty.append(src_index)
            
            a = np.array(src_list)
            b = np.array(des_list)

            matched=float(sum(a==b))/len(src_list)
            # print(matched)
            # print("P-Code unmatched percentage:"+str(float(unmatch)/total))
            # print("Type unmatched percentage:"+str(float(type_unmatch)/type_total))

            mask = S.__idx__[y[0]] == y[1].view(-1, 1)
            # print(mask.size())
            val = S.__val__[[y[0]]][mask]
            # print(val.size())
        if(Type_Constraint):
            # print(val.size())
            # print(val)
            # print(S.__val__.size())
            type_penalty=torch.tensor(type_penalty, dtype=torch.long).to(device)
            # print(type_penalty.size())
            # print(type_penalty)

            value_penalty=torch.tensor(value_penalty, dtype=torch.long).to(device)

            decompile_penalty=torch.tensor(decompile_penalty).to(device)

            first_match=S.__val__[:,:1].squeeze(-1)
            # second_match=S.__val__[:,1:2].squeeze(-1)
            # print(S.__val__[:,:1])
            # print(first_match)
            # print(first_match.size())
            # type_loss=first_match*type_penalty

            type_loss=torch.take(first_match,type_penalty)
            type_loss_2=torch.take(first_match,value_penalty)

            # decompile_loss=torch.take(first_match,decompile_penalty)

            nll2 = torch.exp(type_loss + EPS)-1
            nll3 = torch.exp(type_loss_2 + EPS)-1
            # nll4 = -torch.log(decompile_loss + EPS)

            # nll2 = type_loss + EPS
            # nll3 = type_loss_2 + EPS
            # type_loss=torch.masked_select(first_match,type_penalty)
            # print(S.__val__[:,:1].size())
            # print(type_loss.size())
            # print(type_loss)

        nll = -torch.log(val + EPS)
        # print('********losses:')
        # print(getattr(torch, reduction)(nll))
        # print(getattr(torch, reduction)(nll2))
        # print('********')

        # return nll if reduction == 'none' else getattr(torch, reduction)(nll)+getattr(torch, reduction)(nll2)
        # return nll if reduction == 'none' else getattr(torch, reduction)(nll)
        if(Type_Constraint):
            # return nll if reduction == 'none' else getattr(torch, reduction)(nll)+0.1*(getattr(torch, reduction)(nll2))+0.1*(getattr(torch, reduction)(nll3))+0.5*getattr(torch, reduction)(nll4)
            return nll if reduction == 'none' else getattr(torch, reduction)(nll)+0.1*(getattr(torch, reduction)(nll2))+0.1*(getattr(torch, reduction)(nll3))
            # return nll if reduction == 'none' else getattr(torch, reduction)(nll)+0.3*(getattr(torch, reduction)(nll3))
        else:
            return nll if reduction == 'none' else getattr(torch, reduction)(nll)

    def acc(self, S, y, reduction='mean'):
        r"""Computes the accuracy of correspondence predictions.

        Args:
            S (Tensor): Sparse or dense correspondence matrix of shape
                :obj:`[batch_size * num_nodes, num_nodes]`.
            y (LongTensor): Ground-truth matchings of shape
                :obj:`[2, num_ground_truths]`.
            reduction (string, optional): Specifies the reduction to apply to
                the output: :obj:`'mean'|'sum'`. (default: :obj:`'mean'`)
        """
        assert reduction in ['mean', 'sum']
        if not S.is_sparse:
            pred = S[y[0]].argmax(dim=-1)
        else:
            assert S.__idx__ is not None and S.__val__ is not None
            pred = S.__idx__[y[0], S.__val__[y[0]].argmax(dim=-1)]

        correct = (pred == y[1]).sum().item()
        return correct / y.size(1) if reduction == 'mean' else correct

    def accdiff(self, S, source_lineNum_list,dst_lineNum_list,func_matching_dict,src_func_dict,des_func_dict,source_type_list,dst_type_list,un_matched_list,source_value_dict,dst_value_dict,subject_path,subject_dir, node_mapping1, node_mapping2,final=False, with_gt=False):

        TP=0
        total=0
        relax_TP=0
        file_TP=0
        filter_TP=0
        filter_total=0

        # time_1=datetime.datetime.now()
        # date_string=time_1.strftime('%b--%d')

        subject_name=subject_path.strip('/').replace('/','-')
        result_dir=subject_dir+'-results'

        if(not os.path.exists(result_dir)):
            os.mkdir(result_dir)

        if(final):
            match_file=open(result_dir+'/'+subject_name+'-match_result.txt','a')
            before_filtering_match=open(result_dir+'/'+subject_name+'-Initial_match_result.txt','a')

        for src_index in range(0,S.__idx__.size(0)):
            source_line=source_lineNum_list[src_index]
           
            dst_val_index = S.__val__[src_index].argmax(dim=-1) # corresponds to j
            dst_index=S.__idx__[src_index, dst_val_index].item()
            dst_line=dst_lineNum_list[dst_index]
            dst_line_list=[]
            for j in range(0,self.k):
                this_line=dst_lineNum_list[S.__idx__[src_index][j].item()]
                dst_line_list.append(this_line)

            # if(src_index in un_matched_list):
            #     total=total+1
            #     TP=TP+1
            #     filter_TP=filter_TP+1
            #     filter_total=filter_total+1
            #     continue

            matched=False

            if(not source_line=='null' and not dst_line=='null'):
                if(source_line==dst_line):
                    TP=TP+1
                    matched=True
                else:
                    if(not '##' in source_line and not '##' in dst_line):
                        source_file=source_line.split(':')[0]
                        source_num=int(source_line.split(':')[1])
                        dst_file=dst_line.split(':')[0]
                        dst_num=int(dst_line.split(':')[1])
                        if(source_file==dst_file and abs(source_num-dst_num)==1):
                            TP=TP+1
                            matched=True
                    else:
                        source_set=set(source_line.split('##'))
                        dst_set=set(dst_line.split('##'))
                        if(source_set<dst_set or dst_set<source_set or source_set==dst_set):
                            TP=TP+1
                            matched=True

            if(not source_line=='null'):
                total=total+1
                if(final):
                    before_filtering_match.write(str(node_mapping1[src_index])+','+str(node_mapping2[dst_index])+','+source_line+','+dst_line+','+str(matched)+','+str(S.__val__[src_index][dst_val_index].item())+'\n')
                    before_filtering_match.flush()

            if(not source_line=='null'):
                source_file=source_line.split(':')[0]
                dst_file=dst_line.split(':')[0]
                if(source_file==dst_file):
                    file_TP=file_TP+1

                for each_dst in dst_line_list:
                    if(source_line==each_dst):
                        relax_TP=relax_TP+1
                        break

            double_matched=False
            matched=False
            
            if(not source_line=='null'):
                _, indices = torch.sort(S.__val__[src_index], descending=True)
                for j in indices:
                    j = j.item()
                    dst_line=dst_lineNum_list[S.__idx__[src_index][j].item()]
                    src_type=source_type_list[src_index]
                    dst_type=dst_type_list[S.__idx__[src_index][j].item()]
                    src_value=source_value_dict[src_index]
                    dst_value=dst_value_dict[S.__idx__[src_index][j].item()]
                    if (self.check_compatibility_IR(src_value, dst_value) and self.check_set_compatibility(src_type, dst_type)):
                    # if(src_type==dst_type and src_value==dst_value):
                        
                        filter_total=filter_total+1
                        
                        double_matched=True
                        if(source_line==dst_line):
                            filter_TP=filter_TP+1
                            matched=True
                        else:
                            source_set=set(source_line.split('##'))
                            dst_set=set(dst_line.split('##'))
                            if(source_set<dst_set or dst_set<source_set or source_set==dst_set):
                                filter_TP=filter_TP+1
                                matched=True
                        
                        # elif(source_line in dst_line or dst_line in source_line):
                        #     filter_TP=filter_TP+1
                        #     matched=True
                        if(final):
                            # print('###########')
                            # print(source_line)
                            # print(dst_line)
                            # print('###########')
                            match_file.write(str(node_mapping1[src_index])+','+str(node_mapping2[S.__idx__[src_index][j].item()])+','+source_line+','+dst_line+','+str(matched)+','+str(S.__val__[src_index][j].item())+'\n')
                            match_file.flush()
                        break
                if(not double_matched):
                    for j in indices:
                        j = j.item()
                        dst_line=dst_lineNum_list[S.__idx__[src_index][j].item()]
                        src_type=source_type_list[src_index]
                        dst_type=dst_type_list[S.__idx__[src_index][j].item()]
                        if(self.check_compatibility_IR(src_value, dst_value) or self.check_set_compatibility(src_type, dst_type)):

                            filter_total=filter_total+1
                            
                            if(source_line==dst_line):
                                filter_TP=filter_TP+1
                                matched=True
                            else:
                                source_set=set(source_line.split('##'))
                                dst_set=set(dst_line.split('##'))
                                if(source_set<dst_set or dst_set<source_set or source_set==dst_set):
                                    filter_TP=filter_TP+1
                                    matched=True
                            if(final):
                                # print('###########')
                                # print(source_line)
                                # print(dst_line)
                                # print('###########')
                                match_file.write(str(node_mapping1[src_index])+','+str(node_mapping2[S.__idx__[src_index][j].item()])+','+source_line+','+dst_line+','+str(matched)+','+str(S.__val__[src_index][j].item())+'\n')
                                match_file.flush()
                            break


        if(filter_total==0):
            filter_total=1
        
        
        accuracy=float(TP)/total
        if with_gt:
            print('True Positive='+str(TP))
            print('TP+FP='+str(total))
            print('Filter True Positive='+str(filter_TP))
            print('Accuracy='+str(accuracy))
            print('After Filter Accuracy='+str(float(filter_TP)/filter_total))
        return accuracy


    def hits_at_k(self, k, S, y, reduction='mean'):
        r"""Computes the hits@k of correspondence predictions.

        Args:
            k (int): The :math:`\mathrm{top}_k` predictions to consider.
            S (Tensor): Sparse or dense correspondence matrix of shape
                :obj:`[batch_size * num_nodes, num_nodes]`.
            y (LongTensor): Ground-truth matchings of shape
                :obj:`[2, num_ground_truths]`.
            reduction (string, optional): Specifies the reduction to apply to
                the output: :obj:`'mean'|'sum'`. (default: :obj:`'mean'`)
        """
        assert reduction in ['mean', 'sum']
        if not S.is_sparse:
            pred = S[y[0]].argsort(dim=-1, descending=True)[:, :k]
        else:
            assert S.__idx__ is not None and S.__val__ is not None
            perm = S.__val__[y[0]].argsort(dim=-1, descending=True)[:, :k]
            pred = torch.gather(S.__idx__[y[0]], -1, perm)

        correct = (pred == y[1].view(-1, 1)).sum().item()
        return correct / y.size(1) if reduction == 'mean' else correct

    def __repr__(self):
        return ('{}(\n'
                '    psi_1={},\n'
                '    psi_2={},\n'
                '    num_steps={}, k={}\n)').format(self.__class__.__name__,
                                                    self.psi_1, self.psi_2,
                                                    self.num_steps, self.k)

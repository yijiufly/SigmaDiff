import torch
from torch.nn import Linear as Lin, BatchNorm1d as BN
import torch.nn.functional as F
from torch_geometric.nn import MessagePassing
from torch.utils.checkpoint import checkpoint

class RelConv(MessagePassing):
    def __init__(self, in_channels, out_channels):
        super(RelConv, self).__init__(aggr='mean')

        self.in_channels = in_channels
        self.out_channels = out_channels

        self.lin1 = Lin(in_channels, out_channels, bias=False)
        self.lin2 = Lin(in_channels, out_channels, bias=False)
        self.root = Lin(in_channels, out_channels)

        self.reset_parameters()

    def reset_parameters(self):
        self.lin1.reset_parameters()
        self.lin2.reset_parameters()
        self.root.reset_parameters()

    def forward(self, x, edge_index):
        """"""
        self._explain = False
        self.decomposed_layers = 1
        self.flow = 'source_to_target'
        out1 = self.propagate(edge_index, x=self.lin1(x))
        self.flow = 'target_to_source'
        out2 = self.propagate(edge_index, x=self.lin2(x))
        return self.root(x) + out1 + out2

    def message(self, x_j):
        return x_j

    def __repr__(self):
        return '{}({}, {})'.format(self.__class__.__name__, self.in_channels,
                                   self.out_channels)


class RelCNN(torch.nn.Module):
    def __init__(self, in_channels, out_channels, num_layers, batch_norm=False,
                 cat=True, lin=True, dropout=0.0, further_propogate=False):
        super(RelCNN, self).__init__()

        self.in_channels = in_channels#psi_1:300,256;psi_2:32
        self.num_layers = num_layers
        self.batch_norm = batch_norm
        self.cat = cat
        self.lin = lin
        self.dropout = dropout
        self.further_propogate = further_propogate
        self.dummy_tensor = torch.ones(1, dtype=torch.float32, requires_grad=True)
        self.convs = torch.nn.ModuleList()
        self.batch_norms = torch.nn.ModuleList()
        for _ in range(num_layers):
            self.convs.append(RelConv(in_channels, out_channels))
            self.batch_norms.append(BN(out_channels))
            in_channels = out_channels

        if self.cat:
            in_channels = self.in_channels + num_layers * out_channels
        else:
            in_channels = out_channels

        if self.lin:
            self.out_channels = out_channels
            self.final = Lin(in_channels, out_channels)
        else:
            self.out_channels = in_channels

        self.reset_parameters()

    def reset_parameters(self):
        for conv, batch_norm in zip(self.convs, self.batch_norms):
            conv.reset_parameters()
            batch_norm.reset_parameters()
        if self.lin:
            self.final.reset_parameters()

    def run_function(self, start, end):
        def custom_forward(*inputs):
            for conv, batch_norm in zip(self.convs[start: end], self.batch_norms[start: end]):
                x = conv(inputs[0][-1], inputs[1])
                if(self.further_propogate):
                    for j in range(0,2):
                        x=conv(x, inputs[1])
                x = batch_norm(F.relu(x, inplace=True)) if self.batch_norm else F.relu(x, inplace=True)
                x = F.dropout(x, p=self.dropout, training=self.training)
                inputs[0].append(x)
            return inputs[2]
        return custom_forward

    def forward(self, x, edge_index, *args):#感觉唯一和graph相关的，就是这个edge了。
        """"""
        xs = [x]#why this step??
        # print(xs[-1].size())
        # print(edge_index.size())

        for conv, batch_norm in zip(self.convs, self.batch_norms):
            x = conv(xs[-1], edge_index)
            if(self.further_propogate):
                for j in range(0,2):
                    x=conv(x, edge_index)
            x = batch_norm(F.relu(x, inplace=True)) if self.batch_norm else F.relu(x, inplace=True)
            x = F.dropout(x, p=self.dropout, training=self.training)
            xs.append(x)

        # xs=[xs[-1]]
        
        # for conv, batch_norm in zip(self.convs, self.batch_norms):
        #     x = conv(xs[-1], edge_index)
        #     x = batch_norm(F.relu(x)) if self.batch_norm else F.relu(x)
        #     x = F.dropout(x, p=self.dropout, training=self.training)
        #     xs.append(x)

        # checkpoint(self.run_function(0, self.num_layers//2), xs, edge_index, self.dummy_tensor)
        # checkpoint(self.run_function(self.num_layers//2, self.num_layers), xs, edge_index, self.dummy_tensor)

        x = torch.cat(xs, dim=-1) if self.cat else xs[-1]
        x = self.final(x) if self.lin else x
        return x

    def __repr__(self):
        return ('{}({}, {}, num_layers={}, batch_norm={}, cat={}, lin={}, '
                'dropout={})').format(self.__class__.__name__,
                                      self.in_channels, self.out_channels,
                                      self.num_layers, self.batch_norm,
                                      self.cat, self.lin, self.dropout)

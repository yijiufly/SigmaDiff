from dataclasses import dataclass
import numpy as np
import pickle
@dataclass
class Function:
    name: str
    addr: int
    idx: int
    size: int
    num_inst: int
    data: np.ndarray
    
    
def load_file_with_debug(path, strippedname2addr):
    emb = {}
    addr2strippedname = {value: key for key, value in strippedname2addr.items()}
    funcs = pickle.load(open(path, "rb"))
    for item in funcs:
        addr = item.addr + 1048576
        if str(addr) in addr2strippedname:
            name = addr2strippedname[str(addr)]
            emb[name] = item.data
    return emb

def load_file(path, addrpath, strippedname2addr):
    emb = {}
    emb_tmp = np.load(open(path, "rb"))
    addr2strippedname = {value: key for key, value in strippedname2addr.items()}
    addr_tmp = np.load(open(addrpath, "rb"))
    for i in range(len(emb_tmp)):
        addr = addr_tmp[i] + 1048576
        if str(addr) in addr2strippedname:
            name = addr2strippedname[str(addr)]
            emb[name] = emb_tmp[i]
    return emb

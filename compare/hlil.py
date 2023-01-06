from __future__ import annotations

import ctypes
import glob
import math
import os
import pickle
from dataclasses import dataclass
from math import log2
from typing import List, Dict
from Levenshtein import distance
from collections import Counter
import numpy as np
import sys

import matplotlib
matplotlib.rcParams['savefig.dpi'] = 192
matplotlib.rcParams['figure.dpi'] = 192
import matplotlib.pyplot as plt

import binaryninja as binja
from binaryninja.enums import SymbolType, HighLevelILOperation
from pathlib import Path
import traceback
class Metadata:
    def __init__(self):
        self.const_list: List[int] = []
        self.mem_offset_list: List[int] = []
        self.imported_list: List[str] = []
        self.string: List[str] = []
        self.func_type: str = ''

    def merge(self, other: Metadata):
        self.const_list.extend(other.const_list)
        self.mem_offset_list.extend(other.mem_offset_list)
        self.imported_list.extend(other.imported_list)
        self.string.extend(other.string)

    def diff(self, other: Metadata):
        func_type_diff = distance(self.func_type, other.func_type)
        const_diff = self._int_list_diff(self.const_list, other.const_list)
        mem_diff = self._int_list_diff(self.mem_offset_list, other.mem_offset_list)
        imported_diff = self._str_list_diff(self.imported_list, other.imported_list)
        str_diff = self._str_list_diff(self.string, other.string)
        return func_type_diff, const_diff, mem_diff, imported_diff, str_diff

    def clean(self):
        left_parenthesis = self.func_type.index('(')
        right_parenthesis = self.func_type.index(')', left_parenthesis)
        args = self.func_type[left_parenthesis+1:right_parenthesis].split(', ')
        args = [v for v in args if '@' not in v]
        self.func_type = f'{self.func_type[:left_parenthesis+1]}{", ".join(args)}{self.func_type[right_parenthesis:]}'

        for i, v in enumerate(self.imported_list):
            if v.startswith('__'):
                v = v[2:]
            if v.endswith('_chk'):
                v = v[:-4]
            self.imported_list[i] = v

    @staticmethod
    def _int_list_diff(l1: List[int], l2: List[int]):
        c1, c2 = Metadata._list_to_unique_counter(l1, l2)
        diff = 0
        for c in (c1, c2):
            for k, v in c.items():
                if math.isnan(k):
                    continue
                diff += v * (log2(abs(k) + 1) + 1)
        return diff

    @staticmethod
    def _str_list_diff(l1: List[str], l2: List[str]):
        c1, c2 = Metadata._list_to_unique_counter(l1, l2)
        return len(c1) + len(c2)

    @staticmethod
    def _list_to_unique_counter(l1, l2):
        c1 = Counter(l1)
        c2 = Counter(l2)
        keys = c1.keys() & c2.keys()
        for k in keys:
            v1 = c1[k]
            v2 = c2[k]
            if v1 > v2:
                del c2[k]
            elif v1 < v2:
                del c1[k]
            else:
                del c1[k]
                del c2[k]
        return c1, c2


def process(paths):
    for path in paths:
        if isinstance(path, str):
            if os.path.exists(path + '.formula'):
                continue
            print(path)
            bndb_path = path + '.bndb'
            bndb_exist = os.path.exists(bndb_path)
            bv = binja.BinaryViewType.get_view_of_file(bndb_path if bndb_exist else path)
            if not bndb_exist:
                bv.create_database(bndb_path, clean=True)
        else:
            bv = path
        symbol_map: Dict[int, str] = dict()
        string_map: Dict[int, str] = dict()
        for symbol in bv.get_symbols():
            if symbol.type == SymbolType.DataSymbol:
                continue
            symbol_map[symbol.address] = symbol.full_name
        section_start = sys.maxsize
        section_end = 0
        for name in list(bv.sections.keys()):
            if '.text' in name:
                section_start = min(section_start, bv.get_section_by_name(name).start)
                section_end = max(section_end, bv.get_section_by_name(name).end)

        for string in bv.get_strings():
            if not section_start <= string.start < section_end:
                string_map[string.start] = string.value
        data = get_hlil(bv, symbol_map, string_map)
        bv.file.close()
        print(len(data.keys()))
        if isinstance(path, str):
            with open(path + '.formula', 'wb') as f:
                pickle.dump(data, f)
        else:
            return data


def get_hlil(bv, symbol_map, string_map):
    section_start = sys.maxsize
    section_end = 0
    for name in list(bv.sections.keys()):
        if '.text' in name:
            section_start = min(section_start, bv.get_section_by_name(name).start)
            section_end = max(section_end, bv.get_section_by_name(name).end)
    func_data = dict()
    for func in bv.functions:
        if not section_start <= func.start < section_end:
            continue
        m = Metadata()
        m.func_type = str(func.function_type)
        try:
            for bb in func.hlil:
                for inst in bb:
                    new_m = extract(inst, symbol_map, string_map, [])
                    m.merge(new_m)
            func_data[func.name] = m
        except:
            continue
    return func_data


def extract(inst: binja.HighLevelILInstruction, symbol_map, string_map, history):
    m = Metadata()
    if inst is None:
        return m
    if isinstance(inst, list):
        for op in inst:
            m.merge(extract(op, symbol_map, string_map, history))
        return m
    if not hasattr(inst, 'operation'):
        return m
    history.append(inst)
    if inst.operation == HighLevelILOperation.HLIL_CONST:
        if len(history) >= 3 and history[-3].operation == HighLevelILOperation.HLIL_DEREF:
            m.mem_offset_list.append(inst.constant)
        else:
            m.const_list.append(inst.constant)
    elif inst.operation == HighLevelILOperation.HLIL_CONST_PTR:
        if inst.constant in symbol_map:
            m.imported_list.append(symbol_map[inst.constant])
        elif inst.constant in string_map:
            m.string.append(string_map[inst.constant])
    elif inst.operation == HighLevelILOperation.HLIL_IMPORT:
        m.imported_list.append(str(inst))
    elif inst.operation == HighLevelILOperation.HLIL_IF:
        m.merge(extract(inst.condition, symbol_map, string_map, history))
    else:
        for op in inst.operands:
            m.merge(extract(op, symbol_map, string_map, history))
    history.pop()
    return m

if __name__ == '__main__':
    libdir = '/Users/JennyGao/Downloads/projects/community/data_all/Libraries/'
    for libs in os.listdir(libdir):
        for ida_path in Path(libdir+libs).rglob('*3/objfiles/'):
            file_prefix = str(ida_path).rsplit('/', 1)[0] + '/' + libs
            for objfile in os.listdir(ida_path):
                obj_file = str(ida_path) + '/' + objfile
                if obj_file.endswith('.ida') or obj_file.endswith('.formula') or obj_file.endswith('.bndb') or os.path.exists(obj_file + '.DS_Store'):
                    continue
                try:
                    process([obj_file])
                except:
                    print(traceback.format_exc())



1: 
2: void FUN_0016ba30(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: undefined *puVar3;
8: undefined *puVar4;
9: undefined *__ptr;
10: byte *pbVar5;
11: 
12: iVar1 = *(int *)(param_1 + 0x88);
13: lVar2 = **(long **)(param_1 + 0xa0);
14: __ptr = *(undefined **)(param_2 + 0x38);
15: if (iVar1 != 0) {
16: puVar3 = __ptr;
17: pbVar5 = **(byte ***)(param_2 + 0x28);
18: do {
19: puVar4 = puVar3 + 1;
20: *puVar3 = *(undefined *)(lVar2 + (ulong)*pbVar5);
21: puVar3 = puVar4;
22: pbVar5 = pbVar5 + 1;
23: } while (puVar4 != __ptr + (ulong)(iVar1 - 1) + 1);
24: __ptr = *(undefined **)(param_2 + 0x38);
25: }
26: fwrite(__ptr,1,*(size_t *)(param_2 + 0x48),*(FILE **)(param_2 + 0x20));
27: return;
28: }
29: 

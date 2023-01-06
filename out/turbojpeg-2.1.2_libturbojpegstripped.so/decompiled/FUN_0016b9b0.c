1: 
2: void FUN_0016b9b0(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: long *plVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: undefined *puVar6;
11: undefined *puVar7;
12: undefined *__ptr;
13: byte *pbVar8;
14: ulong uVar9;
15: 
16: plVar2 = *(long **)(param_1 + 0xa0);
17: iVar1 = *(int *)(param_1 + 0x88);
18: lVar3 = *plVar2;
19: lVar4 = plVar2[1];
20: lVar5 = plVar2[2];
21: __ptr = *(undefined **)(param_2 + 0x38);
22: if (iVar1 != 0) {
23: puVar6 = __ptr;
24: pbVar8 = **(byte ***)(param_2 + 0x28);
25: do {
26: uVar9 = (ulong)*pbVar8;
27: puVar7 = puVar6 + 3;
28: *puVar6 = *(undefined *)(lVar3 + uVar9);
29: puVar6[1] = *(undefined *)(lVar4 + uVar9);
30: puVar6[2] = *(undefined *)(lVar5 + uVar9);
31: puVar6 = puVar7;
32: pbVar8 = pbVar8 + 1;
33: } while (puVar7 != __ptr + (ulong)(iVar1 - 1) * 3 + 3);
34: __ptr = *(undefined **)(param_2 + 0x38);
35: }
36: fwrite(__ptr,1,*(size_t *)(param_2 + 0x48),*(FILE **)(param_2 + 0x20));
37: return;
38: }
39: 

1: 
2: void FUN_001451b0(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: int iVar1;
6: long *plVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: byte *pbVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: long lVar9;
14: char *pcVar10;
15: 
16: plVar2 = *(long **)(*(long *)(param_1 + 0x270) + 0x30);
17: lVar3 = *plVar2;
18: lVar4 = plVar2[1];
19: lVar5 = plVar2[2];
20: iVar1 = *(int *)(param_1 + 0x88);
21: if ((0 < param_4) && (iVar1 != 0)) {
22: lVar9 = 0;
23: do {
24: pbVar6 = *(byte **)(param_2 + lVar9);
25: pbVar7 = pbVar6;
26: pcVar10 = *(char **)(param_3 + lVar9);
27: do {
28: pbVar8 = pbVar7 + 3;
29: *pcVar10 = *(char *)(lVar5 + (ulong)pbVar7[2]) +
30: *(char *)(lVar3 + (ulong)*pbVar7) + *(char *)(lVar4 + (ulong)pbVar7[1]);
31: pbVar7 = pbVar8;
32: pcVar10 = pcVar10 + 1;
33: } while (pbVar8 != pbVar6 + (ulong)(iVar1 - 1) * 3 + 3);
34: lVar9 = lVar9 + 8;
35: } while ((ulong)(param_4 - 1) * 8 + 8 != lVar9);
36: }
37: return;
38: }
39: 

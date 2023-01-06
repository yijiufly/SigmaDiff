1: 
2: void FUN_001393c0(long param_1,long param_2,long param_3,int param_4)
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
13: char *pcVar9;
14: long lVar10;
15: 
16: iVar1 = *(int *)(param_1 + 0x88);
17: plVar2 = *(long **)(*(long *)(param_1 + 0x270) + 0x30);
18: lVar3 = *plVar2;
19: lVar4 = plVar2[1];
20: lVar5 = plVar2[2];
21: if (0 < param_4) {
22: lVar10 = 0;
23: do {
24: pbVar6 = *(byte **)(param_2 + lVar10 * 8);
25: pbVar7 = pbVar6;
26: pcVar9 = *(char **)(param_3 + lVar10 * 8);
27: if (iVar1 != 0) {
28: do {
29: pbVar8 = pbVar7 + 3;
30: *pcVar9 = *(char *)(lVar3 + (ulong)*pbVar7) + *(char *)(lVar4 + (ulong)pbVar7[1]) +
31: *(char *)(lVar5 + (ulong)pbVar7[2]);
32: pbVar7 = pbVar8;
33: pcVar9 = pcVar9 + 1;
34: } while (pbVar8 != pbVar6 + (ulong)(iVar1 - 1) * 3 + 3);
35: }
36: lVar10 = lVar10 + 1;
37: } while ((int)lVar10 < param_4);
38: }
39: return;
40: }
41: 

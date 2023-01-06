1: 
2: void FUN_00145100(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: long lVar1;
6: byte *pbVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: char *pcVar6;
11: long lVar7;
12: char cVar8;
13: long lVar9;
14: long lVar10;
15: char *pcVar11;
16: char *pcVar12;
17: long lVar13;
18: 
19: iVar3 = *(int *)(param_1 + 0x90);
20: lVar5 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
21: iVar4 = *(int *)(param_1 + 0x88);
22: if ((0 < param_4) && (iVar4 != 0)) {
23: lVar13 = 0;
24: lVar10 = (ulong)(iVar3 - 1) + 1;
25: do {
26: pcVar6 = *(char **)(param_3 + lVar13);
27: lVar9 = *(long *)(param_2 + lVar13);
28: pcVar11 = pcVar6;
29: do {
30: lVar7 = 0;
31: cVar8 = '\0';
32: if (0 < iVar3) {
33: do {
34: pbVar2 = (byte *)(lVar9 + lVar7);
35: lVar1 = lVar7 * 8;
36: lVar7 = lVar7 + 1;
37: cVar8 = cVar8 + *(char *)(*(long *)(lVar5 + lVar1) + (ulong)*pbVar2);
38: } while (lVar10 != lVar7);
39: lVar9 = lVar9 + lVar10;
40: }
41: pcVar12 = pcVar11 + 1;
42: *pcVar11 = cVar8;
43: pcVar11 = pcVar12;
44: } while (pcVar12 != pcVar6 + (ulong)(iVar4 - 1) + 1);
45: lVar13 = lVar13 + 8;
46: } while ((ulong)(param_4 - 1) * 8 + 8 != lVar13);
47: }
48: return;
49: }
50: 

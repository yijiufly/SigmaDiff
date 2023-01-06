1: 
2: void FUN_001322c0(long param_1,long param_2,long param_3,long *param_4)
3: 
4: {
5: int iVar1;
6: byte *pbVar2;
7: long lVar3;
8: long lVar4;
9: byte *pbVar5;
10: long lVar6;
11: undefined *puVar7;
12: int iVar8;
13: undefined *puVar9;
14: int iVar10;
15: int iVar11;
16: long lVar12;
17: byte **ppbVar13;
18: long lVar14;
19: int iVar15;
20: 
21: lVar14 = *param_4;
22: if (0 < *(int *)(param_1 + 0x19c)) {
23: ppbVar13 = (byte **)(param_3 + -8);
24: iVar15 = 0;
25: do {
26: lVar12 = 0;
27: do {
28: pbVar2 = ppbVar13[1];
29: if ((int)lVar12 == 0) {
30: pbVar5 = *ppbVar13;
31: }
32: else {
33: pbVar5 = ppbVar13[2];
34: }
35: puVar7 = *(undefined **)(lVar14 + lVar12 * 8);
36: puVar9 = puVar7 + 2;
37: iVar10 = (uint)*pbVar5 + (uint)*pbVar2 + (uint)*pbVar2 * 2;
38: iVar8 = (uint)pbVar2[1] + (uint)pbVar2[1] * 2 + (uint)pbVar5[1];
39: *puVar7 = (char)(iVar10 * 4 + 8 >> 4);
40: puVar7[1] = (char)(iVar8 + 7 + iVar10 * 3 >> 4);
41: iVar1 = *(int *)(param_2 + 0x28);
42: if (iVar1 != 2) {
43: lVar6 = 0;
44: puVar7 = puVar9;
45: iVar11 = iVar10;
46: do {
47: iVar10 = iVar8;
48: lVar3 = lVar6 + 2;
49: lVar4 = lVar6 + 2;
50: lVar6 = lVar6 + 1;
51: iVar8 = (uint)pbVar5[lVar4] + (uint)pbVar2[lVar3] + (uint)pbVar2[lVar3] * 2;
52: *puVar7 = (char)(iVar11 + 8 + iVar10 * 3 >> 4);
53: puVar7[1] = (char)(iVar8 + 7 + iVar10 * 3 >> 4);
54: puVar7 = puVar7 + 2;
55: iVar11 = iVar10;
56: } while (lVar6 != (ulong)(iVar1 - 3) + 1);
57: puVar9 = puVar9 + lVar6 * 2;
58: }
59: lVar12 = lVar12 + 1;
60: *puVar9 = (char)(iVar10 + 8 + iVar8 * 3 >> 4);
61: puVar9[1] = (char)(iVar8 * 4 + 7 >> 4);
62: } while (lVar12 != 2);
63: iVar15 = iVar15 + 2;
64: lVar14 = lVar14 + 0x10;
65: ppbVar13 = ppbVar13 + 1;
66: } while (*(int *)(param_1 + 0x19c) != iVar15 && iVar15 <= *(int *)(param_1 + 0x19c));
67: }
68: return;
69: }
70: 

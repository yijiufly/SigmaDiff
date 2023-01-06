1: 
2: void FUN_0013d3f0(long param_1,long param_2,byte **param_3,long *param_4)
3: 
4: {
5: int iVar1;
6: undefined *puVar2;
7: long lVar3;
8: byte *pbVar4;
9: int iVar5;
10: byte *pbVar6;
11: int iVar7;
12: int iVar8;
13: undefined *puVar9;
14: long lVar10;
15: long lVar11;
16: int iVar12;
17: 
18: lVar11 = *param_4;
19: if (0 < *(int *)(param_1 + 0x19c)) {
20: iVar12 = 0;
21: do {
22: lVar10 = 0;
23: pbVar6 = *param_3;
24: pbVar4 = param_3[-1];
25: while( true ) {
26: puVar2 = *(undefined **)(lVar11 + lVar10 * 8);
27: iVar7 = (uint)*pbVar4 + (uint)*pbVar6 + (uint)*pbVar6 * 2;
28: iVar5 = (uint)pbVar6[1] + (uint)pbVar6[1] * 2 + (uint)pbVar4[1];
29: puVar9 = puVar2 + 2;
30: *puVar2 = (char)(iVar7 * 4 + 8 >> 4);
31: puVar2[1] = (char)(iVar5 + 7 + iVar7 * 3 >> 4);
32: iVar1 = *(int *)(param_2 + 0x28);
33: if (iVar1 != 2) {
34: lVar3 = 0;
35: iVar8 = iVar7;
36: do {
37: iVar7 = iVar5;
38: iVar5 = (uint)pbVar4[lVar3 + 2] + (uint)pbVar6[lVar3 + 2] + (uint)pbVar6[lVar3 + 2] * 2;
39: puVar9[lVar3 * 2] = (char)(iVar8 + 8 + iVar7 * 3 >> 4);
40: puVar2[lVar3 * 2 + 3] = (char)(iVar5 + 7 + iVar7 * 3 >> 4);
41: lVar3 = lVar3 + 1;
42: iVar8 = iVar7;
43: } while (lVar3 != (ulong)(iVar1 - 3) + 1);
44: puVar9 = puVar9 + lVar3 * 2;
45: }
46: *puVar9 = (char)(iVar7 + 8 + iVar5 * 3 >> 4);
47: puVar9[1] = (char)(iVar5 * 4 + 7 >> 4);
48: if (lVar10 == 1) break;
49: pbVar6 = *param_3;
50: lVar10 = 1;
51: pbVar4 = param_3[1];
52: }
53: iVar12 = iVar12 + 2;
54: lVar11 = lVar11 + 0x10;
55: param_3 = param_3 + 1;
56: } while (*(int *)(param_1 + 0x19c) != iVar12 && iVar12 <= *(int *)(param_1 + 0x19c));
57: }
58: return;
59: }
60: 

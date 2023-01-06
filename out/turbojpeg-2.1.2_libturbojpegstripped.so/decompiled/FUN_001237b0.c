1: 
2: void FUN_001237b0(long param_1,long param_2,byte **param_3,long param_4)
3: 
4: {
5: long lVar1;
6: byte **ppbVar2;
7: int iVar3;
8: uint uVar4;
9: int iVar5;
10: undefined *puVar6;
11: int iVar7;
12: ulong uVar8;
13: byte *pbVar9;
14: byte *pbVar10;
15: long lVar11;
16: byte *pbVar12;
17: byte *pbVar13;
18: long lVar14;
19: long lVar15;
20: byte **ppbVar16;
21: long lStack96;
22: 
23: iVar3 = *(int *)(param_2 + 0x1c);
24: uVar4 = *(uint *)(param_1 + 0x30);
25: iVar7 = iVar3 * 0x10 - uVar4;
26: if ((0 < iVar7) && (iVar5 = *(int *)(param_1 + 0x13c), -2 < iVar5)) {
27: ppbVar16 = param_3;
28: do {
29: ppbVar2 = ppbVar16 + -1;
30: ppbVar16 = ppbVar16 + 1;
31: memset(*ppbVar2 + uVar4,(uint)(*ppbVar2 + uVar4)[-1],(long)(iVar7 + -1) + 1);
32: } while (param_3 + (ulong)(iVar5 + 1) + 1 != ppbVar16);
33: }
34: lVar15 = (long)(*(int *)(param_1 + 0x110) << 4);
35: lVar14 = (long)(*(int *)(param_1 + 0x110) * -0x50 + 0x4000);
36: if (0 < *(int *)(param_2 + 0xc)) {
37: lStack96 = 1;
38: uVar8 = (ulong)(iVar3 * 8 - 3);
39: lVar1 = uVar8 + 3 + uVar8 + 1;
40: do {
41: pbVar13 = *param_3;
42: pbVar12 = param_3[1];
43: puVar6 = *(undefined **)(param_4 + -8 + lStack96 * 8);
44: pbVar10 = param_3[-1];
45: pbVar9 = param_3[2];
46: lVar11 = 0;
47: *puVar6 = (char)((ulong)((int)((uint)*pbVar12 + (uint)*pbVar13 + (uint)pbVar13[1] +
48: (uint)pbVar12[1]) * lVar14 + 0x8000 +
49: ((long)(int)((uint)*pbVar9 + (uint)*pbVar10 + (uint)pbVar10[2] +
50: (uint)pbVar9[2]) +
51: (long)(int)((uint)pbVar10[1] + (uint)*pbVar10 + (uint)*pbVar9 +
52: (uint)pbVar9[1] + (uint)*pbVar13 + (uint)pbVar13[2] +
53: (uint)*pbVar12 + (uint)pbVar12[2]) * 2) * lVar15) >> 0x10)
54: ;
55: do {
56: puVar6[lVar11 + 1] =
57: (char)((ulong)((int)((uint)pbVar13[lVar11 * 2 + 2] + (uint)pbVar13[lVar11 * 2 + 3] +
58: (uint)pbVar12[lVar11 * 2 + 2] + (uint)pbVar12[lVar11 * 2 + 3]) *
59: lVar14 + 0x8000 +
60: ((long)(int)((uint)pbVar10[lVar11 * 2 + 1] +
61: (uint)pbVar10[lVar11 * 2 + 4] + (uint)pbVar9[lVar11 * 2 + 1]
62: + (uint)pbVar9[lVar11 * 2 + 4]) +
63: (long)(int)((uint)pbVar10[lVar11 * 2 + 2] + (uint)pbVar10[lVar11 * 2 + 3]
64: + (uint)pbVar9[lVar11 * 2 + 2] + (uint)pbVar9[lVar11 * 2 + 3]
65: + (uint)pbVar13[lVar11 * 2 + 1] +
66: (uint)pbVar13[lVar11 * 2 + 4] + (uint)pbVar12[lVar11 * 2 + 1]
67: + (uint)pbVar12[lVar11 * 2 + 4]) * 2) * lVar15) >> 0x10);
68: lVar11 = lVar11 + 1;
69: } while (lVar11 != uVar8 + 1);
70: param_3 = param_3 + 2;
71: pbVar10 = pbVar10 + lVar1;
72: pbVar9 = pbVar9 + lVar1;
73: pbVar12 = pbVar12 + lVar1;
74: pbVar13 = pbVar13 + lVar1;
75: puVar6[uVar8 + 2] =
76: (char)((ulong)((int)((uint)pbVar13[1] + (uint)*pbVar13 + (uint)*pbVar12 +
77: (uint)pbVar12[1]) * lVar14 + 0x8000 +
78: ((long)(int)((uint)pbVar9[1] +
79: (uint)pbVar10[1] + (uint)pbVar10[-1] + (uint)pbVar9[-1]) +
80: (long)(int)((uint)*pbVar10 + (uint)pbVar10[1] + (uint)*pbVar9 +
81: (uint)pbVar9[1] + (uint)pbVar13[-1] + (uint)pbVar13[1] +
82: (uint)pbVar12[-1] + (uint)pbVar12[1]) * 2) * lVar15) >> 0x10);
83: iVar3 = (int)lStack96;
84: lStack96 = lStack96 + 1;
85: } while (*(int *)(param_2 + 0xc) != iVar3 && iVar3 <= *(int *)(param_2 + 0xc));
86: }
87: return;
88: }
89: 

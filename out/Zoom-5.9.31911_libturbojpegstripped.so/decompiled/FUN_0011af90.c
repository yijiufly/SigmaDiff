1: 
2: void FUN_0011af90(long param_1,long param_2,byte **param_3,long *param_4)
3: 
4: {
5: byte **ppbVar1;
6: byte *pbVar2;
7: byte *pbVar3;
8: byte bVar4;
9: int iVar5;
10: uint uVar6;
11: int iVar7;
12: byte *pbVar8;
13: undefined *puVar9;
14: long lVar10;
15: ulong uVar11;
16: byte *pbVar12;
17: byte *pbVar13;
18: byte *pbVar14;
19: byte *pbVar15;
20: byte *pbVar16;
21: uint uVar17;
22: long lVar18;
23: long lVar19;
24: byte *pbVar20;
25: undefined *puVar21;
26: undefined *puVar22;
27: byte **ppbVar23;
28: byte *pbVar24;
29: long *plStack128;
30: int iStack92;
31: 
32: iVar5 = *(int *)(param_2 + 0x1c);
33: uVar6 = *(uint *)(param_1 + 0x30);
34: uVar17 = iVar5 * 0x10 - uVar6;
35: iVar7 = *(int *)(param_1 + 0x13c);
36: if ((0 < (int)uVar17) && (-2 < iVar7)) {
37: ppbVar23 = param_3;
38: do {
39: ppbVar1 = ppbVar23 + -1;
40: ppbVar23 = ppbVar23 + 1;
41: memset(*ppbVar1 + uVar6,(uint)(*ppbVar1 + uVar6)[-1],(ulong)uVar17);
42: } while (ppbVar23 != param_3 + (ulong)(iVar7 + 1) + 1);
43: }
44: lVar18 = (long)(*(int *)(param_1 + 0x110) << 4);
45: lVar19 = (long)(*(int *)(param_1 + 0x110) * -0x50 + 0x4000);
46: if (0 < *(int *)(param_2 + 0xc)) {
47: iStack92 = 0;
48: uVar11 = (ulong)(iVar5 * 8 - 3);
49: lVar10 = (uVar11 + 1) * 2;
50: plStack128 = param_4;
51: do {
52: pbVar14 = param_3[-1];
53: pbVar16 = *param_3;
54: pbVar8 = param_3[1];
55: puVar9 = (undefined *)*plStack128;
56: pbVar13 = param_3[2];
57: pbVar24 = pbVar16 + 2;
58: pbVar12 = pbVar13 + 2;
59: *puVar9 = (char)((ulong)((int)((uint)*pbVar8 + (uint)*pbVar16 + (uint)pbVar16[1] +
60: (uint)pbVar8[1]) * lVar19 + 0x8000 +
61: ((long)(int)((uint)*pbVar13 + (uint)*pbVar14 + (uint)pbVar14[2] +
62: (uint)*pbVar12) +
63: (long)(int)((uint)pbVar8[2] +
64: (uint)pbVar14[1] + (uint)*pbVar14 + (uint)*pbVar13 +
65: (uint)pbVar13[1] + (uint)*pbVar16 + (uint)*pbVar24 +
66: (uint)*pbVar8) * 2) * lVar18) >> 0x10);
67: pbVar16 = pbVar24;
68: pbVar13 = pbVar14 + 2;
69: pbVar15 = pbVar8 + 2;
70: pbVar20 = pbVar12;
71: puVar21 = puVar9 + 1;
72: do {
73: pbVar2 = pbVar13 + 1;
74: bVar4 = *pbVar13;
75: puVar22 = puVar21 + 1;
76: pbVar3 = pbVar13 + -1;
77: pbVar13 = pbVar13 + 2;
78: *puVar21 = (char)((ulong)((int)((uint)*pbVar16 + (uint)pbVar16[1] + (uint)*pbVar15 +
79: (uint)pbVar15[1]) * lVar19 + 0x8000 +
80: ((long)(int)((uint)*pbVar13 + (uint)*pbVar3 + (uint)pbVar20[-1] +
81: (uint)pbVar20[2]) +
82: (long)(int)((uint)bVar4 + (uint)*pbVar2 + (uint)*pbVar20 +
83: (uint)pbVar20[1] + (uint)pbVar16[-1] + (uint)pbVar16[2]
84: + (uint)pbVar15[-1] + (uint)pbVar15[2]) * 2) * lVar18)
85: >> 0x10);
86: pbVar16 = pbVar16 + 2;
87: pbVar15 = pbVar15 + 2;
88: pbVar20 = pbVar20 + 2;
89: puVar21 = puVar22;
90: } while (puVar22 != puVar9 + uVar11 + 2);
91: param_3 = param_3 + 2;
92: iStack92 = iStack92 + 1;
93: plStack128 = plStack128 + 1;
94: pbVar16 = pbVar14 + 2 + lVar10;
95: pbVar24 = pbVar24 + lVar10;
96: pbVar12 = pbVar12 + lVar10;
97: pbVar14 = pbVar8 + 2 + lVar10;
98: puVar9[uVar11 + 2] =
99: (char)((ulong)((int)((uint)pbVar24[1] + (uint)*pbVar24 + (uint)*pbVar14 +
100: (uint)pbVar14[1]) * lVar19 + 0x8000 +
101: ((long)(int)((uint)pbVar12[1] +
102: (uint)pbVar12[-1] + (uint)pbVar16[1] + (uint)pbVar16[-1]) +
103: (long)(int)((uint)pbVar14[-1] +
104: (uint)*pbVar16 + (uint)pbVar16[1] + (uint)*pbVar12 +
105: (uint)pbVar12[1] + (uint)pbVar24[-1] + (uint)pbVar24[1] +
106: (uint)pbVar14[1]) * 2) * lVar18) >> 0x10);
107: } while (*(int *)(param_2 + 0xc) != iStack92 && iStack92 <= *(int *)(param_2 + 0xc));
108: }
109: return;
110: }
111: 

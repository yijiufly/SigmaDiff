1: 
2: void FUN_0013f5d0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: short *psVar2;
7: short *psVar3;
8: short *psVar4;
9: short *psVar5;
10: short *psVar6;
11: short *psVar7;
12: short sVar8;
13: long lVar9;
14: long lVar10;
15: undefined *puVar11;
16: float *pfVar12;
17: float *pfVar13;
18: float *pfVar14;
19: long in_FS_OFFSET;
20: float fVar15;
21: float fVar16;
22: float fVar17;
23: float fVar18;
24: float fVar19;
25: float fVar20;
26: float fVar21;
27: float fVar22;
28: float fVar23;
29: float fVar24;
30: float fVar25;
31: float afStack328 [66];
32: long lStack64;
33: 
34: lVar9 = *(long *)(param_1 + 0x1a8);
35: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
36: pfVar12 = afStack328;
37: pfVar14 = *(float **)(param_2 + 0x58);
38: do {
39: sVar8 = *param_3;
40: psVar1 = param_3 + 8;
41: psVar2 = param_3 + 0x10;
42: psVar3 = param_3 + 0x20;
43: psVar4 = param_3 + 0x30;
44: psVar5 = param_3 + 0x18;
45: psVar6 = param_3 + 0x28;
46: psVar7 = param_3 + 0x38;
47: pfVar13 = pfVar12 + 1;
48: param_3 = param_3 + 1;
49: fVar17 = (float)(int)sVar8 * *pfVar14 * 0.125;
50: if ((((*psVar1 == 0) && (*psVar2 == 0)) && (*psVar5 == 0)) &&
51: (((*psVar3 == 0 && (*psVar6 == 0)) && ((*psVar4 == 0 && (*psVar7 == 0)))))) {
52: *pfVar12 = fVar17;
53: pfVar12[8] = fVar17;
54: pfVar12[0x10] = fVar17;
55: pfVar12[0x18] = fVar17;
56: pfVar12[0x20] = fVar17;
57: pfVar12[0x28] = fVar17;
58: pfVar12[0x30] = fVar17;
59: pfVar12[0x38] = fVar17;
60: }
61: else {
62: fVar15 = (float)(int)*psVar2 * pfVar14[0x10] * 0.125;
63: fVar16 = (float)(int)*psVar3 * pfVar14[0x20] * 0.125;
64: fVar18 = (float)(int)*psVar4 * pfVar14[0x30] * 0.125;
65: fVar20 = fVar16 + fVar17;
66: fVar17 = fVar17 - fVar16;
67: fVar16 = fVar15 + fVar18;
68: fVar22 = fVar20 + fVar16;
69: fVar20 = fVar20 - fVar16;
70: fVar16 = (fVar15 - fVar18) * 1.414214 - fVar16;
71: fVar21 = fVar17 + fVar16;
72: fVar17 = fVar17 - fVar16;
73: fVar16 = pfVar14[8] * 0.125 * (float)(int)*psVar1;
74: fVar18 = pfVar14[0x18] * 0.125 * (float)(int)*psVar5;
75: fVar15 = (float)(int)*psVar6 * pfVar14[0x28] * 0.125;
76: fVar19 = (float)(int)*psVar7 * pfVar14[0x38] * 0.125;
77: fVar23 = fVar18 + fVar15;
78: fVar15 = fVar15 - fVar18;
79: fVar18 = fVar16 - fVar19;
80: fVar16 = fVar16 + fVar19;
81: fVar24 = fVar23 + fVar16;
82: fVar19 = (fVar15 + fVar18) * 1.847759;
83: fVar25 = (fVar19 - fVar15 * 2.613126) - fVar24;
84: *pfVar12 = fVar22 + fVar24;
85: pfVar12[0x38] = fVar22 - fVar24;
86: fVar15 = (fVar16 - fVar23) * 1.414214 - fVar25;
87: pfVar12[8] = fVar21 + fVar25;
88: pfVar12[0x30] = fVar21 - fVar25;
89: fVar16 = (fVar19 - fVar18 * 1.082392) - fVar15;
90: pfVar12[0x10] = fVar17 + fVar15;
91: pfVar12[0x28] = fVar17 - fVar15;
92: pfVar12[0x20] = fVar20 - fVar16;
93: pfVar12[0x18] = fVar20 + fVar16;
94: }
95: pfVar12 = pfVar13;
96: pfVar14 = pfVar14 + 1;
97: } while (pfVar13 != afStack328 + 8);
98: pfVar12 = afStack328;
99: do {
100: lVar10 = *param_4;
101: pfVar14 = pfVar12 + 8;
102: param_4 = param_4 + 1;
103: puVar11 = (undefined *)(lVar10 + (ulong)param_5);
104: fVar17 = pfVar12[4] + *pfVar12 + 128.5;
105: fVar15 = (*pfVar12 + 128.5) - pfVar12[4];
106: fVar16 = pfVar12[2] + pfVar12[6];
107: fVar19 = fVar17 + fVar16;
108: fVar17 = fVar17 - fVar16;
109: fVar16 = (pfVar12[2] - pfVar12[6]) * 1.414214 - fVar16;
110: fVar18 = fVar15 + fVar16;
111: fVar15 = fVar15 - fVar16;
112: fVar20 = pfVar12[5] - pfVar12[3];
113: fVar24 = pfVar12[5] + pfVar12[3];
114: fVar22 = pfVar12[1] - pfVar12[7];
115: fVar16 = pfVar12[1] + pfVar12[7];
116: fVar23 = fVar24 + fVar16;
117: fVar21 = (fVar20 + fVar22) * 1.847759;
118: fVar20 = (fVar21 - fVar20 * 2.613126) - fVar23;
119: fVar16 = (fVar16 - fVar24) * 1.414214 - fVar20;
120: fVar21 = (fVar21 - fVar22 * 1.082392) - fVar16;
121: *puVar11 = *(undefined *)(lVar9 + (ulong)((int)(fVar19 + fVar23) & 0x3ff));
122: puVar11[7] = *(undefined *)(lVar9 + (ulong)((int)(fVar19 - fVar23) & 0x3ff));
123: puVar11[1] = *(undefined *)(lVar9 + (ulong)((int)(fVar18 + fVar20) & 0x3ff));
124: puVar11[6] = *(undefined *)(lVar9 + (ulong)((int)(fVar18 - fVar20) & 0x3ff));
125: puVar11[2] = *(undefined *)(lVar9 + (ulong)((int)(fVar15 + fVar16) & 0x3ff));
126: puVar11[5] = *(undefined *)(lVar9 + (ulong)((int)(fVar15 - fVar16) & 0x3ff));
127: puVar11[3] = *(undefined *)(lVar9 + (ulong)((int)(fVar17 + fVar21) & 0x3ff));
128: puVar11[4] = *(undefined *)(lVar9 + (ulong)((int)(fVar17 - fVar21) & 0x3ff));
129: pfVar12 = pfVar14;
130: } while (pfVar14 != afStack328 + 0x40);
131: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
132: return;
133: }
134: /* WARNING: Subroutine does not return */
135: __stack_chk_fail();
136: }
137: 

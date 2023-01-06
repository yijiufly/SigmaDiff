1: 
2: void FUN_00141c40(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: short *psVar2;
7: short *psVar3;
8: short *psVar4;
9: short *psVar5;
10: long lVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: undefined *puVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: short *psVar17;
22: long lVar18;
23: long lVar19;
24: long lVar20;
25: long lVar21;
26: long lVar22;
27: int *piVar23;
28: int *piVar24;
29: long in_FS_OFFSET;
30: long *plStack472;
31: int aiStack392 [8];
32: int aiStack360 [8];
33: int aiStack328 [8];
34: int aiStack296 [8];
35: int aiStack264 [8];
36: int aiStack232 [8];
37: int aiStack200 [8];
38: int aiStack168 [8];
39: int aiStack136 [8];
40: int aiStack104 [8];
41: int aiStack72 [2];
42: long lStack64;
43: 
44: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
45: piVar24 = aiStack392;
46: psVar17 = *(short **)(param_2 + 0x58);
47: lVar6 = *(long *)(param_1 + 0x1a8) + 0x80;
48: psVar1 = param_3 + 8;
49: piVar23 = piVar24;
50: do {
51: lVar20 = (long)((int)*param_3 * (int)*psVar17) * 0x2000 + 0x400;
52: lVar9 = (long)((int)param_3[0x20] * (int)psVar17[0x20]);
53: lVar16 = lVar20 + lVar9 * 0x249d;
54: lVar11 = lVar20 + lVar9 * -0xdfc;
55: lVar19 = ((long)((int)param_3[0x10] * (int)psVar17[0x10]) +
56: (long)((int)param_3[0x30] * (int)psVar17[0x30])) * 0x1a9a;
57: psVar2 = psVar17 + 8;
58: lVar15 = (long)((int)param_3[0x10] * (int)psVar17[0x10]) * 0x1071 + lVar19;
59: lVar19 = (long)((int)param_3[0x30] * (int)psVar17[0x30]) * -0x45a4 + lVar19;
60: lVar18 = lVar16 + lVar15;
61: lVar16 = lVar16 - lVar15;
62: lVar15 = lVar11 + lVar19;
63: lVar11 = lVar11 - lVar19;
64: psVar3 = param_3 + 8;
65: psVar4 = param_3 + 0x28;
66: lVar10 = (long)((int)*psVar3 * (int)*psVar2);
67: psVar5 = psVar17 + 0x28;
68: lVar19 = (long)((int)param_3[0x18] * (int)psVar17[0x18]) +
69: (long)((int)param_3[0x38] * (int)psVar17[0x38]);
70: lVar14 = (long)((int)param_3[0x18] * (int)psVar17[0x18]) -
71: (long)((int)param_3[0x38] * (int)psVar17[0x38]);
72: lVar12 = (long)((int)*psVar4 * (int)*psVar5) * 0x2000;
73: lVar22 = lVar14 * 0x9e3 + lVar12;
74: lVar12 = lVar12 + lVar14 * -0x19e3;
75: lVar21 = lVar10 * 0x2cb3 + lVar19 * 0x1e6f + lVar22;
76: lVar22 = lVar22 + lVar10 * 0x714 + lVar19 * -0x1e6f;
77: param_3 = param_3 + 1;
78: psVar17 = psVar17 + 1;
79: iVar8 = ((int)*psVar3 * (int)*psVar2 - (int)lVar14) - (int)*psVar4 * (int)*psVar5;
80: lVar14 = (lVar10 * 0x2853 + lVar19 * -0x12cf) - lVar12;
81: lVar12 = lVar12 + lVar10 * 0x148c + lVar19 * -0x12cf;
82: piVar23[0x48] = (int)(lVar18 - lVar21 >> 0xb);
83: *piVar23 = (int)(lVar18 + lVar21 >> 0xb);
84: piVar23[8] = (int)(lVar15 + lVar14 >> 0xb);
85: piVar23[0x40] = (int)(lVar15 - lVar14 >> 0xb);
86: iVar7 = (int)(lVar20 + lVar9 * -0x2d42 >> 0xb);
87: piVar23[0x38] = iVar7 + iVar8 * -4;
88: piVar23[0x10] = iVar8 * 4 + iVar7;
89: piVar23[0x18] = (int)(lVar11 + lVar12 >> 0xb);
90: piVar23[0x30] = (int)(lVar11 - lVar12 >> 0xb);
91: piVar23[0x20] = (int)(lVar16 + lVar22 >> 0xb);
92: piVar23[0x28] = (int)(lVar16 - lVar22 >> 0xb);
93: piVar23 = piVar23 + 1;
94: } while (param_3 != psVar1);
95: plStack472 = param_4;
96: do {
97: lVar16 = (long)piVar24[4];
98: puVar13 = (undefined *)((ulong)param_5 + *plStack472);
99: lVar10 = (long)piVar24[5] * 0x2000;
100: lVar22 = ((long)*piVar24 + 0x10) * 0x2000;
101: lVar20 = lVar22 + lVar16 * 0x249d;
102: lVar12 = lVar22 + lVar16 * -0xdfc;
103: lVar22 = lVar22 + lVar16 * -0x2d42;
104: lVar15 = ((long)piVar24[2] + (long)piVar24[6]) * 0x1a9a;
105: lVar18 = (long)piVar24[2] * 0x1071 + lVar15;
106: lVar15 = (long)piVar24[6] * -0x45a4 + lVar15;
107: lVar16 = lVar20 + lVar18;
108: lVar20 = lVar20 - lVar18;
109: lVar18 = lVar12 + lVar15;
110: lVar12 = lVar12 - lVar15;
111: lVar9 = (long)piVar24[1];
112: lVar15 = (long)piVar24[3] + (long)piVar24[7];
113: lVar11 = (long)piVar24[3] - (long)piVar24[7];
114: lVar19 = lVar10 + lVar11 * 0x9e3;
115: lVar14 = lVar9 * 0x2cb3 + lVar15 * 0x1e6f + lVar19;
116: lVar19 = lVar19 + lVar9 * 0x714 + lVar15 * -0x1e6f;
117: lVar10 = lVar10 + lVar11 * -0x19e3;
118: lVar21 = (lVar9 - lVar11) * 0x2000 + (long)piVar24[5] * -0x2000;
119: lVar11 = (lVar9 * 0x2853 + lVar15 * -0x12cf) - lVar10;
120: lVar10 = lVar10 + lVar9 * 0x148c + lVar15 * -0x12cf;
121: *puVar13 = *(undefined *)(lVar6 + (ulong)((uint)(lVar16 + lVar14 >> 0x12) & 0x3ff));
122: puVar13[9] = *(undefined *)(lVar6 + (ulong)((uint)(lVar16 - lVar14 >> 0x12) & 0x3ff));
123: puVar13[1] = *(undefined *)(lVar6 + (ulong)((uint)(lVar18 + lVar11 >> 0x12) & 0x3ff));
124: puVar13[8] = *(undefined *)(lVar6 + (ulong)((uint)(lVar18 - lVar11 >> 0x12) & 0x3ff));
125: puVar13[2] = *(undefined *)(lVar6 + (ulong)((uint)(lVar22 + lVar21 >> 0x12) & 0x3ff));
126: puVar13[7] = *(undefined *)(lVar6 + (ulong)((uint)(lVar22 - lVar21 >> 0x12) & 0x3ff));
127: puVar13[3] = *(undefined *)(lVar6 + (ulong)((uint)(lVar12 + lVar10 >> 0x12) & 0x3ff));
128: puVar13[6] = *(undefined *)(lVar6 + (ulong)((uint)(lVar12 - lVar10 >> 0x12) & 0x3ff));
129: puVar13[4] = *(undefined *)(lVar6 + (ulong)((uint)(lVar20 + lVar19 >> 0x12) & 0x3ff));
130: piVar24 = piVar24 + 8;
131: plStack472 = plStack472 + 1;
132: puVar13[5] = *(undefined *)(lVar6 + (ulong)((uint)(lVar20 - lVar19 >> 0x12) & 0x3ff));
133: } while (piVar24 != aiStack72);
134: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
135: return;
136: }
137: /* WARNING: Subroutine does not return */
138: __stack_chk_fail();
139: }
140: 

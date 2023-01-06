1: 
2: void FUN_00134eb0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: short *psVar2;
7: int *piVar3;
8: long lVar4;
9: long lVar5;
10: undefined *puVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: int *piVar20;
25: long *plStack304;
26: int aiStack264 [7];
27: int aiStack236 [7];
28: int aiStack208 [7];
29: int aiStack180 [7];
30: int aiStack152 [7];
31: int aiStack124 [7];
32: int aiStack96 [7];
33: int aiStack68 [5];
34: 
35: psVar1 = param_3 + 7;
36: psVar2 = *(short **)(param_2 + 0x58);
37: piVar3 = aiStack264;
38: lVar4 = *(long *)(param_1 + 0x1a8) + 0x80;
39: piVar20 = piVar3;
40: do {
41: lVar8 = (long)((int)*param_3 * (int)*psVar2) * 0x2000 + 0x400;
42: lVar9 = (long)((int)param_3[0x10] * (int)psVar2[0x10]);
43: lVar5 = (long)((int)param_3[0x20] * (int)psVar2[0x20]);
44: lVar10 = (long)((int)param_3[0x30] * (int)psVar2[0x30]);
45: lVar17 = (lVar5 - lVar10) * 0x1c37;
46: lVar13 = (lVar9 - lVar5) * 0xa12;
47: lVar7 = lVar17 + lVar13 + lVar8 + lVar5 * -0x3aeb;
48: lVar16 = (lVar9 + lVar10) * 0x28c6 + lVar8;
49: lVar13 = lVar16 + lVar9 * -0x4f0f + lVar13;
50: lVar17 = lVar10 * -0x27d + lVar16 + lVar17;
51: lVar11 = (long)((int)param_3[8] * (int)psVar2[8]);
52: lVar14 = (long)((int)param_3[0x18] * (int)psVar2[0x18]);
53: lVar16 = (long)((int)param_3[0x28] * (int)psVar2[0x28]);
54: lVar19 = (lVar11 + lVar14) * 0x1def;
55: lVar15 = (lVar14 + lVar16) * -0x2c1f;
56: lVar18 = (lVar11 - lVar14) * 0x573 + lVar19 + lVar15;
57: lVar12 = (lVar11 + lVar16) * 0x13a3;
58: param_3 = param_3 + 1;
59: psVar2 = psVar2 + 1;
60: lVar11 = lVar19 + (lVar11 - lVar14) * -0x573 + lVar12;
61: lVar15 = lVar15 + lVar16 * 0x3bde + lVar12;
62: piVar20[0x15] = (int)(lVar8 + (lVar5 - (lVar9 + lVar10)) * 0x2d41 >> 0xb);
63: *piVar20 = (int)(lVar17 + lVar11 >> 0xb);
64: piVar20[0x2a] = (int)(lVar17 - lVar11 >> 0xb);
65: piVar20[0x23] = (int)(lVar7 - lVar18 >> 0xb);
66: piVar20[7] = (int)(lVar7 + lVar18 >> 0xb);
67: piVar20[0x1c] = (int)(lVar13 - lVar15 >> 0xb);
68: piVar20[0xe] = (int)(lVar13 + lVar15 >> 0xb);
69: piVar20 = piVar20 + 1;
70: } while (param_3 != psVar1);
71: plStack304 = param_4;
72: do {
73: lVar9 = (long)piVar3[4];
74: lVar16 = (long)piVar3[2];
75: lVar11 = (long)piVar3[6];
76: puVar6 = (undefined *)((ulong)param_5 + *plStack304);
77: lVar15 = (lVar9 - lVar11) * 0x1c37;
78: lVar7 = (lVar16 - lVar9) * 0xa12;
79: lVar8 = ((long)*piVar3 + 0x10) * 0x2000;
80: lVar17 = lVar15 + lVar7 + lVar8 + lVar9 * -0x3aeb;
81: lVar12 = (long)piVar3[1];
82: lVar5 = (lVar16 + lVar11) * 0x28c6 + lVar8;
83: lVar10 = (long)piVar3[5];
84: lVar7 = lVar5 + lVar16 * -0x4f0f + lVar7;
85: lVar13 = (long)piVar3[3];
86: lVar15 = lVar11 * -0x27d + lVar5 + lVar15;
87: lVar18 = (lVar12 + lVar13) * 0x1def;
88: lVar5 = (lVar12 + lVar10) * 0x13a3;
89: lVar19 = lVar18 + (lVar12 - lVar13) * -0x573 + lVar5;
90: lVar14 = (lVar13 + lVar10) * -0x2c1f;
91: lVar12 = (lVar12 - lVar13) * 0x573 + lVar18 + lVar14;
92: lVar14 = lVar14 + lVar10 * 0x3bde + lVar5;
93: piVar3 = piVar3 + 7;
94: plStack304 = plStack304 + 1;
95: *puVar6 = *(undefined *)(lVar4 + (ulong)((uint)(lVar15 + lVar19 >> 0x12) & 0x3ff));
96: puVar6[6] = *(undefined *)(lVar4 + (ulong)((uint)(lVar15 - lVar19 >> 0x12) & 0x3ff));
97: puVar6[1] = *(undefined *)(lVar4 + (ulong)((uint)(lVar17 + lVar12 >> 0x12) & 0x3ff));
98: puVar6[5] = *(undefined *)(lVar4 + (ulong)((uint)(lVar17 - lVar12 >> 0x12) & 0x3ff));
99: puVar6[2] = *(undefined *)(lVar4 + (ulong)((uint)(lVar7 + lVar14 >> 0x12) & 0x3ff));
100: puVar6[4] = *(undefined *)(lVar4 + (ulong)((uint)(lVar7 - lVar14 >> 0x12) & 0x3ff));
101: puVar6[3] = *(undefined *)
102: (lVar4 + (ulong)((uint)(lVar8 + (lVar9 - (lVar16 + lVar11)) * 0x2d41 >> 0x12) &
103: 0x3ff));
104: } while (piVar3 != aiStack68);
105: return;
106: }
107: 

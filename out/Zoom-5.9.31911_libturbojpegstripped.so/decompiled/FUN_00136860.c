1: 
2: void FUN_00136860(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: long lVar2;
7: long lVar3;
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
21: int *piVar17;
22: long lVar18;
23: long lVar19;
24: short *psVar20;
25: int *piVar21;
26: long *plStack528;
27: int aiStack440 [8];
28: int aiStack408 [8];
29: int aiStack376 [8];
30: int aiStack344 [8];
31: int aiStack312 [8];
32: int aiStack280 [8];
33: int aiStack248 [8];
34: int aiStack216 [8];
35: int aiStack184 [8];
36: int aiStack152 [8];
37: int aiStack120 [8];
38: int aiStack88 [8];
39: int aiStack56 [2];
40: 
41: psVar20 = *(short **)(param_2 + 0x58);
42: lVar2 = *(long *)(param_1 + 0x1a8) + 0x80;
43: psVar1 = param_3 + 8;
44: piVar21 = aiStack440;
45: piVar17 = piVar21;
46: do {
47: lVar7 = (long)((int)*param_3 * (int)*psVar20) * 0x2000 + 0x400;
48: lVar14 = lVar7 + (long)((int)param_3[0x20] * (int)psVar20[0x20]) * 0x2731;
49: lVar10 = lVar7 + (long)((int)param_3[0x20] * (int)psVar20[0x20]) * -0x2731;
50: lVar12 = (long)((int)param_3[0x10] * (int)psVar20[0x10]);
51: lVar4 = (long)((int)param_3[0x30] * (int)psVar20[0x30]);
52: lVar16 = lVar12 * 0x2000 + lVar4 * -0x2000;
53: lVar3 = lVar7 + lVar16;
54: lVar7 = lVar7 - lVar16;
55: lVar16 = lVar12 * 0x2bb6 + lVar4 * 0x2000;
56: lVar12 = lVar12 * 0xbb6 + lVar4 * -0x2000;
57: lVar4 = lVar10 + lVar12;
58: lVar10 = lVar10 - lVar12;
59: lVar12 = lVar14 + lVar16;
60: lVar14 = lVar14 - lVar16;
61: lVar9 = (long)((int)param_3[8] * (int)psVar20[8]);
62: lVar11 = (long)((int)param_3[0x18] * (int)psVar20[0x18]);
63: lVar8 = (long)((int)param_3[0x28] * (int)psVar20[0x28]);
64: lVar16 = (long)((int)param_3[0x38] * (int)psVar20[0x38]);
65: lVar13 = (lVar9 + lVar8 + lVar16) * 0x1b8d;
66: lVar18 = (lVar8 + lVar16) * -0x2175;
67: lVar19 = (lVar9 + lVar8) * 0x85b + lVar13;
68: lVar15 = lVar9 * 0x8f7 + lVar19 + lVar11 * 0x29cf;
69: lVar19 = lVar19 + lVar8 * -0x2f50 + lVar18 + lVar11 * -0x1151;
70: lVar18 = lVar18 + lVar16 * 0x32c6 + lVar13 + lVar11 * -0x29cf;
71: lVar5 = ((lVar9 - lVar16) + (lVar11 - lVar8)) * 0x1151;
72: lVar13 = lVar11 * -0x1151 + lVar9 * -0x15a4 + lVar16 * -0x3f74 + lVar13;
73: lVar16 = (lVar9 - lVar16) * 0x187e + lVar5;
74: *piVar17 = (int)(lVar12 + lVar15 >> 0xb);
75: piVar17[0x58] = (int)(lVar12 - lVar15 >> 0xb);
76: lVar5 = lVar5 + (lVar11 - lVar8) * -0x3b21;
77: piVar17[0x50] = (int)(lVar3 - lVar16 >> 0xb);
78: piVar17[8] = (int)(lVar3 + lVar16 >> 0xb);
79: piVar17[0x10] = (int)(lVar4 + lVar19 >> 0xb);
80: piVar17[0x48] = (int)(lVar4 - lVar19 >> 0xb);
81: piVar17[0x18] = (int)(lVar10 + lVar18 >> 0xb);
82: piVar17[0x40] = (int)(lVar10 - lVar18 >> 0xb);
83: piVar17[0x38] = (int)(lVar7 - lVar5 >> 0xb);
84: piVar17[0x20] = (int)(lVar7 + lVar5 >> 0xb);
85: piVar17[0x28] = (int)(lVar14 + lVar13 >> 0xb);
86: param_3 = param_3 + 1;
87: psVar20 = psVar20 + 1;
88: piVar17[0x30] = (int)(lVar14 - lVar13 >> 0xb);
89: piVar17 = piVar17 + 1;
90: } while (param_3 != psVar1);
91: plStack528 = param_4;
92: do {
93: lVar7 = (long)piVar21[2];
94: puVar6 = (undefined *)((ulong)param_5 + *plStack528);
95: lVar5 = ((long)*piVar21 + 0x10) * 0x2000;
96: lVar14 = lVar5 + (long)piVar21[4] * 0x2731;
97: lVar10 = lVar5 + (long)piVar21[4] * -0x2731;
98: lVar12 = (long)piVar21[6];
99: lVar16 = lVar7 * 0x2000 + lVar12 * -0x2000;
100: lVar3 = lVar5 + lVar16;
101: lVar5 = lVar5 - lVar16;
102: lVar16 = lVar7 * 0x2bb6 + lVar12 * 0x2000;
103: lVar13 = (long)piVar21[3];
104: lVar4 = lVar14 + lVar16;
105: lVar14 = lVar14 - lVar16;
106: lVar7 = lVar7 * 0xbb6 + lVar12 * -0x2000;
107: lVar12 = (long)piVar21[1];
108: lVar16 = lVar10 + lVar7;
109: lVar10 = lVar10 - lVar7;
110: lVar11 = (long)piVar21[5];
111: lVar7 = (long)piVar21[7];
112: lVar15 = (lVar12 + lVar11 + lVar7) * 0x1b8d;
113: lVar19 = (lVar12 + lVar11) * 0x85b + lVar15;
114: lVar9 = (lVar11 + lVar7) * -0x2175;
115: lVar18 = lVar12 * 0x8f7 + lVar19 + lVar13 * 0x29cf;
116: lVar19 = lVar19 + lVar11 * -0x2f50 + lVar9 + lVar13 * -0x1151;
117: lVar9 = lVar9 + lVar7 * 0x32c6 + lVar15 + lVar13 * -0x29cf;
118: lVar15 = lVar13 * -0x1151 + lVar12 * -0x15a4 + lVar7 * -0x3f74 + lVar15;
119: lVar8 = ((lVar12 - lVar7) + (lVar13 - lVar11)) * 0x1151;
120: *puVar6 = *(undefined *)(lVar2 + (ulong)((uint)(lVar4 + lVar18 >> 0x12) & 0x3ff));
121: lVar12 = (lVar12 - lVar7) * 0x187e + lVar8;
122: lVar8 = lVar8 + (lVar13 - lVar11) * -0x3b21;
123: puVar6[0xb] = *(undefined *)(lVar2 + (ulong)((uint)(lVar4 - lVar18 >> 0x12) & 0x3ff));
124: puVar6[1] = *(undefined *)(lVar2 + (ulong)((uint)(lVar3 + lVar12 >> 0x12) & 0x3ff));
125: puVar6[10] = *(undefined *)(lVar2 + (ulong)((uint)(lVar3 - lVar12 >> 0x12) & 0x3ff));
126: puVar6[2] = *(undefined *)(lVar2 + (ulong)((uint)(lVar16 + lVar19 >> 0x12) & 0x3ff));
127: puVar6[9] = *(undefined *)(lVar2 + (ulong)((uint)(lVar16 - lVar19 >> 0x12) & 0x3ff));
128: puVar6[3] = *(undefined *)(lVar2 + (ulong)((uint)(lVar10 + lVar9 >> 0x12) & 0x3ff));
129: puVar6[8] = *(undefined *)(lVar2 + (ulong)((uint)(lVar10 - lVar9 >> 0x12) & 0x3ff));
130: piVar21 = piVar21 + 8;
131: plStack528 = plStack528 + 1;
132: puVar6[4] = *(undefined *)(lVar2 + (ulong)((uint)(lVar5 + lVar8 >> 0x12) & 0x3ff));
133: puVar6[7] = *(undefined *)(lVar2 + (ulong)((uint)(lVar5 - lVar8 >> 0x12) & 0x3ff));
134: puVar6[5] = *(undefined *)(lVar2 + (ulong)((uint)(lVar14 + lVar15 >> 0x12) & 0x3ff));
135: puVar6[6] = *(undefined *)(lVar2 + (ulong)((uint)(lVar14 - lVar15 >> 0x12) & 0x3ff));
136: } while (piVar21 != aiStack56);
137: return;
138: }
139: 
1: 
2: void FUN_001362a0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: long lVar2;
7: short *psVar3;
8: undefined *puVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: int *piVar8;
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
25: long lVar21;
26: long lVar22;
27: long lVar23;
28: long *plStack480;
29: int aiStack408 [8];
30: int aiStack376 [8];
31: int aiStack344 [8];
32: int aiStack312 [8];
33: int aiStack280 [8];
34: int aiStack248 [8];
35: int aiStack216 [8];
36: int aiStack184 [8];
37: int aiStack152 [8];
38: int aiStack120 [8];
39: int aiStack88 [8];
40: int aiStack56 [2];
41: 
42: psVar1 = param_3 + 8;
43: piVar20 = aiStack408;
44: lVar2 = *(long *)(param_1 + 0x1a8) + 0x80;
45: psVar3 = *(short **)(param_2 + 0x58);
46: piVar8 = piVar20;
47: do {
48: lVar9 = (long)((int)param_3[0x10] * (int)psVar3[0x10]);
49: lVar5 = (long)((int)param_3[0x20] * (int)psVar3[0x20]);
50: lVar10 = (long)((int)param_3[0x30] * (int)psVar3[0x30]);
51: lVar16 = (lVar5 - lVar10) * 0x517e;
52: lVar17 = (lVar9 + lVar10) - lVar5;
53: lVar14 = (lVar5 - lVar9) * 0xdc9;
54: lVar6 = (long)((int)*param_3 * (int)*psVar3) * 0x2000 + 0x400 + lVar17 * 0x2b6c;
55: lVar12 = (lVar9 + lVar10) * -0x24fb + lVar6;
56: lVar7 = lVar16 + lVar14 + lVar6 + lVar5 * -0x3a4c;
57: lVar16 = lVar10 * 0x43b5 + lVar6 + lVar16;
58: lVar10 = lVar10 * -0x193d + lVar12;
59: lVar14 = lVar9 * -0x306f + lVar6 + lVar14;
60: lVar12 = lVar5 * 0x3e39 + lVar9 * -0x2c83 + lVar12;
61: lVar15 = (long)((int)param_3[8] * (int)psVar3[8]);
62: lVar11 = (long)((int)param_3[0x18] * (int)psVar3[0x18]);
63: lVar9 = (long)((int)param_3[0x28] * (int)psVar3[0x28]);
64: lVar23 = (lVar15 + lVar11) * 0x1c6a;
65: lVar5 = (long)((int)param_3[0x38] * (int)psVar3[0x38]);
66: lVar13 = (lVar15 + lVar11 + lVar9 + lVar5) * 0xcc0;
67: lVar21 = (lVar15 + lVar9) * 0x1574;
68: lVar19 = (lVar15 + lVar5) * 3000 + lVar13;
69: lVar18 = lVar15 * -0x1d8a + lVar23 + lVar21 + lVar19;
70: lVar15 = (lVar11 + lVar9) * -0x2537 + lVar13;
71: lVar21 = lVar15 + lVar9 * -0x2626 + lVar21;
72: lVar22 = (lVar11 + lVar5) * -0x398b;
73: lVar15 = lVar11 * 0x4258 + lVar15 + lVar23 + lVar22;
74: lVar19 = lVar22 + lVar5 * 0x4347 + lVar19;
75: piVar8[0x50] = (int)(lVar16 - lVar18 >> 0xb);
76: *piVar8 = (int)(lVar16 + lVar18 >> 0xb);
77: lVar13 = lVar13 + lVar11 * -0x2ef3 + lVar9 * 0x200b + lVar5 * -0x35ea;
78: piVar8[8] = (int)(lVar7 + lVar15 >> 0xb);
79: piVar8[0x48] = (int)(lVar7 - lVar15 >> 0xb);
80: piVar8[0x10] = (int)(lVar10 + lVar21 >> 0xb);
81: param_3 = param_3 + 1;
82: psVar3 = psVar3 + 1;
83: piVar8[0x40] = (int)(lVar10 - lVar21 >> 0xb);
84: piVar8[0x18] = (int)(lVar14 + lVar19 >> 0xb);
85: piVar8[0x38] = (int)(lVar14 - lVar19 >> 0xb);
86: piVar8[0x20] = (int)(lVar12 + lVar13 >> 0xb);
87: piVar8[0x30] = (int)(lVar12 - lVar13 >> 0xb);
88: piVar8[0x28] = (int)(lVar6 + lVar17 * -0x58ad >> 0xb);
89: piVar8 = piVar8 + 1;
90: } while (param_3 != psVar1);
91: plStack480 = param_4;
92: do {
93: lVar16 = (long)piVar20[2];
94: lVar9 = (long)piVar20[6];
95: lVar6 = (long)piVar20[4];
96: puVar4 = (undefined *)((ulong)param_5 + *plStack480);
97: lVar17 = (lVar16 + lVar9) - lVar6;
98: lVar7 = (lVar6 - lVar9) * 0x517e;
99: lVar14 = (lVar6 - lVar16) * 0xdc9;
100: lVar5 = ((long)*piVar20 + 0x10) * 0x2000 + lVar17 * 0x2b6c;
101: lVar13 = (lVar16 + lVar9) * -0x24fb + lVar5;
102: lVar12 = lVar7 + lVar14 + lVar5 + lVar6 * -0x3a4c;
103: lVar7 = lVar9 * 0x43b5 + lVar5 + lVar7;
104: lVar10 = lVar9 * -0x193d + lVar13;
105: lVar11 = (long)piVar20[3];
106: lVar14 = lVar16 * -0x306f + lVar5 + lVar14;
107: lVar15 = (long)piVar20[1];
108: lVar9 = (long)piVar20[5];
109: lVar13 = lVar13 + lVar6 * 0x3e39 + lVar16 * -0x2c83;
110: lVar6 = (long)piVar20[7];
111: lVar21 = (lVar15 + lVar9) * 0x1574;
112: lVar23 = (lVar15 + lVar11) * 0x1c6a;
113: lVar16 = (lVar15 + lVar11 + lVar9 + lVar6) * 0xcc0;
114: lVar19 = (lVar15 + lVar6) * 3000 + lVar16;
115: lVar18 = lVar15 * -0x1d8a + lVar23 + lVar21 + lVar19;
116: lVar15 = (lVar11 + lVar9) * -0x2537 + lVar16;
117: lVar21 = lVar15 + lVar9 * -0x2626 + lVar21;
118: lVar22 = (lVar11 + lVar6) * -0x398b;
119: lVar15 = lVar11 * 0x4258 + lVar15 + lVar23 + lVar22;
120: lVar19 = lVar22 + lVar6 * 0x4347 + lVar19;
121: lVar16 = lVar16 + lVar11 * -0x2ef3 + lVar9 * 0x200b + lVar6 * -0x35ea;
122: *puVar4 = *(undefined *)(lVar2 + (ulong)((uint)(lVar7 + lVar18 >> 0x12) & 0x3ff));
123: puVar4[10] = *(undefined *)(lVar2 + (ulong)((uint)(lVar7 - lVar18 >> 0x12) & 0x3ff));
124: puVar4[1] = *(undefined *)(lVar2 + (ulong)((uint)(lVar12 + lVar15 >> 0x12) & 0x3ff));
125: puVar4[9] = *(undefined *)(lVar2 + (ulong)((uint)(lVar12 - lVar15 >> 0x12) & 0x3ff));
126: puVar4[2] = *(undefined *)(lVar2 + (ulong)((uint)(lVar10 + lVar21 >> 0x12) & 0x3ff));
127: piVar20 = piVar20 + 8;
128: puVar4[8] = *(undefined *)(lVar2 + (ulong)((uint)(lVar10 - lVar21 >> 0x12) & 0x3ff));
129: puVar4[3] = *(undefined *)(lVar2 + (ulong)((uint)(lVar14 + lVar19 >> 0x12) & 0x3ff));
130: puVar4[7] = *(undefined *)(lVar2 + (ulong)((uint)(lVar14 - lVar19 >> 0x12) & 0x3ff));
131: plStack480 = plStack480 + 1;
132: puVar4[4] = *(undefined *)(lVar2 + (ulong)((uint)(lVar13 + lVar16 >> 0x12) & 0x3ff));
133: puVar4[6] = *(undefined *)(lVar2 + (ulong)((uint)(lVar13 - lVar16 >> 0x12) & 0x3ff));
134: puVar4[5] = *(undefined *)(lVar2 + (ulong)((uint)(lVar5 + lVar17 * -0x58ad >> 0x12) & 0x3ff));
135: } while (piVar20 != aiStack56);
136: return;
137: }
138: 

1: 
2: void FUN_001374c0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: long lVar2;
7: short sVar3;
8: short sVar4;
9: short sVar5;
10: short sVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: undefined *puVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: int *piVar18;
23: long lVar19;
24: long lVar20;
25: long lVar21;
26: long lVar22;
27: long lVar23;
28: int *piVar24;
29: long lVar25;
30: long lVar26;
31: long lVar27;
32: long lVar28;
33: long lVar29;
34: long lVar30;
35: short *psVar31;
36: long *plStack632;
37: int aiStack504 [8];
38: int aiStack472 [8];
39: int aiStack440 [8];
40: int aiStack408 [8];
41: int aiStack376 [8];
42: int aiStack344 [8];
43: int aiStack312 [8];
44: int aiStack280 [8];
45: int aiStack248 [8];
46: int aiStack216 [8];
47: int aiStack184 [8];
48: int aiStack152 [8];
49: int aiStack120 [8];
50: int aiStack88 [8];
51: int aiStack56 [2];
52: 
53: psVar31 = *(short **)(param_2 + 0x58);
54: lVar2 = *(long *)(param_1 + 0x1a8) + 0x80;
55: psVar1 = param_3 + 8;
56: piVar18 = aiStack504;
57: piVar24 = piVar18;
58: do {
59: lVar9 = (long)((int)*param_3 * (int)*psVar31) * 0x2000 + 0x400;
60: lVar10 = (long)((int)param_3[0x20] * (int)psVar31[0x20]);
61: lVar21 = lVar9 + lVar10 * 0x28c6;
62: lVar14 = lVar9 + lVar10 * -0x1c37;
63: lVar19 = lVar9 + lVar10 * 0xa12;
64: lVar25 = (long)((int)param_3[0x10] * (int)psVar31[0x10]);
65: lVar11 = (long)((int)param_3[0x30] * (int)psVar31[0x30]);
66: lVar13 = (lVar25 + lVar11) * 0x2362;
67: lVar20 = lVar25 * 0x8bd + lVar13;
68: lVar13 = lVar13 + lVar11 * -0x3704;
69: lVar23 = lVar21 + lVar20;
70: lVar21 = lVar21 - lVar20;
71: lVar20 = lVar11 * -0x2c1f + lVar25 * 0x13a3;
72: lVar11 = lVar19 + lVar13;
73: lVar19 = lVar19 - lVar13;
74: lVar13 = lVar14 + lVar20;
75: sVar3 = psVar31[0x38];
76: lVar14 = lVar14 - lVar20;
77: sVar4 = psVar31[0x28];
78: lVar26 = (long)((int)param_3[8] * (int)psVar31[8]);
79: sVar5 = param_3[0x28];
80: lVar15 = (long)((int)param_3[0x18] * (int)psVar31[0x18]);
81: sVar6 = param_3[0x38];
82: lVar20 = (long)((int)sVar5 * (int)sVar4);
83: lVar30 = (lVar26 + lVar15) * 0x2ab7;
84: lVar16 = (long)((int)sVar6 * (int)sVar3);
85: lVar27 = (lVar26 + lVar20) * 0x2652;
86: lVar17 = lVar30 + lVar27 + lVar16 * 0x2000 + lVar26 * -0x2410;
87: lVar29 = (lVar26 + lVar20) * 0x1814;
88: lVar25 = (lVar15 + lVar20) * -0x511 + lVar16 * -0x2000;
89: lVar30 = lVar15 * -0xd92 + lVar25 + lVar30;
90: lVar27 = lVar25 + lVar20 * -0x4bf7 + lVar27;
91: lVar25 = (lVar26 - lVar15) * 0xef2 + lVar16 * -0x2000;
92: lVar28 = (lVar20 - lVar15) * 0x2cf8;
93: lVar22 = lVar26 * -0x21f5 + lVar29 + lVar25;
94: lVar29 = lVar16 * 0x2000 + lVar28 + lVar20 * -0x361a + lVar29;
95: lVar25 = lVar25 + lVar15 * 0x1599 + lVar28;
96: piVar24[0x68] = (int)(lVar23 - lVar17 >> 0xb);
97: *piVar24 = (int)(lVar23 + lVar17 >> 0xb);
98: piVar24[8] = (int)(lVar11 + lVar30 >> 0xb);
99: piVar24[0x60] = (int)(lVar11 - lVar30 >> 0xb);
100: piVar24[0x10] = (int)(lVar13 + lVar27 >> 0xb);
101: piVar24[0x58] = (int)(lVar13 - lVar27 >> 0xb);
102: param_3 = param_3 + 1;
103: psVar31 = psVar31 + 1;
104: iVar8 = ((int)(lVar26 - lVar15) + (int)sVar6 * (int)sVar3) - (int)sVar5 * (int)sVar4;
105: iVar7 = (int)(lVar9 + lVar10 * -0x2d42 >> 0xb);
106: piVar24[0x50] = iVar7 + iVar8 * -4;
107: piVar24[0x18] = iVar8 * 4 + iVar7;
108: piVar24[0x20] = (int)(lVar14 + lVar29 >> 0xb);
109: piVar24[0x48] = (int)(lVar14 - lVar29 >> 0xb);
110: piVar24[0x28] = (int)(lVar19 + lVar25 >> 0xb);
111: piVar24[0x40] = (int)(lVar19 - lVar25 >> 0xb);
112: piVar24[0x30] = (int)(lVar21 + lVar22 >> 0xb);
113: piVar24[0x38] = (int)(lVar21 - lVar22 >> 0xb);
114: piVar24 = piVar24 + 1;
115: } while (param_3 != psVar1);
116: plStack632 = param_4;
117: do {
118: lVar13 = (long)piVar18[4];
119: puVar12 = (undefined *)((ulong)param_5 + *plStack632);
120: lVar14 = ((long)*piVar18 + 0x10) * 0x2000;
121: lVar23 = lVar14 + lVar13 * 0x28c6;
122: lVar11 = lVar14 + lVar13 * 0xa12;
123: lVar30 = lVar14 + lVar13 * -0x1c37;
124: lVar14 = lVar14 + lVar13 * -0x2d42;
125: lVar9 = (long)piVar18[2];
126: lVar10 = (long)piVar18[6];
127: lVar20 = (lVar9 + lVar10) * 0x2362;
128: lVar25 = lVar9 * 0x8bd + lVar20;
129: lVar20 = lVar20 + lVar10 * -0x3704;
130: lVar22 = (long)piVar18[1];
131: lVar13 = lVar11 + lVar20;
132: lVar11 = lVar11 - lVar20;
133: lVar20 = lVar10 * -0x2c1f + lVar9 * 0x13a3;
134: lVar9 = lVar23 + lVar25;
135: lVar23 = lVar23 - lVar25;
136: lVar10 = lVar30 + lVar20;
137: lVar30 = lVar30 - lVar20;
138: lVar25 = (long)piVar18[7];
139: lVar20 = (long)piVar18[5];
140: lVar16 = (long)piVar18[3];
141: lVar15 = lVar25 * 0x2000;
142: lVar29 = (lVar22 + lVar20) * 0x2652;
143: lVar27 = (lVar22 + lVar16) * 0x2ab7;
144: lVar26 = (lVar22 + lVar20) * 0x1814;
145: lVar21 = lVar27 + lVar29 + lVar15 + lVar22 * -0x2410;
146: lVar17 = (lVar22 - lVar16) * 0xef2 + lVar25 * -0x2000;
147: lVar19 = lVar22 * -0x21f5 + lVar26 + lVar17;
148: lVar22 = ((lVar22 - lVar16) - lVar20) * 0x2000 + lVar15;
149: lVar25 = (lVar16 + lVar20) * -0x511 + lVar25 * -0x2000;
150: lVar27 = lVar16 * -0xd92 + lVar25 + lVar27;
151: lVar29 = lVar20 * -0x4bf7 + lVar25 + lVar29;
152: lVar25 = (lVar20 - lVar16) * 0x2cf8;
153: lVar17 = lVar16 * 0x1599 + lVar25 + lVar17;
154: lVar26 = lVar20 * -0x361a + lVar25 + lVar15 + lVar26;
155: *puVar12 = *(undefined *)(lVar2 + (ulong)((uint)(lVar9 + lVar21 >> 0x12) & 0x3ff));
156: puVar12[0xd] = *(undefined *)(lVar2 + (ulong)((uint)(lVar9 - lVar21 >> 0x12) & 0x3ff));
157: puVar12[1] = *(undefined *)(lVar2 + (ulong)((uint)(lVar13 + lVar27 >> 0x12) & 0x3ff));
158: puVar12[0xc] = *(undefined *)(lVar2 + (ulong)((uint)(lVar13 - lVar27 >> 0x12) & 0x3ff));
159: piVar18 = piVar18 + 8;
160: puVar12[2] = *(undefined *)(lVar2 + (ulong)((uint)(lVar10 + lVar29 >> 0x12) & 0x3ff));
161: puVar12[0xb] = *(undefined *)(lVar2 + (ulong)((uint)(lVar10 - lVar29 >> 0x12) & 0x3ff));
162: plStack632 = plStack632 + 1;
163: puVar12[3] = *(undefined *)(lVar2 + (ulong)((uint)(lVar14 + lVar22 >> 0x12) & 0x3ff));
164: puVar12[10] = *(undefined *)(lVar2 + (ulong)((uint)(lVar14 - lVar22 >> 0x12) & 0x3ff));
165: puVar12[4] = *(undefined *)(lVar2 + (ulong)((uint)(lVar30 + lVar26 >> 0x12) & 0x3ff));
166: puVar12[9] = *(undefined *)(lVar2 + (ulong)((uint)(lVar30 - lVar26 >> 0x12) & 0x3ff));
167: puVar12[5] = *(undefined *)(lVar2 + (ulong)((uint)(lVar11 + lVar17 >> 0x12) & 0x3ff));
168: puVar12[8] = *(undefined *)(lVar2 + (ulong)((uint)(lVar11 - lVar17 >> 0x12) & 0x3ff));
169: puVar12[6] = *(undefined *)(lVar2 + (ulong)((uint)(lVar23 + lVar19 >> 0x12) & 0x3ff));
170: puVar12[7] = *(undefined *)(lVar2 + (ulong)((uint)(lVar23 - lVar19 >> 0x12) & 0x3ff));
171: } while (piVar18 != aiStack56);
172: return;
173: }
174: 

1: 
2: void FUN_0013ff70(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: undefined uVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: short *psVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: undefined *puVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: int *piVar19;
24: int *piVar20;
25: long lVar21;
26: long in_FS_OFFSET;
27: long *plStack376;
28: int aiStack328 [8];
29: int aiStack296 [8];
30: int aiStack264 [8];
31: int aiStack232 [8];
32: int aiStack200 [8];
33: int aiStack168 [8];
34: int aiStack136 [8];
35: int aiStack104 [8];
36: int aiStack72 [2];
37: long lStack64;
38: 
39: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
40: lVar5 = *(long *)(param_1 + 0x1a8) + 0x80;
41: psVar9 = *(short **)(param_2 + 0x58);
42: piVar20 = aiStack328;
43: do {
44: piVar19 = piVar20 + 1;
45: iVar4 = (int)*psVar9 * (int)*param_3;
46: if ((((param_3[8] == 0) && (param_3[0x10] == 0)) && (param_3[0x18] == 0)) &&
47: (((param_3[0x20] == 0 && (param_3[0x28] == 0)) &&
48: ((param_3[0x30] == 0 && (param_3[0x38] == 0)))))) {
49: iVar4 = (int)((long)iVar4 << 2);
50: *piVar20 = iVar4;
51: piVar20[8] = iVar4;
52: piVar20[0x10] = iVar4;
53: piVar20[0x18] = iVar4;
54: piVar20[0x20] = iVar4;
55: piVar20[0x28] = iVar4;
56: piVar20[0x30] = iVar4;
57: piVar20[0x38] = iVar4;
58: }
59: else {
60: lVar14 = (long)((int)param_3[0x10] * (int)psVar9[0x10]);
61: lVar7 = (long)((int)psVar9[0x30] * (int)param_3[0x30]);
62: lVar17 = (lVar14 + lVar7) * 0x1151;
63: lVar8 = lVar7 * -0x3b21 + lVar17;
64: lVar17 = lVar14 * 0x187e + lVar17;
65: lVar7 = (long)((int)param_3[0x20] * (int)psVar9[0x20]);
66: lVar6 = (iVar4 - lVar7) * 0x2000;
67: lVar18 = (iVar4 + lVar7) * 0x2000;
68: lVar7 = lVar17 + lVar18;
69: lVar18 = lVar18 - lVar17;
70: lVar14 = lVar8 + lVar6;
71: lVar6 = lVar6 - lVar8;
72: lVar16 = (long)((int)param_3[0x38] * (int)psVar9[0x38]);
73: lVar15 = (long)((int)param_3[0x28] * (int)psVar9[0x28]);
74: lVar12 = (long)((int)param_3[0x18] * (int)psVar9[0x18]);
75: lVar11 = (long)((int)param_3[8] * (int)psVar9[8]);
76: lVar8 = (lVar15 + lVar12) * -0x5203;
77: lVar17 = (lVar16 + lVar12 + lVar15 + lVar11) * 0x25a1;
78: lVar10 = (lVar16 + lVar11) * -0x1ccd;
79: lVar21 = (lVar16 + lVar12) * -0x3ec5 + lVar17;
80: lVar17 = (lVar15 + lVar11) * -0xc7c + lVar17;
81: lVar16 = lVar16 * 0x98e + lVar10 + lVar21;
82: lVar15 = lVar15 * 0x41b3 + lVar8 + lVar17;
83: lVar12 = lVar12 * 0x6254 + lVar21 + lVar8;
84: lVar8 = lVar11 * 0x300b + lVar17 + lVar10;
85: *piVar20 = (int)(lVar7 + 0x400 + lVar8 >> 0xb);
86: piVar20[0x38] = (int)((lVar7 - lVar8) + 0x400 >> 0xb);
87: piVar20[8] = (int)(lVar14 + 0x400 + lVar12 >> 0xb);
88: piVar20[0x30] = (int)((lVar14 - lVar12) + 0x400 >> 0xb);
89: piVar20[0x28] = (int)((lVar6 - lVar15) + 0x400 >> 0xb);
90: piVar20[0x10] = (int)(lVar6 + 0x400 + lVar15 >> 0xb);
91: piVar20[0x18] = (int)(lVar18 + 0x400 + lVar16 >> 0xb);
92: piVar20[0x20] = (int)((lVar18 - lVar16) + 0x400 >> 0xb);
93: }
94: psVar9 = psVar9 + 1;
95: piVar20 = piVar19;
96: param_3 = param_3 + 1;
97: } while (piVar19 != aiStack296);
98: piVar20 = aiStack328;
99: plStack376 = param_4;
100: do {
101: lVar6 = (long)piVar20[1];
102: piVar19 = piVar20 + 8;
103: iVar4 = piVar20[2];
104: iVar2 = piVar20[6];
105: iVar3 = piVar20[4];
106: lVar14 = (long)piVar20[7];
107: lVar17 = (long)piVar20[5];
108: lVar8 = (long)piVar20[3];
109: puVar13 = (undefined *)((ulong)param_5 + *plStack376);
110: lVar7 = (long)*piVar20;
111: if ((((piVar20[1] == 0) && (iVar4 == 0)) &&
112: ((piVar20[3] == 0 && (((iVar3 == 0 && (piVar20[5] == 0)) && (iVar2 == 0)))))) &&
113: (piVar20[7] == 0)) {
114: uVar1 = *(undefined *)(lVar5 + (ulong)((uint)(lVar7 + 0x10 >> 5) & 0x3ff));
115: *puVar13 = uVar1;
116: puVar13[1] = uVar1;
117: puVar13[2] = uVar1;
118: puVar13[3] = uVar1;
119: puVar13[4] = uVar1;
120: puVar13[5] = uVar1;
121: puVar13[6] = uVar1;
122: puVar13[7] = uVar1;
123: }
124: else {
125: lVar10 = ((long)iVar4 + (long)iVar2) * 0x1151;
126: lVar11 = (lVar7 - iVar3) * 0x2000;
127: lVar15 = (long)iVar2 * -0x3b21 + lVar10;
128: lVar12 = (iVar3 + lVar7) * 0x2000;
129: lVar10 = (long)iVar4 * 0x187e + lVar10;
130: lVar7 = lVar10 + lVar12;
131: lVar12 = lVar12 - lVar10;
132: lVar10 = lVar15 + lVar11;
133: lVar11 = lVar11 - lVar15;
134: lVar16 = (lVar14 + lVar6) * -0x1ccd;
135: lVar18 = (lVar14 + lVar8 + lVar17 + lVar6) * 0x25a1;
136: lVar15 = (lVar17 + lVar8) * -0x5203;
137: lVar21 = (lVar14 + lVar8) * -0x3ec5 + lVar18;
138: lVar18 = (lVar17 + lVar6) * -0xc7c + lVar18;
139: lVar14 = lVar14 * 0x98e + lVar16 + lVar21;
140: lVar6 = lVar6 * 0x300b + lVar18 + lVar16;
141: lVar17 = lVar17 * 0x41b3 + lVar15 + lVar18;
142: lVar8 = lVar21 + lVar15 + lVar8 * 0x6254;
143: *puVar13 = *(undefined *)(lVar5 + (ulong)((uint)(lVar7 + 0x20000 + lVar6 >> 0x12) & 0x3ff));
144: puVar13[7] = *(undefined *)
145: (lVar5 + (ulong)((uint)((lVar7 - lVar6) + 0x20000 >> 0x12) & 0x3ff));
146: puVar13[1] = *(undefined *)(lVar5 + (ulong)((uint)(lVar10 + 0x20000 + lVar8 >> 0x12) & 0x3ff))
147: ;
148: puVar13[6] = *(undefined *)
149: (lVar5 + (ulong)((uint)((lVar10 - lVar8) + 0x20000 >> 0x12) & 0x3ff));
150: puVar13[2] = *(undefined *)
151: (lVar5 + (ulong)((uint)(lVar11 + 0x20000 + lVar17 >> 0x12) & 0x3ff));
152: puVar13[5] = *(undefined *)
153: (lVar5 + (ulong)((uint)((lVar11 - lVar17) + 0x20000 >> 0x12) & 0x3ff));
154: puVar13[3] = *(undefined *)
155: (lVar5 + (ulong)((uint)(lVar12 + 0x20000 + lVar14 >> 0x12) & 0x3ff));
156: puVar13[4] = *(undefined *)
157: (lVar5 + (ulong)((uint)((lVar12 - lVar14) + 0x20000 >> 0x12) & 0x3ff));
158: }
159: plStack376 = plStack376 + 1;
160: piVar20 = piVar19;
161: } while (piVar19 != aiStack72);
162: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
163: /* WARNING: Subroutine does not return */
164: __stack_chk_fail();
165: }
166: return;
167: }
168: 

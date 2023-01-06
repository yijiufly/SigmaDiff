1: 
2: void FUN_00134850(long param_1,long param_2,long param_3,long param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: undefined uVar2;
7: int iVar3;
8: short *psVar4;
9: int *piVar5;
10: int *piVar6;
11: int iVar7;
12: long lVar8;
13: undefined *puVar9;
14: int iVar10;
15: long lVar11;
16: int iVar12;
17: long lVar13;
18: int iVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: int iVar19;
24: long lVar20;
25: int iVar21;
26: long lVar22;
27: long lVar23;
28: long lVar24;
29: long lVar25;
30: long lVar26;
31: int aiStack312 [8];
32: int aiStack280 [8];
33: int aiStack248 [8];
34: int aiStack216 [8];
35: int aiStack184 [8];
36: int aiStack152 [8];
37: int aiStack120 [8];
38: int aiStack88 [10];
39: 
40: param_3 = param_3 + 2;
41: iVar3 = 8;
42: lVar1 = *(long *)(param_1 + 0x1a8) + 0x80;
43: piVar6 = aiStack312;
44: piVar5 = piVar6;
45: psVar4 = *(short **)(param_2 + 0x58);
46: do {
47: iVar10 = (int)*(short *)(param_3 + 0x1e);
48: if ((*(short *)(param_3 + 0xe) == 0) && (*(short *)(param_3 + 0x1e) == 0)) {
49: iVar7 = (int)*(short *)(param_3 + 0x2e);
50: if (*(short *)(param_3 + 0x2e) != 0) {
51: iVar21 = (int)*(short *)(param_3 + 0x5e);
52: iVar19 = (int)*(short *)(param_3 + 0x3e);
53: iVar10 = 0;
54: iVar14 = (int)*(short *)(param_3 + 0x6e);
55: iVar12 = (int)*(short *)(param_3 + 0x4e);
56: goto LAB_001348d8;
57: }
58: iVar19 = (int)*(short *)(param_3 + 0x3e);
59: if (*(short *)(param_3 + 0x3e) != 0) {
60: iVar21 = (int)*(short *)(param_3 + 0x5e);
61: iVar14 = (int)*(short *)(param_3 + 0x6e);
62: iVar7 = 0;
63: iVar12 = (int)*(short *)(param_3 + 0x4e);
64: iVar10 = 0;
65: goto LAB_001348d8;
66: }
67: iVar12 = (int)*(short *)(param_3 + 0x4e);
68: iVar21 = (int)*(short *)(param_3 + 0x5e);
69: iVar14 = (int)*(short *)(param_3 + 0x6e);
70: if (*(short *)(param_3 + 0x4e) != 0) {
71: iVar7 = 0;
72: iVar19 = 0;
73: iVar10 = 0;
74: goto LAB_001348d8;
75: }
76: if (*(short *)(param_3 + 0x5e) != 0) {
77: iVar7 = 0;
78: iVar12 = 0;
79: iVar19 = 0;
80: iVar10 = 0;
81: goto LAB_001348d8;
82: }
83: if (*(short *)(param_3 + 0x6e) != 0) {
84: iVar7 = 0;
85: iVar12 = 0;
86: iVar19 = 0;
87: iVar21 = 0;
88: iVar10 = 0;
89: goto LAB_001348d8;
90: }
91: iVar10 = (int)((long)((int)*(short *)(param_3 + -2) * (int)*psVar4) << 2);
92: *piVar5 = iVar10;
93: piVar5[8] = iVar10;
94: piVar5[0x10] = iVar10;
95: piVar5[0x18] = iVar10;
96: piVar5[0x20] = iVar10;
97: piVar5[0x28] = iVar10;
98: piVar5[0x30] = iVar10;
99: piVar5[0x38] = iVar10;
100: }
101: else {
102: iVar21 = (int)*(short *)(param_3 + 0x5e);
103: iVar19 = (int)*(short *)(param_3 + 0x3e);
104: iVar14 = (int)*(short *)(param_3 + 0x6e);
105: iVar12 = (int)*(short *)(param_3 + 0x4e);
106: iVar7 = (int)*(short *)(param_3 + 0x2e);
107: LAB_001348d8:
108: lVar16 = ((long)(iVar10 * psVar4[0x10]) + (long)(iVar21 * psVar4[0x30])) * 0x1151;
109: lVar22 = (long)(iVar21 * psVar4[0x30]) * -0x3b21 + lVar16;
110: lVar16 = (long)(iVar10 * psVar4[0x10]) * 0x187e + lVar16;
111: lVar17 = (long)((int)*(short *)(param_3 + -2) * (int)*psVar4);
112: lVar18 = (lVar17 - iVar19 * psVar4[0x20]) * 0x2000;
113: lVar20 = (lVar17 + iVar19 * psVar4[0x20]) * 0x2000;
114: lVar17 = lVar20 + lVar16;
115: lVar20 = lVar20 - lVar16;
116: lVar16 = lVar18 + lVar22;
117: lVar18 = lVar18 - lVar22;
118: lVar15 = (long)(iVar14 * psVar4[0x38]);
119: lVar13 = (long)(iVar12 * psVar4[0x28]);
120: lVar22 = (long)(iVar7 * psVar4[0x18]);
121: lVar8 = (long)((int)*(short *)(param_3 + 0xe) * (int)psVar4[8]);
122: lVar24 = (lVar13 + lVar22) * -0x5203;
123: lVar23 = (lVar15 + lVar22 + lVar13 + lVar8) * 0x25a1;
124: lVar25 = (lVar15 + lVar8) * -0x1ccd;
125: lVar11 = (lVar15 + lVar22) * -0x3ec5 + lVar23;
126: lVar23 = (lVar13 + lVar8) * -0xc7c + lVar23;
127: lVar15 = lVar15 * 0x98e + lVar25 + lVar11;
128: lVar22 = lVar22 * 0x6254 + lVar24 + lVar11;
129: lVar11 = lVar13 * 0x41b3 + lVar24 + lVar23;
130: lVar8 = lVar8 * 0x300b + lVar25 + lVar23;
131: piVar5[8] = (int)(lVar16 + 0x400 + lVar22 >> 0xb);
132: piVar5[0x30] = (int)((lVar16 - lVar22) + 0x400 >> 0xb);
133: piVar5[0x10] = (int)(lVar18 + 0x400 + lVar11 >> 0xb);
134: *piVar5 = (int)(lVar17 + 0x400 + lVar8 >> 0xb);
135: piVar5[0x38] = (int)((lVar17 - lVar8) + 0x400 >> 0xb);
136: piVar5[0x28] = (int)((lVar18 - lVar11) + 0x400 >> 0xb);
137: piVar5[0x18] = (int)(lVar20 + 0x400 + lVar15 >> 0xb);
138: piVar5[0x20] = (int)((lVar20 - lVar15) + 0x400 >> 0xb);
139: }
140: piVar5 = piVar5 + 1;
141: param_3 = param_3 + 2;
142: iVar3 = iVar3 + -1;
143: psVar4 = psVar4 + 1;
144: } while (iVar3 != 0);
145: lVar17 = 0;
146: do {
147: lVar16 = (long)piVar6[1];
148: lVar22 = (long)piVar6[2];
149: puVar9 = (undefined *)((ulong)param_5 + *(long *)(param_4 + lVar17));
150: if ((piVar6[1] == 0) && (piVar6[2] == 0)) {
151: lVar8 = (long)piVar6[3];
152: if (piVar6[3] != 0) {
153: lVar11 = (long)piVar6[6];
154: lVar23 = (long)piVar6[4];
155: lVar15 = (long)piVar6[7];
156: lVar13 = (long)piVar6[5];
157: goto LAB_00134b18;
158: }
159: lVar23 = (long)piVar6[4];
160: if (piVar6[4] != 0) {
161: lVar11 = (long)piVar6[6];
162: lVar15 = (long)piVar6[7];
163: lVar22 = 0;
164: lVar13 = (long)piVar6[5];
165: goto LAB_00134b18;
166: }
167: lVar13 = (long)piVar6[5];
168: lVar11 = (long)piVar6[6];
169: lVar15 = (long)piVar6[7];
170: if (piVar6[5] != 0) {
171: lVar8 = 0;
172: lVar22 = 0;
173: goto LAB_00134b18;
174: }
175: if (piVar6[6] != 0) {
176: lVar8 = 0;
177: lVar23 = 0;
178: lVar22 = 0;
179: goto LAB_00134b18;
180: }
181: if (piVar6[7] != 0) {
182: lVar8 = 0;
183: lVar13 = 0;
184: lVar23 = 0;
185: lVar22 = 0;
186: goto LAB_00134b18;
187: }
188: uVar2 = *(undefined *)(lVar1 + (ulong)((uint)((long)*piVar6 + 0x10 >> 5) & 0x3ff));
189: *puVar9 = uVar2;
190: puVar9[1] = uVar2;
191: puVar9[2] = uVar2;
192: puVar9[3] = uVar2;
193: puVar9[4] = uVar2;
194: puVar9[5] = uVar2;
195: puVar9[6] = uVar2;
196: puVar9[7] = uVar2;
197: }
198: else {
199: lVar11 = (long)piVar6[6];
200: lVar23 = (long)piVar6[4];
201: lVar15 = (long)piVar6[7];
202: lVar13 = (long)piVar6[5];
203: lVar8 = (long)piVar6[3];
204: LAB_00134b18:
205: lVar20 = (lVar22 + lVar11) * 0x1151;
206: lVar18 = lVar11 * -0x3b21 + lVar20;
207: lVar20 = lVar22 * 0x187e + lVar20;
208: lVar11 = (*piVar6 - lVar23) * 0x2000;
209: lVar24 = (*piVar6 + lVar23) * 0x2000;
210: lVar22 = lVar24 + lVar20;
211: lVar24 = lVar24 - lVar20;
212: lVar23 = lVar11 + lVar18;
213: lVar11 = lVar11 - lVar18;
214: lVar26 = (lVar15 + lVar16) * -0x1ccd;
215: lVar18 = (lVar15 + lVar8 + lVar13 + lVar16) * 0x25a1;
216: lVar20 = (lVar15 + lVar8) * -0x3ec5 + lVar18;
217: lVar25 = (lVar13 + lVar8) * -0x5203;
218: lVar18 = (lVar13 + lVar16) * -0xc7c + lVar18;
219: lVar16 = lVar16 * 0x300b + lVar26 + lVar18;
220: lVar15 = lVar15 * 0x98e + lVar26 + lVar20;
221: lVar13 = lVar13 * 0x41b3 + lVar25 + lVar18;
222: *puVar9 = *(undefined *)(lVar1 + (ulong)((uint)(lVar22 + 0x20000 + lVar16 >> 0x12) & 0x3ff));
223: lVar8 = lVar8 * 0x6254 + lVar25 + lVar20;
224: puVar9[7] = *(undefined *)
225: (lVar1 + (ulong)((uint)((lVar22 - lVar16) + 0x20000 >> 0x12) & 0x3ff));
226: puVar9[1] = *(undefined *)(lVar1 + (ulong)((uint)(lVar23 + 0x20000 + lVar8 >> 0x12) & 0x3ff));
227: puVar9[6] = *(undefined *)
228: (lVar1 + (ulong)((uint)((lVar23 - lVar8) + 0x20000 >> 0x12) & 0x3ff));
229: puVar9[2] = *(undefined *)(lVar1 + (ulong)((uint)(lVar11 + 0x20000 + lVar13 >> 0x12) & 0x3ff))
230: ;
231: puVar9[5] = *(undefined *)
232: (lVar1 + (ulong)((uint)((lVar11 - lVar13) + 0x20000 >> 0x12) & 0x3ff));
233: puVar9[3] = *(undefined *)(lVar1 + (ulong)((uint)(lVar24 + 0x20000 + lVar15 >> 0x12) & 0x3ff))
234: ;
235: puVar9[4] = *(undefined *)
236: (lVar1 + (ulong)((uint)((lVar24 - lVar15) + 0x20000 >> 0x12) & 0x3ff));
237: }
238: piVar6 = piVar6 + 8;
239: lVar17 = lVar17 + 8;
240: if (lVar17 == 0x40) {
241: return;
242: }
243: } while( true );
244: }
245: 

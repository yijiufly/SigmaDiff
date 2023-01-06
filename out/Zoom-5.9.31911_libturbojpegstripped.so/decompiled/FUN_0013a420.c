1: 
2: void FUN_0013a420(uint param_1,long param_2,int *param_3)
3: 
4: {
5: short sVar1;
6: long lVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: ulong uVar6;
11: uint uVar7;
12: short *psVar8;
13: long *plVar9;
14: long *plVar10;
15: int iVar11;
16: int iVar12;
17: ulong uVar13;
18: short *psVar14;
19: int iVar15;
20: int iVar16;
21: int iVar17;
22: long lVar18;
23: int iVar19;
24: int iVar20;
25: long lVar21;
26: int iVar22;
27: ulong uVar23;
28: 
29: iVar20 = *param_3;
30: uVar13 = SEXT48(iVar20);
31: iVar12 = param_3[1];
32: lVar2 = *(long *)(param_2 + 0x30);
33: iVar4 = param_3[4];
34: iVar11 = param_3[3];
35: iVar17 = param_3[2];
36: iVar3 = param_3[5];
37: iVar16 = iVar12;
38: if (iVar20 < iVar12) {
39: plVar9 = (long *)(lVar2 + (long)iVar20 * 8);
40: lVar5 = ((long)iVar17 * 0x20 + 1 + (long)iVar4) * 2;
41: iVar19 = iVar20;
42: do {
43: if (iVar17 <= iVar11) {
44: psVar8 = (short *)(lVar5 + *plVar9);
45: iVar22 = iVar17;
46: do {
47: if (iVar4 <= iVar3) {
48: sVar1 = psVar8[-1];
49: iVar15 = iVar4;
50: psVar14 = psVar8;
51: while( true ) {
52: if (sVar1 != 0) {
53: *param_3 = iVar19;
54: iVar20 = iVar19;
55: if (iVar19 < iVar12) goto LAB_0013a7e8;
56: goto LAB_0013a84f;
57: }
58: iVar15 = iVar15 + 1;
59: if (iVar3 < iVar15) break;
60: sVar1 = *psVar14;
61: psVar14 = psVar14 + 1;
62: }
63: }
64: iVar22 = iVar22 + 1;
65: psVar8 = psVar8 + 0x20;
66: } while (iVar22 <= iVar11);
67: }
68: iVar19 = iVar19 + 1;
69: plVar9 = plVar9 + 1;
70: } while (iVar19 <= iVar12);
71: LAB_0013a7e8:
72: plVar9 = (long *)(lVar2 + (long)iVar12 * 8);
73: do {
74: if (iVar17 <= iVar11) {
75: psVar8 = (short *)(lVar5 + *plVar9);
76: iVar19 = iVar17;
77: do {
78: if (iVar4 <= iVar3) {
79: sVar1 = psVar8[-1];
80: iVar22 = iVar4;
81: psVar14 = psVar8;
82: while( true ) {
83: if (sVar1 != 0) {
84: param_3[1] = iVar16;
85: uVar13 = SEXT48(iVar20);
86: goto LAB_0013a4e2;
87: }
88: iVar22 = iVar22 + 1;
89: if (iVar3 < iVar22) break;
90: sVar1 = *psVar14;
91: psVar14 = psVar14 + 1;
92: }
93: }
94: iVar19 = iVar19 + 1;
95: psVar8 = psVar8 + 0x20;
96: } while (iVar19 <= iVar11);
97: }
98: iVar16 = iVar16 + -1;
99: plVar9 = plVar9 + -1;
100: iVar19 = iVar20;
101: } while (iVar20 <= iVar16);
102: LAB_0013a84f:
103: uVar13 = SEXT48(iVar19);
104: iVar16 = iVar12;
105: }
106: LAB_0013a4e2:
107: iVar12 = (int)uVar13;
108: iVar20 = iVar17;
109: if (iVar17 < iVar11) {
110: lVar5 = (long)iVar17 << 6;
111: plVar9 = (long *)(lVar2 + (long)iVar12 * 8);
112: do {
113: if (iVar12 <= iVar16) {
114: uVar6 = uVar13 & 0xffffffff;
115: plVar10 = plVar9;
116: do {
117: psVar8 = (short *)((long)iVar4 * 2 + lVar5 + *plVar10);
118: if (iVar4 <= iVar3) {
119: sVar1 = *(short *)(lVar5 + *plVar10 + (long)iVar4 * 2);
120: iVar19 = iVar4;
121: while( true ) {
122: if (sVar1 != 0) {
123: param_3[2] = iVar20;
124: iVar17 = iVar20;
125: if (iVar20 < iVar11) goto LAB_0013a869;
126: goto LAB_0013a58a;
127: }
128: psVar8 = psVar8 + 1;
129: iVar19 = iVar19 + 1;
130: if (iVar3 < iVar19) break;
131: sVar1 = *psVar8;
132: }
133: }
134: uVar7 = (int)uVar6 + 1;
135: uVar6 = (ulong)uVar7;
136: plVar10 = plVar10 + 1;
137: } while ((int)uVar7 <= iVar16);
138: }
139: iVar20 = iVar20 + 1;
140: lVar5 = lVar5 + 0x40;
141: } while (iVar20 <= iVar11);
142: LAB_0013a869:
143: iVar20 = iVar17;
144: lVar5 = (long)iVar11 << 6;
145: iVar17 = iVar11;
146: do {
147: if (iVar12 <= iVar16) {
148: uVar6 = uVar13 & 0xffffffff;
149: plVar10 = plVar9;
150: do {
151: psVar8 = (short *)((long)iVar4 * 2 + lVar5 + *plVar10);
152: if (iVar4 <= iVar3) {
153: sVar1 = *(short *)(lVar5 + *plVar10 + (long)iVar4 * 2);
154: iVar19 = iVar4;
155: while( true ) {
156: if (sVar1 != 0) {
157: param_3[3] = iVar17;
158: iVar11 = iVar17;
159: goto LAB_0013a58a;
160: }
161: psVar8 = psVar8 + 1;
162: iVar19 = iVar19 + 1;
163: if (iVar3 < iVar19) break;
164: sVar1 = *psVar8;
165: }
166: }
167: uVar7 = (int)uVar6 + 1;
168: uVar6 = (ulong)uVar7;
169: plVar10 = plVar10 + 1;
170: } while ((int)uVar7 <= iVar16);
171: }
172: iVar17 = iVar17 + -1;
173: lVar5 = lVar5 + -0x40;
174: } while (iVar20 <= iVar17);
175: }
176: LAB_0013a58a:
177: iVar17 = iVar4;
178: if (iVar4 < iVar3) {
179: plVar9 = (long *)(lVar2 + (long)iVar12 * 8);
180: do {
181: iVar19 = iVar3;
182: if (iVar12 <= iVar16) {
183: uVar6 = uVar13 & 0xffffffff;
184: plVar10 = plVar9;
185: do {
186: lVar5 = (long)iVar20 * 0x40 + *plVar10;
187: psVar8 = (short *)(lVar5 + (long)iVar17 * 2);
188: if (iVar20 <= iVar11) {
189: sVar1 = *(short *)(lVar5 + (long)iVar17 * 2);
190: iVar22 = iVar20;
191: while( true ) {
192: if (sVar1 != 0) {
193: param_3[4] = iVar17;
194: iVar4 = iVar17;
195: if (iVar17 < iVar3) goto LAB_0013a773;
196: goto LAB_0013a62a;
197: }
198: iVar22 = iVar22 + 1;
199: psVar8 = psVar8 + 0x20;
200: if (iVar11 < iVar22) break;
201: sVar1 = *psVar8;
202: }
203: }
204: uVar7 = (int)uVar6 + 1;
205: uVar6 = (ulong)uVar7;
206: plVar10 = plVar10 + 1;
207: } while ((int)uVar7 <= iVar16);
208: }
209: iVar17 = iVar17 + 1;
210: } while (iVar17 <= iVar3);
211: LAB_0013a773:
212: do {
213: iVar17 = iVar4;
214: if (iVar12 <= iVar16) {
215: uVar6 = uVar13 & 0xffffffff;
216: plVar10 = plVar9;
217: do {
218: lVar5 = (long)iVar20 * 0x40 + *plVar10;
219: psVar8 = (short *)(lVar5 + (long)iVar19 * 2);
220: if (iVar20 <= iVar11) {
221: sVar1 = *(short *)(lVar5 + (long)iVar19 * 2);
222: iVar4 = iVar20;
223: while( true ) {
224: if (sVar1 != 0) {
225: param_3[5] = iVar19;
226: iVar3 = iVar19;
227: goto LAB_0013a62a;
228: }
229: iVar4 = iVar4 + 1;
230: psVar8 = psVar8 + 0x20;
231: if (iVar11 < iVar4) break;
232: sVar1 = *psVar8;
233: }
234: }
235: uVar7 = (int)uVar6 + 1;
236: uVar6 = (ulong)uVar7;
237: plVar10 = plVar10 + 1;
238: } while ((int)uVar7 <= iVar16);
239: }
240: iVar19 = iVar19 + -1;
241: iVar4 = iVar17;
242: } while (iVar17 <= iVar19);
243: }
244: LAB_0013a62a:
245: uVar6 = (ulong)param_1;
246: uVar23 = (ulong)(uint)(iVar3 - iVar17);
247: lVar18 = (long)((iVar16 - iVar12) * 8 *
248: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar6 * 4) * 4));
249: lVar5 = (long)((iVar11 - iVar20) * 4 *
250: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar6 * 4) * 4));
251: lVar21 = (long)((iVar3 - iVar17) * 8 *
252: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b340 + uVar6 * 4) * 4));
253: *(long *)(param_3 + 6) = lVar21 * lVar21 + lVar5 * lVar5 + lVar18 * lVar18;
254: if (iVar12 <= iVar16) {
255: plVar9 = (long *)(lVar2 + uVar13 * 8);
256: lVar5 = 0;
257: do {
258: if (iVar20 <= iVar11) {
259: psVar8 = (short *)(*plVar9 + ((long)iVar17 + 1 + (long)iVar20 * 0x20 + uVar23) * 2);
260: do {
261: psVar14 = psVar8 + (-1 - uVar23);
262: if (iVar17 <= iVar3) {
263: do {
264: if (*psVar14 != 0) {
265: lVar5 = lVar5 + 1;
266: }
267: psVar14 = psVar14 + 1;
268: } while (psVar14 != psVar8);
269: }
270: psVar8 = psVar8 + 0x20;
271: } while (psVar8 != (short *)(*plVar9 +
272: (uVar23 + ((long)iVar20 + (ulong)(uint)(iVar11 - iVar20)) * 0x20
273: + (long)iVar17) * 2 + 0x42));
274: }
275: plVar9 = plVar9 + 1;
276: } while (plVar9 != (long *)(lVar2 + 8 + (uVar13 + (uint)(iVar16 - iVar12)) * 8));
277: *(long *)(param_3 + 8) = lVar5;
278: return;
279: }
280: *(undefined8 *)(param_3 + 8) = 0;
281: return;
282: }
283: 

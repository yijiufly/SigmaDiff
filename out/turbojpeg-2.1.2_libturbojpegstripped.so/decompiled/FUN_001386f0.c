1: 
2: void FUN_001386f0(long param_1,long *param_2,uint param_3,undefined8 *param_4)
3: 
4: {
5: undefined uVar1;
6: byte bVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: int iVar12;
17: ulong uVar13;
18: undefined *puVar14;
19: undefined *puVar15;
20: undefined *puVar16;
21: uint uVar17;
22: uint uVar18;
23: byte *pbVar19;
24: byte *pbVar20;
25: byte *pbVar21;
26: long lVar22;
27: long lVar23;
28: bool bVar24;
29: long lStack72;
30: 
31: uVar13 = (ulong)param_3;
32: lVar5 = *(long *)(param_1 + 0x260);
33: lVar6 = *(long *)(param_1 + 0x1a8);
34: lVar7 = *(long *)(lVar5 + 0x20);
35: lVar8 = *(long *)(lVar5 + 0x38);
36: pbVar20 = *(byte **)(param_2[1] + uVar13 * 8);
37: lVar9 = *(long *)(lVar5 + 0x28);
38: lVar5 = *(long *)(lVar5 + 0x30);
39: pbVar19 = *(byte **)(*param_2 + uVar13 * 8);
40: pbVar21 = *(byte **)(param_2[2] + uVar13 * 8);
41: puVar15 = (undefined *)*param_4;
42: uVar18 = *(uint *)(param_1 + 0x88);
43: uVar17 = uVar18 >> 1;
44: if (*(int *)(param_1 + 0x40) - 6U < 10) {
45: bVar24 = uVar18 >> 1 != 0;
46: switch(*(int *)(param_1 + 0x40)) {
47: case 6:
48: if (bVar24) {
49: lVar23 = 0;
50: lStack72 = (ulong)(uVar17 - 1) + 1;
51: puVar14 = puVar15 + lStack72 * 6;
52: do {
53: puVar16 = puVar15 + 6;
54: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar23] * 4);
55: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar23] * 4);
56: lVar22 = *(long *)(lVar5 + (ulong)pbVar21[lVar23] * 8);
57: lVar11 = *(long *)(lVar8 + (ulong)pbVar20[lVar23] * 8);
58: bVar2 = pbVar19[lVar23 * 2];
59: *puVar15 = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
60: iVar12 = (int)((ulong)(lVar22 + lVar11) >> 0x10);
61: puVar15[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
62: puVar15[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
63: bVar2 = pbVar19[lVar23 * 2 + 1];
64: lVar23 = lVar23 + 1;
65: puVar15[3] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
66: puVar15[4] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
67: puVar15[5] = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
68: puVar15 = puVar16;
69: } while (puVar14 != puVar16);
70: goto LAB_00138ad3;
71: }
72: goto LAB_00138aed;
73: default:
74: if (bVar24) {
75: lVar23 = 0;
76: puVar14 = puVar15;
77: do {
78: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar23] * 4);
79: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar23] * 4);
80: lVar22 = *(long *)(lVar5 + (ulong)pbVar21[lVar23] * 8);
81: lVar11 = *(long *)(lVar8 + (ulong)pbVar20[lVar23] * 8);
82: bVar2 = pbVar19[lVar23 * 2];
83: *puVar14 = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
84: iVar12 = (int)((ulong)(lVar22 + lVar11) >> 0x10);
85: puVar14[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
86: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
87: puVar14[3] = 0xff;
88: puVar14[2] = uVar1;
89: bVar2 = pbVar19[lVar23 * 2 + 1];
90: lVar23 = lVar23 + 1;
91: puVar14[4] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
92: puVar14[5] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
93: uVar1 = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
94: puVar14[7] = 0xff;
95: puVar14[6] = uVar1;
96: puVar14 = puVar14 + 8;
97: } while (lVar23 != (ulong)(uVar17 - 1) + 1);
98: pbVar19 = pbVar19 + lVar23 * 2;
99: pbVar20 = pbVar20 + lVar23;
100: pbVar21 = pbVar21 + lVar23;
101: uVar18 = *(uint *)(param_1 + 0x88);
102: puVar15 = puVar15 + lVar23 * 8;
103: }
104: if ((uVar18 & 1) != 0) {
105: uVar18 = (uint)*pbVar19;
106: lVar5 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
107: lVar8 = *(long *)(lVar8 + (ulong)*pbVar20 * 8);
108: iVar3 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
109: *puVar15 = *(undefined *)(lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar21 * 4) + uVar18));
110: puVar15[1] = *(undefined *)(lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + uVar18));
111: uVar1 = *(undefined *)(lVar6 + (int)(iVar3 + uVar18));
112: puVar15[3] = 0xff;
113: puVar15[2] = uVar1;
114: }
115: break;
116: case 8:
117: if (bVar24) {
118: lVar22 = 0;
119: lVar23 = (ulong)(uVar17 - 1) + 1;
120: puVar14 = puVar15;
121: do {
122: puVar16 = puVar14 + 6;
123: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar22] * 4);
124: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar22] * 4);
125: lVar11 = *(long *)(lVar5 + (ulong)pbVar21[lVar22] * 8);
126: lVar10 = *(long *)(lVar8 + (ulong)pbVar20[lVar22] * 8);
127: bVar2 = pbVar19[lVar22 * 2];
128: puVar14[2] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
129: iVar12 = (int)((ulong)(lVar11 + lVar10) >> 0x10);
130: puVar14[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
131: *puVar14 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
132: bVar2 = pbVar19[lVar22 * 2 + 1];
133: lVar22 = lVar22 + 1;
134: puVar14[5] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
135: puVar14[4] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
136: puVar14[3] = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
137: puVar14 = puVar16;
138: } while (puVar15 + lVar23 * 6 != puVar16);
139: uVar18 = *(uint *)(param_1 + 0x88);
140: pbVar19 = pbVar19 + lVar23 * 2;
141: pbVar20 = pbVar20 + lVar23;
142: pbVar21 = pbVar21 + lVar23;
143: puVar15 = puVar15 + lVar23 * 6;
144: }
145: if ((uVar18 & 1) != 0) {
146: uVar18 = (uint)*pbVar19;
147: lVar5 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
148: lVar8 = *(long *)(lVar8 + (ulong)*pbVar20 * 8);
149: iVar3 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
150: puVar15[2] = *(undefined *)(lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar21 * 4) + uVar18));
151: puVar15[1] = *(undefined *)(lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + uVar18));
152: *puVar15 = *(undefined *)(lVar6 + (int)(iVar3 + uVar18));
153: }
154: break;
155: case 9:
156: case 0xd:
157: if (bVar24) {
158: lVar23 = 0;
159: puVar14 = puVar15;
160: do {
161: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar23] * 4);
162: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar23] * 4);
163: lVar22 = *(long *)(lVar5 + (ulong)pbVar21[lVar23] * 8);
164: lVar11 = *(long *)(lVar8 + (ulong)pbVar20[lVar23] * 8);
165: bVar2 = pbVar19[lVar23 * 2];
166: puVar14[2] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
167: iVar12 = (int)((ulong)(lVar22 + lVar11) >> 0x10);
168: puVar14[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
169: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
170: puVar14[3] = 0xff;
171: *puVar14 = uVar1;
172: bVar2 = pbVar19[lVar23 * 2 + 1];
173: lVar23 = lVar23 + 1;
174: puVar14[6] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
175: puVar14[5] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
176: uVar1 = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
177: puVar14[7] = 0xff;
178: puVar14[4] = uVar1;
179: puVar14 = puVar14 + 8;
180: } while (lVar23 != (ulong)(uVar17 - 1) + 1);
181: pbVar19 = pbVar19 + lVar23 * 2;
182: pbVar20 = pbVar20 + lVar23;
183: pbVar21 = pbVar21 + lVar23;
184: uVar18 = *(uint *)(param_1 + 0x88);
185: puVar15 = puVar15 + lVar23 * 8;
186: }
187: if ((uVar18 & 1) != 0) {
188: uVar18 = (uint)*pbVar19;
189: lVar5 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
190: lVar8 = *(long *)(lVar8 + (ulong)*pbVar20 * 8);
191: iVar3 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
192: puVar15[2] = *(undefined *)(lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar21 * 4) + uVar18));
193: puVar15[1] = *(undefined *)(lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + uVar18));
194: uVar1 = *(undefined *)(lVar6 + (int)(iVar3 + uVar18));
195: puVar15[3] = 0xff;
196: *puVar15 = uVar1;
197: }
198: break;
199: case 10:
200: case 0xe:
201: if (bVar24) {
202: lVar23 = 0;
203: puVar14 = puVar15;
204: do {
205: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar23] * 4);
206: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar23] * 4);
207: lVar22 = *(long *)(lVar5 + (ulong)pbVar21[lVar23] * 8);
208: lVar11 = *(long *)(lVar8 + (ulong)pbVar20[lVar23] * 8);
209: bVar2 = pbVar19[lVar23 * 2];
210: puVar14[3] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
211: iVar12 = (int)((ulong)(lVar22 + lVar11) >> 0x10);
212: puVar14[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
213: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
214: *puVar14 = 0xff;
215: puVar14[1] = uVar1;
216: bVar2 = pbVar19[lVar23 * 2 + 1];
217: lVar23 = lVar23 + 1;
218: puVar14[7] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
219: puVar14[6] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
220: uVar1 = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
221: puVar14[4] = 0xff;
222: puVar14[5] = uVar1;
223: puVar14 = puVar14 + 8;
224: } while (lVar23 != (ulong)(uVar17 - 1) + 1);
225: pbVar19 = pbVar19 + lVar23 * 2;
226: pbVar20 = pbVar20 + lVar23;
227: pbVar21 = pbVar21 + lVar23;
228: uVar18 = *(uint *)(param_1 + 0x88);
229: puVar15 = puVar15 + lVar23 * 8;
230: }
231: if ((uVar18 & 1) != 0) {
232: uVar18 = (uint)*pbVar19;
233: lVar5 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
234: lVar8 = *(long *)(lVar8 + (ulong)*pbVar20 * 8);
235: iVar3 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
236: puVar15[3] = *(undefined *)(lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar21 * 4) + uVar18));
237: puVar15[2] = *(undefined *)(lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + uVar18));
238: uVar1 = *(undefined *)(lVar6 + (int)(iVar3 + uVar18));
239: *puVar15 = 0xff;
240: puVar15[1] = uVar1;
241: }
242: break;
243: case 0xb:
244: case 0xf:
245: if (bVar24) {
246: lVar23 = 0;
247: puVar14 = puVar15;
248: do {
249: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar23] * 4);
250: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar23] * 4);
251: lVar22 = *(long *)(lVar5 + (ulong)pbVar21[lVar23] * 8);
252: lVar11 = *(long *)(lVar8 + (ulong)pbVar20[lVar23] * 8);
253: bVar2 = pbVar19[lVar23 * 2];
254: puVar14[1] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
255: iVar12 = (int)((ulong)(lVar22 + lVar11) >> 0x10);
256: puVar14[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
257: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
258: *puVar14 = 0xff;
259: puVar14[3] = uVar1;
260: bVar2 = pbVar19[lVar23 * 2 + 1];
261: lVar23 = lVar23 + 1;
262: puVar14[5] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
263: puVar14[6] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
264: uVar1 = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
265: puVar14[4] = 0xff;
266: puVar14[7] = uVar1;
267: puVar14 = puVar14 + 8;
268: } while (lVar23 != (ulong)(uVar17 - 1) + 1);
269: pbVar19 = pbVar19 + lVar23 * 2;
270: pbVar20 = pbVar20 + lVar23;
271: pbVar21 = pbVar21 + lVar23;
272: uVar18 = *(uint *)(param_1 + 0x88);
273: puVar15 = puVar15 + lVar23 * 8;
274: }
275: if ((uVar18 & 1) != 0) {
276: uVar18 = (uint)*pbVar19;
277: lVar5 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
278: lVar8 = *(long *)(lVar8 + (ulong)*pbVar20 * 8);
279: iVar3 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
280: puVar15[1] = *(undefined *)(lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar21 * 4) + uVar18));
281: puVar15[2] = *(undefined *)(lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + uVar18));
282: uVar1 = *(undefined *)(lVar6 + (int)(iVar3 + uVar18));
283: *puVar15 = 0xff;
284: puVar15[3] = uVar1;
285: }
286: }
287: }
288: else {
289: if (uVar18 >> 1 != 0) {
290: lVar23 = 0;
291: lStack72 = (ulong)(uVar17 - 1) + 1;
292: puVar14 = puVar15 + lStack72 * 6;
293: do {
294: puVar16 = puVar15 + 6;
295: iVar3 = *(int *)(lVar7 + (ulong)pbVar21[lVar23] * 4);
296: iVar4 = *(int *)(lVar9 + (ulong)pbVar20[lVar23] * 4);
297: lVar22 = *(long *)(lVar5 + (ulong)pbVar21[lVar23] * 8);
298: lVar11 = *(long *)(lVar8 + (ulong)pbVar20[lVar23] * 8);
299: bVar2 = pbVar19[lVar23 * 2];
300: *puVar15 = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
301: iVar12 = (int)((ulong)(lVar22 + lVar11) >> 0x10);
302: puVar15[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
303: puVar15[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
304: bVar2 = pbVar19[lVar23 * 2 + 1];
305: lVar23 = lVar23 + 1;
306: puVar15[3] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
307: puVar15[4] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
308: puVar15[5] = *(undefined *)(lVar6 + (int)(iVar4 + (uint)bVar2));
309: puVar15 = puVar16;
310: } while (puVar14 != puVar16);
311: LAB_00138ad3:
312: uVar18 = *(uint *)(param_1 + 0x88);
313: pbVar19 = pbVar19 + lStack72 * 2;
314: pbVar20 = pbVar20 + lStack72;
315: pbVar21 = pbVar21 + lStack72;
316: puVar15 = puVar14;
317: }
318: LAB_00138aed:
319: if ((uVar18 & 1) != 0) {
320: uVar18 = (uint)*pbVar19;
321: lVar5 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
322: lVar8 = *(long *)(lVar8 + (ulong)*pbVar20 * 8);
323: iVar3 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
324: *puVar15 = *(undefined *)(lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar21 * 4) + uVar18));
325: puVar15[1] = *(undefined *)(lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + uVar18));
326: puVar15[2] = *(undefined *)(lVar6 + (int)(iVar3 + uVar18));
327: }
328: }
329: return;
330: }
331: 

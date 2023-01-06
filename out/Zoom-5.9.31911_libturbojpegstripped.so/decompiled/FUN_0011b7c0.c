1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_0011b7c0(long param_1)
5: 
6: {
7: int iVar1;
8: int iVar2;
9: int iVar3;
10: uint uVar4;
11: long lVar5;
12: undefined2 *puVar6;
13: long lVar7;
14: int iVar8;
15: long lVar9;
16: int iVar10;
17: int iVar11;
18: long lVar12;
19: int iVar13;
20: int iVar14;
21: int iVar15;
22: long lVar16;
23: int iVar17;
24: int iVar18;
25: int iVar19;
26: int iVar20;
27: int iVar21;
28: int iVar22;
29: int iStack256;
30: int iStack252;
31: int iStack248;
32: long lStack240;
33: uint uStack200;
34: int iStack196;
35: int iStack192;
36: long lStack184;
37: long alStack168 [4];
38: long alStack136 [11];
39: 
40: iVar1 = *(int *)(param_1 + 0x168);
41: lVar5 = *(long *)(param_1 + 0x1c8);
42: iVar2 = *(int *)(param_1 + 0x140);
43: iStack196 = *(int *)(param_1 + 0x144);
44: if (0 < iStack196) {
45: lVar12 = 0;
46: do {
47: lVar7 = *(long *)(param_1 + 0x148 + lVar12 * 8);
48: iVar8 = *(int *)(lVar7 + 0xc);
49: lVar7 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
50: (param_1,*(undefined8 *)
51: (*(long *)(lVar5 + 0x20) + (long)*(int *)(lVar7 + 4) * 8),
52: *(int *)(lVar5 + 0x10) * iVar8,iVar8,0);
53: iStack196 = *(int *)(param_1 + 0x144);
54: alStack168[lVar12] = lVar7;
55: iVar8 = (int)lVar12;
56: lVar12 = lVar12 + 1;
57: } while (iVar8 + 1 < iStack196);
58: }
59: iStack192 = *(int *)(lVar5 + 0x18);
60: iVar8 = *(int *)(lVar5 + 0x1c);
61: if (iVar8 <= iStack192) {
62: LAB_0011c0b5:
63: *(int *)(lVar5 + 0x10) = *(int *)(lVar5 + 0x10) + 1;
64: lVar5 = *(long *)(param_1 + 0x1c8);
65: if (iStack196 < 2) {
66: if (*(uint *)(lVar5 + 0x10) < *(int *)(param_1 + 0x140) - 1U) {
67: *(undefined4 *)(lVar5 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0xc);
68: }
69: else {
70: *(undefined4 *)(lVar5 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0x48);
71: }
72: }
73: else {
74: *(undefined4 *)(lVar5 + 0x1c) = 1;
75: }
76: *(undefined4 *)(lVar5 + 0x14) = 0;
77: *(undefined4 *)(lVar5 + 0x18) = 0;
78: return 1;
79: }
80: lStack184 = (long)iStack192 * 8;
81: uStack200 = *(uint *)(lVar5 + 0x14);
82: LAB_0011b89d:
83: if (uStack200 <= *(uint *)(param_1 + 0x168) && *(uint *)(param_1 + 0x168) != uStack200) {
84: do {
85: if (0 < iStack196) {
86: lStack240 = 0;
87: iVar8 = 0;
88: do {
89: lVar12 = *(long *)(param_1 + 0x148 + lStack240 * 8);
90: iVar3 = *(int *)(lVar12 + 0x34);
91: iVar19 = iVar3;
92: if (iVar1 - 1U <= uStack200) {
93: iVar19 = *(int *)(lVar12 + 0x44);
94: }
95: if (0 < *(int *)(lVar12 + 0x38)) {
96: uVar4 = *(uint *)(lVar5 + 0x10);
97: iVar10 = *(int *)(lVar12 + 0x38) + iStack192;
98: lVar7 = lStack184;
99: iVar18 = iStack192;
100: iVar13 = iVar8;
101: do {
102: while( true ) {
103: if (((uVar4 < iVar2 - 1U) || (iVar18 < *(int *)(lVar12 + 0x48))) &&
104: (lVar16 = (ulong)(uStack200 * iVar3) * 0x80 +
105: *(long *)(alStack168[lStack240] + lVar7), 0 < iVar19)) {
106: alStack136[iVar13] = lVar16;
107: if (iVar19 == 1) {
108: iStack248 = 10;
109: iVar22 = 9;
110: iVar21 = 8;
111: iVar20 = 7;
112: iStack252 = 6;
113: iStack256 = 5;
114: iVar17 = 4;
115: iVar15 = 3;
116: iVar14 = 2;
117: iVar11 = 1;
118: iVar13 = iVar13 + 1;
119: }
120: else {
121: alStack136[iVar13 + 1] = lVar16 + 0x80;
122: if (iVar19 == 2) {
123: iStack248 = 0xb;
124: iVar22 = 10;
125: iVar21 = 9;
126: iVar20 = 8;
127: iStack252 = 7;
128: iStack256 = 6;
129: iVar17 = 5;
130: iVar15 = 4;
131: iVar14 = 3;
132: iVar11 = 2;
133: iVar13 = iVar13 + 2;
134: }
135: else {
136: alStack136[iVar13 + 2] = lVar16 + 0x100;
137: if (iVar19 == 3) {
138: iStack248 = 0xc;
139: iVar22 = 0xb;
140: iVar21 = 10;
141: iVar20 = 9;
142: iStack252 = 8;
143: iStack256 = 7;
144: iVar17 = 6;
145: iVar15 = 5;
146: iVar14 = 4;
147: iVar11 = 3;
148: iVar13 = iVar13 + 3;
149: }
150: else {
151: alStack136[iVar13 + 3] = lVar16 + 0x180;
152: if (iVar19 == 4) {
153: iStack248 = 0xd;
154: iVar22 = 0xc;
155: iVar21 = 0xb;
156: iVar20 = 10;
157: iStack252 = 9;
158: iStack256 = 8;
159: iVar17 = 7;
160: iVar15 = 6;
161: iVar14 = 5;
162: iVar11 = 4;
163: iVar13 = iVar13 + 4;
164: }
165: else {
166: alStack136[iVar13 + 4] = lVar16 + 0x200;
167: if (iVar19 == 5) {
168: iStack248 = 0xe;
169: iVar22 = 0xd;
170: iVar21 = 0xc;
171: iVar20 = 0xb;
172: iStack252 = 10;
173: iStack256 = 9;
174: iVar17 = 8;
175: iVar15 = 7;
176: iVar14 = 6;
177: iVar11 = 5;
178: iVar13 = iVar13 + 5;
179: }
180: else {
181: alStack136[iVar13 + 5] = lVar16 + 0x280;
182: if (iVar19 == 6) {
183: iStack248 = 0xf;
184: iVar22 = 0xe;
185: iVar21 = 0xd;
186: iVar20 = 0xc;
187: iStack252 = 0xb;
188: iStack256 = 10;
189: iVar17 = 9;
190: iVar15 = 8;
191: iVar14 = 7;
192: iVar11 = 6;
193: iVar13 = iVar13 + 6;
194: }
195: else {
196: alStack136[iVar13 + 6] = lVar16 + 0x300;
197: if (iVar19 == 7) {
198: iStack248 = 0x10;
199: iVar22 = 0xf;
200: iVar21 = 0xe;
201: iVar20 = 0xd;
202: iStack252 = 0xc;
203: iStack256 = 0xb;
204: iVar17 = 10;
205: iVar15 = 9;
206: iVar14 = 8;
207: iVar11 = 7;
208: iVar13 = iVar13 + 7;
209: }
210: else {
211: alStack136[iVar13 + 7] = lVar16 + 0x380;
212: if (iVar19 == 8) {
213: iStack248 = 0x11;
214: iVar22 = 0x10;
215: iVar21 = 0xf;
216: iVar20 = 0xe;
217: iStack252 = 0xd;
218: iStack256 = 0xc;
219: iVar17 = 0xb;
220: iVar15 = 10;
221: iVar14 = 9;
222: iVar11 = 8;
223: iVar13 = iVar13 + 8;
224: }
225: else {
226: alStack136[iVar13 + 8] = lVar16 + 0x400;
227: if (iVar19 == 9) {
228: iStack248 = 0x12;
229: iVar22 = 0x11;
230: iVar21 = 0x10;
231: iVar20 = 0xf;
232: iStack252 = 0xe;
233: iStack256 = 0xd;
234: iVar17 = 0xc;
235: iVar15 = 0xb;
236: iVar14 = 10;
237: iVar11 = 9;
238: iVar13 = iVar13 + 9;
239: }
240: else {
241: iStack248 = 0x13;
242: alStack136[iVar13 + 9] = lVar16 + 0x480;
243: iVar22 = 0x12;
244: iVar21 = 0x11;
245: iVar20 = 0x10;
246: iStack252 = 0xf;
247: iStack256 = 0xe;
248: iVar17 = 0xd;
249: iVar15 = 0xc;
250: iVar14 = 0xb;
251: iVar11 = 10;
252: iVar13 = iVar13 + 10;
253: }
254: }
255: }
256: }
257: }
258: }
259: }
260: }
261: }
262: }
263: else {
264: iStack248 = 9;
265: iVar22 = 8;
266: iVar21 = 7;
267: iVar20 = 6;
268: iStack252 = 5;
269: iStack256 = 4;
270: iVar17 = 3;
271: iVar15 = 2;
272: iVar14 = 1;
273: iVar11 = 0;
274: }
275: iVar8 = iVar13;
276: if (iVar11 < iVar3) break;
277: LAB_0011bb48:
278: iVar18 = iVar18 + 1;
279: lVar7 = lVar7 + 8;
280: iVar13 = iVar8;
281: if (iVar18 == iVar10) goto LAB_0011bd0d;
282: }
283: lVar16 = (long)iVar13;
284: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar16 * 8);
285: alStack136[lVar16] = (long)puVar6;
286: *puVar6 = *(undefined2 *)alStack136[iVar13 + -1];
287: iVar8 = iVar13 + 1;
288: if (iVar3 <= iVar14) goto LAB_0011bb48;
289: lVar9 = (long)iVar8;
290: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar9 * 8);
291: alStack136[lVar9] = (long)puVar6;
292: *puVar6 = *(undefined2 *)alStack136[lVar16];
293: iVar8 = iVar13 + 2;
294: if (iVar15 < iVar3) {
295: lVar16 = (long)iVar8;
296: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar16 * 8);
297: alStack136[lVar16] = (long)puVar6;
298: *puVar6 = *(undefined2 *)alStack136[lVar9];
299: iVar8 = iVar13 + 3;
300: if (iVar17 < iVar3) {
301: lVar9 = (long)iVar8;
302: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar9 * 8);
303: alStack136[lVar9] = (long)puVar6;
304: *puVar6 = *(undefined2 *)alStack136[lVar16];
305: iVar8 = iVar13 + 4;
306: if (iVar3 <= iStack256) goto LAB_0011bcf8;
307: lVar16 = (long)iVar8;
308: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar16 * 8);
309: alStack136[lVar16] = (long)puVar6;
310: *puVar6 = *(undefined2 *)alStack136[lVar9];
311: iVar8 = iVar13 + 5;
312: if (iStack252 < iVar3) {
313: lVar9 = (long)iVar8;
314: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar9 * 8);
315: alStack136[lVar9] = (long)puVar6;
316: *puVar6 = *(undefined2 *)alStack136[lVar16];
317: iVar8 = iVar13 + 6;
318: if (iVar3 <= iVar20) goto LAB_0011bcf8;
319: lVar16 = (long)iVar8;
320: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar16 * 8);
321: alStack136[lVar16] = (long)puVar6;
322: *puVar6 = *(undefined2 *)alStack136[lVar9];
323: iVar8 = iVar13 + 7;
324: if (iVar21 < iVar3) {
325: lVar9 = (long)iVar8;
326: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar9 * 8);
327: alStack136[lVar9] = (long)puVar6;
328: *puVar6 = *(undefined2 *)alStack136[lVar16];
329: iVar8 = iVar13 + 8;
330: if (iVar3 <= iVar22) goto LAB_0011bcf8;
331: lVar16 = (long)iVar8;
332: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar16 * 8);
333: alStack136[lVar16] = (long)puVar6;
334: *puVar6 = *(undefined2 *)alStack136[lVar9];
335: iVar8 = iVar13 + 9;
336: if (iStack248 < iVar3) {
337: lVar9 = (long)iVar8;
338: iVar8 = iVar13 + 10;
339: puVar6 = *(undefined2 **)(lVar5 + 0x28 + lVar9 * 8);
340: alStack136[lVar9] = (long)puVar6;
341: *puVar6 = *(undefined2 *)alStack136[lVar16];
342: }
343: }
344: }
345: }
346: goto LAB_0011bb48;
347: }
348: LAB_0011bcf8:
349: iVar18 = iVar18 + 1;
350: lVar7 = lVar7 + 8;
351: iVar13 = iVar8;
352: } while (iVar18 != iVar10);
353: }
354: LAB_0011bd0d:
355: lStack240 = lStack240 + 1;
356: } while ((int)lStack240 < iStack196);
357: }
358: iVar8 = (**(code **)(*(long *)(param_1 + 0x1f0) + 8))();
359: if (iVar8 == 0) {
360: *(int *)(lVar5 + 0x18) = iStack192;
361: *(uint *)(lVar5 + 0x14) = uStack200;
362: return 0;
363: }
364: uStack200 = uStack200 + 1;
365: if (*(uint *)(param_1 + 0x168) < uStack200 || *(uint *)(param_1 + 0x168) == uStack200)
366: goto LAB_0011c056;
367: iStack196 = *(int *)(param_1 + 0x144);
368: } while( true );
369: }
370: goto LAB_0011c06b;
371: LAB_0011c056:
372: iVar8 = *(int *)(lVar5 + 0x1c);
373: iStack196 = *(int *)(param_1 + 0x144);
374: LAB_0011c06b:
375: iStack192 = iStack192 + 1;
376: lStack184 = lStack184 + 8;
377: *(undefined4 *)(lVar5 + 0x14) = 0;
378: if (iVar8 <= iStack192) goto LAB_0011c0b5;
379: uStack200 = 0;
380: goto LAB_0011b89d;
381: }
382: 

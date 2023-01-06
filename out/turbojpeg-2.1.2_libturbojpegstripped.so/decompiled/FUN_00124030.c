1: 
2: undefined8 FUN_00124030(long param_1)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: undefined2 *puVar6;
11: uint uVar7;
12: long lVar8;
13: undefined8 uVar9;
14: int iVar10;
15: long lVar11;
16: int iVar12;
17: int iVar13;
18: long lVar14;
19: int iVar15;
20: long lVar16;
21: long lVar17;
22: int iVar18;
23: int iVar19;
24: int iVar20;
25: int iVar21;
26: int iVar22;
27: long lVar23;
28: int iVar24;
29: long in_FS_OFFSET;
30: int iStack288;
31: int iStack284;
32: int iStack280;
33: int iStack276;
34: uint uStack224;
35: int iStack220;
36: int iStack212;
37: long lStack208;
38: long lStack200;
39: long alStack184 [4];
40: long alStack152 [11];
41: long lStack64;
42: 
43: lVar5 = *(long *)(param_1 + 0x1c8);
44: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
45: iVar2 = *(int *)(param_1 + 0x168);
46: iVar3 = *(int *)(param_1 + 0x140);
47: iStack220 = *(int *)(param_1 + 0x144);
48: if (0 < iStack220) {
49: lVar16 = 1;
50: do {
51: lVar8 = *(long *)(param_1 + 0x140 + lVar16 * 8);
52: iVar10 = *(int *)(lVar8 + 0xc);
53: lVar8 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
54: (param_1,*(undefined8 *)
55: (*(long *)(lVar5 + 0x20) + (long)*(int *)(lVar8 + 4) * 8),
56: *(int *)(lVar5 + 0x10) * iVar10,iVar10,0);
57: alStack184[lVar16 + -1] = lVar8;
58: iStack220 = *(int *)(param_1 + 0x144);
59: iVar10 = (int)lVar16;
60: lVar16 = lVar16 + 1;
61: } while (iVar10 < iStack220);
62: }
63: iStack212 = *(int *)(lVar5 + 0x18);
64: lStack208 = (long)iStack212;
65: iVar10 = *(int *)(lVar5 + 0x1c);
66: if (iStack212 < iVar10) {
67: uStack224 = *(uint *)(lVar5 + 0x14);
68: lStack200 = lStack208 << 3;
69: uVar7 = *(uint *)(param_1 + 0x168);
70: do {
71: if (uStack224 < uVar7) {
72: do {
73: lVar16 = 0;
74: iVar10 = 0;
75: if (0 < iStack220) {
76: do {
77: lVar8 = *(long *)(param_1 + 0x148 + lVar16 * 8);
78: iVar4 = *(int *)(lVar8 + 0x34);
79: iVar15 = iVar4;
80: if (iVar2 - 1U <= uStack224) {
81: iVar15 = *(int *)(lVar8 + 0x44);
82: }
83: if (0 < *(int *)(lVar8 + 0x38)) {
84: uVar7 = *(uint *)(lVar5 + 0x10);
85: lVar1 = (lStack208 + 1 + (ulong)(*(int *)(lVar8 + 0x38) - 1)) * 8;
86: lVar23 = lStack200;
87: iVar22 = iStack212;
88: iVar24 = iVar10;
89: do {
90: while( true ) {
91: if (((uVar7 < iVar3 - 1U) ||
92: (*(int *)(lVar8 + 0x48) != iVar22 && iVar22 <= *(int *)(lVar8 + 0x48))) &&
93: (lVar14 = (ulong)(uStack224 * iVar4) * 0x80 +
94: *(long *)(alStack184[lVar16] + lVar23), 0 < iVar15)) {
95: alStack152[iVar24] = lVar14;
96: if (iVar15 == 1) {
97: iVar12 = 1;
98: iStack276 = 10;
99: iStack280 = 9;
100: iStack284 = 8;
101: iVar13 = 6;
102: iStack288 = 7;
103: iVar21 = 5;
104: iVar20 = 4;
105: iVar19 = 3;
106: iVar18 = 2;
107: iVar24 = iVar24 + 1;
108: }
109: else {
110: alStack152[iVar24 + 1] = lVar14 + 0x80;
111: if (iVar15 == 2) {
112: iVar12 = 2;
113: iStack276 = 0xb;
114: iStack280 = 10;
115: iStack284 = 9;
116: iVar13 = 7;
117: iStack288 = 8;
118: iVar21 = 6;
119: iVar20 = 5;
120: iVar19 = 4;
121: iVar18 = 3;
122: iVar24 = iVar24 + 2;
123: }
124: else {
125: alStack152[iVar24 + 2] = lVar14 + 0x100;
126: if (iVar15 == 3) {
127: iVar12 = 3;
128: iStack276 = 0xc;
129: iStack280 = 0xb;
130: iStack284 = 10;
131: iVar13 = 8;
132: iStack288 = 9;
133: iVar21 = 7;
134: iVar20 = 6;
135: iVar19 = 5;
136: iVar18 = 4;
137: iVar24 = iVar24 + 3;
138: }
139: else {
140: alStack152[iVar24 + 3] = lVar14 + 0x180;
141: if (iVar15 == 4) {
142: iVar12 = 4;
143: iStack276 = 0xd;
144: iStack280 = 0xc;
145: iStack284 = 0xb;
146: iVar13 = 9;
147: iStack288 = 10;
148: iVar21 = 8;
149: iVar20 = 7;
150: iVar19 = 6;
151: iVar18 = 5;
152: iVar24 = iVar24 + 4;
153: }
154: else {
155: alStack152[iVar24 + 4] = lVar14 + 0x200;
156: if (iVar15 == 5) {
157: iVar12 = 5;
158: iStack276 = 0xe;
159: iStack280 = 0xd;
160: iStack284 = 0xc;
161: iVar13 = 10;
162: iStack288 = 0xb;
163: iVar21 = 9;
164: iVar20 = 8;
165: iVar19 = 7;
166: iVar18 = 6;
167: iVar24 = iVar24 + 5;
168: }
169: else {
170: alStack152[iVar24 + 5] = lVar14 + 0x280;
171: if (iVar15 == 6) {
172: iVar12 = 6;
173: iStack276 = 0xf;
174: iStack280 = 0xe;
175: iStack284 = 0xd;
176: iVar13 = 0xb;
177: iStack288 = 0xc;
178: iVar21 = 10;
179: iVar20 = 9;
180: iVar19 = 8;
181: iVar18 = 7;
182: iVar24 = iVar24 + 6;
183: }
184: else {
185: alStack152[iVar24 + 6] = lVar14 + 0x300;
186: if (iVar15 == 7) {
187: iVar12 = 7;
188: iStack276 = 0x10;
189: iStack280 = 0xf;
190: iStack284 = 0xe;
191: iVar13 = 0xc;
192: iStack288 = 0xd;
193: iVar21 = 0xb;
194: iVar20 = 10;
195: iVar19 = 9;
196: iVar18 = 8;
197: iVar24 = iVar24 + 7;
198: }
199: else {
200: alStack152[iVar24 + 7] = lVar14 + 0x380;
201: if (iVar15 == 8) {
202: iVar12 = 8;
203: iStack276 = 0x11;
204: iStack280 = 0x10;
205: iStack284 = 0xf;
206: iVar13 = 0xd;
207: iStack288 = 0xe;
208: iVar21 = 0xc;
209: iVar20 = 0xb;
210: iVar19 = 10;
211: iVar18 = 9;
212: iVar24 = iVar24 + 8;
213: }
214: else {
215: alStack152[iVar24 + 8] = lVar14 + 0x400;
216: if (iVar15 == 9) {
217: iVar12 = 9;
218: iStack276 = 0x12;
219: iStack280 = 0x11;
220: iStack284 = 0x10;
221: iVar13 = 0xe;
222: iStack288 = 0xf;
223: iVar21 = 0xd;
224: iVar20 = 0xc;
225: iVar19 = 0xb;
226: iVar18 = 10;
227: iVar24 = iVar24 + 9;
228: }
229: else {
230: iStack276 = 0x13;
231: alStack152[iVar24 + 9] = lVar14 + 0x480;
232: iStack280 = 0x12;
233: iVar13 = 0xf;
234: iStack284 = 0x11;
235: iStack288 = 0x10;
236: iVar21 = 0xe;
237: iVar20 = 0xd;
238: iVar19 = 0xc;
239: iVar18 = 0xb;
240: iVar12 = 10;
241: iVar24 = iVar24 + 10;
242: }
243: }
244: }
245: }
246: }
247: }
248: }
249: }
250: }
251: }
252: else {
253: iStack276 = 9;
254: iStack280 = 8;
255: iVar13 = 5;
256: iStack284 = 7;
257: iStack288 = 6;
258: iVar21 = 4;
259: iVar20 = 3;
260: iVar19 = 2;
261: iVar18 = 1;
262: iVar12 = 0;
263: }
264: iVar10 = iVar24;
265: if (iVar12 < iVar4) break;
266: LAB_001243d4:
267: iVar22 = iVar22 + 1;
268: lVar23 = lVar23 + 8;
269: iVar24 = iVar10;
270: if (lVar1 == lVar23) goto LAB_00124596;
271: }
272: lVar17 = (long)iVar24;
273: lVar14 = lVar5 + lVar17 * 8;
274: puVar6 = *(undefined2 **)(lVar14 + 0x28);
275: alStack152[lVar17] = (long)puVar6;
276: *puVar6 = *(undefined2 *)alStack152[iVar24 + -1];
277: iVar10 = iVar24 + 1;
278: if (iVar18 < iVar4) {
279: puVar6 = *(undefined2 **)(lVar14 + 0x30);
280: lVar11 = (long)iVar10;
281: alStack152[lVar11] = (long)puVar6;
282: *puVar6 = *(undefined2 *)alStack152[lVar17];
283: iVar10 = iVar24 + 2;
284: if (iVar19 < iVar4) {
285: puVar6 = *(undefined2 **)(lVar14 + 0x38);
286: lVar17 = (long)iVar10;
287: alStack152[lVar17] = (long)puVar6;
288: *puVar6 = *(undefined2 *)alStack152[lVar11];
289: iVar10 = iVar24 + 3;
290: if (iVar4 <= iVar20) goto LAB_00124580;
291: puVar6 = *(undefined2 **)(lVar14 + 0x40);
292: lVar11 = (long)iVar10;
293: alStack152[lVar11] = (long)puVar6;
294: *puVar6 = *(undefined2 *)alStack152[lVar17];
295: iVar10 = iVar24 + 4;
296: if (iVar21 < iVar4) {
297: puVar6 = *(undefined2 **)(lVar14 + 0x48);
298: lVar17 = (long)iVar10;
299: alStack152[lVar17] = (long)puVar6;
300: *puVar6 = *(undefined2 *)alStack152[lVar11];
301: iVar10 = iVar24 + 5;
302: if (iVar4 <= iVar13) goto LAB_00124580;
303: puVar6 = *(undefined2 **)(lVar14 + 0x50);
304: lVar11 = (long)iVar10;
305: alStack152[lVar11] = (long)puVar6;
306: *puVar6 = *(undefined2 *)alStack152[lVar17];
307: iVar10 = iVar24 + 6;
308: if (iStack288 < iVar4) {
309: puVar6 = *(undefined2 **)(lVar14 + 0x58);
310: lVar17 = (long)iVar10;
311: alStack152[lVar17] = (long)puVar6;
312: *puVar6 = *(undefined2 *)alStack152[lVar11];
313: iVar10 = iVar24 + 7;
314: if (iVar4 <= iStack284) goto LAB_00124580;
315: puVar6 = *(undefined2 **)(lVar14 + 0x60);
316: lVar11 = (long)iVar10;
317: alStack152[lVar11] = (long)puVar6;
318: *puVar6 = *(undefined2 *)alStack152[lVar17];
319: iVar10 = iVar24 + 8;
320: if (iStack280 < iVar4) {
321: puVar6 = *(undefined2 **)(lVar14 + 0x68);
322: lVar17 = (long)iVar10;
323: alStack152[lVar17] = (long)puVar6;
324: *puVar6 = *(undefined2 *)alStack152[lVar11];
325: iVar10 = iVar24 + 9;
326: if (iVar4 <= iStack276) goto LAB_00124580;
327: puVar6 = *(undefined2 **)(lVar14 + 0x70);
328: lVar14 = (long)iVar10;
329: iVar10 = iVar24 + 10;
330: alStack152[lVar14] = (long)puVar6;
331: *puVar6 = *(undefined2 *)alStack152[lVar17];
332: }
333: }
334: }
335: }
336: goto LAB_001243d4;
337: }
338: LAB_00124580:
339: iVar22 = iVar22 + 1;
340: lVar23 = lVar23 + 8;
341: iVar24 = iVar10;
342: } while (lVar1 != lVar23);
343: }
344: LAB_00124596:
345: lVar16 = lVar16 + 1;
346: } while ((int)lVar16 < iStack220);
347: }
348: uVar9 = (**(code **)(*(long *)(param_1 + 0x1f0) + 8))(param_1,alStack152);
349: if ((int)uVar9 == 0) {
350: *(int *)(lVar5 + 0x18) = iStack212;
351: *(uint *)(lVar5 + 0x14) = uStack224;
352: goto LAB_0012494d;
353: }
354: uStack224 = uStack224 + 1;
355: uVar7 = *(uint *)(param_1 + 0x168);
356: iStack220 = *(int *)(param_1 + 0x144);
357: } while (uStack224 < uVar7);
358: iVar10 = *(int *)(lVar5 + 0x1c);
359: }
360: iStack212 = iStack212 + 1;
361: *(undefined4 *)(lVar5 + 0x14) = 0;
362: lStack200 = lStack200 + 8;
363: lStack208 = lStack208 + 1;
364: uStack224 = 0;
365: } while (iStack212 < iVar10);
366: }
367: *(int *)(lVar5 + 0x10) = *(int *)(lVar5 + 0x10) + 1;
368: lVar5 = *(long *)(param_1 + 0x1c8);
369: if (*(int *)(param_1 + 0x144) < 2) {
370: if (*(uint *)(lVar5 + 0x10) < *(int *)(param_1 + 0x140) - 1U) {
371: *(undefined4 *)(lVar5 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0xc);
372: }
373: else {
374: *(undefined4 *)(lVar5 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0x48);
375: }
376: }
377: else {
378: *(undefined4 *)(lVar5 + 0x1c) = 1;
379: }
380: *(undefined8 *)(lVar5 + 0x14) = 0;
381: uVar9 = 1;
382: LAB_0012494d:
383: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
384: /* WARNING: Subroutine does not return */
385: __stack_chk_fail();
386: }
387: return uVar9;
388: }
389: 

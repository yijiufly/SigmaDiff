1: 
2: void FUN_0012d400(long param_1,long *param_2,ulong param_3,undefined8 *param_4)
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
17: uint uVar13;
18: undefined *puVar14;
19: undefined *puVar15;
20: long lVar16;
21: byte *pbVar17;
22: byte *pbVar18;
23: byte *pbVar19;
24: byte *pbVar20;
25: byte *pbVar21;
26: byte *pbStack80;
27: byte *pbStack72;
28: byte *pbStack64;
29: 
30: if (*(int *)(param_1 + 0x40) - 6U < 10) {
31: puVar14 = (undefined *)*param_4;
32: pbStack72 = puVar14;
33: switch(*(int *)(param_1 + 0x40)) {
34: case 6:
35: param_3 = param_3 & 0xffffffff;
36: lVar5 = *(long *)(param_1 + 0x260);
37: lVar6 = *(long *)(param_1 + 0x1a8);
38: lVar7 = *(long *)(lVar5 + 0x20);
39: lVar8 = *(long *)(lVar5 + 0x28);
40: lVar9 = *(long *)(lVar5 + 0x30);
41: lVar5 = *(long *)(lVar5 + 0x38);
42: pbStack80 = *(byte **)(*param_2 + param_3 * 8);
43: pbStack72 = *(byte **)(param_2[1] + param_3 * 8);
44: pbStack64 = *(byte **)(param_2[2] + param_3 * 8);
45: uVar13 = *(uint *)(param_1 + 0x88);
46: if (uVar13 >> 1 != 0) {
47: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
48: pbVar17 = pbStack80;
49: pbVar18 = pbStack72;
50: pbVar19 = pbStack64;
51: do {
52: puVar15 = puVar14 + 6;
53: iVar3 = *(int *)(lVar7 + (ulong)*pbVar19 * 4);
54: lVar10 = *(long *)(lVar5 + (ulong)*pbVar18 * 8);
55: lVar11 = *(long *)(lVar9 + (ulong)*pbVar19 * 8);
56: bVar2 = *pbVar17;
57: iVar4 = *(int *)(lVar8 + (ulong)*pbVar18 * 4);
58: *puVar14 = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
59: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
60: puVar14[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
61: puVar14[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
62: bVar2 = pbVar17[1];
63: puVar14[3] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
64: puVar14[4] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
65: puVar14[5] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
66: puVar14 = puVar15;
67: pbVar17 = pbVar17 + 2;
68: pbVar18 = pbVar18 + 1;
69: pbVar19 = pbVar19 + 1;
70: } while (puVar15 != puVar14 + lVar16 * 6);
71: pbStack72 = pbStack72 + lVar16;
72: pbStack64 = pbStack64 + lVar16;
73: pbStack80 = pbStack80 + lVar16 * 2;
74: uVar13 = *(uint *)(param_1 + 0x88);
75: puVar14 = puVar14 + lVar16 * 6;
76: }
77: if ((uVar13 & 1) != 0) {
78: lVar5 = *(long *)(lVar5 + (ulong)*pbStack72 * 8);
79: iVar3 = *(int *)(lVar8 + (ulong)*pbStack72 * 4);
80: lVar8 = *(long *)(lVar9 + (ulong)*pbStack64 * 8);
81: bVar2 = *pbStack80;
82: *puVar14 = *(undefined *)
83: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbStack64 * 4) + (uint)bVar2));
84: puVar14[1] = *(undefined *)
85: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
86: puVar14[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
87: }
88: break;
89: default:
90: param_3 = param_3 & 0xffffffff;
91: lVar5 = *(long *)(param_1 + 0x260);
92: lVar6 = *(long *)(param_1 + 0x1a8);
93: lVar7 = *(long *)(lVar5 + 0x20);
94: lVar8 = *(long *)(lVar5 + 0x28);
95: lVar9 = *(long *)(lVar5 + 0x30);
96: lVar5 = *(long *)(lVar5 + 0x38);
97: pbStack80 = *(byte **)(*param_2 + param_3 * 8);
98: pbStack64 = *(byte **)(param_2[1] + param_3 * 8);
99: pbVar17 = *(byte **)(param_2[2] + param_3 * 8);
100: uVar13 = *(uint *)(param_1 + 0x88);
101: if (uVar13 >> 1 != 0) {
102: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
103: puVar15 = puVar14;
104: pbVar18 = pbVar17;
105: pbVar19 = pbStack80;
106: pbVar21 = pbStack64;
107: do {
108: pbVar20 = pbVar18 + 1;
109: iVar3 = *(int *)(lVar7 + (ulong)*pbVar18 * 4);
110: lVar10 = *(long *)(lVar5 + (ulong)*pbVar21 * 8);
111: lVar11 = *(long *)(lVar9 + (ulong)*pbVar18 * 8);
112: bVar2 = *pbVar19;
113: iVar4 = *(int *)(lVar8 + (ulong)*pbVar21 * 4);
114: *puVar15 = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
115: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
116: puVar15[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
117: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
118: puVar15[3] = 0xff;
119: puVar15[2] = uVar1;
120: bVar2 = pbVar19[1];
121: puVar15[4] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
122: puVar15[5] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
123: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
124: puVar15[7] = 0xff;
125: puVar15[6] = uVar1;
126: puVar15 = puVar15 + 8;
127: pbVar18 = pbVar20;
128: pbVar19 = pbVar19 + 2;
129: pbVar21 = pbVar21 + 1;
130: } while (pbVar20 != pbVar17 + lVar16);
131: pbStack64 = pbStack64 + lVar16;
132: pbStack80 = pbStack80 + lVar16 * 2;
133: uVar13 = *(uint *)(param_1 + 0x88);
134: pbVar17 = pbVar17 + lVar16;
135: pbStack72 = puVar14 + lVar16 * 8;
136: }
137: if ((uVar13 & 1) != 0) {
138: lVar5 = *(long *)(lVar5 + (ulong)*pbStack64 * 8);
139: iVar3 = *(int *)(lVar8 + (ulong)*pbStack64 * 4);
140: lVar8 = *(long *)(lVar9 + (ulong)*pbVar17 * 8);
141: bVar2 = *pbStack80;
142: *pbStack72 = *(undefined *)
143: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbVar17 * 4) + (uint)bVar2));
144: pbStack72[1] = *(undefined *)
145: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
146: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
147: pbStack72[3] = 0xff;
148: pbStack72[2] = uVar1;
149: }
150: break;
151: case 8:
152: param_3 = param_3 & 0xffffffff;
153: lVar5 = *(long *)(param_1 + 0x260);
154: lVar6 = *(long *)(param_1 + 0x1a8);
155: lVar7 = *(long *)(lVar5 + 0x20);
156: lVar8 = *(long *)(lVar5 + 0x28);
157: lVar9 = *(long *)(lVar5 + 0x30);
158: lVar5 = *(long *)(lVar5 + 0x38);
159: pbStack64 = *(byte **)(*param_2 + param_3 * 8);
160: pbVar17 = *(byte **)(param_2[1] + param_3 * 8);
161: pbStack72 = *(byte **)(param_2[2] + param_3 * 8);
162: uVar13 = *(uint *)(param_1 + 0x88);
163: pbStack80 = puVar14;
164: if (uVar13 >> 1 != 0) {
165: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
166: puVar15 = puVar14;
167: pbVar18 = pbStack64;
168: pbVar19 = pbVar17;
169: pbVar21 = pbStack72;
170: do {
171: pbVar20 = pbVar19 + 1;
172: iVar3 = *(int *)(lVar7 + (ulong)*pbVar21 * 4);
173: lVar10 = *(long *)(lVar5 + (ulong)*pbVar19 * 8);
174: lVar11 = *(long *)(lVar9 + (ulong)*pbVar21 * 8);
175: bVar2 = *pbVar18;
176: iVar4 = *(int *)(lVar8 + (ulong)*pbVar19 * 4);
177: puVar15[2] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
178: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
179: puVar15[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
180: *puVar15 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
181: bVar2 = pbVar18[1];
182: puVar15[5] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
183: puVar15[4] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
184: puVar15[3] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
185: puVar15 = puVar15 + 6;
186: pbVar18 = pbVar18 + 2;
187: pbVar19 = pbVar20;
188: pbVar21 = pbVar21 + 1;
189: } while (pbVar20 != pbVar17 + lVar16);
190: pbStack72 = pbStack72 + lVar16;
191: pbStack64 = pbStack64 + lVar16 * 2;
192: uVar13 = *(uint *)(param_1 + 0x88);
193: pbVar17 = pbVar17 + lVar16;
194: pbStack80 = puVar14 + lVar16 * 6;
195: }
196: if ((uVar13 & 1) != 0) {
197: iVar3 = *(int *)(lVar8 + (ulong)*pbVar17 * 4);
198: lVar5 = *(long *)(lVar5 + (ulong)*pbVar17 * 8);
199: lVar8 = *(long *)(lVar9 + (ulong)*pbStack72 * 8);
200: bVar2 = *pbStack64;
201: pbStack80[2] = *(undefined *)
202: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbStack72 * 4) + (uint)bVar2));
203: pbStack80[1] = *(undefined *)
204: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
205: *pbStack80 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
206: }
207: break;
208: case 9:
209: case 0xd:
210: param_3 = param_3 & 0xffffffff;
211: lVar5 = *(long *)(param_1 + 0x260);
212: lVar6 = *(long *)(param_1 + 0x1a8);
213: lVar7 = *(long *)(lVar5 + 0x20);
214: lVar8 = *(long *)(lVar5 + 0x28);
215: lVar9 = *(long *)(lVar5 + 0x30);
216: lVar5 = *(long *)(lVar5 + 0x38);
217: pbStack80 = *(byte **)(*param_2 + param_3 * 8);
218: pbVar17 = *(byte **)(param_2[1] + param_3 * 8);
219: pbStack64 = *(byte **)(param_2[2] + param_3 * 8);
220: uVar13 = *(uint *)(param_1 + 0x88);
221: if (uVar13 >> 1 != 0) {
222: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
223: puVar15 = puVar14;
224: pbVar18 = pbStack80;
225: pbVar19 = pbVar17;
226: pbVar21 = pbStack64;
227: do {
228: pbVar20 = pbVar19 + 1;
229: iVar3 = *(int *)(lVar7 + (ulong)*pbVar21 * 4);
230: lVar10 = *(long *)(lVar5 + (ulong)*pbVar19 * 8);
231: lVar11 = *(long *)(lVar9 + (ulong)*pbVar21 * 8);
232: bVar2 = *pbVar18;
233: iVar4 = *(int *)(lVar8 + (ulong)*pbVar19 * 4);
234: puVar15[2] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
235: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
236: puVar15[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
237: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
238: puVar15[3] = 0xff;
239: *puVar15 = uVar1;
240: bVar2 = pbVar18[1];
241: puVar15[6] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
242: puVar15[5] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
243: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
244: puVar15[7] = 0xff;
245: puVar15[4] = uVar1;
246: puVar15 = puVar15 + 8;
247: pbVar18 = pbVar18 + 2;
248: pbVar19 = pbVar20;
249: pbVar21 = pbVar21 + 1;
250: } while (pbVar20 != pbVar17 + lVar16);
251: pbStack64 = pbStack64 + lVar16;
252: pbStack80 = pbStack80 + lVar16 * 2;
253: uVar13 = *(uint *)(param_1 + 0x88);
254: pbVar17 = pbVar17 + lVar16;
255: pbStack72 = puVar14 + lVar16 * 8;
256: }
257: if ((uVar13 & 1) != 0) {
258: iVar3 = *(int *)(lVar8 + (ulong)*pbVar17 * 4);
259: lVar5 = *(long *)(lVar5 + (ulong)*pbVar17 * 8);
260: lVar8 = *(long *)(lVar9 + (ulong)*pbStack64 * 8);
261: bVar2 = *pbStack80;
262: pbStack72[2] = *(undefined *)
263: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbStack64 * 4) + (uint)bVar2));
264: pbStack72[1] = *(undefined *)
265: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
266: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
267: pbStack72[3] = 0xff;
268: *pbStack72 = uVar1;
269: }
270: break;
271: case 10:
272: case 0xe:
273: param_3 = param_3 & 0xffffffff;
274: lVar5 = *(long *)(param_1 + 0x260);
275: lVar6 = *(long *)(param_1 + 0x1a8);
276: lVar7 = *(long *)(lVar5 + 0x20);
277: lVar8 = *(long *)(lVar5 + 0x28);
278: lVar9 = *(long *)(lVar5 + 0x30);
279: lVar5 = *(long *)(lVar5 + 0x38);
280: pbStack80 = *(byte **)(*param_2 + param_3 * 8);
281: pbVar17 = *(byte **)(param_2[1] + param_3 * 8);
282: pbStack64 = *(byte **)(param_2[2] + param_3 * 8);
283: uVar13 = *(uint *)(param_1 + 0x88);
284: if (uVar13 >> 1 != 0) {
285: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
286: puVar15 = puVar14;
287: pbVar18 = pbStack80;
288: pbVar19 = pbVar17;
289: pbVar21 = pbStack64;
290: do {
291: pbVar20 = pbVar19 + 1;
292: iVar3 = *(int *)(lVar7 + (ulong)*pbVar21 * 4);
293: lVar10 = *(long *)(lVar5 + (ulong)*pbVar19 * 8);
294: lVar11 = *(long *)(lVar9 + (ulong)*pbVar21 * 8);
295: bVar2 = *pbVar18;
296: iVar4 = *(int *)(lVar8 + (ulong)*pbVar19 * 4);
297: puVar15[3] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
298: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
299: puVar15[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
300: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
301: *puVar15 = 0xff;
302: puVar15[1] = uVar1;
303: bVar2 = pbVar18[1];
304: puVar15[7] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
305: puVar15[6] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
306: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
307: puVar15[4] = 0xff;
308: puVar15[5] = uVar1;
309: puVar15 = puVar15 + 8;
310: pbVar18 = pbVar18 + 2;
311: pbVar19 = pbVar20;
312: pbVar21 = pbVar21 + 1;
313: } while (pbVar20 != pbVar17 + lVar16);
314: pbStack64 = pbStack64 + lVar16;
315: pbStack80 = pbStack80 + lVar16 * 2;
316: uVar13 = *(uint *)(param_1 + 0x88);
317: pbVar17 = pbVar17 + lVar16;
318: pbStack72 = puVar14 + lVar16 * 8;
319: }
320: if ((uVar13 & 1) != 0) {
321: iVar3 = *(int *)(lVar8 + (ulong)*pbVar17 * 4);
322: lVar5 = *(long *)(lVar5 + (ulong)*pbVar17 * 8);
323: lVar8 = *(long *)(lVar9 + (ulong)*pbStack64 * 8);
324: bVar2 = *pbStack80;
325: pbStack72[3] = *(undefined *)
326: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbStack64 * 4) + (uint)bVar2));
327: pbStack72[2] = *(undefined *)
328: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
329: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
330: *pbStack72 = 0xff;
331: pbStack72[1] = uVar1;
332: }
333: break;
334: case 0xb:
335: case 0xf:
336: param_3 = param_3 & 0xffffffff;
337: lVar5 = *(long *)(param_1 + 0x260);
338: lVar6 = *(long *)(param_1 + 0x1a8);
339: lVar7 = *(long *)(lVar5 + 0x20);
340: lVar8 = *(long *)(lVar5 + 0x28);
341: lVar9 = *(long *)(lVar5 + 0x30);
342: lVar5 = *(long *)(lVar5 + 0x38);
343: pbStack80 = *(byte **)(*param_2 + param_3 * 8);
344: pbVar17 = *(byte **)(param_2[1] + param_3 * 8);
345: pbStack64 = *(byte **)(param_2[2] + param_3 * 8);
346: uVar13 = *(uint *)(param_1 + 0x88);
347: if (uVar13 >> 1 != 0) {
348: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
349: puVar15 = puVar14;
350: pbVar18 = pbStack80;
351: pbVar19 = pbVar17;
352: pbVar21 = pbStack64;
353: do {
354: pbVar20 = pbVar19 + 1;
355: iVar3 = *(int *)(lVar7 + (ulong)*pbVar21 * 4);
356: lVar10 = *(long *)(lVar5 + (ulong)*pbVar19 * 8);
357: lVar11 = *(long *)(lVar9 + (ulong)*pbVar21 * 8);
358: bVar2 = *pbVar18;
359: iVar4 = *(int *)(lVar8 + (ulong)*pbVar19 * 4);
360: puVar15[1] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
361: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
362: puVar15[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
363: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
364: *puVar15 = 0xff;
365: puVar15[3] = uVar1;
366: bVar2 = pbVar18[1];
367: puVar15[5] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
368: puVar15[6] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
369: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
370: puVar15[4] = 0xff;
371: puVar15[7] = uVar1;
372: puVar15 = puVar15 + 8;
373: pbVar18 = pbVar18 + 2;
374: pbVar19 = pbVar20;
375: pbVar21 = pbVar21 + 1;
376: } while (pbVar20 != pbVar17 + lVar16);
377: pbStack64 = pbStack64 + lVar16;
378: pbStack80 = pbStack80 + lVar16 * 2;
379: uVar13 = *(uint *)(param_1 + 0x88);
380: pbVar17 = pbVar17 + lVar16;
381: pbStack72 = puVar14 + lVar16 * 8;
382: }
383: if ((uVar13 & 1) != 0) {
384: iVar3 = *(int *)(lVar8 + (ulong)*pbVar17 * 4);
385: lVar5 = *(long *)(lVar5 + (ulong)*pbVar17 * 8);
386: lVar8 = *(long *)(lVar9 + (ulong)*pbStack64 * 8);
387: bVar2 = *pbStack80;
388: pbStack72[1] = *(undefined *)
389: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbStack64 * 4) + (uint)bVar2));
390: pbStack72[2] = *(undefined *)
391: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
392: uVar1 = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
393: *pbStack72 = 0xff;
394: pbStack72[3] = uVar1;
395: }
396: }
397: }
398: else {
399: pbStack80 = (byte *)*param_4;
400: param_3 = param_3 & 0xffffffff;
401: lVar5 = *(long *)(param_1 + 0x260);
402: lVar6 = *(long *)(param_1 + 0x1a8);
403: lVar7 = *(long *)(lVar5 + 0x20);
404: lVar8 = *(long *)(lVar5 + 0x28);
405: lVar9 = *(long *)(lVar5 + 0x30);
406: lVar5 = *(long *)(lVar5 + 0x38);
407: pbStack64 = *(byte **)(*param_2 + param_3 * 8);
408: pbVar17 = *(byte **)(param_2[1] + param_3 * 8);
409: pbStack72 = *(byte **)(param_2[2] + param_3 * 8);
410: uVar13 = *(uint *)(param_1 + 0x88);
411: if (uVar13 >> 1 != 0) {
412: lVar16 = (ulong)((uVar13 >> 1) - 1) + 1;
413: puVar14 = pbStack80;
414: pbVar18 = pbStack64;
415: pbVar19 = pbVar17;
416: pbVar21 = pbStack72;
417: do {
418: pbVar20 = pbVar19 + 1;
419: iVar3 = *(int *)(lVar7 + (ulong)*pbVar21 * 4);
420: lVar10 = *(long *)(lVar5 + (ulong)*pbVar19 * 8);
421: lVar11 = *(long *)(lVar9 + (ulong)*pbVar21 * 8);
422: bVar2 = *pbVar18;
423: iVar4 = *(int *)(lVar8 + (ulong)*pbVar19 * 4);
424: *puVar14 = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
425: iVar12 = (int)((ulong)(lVar10 + lVar11) >> 0x10);
426: puVar14[1] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar12));
427: puVar14[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
428: bVar2 = pbVar18[1];
429: puVar14[3] = *(undefined *)(lVar6 + (int)(iVar3 + (uint)bVar2));
430: puVar14[4] = *(undefined *)(lVar6 + (int)(iVar12 + (uint)bVar2));
431: puVar14[5] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar4));
432: puVar14 = puVar14 + 6;
433: pbVar18 = pbVar18 + 2;
434: pbVar19 = pbVar20;
435: pbVar21 = pbVar21 + 1;
436: } while (pbVar20 != pbVar17 + lVar16);
437: pbStack72 = pbStack72 + lVar16;
438: pbStack64 = pbStack64 + lVar16 * 2;
439: pbStack80 = pbStack80 + lVar16 * 6;
440: uVar13 = *(uint *)(param_1 + 0x88);
441: pbVar17 = pbVar17 + lVar16;
442: }
443: if ((uVar13 & 1) != 0) {
444: iVar3 = *(int *)(lVar8 + (ulong)*pbVar17 * 4);
445: lVar5 = *(long *)(lVar5 + (ulong)*pbVar17 * 8);
446: bVar2 = *pbStack64;
447: lVar8 = *(long *)(lVar9 + (ulong)*pbStack72 * 8);
448: *pbStack80 = *(undefined *)
449: (lVar6 + (int)(*(int *)(lVar7 + (ulong)*pbStack72 * 4) + (uint)bVar2));
450: pbStack80[1] = *(undefined *)
451: (lVar6 + (int)((int)((ulong)(lVar5 + lVar8) >> 0x10) + (uint)bVar2));
452: pbStack80[2] = *(undefined *)(lVar6 + (int)((uint)bVar2 + iVar3));
453: }
454: }
455: return;
456: }
457: 

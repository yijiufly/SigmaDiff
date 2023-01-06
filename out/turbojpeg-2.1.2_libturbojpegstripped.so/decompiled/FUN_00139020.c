1: 
2: void FUN_00139020(long param_1,long *param_2,uint param_3,undefined8 *param_4)
3: 
4: {
5: long lVar1;
6: byte bVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: undefined uVar11;
16: int iVar12;
17: byte *pbVar13;
18: byte *pbVar14;
19: undefined *puVar15;
20: undefined *puVar16;
21: byte *pbVar17;
22: undefined *puVar18;
23: int iVar19;
24: byte *pbVar20;
25: uint uVar21;
26: uint uVar22;
27: undefined *puVar23;
28: byte *pbVar24;
29: byte *pbVar25;
30: byte *pbVar26;
31: bool bVar27;
32: undefined *puStack144;
33: byte *pbStack136;
34: byte *pbStack128;
35: 
36: lVar4 = *(long *)(param_1 + 0x260);
37: lVar5 = *(long *)(param_1 + 0x1a8);
38: lVar6 = *(long *)(lVar4 + 0x20);
39: lVar7 = *(long *)(lVar4 + 0x28);
40: lVar8 = *(long *)(lVar4 + 0x30);
41: lVar4 = *(long *)(lVar4 + 0x38);
42: pbStack128 = *(byte **)(*param_2 + (ulong)(param_3 * 2) * 8);
43: pbStack136 = *(byte **)(*param_2 + (ulong)(param_3 * 2 + 1) * 8);
44: uVar21 = *(uint *)(param_1 + 0x88);
45: puStack144 = (undefined *)param_4[1];
46: pbVar20 = *(byte **)(param_2[1] + (ulong)param_3 * 8);
47: pbVar14 = *(byte **)(param_2[2] + (ulong)param_3 * 8);
48: puVar18 = (undefined *)*param_4;
49: uVar22 = uVar21 >> 1;
50: if (*(int *)(param_1 + 0x40) - 6U < 10) {
51: bVar27 = uVar21 >> 1 != 0;
52: switch(*(int *)(param_1 + 0x40)) {
53: case 6:
54: if (bVar27) {
55: lVar1 = (ulong)(uVar22 - 1) + 1;
56: puVar15 = puVar18 + lVar1 * 6;
57: pbVar13 = pbStack128;
58: puVar16 = puVar18;
59: puVar23 = puStack144;
60: pbVar24 = pbStack136;
61: pbVar25 = pbVar20;
62: pbVar26 = pbVar14;
63: do {
64: puVar18 = puVar16 + 6;
65: iVar3 = *(int *)(lVar6 + (ulong)*pbVar26 * 4);
66: lVar9 = *(long *)(lVar8 + (ulong)*pbVar26 * 8);
67: lVar10 = *(long *)(lVar4 + (ulong)*pbVar25 * 8);
68: bVar2 = *pbVar13;
69: iVar19 = *(int *)(lVar7 + (ulong)*pbVar25 * 4);
70: *puVar16 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
71: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
72: puVar16[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
73: puVar16[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
74: bVar2 = pbVar13[1];
75: puVar16[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
76: puVar16[4] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
77: puVar16[5] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
78: bVar2 = *pbVar24;
79: *puVar23 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
80: puVar23[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
81: puVar23[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
82: bVar2 = pbVar24[1];
83: puVar23[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
84: puVar23[4] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
85: puVar23[5] = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
86: pbVar13 = pbVar13 + 2;
87: puVar16 = puVar18;
88: puVar23 = puVar23 + 6;
89: pbVar24 = pbVar24 + 2;
90: pbVar25 = pbVar25 + 1;
91: pbVar26 = pbVar26 + 1;
92: } while (puVar18 != puVar15);
93: pbStack128 = pbStack128 + lVar1 * 2;
94: pbStack136 = pbStack136 + lVar1 * 2;
95: uVar21 = *(uint *)(param_1 + 0x88);
96: pbVar20 = pbVar20 + lVar1;
97: puStack144 = puStack144 + lVar1 * 6;
98: pbVar14 = pbVar14 + lVar1;
99: }
100: if ((uVar21 & 1) != 0) {
101: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
102: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
103: bVar2 = *pbStack128;
104: iVar12 = (int)((ulong)(*(long *)(lVar8 + (ulong)*pbVar14 * 8) +
105: *(long *)(lVar4 + (ulong)*pbVar20 * 8)) >> 0x10);
106: *puVar18 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
107: puVar18[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
108: puVar18[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
109: bVar2 = *pbStack136;
110: uVar11 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
111: goto LAB_001397b4;
112: }
113: break;
114: default:
115: if (bVar27) {
116: lVar1 = (ulong)(uVar22 - 1) + 1;
117: pbVar17 = pbVar14 + lVar1;
118: pbVar13 = pbVar14;
119: puVar16 = puVar18;
120: puVar23 = puStack144;
121: pbVar24 = pbStack128;
122: pbVar25 = pbStack136;
123: pbVar26 = pbVar20;
124: do {
125: pbVar14 = pbVar13 + 1;
126: bVar2 = *pbVar24;
127: iVar3 = *(int *)(lVar6 + (ulong)*pbVar13 * 4);
128: lVar9 = *(long *)(lVar8 + (ulong)*pbVar13 * 8);
129: lVar10 = *(long *)(lVar4 + (ulong)*pbVar26 * 8);
130: iVar19 = *(int *)(lVar7 + (ulong)*pbVar26 * 4);
131: *puVar16 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
132: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
133: puVar16[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
134: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
135: puVar16[3] = 0xff;
136: puVar16[2] = uVar11;
137: bVar2 = pbVar24[1];
138: puVar16[4] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
139: puVar16[5] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
140: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
141: puVar16[7] = 0xff;
142: puVar16[6] = uVar11;
143: bVar2 = *pbVar25;
144: *puVar23 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
145: puVar23[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
146: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
147: puVar23[3] = 0xff;
148: puVar23[2] = uVar11;
149: bVar2 = pbVar25[1];
150: puVar23[4] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
151: puVar23[5] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
152: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
153: puVar23[7] = 0xff;
154: puVar23[6] = uVar11;
155: pbVar13 = pbVar14;
156: puVar16 = puVar16 + 8;
157: puVar23 = puVar23 + 8;
158: pbVar24 = pbVar24 + 2;
159: pbVar25 = pbVar25 + 2;
160: pbVar26 = pbVar26 + 1;
161: } while (pbVar14 != pbVar17);
162: puStack144 = puStack144 + lVar1 * 8;
163: pbStack128 = pbStack128 + lVar1 * 2;
164: pbVar20 = pbVar20 + lVar1;
165: pbStack136 = pbStack136 + lVar1 * 2;
166: uVar21 = *(uint *)(param_1 + 0x88);
167: puVar18 = puVar18 + lVar1 * 8;
168: }
169: if ((uVar21 & 1) != 0) {
170: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
171: lVar6 = *(long *)(lVar8 + (ulong)*pbVar14 * 8);
172: lVar4 = *(long *)(lVar4 + (ulong)*pbVar20 * 8);
173: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
174: bVar2 = *pbStack128;
175: *puVar18 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
176: iVar12 = (int)((ulong)(lVar6 + lVar4) >> 0x10);
177: puVar18[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
178: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
179: puVar18[3] = 0xff;
180: puVar18[2] = uVar11;
181: bVar2 = *pbStack136;
182: *puStack144 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
183: puStack144[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
184: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
185: puStack144[3] = 0xff;
186: puStack144[2] = uVar11;
187: }
188: break;
189: case 8:
190: if (bVar27) {
191: lVar1 = (ulong)(uVar22 - 1) + 1;
192: pbVar17 = pbVar14 + lVar1;
193: pbVar13 = pbVar14;
194: puVar16 = puStack144;
195: puVar23 = puVar18;
196: pbVar24 = pbStack128;
197: pbVar25 = pbStack136;
198: pbVar26 = pbVar20;
199: do {
200: pbVar14 = pbVar13 + 1;
201: bVar2 = *pbVar24;
202: iVar3 = *(int *)(lVar6 + (ulong)*pbVar13 * 4);
203: lVar9 = *(long *)(lVar8 + (ulong)*pbVar13 * 8);
204: lVar10 = *(long *)(lVar4 + (ulong)*pbVar26 * 8);
205: iVar19 = *(int *)(lVar7 + (ulong)*pbVar26 * 4);
206: puVar23[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
207: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
208: puVar23[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
209: *puVar23 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
210: bVar2 = pbVar24[1];
211: puVar23[5] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
212: puVar23[4] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
213: puVar23[3] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
214: bVar2 = *pbVar25;
215: puVar16[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
216: puVar16[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
217: *puVar16 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
218: bVar2 = pbVar25[1];
219: puVar16[5] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
220: puVar16[4] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
221: puVar16[3] = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
222: pbVar13 = pbVar14;
223: puVar16 = puVar16 + 6;
224: puVar23 = puVar23 + 6;
225: pbVar24 = pbVar24 + 2;
226: pbVar25 = pbVar25 + 2;
227: pbVar26 = pbVar26 + 1;
228: } while (pbVar14 != pbVar17);
229: pbStack128 = pbStack128 + lVar1 * 2;
230: pbStack136 = pbStack136 + lVar1 * 2;
231: pbVar20 = pbVar20 + lVar1;
232: uVar21 = *(uint *)(param_1 + 0x88);
233: puStack144 = puStack144 + lVar1 * 6;
234: puVar18 = puVar18 + lVar1 * 6;
235: }
236: if ((uVar21 & 1) != 0) {
237: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
238: lVar6 = *(long *)(lVar8 + (ulong)*pbVar14 * 8);
239: lVar4 = *(long *)(lVar4 + (ulong)*pbVar20 * 8);
240: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
241: bVar2 = *pbStack128;
242: puVar18[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
243: iVar12 = (int)((ulong)(lVar6 + lVar4) >> 0x10);
244: puVar18[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
245: *puVar18 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
246: bVar2 = *pbStack136;
247: puStack144[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
248: puStack144[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
249: *puStack144 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
250: }
251: break;
252: case 9:
253: case 0xd:
254: if (bVar27) {
255: lVar1 = (ulong)(uVar22 - 1) + 1;
256: pbVar17 = pbVar20 + lVar1;
257: pbVar13 = pbVar20;
258: puVar16 = puVar18;
259: puVar23 = puStack144;
260: pbVar24 = pbStack128;
261: pbVar25 = pbStack136;
262: pbVar26 = pbVar14;
263: do {
264: pbVar20 = pbVar13 + 1;
265: bVar2 = *pbVar24;
266: iVar3 = *(int *)(lVar6 + (ulong)*pbVar26 * 4);
267: lVar9 = *(long *)(lVar8 + (ulong)*pbVar26 * 8);
268: lVar10 = *(long *)(lVar4 + (ulong)*pbVar13 * 8);
269: iVar19 = *(int *)(lVar7 + (ulong)*pbVar13 * 4);
270: puVar16[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
271: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
272: puVar16[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
273: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
274: puVar16[3] = 0xff;
275: *puVar16 = uVar11;
276: bVar2 = pbVar24[1];
277: puVar16[6] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
278: puVar16[5] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
279: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
280: puVar16[7] = 0xff;
281: puVar16[4] = uVar11;
282: bVar2 = *pbVar25;
283: puVar23[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
284: puVar23[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
285: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
286: puVar23[3] = 0xff;
287: *puVar23 = uVar11;
288: bVar2 = pbVar25[1];
289: puVar23[6] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
290: puVar23[5] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
291: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
292: puVar23[7] = 0xff;
293: puVar23[4] = uVar11;
294: pbVar13 = pbVar20;
295: puVar16 = puVar16 + 8;
296: puVar23 = puVar23 + 8;
297: pbVar24 = pbVar24 + 2;
298: pbVar25 = pbVar25 + 2;
299: pbVar26 = pbVar26 + 1;
300: } while (pbVar17 != pbVar20);
301: puStack144 = puStack144 + lVar1 * 8;
302: pbStack128 = pbStack128 + lVar1 * 2;
303: pbVar14 = pbVar14 + lVar1;
304: pbStack136 = pbStack136 + lVar1 * 2;
305: uVar21 = *(uint *)(param_1 + 0x88);
306: puVar18 = puVar18 + lVar1 * 8;
307: }
308: if ((uVar21 & 1) != 0) {
309: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
310: lVar6 = *(long *)(lVar8 + (ulong)*pbVar14 * 8);
311: lVar4 = *(long *)(lVar4 + (ulong)*pbVar20 * 8);
312: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
313: bVar2 = *pbStack128;
314: puVar18[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
315: iVar12 = (int)((ulong)(lVar6 + lVar4) >> 0x10);
316: puVar18[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
317: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
318: puVar18[3] = 0xff;
319: *puVar18 = uVar11;
320: bVar2 = *pbStack136;
321: puStack144[2] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
322: puStack144[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
323: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
324: puStack144[3] = 0xff;
325: *puStack144 = uVar11;
326: }
327: break;
328: case 10:
329: case 0xe:
330: if (bVar27) {
331: lVar1 = (ulong)(uVar22 - 1) + 1;
332: pbVar17 = pbVar14 + lVar1;
333: pbVar13 = pbVar14;
334: puVar16 = puVar18;
335: puVar23 = puStack144;
336: pbVar24 = pbStack128;
337: pbVar25 = pbStack136;
338: pbVar26 = pbVar20;
339: do {
340: pbVar14 = pbVar13 + 1;
341: bVar2 = *pbVar24;
342: iVar3 = *(int *)(lVar6 + (ulong)*pbVar13 * 4);
343: lVar9 = *(long *)(lVar8 + (ulong)*pbVar13 * 8);
344: lVar10 = *(long *)(lVar4 + (ulong)*pbVar26 * 8);
345: iVar19 = *(int *)(lVar7 + (ulong)*pbVar26 * 4);
346: puVar16[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
347: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
348: puVar16[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
349: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
350: *puVar16 = 0xff;
351: puVar16[1] = uVar11;
352: bVar2 = pbVar24[1];
353: puVar16[7] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
354: puVar16[6] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
355: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
356: puVar16[4] = 0xff;
357: puVar16[5] = uVar11;
358: bVar2 = *pbVar25;
359: puVar23[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
360: puVar23[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
361: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
362: *puVar23 = 0xff;
363: puVar23[1] = uVar11;
364: bVar2 = pbVar25[1];
365: puVar23[7] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
366: puVar23[6] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
367: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
368: puVar23[4] = 0xff;
369: puVar23[5] = uVar11;
370: pbVar13 = pbVar14;
371: puVar16 = puVar16 + 8;
372: puVar23 = puVar23 + 8;
373: pbVar24 = pbVar24 + 2;
374: pbVar25 = pbVar25 + 2;
375: pbVar26 = pbVar26 + 1;
376: } while (pbVar17 != pbVar14);
377: puStack144 = puStack144 + lVar1 * 8;
378: pbStack128 = pbStack128 + lVar1 * 2;
379: pbVar20 = pbVar20 + lVar1;
380: pbStack136 = pbStack136 + lVar1 * 2;
381: uVar21 = *(uint *)(param_1 + 0x88);
382: puVar18 = puVar18 + lVar1 * 8;
383: }
384: if ((uVar21 & 1) != 0) {
385: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
386: lVar6 = *(long *)(lVar8 + (ulong)*pbVar14 * 8);
387: lVar4 = *(long *)(lVar4 + (ulong)*pbVar20 * 8);
388: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
389: bVar2 = *pbStack128;
390: puVar18[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
391: iVar12 = (int)((ulong)(lVar6 + lVar4) >> 0x10);
392: puVar18[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
393: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
394: *puVar18 = 0xff;
395: puVar18[1] = uVar11;
396: bVar2 = *pbStack136;
397: puStack144[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
398: puStack144[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
399: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
400: *puStack144 = 0xff;
401: puStack144[1] = uVar11;
402: }
403: break;
404: case 0xb:
405: case 0xf:
406: if (bVar27) {
407: lVar1 = (ulong)(uVar22 - 1) + 1;
408: pbVar17 = pbVar20 + lVar1;
409: pbVar13 = pbVar20;
410: puVar16 = puVar18;
411: puVar23 = puStack144;
412: pbVar24 = pbStack128;
413: pbVar25 = pbStack136;
414: pbVar26 = pbVar14;
415: do {
416: pbVar20 = pbVar13 + 1;
417: bVar2 = *pbVar24;
418: iVar3 = *(int *)(lVar6 + (ulong)*pbVar26 * 4);
419: lVar9 = *(long *)(lVar8 + (ulong)*pbVar26 * 8);
420: lVar10 = *(long *)(lVar4 + (ulong)*pbVar13 * 8);
421: iVar19 = *(int *)(lVar7 + (ulong)*pbVar13 * 4);
422: puVar16[1] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
423: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
424: puVar16[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
425: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
426: *puVar16 = 0xff;
427: puVar16[3] = uVar11;
428: bVar2 = pbVar24[1];
429: puVar16[5] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
430: puVar16[6] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
431: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
432: puVar16[4] = 0xff;
433: puVar16[7] = uVar11;
434: bVar2 = *pbVar25;
435: puVar23[1] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
436: puVar23[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
437: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
438: *puVar23 = 0xff;
439: puVar23[3] = uVar11;
440: bVar2 = pbVar25[1];
441: puVar23[5] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
442: puVar23[6] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
443: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
444: puVar23[4] = 0xff;
445: puVar23[7] = uVar11;
446: pbVar13 = pbVar20;
447: puVar16 = puVar16 + 8;
448: puVar23 = puVar23 + 8;
449: pbVar24 = pbVar24 + 2;
450: pbVar25 = pbVar25 + 2;
451: pbVar26 = pbVar26 + 1;
452: } while (pbVar17 != pbVar20);
453: puStack144 = puStack144 + lVar1 * 8;
454: pbStack128 = pbStack128 + lVar1 * 2;
455: pbVar14 = pbVar14 + lVar1;
456: pbStack136 = pbStack136 + lVar1 * 2;
457: uVar21 = *(uint *)(param_1 + 0x88);
458: puVar18 = puVar18 + lVar1 * 8;
459: }
460: if ((uVar21 & 1) != 0) {
461: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
462: lVar6 = *(long *)(lVar8 + (ulong)*pbVar14 * 8);
463: lVar4 = *(long *)(lVar4 + (ulong)*pbVar20 * 8);
464: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
465: bVar2 = *pbStack128;
466: puVar18[1] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
467: iVar12 = (int)((ulong)(lVar6 + lVar4) >> 0x10);
468: puVar18[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
469: uVar11 = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
470: *puVar18 = 0xff;
471: puVar18[3] = uVar11;
472: bVar2 = *pbStack136;
473: puStack144[1] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
474: puStack144[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
475: uVar11 = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
476: *puStack144 = 0xff;
477: puStack144[3] = uVar11;
478: }
479: }
480: }
481: else {
482: if (uVar21 >> 1 != 0) {
483: lVar1 = (ulong)(uVar22 - 1) + 1;
484: pbVar17 = pbVar20 + lVar1;
485: puVar16 = puStack144;
486: pbVar13 = pbVar20;
487: puVar23 = puVar18;
488: pbVar24 = pbStack128;
489: pbVar25 = pbStack136;
490: pbVar26 = pbVar14;
491: do {
492: pbVar20 = pbVar13 + 1;
493: bVar2 = *pbVar24;
494: iVar3 = *(int *)(lVar6 + (ulong)*pbVar26 * 4);
495: lVar9 = *(long *)(lVar8 + (ulong)*pbVar26 * 8);
496: lVar10 = *(long *)(lVar4 + (ulong)*pbVar13 * 8);
497: iVar19 = *(int *)(lVar7 + (ulong)*pbVar13 * 4);
498: *puVar23 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
499: iVar12 = (int)((ulong)(lVar9 + lVar10) >> 0x10);
500: puVar23[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
501: puVar23[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
502: bVar2 = pbVar24[1];
503: puVar23[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
504: puVar23[4] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
505: puVar23[5] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
506: bVar2 = *pbVar25;
507: *puVar16 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
508: puVar16[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
509: puVar16[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
510: bVar2 = pbVar25[1];
511: puVar16[3] = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
512: puVar16[4] = *(undefined *)(lVar5 + (int)(iVar12 + (uint)bVar2));
513: puVar16[5] = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
514: puVar16 = puVar16 + 6;
515: pbVar13 = pbVar20;
516: puVar23 = puVar23 + 6;
517: pbVar24 = pbVar24 + 2;
518: pbVar25 = pbVar25 + 2;
519: pbVar26 = pbVar26 + 1;
520: } while (pbVar17 != pbVar20);
521: pbStack128 = pbStack128 + lVar1 * 2;
522: pbStack136 = pbStack136 + lVar1 * 2;
523: pbVar14 = pbVar14 + lVar1;
524: uVar21 = *(uint *)(param_1 + 0x88);
525: puStack144 = puStack144 + lVar1 * 6;
526: puVar18 = puVar18 + lVar1 * 6;
527: }
528: if ((uVar21 & 1) != 0) {
529: iVar3 = *(int *)(lVar6 + (ulong)*pbVar14 * 4);
530: iVar19 = *(int *)(lVar7 + (ulong)*pbVar20 * 4);
531: bVar2 = *pbStack128;
532: iVar12 = (int)((ulong)(*(long *)(lVar8 + (ulong)*pbVar14 * 8) +
533: *(long *)(lVar4 + (ulong)*pbVar20 * 8)) >> 0x10);
534: *puVar18 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
535: puVar18[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
536: puVar18[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar19));
537: bVar2 = *pbStack136;
538: uVar11 = *(undefined *)(lVar5 + (int)(iVar3 + (uint)bVar2));
539: LAB_001397b4:
540: *puStack144 = uVar11;
541: puStack144[1] = *(undefined *)(lVar5 + (int)((uint)bVar2 + iVar12));
542: puStack144[2] = *(undefined *)(lVar5 + (int)(iVar19 + (uint)bVar2));
543: return;
544: }
545: }
546: return;
547: }
548: 

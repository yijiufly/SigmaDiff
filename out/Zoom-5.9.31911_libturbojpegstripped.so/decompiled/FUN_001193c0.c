1: 
2: undefined8 FUN_001193c0(long param_1,undefined8 *param_2)
3: 
4: {
5: short *psVar1;
6: long *plVar2;
7: byte *pbVar3;
8: byte bVar4;
9: undefined4 uVar5;
10: int iVar6;
11: long lVar7;
12: undefined8 uVar8;
13: undefined8 *puVar9;
14: undefined *puVar10;
15: code **ppcVar11;
16: int iVar12;
17: int iVar13;
18: int iVar14;
19: int iVar15;
20: long lVar16;
21: int iVar17;
22: byte *pbVar18;
23: uint uVar19;
24: uint uVar20;
25: ulong uVar21;
26: ulong uVar22;
27: bool bVar23;
28: short *psStack304;
29: uint uStack248;
30: ulong uStack232;
31: ulong uStack224;
32: short asStack208 [80];
33: 
34: lVar16 = (long)*(int *)(param_1 + 0x19c);
35: iVar13 = *(int *)(param_1 + 0x118);
36: lVar7 = *(long *)(param_1 + 0x1f0);
37: uVar5 = *(undefined4 *)(param_1 + 0x1a8);
38: iVar14 = (*(int *)(param_1 + 0x1a0) - *(int *)(param_1 + 0x19c)) + 1;
39: uVar8 = (*(undefined8 **)(param_1 + 0x28))[1];
40: *(undefined8 *)(lVar7 + 0x30) = **(undefined8 **)(param_1 + 0x28);
41: *(undefined8 *)(lVar7 + 0x38) = uVar8;
42: if ((iVar13 != 0) && (*(int *)(lVar7 + 0x80) == 0)) {
43: FUN_00118d20(lVar7,*(undefined4 *)(lVar7 + 0x84));
44: lVar16 = (long)*(int *)(param_1 + 0x19c);
45: }
46: iVar13 = (**(code **)(lVar7 + 0x20))
47: (*param_2,&DAT_0018b460 + lVar16 * 4,iVar14,uVar5,asStack208,&uStack232);
48: pbVar18 = (byte *)((ulong)*(uint *)(lVar7 + 0x70) + *(long *)(lVar7 + 0x78));
49: psStack304 = asStack208;
50: if (uStack232 != 0) {
51: uStack248 = 0;
52: uVar22 = 0;
53: LAB_00119494:
54: iVar12 = 0;
55: uVar21 = uStack232;
56: while ((uVar21 & 1) == 0) {
57: iVar12 = iVar12 + 1;
58: uVar21 = uVar21 >> 1 | 0x8000000000000000;
59: }
60: uStack248 = uStack248 + iVar12;
61: uStack224 = uStack224 >> ((byte)iVar12 & 0x3f);
62: psVar1 = psStack304 + iVar12;
63: if ((psVar1 <= asStack208 + iVar13) && (0xf < (int)uStack248)) {
64: do {
65: FUN_00118690(lVar7);
66: if (*(int *)(lVar7 + 0x28) == 0) {
67: lVar16 = *(long *)(lVar7 + 0x88 + (long)*(int *)(lVar7 + 0x68) * 8);
68: FUN_00118500(lVar7,*(undefined4 *)(lVar16 + 0x3c0),(int)*(char *)(lVar16 + 0x4f0));
69: iVar15 = *(int *)(lVar7 + 0x28);
70: if ((iVar15 == 0) && ((int)uVar22 != 0)) {
71: uVar19 = *(uint *)(lVar7 + 0x48);
72: pbVar3 = pbVar18 + (ulong)((int)uVar22 - 1) + 1;
73: do {
74: if (iVar15 == 0) {
75: uVar20 = uVar19 + 1;
76: uVar22 = (ulong)(*pbVar18 & 1) << (0x17U - (char)uVar19 & 0x3f) |
77: *(ulong *)(lVar7 + 0x40);
78: if (7 < (int)uVar20) {
79: do {
80: while( true ) {
81: uVar21 = uVar22;
82: puVar10 = *(undefined **)(lVar7 + 0x30);
83: uVar22 = uVar21 >> 0x10 & 0xff;
84: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
85: *puVar10 = (char)uVar22;
86: plVar2 = (long *)(lVar7 + 0x38);
87: *plVar2 = *plVar2 + -1;
88: if (*plVar2 == 0) {
89: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
90: iVar15 = (*(code *)puVar9[3])();
91: if (iVar15 == 0) {
92: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
93: *(undefined4 *)(ppcVar11 + 5) = 0x18;
94: (**ppcVar11)();
95: }
96: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
97: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
98: }
99: if ((int)uVar22 == 0xff) break;
100: LAB_00119599:
101: uVar20 = uVar20 - 8;
102: uVar22 = uVar21 << 8;
103: if ((int)uVar20 < 8) goto LAB_00119660;
104: }
105: puVar10 = *(undefined **)(lVar7 + 0x30);
106: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
107: *puVar10 = 0;
108: plVar2 = (long *)(lVar7 + 0x38);
109: *plVar2 = *plVar2 + -1;
110: if (*plVar2 != 0) goto LAB_00119599;
111: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
112: iVar15 = (*(code *)puVar9[3])();
113: if (iVar15 == 0) {
114: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
115: *(undefined4 *)(ppcVar11 + 5) = 0x18;
116: (**ppcVar11)();
117: }
118: uVar20 = uVar20 - 8;
119: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
120: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
121: uVar22 = uVar21 << 8;
122: } while (7 < (int)uVar20);
123: LAB_00119660:
124: uVar22 = uVar21 << 8;
125: uVar20 = uVar19 - 7 & 7;
126: }
127: *(ulong *)(lVar7 + 0x40) = uVar22;
128: *(uint *)(lVar7 + 0x48) = uVar20;
129: uVar19 = uVar20;
130: }
131: pbVar18 = pbVar18 + 1;
132: if (pbVar18 == pbVar3) break;
133: iVar15 = *(int *)(lVar7 + 0x28);
134: } while( true );
135: }
136: }
137: else {
138: plVar2 = (long *)(*(long *)(lVar7 + 0xa8 + (long)*(int *)(lVar7 + 0x68) * 8) + 0x780);
139: *plVar2 = *plVar2 + 1;
140: }
141: uStack248 = uStack248 - 0x10;
142: pbVar18 = *(byte **)(lVar7 + 0x78);
143: if ((int)uStack248 < 0x10) goto LAB_0011968c;
144: uVar22 = 0;
145: } while( true );
146: }
147: goto LAB_0011968e;
148: }
149: bVar23 = false;
150: iVar15 = 0;
151: uStack248 = 0;
152: LAB_001196d8:
153: if ((0 < (int)(uStack248 | (uint)((long)asStack208 + ((long)iVar14 * 2 - (long)psStack304) >> 1)))
154: || (bVar23)) {
155: uVar19 = iVar15 + *(int *)(lVar7 + 0x70);
156: iVar14 = *(int *)(lVar7 + 0x6c) + 1;
157: *(int *)(lVar7 + 0x6c) = iVar14;
158: *(uint *)(lVar7 + 0x70) = uVar19;
159: if ((iVar14 == 0x7fff) || (0x3a9 < uVar19)) {
160: FUN_00118690(lVar7);
161: }
162: }
163: puVar9 = *(undefined8 **)(param_1 + 0x28);
164: *puVar9 = *(undefined8 *)(lVar7 + 0x30);
165: puVar9[1] = *(undefined8 *)(lVar7 + 0x38);
166: iVar14 = *(int *)(param_1 + 0x118);
167: if (iVar14 != 0) {
168: iVar13 = *(int *)(lVar7 + 0x80);
169: if (*(int *)(lVar7 + 0x80) == 0) {
170: *(uint *)(lVar7 + 0x84) = *(int *)(lVar7 + 0x84) + 1U & 7;
171: iVar13 = iVar14;
172: }
173: *(int *)(lVar7 + 0x80) = iVar13 + -1;
174: }
175: return 1;
176: LAB_0011968c:
177: uVar22 = 0;
178: LAB_0011968e:
179: psStack304 = psVar1 + 1;
180: iVar15 = (int)uVar22;
181: if (1 < *psVar1) {
182: uVar21 = (ulong)(iVar15 + 1);
183: pbVar18[uVar22] = (byte)*psVar1 & 1;
184: goto LAB_001196c4;
185: }
186: FUN_00118690(lVar7);
187: iVar17 = uStack248 * 0x10 + 1;
188: if (*(int *)(lVar7 + 0x28) == 0) {
189: lVar16 = *(long *)(lVar7 + 0x88 + (long)*(int *)(lVar7 + 0x68) * 8);
190: iVar6 = *(int *)(lVar7 + 0x48);
191: bVar4 = *(byte *)(lVar16 + 0x400 + (long)iVar17);
192: uVar19 = *(uint *)(lVar16 + (long)iVar17 * 4);
193: if (bVar4 == 0) {
194: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
195: *(undefined4 *)(ppcVar11 + 5) = 0x28;
196: (**ppcVar11)();
197: if (*(int *)(lVar7 + 0x28) != 0) goto LAB_001197ab;
198: }
199: uVar20 = iVar6 + (char)bVar4;
200: uVar22 = (ulong)(uVar19 & (int)(1 << (bVar4 & 0x3f)) - 1U) << (0x18U - (char)uVar20 & 0x3f) |
201: *(ulong *)(lVar7 + 0x40);
202: uVar19 = uVar20;
203: if ((int)uVar20 < 8) {
204: uStack248 = 0;
205: }
206: else {
207: do {
208: while( true ) {
209: uVar21 = uVar22;
210: puVar10 = *(undefined **)(lVar7 + 0x30);
211: uVar22 = uVar21 >> 0x10 & 0xff;
212: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
213: *puVar10 = (char)uVar22;
214: plVar2 = (long *)(lVar7 + 0x38);
215: *plVar2 = *plVar2 + -1;
216: if (*plVar2 == 0) {
217: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
218: iVar17 = (*(code *)puVar9[3])();
219: if (iVar17 == 0) {
220: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
221: *(undefined4 *)(ppcVar11 + 5) = 0x18;
222: (**ppcVar11)();
223: }
224: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
225: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
226: }
227: if ((int)uVar22 == 0xff) break;
228: LAB_0011984e:
229: uVar19 = uVar19 - 8;
230: uVar22 = uVar21 << 8;
231: if ((int)uVar19 < 8) goto LAB_00119904;
232: }
233: puVar10 = *(undefined **)(lVar7 + 0x30);
234: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
235: *puVar10 = 0;
236: plVar2 = (long *)(lVar7 + 0x38);
237: *plVar2 = *plVar2 + -1;
238: if (*plVar2 != 0) goto LAB_0011984e;
239: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
240: iVar17 = (*(code *)puVar9[3])();
241: if (iVar17 == 0) {
242: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
243: *(undefined4 *)(ppcVar11 + 5) = 0x18;
244: (**ppcVar11)();
245: }
246: uVar19 = uVar19 - 8;
247: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
248: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
249: uVar22 = uVar21 << 8;
250: } while (7 < (int)uVar19);
251: LAB_00119904:
252: uVar22 = uVar21 << 8;
253: uStack248 = *(int *)(lVar7 + 0x28);
254: uVar20 = uVar20 & 7;
255: }
256: *(ulong *)(lVar7 + 0x40) = uVar22;
257: *(uint *)(lVar7 + 0x48) = uVar20;
258: if (uStack248 == 0) {
259: uVar19 = uVar20 + 1;
260: uVar22 = (ulong)((uint)uStack224 & 1) << (0x17U - (char)uVar20 & 0x3f) |
261: *(ulong *)(lVar7 + 0x40);
262: if ((int)uVar19 < 8) {
263: *(ulong *)(lVar7 + 0x40) = uVar22;
264: *(uint *)(lVar7 + 0x48) = uVar19;
265: }
266: else {
267: do {
268: while( true ) {
269: uVar21 = uVar22;
270: puVar10 = *(undefined **)(lVar7 + 0x30);
271: uVar22 = uVar21 >> 0x10 & 0xff;
272: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
273: *puVar10 = (char)uVar22;
274: plVar2 = (long *)(lVar7 + 0x38);
275: *plVar2 = *plVar2 + -1;
276: if (*plVar2 == 0) {
277: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
278: iVar17 = (*(code *)puVar9[3])();
279: if (iVar17 == 0) {
280: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
281: *(undefined4 *)(ppcVar11 + 5) = 0x18;
282: (**ppcVar11)();
283: }
284: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
285: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
286: }
287: if ((int)uVar22 == 0xff) break;
288: LAB_00119964:
289: uVar19 = uVar19 - 8;
290: uVar22 = uVar21 << 8;
291: if ((int)uVar19 < 8) goto LAB_00119a29;
292: }
293: puVar10 = *(undefined **)(lVar7 + 0x30);
294: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
295: *puVar10 = 0;
296: plVar2 = (long *)(lVar7 + 0x38);
297: *plVar2 = *plVar2 + -1;
298: if (*plVar2 != 0) goto LAB_00119964;
299: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
300: iVar17 = (*(code *)puVar9[3])();
301: if (iVar17 == 0) {
302: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
303: *(undefined4 *)(ppcVar11 + 5) = 0x18;
304: (**ppcVar11)();
305: }
306: uVar19 = uVar19 - 8;
307: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
308: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
309: uVar22 = uVar21 << 8;
310: } while (7 < (int)uVar19);
311: LAB_00119a29:
312: *(ulong *)(lVar7 + 0x40) = uVar21 << 8;
313: uVar19 = uVar20 - 7 & 7;
314: *(uint *)(lVar7 + 0x48) = uVar19;
315: if (*(int *)(lVar7 + 0x28) != 0) goto LAB_001197ab;
316: }
317: if (iVar15 != 0) {
318: pbVar3 = pbVar18 + (ulong)(iVar15 - 1) + 1;
319: do {
320: if (uStack248 == 0) {
321: uVar20 = uVar19 + 1;
322: uVar22 = (ulong)(*pbVar18 & 1) << (0x17U - (char)uVar19 & 0x3f) |
323: *(ulong *)(lVar7 + 0x40);
324: if (7 < (int)uVar20) {
325: do {
326: while( true ) {
327: uVar21 = uVar22;
328: puVar10 = *(undefined **)(lVar7 + 0x30);
329: uVar22 = uVar21 >> 0x10 & 0xff;
330: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
331: *puVar10 = (char)uVar22;
332: plVar2 = (long *)(lVar7 + 0x38);
333: *plVar2 = *plVar2 + -1;
334: if (*plVar2 == 0) {
335: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
336: iVar15 = (*(code *)puVar9[3])();
337: if (iVar15 == 0) {
338: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
339: *(undefined4 *)(ppcVar11 + 5) = 0x18;
340: (**ppcVar11)();
341: }
342: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
343: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
344: }
345: if ((int)uVar22 == 0xff) break;
346: LAB_00119aa9:
347: uVar20 = uVar20 - 8;
348: uVar22 = uVar21 << 8;
349: if ((int)uVar20 < 8) goto LAB_00119b67;
350: }
351: puVar10 = *(undefined **)(lVar7 + 0x30);
352: *(undefined **)(lVar7 + 0x30) = puVar10 + 1;
353: *puVar10 = 0;
354: plVar2 = (long *)(lVar7 + 0x38);
355: *plVar2 = *plVar2 + -1;
356: if (*plVar2 != 0) goto LAB_00119aa9;
357: puVar9 = *(undefined8 **)(*(long *)(lVar7 + 0x50) + 0x28);
358: iVar15 = (*(code *)puVar9[3])();
359: if (iVar15 == 0) {
360: ppcVar11 = (code **)**(code ***)(lVar7 + 0x50);
361: *(undefined4 *)(ppcVar11 + 5) = 0x18;
362: (**ppcVar11)();
363: }
364: uVar20 = uVar20 - 8;
365: *(undefined8 *)(lVar7 + 0x30) = *puVar9;
366: *(undefined8 *)(lVar7 + 0x38) = puVar9[1];
367: uVar22 = uVar21 << 8;
368: } while (7 < (int)uVar20);
369: LAB_00119b67:
370: uVar22 = uVar21 << 8;
371: uVar20 = uVar19 - 7 & 7;
372: }
373: *(ulong *)(lVar7 + 0x40) = uVar22;
374: *(uint *)(lVar7 + 0x48) = uVar20;
375: uVar19 = uVar20;
376: }
377: pbVar18 = pbVar18 + 1;
378: if (pbVar18 == pbVar3) break;
379: uStack248 = *(int *)(lVar7 + 0x28);
380: } while( true );
381: }
382: }
383: }
384: else {
385: plVar2 = (long *)(*(long *)(lVar7 + 0xa8 + (long)*(int *)(lVar7 + 0x68) * 8) + (long)iVar17 * 8)
386: ;
387: *plVar2 = *plVar2 + 1;
388: }
389: LAB_001197ab:
390: uVar21 = 0;
391: pbVar18 = *(byte **)(lVar7 + 0x78);
392: uStack248 = 0;
393: LAB_001196c4:
394: iVar15 = (int)uVar21;
395: uStack224 = uStack224 >> 1;
396: uStack232 = (uStack232 >> ((byte)iVar12 & 0x3f)) >> 1;
397: uVar22 = uVar21;
398: if (uStack232 == 0) goto code_r0x001196cd;
399: goto LAB_00119494;
400: code_r0x001196cd:
401: bVar23 = iVar15 != 0;
402: goto LAB_001196d8;
403: }
404: 

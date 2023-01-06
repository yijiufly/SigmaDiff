1: 
2: /* WARNING: Type propagation algorithm not settling */
3: /* WARNING: Could not reconcile some variable overlaps */
4: 
5: void FUN_0014bde0(long param_1,long param_2,long param_3,uint *param_4)
6: 
7: {
8: short sVar1;
9: uint uVar2;
10: uint uVar3;
11: long lVar4;
12: ushort uVar5;
13: ulong uVar6;
14: ulong uVar7;
15: ulong uVar8;
16: ulong uVar9;
17: uint6 uVar10;
18: short sVar11;
19: undefined2 uVar12;
20: short sVar13;
21: unkbyte10 Var14;
22: undefined *puVar15;
23: int iVar16;
24: long lVar17;
25: long lVar18;
26: undefined2 *puVar19;
27: ulong uVar20;
28: undefined (*pauVar21) [16];
29: long lVar22;
30: long *plVar23;
31: undefined (*pauVar24) [16];
32: uint uVar25;
33: int iVar26;
34: uint uVar27;
35: undefined2 *puVar28;
36: undefined2 *puVar29;
37: long *plVar30;
38: undefined2 *puVar31;
39: undefined (*pauVar32) [16];
40: int iVar33;
41: uint uVar34;
42: uint uVar35;
43: uint uVar36;
44: int iVar37;
45: undefined2 *puVar38;
46: uint uVar39;
47: uint uVar40;
48: int iVar41;
49: int iVar42;
50: int iVar43;
51: long lVar44;
52: undefined2 *puVar45;
53: uint uVar46;
54: uint uVar47;
55: long lVar48;
56: long lVar49;
57: uint uVar50;
58: long lVar51;
59: short sVar53;
60: undefined2 uVar54;
61: undefined2 uVar55;
62: undefined2 uVar56;
63: undefined2 uVar57;
64: undefined2 uVar58;
65: undefined2 uVar59;
66: undefined2 uVar60;
67: undefined2 uVar61;
68: undefined2 uVar62;
69: undefined2 uVar63;
70: undefined2 uVar64;
71: undefined2 uVar65;
72: undefined2 uVar66;
73: undefined auVar52 [16];
74: undefined2 uVar67;
75: undefined2 uVar68;
76: undefined2 uVar69;
77: undefined2 uVar73;
78: undefined2 uVar75;
79: undefined2 uVar76;
80: short sVar78;
81: undefined2 uVar79;
82: undefined auVar70 [16];
83: ulong uVar80;
84: undefined auVar71 [16];
85: undefined2 uVar83;
86: undefined2 uVar84;
87: undefined auVar81 [16];
88: undefined auVar82 [16];
89: undefined2 uVar85;
90: undefined2 uVar86;
91: undefined2 uVar87;
92: undefined2 uVar88;
93: short sVar89;
94: undefined2 uVar90;
95: ulong uVar91;
96: undefined2 uVar93;
97: undefined2 uVar94;
98: undefined auVar92 [16];
99: short sVar95;
100: undefined2 uVar96;
101: undefined2 uVar99;
102: undefined2 uVar100;
103: short sVar101;
104: undefined2 uVar102;
105: short sVar103;
106: short sVar104;
107: undefined2 uVar105;
108: undefined auVar97 [16];
109: undefined auVar98 [16];
110: undefined2 uVar107;
111: undefined2 uVar108;
112: uint6 uVar109;
113: undefined auVar106 [16];
114: undefined2 uVar111;
115: undefined2 uVar112;
116: uint6 uVar114;
117: undefined8 uVar113;
118: undefined auVar110 [16];
119: undefined2 uVar117;
120: undefined2 uVar118;
121: short sVar119;
122: undefined2 uVar120;
123: short sVar121;
124: undefined2 uVar122;
125: undefined auVar115 [16];
126: undefined auVar116 [16];
127: short sVar124;
128: short sVar125;
129: undefined2 uVar126;
130: undefined2 uVar127;
131: undefined auVar123 [16];
132: short sVar128;
133: undefined auStack280 [32];
134: undefined auStack248 [32];
135: undefined auStack216 [8];
136: undefined8 uStack208;
137: long lStack200;
138: long lStack192;
139: undefined auStack184 [16];
140: undefined auStack168 [16];
141: undefined auStack152 [32];
142: ulong uStack120;
143: undefined2 uVar72;
144: undefined2 uVar74;
145: short sVar77;
146: 
147: lVar51 = *(long *)(param_4 + 0x10);
148: if (*param_4 < 8) {
149: switch(*param_4) {
150: case 0:
151: if (*(long *)(param_4 + 0x14) != 0) {
152: uVar2 = param_4[0x15];
153: uVar3 = param_4[0x14];
154: iVar37 = *(int *)(param_2 + 0x4c);
155: if (0 < iVar37) {
156: lVar49 = 0;
157: do {
158: lVar22 = lVar49 * 0x60 + *(long *)(param_2 + 0x58);
159: iVar16 = *(int *)(lVar22 + 0xc);
160: iVar43 = *(int *)(lVar22 + 8);
161: if (*(int *)(lVar22 + 0x20) != 0) {
162: uVar27 = 0;
163: do {
164: lVar17 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
165: (param_1,*(undefined8 *)(lVar51 + lVar49 * 8),uVar27);
166: lVar18 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
167: (param_1,*(undefined8 *)(param_3 + lVar49 * 8),
168: uVar2 * iVar16 + uVar27);
169: iVar37 = *(int *)(lVar22 + 0xc);
170: if (0 < iVar37) {
171: lVar44 = 0;
172: do {
173: FUN_0013beb0((ulong)(uVar3 * iVar43) * 0x80 + *(long *)(lVar18 + lVar44 * 8),
174: *(undefined8 *)(lVar17 + lVar44 * 8),*(undefined4 *)(lVar22 + 0x1c)
175: );
176: iVar37 = *(int *)(lVar22 + 0xc);
177: iVar26 = (int)lVar44;
178: lVar44 = lVar44 + 1;
179: } while (iVar26 + 1 < iVar37);
180: }
181: uVar27 = uVar27 + iVar37;
182: } while (uVar27 < *(uint *)(lVar22 + 0x20));
183: iVar37 = *(int *)(param_2 + 0x4c);
184: }
185: iVar16 = (int)lVar49;
186: lVar49 = lVar49 + 1;
187: } while (iVar16 + 1 < iVar37);
188: }
189: }
190: break;
191: case 1:
192: uVar2 = param_4[0x15];
193: if ((uVar2 == 0) && (param_4[5] == 0)) {
194: uVar2 = param_4[0x14];
195: iVar37 = *(int *)(param_2 + 0x138);
196: uVar3 = *(uint *)(param_1 + 0x88);
197: iVar16 = *(int *)(param_2 + 0x4c);
198: if (0 < iVar16) {
199: lVar51 = 0;
200: do {
201: lVar49 = lVar51 * 0x60 + *(long *)(param_2 + 0x58);
202: uVar34 = (uVar3 / (uint)(iVar37 * 8)) * *(int *)(lVar49 + 8);
203: uVar27 = *(int *)(lVar49 + 8) * uVar2;
204: if (*(int *)(lVar49 + 0x20) != 0) {
205: uVar39 = 0;
206: do {
207: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
208: (0,param_1,*(undefined8 *)(param_3 + lVar51 * 8),uVar39)
209: ;
210: iVar16 = *(int *)(lVar49 + 0xc);
211: if (0 < iVar16) {
212: iVar43 = 0;
213: do {
214: if (uVar34 != 0) {
215: lVar22 = *plVar23;
216: uVar20 = 0;
217: do {
218: while( true ) {
219: iVar26 = (int)uVar20;
220: pauVar24 = (undefined (*) [16])(uVar20 * 0x80 + lVar22);
221: pauVar21 = (undefined (*) [16])
222: ((ulong)((uVar34 - 1) - iVar26) * 0x80 + lVar22);
223: if ((pauVar21[2] <= pauVar24) || (pauVar24[2] <= pauVar21)) break;
224: pauVar32 = pauVar21;
225: do {
226: uVar75 = *(undefined2 *)*pauVar24;
227: puVar15 = *pauVar32;
228: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
229: *(undefined2 *)*pauVar32 = uVar75;
230: sVar1 = *(short *)(*pauVar24 + 2);
231: *(short *)(*pauVar24 + 2) = -*(short *)(*pauVar32 + 2);
232: *(short *)(*pauVar32 + 2) = -sVar1;
233: pauVar32 = (undefined (*) [16])(puVar15 + 4);
234: pauVar24 = (undefined (*) [16])(*pauVar24 + 4);
235: } while (pauVar21[8] != (undefined (*) [16])(puVar15 + 4));
236: uVar20 = (ulong)(iVar26 + 1U);
237: if (uVar34 <= (iVar26 + 1U) * 2) goto code_r0x0014ea7b;
238: }
239: auVar71 = *pauVar21;
240: uVar20 = (ulong)(iVar26 + 1U);
241: uVar75 = *(undefined2 *)(pauVar21[1] + 2);
242: uVar54 = *(undefined2 *)(pauVar21[1] + 4);
243: sVar11 = *(short *)(pauVar21[1] + 6);
244: uVar55 = *(undefined2 *)(pauVar21[1] + 8);
245: uVar12 = *(undefined2 *)(pauVar21[1] + 0xc);
246: sVar13 = *(short *)(pauVar21[1] + 0xe);
247: sVar89 = SUB162(auVar71 >> 0x30,0);
248: uVar87 = SUB162(auVar71 >> 0x20,0);
249: uVar64 = SUB162(auVar71 >> 0x10,0);
250: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
251: SUB164(CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(
252: auVar71,0))) >> 0x60,0),
253: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
254: CONCAT28(uVar87,SUB168(auVar71,0))) >> 0x40,0),
255: uVar75),uVar64)) << 0x20;
256: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
257: CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(auVar71,
258: 0))) >> 0x60,0),
259: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
260: CONCAT28(uVar87,SUB168(auVar71,0))) >> 0x40,0),
261: uVar75)) << 0x30 &
262: (undefined  [16])0xffffffff00000000;
263: auVar52 = *pauVar24;
264: uVar86 = SUB162(auVar71 >> 0x50,0);
265: uVar73 = *(undefined2 *)pauVar24[1];
266: uVar72 = *(undefined2 *)(pauVar24[1] + 2);
267: uVar74 = *(undefined2 *)(pauVar24[1] + 4);
268: sVar77 = *(short *)(pauVar24[1] + 6);
269: uVar83 = *(undefined2 *)(pauVar24[1] + 8);
270: uVar62 = *(undefined2 *)(pauVar24[1] + 10);
271: uVar99 = *(undefined2 *)(pauVar24[1] + 0xc);
272: sVar53 = *(short *)(pauVar24[1] + 0xe);
273: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
274: CONCAT214(*(undefined2 *)(pauVar21[1] + 10),
275: CONCAT212(SUB162(auVar81 >> 0x30,0),
276: SUB1612(auVar81,0))) >> 0x60,0
277: ),CONCAT210(uVar86,SUB1610(auVar81,0))) >> 0x50,0)
278: ,CONCAT28(uVar64,SUB168(auVar81,0))) >> 0x40,0),
279: uVar55)) << 0x30;
280: auVar81 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
281: CONCAT214(*(undefined2 *)(pauVar21[1] + 10),
282: CONCAT212(uVar75,SUB1612(auVar70,0))) >>
283: 0x60,0),CONCAT210(uVar86,SUB1610(auVar70,0))) >>
284: 0x50,0),CONCAT28(uVar64,SUB168(auVar70,0))) >>
285: 0x40,0),uVar55)) << 0x30 &
286: (undefined  [16])0xffffffff00000000;
287: sVar78 = SUB162(auVar52 >> 0x30,0);
288: uVar75 = SUB162(auVar52 >> 0x20,0);
289: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
290: CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(auVar52,
291: 0))) >> 0x60,0),
292: CONCAT210(uVar74,SUB1610(auVar52,0))) >> 0x50,0),
293: CONCAT28(uVar75,SUB168(auVar52,0))) >> 0x40,0),
294: uVar72)) << 0x30 &
295: (undefined  [16])0xffffffff00000000;
296: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar87)) &
297: 0xffff0000;
298: auVar81 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
299: CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212(uVar55
300: ,SUB1612(auVar81,0))) >> 0x60,0),
301: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
302: CONCAT28(*(undefined2 *)pauVar21[1],
303: SUB168(auVar81,0))) >> 0x40,0),
304: (uVar6 >> 0x10) << 0x30) >> 0x20,0) &
305: SUB1612((undefined  [16])0xffff000000000000 >>
306: 0x20,0),uVar87)) << 0x10;
307: uVar64 = SUB162(auVar52 >> 0x50,0);
308: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
309: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
310: uVar87 = SUB162(auVar52 >> 0x10,0);
311: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
312: SUB164(CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(
313: auVar52,0))) >> 0x60,0),
314: CONCAT210(uVar74,SUB1610(auVar52,0))) >> 0x50,0),
315: CONCAT28(uVar75,SUB168(auVar52,0))) >> 0x40,0),
316: uVar72),uVar87)) << 0x20;
317: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
318: CONCAT214(uVar62,CONCAT212(uVar72,SUB1612(auVar70,
319: 0))) >> 0x60,0),
320: CONCAT210(uVar64,SUB1610(auVar70,0))) >> 0x50,0),
321: CONCAT28(uVar87,SUB168(auVar70,0))) >> 0x40,0),
322: uVar83)) << 0x30 &
323: (undefined  [16])0xffffffff00000000;
324: *(undefined2 *)pauVar24[1] = *(undefined2 *)pauVar21[1];
325: *(short *)(pauVar24[1] + 2) = -SUB162(auVar82 >> 0x60,0);
326: *(undefined2 *)(pauVar24[1] + 4) = uVar54;
327: *(short *)(pauVar24[1] + 6) = -sVar11;
328: *(undefined2 *)(pauVar24[1] + 8) = uVar55;
329: *(short *)(pauVar24[1] + 10) = -SUB162(auVar82 >> 0x70,0);
330: *(undefined2 *)(pauVar24[1] + 0xc) = uVar12;
331: *(short *)(pauVar24[1] + 0xe) = -sVar13;
332: uVar7 = (ulong)CONCAT24(uVar74,CONCAT22(SUB162(auVar52 >> 0x60,0),uVar75)) &
333: 0xffff0000;
334: auVar70 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
335: CONCAT412(SUB164(CONCAT214(uVar99,CONCAT212(uVar83
336: ,SUB1612(auVar70,0))) >> 0x60,0),
337: CONCAT210(uVar74,SUB1610(auVar70,0))) >> 0x50,0),
338: CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
339: (uVar7 >> 0x10) << 0x30) >> 0x20,0) &
340: SUB1612((undefined  [16])0xffff000000000000 >>
341: 0x20,0),uVar75)) << 0x10;
342: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
343: CONCAT214(uVar62,CONCAT212(SUB162(auVar92 >> 0x30,
344: 0),
345: SUB1612(auVar92,0))) >>
346: 0x60,0),CONCAT210(uVar64,SUB1610(auVar92,0))) >>
347: 0x50,0),CONCAT28(uVar87,SUB168(auVar92,0))) >>
348: 0x40,0),uVar83)) << 0x30;
349: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
350: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
351: >> 0x70,0),
352: CONCAT212((short)(uVar6 >> 0x10),
353: SUB1612(auVar81,0))) >> 0x60,0),
354: CONCAT210(sVar1,SUB1610(auVar81,0))) >> 0x50,0),
355: CONCAT28(SUB162(auVar71 >> 0x40,0),
356: SUB168(auVar81,0))) >> 0x40,0),
357: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar89,uVar5)) &
358: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
359: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
360: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
361: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
362: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
363: uVar75 = *(undefined2 *)pauVar21[3];
364: uVar54 = *(undefined2 *)(pauVar21[3] + 2);
365: uVar55 = *(undefined2 *)(pauVar21[3] + 4);
366: sVar11 = *(short *)(pauVar21[3] + 6);
367: uVar12 = *(undefined2 *)(pauVar21[3] + 8);
368: uVar72 = *(undefined2 *)(pauVar21[3] + 10);
369: uVar62 = *(undefined2 *)(pauVar21[3] + 0xc);
370: sVar13 = *(short *)(pauVar21[3] + 0xe);
371: *pauVar21 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
372: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar52 
373: >> 0x70,0),
374: CONCAT212((short)(uVar7 >> 0x10),
375: SUB1612(auVar70,0))) >> 0x60,0),
376: CONCAT210(sVar1,SUB1610(auVar70,0))) >> 0x50,0),
377: CONCAT28(SUB162(auVar52 >> 0x40,0),
378: SUB168(auVar70,0))) >> 0x40,0),
379: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar78,uVar5)) &
380: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
381: (SUB166(auVar70,0) >> 0x10) << 0x20) >> 0x20,0),
382: SUB164(auVar52,0) & 0xffff | (uint)uVar5 << 0x10);
383: *(undefined2 *)pauVar21[1] = uVar73;
384: *(short *)(pauVar21[1] + 2) = -SUB162(auVar82 >> 0x60,0);
385: *(undefined2 *)(pauVar21[1] + 4) = uVar74;
386: *(short *)(pauVar21[1] + 6) = -sVar77;
387: *(undefined2 *)(pauVar21[1] + 8) = uVar83;
388: *(short *)(pauVar21[1] + 10) = -SUB162(auVar82 >> 0x70,0);
389: *(undefined2 *)(pauVar21[1] + 0xc) = uVar99;
390: *(short *)(pauVar21[1] + 0xe) = -sVar53;
391: auVar71 = pauVar21[2];
392: sVar89 = SUB162(auVar71 >> 0x30,0);
393: uVar88 = SUB162(auVar71 >> 0x20,0);
394: uVar86 = SUB162(auVar71 >> 0x10,0);
395: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
396: SUB164(CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(
397: auVar71,0))) >> 0x60,0),
398: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
399: CONCAT28(uVar88,SUB168(auVar71,0))) >> 0x40,0),
400: uVar54),uVar86)) << 0x20;
401: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
402: CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(auVar71,
403: 0))) >> 0x60,0),
404: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
405: CONCAT28(uVar88,SUB168(auVar71,0))) >> 0x40,0),
406: uVar54)) << 0x30 &
407: (undefined  [16])0xffffffff00000000;
408: uVar56 = SUB162(auVar71 >> 0x50,0);
409: auVar52 = pauVar24[2];
410: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
411: CONCAT214(uVar72,CONCAT212(SUB162(auVar81 >> 0x30,
412: 0),
413: SUB1612(auVar81,0))) >>
414: 0x60,0),CONCAT210(uVar56,SUB1610(auVar81,0))) >>
415: 0x50,0),CONCAT28(uVar86,SUB168(auVar81,0))) >>
416: 0x40,0),uVar12)) << 0x30;
417: uVar73 = *(undefined2 *)pauVar24[3];
418: uVar74 = *(undefined2 *)(pauVar24[3] + 2);
419: uVar83 = *(undefined2 *)(pauVar24[3] + 4);
420: sVar77 = *(short *)(pauVar24[3] + 6);
421: uVar99 = *(undefined2 *)(pauVar24[3] + 8);
422: uVar64 = *(undefined2 *)(pauVar24[3] + 10);
423: uVar87 = *(undefined2 *)(pauVar24[3] + 0xc);
424: sVar53 = *(short *)(pauVar24[3] + 0xe);
425: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
426: CONCAT214(uVar72,CONCAT212(uVar54,SUB1612(auVar70,
427: 0))) >> 0x60,0),
428: CONCAT210(uVar56,SUB1610(auVar70,0))) >> 0x50,0),
429: CONCAT28(uVar86,SUB168(auVar70,0))) >> 0x40,0),
430: uVar12)) << 0x30 &
431: (undefined  [16])0xffffffff00000000;
432: uVar6 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar88)) &
433: 0xffff0000;
434: auVar81 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
435: CONCAT412(SUB164(CONCAT214(uVar62,CONCAT212(uVar12
436: ,SUB1612(auVar70,0))) >> 0x60,0),
437: CONCAT210(uVar55,SUB1610(auVar70,0))) >> 0x50,0),
438: CONCAT28(uVar75,SUB168(auVar70,0))) >> 0x40,0),
439: (uVar6 >> 0x10) << 0x30) >> 0x20,0) &
440: SUB1612((undefined  [16])0xffff000000000000 >>
441: 0x20,0),uVar88)) << 0x10;
442: sVar78 = SUB162(auVar52 >> 0x30,0);
443: uVar54 = SUB162(auVar52 >> 0x20,0);
444: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
445: CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(auVar52,
446: 0))) >> 0x60,0),
447: CONCAT210(uVar83,SUB1610(auVar52,0))) >> 0x50,0),
448: CONCAT28(uVar54,SUB168(auVar52,0))) >> 0x40,0),
449: uVar74)) << 0x30 &
450: (undefined  [16])0xffffffff00000000;
451: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
452: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
453: uVar72 = SUB162(auVar52 >> 0x50,0);
454: uVar86 = SUB162(auVar52 >> 0x10,0);
455: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
456: SUB164(CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(
457: auVar52,0))) >> 0x60,0),
458: CONCAT210(uVar83,SUB1610(auVar52,0))) >> 0x50,0),
459: CONCAT28(uVar54,SUB168(auVar52,0))) >> 0x40,0),
460: uVar74),uVar86)) << 0x20;
461: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
462: CONCAT214(uVar64,CONCAT212(uVar74,SUB1612(auVar70,
463: 0))) >> 0x60,0),
464: CONCAT210(uVar72,SUB1610(auVar70,0))) >> 0x50,0),
465: CONCAT28(uVar86,SUB168(auVar70,0))) >> 0x40,0),
466: uVar99)) << 0x30 &
467: (undefined  [16])0xffffffff00000000;
468: *(undefined2 *)pauVar24[3] = uVar75;
469: *(short *)(pauVar24[3] + 2) = -SUB162(auVar82 >> 0x60,0);
470: *(undefined2 *)(pauVar24[3] + 4) = uVar55;
471: *(short *)(pauVar24[3] + 6) = -sVar11;
472: *(undefined2 *)(pauVar24[3] + 8) = uVar12;
473: *(short *)(pauVar24[3] + 10) = -SUB162(auVar82 >> 0x70,0);
474: *(undefined2 *)(pauVar24[3] + 0xc) = uVar62;
475: *(short *)(pauVar24[3] + 0xe) = -sVar13;
476: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
477: CONCAT214(uVar64,CONCAT212(SUB162(auVar92 >> 0x30,
478: 0),
479: SUB1612(auVar92,0))) >>
480: 0x60,0),CONCAT210(uVar72,SUB1610(auVar92,0))) >>
481: 0x50,0),CONCAT28(uVar86,SUB168(auVar92,0))) >>
482: 0x40,0),uVar99)) << 0x30;
483: uVar7 = (ulong)CONCAT24(uVar83,CONCAT22(SUB162(auVar52 >> 0x60,0),uVar54)) &
484: 0xffff0000;
485: auVar70 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
486: CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212(uVar99
487: ,SUB1612(auVar70,0))) >> 0x60,0),
488: CONCAT210(uVar83,SUB1610(auVar70,0))) >> 0x50,0),
489: CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
490: (uVar7 >> 0x10) << 0x30) >> 0x20,0) &
491: SUB1612((undefined  [16])0xffff000000000000 >>
492: 0x20,0),uVar54)) << 0x10;
493: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
494: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
495: >> 0x70,0),
496: CONCAT212((short)(uVar6 >> 0x10),
497: SUB1612(auVar81,0))) >> 0x60,0),
498: CONCAT210(sVar1,SUB1610(auVar81,0))) >> 0x50,0),
499: CONCAT28(SUB162(auVar71 >> 0x40,0),
500: SUB168(auVar81,0))) >> 0x40,0),
501: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar89,uVar5)) &
502: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
503: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
504: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
505: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
506: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
507: uVar75 = *(undefined2 *)pauVar21[5];
508: uVar54 = *(undefined2 *)(pauVar21[5] + 2);
509: uVar55 = *(undefined2 *)(pauVar21[5] + 4);
510: sVar11 = *(short *)(pauVar21[5] + 6);
511: uVar12 = *(undefined2 *)(pauVar21[5] + 8);
512: uVar72 = *(undefined2 *)(pauVar21[5] + 10);
513: uVar74 = *(undefined2 *)(pauVar21[5] + 0xc);
514: sVar13 = *(short *)(pauVar21[5] + 0xe);
515: pauVar21[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
516: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar52 
517: >> 0x70,0),
518: CONCAT212((short)(uVar7 >> 0x10),
519: SUB1612(auVar70,0))) >> 0x60,0),
520: CONCAT210(sVar1,SUB1610(auVar70,0))) >> 0x50,0),
521: CONCAT28(SUB162(auVar52 >> 0x40,0),
522: SUB168(auVar70,0))) >> 0x40,0),
523: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar78,uVar5)) &
524: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
525: (SUB166(auVar70,0) >> 0x10) << 0x20) >> 0x20,0),
526: SUB164(auVar52,0) & 0xffff | (uint)uVar5 << 0x10);
527: *(undefined2 *)pauVar21[3] = uVar73;
528: *(short *)(pauVar21[3] + 2) = -SUB162(auVar82 >> 0x60,0);
529: *(undefined2 *)(pauVar21[3] + 4) = uVar83;
530: *(short *)(pauVar21[3] + 6) = -sVar77;
531: *(undefined2 *)(pauVar21[3] + 8) = uVar99;
532: *(short *)(pauVar21[3] + 10) = -SUB162(auVar82 >> 0x70,0);
533: *(undefined2 *)(pauVar21[3] + 0xc) = uVar87;
534: *(short *)(pauVar21[3] + 0xe) = -sVar53;
535: auVar71 = pauVar21[4];
536: sVar89 = SUB162(auVar71 >> 0x30,0);
537: uVar88 = SUB162(auVar71 >> 0x20,0);
538: uVar86 = SUB162(auVar71 >> 0x10,0);
539: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
540: SUB164(CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(
541: auVar71,0))) >> 0x60,0),
542: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
543: CONCAT28(uVar88,SUB168(auVar71,0))) >> 0x40,0),
544: uVar54),uVar86)) << 0x20;
545: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
546: CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(auVar71,
547: 0))) >> 0x60,0),
548: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
549: CONCAT28(uVar88,SUB168(auVar71,0))) >> 0x40,0),
550: uVar54)) << 0x30 &
551: (undefined  [16])0xffffffff00000000;
552: uVar56 = SUB162(auVar71 >> 0x50,0);
553: auVar52 = pauVar24[4];
554: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
555: CONCAT214(uVar72,CONCAT212(SUB162(auVar81 >> 0x30,
556: 0),
557: SUB1612(auVar81,0))) >>
558: 0x60,0),CONCAT210(uVar56,SUB1610(auVar81,0))) >>
559: 0x50,0),CONCAT28(uVar86,SUB168(auVar81,0))) >>
560: 0x40,0),uVar12)) << 0x30;
561: uVar73 = *(undefined2 *)pauVar24[5];
562: uVar83 = *(undefined2 *)(pauVar24[5] + 2);
563: uVar62 = *(undefined2 *)(pauVar24[5] + 4);
564: sVar77 = *(short *)(pauVar24[5] + 6);
565: uVar99 = *(undefined2 *)(pauVar24[5] + 8);
566: uVar64 = *(undefined2 *)(pauVar24[5] + 10);
567: uVar87 = *(undefined2 *)(pauVar24[5] + 0xc);
568: sVar53 = *(short *)(pauVar24[5] + 0xe);
569: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
570: CONCAT214(uVar72,CONCAT212(uVar54,SUB1612(auVar70,
571: 0))) >> 0x60,0),
572: CONCAT210(uVar56,SUB1610(auVar70,0))) >> 0x50,0),
573: CONCAT28(uVar86,SUB168(auVar70,0))) >> 0x40,0),
574: uVar12)) << 0x30 &
575: (undefined  [16])0xffffffff00000000;
576: uVar6 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar88)) &
577: 0xffff0000;
578: auVar81 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
579: CONCAT412(SUB164(CONCAT214(uVar74,CONCAT212(uVar12
580: ,SUB1612(auVar70,0))) >> 0x60,0),
581: CONCAT210(uVar55,SUB1610(auVar70,0))) >> 0x50,0),
582: CONCAT28(uVar75,SUB168(auVar70,0))) >> 0x40,0),
583: (uVar6 >> 0x10) << 0x30) >> 0x20,0) &
584: SUB1612((undefined  [16])0xffff000000000000 >>
585: 0x20,0),uVar88)) << 0x10;
586: sVar78 = SUB162(auVar52 >> 0x30,0);
587: uVar54 = SUB162(auVar52 >> 0x20,0);
588: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
589: CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(auVar52,
590: 0))) >> 0x60,0),
591: CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0),
592: CONCAT28(uVar54,SUB168(auVar52,0))) >> 0x40,0),
593: uVar83)) << 0x30 &
594: (undefined  [16])0xffffffff00000000;
595: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
596: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
597: uVar72 = SUB162(auVar52 >> 0x50,0);
598: uVar86 = SUB162(auVar52 >> 0x10,0);
599: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
600: SUB164(CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(
601: auVar52,0))) >> 0x60,0),
602: CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0),
603: CONCAT28(uVar54,SUB168(auVar52,0))) >> 0x40,0),
604: uVar83),uVar86)) << 0x20;
605: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
606: CONCAT214(uVar64,CONCAT212(uVar83,SUB1612(auVar70,
607: 0))) >> 0x60,0),
608: CONCAT210(uVar72,SUB1610(auVar70,0))) >> 0x50,0),
609: CONCAT28(uVar86,SUB168(auVar70,0))) >> 0x40,0),
610: uVar99)) << 0x30 &
611: (undefined  [16])0xffffffff00000000;
612: *(undefined2 *)pauVar24[5] = uVar75;
613: *(short *)(pauVar24[5] + 2) = -SUB162(auVar82 >> 0x60,0);
614: *(undefined2 *)(pauVar24[5] + 4) = uVar55;
615: *(short *)(pauVar24[5] + 6) = -sVar11;
616: *(undefined2 *)(pauVar24[5] + 8) = uVar12;
617: *(short *)(pauVar24[5] + 10) = -SUB162(auVar82 >> 0x70,0);
618: *(undefined2 *)(pauVar24[5] + 0xc) = uVar74;
619: *(short *)(pauVar24[5] + 0xe) = -sVar13;
620: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
621: CONCAT214(uVar64,CONCAT212(SUB162(auVar92 >> 0x30,
622: 0),
623: SUB1612(auVar92,0))) >>
624: 0x60,0),CONCAT210(uVar72,SUB1610(auVar92,0))) >>
625: 0x50,0),CONCAT28(uVar86,SUB168(auVar92,0))) >>
626: 0x40,0),uVar99)) << 0x30;
627: uVar7 = (ulong)CONCAT24(uVar62,CONCAT22(SUB162(auVar52 >> 0x60,0),uVar54)) &
628: 0xffff0000;
629: auVar70 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
630: CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212(uVar99
631: ,SUB1612(auVar70,0))) >> 0x60,0),
632: CONCAT210(uVar62,SUB1610(auVar70,0))) >> 0x50,0),
633: CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
634: (uVar7 >> 0x10) << 0x30) >> 0x20,0) &
635: SUB1612((undefined  [16])0xffff000000000000 >>
636: 0x20,0),uVar54)) << 0x10;
637: pauVar24[4] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
638: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
639: >> 0x70,0),
640: CONCAT212((short)(uVar6 >> 0x10),
641: SUB1612(auVar81,0))) >> 0x60,0),
642: CONCAT210(sVar1,SUB1610(auVar81,0))) >> 0x50,0),
643: CONCAT28(SUB162(auVar71 >> 0x40,0),
644: SUB168(auVar81,0))) >> 0x40,0),
645: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar89,uVar5)) &
646: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
647: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
648: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
649: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
650: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
651: uVar75 = *(undefined2 *)pauVar21[7];
652: uVar54 = *(undefined2 *)(pauVar21[7] + 2);
653: uVar55 = *(undefined2 *)(pauVar21[7] + 4);
654: sVar11 = *(short *)(pauVar21[7] + 6);
655: uVar12 = *(undefined2 *)(pauVar21[7] + 8);
656: uVar72 = *(undefined2 *)(pauVar21[7] + 10);
657: uVar74 = *(undefined2 *)(pauVar21[7] + 0xc);
658: sVar13 = *(short *)(pauVar21[7] + 0xe);
659: pauVar21[4] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
660: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar52 
661: >> 0x70,0),
662: CONCAT212((short)(uVar7 >> 0x10),
663: SUB1612(auVar70,0))) >> 0x60,0),
664: CONCAT210(sVar1,SUB1610(auVar70,0))) >> 0x50,0),
665: CONCAT28(SUB162(auVar52 >> 0x40,0),
666: SUB168(auVar70,0))) >> 0x40,0),
667: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar78,uVar5)) &
668: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
669: (SUB166(auVar70,0) >> 0x10) << 0x20) >> 0x20,0),
670: SUB164(auVar52,0) & 0xffff | (uint)uVar5 << 0x10);
671: *(undefined2 *)pauVar21[5] = uVar73;
672: *(short *)(pauVar21[5] + 2) = -SUB162(auVar82 >> 0x60,0);
673: *(undefined2 *)(pauVar21[5] + 4) = uVar62;
674: *(short *)(pauVar21[5] + 6) = -sVar77;
675: *(undefined2 *)(pauVar21[5] + 8) = uVar99;
676: *(short *)(pauVar21[5] + 10) = -SUB162(auVar82 >> 0x70,0);
677: *(undefined2 *)(pauVar21[5] + 0xc) = uVar87;
678: *(short *)(pauVar21[5] + 0xe) = -sVar53;
679: auVar71 = pauVar21[6];
680: sVar89 = SUB162(auVar71 >> 0x30,0);
681: uVar88 = SUB162(auVar71 >> 0x20,0);
682: uVar86 = SUB162(auVar71 >> 0x10,0);
683: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
684: SUB164(CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(
685: auVar71,0))) >> 0x60,0),
686: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
687: CONCAT28(uVar88,SUB168(auVar71,0))) >> 0x40,0),
688: uVar54),uVar86)) << 0x20;
689: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
690: CONCAT214(sVar11,CONCAT212(sVar89,SUB1612(auVar71,
691: 0))) >> 0x60,0),
692: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
693: CONCAT28(uVar88,SUB168(auVar71,0))) >> 0x40,0),
694: uVar54)) << 0x30 &
695: (undefined  [16])0xffffffff00000000;
696: uVar56 = SUB162(auVar71 >> 0x50,0);
697: auVar52 = pauVar24[6];
698: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
699: CONCAT214(uVar72,CONCAT212(SUB162(auVar81 >> 0x30,
700: 0),
701: SUB1612(auVar81,0))) >>
702: 0x60,0),CONCAT210(uVar56,SUB1610(auVar81,0))) >>
703: 0x50,0),CONCAT28(uVar86,SUB168(auVar81,0))) >>
704: 0x40,0),uVar12)) << 0x30;
705: uVar73 = *(undefined2 *)pauVar24[7];
706: uVar83 = *(undefined2 *)(pauVar24[7] + 2);
707: uVar62 = *(undefined2 *)(pauVar24[7] + 4);
708: sVar77 = *(short *)(pauVar24[7] + 6);
709: uVar99 = *(undefined2 *)(pauVar24[7] + 8);
710: uVar64 = *(undefined2 *)(pauVar24[7] + 10);
711: uVar87 = *(undefined2 *)(pauVar24[7] + 0xc);
712: sVar53 = *(short *)(pauVar24[7] + 0xe);
713: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
714: CONCAT214(uVar72,CONCAT212(uVar54,SUB1612(auVar70,
715: 0))) >> 0x60,0),
716: CONCAT210(uVar56,SUB1610(auVar70,0))) >> 0x50,0),
717: CONCAT28(uVar86,SUB168(auVar70,0))) >> 0x40,0),
718: uVar12)) << 0x30 &
719: (undefined  [16])0xffffffff00000000;
720: uVar6 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar88)) &
721: 0xffff0000;
722: auVar81 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
723: CONCAT412(SUB164(CONCAT214(uVar74,CONCAT212(uVar12
724: ,SUB1612(auVar70,0))) >> 0x60,0),
725: CONCAT210(uVar55,SUB1610(auVar70,0))) >> 0x50,0),
726: CONCAT28(uVar75,SUB168(auVar70,0))) >> 0x40,0),
727: (uVar6 >> 0x10) << 0x30) >> 0x20,0) &
728: SUB1612((undefined  [16])0xffff000000000000 >>
729: 0x20,0),uVar88)) << 0x10;
730: sVar78 = SUB162(auVar52 >> 0x30,0);
731: uVar54 = SUB162(auVar52 >> 0x20,0);
732: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
733: CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(auVar52,
734: 0))) >> 0x60,0),
735: CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0),
736: CONCAT28(uVar54,SUB168(auVar52,0))) >> 0x40,0),
737: uVar83)) << 0x30 &
738: (undefined  [16])0xffffffff00000000;
739: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
740: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
741: uVar72 = SUB162(auVar52 >> 0x50,0);
742: uVar86 = SUB162(auVar52 >> 0x10,0);
743: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
744: SUB164(CONCAT214(sVar77,CONCAT212(sVar78,SUB1612(
745: auVar52,0))) >> 0x60,0),
746: CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0),
747: CONCAT28(uVar54,SUB168(auVar52,0))) >> 0x40,0),
748: uVar83),uVar86)) << 0x20;
749: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
750: CONCAT214(uVar64,CONCAT212(uVar83,SUB1612(auVar70,
751: 0))) >> 0x60,0),
752: CONCAT210(uVar72,SUB1610(auVar70,0))) >> 0x50,0),
753: CONCAT28(uVar86,SUB168(auVar70,0))) >> 0x40,0),
754: uVar99)) << 0x30 &
755: (undefined  [16])0xffffffff00000000;
756: *(undefined2 *)pauVar24[7] = uVar75;
757: *(short *)(pauVar24[7] + 2) = -SUB162(auVar82 >> 0x60,0);
758: *(undefined2 *)(pauVar24[7] + 4) = uVar55;
759: *(short *)(pauVar24[7] + 6) = -sVar11;
760: *(undefined2 *)(pauVar24[7] + 8) = uVar12;
761: *(short *)(pauVar24[7] + 10) = -SUB162(auVar82 >> 0x70,0);
762: *(undefined2 *)(pauVar24[7] + 0xc) = uVar74;
763: *(short *)(pauVar24[7] + 0xe) = -sVar13;
764: uVar7 = (ulong)CONCAT24(uVar62,CONCAT22(SUB162(auVar52 >> 0x60,0),uVar54)) &
765: 0xffff0000;
766: auVar70 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
767: CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212(uVar99
768: ,SUB1612(auVar70,0))) >> 0x60,0),
769: CONCAT210(uVar62,SUB1610(auVar70,0))) >> 0x50,0),
770: CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
771: (uVar7 >> 0x10) << 0x30) >> 0x20,0) &
772: SUB1612((undefined  [16])0xffff000000000000 >>
773: 0x20,0),uVar54)) << 0x10;
774: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
775: CONCAT214(uVar64,CONCAT212(SUB162(auVar92 >> 0x30,
776: 0),
777: SUB1612(auVar92,0))) >>
778: 0x60,0),CONCAT210(uVar72,SUB1610(auVar92,0))) >>
779: 0x50,0),CONCAT28(uVar86,SUB168(auVar92,0))) >>
780: 0x40,0),uVar99)) << 0x30;
781: pauVar24[6] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
782: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
783: >> 0x70,0),
784: CONCAT212((short)(uVar6 >> 0x10),
785: SUB1612(auVar81,0))) >> 0x60,0),
786: CONCAT210(sVar1,SUB1610(auVar81,0))) >> 0x50,0),
787: CONCAT28(SUB162(auVar71 >> 0x40,0),
788: SUB168(auVar81,0))) >> 0x40,0),
789: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar89,uVar5)) &
790: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
791: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
792: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
793: uVar5 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
794: sVar1 = -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
795: pauVar21[6] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
796: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar52 
797: >> 0x70,0),
798: CONCAT212((short)(uVar7 >> 0x10),
799: SUB1612(auVar70,0))) >> 0x60,0),
800: CONCAT210(sVar1,SUB1610(auVar70,0))) >> 0x50,0),
801: CONCAT28(SUB162(auVar52 >> 0x40,0),
802: SUB168(auVar70,0))) >> 0x40,0),
803: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar78,uVar5)) &
804: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
805: (SUB166(auVar70,0) >> 0x10) << 0x20) >> 0x20,0),
806: SUB164(auVar52,0) & 0xffff | (uint)uVar5 << 0x10);
807: *(undefined2 *)pauVar21[7] = uVar73;
808: *(short *)(pauVar21[7] + 2) = -SUB162(auVar82 >> 0x60,0);
809: *(undefined2 *)(pauVar21[7] + 4) = uVar62;
810: *(short *)(pauVar21[7] + 6) = -sVar77;
811: *(undefined2 *)(pauVar21[7] + 8) = uVar99;
812: *(short *)(pauVar21[7] + 10) = -SUB162(auVar82 >> 0x70,0);
813: *(undefined2 *)(pauVar21[7] + 0xc) = uVar87;
814: *(short *)(pauVar21[7] + 0xe) = -sVar53;
815: } while ((iVar26 + 1U) * 2 < uVar34);
816: }
817: code_r0x0014ea7b:
818: if ((uVar27 != 0) && (*(int *)(lVar49 + 0x1c) != 0)) {
819: uVar35 = 0;
820: do {
821: FUN_0013beb0(0,*plVar23 + ((ulong)uVar35 + (ulong)uVar27) * 0x80,
822: (ulong)uVar35 * 0x80 + *plVar23,1);
823: uVar35 = uVar35 + 1;
824: } while (uVar35 < *(uint *)(lVar49 + 0x1c));
825: iVar16 = *(int *)(lVar49 + 0xc);
826: }
827: iVar43 = iVar43 + 1;
828: plVar23 = plVar23 + 1;
829: } while (iVar43 < iVar16);
830: }
831: uVar39 = uVar39 + iVar16;
832: } while (uVar39 < *(uint *)(lVar49 + 0x20));
833: iVar16 = *(int *)(param_2 + 0x4c);
834: }
835: iVar43 = (int)lVar51;
836: lVar51 = lVar51 + 1;
837: } while (iVar43 + 1 < iVar16);
838: }
839: }
840: else {
841: uVar3 = param_4[0x14];
842: iVar37 = *(int *)(param_2 + 0x138);
843: uVar27 = *(uint *)(param_1 + 0x88);
844: iVar16 = *(int *)(param_2 + 0x4c);
845: if (0 < iVar16) {
846: lVar49 = 0;
847: do {
848: lVar22 = lVar49 * 0x60 + *(long *)(param_2 + 0x58);
849: uVar34 = (uVar27 / (uint)(iVar37 * 8)) * *(int *)(lVar22 + 8);
850: uVar39 = *(int *)(lVar22 + 8) * uVar3;
851: iVar43 = *(int *)(lVar22 + 0xc);
852: if (*(int *)(lVar22 + 0x20) != 0) {
853: uVar35 = 0;
854: do {
855: lVar17 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
856: (param_1,*(undefined8 *)(lVar51 + lVar49 * 8),uVar35);
857: lVar18 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
858: (param_1,*(undefined8 *)(param_3 + lVar49 * 8),
859: uVar2 * iVar43 + uVar35);
860: iVar16 = *(int *)(lVar22 + 0xc);
861: if (0 < iVar16) {
862: uVar47 = *(uint *)(lVar22 + 0x1c);
863: lVar44 = 0;
864: do {
865: lVar48 = *(long *)(lVar17 + lVar44 * 8);
866: lVar4 = *(long *)(lVar18 + lVar44 * 8);
867: if (uVar47 != 0) {
868: uVar50 = 0;
869: do {
870: while (uVar34 <= uVar39 + uVar50) {
871: uVar20 = (ulong)uVar50;
872: uVar40 = uVar50 + 1;
873: uVar50 = uVar50 + 1;
874: FUN_0013beb0(lVar4 + (uVar20 + uVar39) * 0x80,uVar20 * 0x80 + lVar48,1);
875: uVar47 = *(uint *)(lVar22 + 0x1c);
876: if (uVar47 <= uVar40) goto code_r0x0014e59f;
877: }
878: pauVar24 = (undefined (*) [16])((ulong)uVar50 * 0x80 + lVar48);
879: pauVar21 = (undefined (*) [16])
880: ((ulong)(((uVar34 - uVar39) + -1) - uVar50) * 0x80 + lVar4);
881: if ((pauVar24 < pauVar21[2]) && (pauVar21 < pauVar24[2])) {
882: pauVar32 = pauVar21;
883: do {
884: puVar15 = *pauVar32;
885: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
886: *(short *)(*pauVar24 + 2) = -*(short *)(*pauVar32 + 2);
887: pauVar32 = (undefined (*) [16])(puVar15 + 4);
888: pauVar24 = (undefined (*) [16])(*pauVar24 + 4);
889: } while (pauVar21[8] != (undefined (*) [16])(puVar15 + 4));
890: }
891: else {
892: auVar71 = *pauVar21;
893: uVar75 = *(undefined2 *)(pauVar21[1] + 2);
894: uVar54 = *(undefined2 *)(pauVar21[1] + 4);
895: sVar11 = *(short *)(pauVar21[1] + 6);
896: uVar55 = *(undefined2 *)(pauVar21[1] + 8);
897: uVar12 = *(undefined2 *)(pauVar21[1] + 0xc);
898: sVar13 = *(short *)(pauVar21[1] + 0xe);
899: sVar77 = SUB162(auVar71 >> 0x30,0);
900: uVar72 = SUB162(auVar71 >> 0x20,0);
901: uVar73 = SUB162(auVar71 >> 0x10,0);
902: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
903: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
904: auVar71,0))) >> 0x60,0),
905: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
906: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
907: uVar75),uVar73)) << 0x20;
908: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
909: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
910: 0))) >> 0x60,0),
911: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
912: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
913: uVar75)) << 0x30 &
914: (undefined  [16])0xffffffff00000000;
915: uVar74 = SUB162(auVar71 >> 0x50,0);
916: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
917: CONCAT214(*(undefined2 *)(pauVar21[1] + 10),
918: CONCAT212(uVar75,SUB1612(auVar52,0))) >>
919: 0x60,0),CONCAT210(uVar74,SUB1610(auVar52,0))) >>
920: 0x50,0),CONCAT28(uVar73,SUB168(auVar52,0))) >>
921: 0x40,0),uVar55)) << 0x30 &
922: (undefined  [16])0xffffffff00000000;
923: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
924: CONCAT214(*(undefined2 *)(pauVar21[1] + 10),
925: CONCAT212(SUB162(auVar70 >> 0x30,0),
926: SUB1612(auVar70,0))) >> 0x60,0
927: ),CONCAT210(uVar74,SUB1610(auVar70,0))) >> 0x50,0)
928: ,CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
929: uVar55)) << 0x30;
930: uVar20 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar72)
931: ) & 0xffff0000;
932: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
933: CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212(uVar55
934: ,SUB1612(auVar52,0))) >> 0x60,0),
935: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
936: CONCAT28(*(undefined2 *)pauVar21[1],
937: SUB168(auVar52,0))) >> 0x40,0),
938: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
939: SUB1612((undefined  [16])0xffff000000000000 >>
940: 0x20,0),uVar72)) << 0x10;
941: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
942: ;
943: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
944: ;
945: *(undefined2 *)pauVar24[1] = *(undefined2 *)pauVar21[1];
946: *(short *)(pauVar24[1] + 2) = -SUB162(auVar70 >> 0x60,0);
947: *(undefined2 *)(pauVar24[1] + 4) = uVar54;
948: *(short *)(pauVar24[1] + 6) = -sVar11;
949: *(undefined2 *)(pauVar24[1] + 8) = uVar55;
950: *(short *)(pauVar24[1] + 10) = -SUB162(auVar70 >> 0x70,0);
951: *(undefined2 *)(pauVar24[1] + 0xc) = uVar12;
952: *(short *)(pauVar24[1] + 0xe) = -sVar13;
953: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
954: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
955: >> 0x70,0),
956: CONCAT212((short)(uVar20 >> 0x10),
957: SUB1612(auVar52,0))) >> 0x60,0),
958: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
959: CONCAT28(SUB162(auVar71 >> 0x40,0),
960: SUB168(auVar52,0))) >> 0x40,0),
961: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
962: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
963: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
964: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
965: auVar71 = pauVar21[2];
966: uVar75 = *(undefined2 *)(pauVar21[3] + 2);
967: uVar54 = *(undefined2 *)(pauVar21[3] + 4);
968: sVar11 = *(short *)(pauVar21[3] + 6);
969: uVar55 = *(undefined2 *)(pauVar21[3] + 8);
970: uVar12 = *(undefined2 *)(pauVar21[3] + 0xc);
971: sVar13 = *(short *)(pauVar21[3] + 0xe);
972: sVar77 = SUB162(auVar71 >> 0x30,0);
973: uVar72 = SUB162(auVar71 >> 0x20,0);
974: uVar73 = SUB162(auVar71 >> 0x10,0);
975: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
976: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
977: auVar71,0))) >> 0x60,0),
978: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
979: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
980: uVar75),uVar73)) << 0x20;
981: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
982: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
983: 0))) >> 0x60,0),
984: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
985: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
986: uVar75)) << 0x30 &
987: (undefined  [16])0xffffffff00000000;
988: uVar74 = SUB162(auVar71 >> 0x50,0);
989: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
990: CONCAT214(*(undefined2 *)(pauVar21[3] + 10),
991: CONCAT212(uVar75,SUB1612(auVar52,0))) >>
992: 0x60,0),CONCAT210(uVar74,SUB1610(auVar52,0))) >>
993: 0x50,0),CONCAT28(uVar73,SUB168(auVar52,0))) >>
994: 0x40,0),uVar55)) << 0x30 &
995: (undefined  [16])0xffffffff00000000;
996: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
997: CONCAT214(*(undefined2 *)(pauVar21[3] + 10),
998: CONCAT212(SUB162(auVar70 >> 0x30,0),
999: SUB1612(auVar70,0))) >> 0x60,0
1000: ),CONCAT210(uVar74,SUB1610(auVar70,0))) >> 0x50,0)
1001: ,CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
1002: uVar55)) << 0x30;
1003: uVar20 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar72)
1004: ) & 0xffff0000;
1005: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
1006: CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212(uVar55
1007: ,SUB1612(auVar52,0))) >> 0x60,0),
1008: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
1009: CONCAT28(*(undefined2 *)pauVar21[3],
1010: SUB168(auVar52,0))) >> 0x40,0),
1011: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
1012: SUB1612((undefined  [16])0xffff000000000000 >>
1013: 0x20,0),uVar72)) << 0x10;
1014: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
1015: ;
1016: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
1017: ;
1018: *(undefined2 *)pauVar24[3] = *(undefined2 *)pauVar21[3];
1019: *(short *)(pauVar24[3] + 2) = -SUB162(auVar70 >> 0x60,0);
1020: *(undefined2 *)(pauVar24[3] + 4) = uVar54;
1021: *(short *)(pauVar24[3] + 6) = -sVar11;
1022: *(undefined2 *)(pauVar24[3] + 8) = uVar55;
1023: *(short *)(pauVar24[3] + 10) = -SUB162(auVar70 >> 0x70,0);
1024: *(undefined2 *)(pauVar24[3] + 0xc) = uVar12;
1025: *(short *)(pauVar24[3] + 0xe) = -sVar13;
1026: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
1027: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(-
1028: SUB162(auVar71 >> 0x70,0),
1029: CONCAT212((short)(uVar20 >> 0x10),
1030: SUB1612(auVar52,0))) >> 0x60,0),
1031: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
1032: CONCAT28(SUB162(auVar71 >> 0x40,0),
1033: SUB168(auVar52,0))) >> 0x40,0),
1034: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
1035: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
1036: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
1037: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
1038: auVar71 = pauVar21[4];
1039: uVar75 = *(undefined2 *)(pauVar21[5] + 2);
1040: uVar54 = *(undefined2 *)(pauVar21[5] + 4);
1041: sVar11 = *(short *)(pauVar21[5] + 6);
1042: uVar55 = *(undefined2 *)(pauVar21[5] + 8);
1043: uVar12 = *(undefined2 *)(pauVar21[5] + 0xc);
1044: sVar13 = *(short *)(pauVar21[5] + 0xe);
1045: sVar77 = SUB162(auVar71 >> 0x30,0);
1046: uVar72 = SUB162(auVar71 >> 0x20,0);
1047: uVar73 = SUB162(auVar71 >> 0x10,0);
1048: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1049: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
1050: auVar71,0))) >> 0x60,0),
1051: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
1052: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
1053: uVar75),uVar73)) << 0x20;
1054: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1055: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
1056: 0))) >> 0x60,0),
1057: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
1058: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
1059: uVar75)) << 0x30 &
1060: (undefined  [16])0xffffffff00000000;
1061: uVar74 = SUB162(auVar71 >> 0x50,0);
1062: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1063: CONCAT214(*(undefined2 *)(pauVar21[5] + 10),
1064: CONCAT212(uVar75,SUB1612(auVar52,0))) >>
1065: 0x60,0),CONCAT210(uVar74,SUB1610(auVar52,0))) >>
1066: 0x50,0),CONCAT28(uVar73,SUB168(auVar52,0))) >>
1067: 0x40,0),uVar55)) << 0x30 &
1068: (undefined  [16])0xffffffff00000000;
1069: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1070: CONCAT214(*(undefined2 *)(pauVar21[5] + 10),
1071: CONCAT212(SUB162(auVar70 >> 0x30,0),
1072: SUB1612(auVar70,0))) >> 0x60,0
1073: ),CONCAT210(uVar74,SUB1610(auVar70,0))) >> 0x50,0)
1074: ,CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
1075: uVar55)) << 0x30;
1076: uVar20 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar72)
1077: ) & 0xffff0000;
1078: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
1079: CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212(uVar55
1080: ,SUB1612(auVar52,0))) >> 0x60,0),
1081: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
1082: CONCAT28(*(undefined2 *)pauVar21[5],
1083: SUB168(auVar52,0))) >> 0x40,0),
1084: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
1085: SUB1612((undefined  [16])0xffff000000000000 >>
1086: 0x20,0),uVar72)) << 0x10;
1087: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
1088: ;
1089: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
1090: ;
1091: *(undefined2 *)pauVar24[5] = *(undefined2 *)pauVar21[5];
1092: *(short *)(pauVar24[5] + 2) = -SUB162(auVar70 >> 0x60,0);
1093: *(undefined2 *)(pauVar24[5] + 4) = uVar54;
1094: *(short *)(pauVar24[5] + 6) = -sVar11;
1095: *(undefined2 *)(pauVar24[5] + 8) = uVar55;
1096: *(short *)(pauVar24[5] + 10) = -SUB162(auVar70 >> 0x70,0);
1097: *(undefined2 *)(pauVar24[5] + 0xc) = uVar12;
1098: *(short *)(pauVar24[5] + 0xe) = -sVar13;
1099: pauVar24[4] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
1100: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(-
1101: SUB162(auVar71 >> 0x70,0),
1102: CONCAT212((short)(uVar20 >> 0x10),
1103: SUB1612(auVar52,0))) >> 0x60,0),
1104: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
1105: CONCAT28(SUB162(auVar71 >> 0x40,0),
1106: SUB168(auVar52,0))) >> 0x40,0),
1107: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
1108: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
1109: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
1110: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
1111: auVar71 = pauVar21[6];
1112: uVar75 = *(undefined2 *)(pauVar21[7] + 2);
1113: uVar54 = *(undefined2 *)(pauVar21[7] + 4);
1114: sVar11 = *(short *)(pauVar21[7] + 6);
1115: uVar55 = *(undefined2 *)(pauVar21[7] + 8);
1116: uVar12 = *(undefined2 *)(pauVar21[7] + 0xc);
1117: sVar13 = *(short *)(pauVar21[7] + 0xe);
1118: sVar77 = SUB162(auVar71 >> 0x30,0);
1119: uVar72 = SUB162(auVar71 >> 0x20,0);
1120: uVar73 = SUB162(auVar71 >> 0x10,0);
1121: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1122: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
1123: auVar71,0))) >> 0x60,0),
1124: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
1125: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
1126: uVar75),uVar73)) << 0x20;
1127: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1128: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
1129: 0))) >> 0x60,0),
1130: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
1131: CONCAT28(uVar72,SUB168(auVar71,0))) >> 0x40,0),
1132: uVar75)) << 0x30 &
1133: (undefined  [16])0xffffffff00000000;
1134: uVar74 = SUB162(auVar71 >> 0x50,0);
1135: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1136: CONCAT214(*(undefined2 *)(pauVar21[7] + 10),
1137: CONCAT212(uVar75,SUB1612(auVar52,0))) >>
1138: 0x60,0),CONCAT210(uVar74,SUB1610(auVar52,0))) >>
1139: 0x50,0),CONCAT28(uVar73,SUB168(auVar52,0))) >>
1140: 0x40,0),uVar55)) << 0x30 &
1141: (undefined  [16])0xffffffff00000000;
1142: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1143: CONCAT214(*(undefined2 *)(pauVar21[7] + 10),
1144: CONCAT212(SUB162(auVar70 >> 0x30,0),
1145: SUB1612(auVar70,0))) >> 0x60,0
1146: ),CONCAT210(uVar74,SUB1610(auVar70,0))) >> 0x50,0)
1147: ,CONCAT28(uVar73,SUB168(auVar70,0))) >> 0x40,0),
1148: uVar55)) << 0x30;
1149: uVar20 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar72)
1150: ) & 0xffff0000;
1151: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
1152: CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212(uVar55
1153: ,SUB1612(auVar52,0))) >> 0x60,0),
1154: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
1155: CONCAT28(*(undefined2 *)pauVar21[7],
1156: SUB168(auVar52,0))) >> 0x40,0),
1157: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
1158: SUB1612((undefined  [16])0xffff000000000000 >>
1159: 0x20,0),uVar72)) << 0x10;
1160: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
1161: ;
1162: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
1163: ;
1164: *(undefined2 *)pauVar24[7] = *(undefined2 *)pauVar21[7];
1165: *(short *)(pauVar24[7] + 2) = -SUB162(auVar70 >> 0x60,0);
1166: *(undefined2 *)(pauVar24[7] + 4) = uVar54;
1167: *(short *)(pauVar24[7] + 6) = -sVar11;
1168: *(undefined2 *)(pauVar24[7] + 8) = uVar55;
1169: *(short *)(pauVar24[7] + 10) = -SUB162(auVar70 >> 0x70,0);
1170: *(undefined2 *)(pauVar24[7] + 0xc) = uVar12;
1171: *(short *)(pauVar24[7] + 0xe) = -sVar13;
1172: pauVar24[6] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
1173: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(-
1174: SUB162(auVar71 >> 0x70,0),
1175: CONCAT212((short)(uVar20 >> 0x10),
1176: SUB1612(auVar52,0))) >> 0x60,0),
1177: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
1178: CONCAT28(SUB162(auVar71 >> 0x40,0),
1179: SUB168(auVar52,0))) >> 0x40,0),
1180: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
1181: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
1182: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
1183: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
1184: }
1185: uVar40 = uVar50 + 1;
1186: uVar50 = uVar50 + 1;
1187: } while (uVar40 < uVar47);
1188: code_r0x0014e59f:
1189: iVar16 = *(int *)(lVar22 + 0xc);
1190: }
1191: iVar26 = (int)lVar44;
1192: lVar44 = lVar44 + 1;
1193: } while (iVar26 + 1 < iVar16);
1194: }
1195: uVar35 = uVar35 + iVar16;
1196: } while (uVar35 < *(uint *)(lVar22 + 0x20));
1197: iVar16 = *(int *)(param_2 + 0x4c);
1198: }
1199: iVar43 = (int)lVar49;
1200: lVar49 = lVar49 + 1;
1201: } while (iVar43 + 1 < iVar16);
1202: }
1203: }
1204: break;
1205: case 2:
1206: uVar2 = param_4[0x15];
1207: uVar3 = param_4[0x14];
1208: iVar37 = *(int *)(param_2 + 0x13c);
1209: uVar27 = *(uint *)(param_1 + 0x8c);
1210: iVar16 = *(int *)(param_2 + 0x4c);
1211: if (0 < iVar16) {
1212: lVar49 = 0;
1213: do {
1214: lVar22 = lVar49 * 0x60 + *(long *)(param_2 + 0x58);
1215: iVar43 = *(int *)(lVar22 + 0xc);
1216: uVar34 = (uVar27 / (uint)(iVar37 * 8)) * iVar43;
1217: iVar26 = uVar2 * iVar43;
1218: if (*(int *)(lVar22 + 0x20) != 0) {
1219: uVar39 = 0;
1220: lVar17 = (ulong)(uVar3 * *(int *)(lVar22 + 8)) * 0x80;
1221: do {
1222: lVar18 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
1223: (param_1,*(undefined8 *)(lVar51 + lVar49 * 8),uVar39,iVar43,1);
1224: uVar35 = iVar26 + uVar39;
1225: if (uVar35 < uVar34) {
1226: lVar44 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
1227: (param_1,*(undefined8 *)(param_3 + lVar49 * 8),
1228: ((uVar34 - iVar26) - uVar39) - *(int *)(lVar22 + 0xc),
1229: *(int *)(lVar22 + 0xc),0);
1230: }
1231: else {
1232: lVar44 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
1233: (param_1,*(undefined8 *)(param_3 + lVar49 * 8),uVar35,
1234: *(undefined4 *)(lVar22 + 0xc),0);
1235: }
1236: iVar43 = *(int *)(lVar22 + 0xc);
1237: if (0 < iVar43) {
1238: lVar48 = 0;
1239: do {
1240: while (iVar16 = (int)lVar48, uVar34 <= uVar35) {
1241: FUN_0013beb0(lVar17 + *(long *)(lVar44 + lVar48 * 8),
1242: *(undefined8 *)(lVar18 + lVar48 * 8),*(undefined4 *)(lVar22 + 0x1c)
1243: );
1244: iVar43 = *(int *)(lVar22 + 0xc);
1245: lVar48 = lVar48 + 1;
1246: if (iVar43 <= iVar16 + 1) goto code_r0x0014e1a8;
1247: }
1248: puVar45 = (undefined2 *)
1249: (lVar17 + *(long *)(lVar44 + -8 + (long)(iVar43 - iVar16) * 8));
1250: if (*(int *)(lVar22 + 0x1c) != 0) {
1251: puVar19 = puVar45 + (ulong)(*(int *)(lVar22 + 0x1c) - 1) * 0x40 + 0x40;
1252: puVar29 = *(undefined2 **)(lVar18 + lVar48 * 8);
1253: do {
1254: puVar28 = puVar29;
1255: puVar38 = puVar45;
1256: do {
1257: puVar31 = puVar28 + 0x10;
1258: *puVar28 = *puVar38;
1259: puVar28[1] = puVar38[1];
1260: puVar28[2] = puVar38[2];
1261: puVar28[3] = puVar38[3];
1262: puVar28[4] = puVar38[4];
1263: puVar28[5] = puVar38[5];
1264: puVar28[6] = puVar38[6];
1265: puVar28[7] = puVar38[7];
1266: puVar28[8] = -puVar38[8];
1267: puVar28[9] = -puVar38[9];
1268: puVar28[10] = -puVar38[10];
1269: puVar28[0xb] = -puVar38[0xb];
1270: puVar28[0xc] = -puVar38[0xc];
1271: puVar28[0xd] = -puVar38[0xd];
1272: puVar28[0xe] = -puVar38[0xe];
1273: puVar28[0xf] = -puVar38[0xf];
1274: puVar28 = puVar31;
1275: puVar38 = puVar38 + 0x10;
1276: } while (puVar29 + 0x40 != puVar31);
1277: puVar45 = puVar45 + 0x40;
1278: puVar29 = puVar29 + 0x40;
1279: } while (puVar45 != puVar19);
1280: }
1281: lVar48 = lVar48 + 1;
1282: } while (iVar16 + 1 < iVar43);
1283: }
1284: code_r0x0014e1a8:
1285: uVar39 = uVar39 + iVar43;
1286: } while (uVar39 < *(uint *)(lVar22 + 0x20));
1287: iVar16 = *(int *)(param_2 + 0x4c);
1288: }
1289: iVar43 = (int)lVar49;
1290: lVar49 = lVar49 + 1;
1291: } while (iVar43 + 1 < iVar16);
1292: }
1293: break;
1294: case 3:
1295: uVar2 = param_4[0x15];
1296: uVar3 = param_4[0x14];
1297: iVar37 = *(int *)(param_2 + 0x4c);
1298: if (0 < iVar37) {
1299: auStack280._0_16_ = auStack280._0_16_ & (undefined  [16])0xffffffffffffffff;
1300: do {
1301: lVar49 = auStack280._0_8_ * 0x60 + *(long *)(param_2 + 0x58);
1302: iVar16 = *(int *)(lVar49 + 8);
1303: iVar43 = *(int *)(lVar49 + 0xc);
1304: if (*(int *)(lVar49 + 0x20) != 0) {
1305: uVar27 = 0;
1306: do {
1307: lVar22 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
1308: (param_1,*(undefined8 *)(lVar51 + auStack280._0_8_ * 8),uVar27);
1309: iVar37 = *(int *)(lVar49 + 0xc);
1310: if (0 < iVar37) {
1311: uVar34 = *(uint *)(lVar49 + 0x1c);
1312: auStack248._0_16_ = auStack248._0_16_ & (undefined  [16])0xffffffffffffffff;
1313: do {
1314: if (uVar34 != 0) {
1315: uVar20 = 0;
1316: do {
1317: while( true ) {
1318: iVar26 = (int)uVar20;
1319: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
1320: (param_1,*(undefined8 *)
1321: (param_3 + auStack280._0_8_ * 8),
1322: uVar3 * iVar16 + iVar26);
1323: iVar37 = *(int *)(lVar49 + 8);
1324: if (iVar37 < 1) break;
1325: uVar39 = iVar26 + iVar37;
1326: lVar17 = *(long *)(lVar22 + auStack248._0_8_ * 8);
1327: do {
1328: while( true ) {
1329: pauVar32 = (undefined (*) [16])
1330: ((ulong)(auStack248._0_4_ + uVar2 * iVar43 + uVar27) * 0x80 +
1331: *plVar23);
1332: pauVar21 = (undefined (*) [16])(uVar20 * 0x80 + lVar17);
1333: pauVar24 = pauVar32[8];
1334: if ((((((((pauVar21[7] <= pauVar32 || pauVar24 <= pauVar21[6]) &&
1335: (pauVar21[8] <= pauVar32 || pauVar24 <= pauVar21[7])) &&
1336: (pauVar21[6] <= pauVar32 || pauVar24 <= pauVar21[5])) &&
1337: (pauVar21[5] <= pauVar32 || pauVar24 <= pauVar21[4])) &&
1338: (pauVar21[4] <= pauVar32 || pauVar24 <= pauVar21[3])) &&
1339: (pauVar21[3] <= pauVar32 || pauVar24 <= pauVar21[2])) &&
1340: (pauVar21[2] <= pauVar32 || pauVar24 <= pauVar21[1])) &&
1341: (pauVar21[1] <= pauVar32 || pauVar24 <= pauVar21)) break;
1342: iVar37 = 8;
1343: do {
1344: *(undefined2 *)*pauVar21 = *(undefined2 *)*pauVar32;
1345: *(undefined2 *)pauVar21[1] = *(undefined2 *)(*pauVar32 + 2);
1346: *(undefined2 *)pauVar21[2] = *(undefined2 *)(*pauVar32 + 4);
1347: *(undefined2 *)pauVar21[3] = *(undefined2 *)(*pauVar32 + 6);
1348: *(undefined2 *)pauVar21[4] = *(undefined2 *)(*pauVar32 + 8);
1349: *(undefined2 *)pauVar21[5] = *(undefined2 *)(*pauVar32 + 10);
1350: *(undefined2 *)pauVar21[6] = *(undefined2 *)(*pauVar32 + 0xc);
1351: *(undefined2 *)pauVar21[7] = *(undefined2 *)(*pauVar32 + 0xe);
1352: iVar37 = iVar37 + -1;
1353: pauVar21 = (undefined (*) [16])(*pauVar21 + 2);
1354: pauVar32 = pauVar32[1];
1355: } while (iVar37 != 0);
1356: uVar34 = (int)uVar20 + 1;
1357: uVar20 = (ulong)uVar34;
1358: plVar23 = plVar23 + 1;
1359: if (uVar34 == uVar39) goto code_r0x0014df2d;
1360: }
1361: auVar71 = *pauVar32;
1362: uVar47 = (int)uVar20 + 1;
1363: uVar20 = (ulong)uVar47;
1364: plVar23 = plVar23 + 1;
1365: uVar5 = *(ushort *)pauVar32[1];
1366: uVar75 = *(undefined2 *)(pauVar32[1] + 2);
1367: uVar54 = *(undefined2 *)(pauVar32[1] + 4);
1368: uVar55 = *(undefined2 *)(pauVar32[1] + 8);
1369: uVar12 = *(undefined2 *)(pauVar32[1] + 0xc);
1370: uVar73 = *(undefined2 *)(pauVar32[1] + 0xe);
1371: uVar112 = SUB162(auVar71 >> 0x30,0);
1372: uVar111 = SUB162(auVar71 >> 0x20,0);
1373: uVar114 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
1374: (pauVar32[1] + 6),
1375: CONCAT212(uVar112,SUB1612(
1376: auVar71,0))) >> 0x60,0),
1377: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0);
1378: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar114,CONCAT28(uVar111,
1379: SUB168(auVar71,0))) >> 0x40,0),uVar75)) << 0x30 &
1380: (undefined  [16])0xffffffff00000000;
1381: auVar52 = pauVar32[2];
1382: uVar59 = SUB162(auVar71 >> 0x40,0);
1383: uVar64 = SUB162(auVar71 >> 0x50,0);
1384: uVar67 = SUB162(auVar71 >> 0x70,0);
1385: uVar87 = SUB162(auVar71 >> 0x10,0);
1386: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1387: SUB164(CONCAT214(*(undefined2 *)(pauVar32[1] + 6),
1388: CONCAT212(uVar112,SUB1612(auVar71
1389: ,0))) >> 0x60,0),
1390: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
1391: CONCAT28(uVar111,SUB168(auVar71,0))) >> 0x40,0),
1392: uVar75),uVar87)) << 0x20;
1393: uVar72 = *(undefined2 *)pauVar32[3];
1394: uVar74 = *(undefined2 *)(pauVar32[3] + 4);
1395: uVar83 = *(undefined2 *)(pauVar32[3] + 6);
1396: uVar62 = *(undefined2 *)(pauVar32[3] + 0xc);
1397: uVar99 = *(undefined2 *)(pauVar32[3] + 0xe);
1398: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1399: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
1400: CONCAT212(uVar75,SUB1612(auVar70,0))) >>
1401: 0x60,0),CONCAT210(uVar64,SUB1610(auVar70,0))) >>
1402: 0x50,0),CONCAT28(uVar87,SUB168(auVar70,0))) >>
1403: 0x40,0),uVar55)) << 0x30 &
1404: (undefined  [16])0xffffffff00000000;
1405: uVar79 = SUB162(auVar52 >> 0x30,0);
1406: uVar76 = SUB162(auVar52 >> 0x20,0);
1407: uVar34 = SUB164(auVar52,0) & 0xffff;
1408: auVar70 = pauVar32[4];
1409: auVar97 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1410: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
1411: CONCAT212(SUB162(auVar81 >> 0x30,0),
1412: SUB1612(auVar81,0))) >> 0x60,0
1413: ),CONCAT210(uVar64,SUB1610(auVar81,0))) >> 0x50,0)
1414: ,CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
1415: uVar55)) << 0x30;
1416: uVar57 = SUB162(auVar52 >> 0x10,0);
1417: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1418: SUB164(CONCAT214(uVar83,CONCAT212(uVar79,SUB1612(
1419: auVar52,0))) >> 0x60,0),
1420: CONCAT210(uVar74,SUB1610(auVar52,0))) >> 0x50,0),
1421: CONCAT28(uVar76,SUB168(auVar52,0))) >> 0x40,0),
1422: *(undefined2 *)(pauVar32[3] + 2)),uVar57)) << 0x20
1423: ;
1424: uVar75 = *(undefined2 *)pauVar32[5];
1425: uVar64 = *(undefined2 *)(pauVar32[5] + 2);
1426: uVar87 = *(undefined2 *)(pauVar32[5] + 4);
1427: uVar86 = *(undefined2 *)(pauVar32[5] + 8);
1428: uVar88 = *(undefined2 *)(pauVar32[5] + 0xc);
1429: uVar56 = *(undefined2 *)(pauVar32[5] + 0xe);
1430: uVar60 = SUB162(auVar52 >> 0x40,0);
1431: uVar66 = SUB162(auVar52 >> 0x60,0);
1432: uVar68 = SUB162(auVar52 >> 0x70,0);
1433: uVar113 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,
1434: CONCAT212(uVar55,SUB1612(auVar82,0))) >> 0x60,0),
1435: CONCAT210(uVar54,SUB1610(auVar82,0))) >> 0x50,0),
1436: CONCAT28(uVar5,SUB168(auVar82,0))) >> 0x40,0);
1437: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar111)
1438: ) & 0xffff0000;
1439: auVar98 = CONCAT88(uVar113,(uVar6 >> 0x10) << 0x30) &
1440: (undefined  [16])0xffff000000000000;
1441: uVar100 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x40,0
1442: );
1443: uVar102 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x50,0
1444: );
1445: uVar105 = SUB162(auVar97 >> 0x60,0);
1446: uVar108 = SUB162(auVar70 >> 0x30,0);
1447: uVar107 = SUB162(auVar70 >> 0x20,0);
1448: uVar109 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
1449: (pauVar32[5] + 6),
1450: CONCAT212(uVar108,SUB1612(
1451: auVar70,0))) >> 0x60,0),
1452: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0);
1453: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar109,CONCAT28(uVar107,
1454: SUB168(auVar70,0))) >> 0x40,0),uVar64)) << 0x30 &
1455: (undefined  [16])0xffffffff00000000;
1456: auVar81 = pauVar32[6];
1457: auVar123 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1458: CONCAT214(*(undefined2 *)(pauVar32[3] + 10),
1459: CONCAT212(SUB162(auVar106 >> 0x30,0),
1460: SUB1612(auVar106,0))) >> 0x60,
1461: 0),CONCAT210(SUB162(auVar52 >> 0x50,0),
1462: SUB1610(auVar106,0))) >> 0x50,0),
1463: CONCAT28(uVar57,SUB168(auVar106,0))) >> 0x40,0),
1464: *(undefined2 *)(pauVar32[3] + 8))) << 0x30;
1465: uVar84 = SUB162(auVar70 >> 0x10,0);
1466: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1467: SUB164(CONCAT214(*(undefined2 *)(pauVar32[5] + 6),
1468: CONCAT212(uVar108,SUB1612(auVar70
1469: ,0))) >> 0x60,0),
1470: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0),
1471: CONCAT28(uVar107,SUB168(auVar70,0))) >> 0x40,0),
1472: uVar64),uVar84)) << 0x20;
1473: uVar61 = SUB162(auVar70 >> 0x40,0);
1474: uVar65 = SUB162(auVar70 >> 0x50,0);
1475: uVar69 = SUB162(auVar70 >> 0x70,0);
1476: uVar57 = *(undefined2 *)(pauVar32[7] + 8);
1477: uVar58 = *(undefined2 *)(pauVar32[7] + 0xc);
1478: uVar63 = *(undefined2 *)(pauVar32[7] + 0xe);
1479: uVar126 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >> 0x40,
1480: 0);
1481: uVar127 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >> 0x50,
1482: 0);
1483: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1484: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
1485: CONCAT212(SUB162(auVar52 >> 0x30,0),
1486: SUB1612(auVar52,0))) >> 0x60,0
1487: ),CONCAT210(uVar65,SUB1610(auVar52,0))) >> 0x50,0)
1488: ,CONCAT28(uVar84,SUB168(auVar52,0))) >> 0x40,0),
1489: uVar86)) << 0x30;
1490: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1491: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
1492: CONCAT212(uVar64,SUB1612(auVar92,0))) >>
1493: 0x60,0),CONCAT210(uVar65,SUB1610(auVar92,0))) >>
1494: 0x50,0),CONCAT28(uVar84,SUB168(auVar92,0))) >>
1495: 0x40,0),uVar86)) << 0x30 &
1496: (undefined  [16])0xffffffff00000000;
1497: uVar65 = SUB162(auVar81 >> 0x40,0);
1498: uVar84 = SUB162(auVar81 >> 0x60,0);
1499: uVar85 = SUB162(auVar81 >> 0x70,0);
1500: uVar120 = SUB162(auVar81 >> 0x30,0);
1501: uVar118 = SUB162(auVar81 >> 0x20,0);
1502: uVar117 = SUB162(auVar81 >> 0x10,0);
1503: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1504: SUB164(CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
1505: CONCAT212(uVar120,SUB1612(auVar81
1506: ,0))) >> 0x60,0),
1507: CONCAT210(*(undefined2 *)(pauVar32[7] + 4),
1508: SUB1610(auVar81,0))) >> 0x50,0),
1509: CONCAT28(uVar118,SUB168(auVar81,0))) >> 0x40,0),
1510: *(undefined2 *)(pauVar32[7] + 2)),uVar117)) <<
1511: 0x20;
1512: uVar64 = SUB162(auVar81,0);
1513: uVar7 = (ulong)CONCAT24(uVar87,CONCAT22(SUB162(auVar70 >> 0x60,0),uVar107)
1514: ) & 0xffff0000;
1515: auVar92 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
1516: uVar88,CONCAT212(uVar86,SUB1612(auVar52,0))) >>
1517: 0x60,0),CONCAT210(uVar87,SUB1610(auVar52,0))) >>
1518: 0x50,0),CONCAT28(uVar75,SUB168(auVar52,0))) >>
1519: 0x40,0),(uVar7 >> 0x10) << 0x30) &
1520: (undefined  [16])0xffff000000000000;
1521: uVar93 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
1522: ;
1523: uVar94 = SUB162(auVar82 >> 0x60,0);
1524: uVar96 = SUB162(auVar82 >> 0x70,0);
1525: uVar90 = (undefined2)(uVar6 >> 0x10);
1526: uVar10 = SUB166(CONCAT412(SUB164(CONCAT214(uVar66,CONCAT212(uVar90,SUB1612
1527: (auVar98,0))) >> 0x60,0),
1528: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0);
1529: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar10,CONCAT28(uVar59,SUB168
1530: (auVar98,0))) >> 0x40,0),uVar76) &
1531: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0))
1532: << 0x30 & (undefined  [16])0xffffffff00000000;
1533: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1534: CONCAT214(*(undefined2 *)(pauVar32[7] + 10),
1535: CONCAT212(SUB162(auVar106 >> 0x30,0),
1536: SUB1612(auVar106,0))) >> 0x60,
1537: 0),CONCAT210(SUB162(auVar81 >> 0x50,0),
1538: SUB1610(auVar106,0))) >> 0x50,0),
1539: CONCAT28(uVar117,SUB168(auVar106,0))) >> 0x40,0),
1540: uVar57)) << 0x30;
1541: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1542: SUB164(CONCAT214(uVar66,CONCAT212(uVar90,SUB1612(
1543: auVar98,0))) >> 0x60,0),
1544: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0),
1545: CONCAT28(uVar59,SUB168(auVar98,0))) >> 0x40,0),
1546: uVar76) & SUB1610((undefined  [16])
1547: 0xffffffffffffffff >> 0x30,0),
1548: uVar111)) << 0x20;
1549: uVar117 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >> 0x40,
1550: 0);
1551: uVar122 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >> 0x50,
1552: 0);
1553: auVar110 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1554: CONCAT214(uVar74,CONCAT212(SUB162(auVar81 >> 0x30,
1555: 0),
1556: SUB1612(auVar81,0))) >>
1557: 0x60,0),CONCAT210(uVar54,SUB1610(auVar81,0))) >>
1558: 0x50,0),CONCAT28(uVar111,SUB168(auVar81,0))) >>
1559: 0x40,0),uVar72)) << 0x30;
1560: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1561: CONCAT214(uVar74,CONCAT212(uVar76,SUB1612(auVar52,
1562: 0))) >> 0x60,0),
1563: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
1564: CONCAT28(uVar111,SUB168(auVar52,0))) >> 0x40,0),
1565: uVar72)) << 0x30 &
1566: (undefined  [16])0xffffffff00000000;
1567: uVar54 = (undefined2)(uVar7 >> 0x10);
1568: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1569: SUB164(CONCAT214(uVar84,CONCAT212(uVar54,SUB1612(
1570: auVar92,0))) >> 0x60,0),
1571: CONCAT210(uVar65,SUB1610(auVar92,0))) >> 0x50,0),
1572: CONCAT28(uVar61,SUB168(auVar92,0))) >> 0x40,0),
1573: uVar118) &
1574: SUB1610((undefined  [16])0xffffffffffffffff >>
1575: 0x30,0),uVar107)) << 0x20;
1576: uVar91 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *
1577: )(pauVar32[3]
1578: + 8),
1579: CONCAT212(uVar72,SUB1612(auVar52,0))) >> 0x60,0),
1580: CONCAT210(uVar60,SUB1610(auVar52,0))) >> 0x50,0),
1581: CONCAT28((short)uVar34,SUB168(auVar52,0))) >> 0x40
1582: ,0);
1583: uVar6 = (ulong)CONCAT24(uVar60,CONCAT22(uVar55,uVar59)) & 0xffff0000;
1584: auVar81 = CONCAT88(uVar91,(uVar6 >> 0x10) << 0x30) &
1585: (undefined  [16])0xffff000000000000;
1586: uVar76 = SUB162((auVar110 & (undefined  [16])0xffffffff00000000) >> 0x40,0
1587: );
1588: uVar7 = (ulong)CONCAT24(SUB162((auVar110 &
1589: (undefined  [16])0xffffffff00000000) >>
1590: 0x50,0),CONCAT22(uVar90,uVar76));
1591: uVar111 = SUB162(auVar110 >> 0x60,0);
1592: Var14 = CONCAT28(uVar111,uVar113);
1593: auVar106 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1594: CONCAT214(*(undefined2 *)(pauVar32[7] + 4),
1595: CONCAT212(SUB162(auVar92 >> 0x30,0),
1596: SUB1612(auVar92,0))) >> 0x60,0
1597: ),CONCAT210(uVar87,SUB1610(auVar92,0))) >> 0x50,0)
1598: ,CONCAT28(uVar107,SUB168(auVar92,0))) >> 0x40,0),
1599: *(undefined2 *)pauVar32[7])) << 0x30;
1600: uVar8 = (ulong)(uVar114 & 0xffff00000000 |
1601: (uint6)CONCAT22(SUB162(auVar123 >> 0x60,0),uVar105));
1602: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
1603: uVar68,uVar67),uVar127),CONCAT22(uVar102,uVar67))
1604: >> 0x10),uVar79),uVar112)) << 0x20;
1605: uVar35 = CONCAT22(uVar68,uVar67);
1606: auVar52 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar35,uVar127),
1607: CONCAT22(uVar102,uVar67)) >>
1608: 0x10),uVar79)) << 0x30 &
1609: (undefined  [16])0xffffffff00000000;
1610: uVar87 = SUB162((auVar106 & (undefined  [16])0xffffffff00000000) >> 0x40,0
1611: );
1612: uVar9 = (ulong)CONCAT24(SUB162((auVar106 &
1613: (undefined  [16])0xffffffff00000000) >>
1614: 0x50,0),CONCAT22(uVar54,uVar87));
1615: uVar55 = (undefined2)(uVar8 >> 0x20);
1616: uVar54 = (undefined2)(uVar8 >> 0x10);
1617: auVar98 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1618: CONCAT214(uVar83,CONCAT212(SUB162(auVar92 >> 0x30,
1619: 0),
1620: SUB1612(auVar92,0))) >>
1621: 0x60,0),CONCAT210(uVar55,SUB1610(auVar92,0))) >>
1622: 0x50,0),CONCAT28(uVar112,SUB168(auVar92,0))) >>
1623: 0x40,0),uVar54) & 0xffffffffffffffff) << 0x30;
1624: auVar52 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
1625: CONCAT412(SUB164(CONCAT214(uVar83,CONCAT212(uVar79
1626: ,SUB1612(auVar52,0))) >> 0x60,0),
1627: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
1628: CONCAT28(uVar112,SUB168(auVar52,0))) >> 0x40,0),
1629: uVar54)) << 0x30) >> 0x20,0) &
1630: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0))
1631: << 0x20;
1632: uVar8 = (ulong)(uVar109 & 0xffff00000000 |
1633: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),uVar94));
1634: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
1635: uVar85,uVar69),uVar122),CONCAT22(uVar93,uVar69))
1636: >> 0x10),uVar120),uVar108)) << 0x20;
1637: uVar68 = (undefined2)(uVar6 >> 0x10);
1638: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1639: CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(auVar81,
1640: 0))) >> 0x60,0),
1641: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
1642: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
1643: uVar61) &
1644: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)
1645: ) << 0x30 & (undefined  [16])0xffffffff00000000;
1646: uVar80 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162(
1647: auVar123 >> 0x70,0),
1648: CONCAT212(uVar54,SUB1612(auVar52,0))) >> 0x60,0),
1649: CONCAT210(uVar127,SUB1610(auVar52,0))) >> 0x50,0),
1650: CONCAT28(uVar126,SUB168(auVar52,0))) >> 0x40,0);
1651: uVar6 = (ulong)CONCAT24(uVar127,CONCAT22(SUB162(auVar97 >> 0x70,0),uVar102
1652: )) & 0xffff0000;
1653: auVar52 = CONCAT88(uVar80,(uVar6 >> 0x10) << 0x30) &
1654: (undefined  [16])0xffff000000000000;
1655: uVar74 = SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
1656: ;
1657: uVar83 = SUB162(auVar98 >> 0x60,0);
1658: auVar97 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
1659: CONCAT412(SUB164(CONCAT214(uVar65,CONCAT212(uVar61
1660: ,SUB1612(auVar116,0))) >> 0x60,0),
1661: CONCAT210(uVar60,SUB1610(auVar116,0))) >> 0x50,0),
1662: CONCAT28(uVar59,SUB168(auVar116,0))) >> 0x40,0),
1663: uVar64)) << 0x30) >> 0x20,0) &
1664: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)
1665: ,uVar34 << 0x10);
1666: uVar107 = (undefined2)(uVar8 >> 0x10);
1667: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1668: CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
1669: CONCAT212(SUB162(auVar92 >> 0x30,0),
1670: SUB1612(auVar92,0))) >> 0x60,0
1671: ),CONCAT210((short)(uVar8 >> 0x20),
1672: SUB1610(auVar92,0))) >> 0x50,0),
1673: CONCAT28(uVar108,SUB168(auVar92,0))) >> 0x40,0),
1674: uVar107) & 0xffffffffffffffff) << 0x30;
1675: *pauVar21 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
1676: SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
1677: pauVar32[7],
1678: CONCAT212(uVar64
1679: ,SUB1612(auVar97,0))) >> 0x60,0),
1680: CONCAT210(uVar75,SUB1610(auVar97,0))) >> 0x50,0),
1681: CONCAT28(SUB162(auVar70,0),SUB168(auVar97,0))) >>
1682: 0x40,0),(((ulong)CONCAT24(uVar75,CONCAT22(uVar72,
1683: uVar5)) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0)
1684: & SUB1610((undefined  [16])0xffffffffffffffff >>
1685: 0x30,0) &
1686: SUB1610((undefined  [16])0xffffffffffffffff >>
1687: 0x30,0),
1688: (SUB166(auVar97,0) >> 0x10) << 0x20) >> 0x20,0),
1689: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
1690: uVar79 = (undefined2)(uVar6 >> 0x10);
1691: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1692: CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(auVar52,
1693: 0))) >> 0x60,0),
1694: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
1695: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
1696: uVar93) &
1697: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0))
1698: << 0x30 & (undefined  [16])0xffffffff00000000;
1699: uVar55 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
1700: ;
1701: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1702: SUB164(CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(
1703: auVar81,0))) >> 0x60,0),
1704: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
1705: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
1706: uVar61) & SUB1610((undefined  [16])
1707: 0xffffffffffffffff >> 0x30,0),
1708: uVar59)) << 0x20;
1709: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
1710: CONCAT412(SUB164(CONCAT214(uVar122,CONCAT212(
1711: uVar93,SUB1612(auVar71,0))) >> 0x60,0),
1712: CONCAT210(uVar127,SUB1610(auVar71,0))) >> 0x50,0),
1713: CONCAT28(uVar102,SUB168(auVar71,0))) >> 0x40,0),
1714: uVar117)) << 0x30) >> 0x20,0),
1715: CONCAT22(uVar126,uVar100));
1716: uVar6 = (ulong)(uVar10 & 0xffff00000000 |
1717: (uint6)CONCAT22(SUB162(auVar106 >> 0x60,0),uVar111));
1718: uVar8 = (ulong)(((uint6)uVar35 & 0xffff0000) << 0x10 |
1719: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),uVar83));
1720: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1721: SUB164(CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(
1722: auVar52,0))) >> 0x60,0),
1723: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
1724: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
1725: uVar93) & SUB1610((undefined  [16])
1726: 0xffffffffffffffff >> 0x30,0),
1727: uVar102)) << 0x20;
1728: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1729: CONCAT214(uVar65,CONCAT212(SUB162(auVar70 >> 0x30,
1730: 0),
1731: SUB1612(auVar70,0))) >>
1732: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
1733: 0x50,0),CONCAT28(uVar59,SUB168(auVar70,0))) >>
1734: 0x40,0),uVar64) & 0xffffffffffffffff) << 0x30;
1735: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1736: CONCAT214(uVar122,CONCAT212(SUB162(auVar71 >> 0x30
1737: ,0),
1738: SUB1612(auVar71,0)))
1739: >> 0x60,0),CONCAT210(uVar127,SUB1610(auVar71,0)))
1740: >> 0x50,0),CONCAT28(uVar102,SUB168(auVar71,0))) >>
1741: 0x40,0),uVar117)) << 0x30;
1742: pauVar21[1] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
1743: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
1744: uVar107,CONCAT212(uVar117,SUB1612(auVar81,0))) >>
1745: 0x60,0),CONCAT210(uVar94,SUB1610(auVar81,0))) >>
1746: 0x50,0),CONCAT28(SUB162((auVar82 &
1747: (undefined  [16])
1748: 0xffffffff00000000) >>
1749: 0x40,0),SUB168(auVar81,0))
1750: ) >> 0x40,0),
1751: (((ulong)CONCAT24(uVar94,CONCAT22(uVar54,uVar105))
1752: & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
1753: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
1754: CONCAT22(uVar105,uVar100));
1755: uVar54 = (undefined2)(uVar9 >> 0x20);
1756: uVar64 = (undefined2)(uVar7 >> 0x20);
1757: uVar75 = (undefined2)(uVar9 >> 0x10);
1758: uVar72 = (undefined2)(uVar7 >> 0x10);
1759: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
1760: SUB164(CONCAT214(uVar88,CONCAT212(uVar12,CONCAT210
1761: (uVar66,Var14))) >> 0x60,0),
1762: CONCAT210(uVar54,Var14)) >> 0x50,0),
1763: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75),
1764: uVar72) & (undefined  [12])0xffffffffffffffff) <<
1765: 0x20;
1766: auVar81 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
1767: CONCAT412(SUB164(CONCAT214(uVar88,CONCAT212(uVar12
1768: ,CONCAT210(uVar66,Var14))) >> 0x60,0),
1769: CONCAT210(uVar54,Var14)) >> 0x50,0),
1770: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75) &
1771: 0xffffffffffffffff) << 0x30) >> 0x20,0) &
1772: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0))
1773: << 0x20;
1774: uVar60 = (undefined2)(uVar6 >> 0x20);
1775: uVar59 = (undefined2)(uVar6 >> 0x10);
1776: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1777: CONCAT214(uVar84,CONCAT212(SUB162(auVar70 >> 0x30,
1778: 0),
1779: SUB1612(auVar70,0))) >>
1780: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
1781: 0x50,0),CONCAT28(uVar72,SUB168(auVar70,0))) >>
1782: 0x40,0),uVar59) & 0xffffffffffffffff) << 0x30;
1783: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
1784: CONCAT412(SUB164(CONCAT214(uVar84,CONCAT212(uVar75
1785: ,SUB1612(auVar81,0))) >> 0x60,0),
1786: CONCAT210(uVar60,SUB1610(auVar81,0))) >> 0x50,0),
1787: CONCAT28(uVar90,SUB168(auVar81,0))) >> 0x40,0),
1788: uVar59)) << 0x30) >> 0x20,0) &
1789: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)
1790: ,CONCAT22(uVar111,uVar76));
1791: pauVar21[4] = CONCAT214(uVar57,CONCAT212(SUB162(auVar52 >> 0x70,0),
1792: CONCAT210(uVar86,CONCAT28(SUB162(
1793: auVar52 >> 0x60,0),
1794: uVar91 & 0xffff000000000000 |
1795: (ulong)CONCAT24(SUB162((auVar52 &
1796: (undefined  [16])
1797: 0xffffffff00000000) >> 0x50
1798: ,0),
1799: CONCAT22(uVar68,SUB162((auVar52 &
1800: (undefined 
1801: 
1802: [16])0xffffffff00000000) >> 0x40,0)))))));
1803: pauVar21[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
1804: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
1805: (auVar106 >> 0x70,0),
1806: CONCAT212(uVar59,SUB1612(auVar81,0))) >> 0x60,0),
1807: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
1808: CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
1809: (((ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar110 
1810: >> 0x70,0),uVar64)) & 0xffff0000) >> 0x10) << 0x30
1811: ) >> 0x30,0),(SUB166(auVar81,0) >> 0x10) << 0x20)
1812: >> 0x20,0),CONCAT22(uVar64,uVar76));
1813: auVar52 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
1814: uVar56,uVar73),uVar55),CONCAT22(uVar74,uVar73)) >>
1815: 0x10),uVar69),uVar67)) << 0x20;
1816: auVar81 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar56,
1817: uVar73),uVar55),CONCAT22(uVar74,uVar73)) >> 0x10),
1818: uVar69)) << 0x30 &
1819: (undefined  [16])0xffffffff00000000;
1820: pauVar21[5] = CONCAT214(SUB162(auVar115 >> 0x70,0),
1821: CONCAT212(SUB162(auVar71 >> 0x70,0),
1822: CONCAT210(uVar96,CONCAT28(SUB162(auVar71
1823: >> 0x60
1824: ,0),uVar80 & 0xffff000000000000 |
1825: (ulong)CONCAT24(SUB162((auVar71 &
1826: (undefined  [16])
1827: 0xffffffff00000000) >>
1828: 0x50,0),
1829: CONCAT22(uVar79,SUB162((
1830: auVar71 & (undefined  [16])0xffffffff00000000) >>
1831: 0x40,0)))))));
1832: uVar54 = (undefined2)(uVar8 >> 0x20);
1833: uVar75 = (undefined2)(uVar8 >> 0x10);
1834: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1835: CONCAT214(uVar85,CONCAT212(SUB162(auVar52 >> 0x30,
1836: 0),
1837: SUB1612(auVar52,0))) >>
1838: 0x60,0),CONCAT210(uVar54,SUB1610(auVar52,0))) >>
1839: 0x50,0),CONCAT28(uVar67,SUB168(auVar52,0))) >>
1840: 0x40,0),uVar75) & 0xffffffffffffffff) << 0x30;
1841: auVar52 = ZEXT1416(CONCAT122(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
1842: SUB166(CONCAT412(SUB164(CONCAT214(uVar85,CONCAT212
1843: (uVar69,SUB1612(auVar81,0))) >> 0x60,0),
1844: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
1845: CONCAT28(uVar67,SUB168(auVar81,0))) >> 0x40,0),
1846: uVar75)) << 0x30) >> 0x20,0) &
1847: SUB1612((undefined  [16])0xffffffffffffffff >>
1848: 0x20,0),uVar83)) << 0x10;
1849: *(short *)pauVar21[6] =
1850: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
1851: *(undefined2 *)(pauVar21[6] + 2) = uVar12;
1852: *(short *)(pauVar21[6] + 4) =
1853: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
1854: *(undefined2 *)(pauVar21[6] + 6) = uVar62;
1855: *(short *)(pauVar21[6] + 8) = SUB162(auVar70 >> 0x60,0);
1856: *(undefined2 *)(pauVar21[6] + 10) = uVar88;
1857: *(short *)(pauVar21[6] + 0xc) = SUB162(auVar70 >> 0x70,0);
1858: *(undefined2 *)(pauVar21[6] + 0xe) = uVar58;
1859: *(short *)pauVar21[7] =
1860: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
1861: *(undefined2 *)(pauVar21[7] + 2) = uVar73;
1862: *(short *)(pauVar21[7] + 4) =
1863: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
1864: *(undefined2 *)(pauVar21[7] + 6) = uVar99;
1865: *(short *)(pauVar21[7] + 8) = SUB162(auVar71 >> 0x60,0);
1866: *(undefined2 *)(pauVar21[7] + 10) = uVar56;
1867: *(short *)(pauVar21[7] + 0xc) = SUB162(auVar71 >> 0x70,0);
1868: *(undefined2 *)(pauVar21[7] + 0xe) = uVar63;
1869: pauVar21[3] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
1870: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
1871: (auVar92 >> 0x70,0),
1872: CONCAT212(uVar75,SUB1612(auVar52,0))) >> 0x60,0),
1873: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
1874: CONCAT28(SUB162((auVar92 &
1875: (undefined  [16])
1876: 0xffffffff00000000) >> 0x40,0),
1877: SUB168(auVar52,0))) >> 0x40,0),
1878: (((ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar98 
1879: >> 0x70,0),uVar74)) & 0xffff0000) >> 0x10) << 0x30
1880: ) >> 0x30,0),(SUB166(auVar52,0) >> 0x10) << 0x20)
1881: >> 0x20,0),
1882: SUB164((auVar98 &
1883: (undefined  [16])0xffffffff00000000) >>
1884: 0x40,0));
1885: } while (uVar47 != uVar39);
1886: code_r0x0014df2d:
1887: uVar34 = *(uint *)(lVar49 + 0x1c);
1888: uVar20 = (ulong)uVar39;
1889: if (uVar34 <= uVar39) goto code_r0x0014df3c;
1890: }
1891: uVar34 = *(uint *)(lVar49 + 0x1c);
1892: uVar20 = (ulong)(uint)(iVar26 + iVar37);
1893: } while ((uint)(iVar26 + iVar37) < uVar34);
1894: code_r0x0014df3c:
1895: iVar37 = *(int *)(lVar49 + 0xc);
1896: }
1897: auStack248._0_16_ = CONCAT88(auStack248._8_8_,auStack248._0_8_ + 1);
1898: } while (auStack248._0_4_ + 1 < iVar37);
1899: }
1900: uVar27 = uVar27 + iVar37;
1901: } while (uVar27 < *(uint *)(lVar49 + 0x20));
1902: iVar37 = *(int *)(param_2 + 0x4c);
1903: }
1904: auStack280._0_16_ = CONCAT88(auStack280._8_8_,auStack280._0_8_ + 1);
1905: } while (auStack280._0_4_ + 1 < iVar37);
1906: }
1907: break;
1908: case 4:
1909: uVar2 = param_4[0x15];
1910: uVar3 = param_4[0x14];
1911: iVar37 = *(int *)(param_2 + 0x138);
1912: uVar27 = *(uint *)(param_1 + 0x8c);
1913: iVar16 = *(int *)(param_2 + 0x13c);
1914: uVar34 = *(uint *)(param_1 + 0x88);
1915: iVar43 = *(int *)(param_2 + 0x4c);
1916: if (0 < iVar43) {
1917: lStack200 = 0;
1918: do {
1919: lVar49 = lStack200 * 0x60 + *(long *)(param_2 + 0x58);
1920: uVar35 = (uVar27 / (uint)(iVar37 * 8)) * *(int *)(lVar49 + 8);
1921: iVar26 = *(int *)(lVar49 + 8) * uVar3;
1922: iVar33 = uVar2 * *(int *)(lVar49 + 0xc);
1923: uVar39 = (uVar34 / (uint)(iVar16 * 8)) * *(int *)(lVar49 + 0xc);
1924: if (*(int *)(lVar49 + 0x20) != 0) {
1925: uVar47 = 0;
1926: do {
1927: lVar22 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
1928: (param_1,*(undefined8 *)(lVar51 + lStack200 * 8),uVar47);
1929: iVar43 = *(int *)(lVar49 + 0xc);
1930: if (0 < iVar43) {
1931: uVar50 = *(uint *)(lVar49 + 0x1c);
1932: auStack152._0_16_ = auStack152._0_16_ & (undefined  [16])0xffffffffffffffff;
1933: uVar40 = iVar33 + uVar47;
1934: uStack120 = uStack120 & 0xffffffff00000000 |
1935: (ulong)(((uVar39 - iVar33) + -1) - uVar47);
1936: do {
1937: iVar41 = SUB164(auStack152._0_16_,0);
1938: if (uVar50 != 0) {
1939: uVar20 = 0;
1940: iVar43 = *(int *)(lVar49 + 8);
1941: auStack248._0_16_ =
1942: CONCAT88(auStack248._8_8_,uStack120) & (undefined  [16])0xffffffffffffffff;
1943: auStack248._0_8_ = auStack248._0_8_ * 0x80;
1944: lVar17 = (ulong)(uVar40 + iVar41) * 0x80;
1945: do {
1946: while( true ) {
1947: iVar42 = (int)uVar20;
1948: uVar50 = iVar42 + iVar26;
1949: if (uVar35 <= uVar50) break;
1950: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
1951: (param_1,*(undefined8 *)
1952: (param_3 + lStack200 * 8),
1953: ((uVar35 - iVar26) - iVar42) - iVar43);
1954: iVar43 = *(int *)(lVar49 + 8);
1955: if (iVar43 < 1) goto code_r0x0014d8b6;
1956: code_r0x0014ce87:
1957: lVar18 = *(long *)(lVar22 + auStack152._0_8_ * 8);
1958: uVar46 = iVar42 + iVar43;
1959: plVar30 = plVar23 + (long)iVar43 + -1;
1960: do {
1961: while( true ) {
1962: pauVar24 = (undefined (*) [16])(uVar20 * 0x80 + lVar18);
1963: if (uVar39 <= uVar40) break;
1964: if (uVar50 < uVar35) {
1965: iVar42 = 4;
1966: puVar45 = (undefined2 *)(auStack248._0_8_ + *plVar30);
1967: do {
1968: *(undefined2 *)*pauVar24 = *puVar45;
1969: *(undefined2 *)pauVar24[1] = -puVar45[1];
1970: *(undefined2 *)pauVar24[2] = puVar45[2];
1971: *(undefined2 *)pauVar24[3] = -puVar45[3];
1972: *(undefined2 *)pauVar24[4] = puVar45[4];
1973: *(undefined2 *)pauVar24[5] = -puVar45[5];
1974: *(undefined2 *)pauVar24[6] = puVar45[6];
1975: *(undefined2 *)pauVar24[7] = -puVar45[7];
1976: *(undefined2 *)(*pauVar24 + 2) = -puVar45[8];
1977: *(undefined2 *)(pauVar24[1] + 2) = puVar45[9];
1978: *(undefined2 *)(pauVar24[2] + 2) = -puVar45[10];
1979: *(undefined2 *)(pauVar24[3] + 2) = puVar45[0xb];
1980: *(undefined2 *)(pauVar24[4] + 2) = -puVar45[0xc];
1981: *(undefined2 *)(pauVar24[5] + 2) = puVar45[0xd];
1982: *(undefined2 *)(pauVar24[6] + 2) = -puVar45[0xe];
1983: *(undefined2 *)(pauVar24[7] + 2) = puVar45[0xf];
1984: iVar42 = iVar42 + -1;
1985: pauVar24 = (undefined (*) [16])(*pauVar24 + 4);
1986: puVar45 = puVar45 + 0x10;
1987: } while (iVar42 != 0);
1988: }
1989: else {
1990: pauVar32 = (undefined (*) [16])(auStack248._0_8_ + *plVar23);
1991: pauVar21 = pauVar32[8];
1992: if (((((((pauVar32 < pauVar24[7] && pauVar24[6] < pauVar21 ||
1993: pauVar32 < pauVar24[8] && pauVar24[7] < pauVar21) ||
1994: pauVar32 < pauVar24[6] && pauVar24[5] < pauVar21) ||
1995: pauVar32 < pauVar24[5] && pauVar24[4] < pauVar21) ||
1996: pauVar32 < pauVar24[4] && pauVar24[3] < pauVar21) ||
1997: pauVar32 < pauVar24[3] && pauVar24[2] < pauVar21) ||
1998: pauVar32 < pauVar24[2] && pauVar24[1] < pauVar21) ||
1999: (pauVar32 < pauVar24[1] && pauVar24 < pauVar21)) {
2000: iVar42 = 8;
2001: do {
2002: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
2003: *(short *)pauVar24[1] = -*(short *)(*pauVar32 + 2);
2004: *(undefined2 *)pauVar24[2] = *(undefined2 *)(*pauVar32 + 4);
2005: *(short *)pauVar24[3] = -*(short *)(*pauVar32 + 6);
2006: *(undefined2 *)pauVar24[4] = *(undefined2 *)(*pauVar32 + 8);
2007: *(short *)pauVar24[5] = -*(short *)(*pauVar32 + 10);
2008: *(undefined2 *)pauVar24[6] = *(undefined2 *)(*pauVar32 + 0xc);
2009: *(short *)pauVar24[7] = -*(short *)(*pauVar32 + 0xe);
2010: iVar42 = iVar42 + -1;
2011: pauVar24 = (undefined (*) [16])(*pauVar24 + 2);
2012: pauVar32 = pauVar32[1];
2013: } while (iVar42 != 0);
2014: }
2015: else {
2016: auVar71 = *pauVar32;
2017: uVar5 = *(ushort *)pauVar32[1];
2018: uVar75 = *(undefined2 *)(pauVar32[1] + 2);
2019: uVar54 = *(undefined2 *)(pauVar32[1] + 4);
2020: uVar55 = *(undefined2 *)(pauVar32[1] + 8);
2021: uVar12 = *(undefined2 *)(pauVar32[1] + 0xc);
2022: sVar1 = *(short *)(pauVar32[1] + 0xe);
2023: auVar52 = pauVar32[2];
2024: uVar94 = SUB162(auVar71 >> 0x30,0);
2025: uVar93 = SUB162(auVar71 >> 0x20,0);
2026: uVar114 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2027: (pauVar32[1] + 6),
2028: CONCAT212(uVar94,SUB1612
2029: (auVar71,0))) >> 0x60,0),
2030: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0);
2031: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar114,CONCAT28(uVar93
2032: ,SUB168(auVar71,0))) >> 0x40,0),uVar75)) << 0x30 &
2033: (undefined  [16])0xffffffff00000000;
2034: uVar56 = SUB162(auVar71 >> 0x40,0);
2035: uVar62 = SUB162(auVar71 >> 0x50,0);
2036: uVar60 = SUB162(auVar71 >> 0x70,0);
2037: uVar73 = *(undefined2 *)pauVar32[3];
2038: uVar72 = *(undefined2 *)(pauVar32[3] + 4);
2039: uVar74 = *(undefined2 *)(pauVar32[3] + 6);
2040: uVar83 = *(undefined2 *)(pauVar32[3] + 0xc);
2041: sVar11 = *(short *)(pauVar32[3] + 0xe);
2042: uVar99 = SUB162(auVar71 >> 0x10,0);
2043: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2044: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2045: (pauVar32[1] + 6),
2046: CONCAT212(uVar94,
2047: SUB1612(auVar71,0))) >> 0x60,0),
2048: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
2049: CONCAT28(uVar93,SUB168(auVar71,0))) >> 0x40,0),
2050: uVar75),uVar99)) << 0x20;
2051: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2052: (CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
2053: CONCAT212(uVar75,SUB1612(auVar70,0)))
2054: >> 0x60,0),CONCAT210(uVar62,SUB1610(auVar70,0)))
2055: >> 0x50,0),CONCAT28(uVar99,SUB168(auVar70,0))) >>
2056: 0x40,0),uVar55)) << 0x30 &
2057: (undefined  [16])0xffffffff00000000;
2058: auVar70 = pauVar32[4];
2059: uVar67 = SUB162(auVar52 >> 0x30,0);
2060: uVar66 = SUB162(auVar52 >> 0x20,0);
2061: uVar36 = SUB164(auVar52,0) & 0xffff;
2062: auVar97 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2063: (CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
2064: CONCAT212(SUB162(auVar81 >> 0x30,0),
2065: SUB1612(auVar81,0))) >> 0x60,
2066: 0),CONCAT210(uVar62,SUB1610(auVar81,0))) >> 0x50,
2067: 0),CONCAT28(uVar99,SUB168(auVar81,0))) >> 0x40,0),
2068: uVar55)) << 0x30;
2069: uVar58 = SUB162(auVar52 >> 0x10,0);
2070: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2071: CONCAT412(SUB164(CONCAT214(uVar74,CONCAT212(uVar67
2072: ,SUB1612(auVar52,0))) >> 0x60,0),
2073: CONCAT210(uVar72,SUB1610(auVar52,0))) >> 0x50,0),
2074: CONCAT28(uVar66,SUB168(auVar52,0))) >> 0x40,0),
2075: *(undefined2 *)(pauVar32[3] + 2)),uVar58)) << 0x20
2076: ;
2077: uVar57 = SUB162(auVar52 >> 0x40,0);
2078: uVar59 = SUB162(auVar52 >> 0x60,0);
2079: uVar61 = SUB162(auVar52 >> 0x70,0);
2080: uVar75 = *(undefined2 *)pauVar32[5];
2081: uVar62 = *(undefined2 *)(pauVar32[5] + 2);
2082: uVar99 = *(undefined2 *)(pauVar32[5] + 4);
2083: uVar64 = *(undefined2 *)(pauVar32[5] + 8);
2084: uVar87 = *(undefined2 *)(pauVar32[5] + 0xc);
2085: sVar13 = *(short *)(pauVar32[5] + 0xe);
2086: uVar113 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,
2087: CONCAT212(uVar55,SUB1612(auVar82,0))) >> 0x60,0),
2088: CONCAT210(uVar54,SUB1610(auVar82,0))) >> 0x50,0),
2089: CONCAT28(uVar5,SUB168(auVar82,0))) >> 0x40,0);
2090: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),
2091: uVar93)) & 0xffff0000;
2092: auVar98 = CONCAT88(uVar113,(uVar6 >> 0x10) << 0x30) &
2093: (undefined  [16])0xffff000000000000;
2094: uVar84 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >>
2095: 0x50,0);
2096: sVar103 = SUB162(auVar97 >> 0x60,0);
2097: uVar90 = SUB162(auVar70 >> 0x30,0);
2098: uVar85 = SUB162(auVar70 >> 0x20,0);
2099: uVar109 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2100: (pauVar32[5] + 6),
2101: CONCAT212(uVar90,SUB1612
2102: (auVar70,0))) >> 0x60,0),
2103: CONCAT210(uVar99,SUB1610(auVar70,0))) >> 0x50,0);
2104: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar109,CONCAT28(uVar85
2105: ,SUB168(auVar70,0))) >> 0x40,0),uVar62)) << 0x30 &
2106: (undefined  [16])0xffffffff00000000;
2107: auVar81 = pauVar32[6];
2108: uVar86 = *(undefined2 *)(pauVar32[7] + 8);
2109: uVar88 = *(undefined2 *)(pauVar32[7] + 0xc);
2110: sVar77 = *(short *)(pauVar32[7] + 0xe);
2111: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2112: SUB164(CONCAT214(*(undefined2 *)(pauVar32[3] + 10)
2113: ,CONCAT212(SUB162(auVar92 >> 0x30
2114: ,0),
2115: SUB1612(auVar92,0)))
2116: >> 0x60,0),
2117: CONCAT210(SUB162(auVar52 >> 0x50,0),
2118: SUB1610(auVar92,0))) >> 0x50,0),
2119: CONCAT28(uVar58,SUB168(auVar92,0))) >> 0x40,0),
2120: *(undefined2 *)(pauVar32[3] + 8))) << 0x30;
2121: uVar79 = SUB162(auVar70 >> 0x10,0);
2122: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2123: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2124: (pauVar32[5] + 6),
2125: CONCAT212(uVar90,
2126: SUB1612(auVar70,0))) >> 0x60,0),
2127: CONCAT210(uVar99,SUB1610(auVar70,0))) >> 0x50,0),
2128: CONCAT28(uVar85,SUB168(auVar70,0))) >> 0x40,0),
2129: uVar62),uVar79)) << 0x20;
2130: uVar58 = SUB162(auVar70 >> 0x40,0);
2131: uVar63 = SUB162(auVar70 >> 0x50,0);
2132: uVar65 = SUB162(auVar70 >> 0x70,0);
2133: sVar125 = SUB162((auVar116 & (undefined  [16])0xffffffff00000000) >>
2134: 0x40,0);
2135: uVar105 = SUB162((auVar116 & (undefined  [16])0xffffffff00000000) >>
2136: 0x50,0);
2137: sVar128 = SUB162(auVar116 >> 0x70,0);
2138: uVar68 = SUB162(auVar81 >> 0x40,0);
2139: uVar69 = SUB162(auVar81 >> 0x60,0);
2140: uVar76 = SUB162(auVar81 >> 0x70,0);
2141: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2142: (CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
2143: CONCAT212(uVar62,SUB1612(auVar82,0)))
2144: >> 0x60,0),CONCAT210(uVar63,SUB1610(auVar82,0)))
2145: >> 0x50,0),CONCAT28(uVar79,SUB168(auVar82,0))) >>
2146: 0x40,0),uVar64)) << 0x30 &
2147: (undefined  [16])0xffffffff00000000;
2148: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2149: (CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
2150: CONCAT212(SUB162(auVar52 >> 0x30,0),
2151: SUB1612(auVar52,0))) >> 0x60,
2152: 0),CONCAT210(uVar63,SUB1610(auVar52,0))) >> 0x50,
2153: 0),CONCAT28(uVar79,SUB168(auVar52,0))) >> 0x40,0),
2154: uVar64)) << 0x30;
2155: uVar102 = SUB162(auVar81 >> 0x30,0);
2156: uVar100 = SUB162(auVar81 >> 0x20,0);
2157: uVar96 = SUB162(auVar81 >> 0x10,0);
2158: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2159: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2160: (pauVar32[7] + 6),
2161: CONCAT212(uVar102,
2162: SUB1612(auVar81,0))) >> 0x60,0),
2163: CONCAT210(*(undefined2 *)(pauVar32[7] + 4),
2164: SUB1610(auVar81,0))) >> 0x50,0),
2165: CONCAT28(uVar100,SUB168(auVar81,0))) >> 0x40,0),
2166: *(undefined2 *)(pauVar32[7] + 2)),uVar96)) << 0x20
2167: ;
2168: uVar62 = SUB162(auVar81,0);
2169: uVar7 = (ulong)CONCAT24(uVar99,CONCAT22(SUB162(auVar70 >> 0x60,0),
2170: uVar85)) & 0xffff0000;
2171: auVar92 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2172: CONCAT214(uVar87,CONCAT212(uVar64,SUB1612(auVar92,
2173: 0))) >> 0x60,0),
2174: CONCAT210(uVar99,SUB1610(auVar92,0))) >> 0x50,0),
2175: CONCAT28(uVar75,SUB168(auVar92,0))) >> 0x40,0),
2176: (uVar7 >> 0x10) << 0x30) &
2177: (undefined  [16])0xffff000000000000;
2178: uVar79 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >>
2179: 0x50,0);
2180: sVar89 = SUB162(auVar82 >> 0x60,0);
2181: sVar95 = SUB162(auVar82 >> 0x70,0);
2182: uVar63 = (undefined2)(uVar6 >> 0x10);
2183: uVar10 = SUB166(CONCAT412(SUB164(CONCAT214(uVar59,CONCAT212(uVar63,
2184: SUB1612(auVar98,0))) >> 0x60,0),
2185: CONCAT210(uVar57,SUB1610(auVar98,0))) >> 0x50,0);
2186: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar10,CONCAT28(uVar56,
2187: SUB168(auVar98,0))) >> 0x40,0),uVar66) &
2188: SUB1610((undefined  [16])0xffffffffffffffff >>
2189: 0x30,0)) << 0x30 &
2190: (undefined  [16])0xffffffff00000000;
2191: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2192: SUB164(CONCAT214(*(undefined2 *)(pauVar32[7] + 10)
2193: ,CONCAT212(SUB162(auVar106 >>
2194: 0x30,0),
2195: SUB1612(auVar106,0)))
2196: >> 0x60,0),
2197: CONCAT210(SUB162(auVar81 >> 0x50,0),
2198: SUB1610(auVar106,0))) >> 0x50,0),
2199: CONCAT28(uVar96,SUB168(auVar106,0))) >> 0x40,0),
2200: uVar86)) << 0x30;
2201: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2202: CONCAT412(SUB164(CONCAT214(uVar59,CONCAT212(uVar63
2203: ,SUB1612(auVar98,0))) >> 0x60,0),
2204: CONCAT210(uVar57,SUB1610(auVar98,0))) >> 0x50,0),
2205: CONCAT28(uVar56,SUB168(auVar98,0))) >> 0x40,0),
2206: uVar66) & SUB1610((undefined  [16])
2207: 0xffffffffffffffff >> 0x30,0),
2208: uVar93)) << 0x20;
2209: sVar121 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
2210: 0x40,0);
2211: uVar96 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
2212: 0x50,0);
2213: auVar110 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2214: SUB164(CONCAT214(uVar72,CONCAT212(SUB162(auVar81 
2215: >> 0x30,0),SUB1612(auVar81,0))) >> 0x60,0),
2216: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
2217: CONCAT28(uVar93,SUB168(auVar81,0))) >> 0x40,0),
2218: uVar73)) << 0x30;
2219: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2220: (CONCAT214(uVar72,CONCAT212(uVar66,SUB1612(auVar52
2221: ,0))) >> 0x60,0),
2222: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
2223: CONCAT28(uVar93,SUB168(auVar52,0))) >> 0x40,0),
2224: uVar73)) << 0x30 &
2225: (undefined  [16])0xffffffff00000000;
2226: uVar54 = (undefined2)(uVar7 >> 0x10);
2227: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2228: CONCAT412(SUB164(CONCAT214(uVar69,CONCAT212(uVar54
2229: ,SUB1612(auVar92,0))) >> 0x60,0),
2230: CONCAT210(uVar68,SUB1610(auVar92,0))) >> 0x50,0),
2231: CONCAT28(uVar58,SUB168(auVar92,0))) >> 0x40,0),
2232: uVar100) &
2233: SUB1610((undefined  [16])0xffffffffffffffff >>
2234: 0x30,0),uVar85)) << 0x20;
2235: uVar80 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
2236: undefined2 *)(pauVar32[3] + 8),
2237: CONCAT212(uVar73,SUB1612(auVar52,0))) >> 0x60,0),
2238: CONCAT210(uVar57,SUB1610(auVar52,0))) >> 0x50,0),
2239: CONCAT28((short)uVar36,SUB168(auVar52,0))) >> 0x40
2240: ,0);
2241: uVar6 = (ulong)CONCAT24(uVar57,CONCAT22(uVar55,uVar56)) & 0xffff0000
2242: ;
2243: auVar81 = CONCAT88(uVar80,(uVar6 >> 0x10) << 0x30) &
2244: (undefined  [16])0xffff000000000000;
2245: uVar66 = SUB162((auVar110 & (undefined  [16])0xffffffff00000000) >>
2246: 0x40,0);
2247: uVar7 = (ulong)CONCAT24(SUB162((auVar110 &
2248: (undefined  [16])0xffffffff00000000)
2249: >> 0x50,0),CONCAT22(uVar63,uVar66));
2250: uVar93 = SUB162(auVar110 >> 0x60,0);
2251: Var14 = CONCAT28(uVar93,uVar113);
2252: auVar106 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2253: SUB164(CONCAT214(*(undefined2 *)(pauVar32[7] + 4),
2254: CONCAT212(SUB162(auVar92 >> 0x30,
2255: 0),
2256: SUB1612(auVar92,0))) >>
2257: 0x60,0),
2258: CONCAT210(uVar99,SUB1610(auVar92,0))) >> 0x50,0),
2259: CONCAT28(uVar85,SUB168(auVar92,0))) >> 0x40,0),
2260: *(undefined2 *)pauVar32[7])) << 0x30;
2261: uVar8 = (ulong)(uVar114 & 0xffff00000000 |
2262: (uint6)CONCAT22(SUB162(auVar116 >> 0x60,0),sVar103));
2263: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(
2264: CONCAT22(uVar61,uVar60),uVar105),
2265: CONCAT22(uVar84,uVar60)) >> 0x10),uVar67),uVar94))
2266: << 0x20;
2267: uVar25 = CONCAT22(uVar61,uVar60);
2268: auVar52 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar25,uVar105)
2269: ,CONCAT22(uVar84,uVar60)
2270: ) >> 0x10),uVar67)) <<
2271: 0x30 & (undefined  [16])0xffffffff00000000;
2272: uVar55 = SUB162((auVar106 & (undefined  [16])0xffffffff00000000) >>
2273: 0x40,0);
2274: uVar9 = (ulong)CONCAT24(SUB162((auVar106 &
2275: (undefined  [16])0xffffffff00000000)
2276: >> 0x50,0),CONCAT22(uVar54,uVar55));
2277: uVar54 = (undefined2)(uVar8 >> 0x20);
2278: sVar53 = (short)(uVar8 >> 0x10);
2279: auVar98 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2280: (CONCAT214(uVar74,CONCAT212(SUB162(auVar92 >> 0x30
2281: ,0),
2282: SUB1612(auVar92,0)))
2283: >> 0x60,0),CONCAT210(uVar54,SUB1610(auVar92,0)))
2284: >> 0x50,0),CONCAT28(uVar94,SUB168(auVar92,0))) >>
2285: 0x40,0),sVar53) & 0xffffffffffffffff) << 0x30;
2286: auVar52 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
2287: SUB166(CONCAT412(SUB164(CONCAT214(uVar74,CONCAT212
2288: (uVar67,SUB1612(auVar52,0))) >> 0x60,0),
2289: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
2290: CONCAT28(uVar94,SUB168(auVar52,0))) >> 0x40,0),
2291: sVar53)) << 0x30) >> 0x20,0) &
2292: SUB1612((undefined  [16])0xffffffffffffffff >>
2293: 0x20,0)) << 0x20;
2294: uVar8 = (ulong)(uVar109 & 0xffff00000000 |
2295: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),sVar89));
2296: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(
2297: CONCAT22(uVar76,uVar65),uVar96),
2298: CONCAT22(uVar79,uVar65)) >> 0x10),uVar102),uVar90)
2299: ) << 0x20;
2300: uVar74 = (undefined2)(uVar6 >> 0x10);
2301: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2302: SUB164(CONCAT214(uVar64,CONCAT212(uVar74,SUB1612(
2303: auVar81,0))) >> 0x60,0),
2304: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
2305: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
2306: uVar58) & SUB1610((undefined  [16])
2307: 0xffffffffffffffff >> 0x30,0))
2308: << 0x30 & (undefined  [16])0xffffffff00000000;
2309: uVar6 = (ulong)CONCAT24(uVar105,CONCAT22(SUB162(auVar97 >> 0x70,0),
2310: uVar84)) & 0xffff0000;
2311: auVar52 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2312: CONCAT214(sVar128,CONCAT212(sVar53,SUB1612(auVar52
2313: ,0))) >> 0x60,0),
2314: CONCAT210(uVar105,SUB1610(auVar52,0))) >> 0x50,0),
2315: CONCAT28(sVar125,SUB168(auVar52,0))) >> 0x40,0),
2316: (uVar6 >> 0x10) << 0x30) &
2317: (undefined  [16])0xffff000000000000;
2318: sVar101 = SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >>
2319: 0x50,0);
2320: sVar104 = SUB162(auVar98 >> 0x60,0);
2321: auVar116 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
2322: SUB166(CONCAT412(SUB164(CONCAT214(uVar68,CONCAT212
2323: (uVar58,SUB1612(auVar116,0))) >> 0x60,0),
2324: CONCAT210(uVar57,SUB1610(auVar116,0))) >> 0x50,0),
2325: CONCAT28(uVar56,SUB168(auVar116,0))) >> 0x40,0),
2326: uVar62)) << 0x30) >> 0x20,0) &
2327: SUB1612((undefined  [16])0xffffffffffffffff >>
2328: 0x20,0),uVar36 << 0x10);
2329: sVar124 = (short)(uVar8 >> 0x10);
2330: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2331: (CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
2332: CONCAT212(SUB162(auVar92 >> 0x30,0),
2333: SUB1612(auVar92,0))) >> 0x60,
2334: 0),CONCAT210((short)(uVar8 >> 0x20),
2335: SUB1610(auVar92,0))) >> 0x50,0),
2336: CONCAT28(uVar90,SUB168(auVar92,0))) >> 0x40,0),
2337: sVar124) & 0xffffffffffffffff) << 0x30;
2338: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
2339: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
2340: undefined2 *)pauVar32[7],
2341: CONCAT212(uVar62,SUB1612(auVar116,0))) >> 0x60,0),
2342: CONCAT210(uVar75,SUB1610(auVar116,0))) >> 0x50,0),
2343: CONCAT28(SUB162(auVar70,0),SUB168(auVar116,0))) >>
2344: 0x40,0),(((ulong)CONCAT24(uVar75,CONCAT22(uVar73,
2345: uVar5)) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0)
2346: & SUB1610((undefined  [16])0xffffffffffffffff >>
2347: 0x30,0) &
2348: SUB1610((undefined  [16])0xffffffffffffffff >>
2349: 0x30,0),
2350: (SUB166(auVar116,0) >> 0x10) << 0x20) >> 0x20,0),
2351: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
2352: sVar119 = (short)(uVar6 >> 0x10);
2353: sVar78 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >>
2354: 0x50,0);
2355: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2356: CONCAT412(SUB164(CONCAT214(sVar95,CONCAT212(
2357: sVar119,SUB1612(auVar52,0))) >> 0x60,0),
2358: CONCAT210(sVar89,SUB1610(auVar52,0))) >> 0x50,0),
2359: CONCAT28(sVar103,SUB168(auVar52,0))) >> 0x40,0),
2360: uVar79) & SUB1610((undefined  [16])
2361: 0xffffffffffffffff >> 0x30,0),
2362: uVar84)) << 0x20;
2363: uVar6 = (ulong)(uVar10 & 0xffff00000000 |
2364: (uint6)CONCAT22(SUB162(auVar106 >> 0x60,0),uVar93));
2365: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2366: (CONCAT214(uVar96,CONCAT212(SUB162(auVar71 >> 0x30
2367: ,0),
2368: SUB1612(auVar71,0)))
2369: >> 0x60,0),CONCAT210(uVar105,SUB1610(auVar71,0)))
2370: >> 0x50,0),CONCAT28(uVar84,SUB168(auVar71,0))) >>
2371: 0x40,0),sVar121)) << 0x30;
2372: uVar8 = (ulong)(((uint6)uVar25 & 0xffff0000) << 0x10 |
2373: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),sVar104));
2374: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2375: CONCAT412(SUB164(CONCAT214(uVar64,CONCAT212(uVar74
2376: ,SUB1612(auVar81,0))) >> 0x60,0),
2377: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
2378: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
2379: uVar58) & SUB1610((undefined  [16])
2380: 0xffffffffffffffff >> 0x30,0),
2381: uVar56)) << 0x20;
2382: uVar54 = (undefined2)(uVar9 >> 0x20);
2383: uVar72 = (undefined2)(uVar7 >> 0x20);
2384: uVar75 = (undefined2)(uVar9 >> 0x10);
2385: uVar73 = (undefined2)(uVar7 >> 0x10);
2386: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
2387: CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212(uVar12
2388: ,CONCAT210(uVar59,Var14))) >> 0x60,0),
2389: CONCAT210(uVar54,Var14)) >> 0x50,0),
2390: CONCAT28(uVar72,uVar113)) >> 0x40,0),uVar75),
2391: uVar73) & (undefined  [12])0xffffffffffffffff) <<
2392: 0x20;
2393: *(short *)pauVar24[1] =
2394: -SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x40
2395: ,0);
2396: *(short *)(pauVar24[1] + 2) = -sVar103;
2397: *(short *)(pauVar24[1] + 4) = -sVar125;
2398: *(short *)(pauVar24[1] + 6) = -sVar53;
2399: *(short *)(pauVar24[1] + 8) =
2400: -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40
2401: ,0);
2402: *(short *)(pauVar24[1] + 10) = -sVar89;
2403: *(short *)(pauVar24[1] + 0xc) = -sVar121;
2404: *(short *)(pauVar24[1] + 0xe) = -sVar124;
2405: auVar82 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
2406: SUB166(CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212
2407: (uVar12,CONCAT210(uVar59,Var14))) >> 0x60,0),
2408: CONCAT210(uVar54,Var14)) >> 0x50,0),
2409: CONCAT28(uVar72,uVar113)) >> 0x40,0),uVar75) &
2410: 0xffffffffffffffff) << 0x30) >> 0x20,0) &
2411: SUB1612((undefined  [16])0xffffffffffffffff >>
2412: 0x20,0)) << 0x20;
2413: uVar58 = (undefined2)(uVar6 >> 0x20);
2414: uVar99 = (undefined2)(uVar6 >> 0x10);
2415: auVar81 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2416: (CONCAT214(uVar69,CONCAT212(SUB162(auVar70 >> 0x30
2417: ,0),
2418: SUB1612(auVar70,0)))
2419: >> 0x60,0),CONCAT210(uVar58,SUB1610(auVar70,0)))
2420: >> 0x50,0),CONCAT28(uVar73,SUB168(auVar70,0))) >>
2421: 0x40,0),uVar99) & 0xffffffffffffffff) << 0x30;
2422: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2423: (CONCAT214(uVar68,CONCAT212(SUB162(auVar52 >> 0x30
2424: ,0),
2425: SUB1612(auVar52,0)))
2426: >> 0x60,0),CONCAT210(uVar57,SUB1610(auVar52,0)))
2427: >> 0x50,0),CONCAT28(uVar56,SUB168(auVar52,0))) >>
2428: 0x40,0),uVar62) & 0xffffffffffffffff) << 0x30;
2429: auVar70 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
2430: SUB166(CONCAT412(SUB164(CONCAT214(uVar69,CONCAT212
2431: (uVar75,SUB1612(auVar82,0))) >> 0x60,0),
2432: CONCAT210(uVar58,SUB1610(auVar82,0))) >> 0x50,0),
2433: CONCAT28(uVar63,SUB168(auVar82,0))) >> 0x40,0),
2434: uVar99)) << 0x30) >> 0x20,0) &
2435: SUB1612((undefined  [16])0xffffffffffffffff >>
2436: 0x20,0),CONCAT22(uVar93,uVar66));
2437: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
2438: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
2439: (auVar106 >> 0x70,0),
2440: CONCAT212(uVar99,SUB1612(auVar70,0))) >> 0x60,0),
2441: CONCAT210(uVar54,SUB1610(auVar70,0))) >> 0x50,0),
2442: CONCAT28(uVar55,SUB168(auVar70,0))) >> 0x40,0),
2443: (((ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar110 
2444: >> 0x70,0),uVar72)) & 0xffff0000) >> 0x10) << 0x30
2445: ) >> 0x30,0),(SUB166(auVar70,0) >> 0x10) << 0x20)
2446: >> 0x20,0),CONCAT22(uVar72,uVar66));
2447: auVar70 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(
2448: CONCAT22(sVar13,sVar1),sVar78),
2449: CONCAT22(sVar101,sVar1)) >> 0x10),uVar65),uVar60))
2450: << 0x20;
2451: *(short *)pauVar24[5] =
2452: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40
2453: ,0);
2454: *(short *)(pauVar24[5] + 2) = -sVar119;
2455: *(short *)(pauVar24[5] + 4) =
2456: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50
2457: ,0);
2458: *(short *)(pauVar24[5] + 6) = -sVar128;
2459: *(short *)(pauVar24[5] + 8) = -SUB162(auVar71 >> 0x60,0);
2460: *(short *)(pauVar24[5] + 10) = -sVar95;
2461: *(short *)(pauVar24[5] + 0xc) = -SUB162(auVar71 >> 0x70,0);
2462: *(short *)(pauVar24[5] + 0xe) = -SUB162(auVar115 >> 0x70,0);
2463: sVar53 = (short)(uVar8 >> 0x10);
2464: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
2465: (CONCAT214(uVar76,CONCAT212(SUB162(auVar70 >> 0x30
2466: ,0),
2467: SUB1612(auVar70,0)))
2468: >> 0x60,0),
2469: CONCAT210((short)(uVar8 >> 0x20),
2470: SUB1610(auVar70,0))) >> 0x50,0),
2471: CONCAT28(uVar60,SUB168(auVar70,0))) >> 0x40,0),
2472: sVar53) & 0xffffffffffffffff) << 0x30;
2473: pauVar24[4] = CONCAT214(uVar86,CONCAT212(SUB162(auVar52 >> 0x70,0),
2474: CONCAT210(uVar64,CONCAT28(
2475: SUB162(auVar52 >> 0x60,0),
2476: uVar80 & 0xffff000000000000 |
2477: (ulong)CONCAT24(SUB162((auVar52 &
2478: (undefined  [16])
2479: 0xffffffff00000000) >> 0x50
2480: ,0),
2481: CONCAT22(uVar74,SUB162((auVar52 &
2482: (undefined 
2483: 
2484: [16])0xffffffff00000000) >> 0x40,0)))))));
2485: *(short *)pauVar24[6] =
2486: SUB162((auVar81 & (undefined  [16])0xffffffff00000000) >> 0x40,
2487: 0);
2488: *(undefined2 *)(pauVar24[6] + 2) = uVar12;
2489: *(short *)(pauVar24[6] + 4) =
2490: SUB162((auVar81 & (undefined  [16])0xffffffff00000000) >> 0x50,
2491: 0);
2492: *(undefined2 *)(pauVar24[6] + 6) = uVar83;
2493: *(short *)(pauVar24[6] + 8) = SUB162(auVar81 >> 0x60,0);
2494: *(undefined2 *)(pauVar24[6] + 10) = uVar87;
2495: *(short *)(pauVar24[6] + 0xc) = SUB162(auVar81 >> 0x70,0);
2496: *(undefined2 *)(pauVar24[6] + 0xe) = uVar88;
2497: *(short *)pauVar24[3] =
2498: -SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >> 0x40
2499: ,0);
2500: *(short *)(pauVar24[3] + 2) = -sVar101;
2501: *(short *)(pauVar24[3] + 4) = -sVar104;
2502: *(short *)(pauVar24[3] + 6) = -SUB162(auVar98 >> 0x70,0);
2503: *(short *)(pauVar24[3] + 8) =
2504: -SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x40
2505: ,0);
2506: *(short *)(pauVar24[3] + 10) = -sVar78;
2507: *(short *)(pauVar24[3] + 0xc) = -sVar53;
2508: *(short *)(pauVar24[3] + 0xe) = -SUB162(auVar92 >> 0x70,0);
2509: *(short *)pauVar24[7] =
2510: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40
2511: ,0);
2512: *(short *)(pauVar24[7] + 2) = -sVar1;
2513: *(short *)(pauVar24[7] + 4) =
2514: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50
2515: ,0);
2516: *(short *)(pauVar24[7] + 6) = -sVar11;
2517: *(short *)(pauVar24[7] + 8) = -SUB162(auVar71 >> 0x60,0);
2518: *(short *)(pauVar24[7] + 10) = -sVar13;
2519: *(short *)(pauVar24[7] + 0xc) = -SUB162(auVar71 >> 0x70,0);
2520: *(short *)(pauVar24[7] + 0xe) = -sVar77;
2521: }
2522: }
2523: joined_r0x0014d4ca:
2524: uVar36 = (int)uVar20 + 1;
2525: uVar20 = (ulong)uVar36;
2526: plVar30 = plVar30 + -1;
2527: plVar23 = plVar23 + 1;
2528: if (uVar36 == uVar46) goto code_r0x0014cf9a;
2529: }
2530: if (uVar50 < uVar35) {
2531: iVar42 = 4;
2532: puVar45 = (undefined2 *)(lVar17 + *plVar30);
2533: do {
2534: *(undefined2 *)*pauVar24 = *puVar45;
2535: *(undefined2 *)pauVar24[1] = puVar45[1];
2536: *(undefined2 *)pauVar24[2] = puVar45[2];
2537: *(undefined2 *)pauVar24[3] = puVar45[3];
2538: *(undefined2 *)pauVar24[4] = puVar45[4];
2539: *(undefined2 *)pauVar24[5] = puVar45[5];
2540: *(undefined2 *)pauVar24[6] = puVar45[6];
2541: *(undefined2 *)pauVar24[7] = puVar45[7];
2542: *(undefined2 *)(*pauVar24 + 2) = -puVar45[8];
2543: *(undefined2 *)(pauVar24[1] + 2) = -puVar45[9];
2544: *(undefined2 *)(pauVar24[2] + 2) = -puVar45[10];
2545: *(undefined2 *)(pauVar24[3] + 2) = -puVar45[0xb];
2546: *(undefined2 *)(pauVar24[4] + 2) = -puVar45[0xc];
2547: *(undefined2 *)(pauVar24[5] + 2) = -puVar45[0xd];
2548: *(undefined2 *)(pauVar24[6] + 2) = -puVar45[0xe];
2549: *(undefined2 *)(pauVar24[7] + 2) = -puVar45[0xf];
2550: iVar42 = iVar42 + -1;
2551: pauVar24 = (undefined (*) [16])(*pauVar24 + 4);
2552: puVar45 = puVar45 + 0x10;
2553: } while (iVar42 != 0);
2554: goto joined_r0x0014d4ca;
2555: }
2556: pauVar32 = (undefined (*) [16])(lVar17 + *plVar23);
2557: pauVar21 = pauVar32[8];
2558: if ((((((((pauVar24[7] <= pauVar32 || pauVar21 <= pauVar24[6]) &&
2559: (pauVar24[8] <= pauVar32 || pauVar21 <= pauVar24[7])) &&
2560: (pauVar24[6] <= pauVar32 || pauVar21 <= pauVar24[5])) &&
2561: (pauVar24[5] <= pauVar32 || pauVar21 <= pauVar24[4])) &&
2562: (pauVar24[4] <= pauVar32 || pauVar21 <= pauVar24[3])) &&
2563: (pauVar24[3] <= pauVar32 || pauVar21 <= pauVar24[2])) &&
2564: (pauVar24[2] <= pauVar32 || pauVar21 <= pauVar24[1])) &&
2565: (pauVar24[1] <= pauVar32 || pauVar21 <= pauVar24)) {
2566: auVar71 = *pauVar32;
2567: uVar5 = *(ushort *)pauVar32[1];
2568: uVar75 = *(undefined2 *)(pauVar32[1] + 2);
2569: uVar54 = *(undefined2 *)(pauVar32[1] + 4);
2570: uVar55 = *(undefined2 *)(pauVar32[1] + 8);
2571: uVar12 = *(undefined2 *)(pauVar32[1] + 0xc);
2572: uVar73 = *(undefined2 *)(pauVar32[1] + 0xe);
2573: uVar112 = SUB162(auVar71 >> 0x30,0);
2574: uVar111 = SUB162(auVar71 >> 0x20,0);
2575: uVar114 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2576: (pauVar32[1] + 6),
2577: CONCAT212(uVar112,SUB1612(
2578: auVar71,0))) >> 0x60,0),
2579: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0);
2580: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar114,CONCAT28(uVar111,
2581: SUB168(auVar71,0))) >> 0x40,0),uVar75)) << 0x30 &
2582: (undefined  [16])0xffffffff00000000;
2583: auVar52 = pauVar32[2];
2584: uVar59 = SUB162(auVar71 >> 0x40,0);
2585: uVar64 = SUB162(auVar71 >> 0x50,0);
2586: uVar67 = SUB162(auVar71 >> 0x70,0);
2587: uVar87 = SUB162(auVar71 >> 0x10,0);
2588: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2589: SUB164(CONCAT214(*(undefined2 *)(pauVar32[1] + 6),
2590: CONCAT212(uVar112,SUB1612(auVar71
2591: ,0))) >> 0x60,0),
2592: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
2593: CONCAT28(uVar111,SUB168(auVar71,0))) >> 0x40,0),
2594: uVar75),uVar87)) << 0x20;
2595: uVar72 = *(undefined2 *)pauVar32[3];
2596: uVar74 = *(undefined2 *)(pauVar32[3] + 4);
2597: uVar83 = *(undefined2 *)(pauVar32[3] + 6);
2598: uVar62 = *(undefined2 *)(pauVar32[3] + 0xc);
2599: uVar99 = *(undefined2 *)(pauVar32[3] + 0xe);
2600: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2601: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
2602: CONCAT212(uVar75,SUB1612(auVar70,0))) >>
2603: 0x60,0),CONCAT210(uVar64,SUB1610(auVar70,0))) >>
2604: 0x50,0),CONCAT28(uVar87,SUB168(auVar70,0))) >>
2605: 0x40,0),uVar55)) << 0x30 &
2606: (undefined  [16])0xffffffff00000000;
2607: uVar79 = SUB162(auVar52 >> 0x30,0);
2608: uVar76 = SUB162(auVar52 >> 0x20,0);
2609: uVar36 = SUB164(auVar52,0) & 0xffff;
2610: auVar70 = pauVar32[4];
2611: auVar97 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2612: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
2613: CONCAT212(SUB162(auVar81 >> 0x30,0),
2614: SUB1612(auVar81,0))) >> 0x60,0
2615: ),CONCAT210(uVar64,SUB1610(auVar81,0))) >> 0x50,0)
2616: ,CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
2617: uVar55)) << 0x30;
2618: uVar57 = SUB162(auVar52 >> 0x10,0);
2619: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412
2620: (SUB164(CONCAT214(uVar83,CONCAT212(uVar79,SUB1612(
2621: auVar52,0))) >> 0x60,0),
2622: CONCAT210(uVar74,SUB1610(auVar52,0))) >> 0x50,0),
2623: CONCAT28(uVar76,SUB168(auVar52,0))) >> 0x40,0),
2624: *(undefined2 *)(pauVar32[3] + 2)),uVar57)) << 0x20
2625: ;
2626: uVar75 = *(undefined2 *)pauVar32[5];
2627: uVar64 = *(undefined2 *)(pauVar32[5] + 2);
2628: uVar87 = *(undefined2 *)(pauVar32[5] + 4);
2629: uVar86 = *(undefined2 *)(pauVar32[5] + 8);
2630: uVar88 = *(undefined2 *)(pauVar32[5] + 0xc);
2631: uVar56 = *(undefined2 *)(pauVar32[5] + 0xe);
2632: uVar60 = SUB162(auVar52 >> 0x40,0);
2633: uVar66 = SUB162(auVar52 >> 0x60,0);
2634: uVar68 = SUB162(auVar52 >> 0x70,0);
2635: uVar113 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,
2636: CONCAT212(uVar55,SUB1612(auVar82,0))) >> 0x60,0),
2637: CONCAT210(uVar54,SUB1610(auVar82,0))) >> 0x50,0),
2638: CONCAT28(uVar5,SUB168(auVar82,0))) >> 0x40,0);
2639: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),
2640: uVar111)) & 0xffff0000;
2641: auVar98 = CONCAT88(uVar113,(uVar6 >> 0x10) << 0x30) &
2642: (undefined  [16])0xffff000000000000;
2643: uVar100 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x40
2644: ,0);
2645: uVar102 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x50
2646: ,0);
2647: uVar105 = SUB162(auVar97 >> 0x60,0);
2648: uVar108 = SUB162(auVar70 >> 0x30,0);
2649: uVar107 = SUB162(auVar70 >> 0x20,0);
2650: uVar109 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
2651: (pauVar32[5] + 6),
2652: CONCAT212(uVar108,SUB1612(
2653: auVar70,0))) >> 0x60,0),
2654: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0);
2655: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar109,CONCAT28(uVar107,
2656: SUB168(auVar70,0))) >> 0x40,0),uVar64)) << 0x30 &
2657: (undefined  [16])0xffffffff00000000;
2658: auVar81 = pauVar32[6];
2659: auVar123 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2660: CONCAT214(*(undefined2 *)(pauVar32[3] + 10),
2661: CONCAT212(SUB162(auVar106 >> 0x30,0),
2662: SUB1612(auVar106,0))) >> 0x60,
2663: 0),CONCAT210(SUB162(auVar52 >> 0x50,0),
2664: SUB1610(auVar106,0))) >> 0x50,0),
2665: CONCAT28(uVar57,SUB168(auVar106,0))) >> 0x40,0),
2666: *(undefined2 *)(pauVar32[3] + 8))) << 0x30;
2667: uVar84 = SUB162(auVar70 >> 0x10,0);
2668: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2669: SUB164(CONCAT214(*(undefined2 *)(pauVar32[5] + 6),
2670: CONCAT212(uVar108,SUB1612(auVar70
2671: ,0))) >> 0x60,0),
2672: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0),
2673: CONCAT28(uVar107,SUB168(auVar70,0))) >> 0x40,0),
2674: uVar64),uVar84)) << 0x20;
2675: uVar61 = SUB162(auVar70 >> 0x40,0);
2676: uVar65 = SUB162(auVar70 >> 0x50,0);
2677: uVar69 = SUB162(auVar70 >> 0x70,0);
2678: uVar57 = *(undefined2 *)(pauVar32[7] + 8);
2679: uVar58 = *(undefined2 *)(pauVar32[7] + 0xc);
2680: uVar63 = *(undefined2 *)(pauVar32[7] + 0xe);
2681: uVar126 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >>
2682: 0x40,0);
2683: uVar127 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >>
2684: 0x50,0);
2685: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2686: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
2687: CONCAT212(SUB162(auVar52 >> 0x30,0),
2688: SUB1612(auVar52,0))) >> 0x60,0
2689: ),CONCAT210(uVar65,SUB1610(auVar52,0))) >> 0x50,0)
2690: ,CONCAT28(uVar84,SUB168(auVar52,0))) >> 0x40,0),
2691: uVar86)) << 0x30;
2692: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2693: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
2694: CONCAT212(uVar64,SUB1612(auVar92,0))) >>
2695: 0x60,0),CONCAT210(uVar65,SUB1610(auVar92,0))) >>
2696: 0x50,0),CONCAT28(uVar84,SUB168(auVar92,0))) >>
2697: 0x40,0),uVar86)) << 0x30 &
2698: (undefined  [16])0xffffffff00000000;
2699: uVar65 = SUB162(auVar81 >> 0x40,0);
2700: uVar84 = SUB162(auVar81 >> 0x60,0);
2701: uVar85 = SUB162(auVar81 >> 0x70,0);
2702: uVar120 = SUB162(auVar81 >> 0x30,0);
2703: uVar118 = SUB162(auVar81 >> 0x20,0);
2704: uVar117 = SUB162(auVar81 >> 0x10,0);
2705: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412
2706: (SUB164(CONCAT214(*(undefined2 *)(pauVar32[7] + 6)
2707: ,CONCAT212(uVar120,SUB1612(
2708: auVar81,0))) >> 0x60,0),
2709: CONCAT210(*(undefined2 *)(pauVar32[7] + 4),
2710: SUB1610(auVar81,0))) >> 0x50,0),
2711: CONCAT28(uVar118,SUB168(auVar81,0))) >> 0x40,0),
2712: *(undefined2 *)(pauVar32[7] + 2)),uVar117)) <<
2713: 0x20;
2714: uVar64 = SUB162(auVar81,0);
2715: uVar7 = (ulong)CONCAT24(uVar87,CONCAT22(SUB162(auVar70 >> 0x60,0),
2716: uVar107)) & 0xffff0000;
2717: auVar92 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
2718: uVar88,CONCAT212(uVar86,SUB1612(auVar52,0))) >>
2719: 0x60,0),CONCAT210(uVar87,SUB1610(auVar52,0))) >>
2720: 0x50,0),CONCAT28(uVar75,SUB168(auVar52,0))) >>
2721: 0x40,0),(uVar7 >> 0x10) << 0x30) &
2722: (undefined  [16])0xffff000000000000;
2723: uVar93 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,
2724: 0);
2725: uVar94 = SUB162(auVar82 >> 0x60,0);
2726: uVar96 = SUB162(auVar82 >> 0x70,0);
2727: uVar90 = (undefined2)(uVar6 >> 0x10);
2728: uVar10 = SUB166(CONCAT412(SUB164(CONCAT214(uVar66,CONCAT212(uVar90,
2729: SUB1612(auVar98,0))) >> 0x60,0),
2730: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0);
2731: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar10,CONCAT28(uVar59,
2732: SUB168(auVar98,0))) >> 0x40,0),uVar76) &
2733: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0
2734: )) << 0x30 &
2735: (undefined  [16])0xffffffff00000000;
2736: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2737: CONCAT214(*(undefined2 *)(pauVar32[7] + 10),
2738: CONCAT212(SUB162(auVar106 >> 0x30,0),
2739: SUB1612(auVar106,0))) >> 0x60,
2740: 0),CONCAT210(SUB162(auVar81 >> 0x50,0),
2741: SUB1610(auVar106,0))) >> 0x50,0),
2742: CONCAT28(uVar117,SUB168(auVar106,0))) >> 0x40,0),
2743: uVar57)) << 0x30;
2744: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2745: SUB164(CONCAT214(uVar66,CONCAT212(uVar90,SUB1612(
2746: auVar98,0))) >> 0x60,0),
2747: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0),
2748: CONCAT28(uVar59,SUB168(auVar98,0))) >> 0x40,0),
2749: uVar76) & SUB1610((undefined  [16])
2750: 0xffffffffffffffff >> 0x30,0),
2751: uVar111)) << 0x20;
2752: uVar117 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
2753: 0x40,0);
2754: uVar122 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
2755: 0x50,0);
2756: auVar110 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2757: CONCAT214(uVar74,CONCAT212(SUB162(auVar81 >> 0x30,
2758: 0),
2759: SUB1612(auVar81,0))) >>
2760: 0x60,0),CONCAT210(uVar54,SUB1610(auVar81,0))) >>
2761: 0x50,0),CONCAT28(uVar111,SUB168(auVar81,0))) >>
2762: 0x40,0),uVar72)) << 0x30;
2763: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2764: CONCAT214(uVar74,CONCAT212(uVar76,SUB1612(auVar52,
2765: 0))) >> 0x60,0),
2766: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
2767: CONCAT28(uVar111,SUB168(auVar52,0))) >> 0x40,0),
2768: uVar72)) << 0x30 &
2769: (undefined  [16])0xffffffff00000000;
2770: uVar54 = (undefined2)(uVar7 >> 0x10);
2771: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2772: SUB164(CONCAT214(uVar84,CONCAT212(uVar54,SUB1612(
2773: auVar92,0))) >> 0x60,0),
2774: CONCAT210(uVar65,SUB1610(auVar92,0))) >> 0x50,0),
2775: CONCAT28(uVar61,SUB168(auVar92,0))) >> 0x40,0),
2776: uVar118) &
2777: SUB1610((undefined  [16])0xffffffffffffffff >>
2778: 0x30,0),uVar107)) << 0x20;
2779: uVar91 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2
2780: *)(
2781: pauVar32[3] + 8),
2782: CONCAT212(uVar72,SUB1612(auVar52,0))) >> 0x60,0),
2783: CONCAT210(uVar60,SUB1610(auVar52,0))) >> 0x50,0),
2784: CONCAT28((short)uVar36,SUB168(auVar52,0))) >> 0x40
2785: ,0);
2786: uVar6 = (ulong)CONCAT24(uVar60,CONCAT22(uVar55,uVar59)) & 0xffff0000;
2787: auVar81 = CONCAT88(uVar91,(uVar6 >> 0x10) << 0x30) &
2788: (undefined  [16])0xffff000000000000;
2789: uVar76 = SUB162((auVar110 & (undefined  [16])0xffffffff00000000) >> 0x40
2790: ,0);
2791: uVar7 = (ulong)CONCAT24(SUB162((auVar110 &
2792: (undefined  [16])0xffffffff00000000) >>
2793: 0x50,0),CONCAT22(uVar90,uVar76));
2794: uVar111 = SUB162(auVar110 >> 0x60,0);
2795: Var14 = CONCAT28(uVar111,uVar113);
2796: auVar106 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2797: CONCAT214(*(undefined2 *)(pauVar32[7] + 4),
2798: CONCAT212(SUB162(auVar92 >> 0x30,0),
2799: SUB1612(auVar92,0))) >> 0x60,0
2800: ),CONCAT210(uVar87,SUB1610(auVar92,0))) >> 0x50,0)
2801: ,CONCAT28(uVar107,SUB168(auVar92,0))) >> 0x40,0),
2802: *(undefined2 *)pauVar32[7])) << 0x30;
2803: uVar8 = (ulong)(uVar114 & 0xffff00000000 |
2804: (uint6)CONCAT22(SUB162(auVar123 >> 0x60,0),uVar105));
2805: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
2806: uVar68,uVar67),uVar127),CONCAT22(uVar102,uVar67))
2807: >> 0x10),uVar79),uVar112)) << 0x20;
2808: uVar25 = CONCAT22(uVar68,uVar67);
2809: auVar52 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar25,uVar127),
2810: CONCAT22(uVar102,uVar67)) >>
2811: 0x10),uVar79)) << 0x30 &
2812: (undefined  [16])0xffffffff00000000;
2813: uVar87 = SUB162((auVar106 & (undefined  [16])0xffffffff00000000) >> 0x40
2814: ,0);
2815: uVar9 = (ulong)CONCAT24(SUB162((auVar106 &
2816: (undefined  [16])0xffffffff00000000) >>
2817: 0x50,0),CONCAT22(uVar54,uVar87));
2818: uVar55 = (undefined2)(uVar8 >> 0x20);
2819: uVar54 = (undefined2)(uVar8 >> 0x10);
2820: auVar98 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2821: CONCAT214(uVar83,CONCAT212(SUB162(auVar92 >> 0x30,
2822: 0),
2823: SUB1612(auVar92,0))) >>
2824: 0x60,0),CONCAT210(uVar55,SUB1610(auVar92,0))) >>
2825: 0x50,0),CONCAT28(uVar112,SUB168(auVar92,0))) >>
2826: 0x40,0),uVar54) & 0xffffffffffffffff) << 0x30;
2827: auVar52 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
2828: CONCAT412(SUB164(CONCAT214(uVar83,CONCAT212(uVar79
2829: ,SUB1612(auVar52,0))) >> 0x60,0),
2830: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
2831: CONCAT28(uVar112,SUB168(auVar52,0))) >> 0x40,0),
2832: uVar54)) << 0x30) >> 0x20,0) &
2833: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0
2834: )) << 0x20;
2835: uVar8 = (ulong)(uVar109 & 0xffff00000000 |
2836: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),uVar94));
2837: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
2838: uVar85,uVar69),uVar122),CONCAT22(uVar93,uVar69))
2839: >> 0x10),uVar120),uVar108)) << 0x20;
2840: uVar68 = (undefined2)(uVar6 >> 0x10);
2841: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2842: CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(auVar81,
2843: 0))) >> 0x60,0),
2844: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
2845: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
2846: uVar61) &
2847: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,
2848: 0)) << 0x30 &
2849: (undefined  [16])0xffffffff00000000;
2850: uVar80 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162(
2851: auVar123 >> 0x70,0),
2852: CONCAT212(uVar54,SUB1612(auVar52,0))) >> 0x60,0),
2853: CONCAT210(uVar127,SUB1610(auVar52,0))) >> 0x50,0),
2854: CONCAT28(uVar126,SUB168(auVar52,0))) >> 0x40,0);
2855: uVar6 = (ulong)CONCAT24(uVar127,CONCAT22(SUB162(auVar97 >> 0x70,0),
2856: uVar102)) & 0xffff0000;
2857: auVar52 = CONCAT88(uVar80,(uVar6 >> 0x10) << 0x30) &
2858: (undefined  [16])0xffff000000000000;
2859: uVar74 = SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >> 0x50,
2860: 0);
2861: uVar83 = SUB162(auVar98 >> 0x60,0);
2862: auVar97 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
2863: CONCAT412(SUB164(CONCAT214(uVar65,CONCAT212(uVar61
2864: ,SUB1612(auVar116,0))) >> 0x60,0),
2865: CONCAT210(uVar60,SUB1610(auVar116,0))) >> 0x50,0),
2866: CONCAT28(uVar59,SUB168(auVar116,0))) >> 0x40,0),
2867: uVar64)) << 0x30) >> 0x20,0) &
2868: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,
2869: 0),uVar36 << 0x10);
2870: uVar107 = (undefined2)(uVar8 >> 0x10);
2871: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2872: CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
2873: CONCAT212(SUB162(auVar92 >> 0x30,0),
2874: SUB1612(auVar92,0))) >> 0x60,0
2875: ),CONCAT210((short)(uVar8 >> 0x20),
2876: SUB1610(auVar92,0))) >> 0x50,0),
2877: CONCAT28(uVar108,SUB168(auVar92,0))) >> 0x40,0),
2878: uVar107) & 0xffffffffffffffff) << 0x30;
2879: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
2880: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
2881: undefined2 *)pauVar32[7],
2882: CONCAT212(uVar64,SUB1612(auVar97,0))) >> 0x60,0),
2883: CONCAT210(uVar75,SUB1610(auVar97,0))) >> 0x50,0),
2884: CONCAT28(SUB162(auVar70,0),SUB168(auVar97,0))) >>
2885: 0x40,0),(((ulong)CONCAT24(uVar75,CONCAT22(uVar72,
2886: uVar5)) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0)
2887: & SUB1610((undefined  [16])0xffffffffffffffff >>
2888: 0x30,0) &
2889: SUB1610((undefined  [16])0xffffffffffffffff >>
2890: 0x30,0),
2891: (SUB166(auVar97,0) >> 0x10) << 0x20) >> 0x20,0),
2892: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
2893: uVar79 = (undefined2)(uVar6 >> 0x10);
2894: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2895: CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(auVar52,
2896: 0))) >> 0x60,0),
2897: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
2898: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
2899: uVar93) &
2900: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0
2901: )) << 0x30 &
2902: (undefined  [16])0xffffffff00000000;
2903: uVar55 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x50,
2904: 0);
2905: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2906: SUB164(CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(
2907: auVar81,0))) >> 0x60,0),
2908: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
2909: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
2910: uVar61) & SUB1610((undefined  [16])
2911: 0xffffffffffffffff >> 0x30,0),
2912: uVar59)) << 0x20;
2913: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
2914: CONCAT412(SUB164(CONCAT214(uVar122,CONCAT212(
2915: uVar93,SUB1612(auVar71,0))) >> 0x60,0),
2916: CONCAT210(uVar127,SUB1610(auVar71,0))) >> 0x50,0),
2917: CONCAT28(uVar102,SUB168(auVar71,0))) >> 0x40,0),
2918: uVar117)) << 0x30) >> 0x20,0),
2919: CONCAT22(uVar126,uVar100));
2920: uVar6 = (ulong)(uVar10 & 0xffff00000000 |
2921: (uint6)CONCAT22(SUB162(auVar106 >> 0x60,0),uVar111));
2922: uVar8 = (ulong)(((uint6)uVar25 & 0xffff0000) << 0x10 |
2923: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),uVar83));
2924: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2925: SUB164(CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(
2926: auVar52,0))) >> 0x60,0),
2927: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
2928: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
2929: uVar93) & SUB1610((undefined  [16])
2930: 0xffffffffffffffff >> 0x30,0),
2931: uVar102)) << 0x20;
2932: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2933: CONCAT214(uVar65,CONCAT212(SUB162(auVar70 >> 0x30,
2934: 0),
2935: SUB1612(auVar70,0))) >>
2936: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
2937: 0x50,0),CONCAT28(uVar59,SUB168(auVar70,0))) >>
2938: 0x40,0),uVar64) & 0xffffffffffffffff) << 0x30;
2939: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2940: CONCAT214(uVar122,CONCAT212(SUB162(auVar71 >> 0x30
2941: ,0),
2942: SUB1612(auVar71,0)))
2943: >> 0x60,0),CONCAT210(uVar127,SUB1610(auVar71,0)))
2944: >> 0x50,0),CONCAT28(uVar102,SUB168(auVar71,0))) >>
2945: 0x40,0),uVar117)) << 0x30;
2946: pauVar24[1] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
2947: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
2948: uVar107,CONCAT212(uVar117,SUB1612(auVar81,0))) >>
2949: 0x60,0),CONCAT210(uVar94,SUB1610(auVar81,0))) >>
2950: 0x50,0),CONCAT28(SUB162((auVar82 &
2951: (undefined  [16])
2952: 0xffffffff00000000) >>
2953: 0x40,0),SUB168(auVar81,0))
2954: ) >> 0x40,0),
2955: (((ulong)CONCAT24(uVar94,CONCAT22(uVar54,uVar105))
2956: & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
2957: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
2958: CONCAT22(uVar105,uVar100));
2959: uVar54 = (undefined2)(uVar9 >> 0x20);
2960: uVar64 = (undefined2)(uVar7 >> 0x20);
2961: uVar75 = (undefined2)(uVar9 >> 0x10);
2962: uVar72 = (undefined2)(uVar7 >> 0x10);
2963: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
2964: SUB164(CONCAT214(uVar88,CONCAT212(uVar12,CONCAT210
2965: (uVar66,Var14))) >> 0x60,0),
2966: CONCAT210(uVar54,Var14)) >> 0x50,0),
2967: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75),
2968: uVar72) & (undefined  [12])0xffffffffffffffff) <<
2969: 0x20;
2970: auVar81 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
2971: CONCAT412(SUB164(CONCAT214(uVar88,CONCAT212(uVar12
2972: ,CONCAT210(uVar66,Var14))) >> 0x60,0),
2973: CONCAT210(uVar54,Var14)) >> 0x50,0),
2974: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75) &
2975: 0xffffffffffffffff) << 0x30) >> 0x20,0) &
2976: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0
2977: )) << 0x20;
2978: uVar60 = (undefined2)(uVar6 >> 0x20);
2979: uVar59 = (undefined2)(uVar6 >> 0x10);
2980: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
2981: CONCAT214(uVar84,CONCAT212(SUB162(auVar70 >> 0x30,
2982: 0),
2983: SUB1612(auVar70,0))) >>
2984: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
2985: 0x50,0),CONCAT28(uVar72,SUB168(auVar70,0))) >>
2986: 0x40,0),uVar59) & 0xffffffffffffffff) << 0x30;
2987: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
2988: CONCAT412(SUB164(CONCAT214(uVar84,CONCAT212(uVar75
2989: ,SUB1612(auVar81,0))) >> 0x60,0),
2990: CONCAT210(uVar60,SUB1610(auVar81,0))) >> 0x50,0),
2991: CONCAT28(uVar90,SUB168(auVar81,0))) >> 0x40,0),
2992: uVar59)) << 0x30) >> 0x20,0) &
2993: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,
2994: 0),CONCAT22(uVar111,uVar76));
2995: pauVar24[4] = CONCAT214(uVar57,CONCAT212(SUB162(auVar52 >> 0x70,0),
2996: CONCAT210(uVar86,CONCAT28(
2997: SUB162(auVar52 >> 0x60,0),
2998: uVar91 & 0xffff000000000000 |
2999: (ulong)CONCAT24(SUB162((auVar52 &
3000: (undefined  [16])
3001: 0xffffffff00000000) >> 0x50
3002: ,0),
3003: CONCAT22(uVar68,SUB162((auVar52 &
3004: (undefined 
3005: 
3006: [16])0xffffffff00000000) >> 0x40,0)))))));
3007: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
3008: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
3009: (auVar106 >> 0x70,0),
3010: CONCAT212(uVar59,SUB1612(auVar81,0))) >> 0x60,0),
3011: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
3012: CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
3013: (((ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar110 
3014: >> 0x70,0),uVar64)) & 0xffff0000) >> 0x10) << 0x30
3015: ) >> 0x30,0),(SUB166(auVar81,0) >> 0x10) << 0x20)
3016: >> 0x20,0),CONCAT22(uVar64,uVar76));
3017: auVar52 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
3018: uVar56,uVar73),uVar55),CONCAT22(uVar74,uVar73)) >>
3019: 0x10),uVar69),uVar67)) << 0x20;
3020: auVar81 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar56,
3021: uVar73),uVar55),CONCAT22(uVar74,uVar73)) >> 0x10),
3022: uVar69)) << 0x30 &
3023: (undefined  [16])0xffffffff00000000;
3024: pauVar24[5] = CONCAT214(SUB162(auVar115 >> 0x70,0),
3025: CONCAT212(SUB162(auVar71 >> 0x70,0),
3026: CONCAT210(uVar96,CONCAT28(SUB162(
3027: auVar71 >> 0x60,0),
3028: uVar80 & 0xffff000000000000 |
3029: (ulong)CONCAT24(SUB162((auVar71 &
3030: (undefined  [16])
3031: 0xffffffff00000000) >> 0x50
3032: ,0),
3033: CONCAT22(uVar79,SUB162((auVar71 &
3034: (undefined 
3035: 
3036: [16])0xffffffff00000000) >> 0x40,0)))))));
3037: uVar54 = (undefined2)(uVar8 >> 0x20);
3038: uVar75 = (undefined2)(uVar8 >> 0x10);
3039: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3040: CONCAT214(uVar85,CONCAT212(SUB162(auVar52 >> 0x30,
3041: 0),
3042: SUB1612(auVar52,0))) >>
3043: 0x60,0),CONCAT210(uVar54,SUB1610(auVar52,0))) >>
3044: 0x50,0),CONCAT28(uVar67,SUB168(auVar52,0))) >>
3045: 0x40,0),uVar75) & 0xffffffffffffffff) << 0x30;
3046: auVar52 = ZEXT1416(CONCAT122(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610
3047: (SUB166(CONCAT412(SUB164(CONCAT214(uVar85,
3048: CONCAT212(uVar69,SUB1612(auVar81,0))) >> 0x60,0),
3049: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
3050: CONCAT28(uVar67,SUB168(auVar81,0))) >> 0x40,0),
3051: uVar75)) << 0x30) >> 0x20,0) &
3052: SUB1612((undefined  [16])0xffffffffffffffff >>
3053: 0x20,0),uVar83)) << 0x10;
3054: *(short *)pauVar24[6] =
3055: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
3056: *(undefined2 *)(pauVar24[6] + 2) = uVar12;
3057: *(short *)(pauVar24[6] + 4) =
3058: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
3059: *(undefined2 *)(pauVar24[6] + 6) = uVar62;
3060: *(short *)(pauVar24[6] + 8) = SUB162(auVar70 >> 0x60,0);
3061: *(undefined2 *)(pauVar24[6] + 10) = uVar88;
3062: *(short *)(pauVar24[6] + 0xc) = SUB162(auVar70 >> 0x70,0);
3063: *(undefined2 *)(pauVar24[6] + 0xe) = uVar58;
3064: *(short *)pauVar24[7] =
3065: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
3066: *(undefined2 *)(pauVar24[7] + 2) = uVar73;
3067: *(short *)(pauVar24[7] + 4) =
3068: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
3069: *(undefined2 *)(pauVar24[7] + 6) = uVar99;
3070: *(short *)(pauVar24[7] + 8) = SUB162(auVar71 >> 0x60,0);
3071: *(undefined2 *)(pauVar24[7] + 10) = uVar56;
3072: *(short *)(pauVar24[7] + 0xc) = SUB162(auVar71 >> 0x70,0);
3073: *(undefined2 *)(pauVar24[7] + 0xe) = uVar63;
3074: pauVar24[3] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
3075: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
3076: (auVar92 >> 0x70,0),
3077: CONCAT212(uVar75,SUB1612(auVar52,0))) >> 0x60,0),
3078: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
3079: CONCAT28(SUB162((auVar92 &
3080: (undefined  [16])
3081: 0xffffffff00000000) >> 0x40,0),
3082: SUB168(auVar52,0))) >> 0x40,0),
3083: (((ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar98 
3084: >> 0x70,0),uVar74)) & 0xffff0000) >> 0x10) << 0x30
3085: ) >> 0x30,0),(SUB166(auVar52,0) >> 0x10) << 0x20)
3086: >> 0x20,0),
3087: SUB164((auVar98 &
3088: (undefined  [16])0xffffffff00000000) >>
3089: 0x40,0));
3090: goto joined_r0x0014d4ca;
3091: }
3092: iVar42 = 8;
3093: do {
3094: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
3095: *(undefined2 *)pauVar24[1] = *(undefined2 *)(*pauVar32 + 2);
3096: *(undefined2 *)pauVar24[2] = *(undefined2 *)(*pauVar32 + 4);
3097: *(undefined2 *)pauVar24[3] = *(undefined2 *)(*pauVar32 + 6);
3098: *(undefined2 *)pauVar24[4] = *(undefined2 *)(*pauVar32 + 8);
3099: *(undefined2 *)pauVar24[5] = *(undefined2 *)(*pauVar32 + 10);
3100: *(undefined2 *)pauVar24[6] = *(undefined2 *)(*pauVar32 + 0xc);
3101: *(undefined2 *)pauVar24[7] = *(undefined2 *)(*pauVar32 + 0xe);
3102: iVar42 = iVar42 + -1;
3103: pauVar24 = (undefined (*) [16])(*pauVar24 + 2);
3104: pauVar32 = pauVar32[1];
3105: } while (iVar42 != 0);
3106: uVar36 = (int)uVar20 + 1;
3107: uVar20 = (ulong)uVar36;
3108: plVar23 = plVar23 + 1;
3109: plVar30 = plVar30 + -1;
3110: } while (uVar36 != uVar46);
3111: code_r0x0014cf9a:
3112: uVar20 = (ulong)uVar46;
3113: uVar50 = *(uint *)(lVar49 + 0x1c);
3114: if (uVar50 <= uVar46) goto code_r0x0014cfae;
3115: }
3116: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
3117: (param_1,*(undefined8 *)(param_3 + lStack200 * 8),
3118: uVar50);
3119: iVar43 = *(int *)(lVar49 + 8);
3120: if (0 < iVar43) goto code_r0x0014ce87;
3121: code_r0x0014d8b6:
3122: uVar20 = (ulong)(uint)(iVar42 + iVar43);
3123: uVar50 = *(uint *)(lVar49 + 0x1c);
3124: } while ((uint)(iVar42 + iVar43) < uVar50);
3125: code_r0x0014cfae:
3126: iVar43 = *(int *)(lVar49 + 0xc);
3127: }
3128: uStack120 = uStack120 & 0xffffffff00000000 | (ulong)((int)uStack120 - 1);
3129: auStack152._0_16_ = CONCAT88(auStack152._8_8_,auStack152._0_8_ + 1);
3130: } while (iVar41 + 1 < iVar43);
3131: }
3132: uVar47 = uVar47 + iVar43;
3133: } while (uVar47 < *(uint *)(lVar49 + 0x20));
3134: iVar43 = *(int *)(param_2 + 0x4c);
3135: }
3136: lStack200 = lStack200 + 1;
3137: } while ((int)lStack200 + 1 < iVar43);
3138: }
3139: break;
3140: case 5:
3141: uVar2 = param_4[0x15];
3142: uVar3 = param_4[0x14];
3143: iVar37 = *(int *)(param_2 + 0x138);
3144: uVar27 = *(uint *)(param_1 + 0x8c);
3145: iVar16 = *(int *)(param_2 + 0x4c);
3146: if (0 < iVar16) {
3147: auStack248._0_16_ = auStack248._0_16_ & (undefined  [16])0xffffffffffffffff;
3148: do {
3149: lVar49 = auStack248._0_8_ * 0x60 + *(long *)(param_2 + 0x58);
3150: iVar43 = *(int *)(lVar49 + 0xc);
3151: iVar33 = uVar2 * iVar43;
3152: uVar34 = (uVar27 / (uint)(iVar37 * 8)) * *(int *)(lVar49 + 8);
3153: iVar26 = *(int *)(lVar49 + 8) * uVar3;
3154: if (*(int *)(lVar49 + 0x20) != 0) {
3155: uVar39 = 0;
3156: do {
3157: lVar22 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
3158: (param_1,*(undefined8 *)(lVar51 + auStack248._0_8_ * 8),uVar39,
3159: iVar43,1);
3160: iVar43 = *(int *)(lVar49 + 0xc);
3161: if (0 < iVar43) {
3162: uVar35 = *(uint *)(lVar49 + 0x1c);
3163: _auStack216 = _auStack216 & (undefined  [16])0xffffffffffffffff;
3164: do {
3165: iVar16 = SUB164(_auStack216,0);
3166: if (uVar35 != 0) {
3167: uVar47 = 0;
3168: iVar43 = *(int *)(lVar49 + 8);
3169: lVar17 = (ulong)(iVar33 + uVar39 + iVar16) * 0x80;
3170: do {
3171: while( true ) {
3172: uVar35 = uVar47 + iVar26;
3173: if (uVar34 <= uVar35) break;
3174: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
3175: (param_1,*(undefined8 *)
3176: (param_3 + auStack248._0_8_ * 8),
3177: ((uVar34 - iVar26) - uVar47) - iVar43);
3178: iVar43 = *(int *)(lVar49 + 8);
3179: if (iVar43 < 1) goto code_r0x0014cc4e;
3180: code_r0x0014c675:
3181: uVar20 = (ulong)uVar47;
3182: lVar18 = *(long *)(lVar22 + auStack216 * 8);
3183: uVar47 = uVar47 + iVar43;
3184: plVar30 = plVar23 + (long)iVar43 + -1;
3185: do {
3186: while( true ) {
3187: pauVar24 = (undefined (*) [16])(uVar20 * 0x80 + lVar18);
3188: if (uVar34 <= uVar35) break;
3189: iVar41 = 4;
3190: puVar45 = (undefined2 *)(lVar17 + *plVar30);
3191: do {
3192: *(undefined2 *)*pauVar24 = *puVar45;
3193: *(undefined2 *)pauVar24[1] = puVar45[1];
3194: *(undefined2 *)pauVar24[2] = puVar45[2];
3195: *(undefined2 *)pauVar24[3] = puVar45[3];
3196: *(undefined2 *)pauVar24[4] = puVar45[4];
3197: *(undefined2 *)pauVar24[5] = puVar45[5];
3198: *(undefined2 *)pauVar24[6] = puVar45[6];
3199: *(undefined2 *)pauVar24[7] = puVar45[7];
3200: *(undefined2 *)(*pauVar24 + 2) = -puVar45[8];
3201: *(undefined2 *)(pauVar24[1] + 2) = -puVar45[9];
3202: *(undefined2 *)(pauVar24[2] + 2) = -puVar45[10];
3203: *(undefined2 *)(pauVar24[3] + 2) = -puVar45[0xb];
3204: *(undefined2 *)(pauVar24[4] + 2) = -puVar45[0xc];
3205: *(undefined2 *)(pauVar24[5] + 2) = -puVar45[0xd];
3206: *(undefined2 *)(pauVar24[6] + 2) = -puVar45[0xe];
3207: *(undefined2 *)(pauVar24[7] + 2) = -puVar45[0xf];
3208: iVar41 = iVar41 + -1;
3209: pauVar24 = (undefined (*) [16])(*pauVar24 + 4);
3210: puVar45 = puVar45 + 0x10;
3211: } while (iVar41 != 0);
3212: joined_r0x0014cb94:
3213: uVar50 = (int)uVar20 + 1;
3214: uVar20 = (ulong)uVar50;
3215: plVar30 = plVar30 + -1;
3216: plVar23 = plVar23 + 1;
3217: if (uVar50 == uVar47) goto code_r0x0014c77d;
3218: }
3219: pauVar32 = (undefined (*) [16])(lVar17 + *plVar23);
3220: pauVar21 = pauVar32[8];
3221: if ((((((((pauVar24[7] <= pauVar32 || pauVar21 <= pauVar24[6]) &&
3222: (pauVar24[8] <= pauVar32 || pauVar21 <= pauVar24[7])) &&
3223: (pauVar24[6] <= pauVar32 || pauVar21 <= pauVar24[5])) &&
3224: (pauVar24[5] <= pauVar32 || pauVar21 <= pauVar24[4])) &&
3225: (pauVar24[4] <= pauVar32 || pauVar21 <= pauVar24[3])) &&
3226: (pauVar24[3] <= pauVar32 || pauVar21 <= pauVar24[2])) &&
3227: (pauVar24[2] <= pauVar32 || pauVar21 <= pauVar24[1])) &&
3228: (pauVar24[1] <= pauVar32 || pauVar21 <= pauVar24)) {
3229: auVar71 = *pauVar32;
3230: uVar5 = *(ushort *)pauVar32[1];
3231: uVar75 = *(undefined2 *)(pauVar32[1] + 2);
3232: uVar54 = *(undefined2 *)(pauVar32[1] + 4);
3233: uVar55 = *(undefined2 *)(pauVar32[1] + 8);
3234: uVar12 = *(undefined2 *)(pauVar32[1] + 0xc);
3235: uVar73 = *(undefined2 *)(pauVar32[1] + 0xe);
3236: uVar112 = SUB162(auVar71 >> 0x30,0);
3237: uVar111 = SUB162(auVar71 >> 0x20,0);
3238: uVar114 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
3239: (pauVar32[1] + 6),
3240: CONCAT212(uVar112,SUB1612(
3241: auVar71,0))) >> 0x60,0),
3242: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0);
3243: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar114,CONCAT28(uVar111,
3244: SUB168(auVar71,0))) >> 0x40,0),uVar75)) << 0x30 &
3245: (undefined  [16])0xffffffff00000000;
3246: auVar52 = pauVar32[2];
3247: uVar59 = SUB162(auVar71 >> 0x40,0);
3248: uVar64 = SUB162(auVar71 >> 0x50,0);
3249: uVar67 = SUB162(auVar71 >> 0x70,0);
3250: uVar87 = SUB162(auVar71 >> 0x10,0);
3251: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3252: SUB164(CONCAT214(*(undefined2 *)(pauVar32[1] + 6),
3253: CONCAT212(uVar112,SUB1612(auVar71
3254: ,0))) >> 0x60,0),
3255: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
3256: CONCAT28(uVar111,SUB168(auVar71,0))) >> 0x40,0),
3257: uVar75),uVar87)) << 0x20;
3258: uVar72 = *(undefined2 *)pauVar32[3];
3259: uVar74 = *(undefined2 *)(pauVar32[3] + 4);
3260: uVar83 = *(undefined2 *)(pauVar32[3] + 6);
3261: uVar62 = *(undefined2 *)(pauVar32[3] + 0xc);
3262: uVar99 = *(undefined2 *)(pauVar32[3] + 0xe);
3263: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3264: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
3265: CONCAT212(uVar75,SUB1612(auVar70,0))) >>
3266: 0x60,0),CONCAT210(uVar64,SUB1610(auVar70,0))) >>
3267: 0x50,0),CONCAT28(uVar87,SUB168(auVar70,0))) >>
3268: 0x40,0),uVar55)) << 0x30 &
3269: (undefined  [16])0xffffffff00000000;
3270: uVar79 = SUB162(auVar52 >> 0x30,0);
3271: uVar76 = SUB162(auVar52 >> 0x20,0);
3272: uVar50 = SUB164(auVar52,0) & 0xffff;
3273: auVar70 = pauVar32[4];
3274: auVar97 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3275: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
3276: CONCAT212(SUB162(auVar81 >> 0x30,0),
3277: SUB1612(auVar81,0))) >> 0x60,0
3278: ),CONCAT210(uVar64,SUB1610(auVar81,0))) >> 0x50,0)
3279: ,CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
3280: uVar55)) << 0x30;
3281: uVar57 = SUB162(auVar52 >> 0x10,0);
3282: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412
3283: (SUB164(CONCAT214(uVar83,CONCAT212(uVar79,SUB1612(
3284: auVar52,0))) >> 0x60,0),
3285: CONCAT210(uVar74,SUB1610(auVar52,0))) >> 0x50,0),
3286: CONCAT28(uVar76,SUB168(auVar52,0))) >> 0x40,0),
3287: *(undefined2 *)(pauVar32[3] + 2)),uVar57)) << 0x20
3288: ;
3289: uVar75 = *(undefined2 *)pauVar32[5];
3290: uVar64 = *(undefined2 *)(pauVar32[5] + 2);
3291: uVar87 = *(undefined2 *)(pauVar32[5] + 4);
3292: uVar86 = *(undefined2 *)(pauVar32[5] + 8);
3293: uVar88 = *(undefined2 *)(pauVar32[5] + 0xc);
3294: uVar56 = *(undefined2 *)(pauVar32[5] + 0xe);
3295: uVar60 = SUB162(auVar52 >> 0x40,0);
3296: uVar66 = SUB162(auVar52 >> 0x60,0);
3297: uVar68 = SUB162(auVar52 >> 0x70,0);
3298: uVar113 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,
3299: CONCAT212(uVar55,SUB1612(auVar82,0))) >> 0x60,0),
3300: CONCAT210(uVar54,SUB1610(auVar82,0))) >> 0x50,0),
3301: CONCAT28(uVar5,SUB168(auVar82,0))) >> 0x40,0);
3302: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),
3303: uVar111)) & 0xffff0000;
3304: auVar98 = CONCAT88(uVar113,(uVar6 >> 0x10) << 0x30) &
3305: (undefined  [16])0xffff000000000000;
3306: uVar100 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x40
3307: ,0);
3308: uVar102 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x50
3309: ,0);
3310: uVar105 = SUB162(auVar97 >> 0x60,0);
3311: uVar108 = SUB162(auVar70 >> 0x30,0);
3312: uVar107 = SUB162(auVar70 >> 0x20,0);
3313: uVar109 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
3314: (pauVar32[5] + 6),
3315: CONCAT212(uVar108,SUB1612(
3316: auVar70,0))) >> 0x60,0),
3317: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0);
3318: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar109,CONCAT28(uVar107,
3319: SUB168(auVar70,0))) >> 0x40,0),uVar64)) << 0x30 &
3320: (undefined  [16])0xffffffff00000000;
3321: auVar81 = pauVar32[6];
3322: auVar123 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3323: CONCAT214(*(undefined2 *)(pauVar32[3] + 10),
3324: CONCAT212(SUB162(auVar106 >> 0x30,0),
3325: SUB1612(auVar106,0))) >> 0x60,
3326: 0),CONCAT210(SUB162(auVar52 >> 0x50,0),
3327: SUB1610(auVar106,0))) >> 0x50,0),
3328: CONCAT28(uVar57,SUB168(auVar106,0))) >> 0x40,0),
3329: *(undefined2 *)(pauVar32[3] + 8))) << 0x30;
3330: uVar84 = SUB162(auVar70 >> 0x10,0);
3331: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3332: SUB164(CONCAT214(*(undefined2 *)(pauVar32[5] + 6),
3333: CONCAT212(uVar108,SUB1612(auVar70
3334: ,0))) >> 0x60,0),
3335: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0),
3336: CONCAT28(uVar107,SUB168(auVar70,0))) >> 0x40,0),
3337: uVar64),uVar84)) << 0x20;
3338: uVar61 = SUB162(auVar70 >> 0x40,0);
3339: uVar65 = SUB162(auVar70 >> 0x50,0);
3340: uVar69 = SUB162(auVar70 >> 0x70,0);
3341: uVar57 = *(undefined2 *)(pauVar32[7] + 8);
3342: uVar58 = *(undefined2 *)(pauVar32[7] + 0xc);
3343: uVar63 = *(undefined2 *)(pauVar32[7] + 0xe);
3344: uVar126 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >>
3345: 0x40,0);
3346: uVar127 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >>
3347: 0x50,0);
3348: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3349: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
3350: CONCAT212(SUB162(auVar52 >> 0x30,0),
3351: SUB1612(auVar52,0))) >> 0x60,0
3352: ),CONCAT210(uVar65,SUB1610(auVar52,0))) >> 0x50,0)
3353: ,CONCAT28(uVar84,SUB168(auVar52,0))) >> 0x40,0),
3354: uVar86)) << 0x30;
3355: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3356: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
3357: CONCAT212(uVar64,SUB1612(auVar92,0))) >>
3358: 0x60,0),CONCAT210(uVar65,SUB1610(auVar92,0))) >>
3359: 0x50,0),CONCAT28(uVar84,SUB168(auVar92,0))) >>
3360: 0x40,0),uVar86)) << 0x30 &
3361: (undefined  [16])0xffffffff00000000;
3362: uVar65 = SUB162(auVar81 >> 0x40,0);
3363: uVar84 = SUB162(auVar81 >> 0x60,0);
3364: uVar85 = SUB162(auVar81 >> 0x70,0);
3365: uVar120 = SUB162(auVar81 >> 0x30,0);
3366: uVar118 = SUB162(auVar81 >> 0x20,0);
3367: uVar117 = SUB162(auVar81 >> 0x10,0);
3368: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412
3369: (SUB164(CONCAT214(*(undefined2 *)(pauVar32[7] + 6)
3370: ,CONCAT212(uVar120,SUB1612(
3371: auVar81,0))) >> 0x60,0),
3372: CONCAT210(*(undefined2 *)(pauVar32[7] + 4),
3373: SUB1610(auVar81,0))) >> 0x50,0),
3374: CONCAT28(uVar118,SUB168(auVar81,0))) >> 0x40,0),
3375: *(undefined2 *)(pauVar32[7] + 2)),uVar117)) <<
3376: 0x20;
3377: uVar64 = SUB162(auVar81,0);
3378: uVar7 = (ulong)CONCAT24(uVar87,CONCAT22(SUB162(auVar70 >> 0x60,0),
3379: uVar107)) & 0xffff0000;
3380: auVar92 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
3381: uVar88,CONCAT212(uVar86,SUB1612(auVar52,0))) >>
3382: 0x60,0),CONCAT210(uVar87,SUB1610(auVar52,0))) >>
3383: 0x50,0),CONCAT28(uVar75,SUB168(auVar52,0))) >>
3384: 0x40,0),(uVar7 >> 0x10) << 0x30) &
3385: (undefined  [16])0xffff000000000000;
3386: uVar93 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,
3387: 0);
3388: uVar94 = SUB162(auVar82 >> 0x60,0);
3389: uVar96 = SUB162(auVar82 >> 0x70,0);
3390: uVar90 = (undefined2)(uVar6 >> 0x10);
3391: uVar10 = SUB166(CONCAT412(SUB164(CONCAT214(uVar66,CONCAT212(uVar90,
3392: SUB1612(auVar98,0))) >> 0x60,0),
3393: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0);
3394: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar10,CONCAT28(uVar59,
3395: SUB168(auVar98,0))) >> 0x40,0),uVar76) &
3396: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0
3397: )) << 0x30 &
3398: (undefined  [16])0xffffffff00000000;
3399: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3400: CONCAT214(*(undefined2 *)(pauVar32[7] + 10),
3401: CONCAT212(SUB162(auVar106 >> 0x30,0),
3402: SUB1612(auVar106,0))) >> 0x60,
3403: 0),CONCAT210(SUB162(auVar81 >> 0x50,0),
3404: SUB1610(auVar106,0))) >> 0x50,0),
3405: CONCAT28(uVar117,SUB168(auVar106,0))) >> 0x40,0),
3406: uVar57)) << 0x30;
3407: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3408: SUB164(CONCAT214(uVar66,CONCAT212(uVar90,SUB1612(
3409: auVar98,0))) >> 0x60,0),
3410: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0),
3411: CONCAT28(uVar59,SUB168(auVar98,0))) >> 0x40,0),
3412: uVar76) & SUB1610((undefined  [16])
3413: 0xffffffffffffffff >> 0x30,0),
3414: uVar111)) << 0x20;
3415: uVar117 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
3416: 0x40,0);
3417: uVar122 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
3418: 0x50,0);
3419: auVar110 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3420: CONCAT214(uVar74,CONCAT212(SUB162(auVar81 >> 0x30,
3421: 0),
3422: SUB1612(auVar81,0))) >>
3423: 0x60,0),CONCAT210(uVar54,SUB1610(auVar81,0))) >>
3424: 0x50,0),CONCAT28(uVar111,SUB168(auVar81,0))) >>
3425: 0x40,0),uVar72)) << 0x30;
3426: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3427: CONCAT214(uVar74,CONCAT212(uVar76,SUB1612(auVar52,
3428: 0))) >> 0x60,0),
3429: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
3430: CONCAT28(uVar111,SUB168(auVar52,0))) >> 0x40,0),
3431: uVar72)) << 0x30 &
3432: (undefined  [16])0xffffffff00000000;
3433: uVar54 = (undefined2)(uVar7 >> 0x10);
3434: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3435: SUB164(CONCAT214(uVar84,CONCAT212(uVar54,SUB1612(
3436: auVar92,0))) >> 0x60,0),
3437: CONCAT210(uVar65,SUB1610(auVar92,0))) >> 0x50,0),
3438: CONCAT28(uVar61,SUB168(auVar92,0))) >> 0x40,0),
3439: uVar118) &
3440: SUB1610((undefined  [16])0xffffffffffffffff >>
3441: 0x30,0),uVar107)) << 0x20;
3442: uVar91 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2
3443: *)(
3444: pauVar32[3] + 8),
3445: CONCAT212(uVar72,SUB1612(auVar52,0))) >> 0x60,0),
3446: CONCAT210(uVar60,SUB1610(auVar52,0))) >> 0x50,0),
3447: CONCAT28((short)uVar50,SUB168(auVar52,0))) >> 0x40
3448: ,0);
3449: uVar6 = (ulong)CONCAT24(uVar60,CONCAT22(uVar55,uVar59)) & 0xffff0000;
3450: auVar81 = CONCAT88(uVar91,(uVar6 >> 0x10) << 0x30) &
3451: (undefined  [16])0xffff000000000000;
3452: uVar76 = SUB162((auVar110 & (undefined  [16])0xffffffff00000000) >> 0x40
3453: ,0);
3454: uVar7 = (ulong)CONCAT24(SUB162((auVar110 &
3455: (undefined  [16])0xffffffff00000000) >>
3456: 0x50,0),CONCAT22(uVar90,uVar76));
3457: uVar111 = SUB162(auVar110 >> 0x60,0);
3458: Var14 = CONCAT28(uVar111,uVar113);
3459: auVar106 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3460: CONCAT214(*(undefined2 *)(pauVar32[7] + 4),
3461: CONCAT212(SUB162(auVar92 >> 0x30,0),
3462: SUB1612(auVar92,0))) >> 0x60,0
3463: ),CONCAT210(uVar87,SUB1610(auVar92,0))) >> 0x50,0)
3464: ,CONCAT28(uVar107,SUB168(auVar92,0))) >> 0x40,0),
3465: *(undefined2 *)pauVar32[7])) << 0x30;
3466: uVar8 = (ulong)(uVar114 & 0xffff00000000 |
3467: (uint6)CONCAT22(SUB162(auVar123 >> 0x60,0),uVar105));
3468: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
3469: uVar68,uVar67),uVar127),CONCAT22(uVar102,uVar67))
3470: >> 0x10),uVar79),uVar112)) << 0x20;
3471: uVar40 = CONCAT22(uVar68,uVar67);
3472: auVar52 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar40,uVar127),
3473: CONCAT22(uVar102,uVar67)) >>
3474: 0x10),uVar79)) << 0x30 &
3475: (undefined  [16])0xffffffff00000000;
3476: uVar87 = SUB162((auVar106 & (undefined  [16])0xffffffff00000000) >> 0x40
3477: ,0);
3478: uVar9 = (ulong)CONCAT24(SUB162((auVar106 &
3479: (undefined  [16])0xffffffff00000000) >>
3480: 0x50,0),CONCAT22(uVar54,uVar87));
3481: uVar55 = (undefined2)(uVar8 >> 0x20);
3482: uVar54 = (undefined2)(uVar8 >> 0x10);
3483: auVar98 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3484: CONCAT214(uVar83,CONCAT212(SUB162(auVar92 >> 0x30,
3485: 0),
3486: SUB1612(auVar92,0))) >>
3487: 0x60,0),CONCAT210(uVar55,SUB1610(auVar92,0))) >>
3488: 0x50,0),CONCAT28(uVar112,SUB168(auVar92,0))) >>
3489: 0x40,0),uVar54) & 0xffffffffffffffff) << 0x30;
3490: auVar52 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
3491: CONCAT412(SUB164(CONCAT214(uVar83,CONCAT212(uVar79
3492: ,SUB1612(auVar52,0))) >> 0x60,0),
3493: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
3494: CONCAT28(uVar112,SUB168(auVar52,0))) >> 0x40,0),
3495: uVar54)) << 0x30) >> 0x20,0) &
3496: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0
3497: )) << 0x20;
3498: uVar8 = (ulong)(uVar109 & 0xffff00000000 |
3499: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),uVar94));
3500: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
3501: uVar85,uVar69),uVar122),CONCAT22(uVar93,uVar69))
3502: >> 0x10),uVar120),uVar108)) << 0x20;
3503: uVar68 = (undefined2)(uVar6 >> 0x10);
3504: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3505: CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(auVar81,
3506: 0))) >> 0x60,0),
3507: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
3508: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
3509: uVar61) &
3510: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,
3511: 0)) << 0x30 &
3512: (undefined  [16])0xffffffff00000000;
3513: uVar80 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162(
3514: auVar123 >> 0x70,0),
3515: CONCAT212(uVar54,SUB1612(auVar52,0))) >> 0x60,0),
3516: CONCAT210(uVar127,SUB1610(auVar52,0))) >> 0x50,0),
3517: CONCAT28(uVar126,SUB168(auVar52,0))) >> 0x40,0);
3518: uVar6 = (ulong)CONCAT24(uVar127,CONCAT22(SUB162(auVar97 >> 0x70,0),
3519: uVar102)) & 0xffff0000;
3520: auVar52 = CONCAT88(uVar80,(uVar6 >> 0x10) << 0x30) &
3521: (undefined  [16])0xffff000000000000;
3522: uVar74 = SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >> 0x50,
3523: 0);
3524: uVar83 = SUB162(auVar98 >> 0x60,0);
3525: auVar97 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
3526: CONCAT412(SUB164(CONCAT214(uVar65,CONCAT212(uVar61
3527: ,SUB1612(auVar116,0))) >> 0x60,0),
3528: CONCAT210(uVar60,SUB1610(auVar116,0))) >> 0x50,0),
3529: CONCAT28(uVar59,SUB168(auVar116,0))) >> 0x40,0),
3530: uVar64)) << 0x30) >> 0x20,0) &
3531: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,
3532: 0),uVar50 << 0x10);
3533: uVar107 = (undefined2)(uVar8 >> 0x10);
3534: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3535: CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
3536: CONCAT212(SUB162(auVar92 >> 0x30,0),
3537: SUB1612(auVar92,0))) >> 0x60,0
3538: ),CONCAT210((short)(uVar8 >> 0x20),
3539: SUB1610(auVar92,0))) >> 0x50,0),
3540: CONCAT28(uVar108,SUB168(auVar92,0))) >> 0x40,0),
3541: uVar107) & 0xffffffffffffffff) << 0x30;
3542: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
3543: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
3544: undefined2 *)pauVar32[7],
3545: CONCAT212(uVar64,SUB1612(auVar97,0))) >> 0x60,0),
3546: CONCAT210(uVar75,SUB1610(auVar97,0))) >> 0x50,0),
3547: CONCAT28(SUB162(auVar70,0),SUB168(auVar97,0))) >>
3548: 0x40,0),(((ulong)CONCAT24(uVar75,CONCAT22(uVar72,
3549: uVar5)) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0)
3550: & SUB1610((undefined  [16])0xffffffffffffffff >>
3551: 0x30,0) &
3552: SUB1610((undefined  [16])0xffffffffffffffff >>
3553: 0x30,0),
3554: (SUB166(auVar97,0) >> 0x10) << 0x20) >> 0x20,0),
3555: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
3556: uVar79 = (undefined2)(uVar6 >> 0x10);
3557: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3558: CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(auVar52,
3559: 0))) >> 0x60,0),
3560: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
3561: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
3562: uVar93) &
3563: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0
3564: )) << 0x30 &
3565: (undefined  [16])0xffffffff00000000;
3566: uVar55 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x50,
3567: 0);
3568: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3569: SUB164(CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(
3570: auVar81,0))) >> 0x60,0),
3571: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
3572: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
3573: uVar61) & SUB1610((undefined  [16])
3574: 0xffffffffffffffff >> 0x30,0),
3575: uVar59)) << 0x20;
3576: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
3577: CONCAT412(SUB164(CONCAT214(uVar122,CONCAT212(
3578: uVar93,SUB1612(auVar71,0))) >> 0x60,0),
3579: CONCAT210(uVar127,SUB1610(auVar71,0))) >> 0x50,0),
3580: CONCAT28(uVar102,SUB168(auVar71,0))) >> 0x40,0),
3581: uVar117)) << 0x30) >> 0x20,0),
3582: CONCAT22(uVar126,uVar100));
3583: uVar6 = (ulong)(uVar10 & 0xffff00000000 |
3584: (uint6)CONCAT22(SUB162(auVar106 >> 0x60,0),uVar111));
3585: uVar8 = (ulong)(((uint6)uVar40 & 0xffff0000) << 0x10 |
3586: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),uVar83));
3587: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3588: SUB164(CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(
3589: auVar52,0))) >> 0x60,0),
3590: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
3591: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
3592: uVar93) & SUB1610((undefined  [16])
3593: 0xffffffffffffffff >> 0x30,0),
3594: uVar102)) << 0x20;
3595: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3596: CONCAT214(uVar65,CONCAT212(SUB162(auVar70 >> 0x30,
3597: 0),
3598: SUB1612(auVar70,0))) >>
3599: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
3600: 0x50,0),CONCAT28(uVar59,SUB168(auVar70,0))) >>
3601: 0x40,0),uVar64) & 0xffffffffffffffff) << 0x30;
3602: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3603: CONCAT214(uVar122,CONCAT212(SUB162(auVar71 >> 0x30
3604: ,0),
3605: SUB1612(auVar71,0)))
3606: >> 0x60,0),CONCAT210(uVar127,SUB1610(auVar71,0)))
3607: >> 0x50,0),CONCAT28(uVar102,SUB168(auVar71,0))) >>
3608: 0x40,0),uVar117)) << 0x30;
3609: pauVar24[1] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
3610: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
3611: uVar107,CONCAT212(uVar117,SUB1612(auVar81,0))) >>
3612: 0x60,0),CONCAT210(uVar94,SUB1610(auVar81,0))) >>
3613: 0x50,0),CONCAT28(SUB162((auVar82 &
3614: (undefined  [16])
3615: 0xffffffff00000000) >>
3616: 0x40,0),SUB168(auVar81,0))
3617: ) >> 0x40,0),
3618: (((ulong)CONCAT24(uVar94,CONCAT22(uVar54,uVar105))
3619: & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
3620: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
3621: CONCAT22(uVar105,uVar100));
3622: uVar54 = (undefined2)(uVar9 >> 0x20);
3623: uVar64 = (undefined2)(uVar7 >> 0x20);
3624: uVar75 = (undefined2)(uVar9 >> 0x10);
3625: uVar72 = (undefined2)(uVar7 >> 0x10);
3626: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3627: SUB164(CONCAT214(uVar88,CONCAT212(uVar12,CONCAT210
3628: (uVar66,Var14))) >> 0x60,0),
3629: CONCAT210(uVar54,Var14)) >> 0x50,0),
3630: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75),
3631: uVar72) & (undefined  [12])0xffffffffffffffff) <<
3632: 0x20;
3633: auVar81 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
3634: CONCAT412(SUB164(CONCAT214(uVar88,CONCAT212(uVar12
3635: ,CONCAT210(uVar66,Var14))) >> 0x60,0),
3636: CONCAT210(uVar54,Var14)) >> 0x50,0),
3637: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75) &
3638: 0xffffffffffffffff) << 0x30) >> 0x20,0) &
3639: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0
3640: )) << 0x20;
3641: uVar60 = (undefined2)(uVar6 >> 0x20);
3642: uVar59 = (undefined2)(uVar6 >> 0x10);
3643: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3644: CONCAT214(uVar84,CONCAT212(SUB162(auVar70 >> 0x30,
3645: 0),
3646: SUB1612(auVar70,0))) >>
3647: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
3648: 0x50,0),CONCAT28(uVar72,SUB168(auVar70,0))) >>
3649: 0x40,0),uVar59) & 0xffffffffffffffff) << 0x30;
3650: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
3651: CONCAT412(SUB164(CONCAT214(uVar84,CONCAT212(uVar75
3652: ,SUB1612(auVar81,0))) >> 0x60,0),
3653: CONCAT210(uVar60,SUB1610(auVar81,0))) >> 0x50,0),
3654: CONCAT28(uVar90,SUB168(auVar81,0))) >> 0x40,0),
3655: uVar59)) << 0x30) >> 0x20,0) &
3656: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,
3657: 0),CONCAT22(uVar111,uVar76));
3658: pauVar24[4] = CONCAT214(uVar57,CONCAT212(SUB162(auVar52 >> 0x70,0),
3659: CONCAT210(uVar86,CONCAT28(
3660: SUB162(auVar52 >> 0x60,0),
3661: uVar91 & 0xffff000000000000 |
3662: (ulong)CONCAT24(SUB162((auVar52 &
3663: (undefined  [16])
3664: 0xffffffff00000000) >> 0x50
3665: ,0),
3666: CONCAT22(uVar68,SUB162((auVar52 &
3667: (undefined 
3668: 
3669: [16])0xffffffff00000000) >> 0x40,0)))))));
3670: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
3671: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
3672: (auVar106 >> 0x70,0),
3673: CONCAT212(uVar59,SUB1612(auVar81,0))) >> 0x60,0),
3674: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
3675: CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
3676: (((ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar110 
3677: >> 0x70,0),uVar64)) & 0xffff0000) >> 0x10) << 0x30
3678: ) >> 0x30,0),(SUB166(auVar81,0) >> 0x10) << 0x20)
3679: >> 0x20,0),CONCAT22(uVar64,uVar76));
3680: auVar52 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
3681: uVar56,uVar73),uVar55),CONCAT22(uVar74,uVar73)) >>
3682: 0x10),uVar69),uVar67)) << 0x20;
3683: auVar81 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar56,
3684: uVar73),uVar55),CONCAT22(uVar74,uVar73)) >> 0x10),
3685: uVar69)) << 0x30 &
3686: (undefined  [16])0xffffffff00000000;
3687: pauVar24[5] = CONCAT214(SUB162(auVar115 >> 0x70,0),
3688: CONCAT212(SUB162(auVar71 >> 0x70,0),
3689: CONCAT210(uVar96,CONCAT28(SUB162(
3690: auVar71 >> 0x60,0),
3691: uVar80 & 0xffff000000000000 |
3692: (ulong)CONCAT24(SUB162((auVar71 &
3693: (undefined  [16])
3694: 0xffffffff00000000) >> 0x50
3695: ,0),
3696: CONCAT22(uVar79,SUB162((auVar71 &
3697: (undefined 
3698: 
3699: [16])0xffffffff00000000) >> 0x40,0)))))));
3700: uVar54 = (undefined2)(uVar8 >> 0x20);
3701: uVar75 = (undefined2)(uVar8 >> 0x10);
3702: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3703: CONCAT214(uVar85,CONCAT212(SUB162(auVar52 >> 0x30,
3704: 0),
3705: SUB1612(auVar52,0))) >>
3706: 0x60,0),CONCAT210(uVar54,SUB1610(auVar52,0))) >>
3707: 0x50,0),CONCAT28(uVar67,SUB168(auVar52,0))) >>
3708: 0x40,0),uVar75) & 0xffffffffffffffff) << 0x30;
3709: auVar52 = ZEXT1416(CONCAT122(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610
3710: (SUB166(CONCAT412(SUB164(CONCAT214(uVar85,
3711: CONCAT212(uVar69,SUB1612(auVar81,0))) >> 0x60,0),
3712: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
3713: CONCAT28(uVar67,SUB168(auVar81,0))) >> 0x40,0),
3714: uVar75)) << 0x30) >> 0x20,0) &
3715: SUB1612((undefined  [16])0xffffffffffffffff >>
3716: 0x20,0),uVar83)) << 0x10;
3717: *(short *)pauVar24[6] =
3718: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
3719: *(undefined2 *)(pauVar24[6] + 2) = uVar12;
3720: *(short *)(pauVar24[6] + 4) =
3721: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
3722: *(undefined2 *)(pauVar24[6] + 6) = uVar62;
3723: *(short *)(pauVar24[6] + 8) = SUB162(auVar70 >> 0x60,0);
3724: *(undefined2 *)(pauVar24[6] + 10) = uVar88;
3725: *(short *)(pauVar24[6] + 0xc) = SUB162(auVar70 >> 0x70,0);
3726: *(undefined2 *)(pauVar24[6] + 0xe) = uVar58;
3727: *(short *)pauVar24[7] =
3728: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
3729: *(undefined2 *)(pauVar24[7] + 2) = uVar73;
3730: *(short *)(pauVar24[7] + 4) =
3731: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
3732: *(undefined2 *)(pauVar24[7] + 6) = uVar99;
3733: *(short *)(pauVar24[7] + 8) = SUB162(auVar71 >> 0x60,0);
3734: *(undefined2 *)(pauVar24[7] + 10) = uVar56;
3735: *(short *)(pauVar24[7] + 0xc) = SUB162(auVar71 >> 0x70,0);
3736: *(undefined2 *)(pauVar24[7] + 0xe) = uVar63;
3737: pauVar24[3] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
3738: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
3739: (auVar92 >> 0x70,0),
3740: CONCAT212(uVar75,SUB1612(auVar52,0))) >> 0x60,0),
3741: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
3742: CONCAT28(SUB162((auVar92 &
3743: (undefined  [16])
3744: 0xffffffff00000000) >> 0x40,0),
3745: SUB168(auVar52,0))) >> 0x40,0),
3746: (((ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar98 
3747: >> 0x70,0),uVar74)) & 0xffff0000) >> 0x10) << 0x30
3748: ) >> 0x30,0),(SUB166(auVar52,0) >> 0x10) << 0x20)
3749: >> 0x20,0),
3750: SUB164((auVar98 &
3751: (undefined  [16])0xffffffff00000000) >>
3752: 0x40,0));
3753: goto joined_r0x0014cb94;
3754: }
3755: iVar41 = 8;
3756: do {
3757: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
3758: *(undefined2 *)pauVar24[1] = *(undefined2 *)(*pauVar32 + 2);
3759: *(undefined2 *)pauVar24[2] = *(undefined2 *)(*pauVar32 + 4);
3760: *(undefined2 *)pauVar24[3] = *(undefined2 *)(*pauVar32 + 6);
3761: *(undefined2 *)pauVar24[4] = *(undefined2 *)(*pauVar32 + 8);
3762: *(undefined2 *)pauVar24[5] = *(undefined2 *)(*pauVar32 + 10);
3763: *(undefined2 *)pauVar24[6] = *(undefined2 *)(*pauVar32 + 0xc);
3764: *(undefined2 *)pauVar24[7] = *(undefined2 *)(*pauVar32 + 0xe);
3765: iVar41 = iVar41 + -1;
3766: pauVar24 = (undefined (*) [16])(*pauVar24 + 2);
3767: pauVar32 = pauVar32[1];
3768: } while (iVar41 != 0);
3769: uVar50 = (int)uVar20 + 1;
3770: uVar20 = (ulong)uVar50;
3771: plVar23 = plVar23 + 1;
3772: plVar30 = plVar30 + -1;
3773: } while (uVar50 != uVar47);
3774: code_r0x0014c77d:
3775: uVar35 = *(uint *)(lVar49 + 0x1c);
3776: if (uVar35 <= uVar47) goto code_r0x0014c791;
3777: }
3778: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
3779: (param_1,*(undefined8 *)
3780: (param_3 + auStack248._0_8_ * 8),uVar35,
3781: iVar43,0);
3782: iVar43 = *(int *)(lVar49 + 8);
3783: if (0 < iVar43) goto code_r0x0014c675;
3784: code_r0x0014cc4e:
3785: uVar47 = uVar47 + iVar43;
3786: uVar35 = *(uint *)(lVar49 + 0x1c);
3787: } while (uVar47 < uVar35);
3788: code_r0x0014c791:
3789: iVar43 = *(int *)(lVar49 + 0xc);
3790: }
3791: _auStack216 = CONCAT88(uStack208,auStack216 + 1);
3792: } while (iVar16 + 1 < iVar43);
3793: }
3794: uVar39 = uVar39 + iVar43;
3795: } while (uVar39 < *(uint *)(lVar49 + 0x20));
3796: iVar16 = *(int *)(param_2 + 0x4c);
3797: }
3798: auStack248._0_16_ = CONCAT88(auStack248._8_8_,auStack248._0_8_ + 1);
3799: } while (auStack248._0_4_ + 1 < iVar16);
3800: }
3801: break;
3802: case 6:
3803: uVar2 = param_4[0x15];
3804: uVar3 = param_4[0x14];
3805: iVar37 = *(int *)(param_2 + 0x138);
3806: uVar27 = *(uint *)(param_1 + 0x88);
3807: iVar16 = *(int *)(param_2 + 0x13c);
3808: uVar34 = *(uint *)(param_1 + 0x8c);
3809: iVar43 = *(int *)(param_2 + 0x4c);
3810: if (0 < iVar43) {
3811: lVar49 = 0;
3812: do {
3813: lVar22 = lVar49 * 0x60 + *(long *)(param_2 + 0x58);
3814: uVar39 = (uVar27 / (uint)(iVar37 * 8)) * *(int *)(lVar22 + 8);
3815: uVar35 = *(int *)(lVar22 + 8) * uVar3;
3816: uVar47 = (uVar34 / (uint)(iVar16 * 8)) * *(int *)(lVar22 + 0xc);
3817: iVar26 = uVar2 * *(int *)(lVar22 + 0xc);
3818: if (*(int *)(lVar22 + 0x20) != 0) {
3819: uVar50 = 0;
3820: do {
3821: lVar17 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
3822: (param_1,*(undefined8 *)(lVar51 + lVar49 * 8),uVar50);
3823: uVar40 = iVar26 + uVar50;
3824: if (uVar40 < uVar47) {
3825: lVar18 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
3826: (param_1,*(undefined8 *)(param_3 + lVar49 * 8),
3827: ((uVar47 - iVar26) - uVar50) - *(int *)(lVar22 + 0xc));
3828: }
3829: else {
3830: lVar18 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
3831: (param_1,*(undefined8 *)(param_3 + lVar49 * 8),uVar40);
3832: }
3833: iVar43 = *(int *)(lVar22 + 0xc);
3834: if (0 < iVar43) {
3835: uVar46 = *(uint *)(lVar22 + 0x1c);
3836: lVar44 = 0;
3837: do {
3838: while( true ) {
3839: puVar45 = *(undefined2 **)(lVar17 + lVar44 * 8);
3840: iVar33 = (int)lVar44;
3841: if (uVar47 <= uVar40) break;
3842: lVar48 = *(long *)(lVar18 + -8 + (long)(iVar43 - iVar33) * 8);
3843: if (uVar46 != 0) {
3844: uVar36 = ~uVar35 + uVar39;
3845: uVar25 = uVar35;
3846: do {
3847: while (uVar39 <= uVar25) {
3848: puVar28 = (undefined2 *)((ulong)uVar25 * 0x80 + lVar48);
3849: puVar19 = puVar45;
3850: puVar29 = puVar28;
3851: do {
3852: puVar38 = puVar29 + 0x10;
3853: *puVar19 = *puVar29;
3854: puVar19[1] = puVar29[1];
3855: puVar19[2] = puVar29[2];
3856: puVar19[3] = puVar29[3];
3857: puVar19[4] = puVar29[4];
3858: puVar19[5] = puVar29[5];
3859: puVar19[6] = puVar29[6];
3860: puVar19[7] = puVar29[7];
3861: puVar19[8] = -puVar29[8];
3862: puVar19[9] = -puVar29[9];
3863: puVar19[10] = -puVar29[10];
3864: puVar19[0xb] = -puVar29[0xb];
3865: puVar19[0xc] = -puVar29[0xc];
3866: puVar19[0xd] = -puVar29[0xd];
3867: puVar19[0xe] = -puVar29[0xe];
3868: puVar19[0xf] = -puVar29[0xf];
3869: puVar19 = puVar19 + 0x10;
3870: puVar29 = puVar38;
3871: } while (puVar28 + 0x40 != puVar38);
3872: puVar45 = puVar45 + 0x40;
3873: uVar25 = uVar25 + 1;
3874: uVar36 = uVar36 - 1;
3875: if (uVar25 == uVar46 + uVar35) goto code_r0x0014c0d8;
3876: }
3877: puVar19 = puVar45;
3878: puVar29 = (undefined2 *)((ulong)uVar36 * 0x80 + lVar48);
3879: do {
3880: puVar28 = puVar19 + 0x10;
3881: *puVar19 = *puVar29;
3882: puVar19[1] = -puVar29[1];
3883: puVar19[2] = puVar29[2];
3884: puVar19[3] = -puVar29[3];
3885: puVar19[4] = puVar29[4];
3886: puVar19[5] = -puVar29[5];
3887: puVar19[6] = puVar29[6];
3888: puVar19[7] = -puVar29[7];
3889: puVar19[8] = -puVar29[8];
3890: puVar19[9] = puVar29[9];
3891: puVar19[10] = -puVar29[10];
3892: puVar19[0xb] = puVar29[0xb];
3893: puVar19[0xc] = -puVar29[0xc];
3894: puVar19[0xd] = puVar29[0xd];
3895: puVar19[0xe] = -puVar29[0xe];
3896: puVar19[0xf] = puVar29[0xf];
3897: puVar19 = puVar28;
3898: puVar29 = puVar29 + 0x10;
3899: } while (puVar45 + 0x40 != puVar28);
3900: uVar25 = uVar25 + 1;
3901: uVar36 = uVar36 - 1;
3902: puVar45 = puVar45 + 0x40;
3903: } while (uVar25 != uVar46 + uVar35);
3904: }
3905: code_r0x0014c0d8:
3906: lVar44 = lVar44 + 1;
3907: if (iVar43 <= iVar33 + 1) goto code_r0x0014c0e9;
3908: }
3909: lVar48 = *(long *)(lVar18 + lVar44 * 8);
3910: if (uVar46 == 0) goto code_r0x0014c0d8;
3911: uVar36 = 0;
3912: do {
3913: while (uVar35 + uVar36 < uVar39) {
3914: pauVar21 = (undefined (*) [16])(puVar45 + (ulong)uVar36 * 0x40);
3915: pauVar24 = (undefined (*) [16])
3916: ((ulong)(((uVar39 - uVar35) + -1) - uVar36) * 0x80 + lVar48);
3917: if ((pauVar21 < pauVar24[2]) && (pauVar24 < pauVar21[2])) {
3918: pauVar32 = pauVar21;
3919: do {
3920: puVar15 = *pauVar32;
3921: *(undefined2 *)*pauVar32 = *(undefined2 *)*pauVar24;
3922: *(short *)(*pauVar32 + 2) = -*(short *)(*pauVar24 + 2);
3923: pauVar32 = (undefined (*) [16])(puVar15 + 4);
3924: pauVar24 = (undefined (*) [16])(*pauVar24 + 4);
3925: } while ((undefined (*) [16])(puVar15 + 4) != pauVar21[8]);
3926: }
3927: else {
3928: auVar71 = *pauVar24;
3929: uVar75 = *(undefined2 *)pauVar24[1];
3930: uVar54 = *(undefined2 *)(pauVar24[1] + 2);
3931: uVar55 = *(undefined2 *)(pauVar24[1] + 4);
3932: sVar11 = *(short *)(pauVar24[1] + 6);
3933: uVar12 = *(undefined2 *)(pauVar24[1] + 8);
3934: uVar73 = *(undefined2 *)(pauVar24[1] + 0xc);
3935: sVar13 = *(short *)(pauVar24[1] + 0xe);
3936: sVar77 = SUB162(auVar71 >> 0x30,0);
3937: uVar74 = SUB162(auVar71 >> 0x20,0);
3938: uVar72 = SUB162(auVar71 >> 0x10,0);
3939: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
3940: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
3941: auVar71,0))) >> 0x60,0),
3942: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
3943: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
3944: uVar54),uVar72)) << 0x20;
3945: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3946: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
3947: 0))) >> 0x60,0),
3948: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
3949: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
3950: uVar54)) << 0x30 &
3951: (undefined  [16])0xffffffff00000000;
3952: uVar83 = SUB162(auVar71 >> 0x50,0);
3953: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3954: CONCAT214(*(undefined2 *)(pauVar24[1] + 10),
3955: CONCAT212(uVar54,SUB1612(auVar52,0))) >>
3956: 0x60,0),CONCAT210(uVar83,SUB1610(auVar52,0))) >>
3957: 0x50,0),CONCAT28(uVar72,SUB168(auVar52,0))) >>
3958: 0x40,0),uVar12)) << 0x30 &
3959: (undefined  [16])0xffffffff00000000;
3960: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
3961: CONCAT214(*(undefined2 *)(pauVar24[1] + 10),
3962: CONCAT212(SUB162(auVar70 >> 0x30,0),
3963: SUB1612(auVar70,0))) >> 0x60,0
3964: ),CONCAT210(uVar83,SUB1610(auVar70,0))) >> 0x50,0)
3965: ,CONCAT28(uVar72,SUB168(auVar70,0))) >> 0x40,0),
3966: uVar12)) << 0x30;
3967: uVar20 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar74))
3968: & 0xffff0000;
3969: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
3970: CONCAT412(SUB164(CONCAT214(uVar73,CONCAT212(uVar12
3971: ,SUB1612(auVar52,0))) >> 0x60,0),
3972: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
3973: CONCAT28(uVar75,SUB168(auVar52,0))) >> 0x40,0),
3974: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
3975: SUB1612((undefined  [16])0xffff000000000000 >>
3976: 0x20,0),uVar74)) << 0x10;
3977: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
3978: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
3979: *pauVar21 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
3980: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
3981: >> 0x70,0),
3982: CONCAT212((short)(uVar20 >> 0x10),
3983: SUB1612(auVar52,0))) >> 0x60,0),
3984: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
3985: CONCAT28(SUB162(auVar71 >> 0x40,0),
3986: SUB168(auVar52,0))) >> 0x40,0),
3987: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
3988: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
3989: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
3990: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
3991: *(undefined2 *)pauVar21[1] = uVar75;
3992: *(short *)(pauVar21[1] + 2) = -SUB162(auVar70 >> 0x60,0);
3993: *(undefined2 *)(pauVar21[1] + 4) = uVar55;
3994: *(short *)(pauVar21[1] + 6) = -sVar11;
3995: *(undefined2 *)(pauVar21[1] + 8) = uVar12;
3996: *(short *)(pauVar21[1] + 10) = -SUB162(auVar70 >> 0x70,0);
3997: *(undefined2 *)(pauVar21[1] + 0xc) = uVar73;
3998: *(short *)(pauVar21[1] + 0xe) = -sVar13;
3999: auVar71 = pauVar24[2];
4000: uVar75 = *(undefined2 *)pauVar24[3];
4001: uVar54 = *(undefined2 *)(pauVar24[3] + 2);
4002: uVar55 = *(undefined2 *)(pauVar24[3] + 4);
4003: sVar11 = *(short *)(pauVar24[3] + 6);
4004: uVar12 = *(undefined2 *)(pauVar24[3] + 8);
4005: uVar73 = *(undefined2 *)(pauVar24[3] + 0xc);
4006: sVar13 = *(short *)(pauVar24[3] + 0xe);
4007: sVar77 = SUB162(auVar71 >> 0x30,0);
4008: uVar74 = SUB162(auVar71 >> 0x20,0);
4009: uVar72 = SUB162(auVar71 >> 0x10,0);
4010: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4011: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
4012: auVar71,0))) >> 0x60,0),
4013: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
4014: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
4015: uVar54),uVar72)) << 0x20;
4016: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4017: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
4018: 0))) >> 0x60,0),
4019: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
4020: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
4021: uVar54)) << 0x30 &
4022: (undefined  [16])0xffffffff00000000;
4023: uVar83 = SUB162(auVar71 >> 0x50,0);
4024: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4025: CONCAT214(*(undefined2 *)(pauVar24[3] + 10),
4026: CONCAT212(uVar54,SUB1612(auVar52,0))) >>
4027: 0x60,0),CONCAT210(uVar83,SUB1610(auVar52,0))) >>
4028: 0x50,0),CONCAT28(uVar72,SUB168(auVar52,0))) >>
4029: 0x40,0),uVar12)) << 0x30 &
4030: (undefined  [16])0xffffffff00000000;
4031: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4032: CONCAT214(*(undefined2 *)(pauVar24[3] + 10),
4033: CONCAT212(SUB162(auVar70 >> 0x30,0),
4034: SUB1612(auVar70,0))) >> 0x60,0
4035: ),CONCAT210(uVar83,SUB1610(auVar70,0))) >> 0x50,0)
4036: ,CONCAT28(uVar72,SUB168(auVar70,0))) >> 0x40,0),
4037: uVar12)) << 0x30;
4038: uVar20 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar74))
4039: & 0xffff0000;
4040: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
4041: CONCAT412(SUB164(CONCAT214(uVar73,CONCAT212(uVar12
4042: ,SUB1612(auVar52,0))) >> 0x60,0),
4043: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
4044: CONCAT28(uVar75,SUB168(auVar52,0))) >> 0x40,0),
4045: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
4046: SUB1612((undefined  [16])0xffff000000000000 >>
4047: 0x20,0),uVar74)) << 0x10;
4048: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
4049: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
4050: pauVar21[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
4051: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
4052: >> 0x70,0),
4053: CONCAT212((short)(uVar20 >> 0x10),
4054: SUB1612(auVar52,0))) >> 0x60,0),
4055: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
4056: CONCAT28(SUB162(auVar71 >> 0x40,0),
4057: SUB168(auVar52,0))) >> 0x40,0),
4058: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
4059: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
4060: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
4061: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
4062: *(undefined2 *)pauVar21[3] = uVar75;
4063: *(short *)(pauVar21[3] + 2) = -SUB162(auVar70 >> 0x60,0);
4064: *(undefined2 *)(pauVar21[3] + 4) = uVar55;
4065: *(short *)(pauVar21[3] + 6) = -sVar11;
4066: *(undefined2 *)(pauVar21[3] + 8) = uVar12;
4067: *(short *)(pauVar21[3] + 10) = -SUB162(auVar70 >> 0x70,0);
4068: *(undefined2 *)(pauVar21[3] + 0xc) = uVar73;
4069: *(short *)(pauVar21[3] + 0xe) = -sVar13;
4070: auVar71 = pauVar24[4];
4071: uVar75 = *(undefined2 *)pauVar24[5];
4072: uVar54 = *(undefined2 *)(pauVar24[5] + 2);
4073: uVar55 = *(undefined2 *)(pauVar24[5] + 4);
4074: sVar11 = *(short *)(pauVar24[5] + 6);
4075: uVar12 = *(undefined2 *)(pauVar24[5] + 8);
4076: uVar73 = *(undefined2 *)(pauVar24[5] + 0xc);
4077: sVar13 = *(short *)(pauVar24[5] + 0xe);
4078: sVar77 = SUB162(auVar71 >> 0x30,0);
4079: uVar74 = SUB162(auVar71 >> 0x20,0);
4080: uVar72 = SUB162(auVar71 >> 0x10,0);
4081: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4082: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
4083: auVar71,0))) >> 0x60,0),
4084: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
4085: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
4086: uVar54),uVar72)) << 0x20;
4087: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4088: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
4089: 0))) >> 0x60,0),
4090: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
4091: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
4092: uVar54)) << 0x30 &
4093: (undefined  [16])0xffffffff00000000;
4094: uVar83 = SUB162(auVar71 >> 0x50,0);
4095: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4096: CONCAT214(*(undefined2 *)(pauVar24[5] + 10),
4097: CONCAT212(uVar54,SUB1612(auVar52,0))) >>
4098: 0x60,0),CONCAT210(uVar83,SUB1610(auVar52,0))) >>
4099: 0x50,0),CONCAT28(uVar72,SUB168(auVar52,0))) >>
4100: 0x40,0),uVar12)) << 0x30 &
4101: (undefined  [16])0xffffffff00000000;
4102: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4103: CONCAT214(*(undefined2 *)(pauVar24[5] + 10),
4104: CONCAT212(SUB162(auVar70 >> 0x30,0),
4105: SUB1612(auVar70,0))) >> 0x60,0
4106: ),CONCAT210(uVar83,SUB1610(auVar70,0))) >> 0x50,0)
4107: ,CONCAT28(uVar72,SUB168(auVar70,0))) >> 0x40,0),
4108: uVar12)) << 0x30;
4109: uVar20 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar74))
4110: & 0xffff0000;
4111: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
4112: CONCAT412(SUB164(CONCAT214(uVar73,CONCAT212(uVar12
4113: ,SUB1612(auVar52,0))) >> 0x60,0),
4114: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
4115: CONCAT28(uVar75,SUB168(auVar52,0))) >> 0x40,0),
4116: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
4117: SUB1612((undefined  [16])0xffff000000000000 >>
4118: 0x20,0),uVar74)) << 0x10;
4119: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
4120: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
4121: pauVar21[4] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
4122: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
4123: >> 0x70,0),
4124: CONCAT212((short)(uVar20 >> 0x10),
4125: SUB1612(auVar52,0))) >> 0x60,0),
4126: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
4127: CONCAT28(SUB162(auVar71 >> 0x40,0),
4128: SUB168(auVar52,0))) >> 0x40,0),
4129: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
4130: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
4131: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
4132: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
4133: *(undefined2 *)pauVar21[5] = uVar75;
4134: *(short *)(pauVar21[5] + 2) = -SUB162(auVar70 >> 0x60,0);
4135: *(undefined2 *)(pauVar21[5] + 4) = uVar55;
4136: *(short *)(pauVar21[5] + 6) = -sVar11;
4137: *(undefined2 *)(pauVar21[5] + 8) = uVar12;
4138: *(short *)(pauVar21[5] + 10) = -SUB162(auVar70 >> 0x70,0);
4139: *(undefined2 *)(pauVar21[5] + 0xc) = uVar73;
4140: *(short *)(pauVar21[5] + 0xe) = -sVar13;
4141: auVar71 = pauVar24[6];
4142: uVar75 = *(undefined2 *)pauVar24[7];
4143: uVar54 = *(undefined2 *)(pauVar24[7] + 2);
4144: uVar55 = *(undefined2 *)(pauVar24[7] + 4);
4145: sVar11 = *(short *)(pauVar24[7] + 6);
4146: uVar12 = *(undefined2 *)(pauVar24[7] + 8);
4147: uVar73 = *(undefined2 *)(pauVar24[7] + 0xc);
4148: sVar13 = *(short *)(pauVar24[7] + 0xe);
4149: sVar77 = SUB162(auVar71 >> 0x30,0);
4150: uVar74 = SUB162(auVar71 >> 0x20,0);
4151: uVar72 = SUB162(auVar71 >> 0x10,0);
4152: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4153: SUB164(CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(
4154: auVar71,0))) >> 0x60,0),
4155: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
4156: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
4157: uVar54),uVar72)) << 0x20;
4158: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4159: CONCAT214(sVar11,CONCAT212(sVar77,SUB1612(auVar71,
4160: 0))) >> 0x60,0),
4161: CONCAT210(uVar55,SUB1610(auVar71,0))) >> 0x50,0),
4162: CONCAT28(uVar74,SUB168(auVar71,0))) >> 0x40,0),
4163: uVar54)) << 0x30 &
4164: (undefined  [16])0xffffffff00000000;
4165: uVar83 = SUB162(auVar71 >> 0x50,0);
4166: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4167: CONCAT214(*(undefined2 *)(pauVar24[7] + 10),
4168: CONCAT212(uVar54,SUB1612(auVar52,0))) >>
4169: 0x60,0),CONCAT210(uVar83,SUB1610(auVar52,0))) >>
4170: 0x50,0),CONCAT28(uVar72,SUB168(auVar52,0))) >>
4171: 0x40,0),uVar12)) << 0x30 &
4172: (undefined  [16])0xffffffff00000000;
4173: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4174: CONCAT214(*(undefined2 *)(pauVar24[7] + 10),
4175: CONCAT212(SUB162(auVar70 >> 0x30,0),
4176: SUB1612(auVar70,0))) >> 0x60,0
4177: ),CONCAT210(uVar83,SUB1610(auVar70,0))) >> 0x50,0)
4178: ,CONCAT28(uVar72,SUB168(auVar70,0))) >> 0x40,0),
4179: uVar12)) << 0x30;
4180: uVar20 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar74))
4181: & 0xffff0000;
4182: auVar52 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(
4183: CONCAT412(SUB164(CONCAT214(uVar73,CONCAT212(uVar12
4184: ,SUB1612(auVar52,0))) >> 0x60,0),
4185: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
4186: CONCAT28(uVar75,SUB168(auVar52,0))) >> 0x40,0),
4187: (uVar20 >> 0x10) << 0x30) >> 0x20,0) &
4188: SUB1612((undefined  [16])0xffff000000000000 >>
4189: 0x20,0),uVar74)) << 0x10;
4190: uVar5 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
4191: sVar1 = -SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
4192: pauVar21[6] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
4193: SUB166(CONCAT412(SUB164(CONCAT214(-SUB162(auVar71 
4194: >> 0x70,0),
4195: CONCAT212((short)(uVar20 >> 0x10),
4196: SUB1612(auVar52,0))) >> 0x60,0),
4197: CONCAT210(sVar1,SUB1610(auVar52,0))) >> 0x50,0),
4198: CONCAT28(SUB162(auVar71 >> 0x40,0),
4199: SUB168(auVar52,0))) >> 0x40,0),
4200: (((ulong)CONCAT24(sVar1,CONCAT22(-sVar77,uVar5)) &
4201: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
4202: (SUB166(auVar52,0) >> 0x10) << 0x20) >> 0x20,0),
4203: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
4204: *(undefined2 *)pauVar21[7] = uVar75;
4205: *(short *)(pauVar21[7] + 2) = -SUB162(auVar70 >> 0x60,0);
4206: *(undefined2 *)(pauVar21[7] + 4) = uVar55;
4207: *(short *)(pauVar21[7] + 6) = -sVar11;
4208: *(undefined2 *)(pauVar21[7] + 8) = uVar12;
4209: *(short *)(pauVar21[7] + 10) = -SUB162(auVar70 >> 0x70,0);
4210: *(undefined2 *)(pauVar21[7] + 0xc) = uVar73;
4211: *(short *)(pauVar21[7] + 0xe) = -sVar13;
4212: }
4213: uVar25 = uVar36 + 1;
4214: uVar36 = uVar36 + 1;
4215: if (uVar46 <= uVar25) goto code_r0x0014c44f;
4216: }
4217: uVar20 = (ulong)uVar36;
4218: uVar25 = uVar36 + 1;
4219: uVar36 = uVar36 + 1;
4220: FUN_0013beb0(lVar48 + (uVar20 + uVar35) * 0x80,puVar45 + uVar20 * 0x40,1);
4221: uVar46 = *(uint *)(lVar22 + 0x1c);
4222: } while (uVar25 < uVar46);
4223: code_r0x0014c44f:
4224: iVar43 = *(int *)(lVar22 + 0xc);
4225: lVar44 = lVar44 + 1;
4226: } while (iVar33 + 1 < iVar43);
4227: }
4228: code_r0x0014c0e9:
4229: uVar50 = uVar50 + iVar43;
4230: } while (uVar50 < *(uint *)(lVar22 + 0x20));
4231: iVar43 = *(int *)(param_2 + 0x4c);
4232: }
4233: iVar26 = (int)lVar49;
4234: lVar49 = lVar49 + 1;
4235: } while (iVar26 + 1 < iVar43);
4236: }
4237: break;
4238: case 7:
4239: uVar2 = param_4[0x15];
4240: uVar3 = param_4[0x14];
4241: iVar37 = *(int *)(param_2 + 0x13c);
4242: uVar27 = *(uint *)(param_1 + 0x88);
4243: iVar16 = *(int *)(param_2 + 0x4c);
4244: if (0 < iVar16) {
4245: lStack200 = 0;
4246: do {
4247: lVar49 = lStack200 * 0x60 + *(long *)(param_2 + 0x58);
4248: iVar43 = *(int *)(lVar49 + 8);
4249: iVar26 = *(int *)(lVar49 + 0xc);
4250: uVar34 = (uVar27 / (uint)(iVar37 * 8)) * iVar26;
4251: iVar33 = uVar2 * iVar26;
4252: if (*(int *)(lVar49 + 0x20) != 0) {
4253: auStack184 = auStack184 & (undefined  [16])0xffffffff00000000;
4254: do {
4255: lVar22 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
4256: (param_1,*(undefined8 *)(lVar51 + lStack200 * 8),auStack184._0_4_,
4257: iVar26,1);
4258: iVar26 = *(int *)(lVar49 + 0xc);
4259: if (0 < iVar26) {
4260: uVar35 = auStack184._0_4_ + iVar33;
4261: uVar39 = *(uint *)(lVar49 + 0x1c);
4262: lStack192 = 0;
4263: auStack168 = CONCAT124(auStack168._4_12_,((uVar34 - iVar33) + -1) - auStack184._0_4_
4264: );
4265: do {
4266: iVar16 = (int)lStack192;
4267: if (uVar39 != 0) {
4268: uVar20 = 0;
4269: _auStack216 = CONCAT124(stack0xffffffffffffff2c,*(undefined4 *)(lVar49 + 8));
4270: do {
4271: while( true ) {
4272: iVar41 = (int)uVar20;
4273: plVar23 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
4274: (param_1,*(undefined8 *)
4275: (param_3 + lStack200 * 8),
4276: iVar41 + uVar3 * iVar43,auStack216._0_4_,0);
4277: iVar26 = *(int *)(lVar49 + 8);
4278: _auStack216 = CONCAT124(stack0xffffffffffffff2c,iVar26);
4279: if (iVar26 < 1) break;
4280: lVar17 = *(long *)(lVar22 + lStack192 * 8);
4281: uVar47 = iVar41 + iVar26;
4282: do {
4283: while( true ) {
4284: pauVar24 = (undefined (*) [16])(uVar20 * 0x80 + lVar17);
4285: if (uVar34 <= uVar35) break;
4286: pauVar32 = (undefined (*) [16])
4287: ((ulong)auStack168._0_4_ * 0x80 + *plVar23);
4288: pauVar21 = pauVar32[8];
4289: if (((((((pauVar32 < pauVar24[7] && pauVar24[6] < pauVar21 ||
4290: pauVar32 < pauVar24[8] && pauVar24[7] < pauVar21) ||
4291: pauVar32 < pauVar24[6] && pauVar24[5] < pauVar21) ||
4292: pauVar32 < pauVar24[5] && pauVar24[4] < pauVar21) ||
4293: pauVar32 < pauVar24[4] && pauVar24[3] < pauVar21) ||
4294: pauVar32 < pauVar24[3] && pauVar24[2] < pauVar21) ||
4295: pauVar32 < pauVar24[2] && pauVar24[1] < pauVar21) ||
4296: (pauVar32 < pauVar24[1] && pauVar24 < pauVar21)) {
4297: iVar26 = 8;
4298: do {
4299: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
4300: *(short *)pauVar24[1] = -*(short *)(*pauVar32 + 2);
4301: *(undefined2 *)pauVar24[2] = *(undefined2 *)(*pauVar32 + 4);
4302: *(short *)pauVar24[3] = -*(short *)(*pauVar32 + 6);
4303: *(undefined2 *)pauVar24[4] = *(undefined2 *)(*pauVar32 + 8);
4304: *(short *)pauVar24[5] = -*(short *)(*pauVar32 + 10);
4305: *(undefined2 *)pauVar24[6] = *(undefined2 *)(*pauVar32 + 0xc);
4306: *(short *)pauVar24[7] = -*(short *)(*pauVar32 + 0xe);
4307: iVar26 = iVar26 + -1;
4308: pauVar24 = (undefined (*) [16])(*pauVar24 + 2);
4309: pauVar32 = pauVar32[1];
4310: } while (iVar26 != 0);
4311: }
4312: else {
4313: auVar71 = *pauVar32;
4314: uVar5 = *(ushort *)pauVar32[1];
4315: uVar75 = *(undefined2 *)(pauVar32[1] + 2);
4316: uVar54 = *(undefined2 *)(pauVar32[1] + 4);
4317: uVar55 = *(undefined2 *)(pauVar32[1] + 8);
4318: uVar12 = *(undefined2 *)(pauVar32[1] + 0xc);
4319: sVar1 = *(short *)(pauVar32[1] + 0xe);
4320: auVar52 = pauVar32[2];
4321: uVar94 = SUB162(auVar71 >> 0x30,0);
4322: uVar93 = SUB162(auVar71 >> 0x20,0);
4323: uVar114 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4324: (pauVar32[1] + 6),
4325: CONCAT212(uVar94,SUB1612(
4326: auVar71,0))) >> 0x60,0),
4327: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0);
4328: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar114,CONCAT28(uVar93,
4329: SUB168(auVar71,0))) >> 0x40,0),uVar75)) << 0x30 &
4330: (undefined  [16])0xffffffff00000000;
4331: uVar56 = SUB162(auVar71 >> 0x40,0);
4332: uVar62 = SUB162(auVar71 >> 0x50,0);
4333: uVar60 = SUB162(auVar71 >> 0x70,0);
4334: uVar73 = *(undefined2 *)pauVar32[3];
4335: uVar72 = *(undefined2 *)(pauVar32[3] + 4);
4336: uVar74 = *(undefined2 *)(pauVar32[3] + 6);
4337: uVar83 = *(undefined2 *)(pauVar32[3] + 0xc);
4338: sVar11 = *(short *)(pauVar32[3] + 0xe);
4339: uVar99 = SUB162(auVar71 >> 0x10,0);
4340: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4341: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4342: (pauVar32[1] + 6),
4343: CONCAT212(uVar94,
4344: SUB1612(auVar71,0))) >> 0x60,0),
4345: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
4346: CONCAT28(uVar93,SUB168(auVar71,0))) >> 0x40,0),
4347: uVar75),uVar99)) << 0x20;
4348: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4349: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
4350: CONCAT212(uVar75,SUB1612(auVar70,0))) >>
4351: 0x60,0),CONCAT210(uVar62,SUB1610(auVar70,0))) >>
4352: 0x50,0),CONCAT28(uVar99,SUB168(auVar70,0))) >>
4353: 0x40,0),uVar55)) << 0x30 &
4354: (undefined  [16])0xffffffff00000000;
4355: auVar70 = pauVar32[4];
4356: uVar67 = SUB162(auVar52 >> 0x30,0);
4357: uVar66 = SUB162(auVar52 >> 0x20,0);
4358: uVar39 = SUB164(auVar52,0) & 0xffff;
4359: auVar97 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4360: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
4361: CONCAT212(SUB162(auVar81 >> 0x30,0),
4362: SUB1612(auVar81,0))) >> 0x60,0
4363: ),CONCAT210(uVar62,SUB1610(auVar81,0))) >> 0x50,0)
4364: ,CONCAT28(uVar99,SUB168(auVar81,0))) >> 0x40,0),
4365: uVar55)) << 0x30;
4366: uVar58 = SUB162(auVar52 >> 0x10,0);
4367: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4368: CONCAT412(SUB164(CONCAT214(uVar74,CONCAT212(uVar67
4369: ,SUB1612(auVar52,0))) >> 0x60,0),
4370: CONCAT210(uVar72,SUB1610(auVar52,0))) >> 0x50,0),
4371: CONCAT28(uVar66,SUB168(auVar52,0))) >> 0x40,0),
4372: *(undefined2 *)(pauVar32[3] + 2)),uVar58)) << 0x20
4373: ;
4374: uVar57 = SUB162(auVar52 >> 0x40,0);
4375: uVar59 = SUB162(auVar52 >> 0x60,0);
4376: uVar61 = SUB162(auVar52 >> 0x70,0);
4377: uVar75 = *(undefined2 *)pauVar32[5];
4378: uVar62 = *(undefined2 *)(pauVar32[5] + 2);
4379: uVar99 = *(undefined2 *)(pauVar32[5] + 4);
4380: uVar64 = *(undefined2 *)(pauVar32[5] + 8);
4381: uVar87 = *(undefined2 *)(pauVar32[5] + 0xc);
4382: sVar13 = *(short *)(pauVar32[5] + 0xe);
4383: uVar113 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,
4384: CONCAT212(uVar55,SUB1612(auVar82,0))) >> 0x60,0),
4385: CONCAT210(uVar54,SUB1610(auVar82,0))) >> 0x50,0),
4386: CONCAT28(uVar5,SUB168(auVar82,0))) >> 0x40,0);
4387: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),
4388: uVar93)) & 0xffff0000;
4389: auVar98 = CONCAT88(uVar113,(uVar6 >> 0x10) << 0x30) &
4390: (undefined  [16])0xffff000000000000;
4391: uVar84 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >>
4392: 0x50,0);
4393: sVar103 = SUB162(auVar97 >> 0x60,0);
4394: uVar90 = SUB162(auVar70 >> 0x30,0);
4395: uVar85 = SUB162(auVar70 >> 0x20,0);
4396: uVar109 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4397: (pauVar32[5] + 6),
4398: CONCAT212(uVar90,SUB1612(
4399: auVar70,0))) >> 0x60,0),
4400: CONCAT210(uVar99,SUB1610(auVar70,0))) >> 0x50,0);
4401: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar109,CONCAT28(uVar85,
4402: SUB168(auVar70,0))) >> 0x40,0),uVar62)) << 0x30 &
4403: (undefined  [16])0xffffffff00000000;
4404: auVar81 = pauVar32[6];
4405: uVar86 = *(undefined2 *)(pauVar32[7] + 8);
4406: uVar88 = *(undefined2 *)(pauVar32[7] + 0xc);
4407: sVar77 = *(short *)(pauVar32[7] + 0xe);
4408: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4409: CONCAT214(*(undefined2 *)(pauVar32[3] + 10),
4410: CONCAT212(SUB162(auVar92 >> 0x30,0),
4411: SUB1612(auVar92,0))) >> 0x60,0
4412: ),CONCAT210(SUB162(auVar52 >> 0x50,0),
4413: SUB1610(auVar92,0))) >> 0x50,0),
4414: CONCAT28(uVar58,SUB168(auVar92,0))) >> 0x40,0),
4415: *(undefined2 *)(pauVar32[3] + 8))) << 0x30;
4416: uVar79 = SUB162(auVar70 >> 0x10,0);
4417: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4418: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4419: (pauVar32[5] + 6),
4420: CONCAT212(uVar90,
4421: SUB1612(auVar70,0))) >> 0x60,0),
4422: CONCAT210(uVar99,SUB1610(auVar70,0))) >> 0x50,0),
4423: CONCAT28(uVar85,SUB168(auVar70,0))) >> 0x40,0),
4424: uVar62),uVar79)) << 0x20;
4425: uVar58 = SUB162(auVar70 >> 0x40,0);
4426: uVar63 = SUB162(auVar70 >> 0x50,0);
4427: uVar65 = SUB162(auVar70 >> 0x70,0);
4428: sVar125 = SUB162((auVar116 & (undefined  [16])0xffffffff00000000) >>
4429: 0x40,0);
4430: uVar105 = SUB162((auVar116 & (undefined  [16])0xffffffff00000000) >>
4431: 0x50,0);
4432: sVar128 = SUB162(auVar116 >> 0x70,0);
4433: uVar68 = SUB162(auVar81 >> 0x40,0);
4434: uVar69 = SUB162(auVar81 >> 0x60,0);
4435: uVar76 = SUB162(auVar81 >> 0x70,0);
4436: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4437: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
4438: CONCAT212(uVar62,SUB1612(auVar82,0))) >>
4439: 0x60,0),CONCAT210(uVar63,SUB1610(auVar82,0))) >>
4440: 0x50,0),CONCAT28(uVar79,SUB168(auVar82,0))) >>
4441: 0x40,0),uVar64)) << 0x30 &
4442: (undefined  [16])0xffffffff00000000;
4443: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4444: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
4445: CONCAT212(SUB162(auVar52 >> 0x30,0),
4446: SUB1612(auVar52,0))) >> 0x60,0
4447: ),CONCAT210(uVar63,SUB1610(auVar52,0))) >> 0x50,0)
4448: ,CONCAT28(uVar79,SUB168(auVar52,0))) >> 0x40,0),
4449: uVar64)) << 0x30;
4450: uVar102 = SUB162(auVar81 >> 0x30,0);
4451: uVar100 = SUB162(auVar81 >> 0x20,0);
4452: uVar96 = SUB162(auVar81 >> 0x10,0);
4453: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4454: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4455: (pauVar32[7] + 6),
4456: CONCAT212(uVar102,
4457: SUB1612(auVar81,0))) >> 0x60,0),
4458: CONCAT210(*(undefined2 *)(pauVar32[7] + 4),
4459: SUB1610(auVar81,0))) >> 0x50,0),
4460: CONCAT28(uVar100,SUB168(auVar81,0))) >> 0x40,0),
4461: *(undefined2 *)(pauVar32[7] + 2)),uVar96)) << 0x20
4462: ;
4463: uVar62 = SUB162(auVar81,0);
4464: uVar7 = (ulong)CONCAT24(uVar99,CONCAT22(SUB162(auVar70 >> 0x60,0),
4465: uVar85)) & 0xffff0000;
4466: auVar92 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
4467: uVar87,CONCAT212(uVar64,SUB1612(auVar92,0))) >>
4468: 0x60,0),CONCAT210(uVar99,SUB1610(auVar92,0))) >>
4469: 0x50,0),CONCAT28(uVar75,SUB168(auVar92,0))) >>
4470: 0x40,0),(uVar7 >> 0x10) << 0x30) &
4471: (undefined  [16])0xffff000000000000;
4472: uVar79 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >>
4473: 0x50,0);
4474: sVar89 = SUB162(auVar82 >> 0x60,0);
4475: sVar95 = SUB162(auVar82 >> 0x70,0);
4476: uVar63 = (undefined2)(uVar6 >> 0x10);
4477: uVar10 = SUB166(CONCAT412(SUB164(CONCAT214(uVar59,CONCAT212(uVar63,
4478: SUB1612(auVar98,0))) >> 0x60,0),
4479: CONCAT210(uVar57,SUB1610(auVar98,0))) >> 0x50,0);
4480: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar10,CONCAT28(uVar56,
4481: SUB168(auVar98,0))) >> 0x40,0),uVar66) &
4482: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30
4483: ,0)) << 0x30 &
4484: (undefined  [16])0xffffffff00000000;
4485: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4486: CONCAT214(*(undefined2 *)(pauVar32[7] + 10),
4487: CONCAT212(SUB162(auVar106 >> 0x30,0),
4488: SUB1612(auVar106,0))) >> 0x60,
4489: 0),CONCAT210(SUB162(auVar81 >> 0x50,0),
4490: SUB1610(auVar106,0))) >> 0x50,0),
4491: CONCAT28(uVar96,SUB168(auVar106,0))) >> 0x40,0),
4492: uVar86)) << 0x30;
4493: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4494: CONCAT412(SUB164(CONCAT214(uVar59,CONCAT212(uVar63
4495: ,SUB1612(auVar98,0))) >> 0x60,0),
4496: CONCAT210(uVar57,SUB1610(auVar98,0))) >> 0x50,0),
4497: CONCAT28(uVar56,SUB168(auVar98,0))) >> 0x40,0),
4498: uVar66) & SUB1610((undefined  [16])
4499: 0xffffffffffffffff >> 0x30,0),
4500: uVar93)) << 0x20;
4501: sVar121 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
4502: 0x40,0);
4503: uVar96 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >>
4504: 0x50,0);
4505: auVar110 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4506: CONCAT214(uVar72,CONCAT212(SUB162(auVar81 >> 0x30,
4507: 0),
4508: SUB1612(auVar81,0))) >>
4509: 0x60,0),CONCAT210(uVar54,SUB1610(auVar81,0))) >>
4510: 0x50,0),CONCAT28(uVar93,SUB168(auVar81,0))) >>
4511: 0x40,0),uVar73)) << 0x30;
4512: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4513: CONCAT214(uVar72,CONCAT212(uVar66,SUB1612(auVar52,
4514: 0))) >> 0x60,0),
4515: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
4516: CONCAT28(uVar93,SUB168(auVar52,0))) >> 0x40,0),
4517: uVar73)) << 0x30 &
4518: (undefined  [16])0xffffffff00000000;
4519: uVar54 = (undefined2)(uVar7 >> 0x10);
4520: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4521: CONCAT412(SUB164(CONCAT214(uVar69,CONCAT212(uVar54
4522: ,SUB1612(auVar92,0))) >> 0x60,0),
4523: CONCAT210(uVar68,SUB1610(auVar92,0))) >> 0x50,0),
4524: CONCAT28(uVar58,SUB168(auVar92,0))) >> 0x40,0),
4525: uVar100) &
4526: SUB1610((undefined  [16])0xffffffffffffffff >>
4527: 0x30,0),uVar85)) << 0x20;
4528: uVar80 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
4529: undefined2 *)(pauVar32[3] + 8),
4530: CONCAT212(uVar73,SUB1612(auVar52,0))) >> 0x60,0),
4531: CONCAT210(uVar57,SUB1610(auVar52,0))) >> 0x50,0),
4532: CONCAT28((short)uVar39,SUB168(auVar52,0))) >> 0x40
4533: ,0);
4534: uVar6 = (ulong)CONCAT24(uVar57,CONCAT22(uVar55,uVar56)) & 0xffff0000;
4535: auVar81 = CONCAT88(uVar80,(uVar6 >> 0x10) << 0x30) &
4536: (undefined  [16])0xffff000000000000;
4537: uVar66 = SUB162((auVar110 & (undefined  [16])0xffffffff00000000) >>
4538: 0x40,0);
4539: uVar7 = (ulong)CONCAT24(SUB162((auVar110 &
4540: (undefined  [16])0xffffffff00000000) >>
4541: 0x50,0),CONCAT22(uVar63,uVar66));
4542: uVar93 = SUB162(auVar110 >> 0x60,0);
4543: Var14 = CONCAT28(uVar93,uVar113);
4544: auVar106 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4545: CONCAT214(*(undefined2 *)(pauVar32[7] + 4),
4546: CONCAT212(SUB162(auVar92 >> 0x30,0),
4547: SUB1612(auVar92,0))) >> 0x60,0
4548: ),CONCAT210(uVar99,SUB1610(auVar92,0))) >> 0x50,0)
4549: ,CONCAT28(uVar85,SUB168(auVar92,0))) >> 0x40,0),
4550: *(undefined2 *)pauVar32[7])) << 0x30;
4551: uVar8 = (ulong)(uVar114 & 0xffff00000000 |
4552: (uint6)CONCAT22(SUB162(auVar116 >> 0x60,0),sVar103));
4553: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(
4554: CONCAT22(uVar61,uVar60),uVar105),
4555: CONCAT22(uVar84,uVar60)) >> 0x10),uVar67),uVar94))
4556: << 0x20;
4557: uVar50 = CONCAT22(uVar61,uVar60);
4558: auVar52 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar50,uVar105),
4559: CONCAT22(uVar84,uVar60))
4560: >> 0x10),uVar67)) << 0x30 &
4561: (undefined  [16])0xffffffff00000000;
4562: uVar55 = SUB162((auVar106 & (undefined  [16])0xffffffff00000000) >>
4563: 0x40,0);
4564: uVar9 = (ulong)CONCAT24(SUB162((auVar106 &
4565: (undefined  [16])0xffffffff00000000) >>
4566: 0x50,0),CONCAT22(uVar54,uVar55));
4567: uVar54 = (undefined2)(uVar8 >> 0x20);
4568: sVar53 = (short)(uVar8 >> 0x10);
4569: auVar98 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4570: CONCAT214(uVar74,CONCAT212(SUB162(auVar92 >> 0x30,
4571: 0),
4572: SUB1612(auVar92,0))) >>
4573: 0x60,0),CONCAT210(uVar54,SUB1610(auVar92,0))) >>
4574: 0x50,0),CONCAT28(uVar94,SUB168(auVar92,0))) >>
4575: 0x40,0),sVar53) & 0xffffffffffffffff) << 0x30;
4576: auVar52 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
4577: CONCAT412(SUB164(CONCAT214(uVar74,CONCAT212(uVar67
4578: ,SUB1612(auVar52,0))) >> 0x60,0),
4579: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
4580: CONCAT28(uVar94,SUB168(auVar52,0))) >> 0x40,0),
4581: sVar53)) << 0x30) >> 0x20,0) &
4582: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20
4583: ,0)) << 0x20;
4584: uVar8 = (ulong)(uVar109 & 0xffff00000000 |
4585: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),sVar89));
4586: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(
4587: CONCAT22(uVar76,uVar65),uVar96),
4588: CONCAT22(uVar79,uVar65)) >> 0x10),uVar102),uVar90)
4589: ) << 0x20;
4590: uVar74 = (undefined2)(uVar6 >> 0x10);
4591: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4592: CONCAT214(uVar64,CONCAT212(uVar74,SUB1612(auVar81,
4593: 0))) >> 0x60,0),
4594: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
4595: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
4596: uVar58) & SUB1610((undefined  [16])
4597: 0xffffffffffffffff >> 0x30,0))
4598: << 0x30 & (undefined  [16])0xffffffff00000000;
4599: uVar6 = (ulong)CONCAT24(uVar105,CONCAT22(SUB162(auVar97 >> 0x70,0),
4600: uVar84)) & 0xffff0000;
4601: auVar52 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
4602: sVar128,CONCAT212(sVar53,SUB1612(auVar52,0))) >>
4603: 0x60,0),CONCAT210(uVar105,SUB1610(auVar52,0))) >>
4604: 0x50,0),CONCAT28(sVar125,SUB168(auVar52,0))) >>
4605: 0x40,0),(uVar6 >> 0x10) << 0x30) &
4606: (undefined  [16])0xffff000000000000;
4607: sVar101 = SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >>
4608: 0x50,0);
4609: sVar104 = SUB162(auVar98 >> 0x60,0);
4610: auVar116 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
4611: SUB166(CONCAT412(SUB164(CONCAT214(uVar68,CONCAT212
4612: (uVar58,SUB1612(auVar116,0))) >> 0x60,0),
4613: CONCAT210(uVar57,SUB1610(auVar116,0))) >> 0x50,0),
4614: CONCAT28(uVar56,SUB168(auVar116,0))) >> 0x40,0),
4615: uVar62)) << 0x30) >> 0x20,0) &
4616: SUB1612((undefined  [16])0xffffffffffffffff >>
4617: 0x20,0),uVar39 << 0x10);
4618: sVar124 = (short)(uVar8 >> 0x10);
4619: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4620: CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
4621: CONCAT212(SUB162(auVar92 >> 0x30,0),
4622: SUB1612(auVar92,0))) >> 0x60,0
4623: ),CONCAT210((short)(uVar8 >> 0x20),
4624: SUB1610(auVar92,0))) >> 0x50,0),
4625: CONCAT28(uVar90,SUB168(auVar92,0))) >> 0x40,0),
4626: sVar124) & 0xffffffffffffffff) << 0x30;
4627: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
4628: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
4629: undefined2 *)pauVar32[7],
4630: CONCAT212(uVar62,SUB1612(auVar116,0))) >> 0x60,0),
4631: CONCAT210(uVar75,SUB1610(auVar116,0))) >> 0x50,0),
4632: CONCAT28(SUB162(auVar70,0),SUB168(auVar116,0))) >>
4633: 0x40,0),(((ulong)CONCAT24(uVar75,CONCAT22(uVar73,
4634: uVar5)) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0)
4635: & SUB1610((undefined  [16])0xffffffffffffffff >>
4636: 0x30,0) &
4637: SUB1610((undefined  [16])0xffffffffffffffff >>
4638: 0x30,0),
4639: (SUB166(auVar116,0) >> 0x10) << 0x20) >> 0x20,0),
4640: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
4641: sVar119 = (short)(uVar6 >> 0x10);
4642: sVar78 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >>
4643: 0x50,0);
4644: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4645: CONCAT412(SUB164(CONCAT214(sVar95,CONCAT212(
4646: sVar119,SUB1612(auVar52,0))) >> 0x60,0),
4647: CONCAT210(sVar89,SUB1610(auVar52,0))) >> 0x50,0),
4648: CONCAT28(sVar103,SUB168(auVar52,0))) >> 0x40,0),
4649: uVar79) & SUB1610((undefined  [16])
4650: 0xffffffffffffffff >> 0x30,0),
4651: uVar84)) << 0x20;
4652: uVar6 = (ulong)(uVar10 & 0xffff00000000 |
4653: (uint6)CONCAT22(SUB162(auVar106 >> 0x60,0),uVar93));
4654: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4655: CONCAT214(uVar96,CONCAT212(SUB162(auVar71 >> 0x30,
4656: 0),
4657: SUB1612(auVar71,0))) >>
4658: 0x60,0),CONCAT210(uVar105,SUB1610(auVar71,0))) >>
4659: 0x50,0),CONCAT28(uVar84,SUB168(auVar71,0))) >>
4660: 0x40,0),sVar121)) << 0x30;
4661: uVar8 = (ulong)(((uint6)uVar50 & 0xffff0000) << 0x10 |
4662: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),sVar104));
4663: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4664: CONCAT412(SUB164(CONCAT214(uVar64,CONCAT212(uVar74
4665: ,SUB1612(auVar81,0))) >> 0x60,0),
4666: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
4667: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
4668: uVar58) & SUB1610((undefined  [16])
4669: 0xffffffffffffffff >> 0x30,0),
4670: uVar56)) << 0x20;
4671: uVar54 = (undefined2)(uVar9 >> 0x20);
4672: uVar72 = (undefined2)(uVar7 >> 0x20);
4673: uVar75 = (undefined2)(uVar9 >> 0x10);
4674: uVar73 = (undefined2)(uVar7 >> 0x10);
4675: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(
4676: CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212(uVar12
4677: ,CONCAT210(uVar59,Var14))) >> 0x60,0),
4678: CONCAT210(uVar54,Var14)) >> 0x50,0),
4679: CONCAT28(uVar72,uVar113)) >> 0x40,0),uVar75),
4680: uVar73) & (undefined  [12])0xffffffffffffffff) <<
4681: 0x20;
4682: *(short *)pauVar24[1] =
4683: -SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4684: );
4685: *(short *)(pauVar24[1] + 2) = -sVar103;
4686: *(short *)(pauVar24[1] + 4) = -sVar125;
4687: *(short *)(pauVar24[1] + 6) = -sVar53;
4688: *(short *)(pauVar24[1] + 8) =
4689: -SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4690: );
4691: *(short *)(pauVar24[1] + 10) = -sVar89;
4692: *(short *)(pauVar24[1] + 0xc) = -sVar121;
4693: *(short *)(pauVar24[1] + 0xe) = -sVar124;
4694: auVar82 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
4695: CONCAT412(SUB164(CONCAT214(uVar87,CONCAT212(uVar12
4696: ,CONCAT210(uVar59,Var14))) >> 0x60,0),
4697: CONCAT210(uVar54,Var14)) >> 0x50,0),
4698: CONCAT28(uVar72,uVar113)) >> 0x40,0),uVar75) &
4699: 0xffffffffffffffff) << 0x30) >> 0x20,0) &
4700: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20
4701: ,0)) << 0x20;
4702: uVar58 = (undefined2)(uVar6 >> 0x20);
4703: uVar99 = (undefined2)(uVar6 >> 0x10);
4704: auVar81 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4705: CONCAT214(uVar69,CONCAT212(SUB162(auVar70 >> 0x30,
4706: 0),
4707: SUB1612(auVar70,0))) >>
4708: 0x60,0),CONCAT210(uVar58,SUB1610(auVar70,0))) >>
4709: 0x50,0),CONCAT28(uVar73,SUB168(auVar70,0))) >>
4710: 0x40,0),uVar99) & 0xffffffffffffffff) << 0x30;
4711: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4712: CONCAT214(uVar68,CONCAT212(SUB162(auVar52 >> 0x30,
4713: 0),
4714: SUB1612(auVar52,0))) >>
4715: 0x60,0),CONCAT210(uVar57,SUB1610(auVar52,0))) >>
4716: 0x50,0),CONCAT28(uVar56,SUB168(auVar52,0))) >>
4717: 0x40,0),uVar62) & 0xffffffffffffffff) << 0x30;
4718: auVar70 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166
4719: (CONCAT412(SUB164(CONCAT214(uVar69,CONCAT212(
4720: uVar75,SUB1612(auVar82,0))) >> 0x60,0),
4721: CONCAT210(uVar58,SUB1610(auVar82,0))) >> 0x50,0),
4722: CONCAT28(uVar63,SUB168(auVar82,0))) >> 0x40,0),
4723: uVar99)) << 0x30) >> 0x20,0) &
4724: SUB1612((undefined  [16])0xffffffffffffffff >>
4725: 0x20,0),CONCAT22(uVar93,uVar66));
4726: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
4727: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
4728: (auVar106 >> 0x70,0),
4729: CONCAT212(uVar99,SUB1612(auVar70,0))) >> 0x60,0),
4730: CONCAT210(uVar54,SUB1610(auVar70,0))) >> 0x50,0),
4731: CONCAT28(uVar55,SUB168(auVar70,0))) >> 0x40,0),
4732: (((ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar110 
4733: >> 0x70,0),uVar72)) & 0xffff0000) >> 0x10) << 0x30
4734: ) >> 0x30,0),(SUB166(auVar70,0) >> 0x10) << 0x20)
4735: >> 0x20,0),CONCAT22(uVar72,uVar66));
4736: auVar70 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(
4737: CONCAT22(sVar13,sVar1),sVar78),
4738: CONCAT22(sVar101,sVar1)) >> 0x10),uVar65),uVar60))
4739: << 0x20;
4740: *(short *)pauVar24[5] =
4741: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4742: );
4743: *(short *)(pauVar24[5] + 2) = -sVar119;
4744: *(short *)(pauVar24[5] + 4) =
4745: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50,0
4746: );
4747: *(short *)(pauVar24[5] + 6) = -sVar128;
4748: *(short *)(pauVar24[5] + 8) = -SUB162(auVar71 >> 0x60,0);
4749: *(short *)(pauVar24[5] + 10) = -sVar95;
4750: *(short *)(pauVar24[5] + 0xc) = -SUB162(auVar71 >> 0x70,0);
4751: *(short *)(pauVar24[5] + 0xe) = -SUB162(auVar115 >> 0x70,0);
4752: sVar53 = (short)(uVar8 >> 0x10);
4753: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4754: CONCAT214(uVar76,CONCAT212(SUB162(auVar70 >> 0x30,
4755: 0),
4756: SUB1612(auVar70,0))) >>
4757: 0x60,0),CONCAT210((short)(uVar8 >> 0x20),
4758: SUB1610(auVar70,0))) >> 0x50,0),
4759: CONCAT28(uVar60,SUB168(auVar70,0))) >> 0x40,0),
4760: sVar53) & 0xffffffffffffffff) << 0x30;
4761: pauVar24[4] = CONCAT214(uVar86,CONCAT212(SUB162(auVar52 >> 0x70,0),
4762: CONCAT210(uVar64,CONCAT28(
4763: SUB162(auVar52 >> 0x60,0),
4764: uVar80 & 0xffff000000000000 |
4765: (ulong)CONCAT24(SUB162((auVar52 &
4766: (undefined  [16])
4767: 0xffffffff00000000) >> 0x50
4768: ,0),
4769: CONCAT22(uVar74,SUB162((auVar52 &
4770: (undefined 
4771: 
4772: [16])0xffffffff00000000) >> 0x40,0)))))));
4773: *(short *)pauVar24[6] =
4774: SUB162((auVar81 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
4775: ;
4776: *(undefined2 *)(pauVar24[6] + 2) = uVar12;
4777: *(short *)(pauVar24[6] + 4) =
4778: SUB162((auVar81 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
4779: ;
4780: *(undefined2 *)(pauVar24[6] + 6) = uVar83;
4781: *(short *)(pauVar24[6] + 8) = SUB162(auVar81 >> 0x60,0);
4782: *(undefined2 *)(pauVar24[6] + 10) = uVar87;
4783: *(short *)(pauVar24[6] + 0xc) = SUB162(auVar81 >> 0x70,0);
4784: *(undefined2 *)(pauVar24[6] + 0xe) = uVar88;
4785: *(short *)pauVar24[3] =
4786: -SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4787: );
4788: *(short *)(pauVar24[3] + 2) = -sVar101;
4789: *(short *)(pauVar24[3] + 4) = -sVar104;
4790: *(short *)(pauVar24[3] + 6) = -SUB162(auVar98 >> 0x70,0);
4791: *(short *)(pauVar24[3] + 8) =
4792: -SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4793: );
4794: *(short *)(pauVar24[3] + 10) = -sVar78;
4795: *(short *)(pauVar24[3] + 0xc) = -sVar53;
4796: *(short *)(pauVar24[3] + 0xe) = -SUB162(auVar92 >> 0x70,0);
4797: *(short *)pauVar24[7] =
4798: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4799: );
4800: *(short *)(pauVar24[7] + 2) = -sVar1;
4801: *(short *)(pauVar24[7] + 4) =
4802: -SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50,0
4803: );
4804: *(short *)(pauVar24[7] + 6) = -sVar11;
4805: *(short *)(pauVar24[7] + 8) = -SUB162(auVar71 >> 0x60,0);
4806: *(short *)(pauVar24[7] + 10) = -sVar13;
4807: *(short *)(pauVar24[7] + 0xc) = -SUB162(auVar71 >> 0x70,0);
4808: *(short *)(pauVar24[7] + 0xe) = -sVar77;
4809: }
4810: code_r0x0014f063:
4811: uVar39 = (int)uVar20 + 1;
4812: uVar20 = (ulong)uVar39;
4813: plVar23 = plVar23 + 1;
4814: if (uVar39 == uVar47) goto code_r0x0014f42d;
4815: }
4816: pauVar32 = (undefined (*) [16])
4817: ((ulong)(iVar16 + uVar35) * 0x80 + *plVar23);
4818: pauVar21 = pauVar32[8];
4819: if (((((((pauVar32 < pauVar24[1] && pauVar24 < pauVar21 ||
4820: pauVar32 < pauVar24[2] && pauVar24[1] < pauVar21) ||
4821: pauVar32 < pauVar24[8] && pauVar24[7] < pauVar21) ||
4822: pauVar32 < pauVar24[7] && pauVar24[6] < pauVar21) ||
4823: pauVar32 < pauVar24[6] && pauVar24[5] < pauVar21) ||
4824: pauVar32 < pauVar24[5] && pauVar24[4] < pauVar21) ||
4825: pauVar32 < pauVar24[4] && pauVar24[3] < pauVar21) ||
4826: (pauVar32 < pauVar24[3] && pauVar24[2] < pauVar21)) {
4827: iVar26 = 8;
4828: do {
4829: *(undefined2 *)*pauVar24 = *(undefined2 *)*pauVar32;
4830: *(undefined2 *)pauVar24[1] = *(undefined2 *)(*pauVar32 + 2);
4831: *(undefined2 *)pauVar24[2] = *(undefined2 *)(*pauVar32 + 4);
4832: *(undefined2 *)pauVar24[3] = *(undefined2 *)(*pauVar32 + 6);
4833: *(undefined2 *)pauVar24[4] = *(undefined2 *)(*pauVar32 + 8);
4834: *(undefined2 *)pauVar24[5] = *(undefined2 *)(*pauVar32 + 10);
4835: *(undefined2 *)pauVar24[6] = *(undefined2 *)(*pauVar32 + 0xc);
4836: *(undefined2 *)pauVar24[7] = *(undefined2 *)(*pauVar32 + 0xe);
4837: iVar26 = iVar26 + -1;
4838: pauVar24 = (undefined (*) [16])(*pauVar24 + 2);
4839: pauVar32 = pauVar32[1];
4840: } while (iVar26 != 0);
4841: goto code_r0x0014f063;
4842: }
4843: auVar71 = *pauVar32;
4844: uVar40 = (int)uVar20 + 1;
4845: uVar20 = (ulong)uVar40;
4846: plVar23 = plVar23 + 1;
4847: uVar5 = *(ushort *)pauVar32[1];
4848: uVar75 = *(undefined2 *)(pauVar32[1] + 2);
4849: uVar54 = *(undefined2 *)(pauVar32[1] + 4);
4850: uVar55 = *(undefined2 *)(pauVar32[1] + 8);
4851: uVar12 = *(undefined2 *)(pauVar32[1] + 0xc);
4852: uVar73 = *(undefined2 *)(pauVar32[1] + 0xe);
4853: uVar112 = SUB162(auVar71 >> 0x30,0);
4854: uVar111 = SUB162(auVar71 >> 0x20,0);
4855: uVar114 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4856: (pauVar32[1] + 6),
4857: CONCAT212(uVar112,SUB1612(
4858: auVar71,0))) >> 0x60,0),
4859: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0);
4860: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar114,CONCAT28(uVar111,
4861: SUB168(auVar71,0))) >> 0x40,0),uVar75)) << 0x30 &
4862: (undefined  [16])0xffffffff00000000;
4863: auVar52 = pauVar32[2];
4864: uVar59 = SUB162(auVar71 >> 0x40,0);
4865: uVar64 = SUB162(auVar71 >> 0x50,0);
4866: uVar67 = SUB162(auVar71 >> 0x70,0);
4867: uVar87 = SUB162(auVar71 >> 0x10,0);
4868: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4869: SUB164(CONCAT214(*(undefined2 *)(pauVar32[1] + 6),
4870: CONCAT212(uVar112,SUB1612(auVar71
4871: ,0))) >> 0x60,0),
4872: CONCAT210(uVar54,SUB1610(auVar71,0))) >> 0x50,0),
4873: CONCAT28(uVar111,SUB168(auVar71,0))) >> 0x40,0),
4874: uVar75),uVar87)) << 0x20;
4875: uVar72 = *(undefined2 *)pauVar32[3];
4876: uVar74 = *(undefined2 *)(pauVar32[3] + 4);
4877: uVar83 = *(undefined2 *)(pauVar32[3] + 6);
4878: uVar62 = *(undefined2 *)(pauVar32[3] + 0xc);
4879: uVar99 = *(undefined2 *)(pauVar32[3] + 0xe);
4880: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4881: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
4882: CONCAT212(uVar75,SUB1612(auVar70,0))) >>
4883: 0x60,0),CONCAT210(uVar64,SUB1610(auVar70,0))) >>
4884: 0x50,0),CONCAT28(uVar87,SUB168(auVar70,0))) >>
4885: 0x40,0),uVar55)) << 0x30 &
4886: (undefined  [16])0xffffffff00000000;
4887: uVar79 = SUB162(auVar52 >> 0x30,0);
4888: uVar76 = SUB162(auVar52 >> 0x20,0);
4889: uVar39 = SUB164(auVar52,0) & 0xffff;
4890: auVar70 = pauVar32[4];
4891: auVar97 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4892: CONCAT214(*(undefined2 *)(pauVar32[1] + 10),
4893: CONCAT212(SUB162(auVar81 >> 0x30,0),
4894: SUB1612(auVar81,0))) >> 0x60,0
4895: ),CONCAT210(uVar64,SUB1610(auVar81,0))) >> 0x50,0)
4896: ,CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
4897: uVar55)) << 0x30;
4898: uVar57 = SUB162(auVar52 >> 0x10,0);
4899: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4900: SUB164(CONCAT214(uVar83,CONCAT212(uVar79,SUB1612(
4901: auVar52,0))) >> 0x60,0),
4902: CONCAT210(uVar74,SUB1610(auVar52,0))) >> 0x50,0),
4903: CONCAT28(uVar76,SUB168(auVar52,0))) >> 0x40,0),
4904: *(undefined2 *)(pauVar32[3] + 2)),uVar57)) << 0x20
4905: ;
4906: uVar75 = *(undefined2 *)pauVar32[5];
4907: uVar64 = *(undefined2 *)(pauVar32[5] + 2);
4908: uVar87 = *(undefined2 *)(pauVar32[5] + 4);
4909: uVar86 = *(undefined2 *)(pauVar32[5] + 8);
4910: uVar88 = *(undefined2 *)(pauVar32[5] + 0xc);
4911: uVar56 = *(undefined2 *)(pauVar32[5] + 0xe);
4912: uVar60 = SUB162(auVar52 >> 0x40,0);
4913: uVar66 = SUB162(auVar52 >> 0x60,0);
4914: uVar68 = SUB162(auVar52 >> 0x70,0);
4915: uVar113 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,
4916: CONCAT212(uVar55,SUB1612(auVar82,0))) >> 0x60,0),
4917: CONCAT210(uVar54,SUB1610(auVar82,0))) >> 0x50,0),
4918: CONCAT28(uVar5,SUB168(auVar82,0))) >> 0x40,0);
4919: uVar6 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar71 >> 0x60,0),uVar111)
4920: ) & 0xffff0000;
4921: auVar98 = CONCAT88(uVar113,(uVar6 >> 0x10) << 0x30) &
4922: (undefined  [16])0xffff000000000000;
4923: uVar100 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x40,0
4924: );
4925: uVar102 = SUB162((auVar97 & (undefined  [16])0xffffffff00000000) >> 0x50,0
4926: );
4927: uVar105 = SUB162(auVar97 >> 0x60,0);
4928: uVar108 = SUB162(auVar70 >> 0x30,0);
4929: uVar107 = SUB162(auVar70 >> 0x20,0);
4930: uVar109 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
4931: (pauVar32[5] + 6),
4932: CONCAT212(uVar108,SUB1612(
4933: auVar70,0))) >> 0x60,0),
4934: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0);
4935: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar109,CONCAT28(uVar107,
4936: SUB168(auVar70,0))) >> 0x40,0),uVar64)) << 0x30 &
4937: (undefined  [16])0xffffffff00000000;
4938: auVar81 = pauVar32[6];
4939: auVar123 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4940: CONCAT214(*(undefined2 *)(pauVar32[3] + 10),
4941: CONCAT212(SUB162(auVar106 >> 0x30,0),
4942: SUB1612(auVar106,0))) >> 0x60,
4943: 0),CONCAT210(SUB162(auVar52 >> 0x50,0),
4944: SUB1610(auVar106,0))) >> 0x50,0),
4945: CONCAT28(uVar57,SUB168(auVar106,0))) >> 0x40,0),
4946: *(undefined2 *)(pauVar32[3] + 8))) << 0x30;
4947: uVar84 = SUB162(auVar70 >> 0x10,0);
4948: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4949: SUB164(CONCAT214(*(undefined2 *)(pauVar32[5] + 6),
4950: CONCAT212(uVar108,SUB1612(auVar70
4951: ,0))) >> 0x60,0),
4952: CONCAT210(uVar87,SUB1610(auVar70,0))) >> 0x50,0),
4953: CONCAT28(uVar107,SUB168(auVar70,0))) >> 0x40,0),
4954: uVar64),uVar84)) << 0x20;
4955: uVar61 = SUB162(auVar70 >> 0x40,0);
4956: uVar65 = SUB162(auVar70 >> 0x50,0);
4957: uVar69 = SUB162(auVar70 >> 0x70,0);
4958: uVar57 = *(undefined2 *)(pauVar32[7] + 8);
4959: uVar58 = *(undefined2 *)(pauVar32[7] + 0xc);
4960: uVar63 = *(undefined2 *)(pauVar32[7] + 0xe);
4961: uVar126 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >> 0x40,
4962: 0);
4963: uVar127 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >> 0x50,
4964: 0);
4965: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4966: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
4967: CONCAT212(SUB162(auVar52 >> 0x30,0),
4968: SUB1612(auVar52,0))) >> 0x60,0
4969: ),CONCAT210(uVar65,SUB1610(auVar52,0))) >> 0x50,0)
4970: ,CONCAT28(uVar84,SUB168(auVar52,0))) >> 0x40,0),
4971: uVar86)) << 0x30;
4972: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
4973: CONCAT214(*(undefined2 *)(pauVar32[5] + 10),
4974: CONCAT212(uVar64,SUB1612(auVar92,0))) >>
4975: 0x60,0),CONCAT210(uVar65,SUB1610(auVar92,0))) >>
4976: 0x50,0),CONCAT28(uVar84,SUB168(auVar92,0))) >>
4977: 0x40,0),uVar86)) << 0x30 &
4978: (undefined  [16])0xffffffff00000000;
4979: uVar65 = SUB162(auVar81 >> 0x40,0);
4980: uVar84 = SUB162(auVar81 >> 0x60,0);
4981: uVar85 = SUB162(auVar81 >> 0x70,0);
4982: uVar120 = SUB162(auVar81 >> 0x30,0);
4983: uVar118 = SUB162(auVar81 >> 0x20,0);
4984: uVar117 = SUB162(auVar81 >> 0x10,0);
4985: auVar106 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
4986: SUB164(CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
4987: CONCAT212(uVar120,SUB1612(auVar81
4988: ,0))) >> 0x60,0),
4989: CONCAT210(*(undefined2 *)(pauVar32[7] + 4),
4990: SUB1610(auVar81,0))) >> 0x50,0),
4991: CONCAT28(uVar118,SUB168(auVar81,0))) >> 0x40,0),
4992: *(undefined2 *)(pauVar32[7] + 2)),uVar117)) <<
4993: 0x20;
4994: uVar64 = SUB162(auVar81,0);
4995: uVar7 = (ulong)CONCAT24(uVar87,CONCAT22(SUB162(auVar70 >> 0x60,0),uVar107)
4996: ) & 0xffff0000;
4997: auVar92 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
4998: uVar88,CONCAT212(uVar86,SUB1612(auVar52,0))) >>
4999: 0x60,0),CONCAT210(uVar87,SUB1610(auVar52,0))) >>
5000: 0x50,0),CONCAT28(uVar75,SUB168(auVar52,0))) >>
5001: 0x40,0),(uVar7 >> 0x10) << 0x30) &
5002: (undefined  [16])0xffff000000000000;
5003: uVar93 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
5004: ;
5005: uVar94 = SUB162(auVar82 >> 0x60,0);
5006: uVar96 = SUB162(auVar82 >> 0x70,0);
5007: uVar90 = (undefined2)(uVar6 >> 0x10);
5008: uVar10 = SUB166(CONCAT412(SUB164(CONCAT214(uVar66,CONCAT212(uVar90,SUB1612
5009: (auVar98,0))) >> 0x60,0),
5010: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0);
5011: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar10,CONCAT28(uVar59,SUB168
5012: (auVar98,0))) >> 0x40,0),uVar76) &
5013: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0))
5014: << 0x30 & (undefined  [16])0xffffffff00000000;
5015: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5016: CONCAT214(*(undefined2 *)(pauVar32[7] + 10),
5017: CONCAT212(SUB162(auVar106 >> 0x30,0),
5018: SUB1612(auVar106,0))) >> 0x60,
5019: 0),CONCAT210(SUB162(auVar81 >> 0x50,0),
5020: SUB1610(auVar106,0))) >> 0x50,0),
5021: CONCAT28(uVar117,SUB168(auVar106,0))) >> 0x40,0),
5022: uVar57)) << 0x30;
5023: auVar81 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
5024: SUB164(CONCAT214(uVar66,CONCAT212(uVar90,SUB1612(
5025: auVar98,0))) >> 0x60,0),
5026: CONCAT210(uVar60,SUB1610(auVar98,0))) >> 0x50,0),
5027: CONCAT28(uVar59,SUB168(auVar98,0))) >> 0x40,0),
5028: uVar76) & SUB1610((undefined  [16])
5029: 0xffffffffffffffff >> 0x30,0),
5030: uVar111)) << 0x20;
5031: uVar117 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >> 0x40,
5032: 0);
5033: uVar122 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >> 0x50,
5034: 0);
5035: auVar110 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5036: CONCAT214(uVar74,CONCAT212(SUB162(auVar81 >> 0x30,
5037: 0),
5038: SUB1612(auVar81,0))) >>
5039: 0x60,0),CONCAT210(uVar54,SUB1610(auVar81,0))) >>
5040: 0x50,0),CONCAT28(uVar111,SUB168(auVar81,0))) >>
5041: 0x40,0),uVar72)) << 0x30;
5042: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5043: CONCAT214(uVar74,CONCAT212(uVar76,SUB1612(auVar52,
5044: 0))) >> 0x60,0),
5045: CONCAT210(uVar54,SUB1610(auVar52,0))) >> 0x50,0),
5046: CONCAT28(uVar111,SUB168(auVar52,0))) >> 0x40,0),
5047: uVar72)) << 0x30 &
5048: (undefined  [16])0xffffffff00000000;
5049: uVar54 = (undefined2)(uVar7 >> 0x10);
5050: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
5051: SUB164(CONCAT214(uVar84,CONCAT212(uVar54,SUB1612(
5052: auVar92,0))) >> 0x60,0),
5053: CONCAT210(uVar65,SUB1610(auVar92,0))) >> 0x50,0),
5054: CONCAT28(uVar61,SUB168(auVar92,0))) >> 0x40,0),
5055: uVar118) &
5056: SUB1610((undefined  [16])0xffffffffffffffff >>
5057: 0x30,0),uVar107)) << 0x20;
5058: uVar91 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *
5059: )(pauVar32[3]
5060: + 8),
5061: CONCAT212(uVar72,SUB1612(auVar52,0))) >> 0x60,0),
5062: CONCAT210(uVar60,SUB1610(auVar52,0))) >> 0x50,0),
5063: CONCAT28((short)uVar39,SUB168(auVar52,0))) >> 0x40
5064: ,0);
5065: uVar6 = (ulong)CONCAT24(uVar60,CONCAT22(uVar55,uVar59)) & 0xffff0000;
5066: auVar81 = CONCAT88(uVar91,(uVar6 >> 0x10) << 0x30) &
5067: (undefined  [16])0xffff000000000000;
5068: uVar76 = SUB162((auVar110 & (undefined  [16])0xffffffff00000000) >> 0x40,0
5069: );
5070: uVar7 = (ulong)CONCAT24(SUB162((auVar110 &
5071: (undefined  [16])0xffffffff00000000) >>
5072: 0x50,0),CONCAT22(uVar90,uVar76));
5073: uVar111 = SUB162(auVar110 >> 0x60,0);
5074: Var14 = CONCAT28(uVar111,uVar113);
5075: auVar106 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5076: CONCAT214(*(undefined2 *)(pauVar32[7] + 4),
5077: CONCAT212(SUB162(auVar92 >> 0x30,0),
5078: SUB1612(auVar92,0))) >> 0x60,0
5079: ),CONCAT210(uVar87,SUB1610(auVar92,0))) >> 0x50,0)
5080: ,CONCAT28(uVar107,SUB168(auVar92,0))) >> 0x40,0),
5081: *(undefined2 *)pauVar32[7])) << 0x30;
5082: uVar8 = (ulong)(uVar114 & 0xffff00000000 |
5083: (uint6)CONCAT22(SUB162(auVar123 >> 0x60,0),uVar105));
5084: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
5085: uVar68,uVar67),uVar127),CONCAT22(uVar102,uVar67))
5086: >> 0x10),uVar79),uVar112)) << 0x20;
5087: uVar50 = CONCAT22(uVar68,uVar67);
5088: auVar52 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar50,uVar127),
5089: CONCAT22(uVar102,uVar67)) >>
5090: 0x10),uVar79)) << 0x30 &
5091: (undefined  [16])0xffffffff00000000;
5092: uVar87 = SUB162((auVar106 & (undefined  [16])0xffffffff00000000) >> 0x40,0
5093: );
5094: uVar9 = (ulong)CONCAT24(SUB162((auVar106 &
5095: (undefined  [16])0xffffffff00000000) >>
5096: 0x50,0),CONCAT22(uVar54,uVar87));
5097: uVar55 = (undefined2)(uVar8 >> 0x20);
5098: uVar54 = (undefined2)(uVar8 >> 0x10);
5099: auVar98 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5100: CONCAT214(uVar83,CONCAT212(SUB162(auVar92 >> 0x30,
5101: 0),
5102: SUB1612(auVar92,0))) >>
5103: 0x60,0),CONCAT210(uVar55,SUB1610(auVar92,0))) >>
5104: 0x50,0),CONCAT28(uVar112,SUB168(auVar92,0))) >>
5105: 0x40,0),uVar54) & 0xffffffffffffffff) << 0x30;
5106: auVar52 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
5107: CONCAT412(SUB164(CONCAT214(uVar83,CONCAT212(uVar79
5108: ,SUB1612(auVar52,0))) >> 0x60,0),
5109: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
5110: CONCAT28(uVar112,SUB168(auVar52,0))) >> 0x40,0),
5111: uVar54)) << 0x30) >> 0x20,0) &
5112: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0))
5113: << 0x20;
5114: uVar8 = (ulong)(uVar109 & 0xffff00000000 |
5115: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),uVar94));
5116: auVar92 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
5117: uVar85,uVar69),uVar122),CONCAT22(uVar93,uVar69))
5118: >> 0x10),uVar120),uVar108)) << 0x20;
5119: uVar68 = (undefined2)(uVar6 >> 0x10);
5120: auVar116 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5121: CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(auVar81,
5122: 0))) >> 0x60,0),
5123: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
5124: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
5125: uVar61) &
5126: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)
5127: ) << 0x30 & (undefined  [16])0xffffffff00000000;
5128: uVar80 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162(
5129: auVar123 >> 0x70,0),
5130: CONCAT212(uVar54,SUB1612(auVar52,0))) >> 0x60,0),
5131: CONCAT210(uVar127,SUB1610(auVar52,0))) >> 0x50,0),
5132: CONCAT28(uVar126,SUB168(auVar52,0))) >> 0x40,0);
5133: uVar6 = (ulong)CONCAT24(uVar127,CONCAT22(SUB162(auVar97 >> 0x70,0),uVar102
5134: )) & 0xffff0000;
5135: auVar52 = CONCAT88(uVar80,(uVar6 >> 0x10) << 0x30) &
5136: (undefined  [16])0xffff000000000000;
5137: uVar74 = SUB162((auVar98 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
5138: ;
5139: uVar83 = SUB162(auVar98 >> 0x60,0);
5140: auVar97 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
5141: CONCAT412(SUB164(CONCAT214(uVar65,CONCAT212(uVar61
5142: ,SUB1612(auVar116,0))) >> 0x60,0),
5143: CONCAT210(uVar60,SUB1610(auVar116,0))) >> 0x50,0),
5144: CONCAT28(uVar59,SUB168(auVar116,0))) >> 0x40,0),
5145: uVar64)) << 0x30) >> 0x20,0) &
5146: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)
5147: ,uVar39 << 0x10);
5148: uVar107 = (undefined2)(uVar8 >> 0x10);
5149: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5150: CONCAT214(*(undefined2 *)(pauVar32[7] + 6),
5151: CONCAT212(SUB162(auVar92 >> 0x30,0),
5152: SUB1612(auVar92,0))) >> 0x60,0
5153: ),CONCAT210((short)(uVar8 >> 0x20),
5154: SUB1610(auVar92,0))) >> 0x50,0),
5155: CONCAT28(uVar108,SUB168(auVar92,0))) >> 0x40,0),
5156: uVar107) & 0xffffffffffffffff) << 0x30;
5157: *pauVar24 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(
5158: SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
5159: pauVar32[7],
5160: CONCAT212(uVar64
5161: ,SUB1612(auVar97,0))) >> 0x60,0),
5162: CONCAT210(uVar75,SUB1610(auVar97,0))) >> 0x50,0),
5163: CONCAT28(SUB162(auVar70,0),SUB168(auVar97,0))) >>
5164: 0x40,0),(((ulong)CONCAT24(uVar75,CONCAT22(uVar72,
5165: uVar5)) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0)
5166: & SUB1610((undefined  [16])0xffffffffffffffff >>
5167: 0x30,0) &
5168: SUB1610((undefined  [16])0xffffffffffffffff >>
5169: 0x30,0),
5170: (SUB166(auVar97,0) >> 0x10) << 0x20) >> 0x20,0),
5171: SUB164(auVar71,0) & 0xffff | (uint)uVar5 << 0x10);
5172: uVar79 = (undefined2)(uVar6 >> 0x10);
5173: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5174: CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(auVar52,
5175: 0))) >> 0x60,0),
5176: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
5177: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
5178: uVar93) &
5179: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0))
5180: << 0x30 & (undefined  [16])0xffffffff00000000;
5181: uVar55 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x50,0)
5182: ;
5183: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
5184: SUB164(CONCAT214(uVar86,CONCAT212(uVar68,SUB1612(
5185: auVar81,0))) >> 0x60,0),
5186: CONCAT210(uVar75,SUB1610(auVar81,0))) >> 0x50,0),
5187: CONCAT28(uVar5,SUB168(auVar81,0))) >> 0x40,0),
5188: uVar61) & SUB1610((undefined  [16])
5189: 0xffffffffffffffff >> 0x30,0),
5190: uVar59)) << 0x20;
5191: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
5192: CONCAT412(SUB164(CONCAT214(uVar122,CONCAT212(
5193: uVar93,SUB1612(auVar71,0))) >> 0x60,0),
5194: CONCAT210(uVar127,SUB1610(auVar71,0))) >> 0x50,0),
5195: CONCAT28(uVar102,SUB168(auVar71,0))) >> 0x40,0),
5196: uVar117)) << 0x30) >> 0x20,0),
5197: CONCAT22(uVar126,uVar100));
5198: uVar6 = (ulong)(uVar10 & 0xffff00000000 |
5199: (uint6)CONCAT22(SUB162(auVar106 >> 0x60,0),uVar111));
5200: uVar8 = (ulong)(((uint6)uVar50 & 0xffff0000) << 0x10 |
5201: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),uVar83));
5202: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
5203: SUB164(CONCAT214(uVar96,CONCAT212(uVar79,SUB1612(
5204: auVar52,0))) >> 0x60,0),
5205: CONCAT210(uVar94,SUB1610(auVar52,0))) >> 0x50,0),
5206: CONCAT28(uVar105,SUB168(auVar52,0))) >> 0x40,0),
5207: uVar93) & SUB1610((undefined  [16])
5208: 0xffffffffffffffff >> 0x30,0),
5209: uVar102)) << 0x20;
5210: auVar52 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5211: CONCAT214(uVar65,CONCAT212(SUB162(auVar70 >> 0x30,
5212: 0),
5213: SUB1612(auVar70,0))) >>
5214: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
5215: 0x50,0),CONCAT28(uVar59,SUB168(auVar70,0))) >>
5216: 0x40,0),uVar64) & 0xffffffffffffffff) << 0x30;
5217: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5218: CONCAT214(uVar122,CONCAT212(SUB162(auVar71 >> 0x30
5219: ,0),
5220: SUB1612(auVar71,0)))
5221: >> 0x60,0),CONCAT210(uVar127,SUB1610(auVar71,0)))
5222: >> 0x50,0),CONCAT28(uVar102,SUB168(auVar71,0))) >>
5223: 0x40,0),uVar117)) << 0x30;
5224: pauVar24[1] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
5225: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
5226: uVar107,CONCAT212(uVar117,SUB1612(auVar81,0))) >>
5227: 0x60,0),CONCAT210(uVar94,SUB1610(auVar81,0))) >>
5228: 0x50,0),CONCAT28(SUB162((auVar82 &
5229: (undefined  [16])
5230: 0xffffffff00000000) >>
5231: 0x40,0),SUB168(auVar81,0))
5232: ) >> 0x40,0),
5233: (((ulong)CONCAT24(uVar94,CONCAT22(uVar54,uVar105))
5234: & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
5235: (SUB166(auVar81,0) >> 0x10) << 0x20) >> 0x20,0),
5236: CONCAT22(uVar105,uVar100));
5237: uVar54 = (undefined2)(uVar9 >> 0x20);
5238: uVar64 = (undefined2)(uVar7 >> 0x20);
5239: uVar75 = (undefined2)(uVar9 >> 0x10);
5240: uVar72 = (undefined2)(uVar7 >> 0x10);
5241: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
5242: SUB164(CONCAT214(uVar88,CONCAT212(uVar12,CONCAT210
5243: (uVar66,Var14))) >> 0x60,0),
5244: CONCAT210(uVar54,Var14)) >> 0x50,0),
5245: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75),
5246: uVar72) & (undefined  [12])0xffffffffffffffff) <<
5247: 0x20;
5248: auVar81 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
5249: CONCAT412(SUB164(CONCAT214(uVar88,CONCAT212(uVar12
5250: ,CONCAT210(uVar66,Var14))) >> 0x60,0),
5251: CONCAT210(uVar54,Var14)) >> 0x50,0),
5252: CONCAT28(uVar64,uVar113)) >> 0x40,0),uVar75) &
5253: 0xffffffffffffffff) << 0x30) >> 0x20,0) &
5254: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0))
5255: << 0x20;
5256: uVar60 = (undefined2)(uVar6 >> 0x20);
5257: uVar59 = (undefined2)(uVar6 >> 0x10);
5258: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5259: CONCAT214(uVar84,CONCAT212(SUB162(auVar70 >> 0x30,
5260: 0),
5261: SUB1612(auVar70,0))) >>
5262: 0x60,0),CONCAT210(uVar60,SUB1610(auVar70,0))) >>
5263: 0x50,0),CONCAT28(uVar72,SUB168(auVar70,0))) >>
5264: 0x40,0),uVar59) & 0xffffffffffffffff) << 0x30;
5265: auVar81 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(
5266: CONCAT412(SUB164(CONCAT214(uVar84,CONCAT212(uVar75
5267: ,SUB1612(auVar81,0))) >> 0x60,0),
5268: CONCAT210(uVar60,SUB1610(auVar81,0))) >> 0x50,0),
5269: CONCAT28(uVar90,SUB168(auVar81,0))) >> 0x40,0),
5270: uVar59)) << 0x30) >> 0x20,0) &
5271: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)
5272: ,CONCAT22(uVar111,uVar76));
5273: pauVar24[4] = CONCAT214(uVar57,CONCAT212(SUB162(auVar52 >> 0x70,0),
5274: CONCAT210(uVar86,CONCAT28(SUB162(
5275: auVar52 >> 0x60,0),
5276: uVar91 & 0xffff000000000000 |
5277: (ulong)CONCAT24(SUB162((auVar52 &
5278: (undefined  [16])
5279: 0xffffffff00000000) >> 0x50
5280: ,0),
5281: CONCAT22(uVar68,SUB162((auVar52 &
5282: (undefined 
5283: 
5284: [16])0xffffffff00000000) >> 0x40,0)))))));
5285: pauVar24[2] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
5286: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
5287: (auVar106 >> 0x70,0),
5288: CONCAT212(uVar59,SUB1612(auVar81,0))) >> 0x60,0),
5289: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
5290: CONCAT28(uVar87,SUB168(auVar81,0))) >> 0x40,0),
5291: (((ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar110 
5292: >> 0x70,0),uVar64)) & 0xffff0000) >> 0x10) << 0x30
5293: ) >> 0x30,0),(SUB166(auVar81,0) >> 0x10) << 0x20)
5294: >> 0x20,0),CONCAT22(uVar64,uVar76));
5295: auVar52 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(
5296: uVar56,uVar73),uVar55),CONCAT22(uVar74,uVar73)) >>
5297: 0x10),uVar69),uVar67)) << 0x20;
5298: auVar81 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar56,
5299: uVar73),uVar55),CONCAT22(uVar74,uVar73)) >> 0x10),
5300: uVar69)) << 0x30 &
5301: (undefined  [16])0xffffffff00000000;
5302: pauVar24[5] = CONCAT214(SUB162(auVar115 >> 0x70,0),
5303: CONCAT212(SUB162(auVar71 >> 0x70,0),
5304: CONCAT210(uVar96,CONCAT28(SUB162(auVar71
5305: >> 0x60
5306: ,0),uVar80 & 0xffff000000000000 |
5307: (ulong)CONCAT24(SUB162((auVar71 &
5308: (undefined  [16])
5309: 0xffffffff00000000) >>
5310: 0x50,0),
5311: CONCAT22(uVar79,SUB162((
5312: auVar71 & (undefined  [16])0xffffffff00000000) >>
5313: 0x40,0)))))));
5314: uVar54 = (undefined2)(uVar8 >> 0x20);
5315: uVar75 = (undefined2)(uVar8 >> 0x10);
5316: auVar71 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
5317: CONCAT214(uVar85,CONCAT212(SUB162(auVar52 >> 0x30,
5318: 0),
5319: SUB1612(auVar52,0))) >>
5320: 0x60,0),CONCAT210(uVar54,SUB1610(auVar52,0))) >>
5321: 0x50,0),CONCAT28(uVar67,SUB168(auVar52,0))) >>
5322: 0x40,0),uVar75) & 0xffffffffffffffff) << 0x30;
5323: auVar52 = ZEXT1416(CONCAT122(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(
5324: SUB166(CONCAT412(SUB164(CONCAT214(uVar85,CONCAT212
5325: (uVar69,SUB1612(auVar81,0))) >> 0x60,0),
5326: CONCAT210(uVar54,SUB1610(auVar81,0))) >> 0x50,0),
5327: CONCAT28(uVar67,SUB168(auVar81,0))) >> 0x40,0),
5328: uVar75)) << 0x30) >> 0x20,0) &
5329: SUB1612((undefined  [16])0xffffffffffffffff >>
5330: 0x20,0),uVar83)) << 0x10;
5331: *(short *)pauVar24[6] =
5332: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
5333: *(undefined2 *)(pauVar24[6] + 2) = uVar12;
5334: *(short *)(pauVar24[6] + 4) =
5335: SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
5336: *(undefined2 *)(pauVar24[6] + 6) = uVar62;
5337: *(short *)(pauVar24[6] + 8) = SUB162(auVar70 >> 0x60,0);
5338: *(undefined2 *)(pauVar24[6] + 10) = uVar88;
5339: *(short *)(pauVar24[6] + 0xc) = SUB162(auVar70 >> 0x70,0);
5340: *(undefined2 *)(pauVar24[6] + 0xe) = uVar58;
5341: *(short *)pauVar24[7] =
5342: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
5343: *(undefined2 *)(pauVar24[7] + 2) = uVar73;
5344: *(short *)(pauVar24[7] + 4) =
5345: SUB162((auVar71 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
5346: *(undefined2 *)(pauVar24[7] + 6) = uVar99;
5347: *(short *)(pauVar24[7] + 8) = SUB162(auVar71 >> 0x60,0);
5348: *(undefined2 *)(pauVar24[7] + 10) = uVar56;
5349: *(short *)(pauVar24[7] + 0xc) = SUB162(auVar71 >> 0x70,0);
5350: *(undefined2 *)(pauVar24[7] + 0xe) = uVar63;
5351: pauVar24[3] = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(
5352: CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162
5353: (auVar92 >> 0x70,0),
5354: CONCAT212(uVar75,SUB1612(auVar52,0))) >> 0x60,0),
5355: CONCAT210(uVar55,SUB1610(auVar52,0))) >> 0x50,0),
5356: CONCAT28(SUB162((auVar92 &
5357: (undefined  [16])
5358: 0xffffffff00000000) >> 0x40,0),
5359: SUB168(auVar52,0))) >> 0x40,0),
5360: (((ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar98 
5361: >> 0x70,0),uVar74)) & 0xffff0000) >> 0x10) << 0x30
5362: ) >> 0x30,0),(SUB166(auVar52,0) >> 0x10) << 0x20)
5363: >> 0x20,0),
5364: SUB164((auVar98 &
5365: (undefined  [16])0xffffffff00000000) >>
5366: 0x40,0));
5367: } while (uVar40 != uVar47);
5368: code_r0x0014f42d:
5369: uVar20 = (ulong)uVar47;
5370: uVar39 = *(uint *)(lVar49 + 0x1c);
5371: if (uVar39 <= uVar47) goto code_r0x0014f441;
5372: }
5373: uVar20 = (ulong)(uint)(iVar41 + iVar26);
5374: uVar39 = *(uint *)(lVar49 + 0x1c);
5375: } while ((uint)(iVar41 + iVar26) < uVar39);
5376: code_r0x0014f441:
5377: iVar26 = *(int *)(lVar49 + 0xc);
5378: }
5379: auStack168 = CONCAT124(auStack168._4_12_,auStack168._0_4_ - 1);
5380: lStack192 = lStack192 + 1;
5381: } while (iVar16 + 1 < iVar26);
5382: }
5383: auStack184 = CONCAT124(auStack184._4_12_,auStack184._0_4_ + iVar26);
5384: } while ((uint)(auStack184._0_4_ + iVar26) < *(uint *)(lVar49 + 0x20));
5385: iVar16 = *(int *)(param_2 + 0x4c);
5386: }
5387: lStack200 = lStack200 + 1;
5388: } while ((int)lStack200 + 1 < iVar16);
5389: }
5390: }
5391: }
5392: return;
5393: }
5394: 

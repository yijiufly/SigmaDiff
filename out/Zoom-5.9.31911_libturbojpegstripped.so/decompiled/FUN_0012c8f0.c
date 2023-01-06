1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0012c8f0(code **param_1)
5: 
6: {
7: code **ppcVar1;
8: code **ppcVar2;
9: code *pcVar3;
10: int6 iVar4;
11: long lVar5;
12: int6 iVar6;
13: long lVar7;
14: int6 iVar8;
15: long lVar9;
16: uint6 uVar10;
17: ulong uVar11;
18: ulong uVar12;
19: ushort uVar13;
20: undefined auVar14 [16];
21: undefined auVar15 [16];
22: uint uVar16;
23: uint uVar17;
24: undefined4 uVar18;
25: undefined8 *puVar19;
26: int iVar20;
27: ulong uVar21;
28: undefined (*pauVar22) [16];
29: int iVar23;
30: ulong uVar24;
31: undefined8 *puVar25;
32: undefined8 *puVar26;
33: uint uVar27;
34: bool bVar28;
35: byte bVar29;
36: ushort uVar32;
37: short sVar33;
38: undefined auVar30 [16];
39: undefined auVar31 [16];
40: undefined uVar39;
41: uint uVar36;
42: undefined uVar40;
43: undefined uVar41;
44: undefined uVar42;
45: undefined uVar44;
46: uint uVar43;
47: int iVar45;
48: undefined auVar38 [16];
49: uint uVar46;
50: undefined2 uVar48;
51: int iVar49;
52: undefined uVar53;
53: undefined uVar54;
54: int iVar51;
55: undefined uVar55;
56: undefined uVar56;
57: int iVar57;
58: int iVar59;
59: int iVar60;
60: uint uVar61;
61: int iVar62;
62: short sVar63;
63: undefined2 uVar64;
64: undefined uVar34;
65: undefined uVar35;
66: undefined auVar37 [12];
67: uint uVar47;
68: int iVar50;
69: int iVar52;
70: int iVar58;
71: 
72: bVar29 = 0;
73: ppcVar1 = (code **)param_1[0x44];
74: *ppcVar1 = FUN_0012be00;
75: *(undefined4 *)(ppcVar1 + 2) = 0;
76: *(undefined4 *)((long)ppcVar1 + 0x6c) = 0;
77: ppcVar1[1] = FUN_0012bfc0;
78: FUN_0012c110();
79: puVar19 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x580);
80: bVar28 = ((ulong)puVar19 & 1) != 0;
81: uVar24 = 0x100;
82: iVar23 = 0x100;
83: param_1[0x35] = (code *)(puVar19 + 0x20);
84: puVar26 = puVar19;
85: if (bVar28) {
86: *(undefined *)puVar19 = 0;
87: uVar24 = 0xff;
88: iVar23 = 0xff;
89: puVar26 = (undefined8 *)((long)puVar19 + 1);
90: }
91: puVar25 = puVar26;
92: if (((ulong)puVar26 & 2) != 0) {
93: /* WARNING: Read-only address (ram,0x00168ad0) is written */
94: /* WARNING: Read-only address (ram,0x00189c50) is written */
95: puVar25 = (undefined8 *)((long)puVar26 + 2);
96: uVar24 = (ulong)(iVar23 - 2);
97: *(undefined2 *)puVar26 = 0;
98: }
99: if (((ulong)puVar25 & 4) != 0) {
100: *(undefined4 *)puVar25 = 0;
101: uVar24 = (ulong)((int)uVar24 - 4);
102: puVar25 = (undefined8 *)((long)puVar25 + 4);
103: }
104: uVar21 = uVar24 >> 3;
105: while (uVar21 != 0) {
106: uVar21 = uVar21 - 1;
107: *puVar25 = 0;
108: puVar25 = puVar25 + (ulong)bVar29 * -2 + 1;
109: }
110: if ((uVar24 & 4) != 0) {
111: *(undefined4 *)puVar25 = 0;
112: puVar25 = (undefined8 *)((long)puVar25 + 4);
113: }
114: puVar26 = puVar25;
115: if ((uVar24 & 2) != 0) {
116: puVar26 = (undefined8 *)((long)puVar25 + 2);
117: *(undefined2 *)puVar25 = 0;
118: }
119: if (bVar28) {
120: *(undefined *)puVar26 = 0;
121: }
122: uVar16 = -(int)(puVar19 + 0x20) & 0xf;
123: if (uVar16 == 0) {
124: iVar20 = 0x100;
125: iVar23 = 0;
126: }
127: else {
128: *(undefined *)(puVar19 + 0x20) = 0;
129: if (uVar16 < 2) {
130: iVar20 = 0xff;
131: iVar23 = 1;
132: }
133: else {
134: *(undefined *)((long)puVar19 + 0x101) = 1;
135: if (uVar16 < 3) {
136: iVar20 = 0xfe;
137: iVar23 = 2;
138: }
139: else {
140: *(undefined *)((long)puVar19 + 0x102) = 2;
141: if (uVar16 < 4) {
142: iVar20 = 0xfd;
143: iVar23 = 3;
144: }
145: else {
146: *(undefined *)((long)puVar19 + 0x103) = 3;
147: if (uVar16 < 5) {
148: iVar20 = 0xfc;
149: iVar23 = 4;
150: }
151: else {
152: *(undefined *)((long)puVar19 + 0x104) = 4;
153: if (uVar16 < 6) {
154: iVar20 = 0xfb;
155: iVar23 = 5;
156: }
157: else {
158: *(undefined *)((long)puVar19 + 0x105) = 5;
159: if (uVar16 < 7) {
160: iVar20 = 0xfa;
161: iVar23 = 6;
162: }
163: else {
164: *(undefined *)((long)puVar19 + 0x106) = 6;
165: if (uVar16 < 8) {
166: iVar20 = 0xf9;
167: iVar23 = 7;
168: }
169: else {
170: *(undefined *)((long)puVar19 + 0x107) = 7;
171: if (uVar16 < 9) {
172: iVar20 = 0xf8;
173: iVar23 = 8;
174: }
175: else {
176: *(undefined *)(puVar19 + 0x21) = 8;
177: if (uVar16 < 10) {
178: iVar20 = 0xf7;
179: iVar23 = 9;
180: }
181: else {
182: *(undefined *)((long)puVar19 + 0x109) = 9;
183: if (uVar16 < 0xb) {
184: iVar20 = 0xf6;
185: iVar23 = 10;
186: }
187: else {
188: *(undefined *)((long)puVar19 + 0x10a) = 10;
189: if (uVar16 < 0xc) {
190: iVar20 = 0xf5;
191: iVar23 = 0xb;
192: }
193: else {
194: *(undefined *)((long)puVar19 + 0x10b) = 0xb;
195: if (uVar16 < 0xd) {
196: iVar20 = 0xf4;
197: iVar23 = 0xc;
198: }
199: else {
200: *(undefined *)((long)puVar19 + 0x10c) = 0xc;
201: if (uVar16 < 0xe) {
202: iVar20 = 0xf3;
203: iVar23 = 0xd;
204: }
205: else {
206: *(undefined *)((long)puVar19 + 0x10d) = 0xd;
207: if (uVar16 < 0xf) {
208: iVar20 = 0xf2;
209: iVar23 = 0xe;
210: }
211: else {
212: *(undefined *)((long)puVar19 + 0x10e) = 0xe;
213: iVar20 = 0xf1;
214: iVar23 = 0xf;
215: }
216: }
217: }
218: }
219: }
220: }
221: }
222: }
223: }
224: }
225: }
226: }
227: }
228: }
229: }
230: auVar15 = _DAT_00189c50;
231: auVar14 = _DAT_00168ad0;
232: uVar27 = 0x100 - uVar16;
233: uVar17 = 0;
234: pauVar22 = (undefined (*) [16])((long)puVar19 + (ulong)uVar16 + 0x100);
235: auVar31 = CONCAT88(CONCAT44(iVar23 + 3,iVar23 + 2),CONCAT44(iVar23 + 1,iVar23));
236: do {
237: uVar17 = uVar17 + 1;
238: uVar47 = SUB164(auVar31,0);
239: iVar59 = SUB164(auVar14,0);
240: uVar46 = uVar47 + iVar59;
241: iVar50 = SUB164(auVar31 >> 0x20,0);
242: iVar62 = SUB164(auVar14 >> 0x20,0);
243: iVar49 = iVar50 + iVar62;
244: iVar52 = SUB164(auVar31 >> 0x40,0);
245: iVar58 = SUB164(auVar31 >> 0x60,0);
246: iVar60 = SUB164(auVar14 >> 0x40,0);
247: iVar51 = iVar52 + iVar60;
248: iVar45 = SUB164(auVar14 >> 0x60,0);
249: iVar57 = iVar58 + iVar45;
250: uVar48 = (undefined2)iVar49;
251: uVar32 = SUB162(auVar31 >> 0x20,0);
252: auVar30 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)(
253: (uint)iVar49 >> 0x10),
254: CONCAT212(SUB162(auVar31 >> 0x30,0),
255: SUB1612(auVar31,0))) >> 0x60,0),
256: CONCAT210(uVar48,SUB1610(auVar31,0))) >> 0x50,0),
257: CONCAT28(uVar32,SUB168(auVar31,0))) >> 0x40,0),
258: (ulong)(uVar46 >> 0x10) << 0x30) >> 0x20,0) &
259: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar46 * 0x10000);
260: sVar63 = SUB162(auVar31 >> 0x40,0);
261: uVar64 = SUB162(auVar31 >> 0x50,0);
262: uVar24 = (ulong)CONCAT24(uVar64,CONCAT22((short)iVar51,sVar63)) & 0xffff0000;
263: lVar5 = (uVar24 >> 0x10) << 0x30;
264: iVar4 = (SUB166(auVar30,0) >> 0x10) << 0x20;
265: auVar30 = ZEXT1416(CONCAT122(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(
266: CONCAT412(SUB164(CONCAT214((short)((uint)iVar51 >>
267: 0x10),
268: CONCAT212((short)((
269: ulong)uVar46 >> 0x10),SUB1612(auVar30,0))) >> 0x60
270: ,0),CONCAT210(uVar64,SUB1610(auVar30,0))) >> 0x50,
271: 0),CONCAT28(SUB162(auVar31 >> 0x10,0),
272: SUB168(auVar30,0))) >> 0x40,0),lVar5)
273: >> 0x30,0),iVar4) >> 0x20,0),sVar63)) << 0x10;
274: uVar36 = uVar46 + iVar59;
275: uVar16 = iVar49 + iVar62;
276: uVar43 = iVar51 + iVar60;
277: auVar37 = CONCAT48(uVar43,CONCAT44(uVar16,uVar36));
278: iVar45 = iVar57 + iVar45;
279: uVar61 = uVar36 + iVar59;
280: iVar62 = uVar16 + iVar62;
281: sVar33 = (short)(uVar46 * 0x10000 >> 0x10);
282: uVar21 = (ulong)CONCAT24(uVar48,CONCAT22(SUB162(auVar31 >> 0x60,0),uVar32)) & 0xffff0000;
283: lVar7 = (uVar21 >> 0x10) << 0x30;
284: iVar6 = (SUB166(auVar30,0) >> 0x10) << 0x20;
285: auVar30 = CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)
286: iVar57,CONCAT212((short)(uVar24 >> 0x10),
287: SUB1612(auVar30,0))) >> 0x60,0),
288: CONCAT210(uVar48,SUB1610(auVar30,0))) >> 0x50,0),
289: CONCAT28(sVar33,SUB168(auVar30,0))) >> 0x40,0),
290: lVar7) >> 0x30,0),iVar6) &
291: (undefined  [16])0xffffffff00000000;
292: auVar38 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)(
293: (uint)iVar62 >> 0x10),
294: CONCAT212((short)(uVar16 >> 0x10),auVar37)) >>
295: 0x60,0),CONCAT210((short)iVar62,SUB1210(auVar37,0)
296: )) >> 0x50,0),
297: CONCAT28((short)uVar16,CONCAT44(uVar16,uVar36)))
298: >> 0x40,0),(ulong)(uVar61 >> 0x10) << 0x30) >> 0x20,
299: 0) & SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
300: uVar61 * 0x10000);
301: uVar48 = (undefined2)(uVar43 >> 0x10);
302: uVar11 = (ulong)CONCAT24(uVar48,(uVar43 + iVar60) * 0x10000) & 0xffff0000;
303: lVar9 = (uVar11 >> 0x10) << 0x30;
304: iVar8 = (SUB166(auVar38,0) >> 0x10) << 0x20;
305: uVar12 = (ulong)CONCAT24((short)iVar62,iVar45 * 0x10000) & 0xffff0000;
306: uVar10 = (SUB166(CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
307: SUB164(CONCAT214((short)(uVar43 + iVar60 >> 0x10),
308: CONCAT212((short)((ulong)uVar61
309: >> 0x10),
310: SUB1612(auVar38,0))) >>
311: 0x60,0),
312: CONCAT210(uVar48,SUB1610(auVar38,0))) >> 0x50,0),
313: CONCAT28((short)(uVar36 >> 0x10),SUB168(auVar38,0)
314: )) >> 0x40,0),lVar9) >> 0x30,0),iVar8) >>
315: 0x20,0),(uVar43 & 0xffff) << 0x10),0) >> 0x10) << 0x20;
316: uVar53 = (undefined)((uint6)iVar4 >> 0x28);
317: uVar54 = (undefined)iVar49;
318: uVar44 = (undefined)iVar62;
319: uVar55 = (undefined)((uint)iVar49 >> 8);
320: uVar56 = (undefined)(uVar24 >> 0x10);
321: uVar42 = (undefined)(uVar12 >> 0x10);
322: uVar35 = (undefined)(uVar21 >> 0x10);
323: uVar34 = (undefined)((uint6)iVar6 >> 0x28);
324: uVar41 = (undefined)(uVar43 & 0xffff);
325: uVar40 = (undefined)(((uVar16 & 0xffff) << 0x10) >> 0x18);
326: uVar39 = (undefined)(uVar16 & 0xffff);
327: auVar30 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
328: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
329: (CONCAT214(SUB162(CONCAT115((char)(((uVar12 >>
330: 0x10) << 0x30)
331: >> 0x38),
332: CONCAT114((char)((
333: ulong)lVar7 >> 0x38),SUB1614(auVar30,0))) >> 0x70,
334: 0),CONCAT113(uVar42,SUB1613(auVar30,0))) >> 0x68,0
335: ),CONCAT112(uVar35,SUB1612(auVar30,0))) >> 0x60,0)
336: ,CONCAT111((char)(uVar10 >> 0x28),
337: SUB1611(auVar30,0))) >> 0x58,0),
338: CONCAT110(uVar34,SUB1610(auVar30,0))) >> 0x50,0),
339: CONCAT19(uVar41,SUB169(auVar30,0))) >> 0x48,0),
340: CONCAT18(SUB161(auVar31 >> 0x40,0),
341: SUB168(auVar30,0))) >> 0x40,0),uVar40))
342: << 0x38) >> 0x30,0),uVar39)) << 0x28 &
343: (undefined  [16])0xffffffff00000000;
344: uVar24 = ((ulong)CONCAT14(uVar55,CONCAT13(uVar44,CONCAT12(uVar54,CONCAT11((char)((uint6)iVar8 >>
345: 0x28),uVar53))))
346: & 0xff00) << 0x10;
347: auVar31 = CONCAT142(SUB1614(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
348: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
349: (CONCAT115((char)((uint)iVar62 >> 8),
350: CONCAT114(uVar40,SUB1614(auVar30,0)))
351: >> 0x70,0),CONCAT113(uVar55,SUB1613(auVar30,0)))
352: >> 0x68,0),
353: CONCAT112((char)(((uint)uVar32 << 0x10) >> 0x18),
354: SUB1612(auVar30,0))) >> 0x60,0),
355: CONCAT111(uVar44,SUB1611(auVar30,0))) >> 0x58,0),
356: CONCAT110(uVar39,SUB1610(auVar30,0))) >> 0x50,0),
357: CONCAT19(uVar54,SUB169(auVar30,0))) >> 0x48,0),
358: CONCAT18(SUB161(auVar31 >> 0x20,0),
359: SUB168(auVar30,0))) >> 0x40,0),
360: (uVar24 >> 0x18) << 0x38) >> 0x10,0) &
361: SUB1614((undefined  [16])0xff00000000000000 >> 0x10,0) &
362: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
363: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),sVar33 << 8);
364: uVar10 = uVar10 & 0xff0000000000 |
365: (uint6)CONCAT14((char)((ulong)lVar5 >> 0x38),
366: CONCAT13(uVar34,CONCAT12((char)(uVar11 >> 0x10),CONCAT11(uVar41,uVar56)
367: )));
368: lVar5 = (ulong)uVar10 << 8;
369: uVar34 = (undefined)((ulong)lVar5 >> 0x10);
370: auVar31 = CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610(CONCAT88(
371: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
372: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
373: (SUB162(CONCAT115((char)((ulong)lVar9 >> 0x38),
374: CONCAT114((char)(uVar24 >> 0x18)
375: ,SUB1614(auVar31,0)))
376: >> 0x70,0),
377: CONCAT113((char)((ulong)lVar5 >> 0x30),
378: SUB1613(auVar31,0))) >> 0x68,0),
379: CONCAT112((char)((uVar36 & 0xffff) >> 8),
380: SUB1612(auVar31,0))) >> 0x60,0),
381: CONCAT111((char)((ulong)lVar5 >> 0x28),
382: SUB1611(auVar31,0))) >> 0x58,0),
383: CONCAT110(uVar53,SUB1610(auVar31,0))) >> 0x50,0),
384: CONCAT19((char)((ulong)lVar5 >> 0x20),
385: SUB169(auVar31,0))) >> 0x48,0),
386: CONCAT18((char)((uVar47 & 0xffff) >> 8),
387: SUB168(auVar31,0))) >> 0x40,0),
388: (ulong)(uVar10 >> 0x10) << 0x38) >> 0x30,0) &
389: SUB1610((undefined  [16])0xffffffffffffffff >>
390: 0x30,0) &
391: SUB1610((undefined  [16])0xffffffffffffffff >>
392: 0x30,0) &
393: SUB1610((undefined  [16])0xff00000000000000 >>
394: 0x30,0),uVar34)) << 0x28) >> 0x20,0),
395: uVar56),(SUB163(auVar31,0) >> 8) << 0x10) >> 0x10,
396: 0),sVar63 << 8);
397: uVar13 = CONCAT11(uVar54,uVar35);
398: uVar16 = CONCAT13(uVar39,CONCAT12((char)iVar57,uVar13));
399: *pauVar22 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
400: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
401: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
402: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
403: CONCAT115((char)iVar45 + SUB161(auVar14 >> 0x60,0)
404: ,CONCAT114((char)((ulong)lVar5 >> 0x18),
405: SUB1614(auVar31,0))) >> 0x70,
406: 0),CONCAT113(uVar44,SUB1613(auVar31,0))) >> 0x68,0
407: ),CONCAT112((char)(uVar61 * 0x10000 >> 0x10),
408: SUB1612(auVar31,0))) >> 0x60,0),
409: CONCAT111(uVar42,SUB1611(auVar31,0))) >> 0x58,0),
410: CONCAT110(uVar34,SUB1610(auVar31,0))) >> 0x50,0),
411: CONCAT19(uVar39,SUB169(auVar31,0))) >> 0x48,0),
412: CONCAT18((char)(uVar36 & 0xffff),SUB168(auVar31,0)
413: )) >> 0x40,0),
414: ((((ulong)CONCAT15(uVar44,CONCAT14(uVar42,uVar16))
415: & 0xff0000) << 8) >> 0x18) << 0x38) >> 0x38,0) &
416: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
417: ,0),(SUB167(auVar31,0) >> 0x18) << 0x30) >>
418: 0x30,0),((((uint6)uVar16 & 0xff00) << 8) >> 0x10)
419: << 0x28) >> 0x28,0),
420: (SUB165(auVar31,0) >> 0x10) << 0x20) >> 0x20,0),
421: (uint)uVar13 << 0x18) >> 0x18,0),
422: (SUB163(auVar31,0) >> 8) << 0x10) >> 0x10,0),
423: (ushort)(uVar47 & 0xffff) & 0xff | uVar32 << 8);
424: pauVar22 = pauVar22[1];
425: auVar31 = CONCAT412(iVar58 + SUB164(auVar15 >> 0x60,0),
426: CONCAT48(iVar52 + SUB164(auVar15 >> 0x40,0),
427: CONCAT44(iVar50 + SUB164(auVar15 >> 0x20,0),
428: uVar47 + SUB164(auVar15,0))));
429: } while (uVar17 < uVar27 >> 4);
430: iVar23 = iVar23 + (uVar27 & 0xfffffff0);
431: iVar20 = iVar20 + (uVar27 >> 4) * -0x10;
432: if (uVar27 != (uVar27 & 0xfffffff0)) {
433: *(char *)((long)puVar19 + (long)iVar23 + 0x100) = (char)iVar23;
434: if (iVar20 != 1) {
435: *(char *)((long)puVar19 + (long)(iVar23 + 1) + 0x100) = (char)(iVar23 + 1);
436: if (iVar20 != 2) {
437: *(char *)((long)puVar19 + (long)(iVar23 + 2) + 0x100) = (char)(iVar23 + 2);
438: if (iVar20 != 3) {
439: *(char *)((long)puVar19 + (long)(iVar23 + 3) + 0x100) = (char)(iVar23 + 3);
440: if (iVar20 != 4) {
441: *(char *)((long)puVar19 + (long)(iVar23 + 4) + 0x100) = (char)(iVar23 + 4);
442: if (iVar20 != 5) {
443: *(char *)((long)puVar19 + (long)(iVar23 + 5) + 0x100) = (char)(iVar23 + 5);
444: if (iVar20 != 6) {
445: *(char *)((long)puVar19 + (long)(iVar23 + 6) + 0x100) = (char)(iVar23 + 6);
446: if (iVar20 != 7) {
447: *(char *)((long)puVar19 + (long)(iVar23 + 7) + 0x100) = (char)(iVar23 + 7);
448: if (iVar20 != 8) {
449: *(char *)((long)puVar19 + (long)(iVar23 + 8) + 0x100) = (char)(iVar23 + 8);
450: if (iVar20 != 9) {
451: *(char *)((long)puVar19 + (long)(iVar23 + 9) + 0x100) = (char)(iVar23 + 9);
452: if (iVar20 != 10) {
453: *(char *)((long)puVar19 + (long)(iVar23 + 10) + 0x100) = (char)(iVar23 + 10)
454: ;
455: if (iVar20 != 0xb) {
456: *(char *)((long)puVar19 + (long)(iVar23 + 0xb) + 0x100) =
457: (char)(iVar23 + 0xb);
458: if (iVar20 != 0xc) {
459: *(char *)((long)puVar19 + (long)(iVar23 + 0xc) + 0x100) =
460: (char)(iVar23 + 0xc);
461: if (iVar20 != 0xd) {
462: *(char *)((long)puVar19 + (long)(iVar23 + 0xd) + 0x100) =
463: (char)(iVar23 + 0xd);
464: if (iVar20 != 0xe) {
465: *(char *)((long)puVar19 + (long)(iVar23 + 0xe) + 0x100) =
466: (char)(iVar23 + 0xe);
467: }
468: }
469: }
470: }
471: }
472: }
473: }
474: }
475: }
476: }
477: }
478: }
479: }
480: }
481: }
482: puVar26 = puVar19 + 0x40;
483: uVar24 = 0x180;
484: bVar28 = ((ulong)puVar26 & 1) != 0;
485: if (bVar28) {
486: *(undefined *)(puVar19 + 0x40) = 0xff;
487: puVar26 = (undefined8 *)((long)puVar19 + 0x201);
488: uVar24 = 0x17f;
489: }
490: puVar25 = puVar26;
491: if (((ulong)puVar26 & 2) != 0) {
492: puVar25 = (undefined8 *)((long)puVar26 + 2);
493: uVar24 = (ulong)((int)uVar24 - 2);
494: *(undefined2 *)puVar26 = 0xffff;
495: }
496: if (((ulong)puVar25 & 4) != 0) {
497: *(undefined4 *)puVar25 = 0xffffffff;
498: uVar24 = (ulong)((int)uVar24 - 4);
499: puVar25 = (undefined8 *)((long)puVar25 + 4);
500: }
501: uVar21 = uVar24 >> 3;
502: while (uVar21 != 0) {
503: uVar21 = uVar21 - 1;
504: *puVar25 = 0xffffffffffffffff;
505: puVar25 = puVar25 + (ulong)bVar29 * -2 + 1;
506: }
507: if ((uVar24 & 4) != 0) {
508: *(undefined4 *)puVar25 = 0xffffffff;
509: puVar25 = (undefined8 *)((long)puVar25 + 4);
510: }
511: if ((uVar24 & 2) != 0) {
512: *(undefined2 *)puVar25 = 0xffff;
513: puVar25 = (undefined8 *)((long)puVar25 + 2);
514: }
515: if (bVar28) {
516: *(undefined *)puVar25 = 0xff;
517: }
518: puVar26 = puVar19 + 0x70;
519: uVar24 = 0x180;
520: bVar28 = ((ulong)puVar26 & 1) != 0;
521: if (bVar28) {
522: *(undefined *)(puVar19 + 0x70) = 0;
523: puVar26 = (undefined8 *)((long)puVar19 + 0x381);
524: uVar24 = 0x17f;
525: }
526: puVar25 = puVar26;
527: if (((ulong)puVar26 & 2) != 0) {
528: puVar25 = (undefined8 *)((long)puVar26 + 2);
529: uVar24 = (ulong)((int)uVar24 - 2);
530: *(undefined2 *)puVar26 = 0;
531: }
532: if (((ulong)puVar25 & 4) != 0) {
533: *(undefined4 *)puVar25 = 0;
534: uVar24 = (ulong)((int)uVar24 - 4);
535: puVar25 = (undefined8 *)((long)puVar25 + 4);
536: }
537: uVar21 = uVar24 >> 3;
538: while (uVar21 != 0) {
539: uVar21 = uVar21 - 1;
540: *puVar25 = 0;
541: puVar25 = puVar25 + (ulong)bVar29 * -2 + 1;
542: }
543: if ((uVar24 & 4) != 0) {
544: *(undefined4 *)puVar25 = 0;
545: puVar25 = (undefined8 *)((long)puVar25 + 4);
546: }
547: if ((uVar24 & 2) != 0) {
548: *(undefined2 *)puVar25 = 0;
549: puVar25 = (undefined8 *)((long)puVar25 + 2);
550: }
551: if (bVar28) {
552: *(undefined *)puVar25 = 0;
553: }
554: puVar26 = (undefined8 *)param_1[0x35];
555: puVar19[0xa0] = *puVar26;
556: puVar19[0xa1] = puVar26[1];
557: puVar19[0xa2] = puVar26[2];
558: puVar19[0xa3] = puVar26[3];
559: puVar19[0xa4] = puVar26[4];
560: puVar19[0xa5] = puVar26[5];
561: puVar19[0xa6] = puVar26[6];
562: puVar19[0xa7] = puVar26[7];
563: puVar19[0xa8] = puVar26[8];
564: puVar19[0xa9] = puVar26[9];
565: puVar19[0xaa] = puVar26[10];
566: puVar19[0xab] = puVar26[0xb];
567: puVar19[0xac] = puVar26[0xc];
568: puVar19[0xad] = puVar26[0xd];
569: puVar19[0xae] = puVar26[0xe];
570: puVar19[0xaf] = puVar26[0xf];
571: if ((ulong)*(uint *)(param_1 + 0x11) * (long)*(int *)(param_1 + 0x12) -
572: ((ulong)*(uint *)(param_1 + 0x11) * (long)*(int *)(param_1 + 0x12) & 0xffffffff) != 0) {
573: ppcVar2 = (code **)*param_1;
574: *(undefined4 *)(ppcVar2 + 5) = 0x46;
575: (**ppcVar2)(param_1);
576: }
577: *(undefined4 *)(ppcVar1 + 0xe) = 0;
578: uVar18 = FUN_0012bfe0(param_1);
579: *(undefined4 *)((long)ppcVar1 + 0x74) = uVar18;
580: iVar23 = *(int *)((long)param_1 + 0x6c);
581: ppcVar1[0xf] = (code *)0x0;
582: ppcVar1[0x10] = (code *)0x0;
583: if (iVar23 == 0) {
584: *(undefined4 *)((long)param_1 + 0x7c) = 0;
585: *(undefined4 *)(param_1 + 0x10) = 0;
586: *(undefined4 *)((long)param_1 + 0x84) = 0;
587: }
588: else {
589: if (*(int *)(param_1 + 0xb) == 0) {
590: *(undefined4 *)((long)param_1 + 0x7c) = 0;
591: *(undefined4 *)(param_1 + 0x10) = 0;
592: *(undefined4 *)((long)param_1 + 0x84) = 0;
593: }
594: if (*(int *)((long)param_1 + 0x5c) == 0) {
595: if (*(int *)(param_1 + 0x12) != 3) goto LAB_0012cec2;
596: LAB_0012d18c:
597: if (param_1[0x14] == (code *)0x0) {
598: if (*(int *)((long)param_1 + 0x74) != 0) {
599: *(undefined4 *)((long)param_1 + 0x84) = 1;
600: iVar23 = *(int *)((long)param_1 + 0x7c);
601: goto LAB_0012d1a7;
602: }
603: *(undefined4 *)((long)param_1 + 0x7c) = 1;
604: goto LAB_0012cee8;
605: }
606: iVar23 = *(int *)((long)param_1 + 0x7c);
607: *(undefined4 *)(param_1 + 0x10) = 1;
608: LAB_0012d1a7:
609: if (iVar23 != 0) goto LAB_0012cee8;
610: pcVar3 = param_1[0x10];
611: }
612: else {
613: ppcVar2 = (code **)*param_1;
614: *(undefined4 *)(ppcVar2 + 5) = 0x2f;
615: (**ppcVar2)(param_1);
616: if (*(int *)(param_1 + 0x12) == 3) goto LAB_0012d18c;
617: LAB_0012cec2:
618: *(undefined4 *)((long)param_1 + 0x7c) = 1;
619: *(undefined4 *)(param_1 + 0x10) = 0;
620: *(undefined4 *)((long)param_1 + 0x84) = 0;
621: param_1[0x14] = (code *)0x0;
622: LAB_0012cee8:
623: FUN_00139c30(param_1);
624: ppcVar1[0xf] = param_1[0x4e];
625: pcVar3 = param_1[0x10];
626: }
627: if (pcVar3 != (code *)0x0) {
628: FUN_0013bc80(param_1);
629: ppcVar1[0x10] = param_1[0x4e];
630: iVar23 = *(int *)((long)param_1 + 0x5c);
631: goto joined_r0x0012d050;
632: }
633: }
634: iVar23 = *(int *)((long)param_1 + 0x5c);
635: joined_r0x0012d050:
636: if (iVar23 == 0) {
637: if (*(int *)((long)ppcVar1 + 0x74) == 0) {
638: FUN_00124000();
639: FUN_001327d0(param_1);
640: }
641: else {
642: FUN_001300d0(param_1);
643: }
644: FUN_00131920(param_1,*(undefined4 *)((long)param_1 + 0x84));
645: }
646: FUN_00125310(param_1);
647: if (*(int *)((long)param_1 + 0x13c) == 0) {
648: if (*(int *)(param_1 + 0x27) == 0) {
649: FUN_00127580();
650: }
651: else {
652: FUN_001314c0();
653: }
654: }
655: else {
656: FUN_001417a0(param_1);
657: }
658: FUN_00120360();
659: if (*(int *)((long)param_1 + 0x5c) == 0) {
660: FUN_001291c0(param_1);
661: }
662: (**(code **)(param_1[1] + 0x30))(param_1);
663: (**(code **)(param_1[0x48] + 0x10))(param_1);
664: iVar23 = *(int *)(param_1 + 0x3b);
665: pcVar3 = param_1[0x44];
666: *(undefined4 *)(pcVar3 + 0x14) = 0;
667: *(int *)(pcVar3 + 0x18) = iVar23 + -1;
668: pcVar3 = param_1[2];
669: if (((pcVar3 != (code *)0x0) && (*(int *)(param_1 + 0xb) == 0)) &&
670: (*(int *)(param_1[0x48] + 0x20) != 0)) {
671: if (*(int *)(param_1 + 0x27) == 0) {
672: iVar23 = *(int *)(param_1 + 7);
673: }
674: else {
675: iVar23 = *(int *)(param_1 + 7) * 3 + 2;
676: }
677: uVar16 = *(uint *)((long)param_1 + 0x1a4);
678: *(undefined8 *)(pcVar3 + 8) = 0;
679: *(undefined4 *)(pcVar3 + 0x18) = 0;
680: iVar20 = *(int *)((long)param_1 + 0x84);
681: *(ulong *)(pcVar3 + 0x10) = (ulong)uVar16 * (long)iVar23;
682: *(uint *)(pcVar3 + 0x1c) = 3 - (uint)(iVar20 == 0);
683: *(int *)(ppcVar1 + 0xe) = *(int *)(ppcVar1 + 0xe) + 1;
684: }
685: return;
686: }
687: 

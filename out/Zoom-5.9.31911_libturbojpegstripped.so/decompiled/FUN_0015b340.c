1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0015b340(ulong param_1,long *param_2,ulong param_3,undefined (**param_4) [16])
5: 
6: {
7: char cVar1;
8: char cVar6;
9: char cVar10;
10: char cVar14;
11: char cVar19;
12: char cVar24;
13: char cVar28;
14: uint uVar29;
15: undefined (*pauVar30) [16];
16: undefined (*pauVar31) [16];
17: ushort *puVar32;
18: undefined (*pauVar33) [16];
19: short sVar34;
20: short sVar35;
21: uint3 uVar36;
22: short sVar47;
23: short sVar50;
24: short sVar52;
25: undefined2 uVar54;
26: short sVar55;
27: short sVar58;
28: short sVar60;
29: undefined auVar49 [13];
30: short sVar62;
31: undefined auVar44 [16];
32: short sVar48;
33: short sVar51;
34: short sVar53;
35: short sVar56;
36: short sVar59;
37: short sVar61;
38: short sVar63;
39: undefined auVar45 [16];
40: long lVar57;
41: short sVar65;
42: uint3 uVar66;
43: short sVar68;
44: short sVar69;
45: short sVar70;
46: short sVar71;
47: short sVar72;
48: short sVar73;
49: short sVar74;
50: uint3 uVar75;
51: uint6 uVar77;
52: undefined2 uVar78;
53: undefined2 uVar79;
54: undefined2 uVar80;
55: uint3 uVar81;
56: undefined2 uVar98;
57: undefined2 uVar99;
58: undefined auVar90 [16];
59: undefined auVar91 [16];
60: short sVar101;
61: uint3 uVar102;
62: short sVar118;
63: short sVar119;
64: short sVar120;
65: undefined2 uVar121;
66: short sVar122;
67: undefined2 uVar123;
68: short sVar125;
69: short sVar127;
70: short sVar129;
71: undefined auVar111 [16];
72: undefined auVar112 [16];
73: undefined2 uVar126;
74: undefined2 uVar128;
75: long lVar124;
76: uint3 uVar131;
77: uint6 uVar133;
78: ushort uVar134;
79: short sVar135;
80: ushort uVar142;
81: uint6 uVar136;
82: short sVar140;
83: short sVar141;
84: short sVar143;
85: ushort uVar144;
86: short sVar145;
87: ushort uVar146;
88: undefined2 uVar147;
89: short sVar148;
90: ushort uVar149;
91: short sVar150;
92: ushort uVar151;
93: undefined2 uVar152;
94: byte bVar155;
95: short sVar153;
96: undefined auVar138 [16];
97: undefined auVar139 [16];
98: ushort uVar154;
99: ushort uVar156;
100: short sVar157;
101: ushort uVar158;
102: short sVar163;
103: ushort uVar164;
104: short sVar165;
105: ushort uVar166;
106: short sVar167;
107: ushort uVar168;
108: short sVar169;
109: ushort uVar170;
110: short sVar171;
111: ushort uVar172;
112: short sVar173;
113: ushort uVar174;
114: byte bVar177;
115: short sVar175;
116: undefined auVar160 [16];
117: undefined auVar161 [16];
118: undefined auVar162 [16];
119: ushort uVar176;
120: char cVar2;
121: char cVar3;
122: char cVar4;
123: char cVar5;
124: char cVar7;
125: char cVar8;
126: char cVar9;
127: char cVar11;
128: char cVar12;
129: char cVar13;
130: char cVar15;
131: char cVar16;
132: char cVar17;
133: char cVar18;
134: char cVar20;
135: char cVar21;
136: char cVar22;
137: char cVar23;
138: char cVar25;
139: char cVar26;
140: char cVar27;
141: uint5 uVar37;
142: uint7 uVar38;
143: undefined8 uVar39;
144: unkbyte9 Var40;
145: unkbyte10 Var41;
146: undefined auVar42 [11];
147: undefined auVar43 [12];
148: undefined auVar46 [16];
149: undefined2 uVar64;
150: uint5 uVar67;
151: uint5 uVar76;
152: uint5 uVar82;
153: uint7 uVar83;
154: undefined8 uVar84;
155: unkbyte9 Var85;
156: unkbyte10 Var86;
157: undefined auVar87 [11];
158: undefined auVar88 [12];
159: undefined auVar89 [13];
160: undefined auVar92 [16];
161: undefined auVar93 [16];
162: undefined auVar94 [16];
163: undefined auVar95 [16];
164: undefined auVar96 [16];
165: undefined auVar97 [16];
166: undefined2 uVar100;
167: uint5 uVar103;
168: uint7 uVar104;
169: undefined8 uVar105;
170: unkbyte9 Var106;
171: unkbyte10 Var107;
172: undefined auVar108 [11];
173: undefined auVar109 [12];
174: undefined auVar110 [13];
175: undefined auVar113 [16];
176: undefined auVar114 [16];
177: undefined auVar115 [16];
178: undefined auVar116 [16];
179: undefined auVar117 [16];
180: undefined2 uVar130;
181: uint5 uVar132;
182: undefined auVar137 [15];
183: undefined auVar159 [15];
184: 
185: param_1 = param_1 & 0xffffffff;
186: if (param_1 == 0) {
187: /* WARNING: Read-only address (ram,0x0019c960) is written */
188: /* WARNING: Read-only address (ram,0x0019c970) is written */
189: /* WARNING: Read-only address (ram,0x0019c980) is written */
190: return;
191: }
192: param_3 = param_3 & 0xffffffff;
193: puVar32 = *(ushort **)(*param_2 + param_3 * 8);
194: pauVar31 = *(undefined (**) [16])(param_2[1] + param_3 * 8);
195: pauVar30 = *(undefined (**) [16])(param_2[2] + param_3 * 8);
196: pauVar33 = *param_4;
197: do {
198: auVar44 = *pauVar31;
199: auVar111 = *pauVar30;
200: auVar90 = psllw(CONCAT214(0xffff,CONCAT212(0xffff,CONCAT210(0xffff,CONCAT28(0xffff,
201: 0xffffffffffffffff)))),7);
202: uVar134 = (ushort)SUB161(auVar44 >> 0x40,0);
203: bVar155 = SUB161(auVar44 >> 0x78,0);
204: auVar137 = CONCAT114(bVar155,ZEXT1314(CONCAT112(SUB161(auVar44 >> 0x70,0),
205: ZEXT1112(CONCAT110(SUB161(auVar44 >> 0x68,0),
206: (unkuint10)
207: CONCAT18(SUB161(auVar44 >>
208: 0x60,0),
209: (ulong)CONCAT16(
210: SUB161(auVar44 >> 0x58,0),
211: (uint6)CONCAT14(SUB161(auVar44 >> 0x50,0),
212: (uint)CONCAT12(SUB161(auVar44 >>
213: 0x48,0),
214: uVar134)))))))));
215: auVar89 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
216: SUB158(CONCAT78
217: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
218: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
219: CONCAT114(SUB161(auVar44 >> 0x38,0),
220: SUB1614(auVar44,0)) >> 0x68,0),
221: CONCAT112(SUB161(auVar44 >> 0x30,0),
222: SUB1612(auVar44,0))) >> 0x60,0),
223: SUB1612(auVar44,0)) >> 0x58,0),
224: CONCAT110(SUB161(auVar44 >> 0x28,0),
225: SUB1610(auVar44,0))) >> 0x50,0),
226: SUB1610(auVar44,0)) >> 0x48,0),
227: CONCAT18(SUB161(auVar44 >> 0x20,0),
228: SUB168(auVar44,0))) >> 0x40,0),
229: SUB168(auVar44,0)) >> 0x38,0) &
230: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
231: ,0) &
232: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
233: ,0) &
234: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
235: ,0) &
236: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
237: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
238: 0x30,0),SUB166(auVar44,0)) >> 0x28,0) &
239: SUB1611((undefined  [16])0xffff00ffffffffff >>
240: 0x28,0),
241: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
242: SUB164(auVar44,0)) >> 0x18,0) &
243: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
244: uVar156 = (ushort)SUB161(auVar111 >> 0x40,0);
245: bVar177 = SUB161(auVar111 >> 0x78,0);
246: auVar159 = CONCAT114(bVar177,ZEXT1314(CONCAT112(SUB161(auVar111 >> 0x70,0),
247: ZEXT1112(CONCAT110(SUB161(auVar111 >> 0x68,0),
248: (unkuint10)
249: CONCAT18(SUB161(auVar111 >>
250: 0x60,0),
251: (ulong)CONCAT16(
252: SUB161(auVar111 >> 0x58,0),
253: (uint6)CONCAT14(SUB161(auVar111 >> 0x50,0),
254: (uint)CONCAT12(SUB161(auVar111 >>
255: 0x48,0),
256: uVar156)))))))));
257: auVar49 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
258: SUB158(CONCAT78
259: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
260: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
261: CONCAT114(SUB161(auVar111 >> 0x38,0),
262: SUB1614(auVar111,0)) >> 0x68,0),
263: CONCAT112(SUB161(auVar111 >> 0x30,0),
264: SUB1612(auVar111,0))) >> 0x60,0),
265: SUB1612(auVar111,0)) >> 0x58,0),
266: CONCAT110(SUB161(auVar111 >> 0x28,0),
267: SUB1610(auVar111,0))) >> 0x50,0),
268: SUB1610(auVar111,0)) >> 0x48,0),
269: CONCAT18(SUB161(auVar111 >> 0x20,0),
270: SUB168(auVar111,0))) >> 0x40,0),
271: SUB168(auVar111,0)) >> 0x38,0) &
272: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
273: ,0) &
274: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
275: ,0) &
276: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
277: ,0) &
278: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
279: ,0),(SUB167(auVar111,0) >> 0x18) << 0x30)
280: >> 0x30,0),SUB166(auVar111,0)) >> 0x28,0) &
281: SUB1611((undefined  [16])0xffff00ffffffffff >>
282: 0x28,0),
283: (SUB165(auVar111,0) >> 0x10) << 0x20) >> 0x20,0),
284: SUB164(auVar111,0)) >> 0x18,0) &
285: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
286: sVar34 = SUB162(auVar90,0);
287: sVar135 = uVar134 + sVar34;
288: sVar47 = SUB162(auVar90 >> 0x10,0);
289: sVar140 = SUB162(ZEXT1516(auVar137) >> 0x10,0) + sVar47;
290: sVar50 = SUB162(auVar90 >> 0x20,0);
291: sVar141 = SUB142(ZEXT1314(SUB1513(auVar137 >> 0x10,0)) >> 0x10,0) + sVar50;
292: uVar133 = CONCAT24(sVar141,CONCAT22(sVar140,sVar135));
293: sVar52 = SUB162(auVar90 >> 0x30,0);
294: sVar143 = SUB122(ZEXT1112(SUB1511(auVar137 >> 0x20,0)) >> 0x10,0) + sVar52;
295: uVar84 = CONCAT26(sVar143,uVar133);
296: sVar55 = SUB162(auVar90 >> 0x40,0);
297: sVar145 = (short)((unkuint10)SUB159(auVar137 >> 0x30,0) >> 0x10) + sVar55;
298: Var86 = CONCAT28(sVar145,uVar84);
299: sVar58 = SUB162(auVar90 >> 0x50,0);
300: sVar148 = (short)((ulong)SUB157(auVar137 >> 0x40,0) >> 0x10) + sVar58;
301: sVar60 = SUB162(auVar90 >> 0x60,0);
302: sVar150 = (short)((uint6)SUB155(auVar137 >> 0x50,0) >> 0x10) + sVar60;
303: sVar62 = SUB162(auVar90 >> 0x70,0);
304: sVar153 = (ushort)bVar155 + sVar62;
305: sVar101 = (SUB162(auVar44,0) & 0xff) + sVar34;
306: sVar118 = SUB162(CONCAT133(auVar89,(SUB163(auVar44,0) >> 8) << 0x10) >> 0x10,0) + sVar47;
307: sVar119 = SUB132(auVar89 >> 8,0) + sVar50;
308: uVar77 = CONCAT24(sVar119,CONCAT22(sVar118,sVar101));
309: sVar120 = SUB132(auVar89 >> 0x18,0) + sVar52;
310: uVar39 = CONCAT26(sVar120,uVar77);
311: sVar122 = SUB132(auVar89 >> 0x28,0) + sVar55;
312: Var41 = CONCAT28(sVar122,uVar39);
313: sVar125 = SUB132(auVar89 >> 0x38,0) + sVar58;
314: sVar127 = SUB132(auVar89 >> 0x48,0) + sVar60;
315: sVar129 = SUB132(auVar89 >> 0x58,0) + sVar62;
316: sVar157 = uVar156 + sVar34;
317: sVar163 = SUB162(ZEXT1516(auVar159) >> 0x10,0) + sVar47;
318: sVar165 = SUB142(ZEXT1314(SUB1513(auVar159 >> 0x10,0)) >> 0x10,0) + sVar50;
319: sVar167 = SUB122(ZEXT1112(SUB1511(auVar159 >> 0x20,0)) >> 0x10,0) + sVar52;
320: sVar169 = (short)((unkuint10)SUB159(auVar159 >> 0x30,0) >> 0x10) + sVar55;
321: sVar171 = (short)((ulong)SUB157(auVar159 >> 0x40,0) >> 0x10) + sVar58;
322: sVar173 = (short)((uint6)SUB155(auVar159 >> 0x50,0) >> 0x10) + sVar60;
323: sVar175 = (ushort)bVar177 + sVar62;
324: sVar34 = (SUB162(auVar111,0) & 0xff) + sVar34;
325: sVar47 = SUB162(CONCAT133(auVar49,(SUB163(auVar111,0) >> 8) << 0x10) >> 0x10,0) + sVar47;
326: sVar50 = SUB132(auVar49 >> 8,0) + sVar50;
327: sVar52 = SUB132(auVar49 >> 0x18,0) + sVar52;
328: sVar55 = SUB132(auVar49 >> 0x28,0) + sVar55;
329: sVar58 = SUB132(auVar49 >> 0x38,0) + sVar58;
330: sVar60 = SUB132(auVar49 >> 0x48,0) + sVar60;
331: sVar62 = SUB132(auVar49 >> 0x58,0) + sVar62;
332: auVar90 = pmulhw(CONCAT214(sVar153 * 2,
333: CONCAT212(sVar150 * 2,
334: CONCAT210(sVar148 * 2,
335: CONCAT28(sVar145 * 2,
336: CONCAT26(sVar143 * 2,
337: CONCAT24(sVar141 * 2,
338: CONCAT22(sVar140 * 2,
339: sVar135 * 2))
340: ))))),_DAT_0019c970);
341: auVar111 = pmulhw(CONCAT214(sVar129 * 2,
342: CONCAT212(sVar127 * 2,
343: CONCAT210(sVar125 * 2,
344: CONCAT28(sVar122 * 2,
345: CONCAT26(sVar120 * 2,
346: CONCAT24(sVar119 * 2,
347: CONCAT22(sVar118 * 2,
348: sVar101 * 2)
349: )))))),_DAT_0019c970);
350: auVar160 = pmulhw(CONCAT214(sVar175 * 2,
351: CONCAT212(sVar173 * 2,
352: CONCAT210(sVar171 * 2,
353: CONCAT28(sVar169 * 2,
354: CONCAT26(sVar167 * 2,
355: CONCAT24(sVar165 * 2,
356: CONCAT22(sVar163 * 2,
357: sVar157 * 2)
358: )))))),_DAT_0019c960);
359: auVar44 = pmulhw(CONCAT214(sVar62 * 2,
360: CONCAT212(sVar60 * 2,
361: CONCAT210(sVar58 * 2,
362: CONCAT28(sVar55 * 2,
363: CONCAT26(sVar52 * 2,
364: CONCAT24(sVar50 * 2,
365: CONCAT22(sVar47 * 2,
366: sVar34 * 2)))
367: )))),_DAT_0019c960);
368: auVar138 = psraw(CONCAT214(SUB162(auVar90 >> 0x70,0) + 1,
369: CONCAT212(SUB162(auVar90 >> 0x60,0) + 1,
370: CONCAT210(SUB162(auVar90 >> 0x50,0) + 1,
371: CONCAT28(SUB162(auVar90 >> 0x40,0) + 1,
372: CONCAT26(SUB162(auVar90 >> 0x30,0) + 1,
373: CONCAT24(SUB162(auVar90 >> 0x20
374: ,0) + 1,
375: CONCAT22(SUB162(
376: auVar90 >> 0x10,0) + 1,SUB162(auVar90,0) + 1))))))
377: ),1);
378: auVar90 = psraw(CONCAT214(SUB162(auVar111 >> 0x70,0) + 1,
379: CONCAT212(SUB162(auVar111 >> 0x60,0) + 1,
380: CONCAT210(SUB162(auVar111 >> 0x50,0) + 1,
381: CONCAT28(SUB162(auVar111 >> 0x40,0) + 1,
382: CONCAT26(SUB162(auVar111 >> 0x30,0) + 1,
383: CONCAT24(SUB162(auVar111 >> 0x20
384: ,0) + 1,
385: CONCAT22(SUB162(
386: auVar111 >> 0x10,0) + 1,SUB162(auVar111,0) + 1))))
387: ))),1);
388: auVar161 = psraw(CONCAT214(SUB162(auVar160 >> 0x70,0) + 1,
389: CONCAT212(SUB162(auVar160 >> 0x60,0) + 1,
390: CONCAT210(SUB162(auVar160 >> 0x50,0) + 1,
391: CONCAT28(SUB162(auVar160 >> 0x40,0) + 1,
392: CONCAT26(SUB162(auVar160 >> 0x30,0) + 1,
393: CONCAT24(SUB162(auVar160 >>
394: 0x20,0) + 1,
395: CONCAT22(SUB162(
396: auVar160 >> 0x10,0) + 1,SUB162(auVar160,0) + 1))))
397: ))),1);
398: auVar44 = psraw(CONCAT214(SUB162(auVar44 >> 0x70,0) + 1,
399: CONCAT212(SUB162(auVar44 >> 0x60,0) + 1,
400: CONCAT210(SUB162(auVar44 >> 0x50,0) + 1,
401: CONCAT28(SUB162(auVar44 >> 0x40,0) + 1,
402: CONCAT26(SUB162(auVar44 >> 0x30,0) + 1,
403: CONCAT24(SUB162(auVar44 >> 0x20,
404: 0) + 1,
405: CONCAT22(SUB162(auVar44
406: >> 0x10
407: ,0) + 1,SUB162(auVar44,0) + 1))))))),1);
408: auVar160 = pmaddwd(CONCAT124(SUB1612(CONCAT106(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
409: (CONCAT214(sVar167,CONCAT212(sVar143,CONCAT210(
410: sVar148,Var86))) >> 0x60,0),
411: CONCAT210(sVar165,Var86)) >> 0x50,0),
412: CONCAT28(sVar141,uVar84)) >> 0x40,0),sVar163),
413: (uVar133 >> 0x10) << 0x20) >> 0x20,0),
414: CONCAT22(sVar157,sVar135)),_DAT_0019c980);
415: auVar139 = pmaddwd(CONCAT214(sVar175,CONCAT212(sVar153,CONCAT210(sVar173,CONCAT28(sVar150,
416: CONCAT26(sVar171,CONCAT24(sVar148,CONCAT22(sVar169
417: ,sVar145))))))),_DAT_0019c980);
418: auVar111 = pmaddwd(CONCAT124(SUB1612(CONCAT106(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
419: (CONCAT214(sVar52,CONCAT212(sVar120,CONCAT210(
420: sVar125,Var41))) >> 0x60,0),
421: CONCAT210(sVar50,Var41)) >> 0x50,0),
422: CONCAT28(sVar119,uVar39)) >> 0x40,0),sVar47),
423: (uVar77 >> 0x10) << 0x20) >> 0x20,0),
424: CONCAT22(sVar34,sVar101)),_DAT_0019c980);
425: auVar162 = pmaddwd(CONCAT214(sVar62,CONCAT212(sVar129,CONCAT210(sVar60,CONCAT28(sVar127,CONCAT26
426: (sVar58,CONCAT24(sVar125,CONCAT22(sVar55,sVar122))
427: ))))),_DAT_0019c980);
428: auVar160 = packssdw(CONCAT412(SUB164(auVar160 >> 0x60,0) + 0x8000 >> 0x10,
429: CONCAT48(SUB164(auVar160 >> 0x40,0) + 0x8000 >> 0x10,
430: CONCAT44(SUB164(auVar160 >> 0x20,0) + 0x8000 >> 0x10,
431: SUB164(auVar160,0) + 0x8000 >> 0x10))),
432: CONCAT412(SUB164(auVar139 >> 0x60,0) + 0x8000 >> 0x10,
433: CONCAT48(SUB164(auVar139 >> 0x40,0) + 0x8000 >> 0x10,
434: CONCAT44(SUB164(auVar139 >> 0x20,0) + 0x8000 >> 0x10,
435: SUB164(auVar139,0) + 0x8000 >> 0x10))));
436: auVar111 = packssdw(CONCAT412(SUB164(auVar111 >> 0x60,0) + 0x8000 >> 0x10,
437: CONCAT48(SUB164(auVar111 >> 0x40,0) + 0x8000 >> 0x10,
438: CONCAT44(SUB164(auVar111 >> 0x20,0) + 0x8000 >> 0x10,
439: SUB164(auVar111,0) + 0x8000 >> 0x10))),
440: CONCAT412(SUB164(auVar162 >> 0x60,0) + 0x8000 >> 0x10,
441: CONCAT48(SUB164(auVar162 >> 0x40,0) + 0x8000 >> 0x10,
442: CONCAT44(SUB164(auVar162 >> 0x20,0) + 0x8000 >> 0x10,
443: SUB164(auVar162,0) + 0x8000 >> 0x10))));
444: cVar28 = '\x02';
445: sVar65 = SUB162(auVar44,0) + sVar34;
446: sVar68 = SUB162(auVar44 >> 0x10,0) + sVar47;
447: sVar69 = SUB162(auVar44 >> 0x20,0) + sVar50;
448: sVar70 = SUB162(auVar44 >> 0x30,0) + sVar52;
449: sVar71 = SUB162(auVar44 >> 0x40,0) + sVar55;
450: sVar72 = SUB162(auVar44 >> 0x50,0) + sVar58;
451: sVar73 = SUB162(auVar44 >> 0x60,0) + sVar60;
452: sVar74 = SUB162(auVar44 >> 0x70,0) + sVar62;
453: sVar34 = SUB162(auVar111,0) - sVar34;
454: sVar47 = SUB162(auVar111 >> 0x10,0) - sVar47;
455: sVar50 = SUB162(auVar111 >> 0x20,0) - sVar50;
456: sVar52 = SUB162(auVar111 >> 0x30,0) - sVar52;
457: sVar55 = SUB162(auVar111 >> 0x40,0) - sVar55;
458: sVar58 = SUB162(auVar111 >> 0x50,0) - sVar58;
459: sVar60 = SUB162(auVar111 >> 0x60,0) - sVar60;
460: sVar62 = SUB162(auVar111 >> 0x70,0) - sVar62;
461: sVar101 = SUB162(auVar90,0) + sVar101 + sVar101;
462: sVar118 = SUB162(auVar90 >> 0x10,0) + sVar118 + sVar118;
463: sVar119 = SUB162(auVar90 >> 0x20,0) + sVar119 + sVar119;
464: sVar120 = SUB162(auVar90 >> 0x30,0) + sVar120 + sVar120;
465: sVar122 = SUB162(auVar90 >> 0x40,0) + sVar122 + sVar122;
466: sVar125 = SUB162(auVar90 >> 0x50,0) + sVar125 + sVar125;
467: sVar127 = SUB162(auVar90 >> 0x60,0) + sVar127 + sVar127;
468: sVar129 = SUB162(auVar90 >> 0x70,0) + sVar129 + sVar129;
469: do {
470: uVar134 = *puVar32 & 0xff;
471: uVar156 = puVar32[1] & 0xff;
472: uVar142 = puVar32[2] & 0xff;
473: uVar144 = puVar32[3] & 0xff;
474: uVar146 = puVar32[4] & 0xff;
475: uVar149 = puVar32[5] & 0xff;
476: uVar151 = puVar32[6] & 0xff;
477: uVar154 = puVar32[7] & 0xff;
478: uVar158 = *puVar32 >> 8;
479: uVar164 = puVar32[1] >> 8;
480: uVar166 = puVar32[2] >> 8;
481: uVar168 = puVar32[3] >> 8;
482: uVar170 = puVar32[4] >> 8;
483: uVar172 = puVar32[5] >> 8;
484: uVar174 = puVar32[6] >> 8;
485: uVar176 = puVar32[7] >> 8;
486: sVar35 = sVar65 + uVar134;
487: sVar48 = sVar68 + uVar156;
488: sVar51 = sVar69 + uVar142;
489: sVar53 = sVar70 + uVar144;
490: sVar56 = sVar71 + uVar146;
491: sVar59 = sVar72 + uVar149;
492: sVar61 = sVar73 + uVar151;
493: sVar63 = sVar74 + uVar154;
494: sVar65 = sVar65 + uVar158;
495: sVar68 = sVar68 + uVar164;
496: sVar69 = sVar69 + uVar166;
497: sVar70 = sVar70 + uVar168;
498: sVar71 = sVar71 + uVar170;
499: sVar72 = sVar72 + uVar172;
500: sVar73 = sVar73 + uVar174;
501: sVar74 = sVar74 + uVar176;
502: cVar1 = (0 < sVar35) * (sVar35 < 0xff) * (char)sVar35 - (0xff < sVar35);
503: uVar36 = CONCAT12((0 < sVar51) * (sVar51 < 0xff) * (char)sVar51 - (0xff < sVar51),
504: CONCAT11((0 < sVar48) * (sVar48 < 0xff) * (char)sVar48 - (0xff < sVar48),
505: cVar1));
506: cVar2 = (0 < sVar56) * (sVar56 < 0xff) * (char)sVar56 - (0xff < sVar56);
507: uVar37 = CONCAT14(cVar2,CONCAT13((0 < sVar53) * (sVar53 < 0xff) * (char)sVar53 -
508: (0xff < sVar53),uVar36));
509: cVar3 = (0 < sVar59) * (sVar59 < 0xff) * (char)sVar59 - (0xff < sVar59);
510: cVar4 = (0 < sVar61) * (sVar61 < 0xff) * (char)sVar61 - (0xff < sVar61);
511: uVar38 = CONCAT16(cVar4,CONCAT15(cVar3,uVar37));
512: cVar5 = (0 < sVar63) * (sVar63 < 0xff) * (char)sVar63 - (0xff < sVar63);
513: uVar39 = CONCAT17(cVar5,uVar38);
514: Var40 = CONCAT18((0 < sVar35) * (sVar35 < 0xff) * (char)sVar35 - (0xff < sVar35),uVar39);
515: Var41 = CONCAT19((0 < sVar48) * (sVar48 < 0xff) * (char)sVar48 - (0xff < sVar48),Var40);
516: auVar42 = CONCAT110((0 < sVar51) * (sVar51 < 0xff) * (char)sVar51 - (0xff < sVar51),Var41);
517: auVar43 = CONCAT111((0 < sVar53) * (sVar53 < 0xff) * (char)sVar53 - (0xff < sVar53),auVar42);
518: auVar49 = CONCAT112((0 < sVar56) * (sVar56 < 0xff) * (char)sVar56 - (0xff < sVar56),auVar43);
519: cVar6 = (0 < sVar65) * (sVar65 < 0xff) * (char)sVar65 - (0xff < sVar65);
520: uVar66 = CONCAT12((0 < sVar69) * (sVar69 < 0xff) * (char)sVar69 - (0xff < sVar69),
521: CONCAT11((0 < sVar68) * (sVar68 < 0xff) * (char)sVar68 - (0xff < sVar68),
522: cVar6));
523: cVar7 = (0 < sVar71) * (sVar71 < 0xff) * (char)sVar71 - (0xff < sVar71);
524: uVar67 = CONCAT14(cVar7,CONCAT13((0 < sVar70) * (sVar70 < 0xff) * (char)sVar70 -
525: (0xff < sVar70),uVar66));
526: cVar8 = (0 < sVar72) * (sVar72 < 0xff) * (char)sVar72 - (0xff < sVar72);
527: cVar9 = (0 < sVar73) * (sVar73 < 0xff) * (char)sVar73 - (0xff < sVar73);
528: sVar65 = sVar34 + uVar134;
529: sVar68 = sVar47 + uVar156;
530: sVar69 = sVar50 + uVar142;
531: sVar70 = sVar52 + uVar144;
532: sVar71 = sVar55 + uVar146;
533: sVar72 = sVar58 + uVar149;
534: sVar73 = sVar60 + uVar151;
535: sVar35 = sVar62 + uVar154;
536: sVar34 = sVar34 + uVar158;
537: sVar47 = sVar47 + uVar164;
538: sVar50 = sVar50 + uVar166;
539: sVar52 = sVar52 + uVar168;
540: sVar55 = sVar55 + uVar170;
541: sVar58 = sVar58 + uVar172;
542: sVar60 = sVar60 + uVar174;
543: sVar62 = sVar62 + uVar176;
544: cVar10 = (0 < sVar65) * (sVar65 < 0xff) * (char)sVar65 - (0xff < sVar65);
545: uVar75 = CONCAT12((0 < sVar69) * (sVar69 < 0xff) * (char)sVar69 - (0xff < sVar69),
546: CONCAT11((0 < sVar68) * (sVar68 < 0xff) * (char)sVar68 - (0xff < sVar68),
547: cVar10));
548: cVar11 = (0 < sVar71) * (sVar71 < 0xff) * (char)sVar71 - (0xff < sVar71);
549: uVar76 = CONCAT14(cVar11,CONCAT13((0 < sVar70) * (sVar70 < 0xff) * (char)sVar70 -
550: (0xff < sVar70),uVar75));
551: cVar12 = (0 < sVar72) * (sVar72 < 0xff) * (char)sVar72 - (0xff < sVar72);
552: cVar13 = (0 < sVar73) * (sVar73 < 0xff) * (char)sVar73 - (0xff < sVar73);
553: cVar14 = (0 < sVar34) * (sVar34 < 0xff) * (char)sVar34 - (0xff < sVar34);
554: uVar81 = CONCAT12((0 < sVar50) * (sVar50 < 0xff) * (char)sVar50 - (0xff < sVar50),
555: CONCAT11((0 < sVar47) * (sVar47 < 0xff) * (char)sVar47 - (0xff < sVar47),
556: cVar14));
557: cVar15 = (0 < sVar55) * (sVar55 < 0xff) * (char)sVar55 - (0xff < sVar55);
558: uVar82 = CONCAT14(cVar15,CONCAT13((0 < sVar52) * (sVar52 < 0xff) * (char)sVar52 -
559: (0xff < sVar52),uVar81));
560: cVar16 = (0 < sVar58) * (sVar58 < 0xff) * (char)sVar58 - (0xff < sVar58);
561: cVar17 = (0 < sVar60) * (sVar60 < 0xff) * (char)sVar60 - (0xff < sVar60);
562: uVar83 = CONCAT16(cVar17,CONCAT15(cVar16,uVar82));
563: cVar18 = (0 < sVar62) * (sVar62 < 0xff) * (char)sVar62 - (0xff < sVar62);
564: uVar84 = CONCAT17(cVar18,uVar83);
565: Var85 = CONCAT18((0 < sVar34) * (sVar34 < 0xff) * (char)sVar34 - (0xff < sVar34),uVar84);
566: Var86 = CONCAT19((0 < sVar47) * (sVar47 < 0xff) * (char)sVar47 - (0xff < sVar47),Var85);
567: auVar87 = CONCAT110((0 < sVar50) * (sVar50 < 0xff) * (char)sVar50 - (0xff < sVar50),Var86);
568: auVar88 = CONCAT111((0 < sVar52) * (sVar52 < 0xff) * (char)sVar52 - (0xff < sVar52),auVar87);
569: auVar89 = CONCAT112((0 < sVar55) * (sVar55 < 0xff) * (char)sVar55 - (0xff < sVar55),auVar88);
570: sVar65 = sVar101 + uVar134;
571: sVar68 = sVar118 + uVar156;
572: sVar69 = sVar119 + uVar142;
573: sVar70 = sVar120 + uVar144;
574: sVar71 = sVar122 + uVar146;
575: sVar72 = sVar125 + uVar149;
576: sVar73 = sVar127 + uVar151;
577: sVar34 = sVar129 + uVar154;
578: sVar101 = sVar101 + uVar158;
579: sVar118 = sVar118 + uVar164;
580: sVar119 = sVar119 + uVar166;
581: sVar120 = sVar120 + uVar168;
582: sVar122 = sVar122 + uVar170;
583: sVar125 = sVar125 + uVar172;
584: sVar127 = sVar127 + uVar174;
585: sVar129 = sVar129 + uVar176;
586: cVar19 = (0 < sVar65) * (sVar65 < 0xff) * (char)sVar65 - (0xff < sVar65);
587: uVar102 = CONCAT12((0 < sVar69) * (sVar69 < 0xff) * (char)sVar69 - (0xff < sVar69),
588: CONCAT11((0 < sVar68) * (sVar68 < 0xff) * (char)sVar68 - (0xff < sVar68),
589: cVar19));
590: cVar20 = (0 < sVar71) * (sVar71 < 0xff) * (char)sVar71 - (0xff < sVar71);
591: uVar103 = CONCAT14(cVar20,CONCAT13((0 < sVar70) * (sVar70 < 0xff) * (char)sVar70 -
592: (0xff < sVar70),uVar102));
593: cVar21 = (0 < sVar72) * (sVar72 < 0xff) * (char)sVar72 - (0xff < sVar72);
594: cVar22 = (0 < sVar73) * (sVar73 < 0xff) * (char)sVar73 - (0xff < sVar73);
595: uVar104 = CONCAT16(cVar22,CONCAT15(cVar21,uVar103));
596: cVar23 = (0 < sVar34) * (sVar34 < 0xff) * (char)sVar34 - (0xff < sVar34);
597: uVar105 = CONCAT17(cVar23,uVar104);
598: Var106 = CONCAT18((0 < sVar65) * (sVar65 < 0xff) * (char)sVar65 - (0xff < sVar65),uVar105);
599: Var107 = CONCAT19((0 < sVar68) * (sVar68 < 0xff) * (char)sVar68 - (0xff < sVar68),Var106);
600: auVar108 = CONCAT110((0 < sVar69) * (sVar69 < 0xff) * (char)sVar69 - (0xff < sVar69),Var107);
601: auVar109 = CONCAT111((0 < sVar70) * (sVar70 < 0xff) * (char)sVar70 - (0xff < sVar70),auVar108)
602: ;
603: auVar110 = CONCAT112((0 < sVar71) * (sVar71 < 0xff) * (char)sVar71 - (0xff < sVar71),auVar109)
604: ;
605: cVar24 = (0 < sVar101) * (sVar101 < 0xff) * (char)sVar101 - (0xff < sVar101);
606: uVar131 = CONCAT12((0 < sVar119) * (sVar119 < 0xff) * (char)sVar119 - (0xff < sVar119),
607: CONCAT11((0 < sVar118) * (sVar118 < 0xff) * (char)sVar118 -
608: (0xff < sVar118),cVar24));
609: cVar25 = (0 < sVar122) * (sVar122 < 0xff) * (char)sVar122 - (0xff < sVar122);
610: uVar132 = CONCAT14(cVar25,CONCAT13((0 < sVar120) * (sVar120 < 0xff) * (char)sVar120 -
611: (0xff < sVar120),uVar131));
612: cVar26 = (0 < sVar125) * (sVar125 < 0xff) * (char)sVar125 - (0xff < sVar125);
613: cVar27 = (0 < sVar127) * (sVar127 < 0xff) * (char)sVar127 - (0xff < sVar127);
614: uVar64 = SUB162(CONCAT115((0 < sVar35) * (sVar35 < 0xff) * (char)sVar35 - (0xff < sVar35),
615: CONCAT114(cVar5,CONCAT113((0 < sVar59) * (sVar59 < 0xff) *
616: (char)sVar59 - (0xff < sVar59),auVar49)))
617: >> 0x70,0);
618: auVar46 = CONCAT313(SUB163(CONCAT214(uVar64,CONCAT113(cVar13,auVar49)) >> 0x68,0),
619: CONCAT112(cVar4,auVar43));
620: auVar45 = CONCAT511(SUB165(CONCAT412(SUB164(auVar46 >> 0x60,0),CONCAT111(cVar12,auVar42)) >>
621: 0x58,0),CONCAT110(cVar3,Var41));
622: auVar162 = CONCAT79(SUB167(CONCAT610(SUB166(auVar45 >> 0x50,0),CONCAT19(cVar11,Var40)) >> 0x48
623: ,0),CONCAT18(cVar2,uVar39));
624: auVar139 = CONCAT97(SUB169(CONCAT88(SUB168(auVar162 >> 0x40,0),
625: (((ulong)CONCAT16(cVar13,CONCAT15(cVar12,uVar76)) &
626: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
627: (uVar38 >> 0x18) << 0x30);
628: auVar90 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar139 >> 0x30,0),
629: (((uint6)uVar76 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0)
630: ,(uVar37 >> 0x10) << 0x20);
631: auVar111 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar90 >> 0x20,0),
632: ((uVar75 & 0xff00) >> 8) << 0x18) >> 0x18,0),
633: (uVar36 >> 8) << 0x10);
634: auVar44 = CONCAT142(SUB1614(auVar111 >> 0x10,0),CONCAT11(cVar10,cVar1));
635: uVar130 = SUB162(CONCAT115((0 < sVar74) * (sVar74 < 0xff) * (char)sVar74 - (0xff < sVar74),
636: CONCAT114(cVar23,CONCAT113((0 < sVar72) * (sVar72 < 0xff) *
637: (char)sVar72 - (0xff < sVar72),auVar110)
638: )) >> 0x70,0);
639: auVar117 = CONCAT313(SUB163(CONCAT214(uVar130,CONCAT113(cVar9,auVar110)) >> 0x68,0),
640: CONCAT112(cVar22,auVar109));
641: auVar116 = CONCAT511(SUB165(CONCAT412(SUB164(auVar117 >> 0x60,0),CONCAT111(cVar8,auVar108)) >>
642: 0x58,0),CONCAT110(cVar21,Var107));
643: auVar115 = CONCAT79(SUB167(CONCAT610(SUB166(auVar116 >> 0x50,0),CONCAT19(cVar7,Var106)) >>
644: 0x48,0),CONCAT18(cVar20,uVar105));
645: auVar114 = CONCAT97(SUB169(CONCAT88(SUB168(auVar115 >> 0x40,0),
646: (((ulong)CONCAT16(cVar9,CONCAT15(cVar8,uVar67)) &
647: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
648: (uVar104 >> 0x18) << 0x30);
649: auVar113 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar114 >> 0x30,0),
650: (((uint6)uVar67 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0
651: ),(uVar103 >> 0x10) << 0x20);
652: auVar112 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar113 >> 0x20,0),
653: ((uVar66 & 0xff00) >> 8) << 0x18) >> 0x18,0),
654: (uVar102 >> 8) << 0x10);
655: uVar100 = SUB162(CONCAT115((0 < sVar129) * (sVar129 < 0xff) * (char)sVar129 - (0xff < sVar129)
656: ,CONCAT114(cVar18,CONCAT113((0 < sVar58) * (sVar58 < 0xff) *
657: (char)sVar58 - (0xff < sVar58),auVar89)
658: )) >> 0x70,0);
659: auVar97 = CONCAT313(SUB163(CONCAT214(uVar100,CONCAT113(cVar27,auVar89)) >> 0x68,0),
660: CONCAT112(cVar17,auVar88));
661: auVar96 = CONCAT511(SUB165(CONCAT412(SUB164(auVar97 >> 0x60,0),CONCAT111(cVar26,auVar87)) >>
662: 0x58,0),CONCAT110(cVar16,Var86));
663: auVar95 = CONCAT79(SUB167(CONCAT610(SUB166(auVar96 >> 0x50,0),CONCAT19(cVar25,Var85)) >> 0x48,
664: 0),CONCAT18(cVar15,uVar84));
665: auVar94 = CONCAT97(SUB169(CONCAT88(SUB168(auVar95 >> 0x40,0),
666: (((ulong)CONCAT16(cVar27,CONCAT15(cVar26,uVar132)) &
667: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
668: (uVar83 >> 0x18) << 0x30);
669: auVar93 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar94 >> 0x30,0),
670: (((uint6)uVar132 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0
671: ),(uVar82 >> 0x10) << 0x20);
672: auVar92 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar93 >> 0x20,0),
673: ((uVar131 & 0xff00) >> 8) << 0x18) >> 0x18,0),
674: (uVar81 >> 8) << 0x10);
675: auVar91 = CONCAT142(SUB1614(auVar92 >> 0x10,0),CONCAT11(cVar24,cVar14));
676: uVar121 = SUB162(auVar114 >> 0x30,0);
677: uVar54 = SUB162(auVar139 >> 0x30,0);
678: lVar57 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar121,CONCAT212(uVar54,SUB1612(
679: auVar44,0))) >> 0x60,0),
680: CONCAT210(SUB162(auVar113 >> 0x20,0),
681: SUB1610(auVar44,0))) >> 0x50,0),
682: CONCAT28(SUB162(auVar90 >> 0x20,0),SUB168(auVar44,0))) >> 0x40,0);
683: uVar147 = SUB162(auVar162 >> 0x40,0);
684: uVar123 = SUB162(auVar115 >> 0x40,0);
685: uVar80 = SUB162(auVar45 >> 0x50,0);
686: uVar136 = CONCAT24(uVar80,CONCAT22(uVar123,uVar147));
687: uVar126 = SUB162(auVar116 >> 0x50,0);
688: uVar152 = SUB162(auVar46 >> 0x60,0);
689: uVar128 = SUB162(auVar117 >> 0x60,0);
690: uVar99 = SUB162(auVar94 >> 0x30,0);
691: uVar98 = SUB162(auVar93 >> 0x20,0);
692: uVar78 = SUB162(auVar95 >> 0x40,0);
693: uVar79 = SUB162(auVar96 >> 0x50,0);
694: uVar77 = CONCAT24(uVar79,CONCAT22(uVar80,uVar78));
695: uVar80 = SUB162(auVar97 >> 0x60,0);
696: lVar124 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar78,CONCAT212(uVar123,SUB1612(
697: auVar112 >> 0x10,0))) >> 0x60,0),
698: CONCAT210(uVar99,SUB1610(auVar112 >> 0x10,0))) >>
699: 0x50,0),CONCAT28(uVar121,SUB168(auVar112 >> 0x10,0))) >>
700: 0x40,0);
701: uVar133 = CONCAT24(uVar128,CONCAT22(uVar79,uVar126));
702: auVar44 = CONCAT88(SUB168(CONCAT124(SUB1612((ZEXT1016(CONCAT82(lVar124,uVar98)) << 0x30) >>
703: 0x20,0),
704: SUB164(auVar112 >> 0x10,0) & 0xffff |
705: (uint)SUB162(auVar92 >> 0x10,0) << 0x10),0) & 0xffffffff |
706: lVar57 << 0x20,
707: SUB168(CONCAT124(SUB1612((ZEXT1016(CONCAT82(lVar57,SUB162(auVar112 >> 0x10,
708: 0))) << 0x30) >>
709: 0x20,0),
710: SUB164(auVar44,0) & 0xffff |
711: (uint)CONCAT11(cVar6,cVar19) << 0x10),0) & 0xffffffff |
712: (ulong)(SUB164(auVar91,0) & 0xffff |
713: (uint)SUB162(auVar111 >> 0x10,0) << 0x10) << 0x20);
714: auVar111 = CONCAT88((ulong)uVar136 & 0xffffffff | (ulong)uVar77 << 0x20,
715: SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar147,CONCAT212(
716: uVar99,SUB1612(auVar91,0))) >> 0x60,0),
717: CONCAT210(uVar54,SUB1610(auVar91,0))) >> 0x50,0),
718: CONCAT28(uVar98,SUB168(auVar91,0))) >> 0x40,0) &
719: 0xffffffff | lVar124 << 0x20);
720: auVar90 = CONCAT88(CONCAT44(SUB144(ZEXT1214(CONCAT210(uVar100,CONCAT28(uVar130,CONCAT26(uVar80
721: ,uVar133)))) >> 0x40,0),
722: SUB124(CONCAT210(uVar64,CONCAT28(uVar80,CONCAT26(uVar152,uVar77)))
723: >> 0x40,0)),
724: (ulong)uVar133 & 0xffffffff |
725: SUB168(CONCAT214(uVar130,CONCAT212(uVar64,CONCAT210(uVar128,CONCAT28(
726: uVar152,CONCAT26(uVar126,uVar136))))) >> 0x40,0)
727: << 0x20);
728: if (param_1 < 0x10) {
729: param_1 = param_1 * 3;
730: if (param_1 < 0x20) {
731: if (0xf < param_1) {
732: *pauVar33 = auVar44;
733: pauVar33 = pauVar33[1];
734: param_1 = param_1 - 0x10;
735: auVar44 = auVar111;
736: }
737: }
738: else {
739: *pauVar33 = auVar44;
740: pauVar33[1] = auVar111;
741: pauVar33 = pauVar33[2];
742: param_1 = param_1 - 0x20;
743: auVar44 = auVar90;
744: }
745: if (7 < param_1) {
746: *(long *)*pauVar33 = SUB168(auVar44,0);
747: pauVar33 = (undefined (*) [16])(*pauVar33 + 8);
748: param_1 = param_1 - 8;
749: auVar44 = auVar44 >> 0x40;
750: }
751: if (3 < param_1) {
752: *(int *)*pauVar33 = SUB164(auVar44,0);
753: pauVar33 = (undefined (*) [16])(*pauVar33 + 4);
754: param_1 = param_1 - 4;
755: auVar44 = auVar44 >> 0x20;
756: }
757: uVar29 = SUB164(auVar44,0);
758: if (1 < param_1) {
759: *(short *)*pauVar33 = SUB162(auVar44,0);
760: pauVar33 = (undefined (*) [16])(*pauVar33 + 2);
761: param_1 = param_1 - 2;
762: uVar29 = uVar29 >> 0x10;
763: }
764: if (param_1 == 0) {
765: return;
766: }
767: (*pauVar33)[0] = (char)uVar29;
768: return;
769: }
770: if (((ulong)pauVar33 & 0xf) == 0) {
771: *pauVar33 = auVar44;
772: pauVar33[1] = auVar111;
773: pauVar33[2] = auVar90;
774: }
775: else {
776: *pauVar33 = auVar44;
777: pauVar33[1] = auVar111;
778: pauVar33[2] = auVar90;
779: }
780: pauVar33 = pauVar33[3];
781: param_1 = param_1 - 0x10;
782: if (param_1 == 0) {
783: return;
784: }
785: puVar32 = puVar32 + 8;
786: cVar28 = cVar28 + -1;
787: sVar65 = SUB162(auVar161,0) + sVar157;
788: sVar68 = SUB162(auVar161 >> 0x10,0) + sVar163;
789: sVar69 = SUB162(auVar161 >> 0x20,0) + sVar165;
790: sVar70 = SUB162(auVar161 >> 0x30,0) + sVar167;
791: sVar71 = SUB162(auVar161 >> 0x40,0) + sVar169;
792: sVar72 = SUB162(auVar161 >> 0x50,0) + sVar171;
793: sVar73 = SUB162(auVar161 >> 0x60,0) + sVar173;
794: sVar74 = SUB162(auVar161 >> 0x70,0) + sVar175;
795: sVar34 = SUB162(auVar160,0) - sVar157;
796: sVar47 = SUB162(auVar160 >> 0x10,0) - sVar163;
797: sVar50 = SUB162(auVar160 >> 0x20,0) - sVar165;
798: sVar52 = SUB162(auVar160 >> 0x30,0) - sVar167;
799: sVar55 = SUB162(auVar160 >> 0x40,0) - sVar169;
800: sVar58 = SUB162(auVar160 >> 0x50,0) - sVar171;
801: sVar60 = SUB162(auVar160 >> 0x60,0) - sVar173;
802: sVar62 = SUB162(auVar160 >> 0x70,0) - sVar175;
803: sVar101 = SUB162(auVar138,0) + sVar135 + sVar135;
804: sVar118 = SUB162(auVar138 >> 0x10,0) + sVar140 + sVar140;
805: sVar119 = SUB162(auVar138 >> 0x20,0) + sVar141 + sVar141;
806: sVar120 = SUB162(auVar138 >> 0x30,0) + sVar143 + sVar143;
807: sVar122 = SUB162(auVar138 >> 0x40,0) + sVar145 + sVar145;
808: sVar125 = SUB162(auVar138 >> 0x50,0) + sVar148 + sVar148;
809: sVar127 = SUB162(auVar138 >> 0x60,0) + sVar150 + sVar150;
810: sVar129 = SUB162(auVar138 >> 0x70,0) + sVar153 + sVar153;
811: } while (cVar28 != '\0');
812: pauVar31 = pauVar31[1];
813: pauVar30 = pauVar30[1];
814: } while( true );
815: }
816: 

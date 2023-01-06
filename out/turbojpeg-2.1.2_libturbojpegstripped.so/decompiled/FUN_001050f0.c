1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_001050f0(long param_1,long *param_2,long *param_3,uint param_4,int param_5)
5: 
6: {
7: uint uVar1;
8: char *pcVar2;
9: undefined *puVar3;
10: uint uVar4;
11: ulong uVar5;
12: undefined *puVar6;
13: long lVar7;
14: char cVar8;
15: char cVar16;
16: short sVar24;
17: short sVar25;
18: short sVar26;
19: short sVar27;
20: short sVar28;
21: short sVar29;
22: short sVar30;
23: short sVar31;
24: short sVar32;
25: short sVar33;
26: short sVar34;
27: short sVar35;
28: short sVar36;
29: short sVar37;
30: short sVar38;
31: short sVar39;
32: short sVar40;
33: short sVar41;
34: short sVar42;
35: short sVar43;
36: short sVar44;
37: short sVar45;
38: short sVar46;
39: short sVar47;
40: short sVar48;
41: short sVar49;
42: short sVar50;
43: short sVar51;
44: short sVar52;
45: short sVar53;
46: short sVar54;
47: short sVar55;
48: undefined auVar56 [16];
49: long lVar57;
50: undefined *puVar58;
51: undefined *puVar59;
52: undefined *puVar60;
53: ulong uVar61;
54: ulong uVar62;
55: ulong uVar63;
56: ulong uVar64;
57: long *plVar65;
58: long lVar66;
59: ulong uVar67;
60: long lVar68;
61: ulong uVar69;
62: uint uVar70;
63: ushort uVar71;
64: ushort uVar73;
65: ushort uVar74;
66: ushort uVar75;
67: ushort uVar76;
68: ushort uVar77;
69: ushort uVar78;
70: ushort uVar79;
71: undefined auVar72 [16];
72: undefined4 uVar80;
73: undefined auVar86 [16];
74: ushort uVar87;
75: ushort uVar89;
76: ushort uVar90;
77: ushort uVar91;
78: ushort uVar92;
79: ushort uVar93;
80: ushort uVar94;
81: ushort uVar95;
82: undefined auVar88 [16];
83: undefined4 uVar96;
84: undefined auVar102 [16];
85: ushort uVar103;
86: ushort uVar104;
87: ushort uVar105;
88: ushort uVar106;
89: ushort uVar107;
90: ushort uVar108;
91: ushort uVar109;
92: ushort uVar110;
93: ushort uVar111;
94: ushort uVar112;
95: ushort uVar113;
96: ushort uVar114;
97: ushort uVar115;
98: ushort uVar116;
99: ushort uVar117;
100: ushort uVar118;
101: undefined auVar119 [16];
102: undefined auVar120 [16];
103: undefined auVar121 [16];
104: char cVar9;
105: char cVar10;
106: char cVar11;
107: char cVar12;
108: char cVar13;
109: char cVar14;
110: char cVar15;
111: char cVar17;
112: char cVar18;
113: char cVar19;
114: char cVar20;
115: char cVar21;
116: char cVar22;
117: char cVar23;
118: undefined6 uVar81;
119: undefined8 uVar82;
120: unkbyte10 Var83;
121: undefined auVar84 [12];
122: undefined auVar85 [14];
123: undefined6 uVar97;
124: undefined8 uVar98;
125: unkbyte10 Var99;
126: undefined auVar100 [12];
127: undefined auVar101 [14];
128: 
129: auVar56 = _DAT_0016c610;
130: uVar64 = (ulong)param_4;
131: uVar4 = *(uint *)(param_1 + 0x30);
132: switch(*(undefined4 *)(param_1 + 0x3c)) {
133: case 6:
134: while (param_5 = param_5 + -1, plVar65 = param_2, uVar61 = uVar64, -1 < param_5) {
135: while( true ) {
136: param_2 = plVar65 + 1;
137: uVar64 = (ulong)((int)uVar61 + 1);
138: puVar59 = (undefined *)*plVar65;
139: lVar57 = *(long *)(*param_3 + uVar61 * 8);
140: lVar68 = *(long *)(param_3[1] + uVar61 * 8);
141: lVar7 = *(long *)(param_3[2] + uVar61 * 8);
142: if (uVar4 == 0) break;
143: lVar66 = 0;
144: puVar58 = puVar59;
145: do {
146: puVar60 = puVar58 + 3;
147: *(undefined *)(lVar57 + lVar66) = *puVar58;
148: *(undefined *)(lVar68 + lVar66) = puVar58[1];
149: *(undefined *)(lVar7 + lVar66) = puVar58[2];
150: lVar66 = lVar66 + 1;
151: puVar58 = puVar60;
152: } while (puVar60 != puVar59 + (ulong)(uVar4 - 1) * 3 + 3);
153: param_5 = param_5 + -1;
154: plVar65 = param_2;
155: uVar61 = uVar64;
156: if (param_5 < 0) {
157: return;
158: }
159: }
160: }
161: break;
162: case 7:
163: case 0xc:
164: uVar61 = (ulong)uVar4;
165: uVar1 = uVar4 - 1;
166: while (param_5 = param_5 + -1, -1 < param_5) {
167: plVar65 = param_2 + 1;
168: uVar63 = (ulong)((int)uVar64 + 1);
169: puVar59 = (undefined *)*param_2;
170: puVar58 = *(undefined **)(*param_3 + uVar64 * 8);
171: puVar60 = *(undefined **)(param_3[1] + uVar64 * 8);
172: puVar6 = *(undefined **)(param_3[2] + uVar64 * 8);
173: uVar64 = uVar63;
174: param_2 = plVar65;
175: if (uVar4 != 0) {
176: puVar3 = puVar59 + uVar61 * 4;
177: if ((((((puVar59 < puVar60 + uVar61 && puVar60 < puVar3 ||
178: puVar59 < puVar58 + uVar61 && puVar58 < puVar3) || uVar4 < 0x10) ||
179: puVar59 < puVar6 + uVar61 && puVar6 < puVar3) ||
180: puVar58 < puVar60 + 0x10 && puVar60 < puVar58 + 0x10) ||
181: puVar58 < puVar6 + 0x10 && puVar6 < puVar58 + 0x10) ||
182: (puVar60 < puVar6 + 0x10 && puVar6 < puVar60 + 0x10)) {
183: lVar57 = 0;
184: do {
185: puVar58[lVar57] = puVar59[lVar57 * 4];
186: puVar60[lVar57] = puVar59[lVar57 * 4 + 1];
187: puVar6[lVar57] = puVar59[lVar57 * 4 + 2];
188: lVar57 = lVar57 + 1;
189: } while (lVar57 != (ulong)uVar1 + 1);
190: }
191: else {
192: if (uVar1 < 0x10) {
193: uVar70 = 0;
194: }
195: else {
196: lVar57 = 0;
197: uVar70 = 0;
198: do {
199: auVar72 = *(undefined (*) [16])(puVar59 + lVar57 * 4);
200: uVar70 = uVar70 + 1;
201: auVar88 = *(undefined (*) [16])(puVar59 + lVar57 * 4 + 0x10);
202: auVar86 = auVar56 & auVar72;
203: uVar71 = SUB162(auVar72,0) >> 8;
204: uVar73 = SUB162(auVar72 >> 0x10,0) >> 8;
205: uVar74 = SUB162(auVar72 >> 0x20,0) >> 8;
206: uVar75 = SUB162(auVar72 >> 0x30,0) >> 8;
207: uVar76 = SUB162(auVar72 >> 0x40,0) >> 8;
208: uVar77 = SUB162(auVar72 >> 0x50,0) >> 8;
209: uVar78 = SUB162(auVar72 >> 0x60,0) >> 8;
210: uVar79 = SUB162(auVar72 >> 0x78,0);
211: auVar102 = auVar56 & auVar88;
212: uVar111 = SUB162(auVar88,0) >> 8;
213: uVar112 = SUB162(auVar88 >> 0x10,0) >> 8;
214: uVar113 = SUB162(auVar88 >> 0x20,0) >> 8;
215: uVar114 = SUB162(auVar88 >> 0x30,0) >> 8;
216: uVar115 = SUB162(auVar88 >> 0x40,0) >> 8;
217: uVar116 = SUB162(auVar88 >> 0x50,0) >> 8;
218: uVar117 = SUB162(auVar88 >> 0x60,0) >> 8;
219: uVar118 = SUB162(auVar88 >> 0x78,0);
220: auVar120 = *(undefined (*) [16])(puVar59 + lVar57 * 4 + 0x20);
221: auVar121 = *(undefined (*) [16])(puVar59 + lVar57 * 4 + 0x30);
222: sVar24 = SUB162(auVar86,0);
223: sVar25 = SUB162(auVar86 >> 0x10,0);
224: cVar8 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x10,0) - (0xff < sVar25);
225: sVar25 = SUB162(auVar86 >> 0x20,0);
226: sVar29 = SUB162(auVar86 >> 0x30,0);
227: cVar9 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar86 >> 0x30,0) - (0xff < sVar29);
228: uVar80 = CONCAT13(cVar9,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
229: SUB161(auVar86 >> 0x20,0) - (0xff < sVar25),
230: CONCAT11(cVar8,(0 < sVar24) * (sVar24 < 0xff) *
231: SUB161(auVar86,0) - (0xff < sVar24))))
232: ;
233: sVar24 = SUB162(auVar86 >> 0x40,0);
234: sVar25 = SUB162(auVar86 >> 0x50,0);
235: cVar10 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x50,0) - (0xff < sVar25);
236: uVar81 = CONCAT15(cVar10,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
237: SUB161(auVar86 >> 0x40,0) - (0xff < sVar24),uVar80))
238: ;
239: sVar24 = SUB162(auVar86 >> 0x60,0);
240: sVar25 = SUB162(auVar86 >> 0x70,0);
241: cVar11 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x70,0) - (0xff < sVar25);
242: uVar82 = CONCAT17(cVar11,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
243: SUB161(auVar86 >> 0x60,0) - (0xff < sVar24),uVar81))
244: ;
245: sVar24 = SUB162(auVar102,0);
246: sVar25 = SUB162(auVar102 >> 0x10,0);
247: cVar12 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
248: ;
249: Var83 = CONCAT19(cVar12,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar102,0) -
250: (0xff < sVar24),uVar82));
251: sVar24 = SUB162(auVar102 >> 0x20,0);
252: sVar25 = SUB162(auVar102 >> 0x30,0);
253: cVar13 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar25)
254: ;
255: auVar84 = CONCAT111(cVar13,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
256: SUB161(auVar102 >> 0x20,0) - (0xff < sVar24),
257: Var83));
258: sVar24 = SUB162(auVar102 >> 0x40,0);
259: sVar25 = SUB162(auVar102 >> 0x50,0);
260: cVar14 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25)
261: ;
262: auVar85 = CONCAT113(cVar14,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
263: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),
264: auVar84));
265: sVar24 = SUB162(auVar102 >> 0x60,0);
266: sVar25 = SUB162(auVar102 >> 0x70,0);
267: cVar15 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25)
268: ;
269: auVar86 = CONCAT115(cVar15,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
270: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),
271: auVar85));
272: auVar119 = auVar56 & auVar121;
273: uVar103 = SUB162(auVar121,0) >> 8;
274: uVar104 = SUB162(auVar121 >> 0x10,0) >> 8;
275: uVar105 = SUB162(auVar121 >> 0x20,0) >> 8;
276: uVar106 = SUB162(auVar121 >> 0x30,0) >> 8;
277: uVar107 = SUB162(auVar121 >> 0x40,0) >> 8;
278: uVar108 = SUB162(auVar121 >> 0x50,0) >> 8;
279: uVar109 = SUB162(auVar121 >> 0x60,0) >> 8;
280: uVar110 = SUB162(auVar121 >> 0x78,0);
281: auVar102 = auVar56 & auVar120;
282: uVar87 = SUB162(auVar120,0) >> 8;
283: uVar89 = SUB162(auVar120 >> 0x10,0) >> 8;
284: uVar90 = SUB162(auVar120 >> 0x20,0) >> 8;
285: uVar91 = SUB162(auVar120 >> 0x30,0) >> 8;
286: uVar92 = SUB162(auVar120 >> 0x40,0) >> 8;
287: uVar93 = SUB162(auVar120 >> 0x50,0) >> 8;
288: uVar94 = SUB162(auVar120 >> 0x60,0) >> 8;
289: uVar95 = SUB162(auVar120 >> 0x78,0);
290: auVar72 = CONCAT115((uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar88 >> 0x78,0) -
291: (0xff < uVar118),
292: CONCAT114((uVar117 != 0) * (uVar117 < 0xff) *
293: SUB161(auVar88 >> 0x68,0) - (0xff < uVar117),
294: CONCAT113((uVar116 != 0) * (uVar116 < 0xff) *
295: SUB161(auVar88 >> 0x58,0) - (0xff < uVar116),
296: CONCAT112((uVar115 != 0) * (uVar115 < 0xff) *
297: SUB161(auVar88 >> 0x48,0) -
298: (0xff < uVar115),
299: CONCAT111((uVar114 != 0) *
300: (uVar114 < 0xff) *
301: SUB161(auVar88 >> 0x38,0)
302: - (0xff < uVar114),
303: CONCAT110((uVar113 != 0) *
304: (uVar113 < 0xff)
305: * SUB161(auVar88
306: >> 0x28
307: ,0) - (0xff < uVar113),
308: CONCAT19((uVar112 != 0) * (uVar112 < 0xff) *
309: SUB161(auVar88 >> 0x18,0) -
310: (0xff < uVar112),
311: CONCAT18((uVar111 != 0) *
312: (uVar111 < 0xff) *
313: SUB161(auVar88 >> 8,0) -
314: (0xff < uVar111),
315: CONCAT17((uVar79 != 0) *
316: (uVar79 < 0xff) *
317: SUB161(auVar72 >> 0x78,
318: 0) -
319: (0xff < uVar79),
320: CONCAT16((uVar78 != 0)
321: * (uVar78 < 
322: 0xff) * SUB161(auVar72 >> 0x68,0) -
323: (0xff < uVar78),
324: CONCAT15((uVar77 != 0) * (uVar77 < 0xff) *
325: SUB161(auVar72 >> 0x58,0) -
326: (0xff < uVar77),
327: CONCAT14((uVar76 != 0) * (uVar76 < 0xff)
328: * SUB161(auVar72 >> 0x48,0) -
329: (0xff < uVar76),
330: CONCAT13((uVar75 != 0) *
331: (uVar75 < 0xff) *
332: SUB161(auVar72 >> 0x38,
333: 0) -
334: (0xff < uVar75),
335: CONCAT12((uVar74 != 0)
336: * (uVar74 < 
337: 0xff) * SUB161(auVar72 >> 0x28,0) -
338: (0xff < uVar74),
339: CONCAT11((uVar73 != 0) * (uVar73 < 0xff) *
340: SUB161(auVar72 >> 0x18,0) -
341: (0xff < uVar73),
342: (uVar71 != 0) * (uVar71 < 0xff) *
343: SUB161(auVar72 >> 8,0) - (0xff < uVar71))
344: )))))))))))))) & auVar56;
345: sVar24 = SUB162(auVar102,0);
346: sVar25 = SUB162(auVar102 >> 0x10,0);
347: cVar16 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
348: ;
349: sVar25 = SUB162(auVar102 >> 0x20,0);
350: sVar29 = SUB162(auVar102 >> 0x30,0);
351: cVar17 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar29)
352: ;
353: uVar96 = CONCAT13(cVar17,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
354: SUB161(auVar102 >> 0x20,0) - (0xff < sVar25),
355: CONCAT11(cVar16,(0 < sVar24) * (sVar24 < 0xff) *
356: SUB161(auVar102,0) - (0xff < sVar24)
357: )));
358: sVar24 = SUB162(auVar102 >> 0x40,0);
359: sVar25 = SUB162(auVar102 >> 0x50,0);
360: cVar18 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25)
361: ;
362: uVar97 = CONCAT15(cVar18,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
363: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),uVar96)
364: );
365: sVar24 = SUB162(auVar102 >> 0x60,0);
366: sVar25 = SUB162(auVar102 >> 0x70,0);
367: cVar19 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25)
368: ;
369: uVar98 = CONCAT17(cVar19,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
370: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),uVar97)
371: );
372: sVar24 = SUB162(auVar119,0);
373: sVar25 = SUB162(auVar119 >> 0x10,0);
374: cVar20 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x10,0) - (0xff < sVar25)
375: ;
376: Var99 = CONCAT19(cVar20,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar119,0) -
377: (0xff < sVar24),uVar98));
378: sVar24 = SUB162(auVar119 >> 0x20,0);
379: sVar25 = SUB162(auVar119 >> 0x30,0);
380: cVar21 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x30,0) - (0xff < sVar25)
381: ;
382: auVar100 = CONCAT111(cVar21,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
383: SUB161(auVar119 >> 0x20,0) - (0xff < sVar24),
384: Var99));
385: sVar24 = SUB162(auVar119 >> 0x40,0);
386: sVar25 = SUB162(auVar119 >> 0x50,0);
387: cVar22 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x50,0) - (0xff < sVar25)
388: ;
389: auVar101 = CONCAT113(cVar22,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
390: SUB161(auVar119 >> 0x40,0) - (0xff < sVar24),
391: auVar100));
392: sVar24 = SUB162(auVar119 >> 0x60,0);
393: sVar25 = SUB162(auVar119 >> 0x70,0);
394: cVar23 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x70,0) - (0xff < sVar25)
395: ;
396: auVar102 = CONCAT115(cVar23,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
397: SUB161(auVar119 >> 0x60,0) - (0xff < sVar24),
398: auVar101));
399: auVar88 = CONCAT115((uVar110 != 0) * (uVar110 < 0xff) * SUB161(auVar121 >> 0x78,0) -
400: (0xff < uVar110),
401: CONCAT114((uVar109 != 0) * (uVar109 < 0xff) *
402: SUB161(auVar121 >> 0x68,0) - (0xff < uVar109),
403: CONCAT113((uVar108 != 0) * (uVar108 < 0xff) *
404: SUB161(auVar121 >> 0x58,0) - (0xff < uVar108),
405: CONCAT112((uVar107 != 0) * (uVar107 < 0xff) *
406: SUB161(auVar121 >> 0x48,0) -
407: (0xff < uVar107),
408: CONCAT111((uVar106 != 0) *
409: (uVar106 < 0xff) *
410: SUB161(auVar121 >> 0x38,0)
411: - (0xff < uVar106),
412: CONCAT110((uVar105 != 0) *
413: (uVar105 < 0xff)
414: * SUB161(
415: auVar121 >> 0x28,0) - (0xff < uVar105),
416: CONCAT19((uVar104 != 0) * (uVar104 < 0xff) *
417: SUB161(auVar121 >> 0x18,0) -
418: (0xff < uVar104),
419: CONCAT18((uVar103 != 0) *
420: (uVar103 < 0xff) *
421: SUB161(auVar121 >> 8,0) -
422: (0xff < uVar103),
423: CONCAT17((uVar95 != 0) *
424: (uVar95 < 0xff) *
425: SUB161(auVar120 >> 0x78
426: ,0) -
427: (0xff < uVar95),
428: CONCAT16((uVar94 != 0)
429: * (uVar94 < 
430: 0xff) * SUB161(auVar120 >> 0x68,0) -
431: (0xff < uVar94),
432: CONCAT15((uVar93 != 0) * (uVar93 < 0xff) *
433: SUB161(auVar120 >> 0x58,0) -
434: (0xff < uVar93),
435: CONCAT14((uVar92 != 0) * (uVar92 < 0xff)
436: * SUB161(auVar120 >> 0x48,0) -
437: (0xff < uVar92),
438: CONCAT13((uVar91 != 0) *
439: (uVar91 < 0xff) *
440: SUB161(auVar120 >> 0x38
441: ,0) -
442: (0xff < uVar91),
443: CONCAT12((uVar90 != 0)
444: * (uVar90 < 
445: 0xff) * SUB161(auVar120 >> 0x28,0) -
446: (0xff < uVar90),
447: CONCAT11((uVar89 != 0) * (uVar89 < 0xff) *
448: SUB161(auVar120 >> 0x18,0) -
449: (0xff < uVar89),
450: (uVar87 != 0) * (uVar87 < 0xff) *
451: SUB161(auVar120 >> 8,0) - (0xff < uVar87)
452: ))))))))))))))) & auVar56;
453: auVar120 = auVar56 & auVar86;
454: uVar71 = (ushort)((uint)uVar80 >> 0x18);
455: uVar73 = (ushort)((uint6)uVar81 >> 0x28);
456: uVar74 = (ushort)((ulong)uVar82 >> 0x38);
457: uVar75 = (ushort)((unkuint10)Var83 >> 0x48);
458: uVar76 = SUB122(auVar84 >> 0x58,0);
459: uVar77 = SUB142(auVar85 >> 0x68,0);
460: uVar78 = SUB162(auVar86 >> 0x78,0);
461: auVar121 = auVar56 & auVar102;
462: uVar79 = (ushort)((uint)uVar96 >> 0x18);
463: uVar87 = (ushort)((uint6)uVar97 >> 0x28);
464: uVar89 = (ushort)((ulong)uVar98 >> 0x38);
465: uVar90 = (ushort)((unkuint10)Var99 >> 0x48);
466: uVar91 = SUB122(auVar100 >> 0x58,0);
467: uVar92 = SUB142(auVar101 >> 0x68,0);
468: uVar93 = SUB162(auVar102 >> 0x78,0);
469: sVar24 = SUB162(auVar72,0);
470: sVar29 = SUB162(auVar72 >> 0x10,0);
471: sVar27 = SUB162(auVar72 >> 0x20,0);
472: sVar30 = SUB162(auVar72 >> 0x30,0);
473: sVar32 = SUB162(auVar72 >> 0x40,0);
474: sVar34 = SUB162(auVar72 >> 0x50,0);
475: sVar36 = SUB162(auVar72 >> 0x60,0);
476: sVar38 = SUB162(auVar72 >> 0x70,0);
477: sVar40 = SUB162(auVar88,0);
478: sVar42 = SUB162(auVar88 >> 0x10,0);
479: sVar44 = SUB162(auVar88 >> 0x20,0);
480: sVar46 = SUB162(auVar88 >> 0x30,0);
481: sVar48 = SUB162(auVar88 >> 0x40,0);
482: sVar50 = SUB162(auVar88 >> 0x50,0);
483: sVar52 = SUB162(auVar88 >> 0x60,0);
484: sVar54 = SUB162(auVar88 >> 0x70,0);
485: sVar25 = SUB162(auVar120,0);
486: sVar26 = SUB162(auVar120 >> 0x10,0);
487: sVar28 = SUB162(auVar120 >> 0x20,0);
488: sVar31 = SUB162(auVar120 >> 0x30,0);
489: sVar33 = SUB162(auVar120 >> 0x40,0);
490: sVar35 = SUB162(auVar120 >> 0x50,0);
491: sVar37 = SUB162(auVar120 >> 0x60,0);
492: sVar39 = SUB162(auVar120 >> 0x70,0);
493: sVar41 = SUB162(auVar121,0);
494: sVar43 = SUB162(auVar121 >> 0x10,0);
495: sVar45 = SUB162(auVar121 >> 0x20,0);
496: sVar47 = SUB162(auVar121 >> 0x30,0);
497: sVar49 = SUB162(auVar121 >> 0x40,0);
498: sVar51 = SUB162(auVar121 >> 0x50,0);
499: sVar53 = SUB162(auVar121 >> 0x60,0);
500: sVar55 = SUB162(auVar121 >> 0x70,0);
501: pcVar2 = puVar58 + lVar57;
502: *pcVar2 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar120,0) - (0xff < sVar25);
503: pcVar2[1] = (0 < sVar26) * (sVar26 < 0xff) * SUB161(auVar120 >> 0x10,0) -
504: (0xff < sVar26);
505: pcVar2[2] = (0 < sVar28) * (sVar28 < 0xff) * SUB161(auVar120 >> 0x20,0) -
506: (0xff < sVar28);
507: pcVar2[3] = (0 < sVar31) * (sVar31 < 0xff) * SUB161(auVar120 >> 0x30,0) -
508: (0xff < sVar31);
509: pcVar2[4] = (0 < sVar33) * (sVar33 < 0xff) * SUB161(auVar120 >> 0x40,0) -
510: (0xff < sVar33);
511: pcVar2[5] = (0 < sVar35) * (sVar35 < 0xff) * SUB161(auVar120 >> 0x50,0) -
512: (0xff < sVar35);
513: pcVar2[6] = (0 < sVar37) * (sVar37 < 0xff) * SUB161(auVar120 >> 0x60,0) -
514: (0xff < sVar37);
515: pcVar2[7] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar120 >> 0x70,0) -
516: (0xff < sVar39);
517: pcVar2[8] = (0 < sVar41) * (sVar41 < 0xff) * SUB161(auVar121,0) - (0xff < sVar41);
518: pcVar2[9] = (0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar121 >> 0x10,0) -
519: (0xff < sVar43);
520: pcVar2[10] = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar121 >> 0x20,0) -
521: (0xff < sVar45);
522: pcVar2[0xb] = (0 < sVar47) * (sVar47 < 0xff) * SUB161(auVar121 >> 0x30,0) -
523: (0xff < sVar47);
524: pcVar2[0xc] = (0 < sVar49) * (sVar49 < 0xff) * SUB161(auVar121 >> 0x40,0) -
525: (0xff < sVar49);
526: pcVar2[0xd] = (0 < sVar51) * (sVar51 < 0xff) * SUB161(auVar121 >> 0x50,0) -
527: (0xff < sVar51);
528: pcVar2[0xe] = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar121 >> 0x60,0) -
529: (0xff < sVar53);
530: pcVar2[0xf] = (0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar121 >> 0x70,0) -
531: (0xff < sVar55);
532: pcVar2 = puVar60 + lVar57;
533: *pcVar2 = (0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar72,0) - (0xff < sVar24);
534: pcVar2[1] = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar72 >> 0x10,0) -
535: (0xff < sVar29);
536: pcVar2[2] = (0 < sVar27) * (sVar27 < 0xff) * SUB161(auVar72 >> 0x20,0) -
537: (0xff < sVar27);
538: pcVar2[3] = (0 < sVar30) * (sVar30 < 0xff) * SUB161(auVar72 >> 0x30,0) -
539: (0xff < sVar30);
540: pcVar2[4] = (0 < sVar32) * (sVar32 < 0xff) * SUB161(auVar72 >> 0x40,0) -
541: (0xff < sVar32);
542: pcVar2[5] = (0 < sVar34) * (sVar34 < 0xff) * SUB161(auVar72 >> 0x50,0) -
543: (0xff < sVar34);
544: pcVar2[6] = (0 < sVar36) * (sVar36 < 0xff) * SUB161(auVar72 >> 0x60,0) -
545: (0xff < sVar36);
546: pcVar2[7] = (0 < sVar38) * (sVar38 < 0xff) * SUB161(auVar72 >> 0x70,0) -
547: (0xff < sVar38);
548: pcVar2[8] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar88,0) - (0xff < sVar40);
549: pcVar2[9] = (0 < sVar42) * (sVar42 < 0xff) * SUB161(auVar88 >> 0x10,0) -
550: (0xff < sVar42);
551: pcVar2[10] = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar88 >> 0x20,0) -
552: (0xff < sVar44);
553: pcVar2[0xb] = (0 < sVar46) * (sVar46 < 0xff) * SUB161(auVar88 >> 0x30,0) -
554: (0xff < sVar46);
555: pcVar2[0xc] = (0 < sVar48) * (sVar48 < 0xff) * SUB161(auVar88 >> 0x40,0) -
556: (0xff < sVar48);
557: pcVar2[0xd] = (0 < sVar50) * (sVar50 < 0xff) * SUB161(auVar88 >> 0x50,0) -
558: (0xff < sVar50);
559: pcVar2[0xe] = (0 < sVar52) * (sVar52 < 0xff) * SUB161(auVar88 >> 0x60,0) -
560: (0xff < sVar52);
561: pcVar2[0xf] = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar88 >> 0x70,0) -
562: (0xff < sVar54);
563: pcVar2 = puVar6 + lVar57;
564: *pcVar2 = (cVar8 != '\0') * (cVar8 != -1) * cVar8;
565: pcVar2[1] = (uVar71 != 0) * (uVar71 < 0xff) * cVar9 - (0xff < uVar71);
566: pcVar2[2] = (uVar73 != 0) * (uVar73 < 0xff) * cVar10 - (0xff < uVar73);
567: pcVar2[3] = (uVar74 != 0) * (uVar74 < 0xff) * cVar11 - (0xff < uVar74);
568: pcVar2[4] = (uVar75 != 0) * (uVar75 < 0xff) * cVar12 - (0xff < uVar75);
569: pcVar2[5] = (uVar76 != 0) * (uVar76 < 0xff) * cVar13 - (0xff < uVar76);
570: pcVar2[6] = (uVar77 != 0) * (uVar77 < 0xff) * cVar14 - (0xff < uVar77);
571: pcVar2[7] = (uVar78 != 0) * (uVar78 < 0xff) * cVar15 - (0xff < uVar78);
572: pcVar2[8] = (cVar16 != '\0') * (cVar16 != -1) * cVar16;
573: pcVar2[9] = (uVar79 != 0) * (uVar79 < 0xff) * cVar17 - (0xff < uVar79);
574: pcVar2[10] = (uVar87 != 0) * (uVar87 < 0xff) * cVar18 - (0xff < uVar87);
575: pcVar2[0xb] = (uVar89 != 0) * (uVar89 < 0xff) * cVar19 - (0xff < uVar89);
576: pcVar2[0xc] = (uVar90 != 0) * (uVar90 < 0xff) * cVar20 - (0xff < uVar90);
577: pcVar2[0xd] = (uVar91 != 0) * (uVar91 < 0xff) * cVar21 - (0xff < uVar91);
578: pcVar2[0xe] = (uVar92 != 0) * (uVar92 < 0xff) * cVar22 - (0xff < uVar92);
579: pcVar2[0xf] = (uVar93 != 0) * (uVar93 < 0xff) * cVar23 - (0xff < uVar93);
580: lVar57 = lVar57 + 0x10;
581: } while (uVar70 < uVar1 >> 4);
582: puVar59 = puVar59 + (ulong)(uVar1 & 0xfffffff0) * 4;
583: uVar70 = uVar1 & 0xfffffff0;
584: }
585: uVar63 = (ulong)uVar70;
586: puVar58[uVar63] = *puVar59;
587: puVar60[uVar63] = puVar59[1];
588: puVar6[uVar63] = puVar59[2];
589: uVar63 = (ulong)(uVar70 + 1);
590: if (uVar70 + 1 < uVar4) {
591: puVar58[uVar63] = puVar59[4];
592: puVar60[uVar63] = puVar59[5];
593: puVar6[uVar63] = puVar59[6];
594: uVar63 = (ulong)(uVar70 + 2);
595: if (uVar70 + 2 < uVar4) {
596: puVar58[uVar63] = puVar59[8];
597: puVar60[uVar63] = puVar59[9];
598: puVar6[uVar63] = puVar59[10];
599: uVar63 = (ulong)(uVar70 + 3);
600: if (uVar70 + 3 < uVar4) {
601: puVar58[uVar63] = puVar59[0xc];
602: puVar60[uVar63] = puVar59[0xd];
603: puVar6[uVar63] = puVar59[0xe];
604: uVar63 = (ulong)(uVar70 + 4);
605: if (uVar70 + 4 < uVar4) {
606: puVar58[uVar63] = puVar59[0x10];
607: puVar60[uVar63] = puVar59[0x11];
608: puVar6[uVar63] = puVar59[0x12];
609: uVar63 = (ulong)(uVar70 + 5);
610: if (uVar70 + 5 < uVar4) {
611: puVar58[uVar63] = puVar59[0x14];
612: puVar60[uVar63] = puVar59[0x15];
613: puVar6[uVar63] = puVar59[0x16];
614: uVar63 = (ulong)(uVar70 + 6);
615: if (uVar70 + 6 < uVar4) {
616: puVar58[uVar63] = puVar59[0x18];
617: puVar60[uVar63] = puVar59[0x19];
618: puVar6[uVar63] = puVar59[0x1a];
619: uVar63 = (ulong)(uVar70 + 7);
620: if (uVar70 + 7 < uVar4) {
621: puVar58[uVar63] = puVar59[0x1c];
622: puVar60[uVar63] = puVar59[0x1d];
623: puVar6[uVar63] = puVar59[0x1e];
624: uVar63 = (ulong)(uVar70 + 8);
625: if (uVar70 + 8 < uVar4) {
626: puVar58[uVar63] = puVar59[0x20];
627: puVar60[uVar63] = puVar59[0x21];
628: puVar6[uVar63] = puVar59[0x22];
629: uVar63 = (ulong)(uVar70 + 9);
630: if (uVar70 + 9 < uVar4) {
631: puVar58[uVar63] = puVar59[0x24];
632: puVar60[uVar63] = puVar59[0x25];
633: puVar6[uVar63] = puVar59[0x26];
634: uVar63 = (ulong)(uVar70 + 10);
635: if (uVar70 + 10 < uVar4) {
636: puVar58[uVar63] = puVar59[0x28];
637: puVar60[uVar63] = puVar59[0x29];
638: puVar6[uVar63] = puVar59[0x2a];
639: uVar63 = (ulong)(uVar70 + 0xb);
640: if (uVar70 + 0xb < uVar4) {
641: puVar58[uVar63] = puVar59[0x2c];
642: puVar60[uVar63] = puVar59[0x2d];
643: puVar6[uVar63] = puVar59[0x2e];
644: uVar63 = (ulong)(uVar70 + 0xc);
645: if (uVar70 + 0xc < uVar4) {
646: puVar58[uVar63] = puVar59[0x30];
647: puVar60[uVar63] = puVar59[0x31];
648: puVar6[uVar63] = puVar59[0x32];
649: uVar63 = (ulong)(uVar70 + 0xd);
650: if (uVar70 + 0xd < uVar4) {
651: puVar58[uVar63] = puVar59[0x34];
652: puVar60[uVar63] = puVar59[0x35];
653: puVar6[uVar63] = puVar59[0x36];
654: uVar63 = (ulong)(uVar70 + 0xe);
655: if (uVar70 + 0xe < uVar4) {
656: uVar69 = (ulong)(uVar70 + 0xf);
657: puVar58[uVar63] = puVar59[0x38];
658: puVar60[uVar63] = puVar59[0x39];
659: puVar6[uVar63] = puVar59[0x3a];
660: if (uVar70 + 0xf < uVar4) {
661: puVar58[uVar69] = puVar59[0x3c];
662: puVar60[uVar69] = puVar59[0x3d];
663: puVar6[uVar69] = puVar59[0x3e];
664: }
665: }
666: }
667: }
668: }
669: }
670: }
671: }
672: }
673: }
674: }
675: }
676: }
677: }
678: }
679: }
680: }
681: }
682: break;
683: case 8:
684: while (param_5 = param_5 + -1, -1 < param_5) {
685: plVar65 = param_2 + 1;
686: uVar61 = (ulong)((int)uVar64 + 1);
687: puVar59 = (undefined *)*param_2;
688: lVar57 = *(long *)(*param_3 + uVar64 * 8);
689: lVar68 = *(long *)(param_3[1] + uVar64 * 8);
690: lVar7 = *(long *)(param_3[2] + uVar64 * 8);
691: param_2 = plVar65;
692: uVar64 = uVar61;
693: if (uVar4 != 0) {
694: lVar66 = 0;
695: puVar58 = puVar59;
696: do {
697: puVar60 = puVar58 + 3;
698: *(undefined *)(lVar57 + lVar66) = puVar58[2];
699: *(undefined *)(lVar68 + lVar66) = puVar58[1];
700: *(undefined *)(lVar7 + lVar66) = *puVar58;
701: lVar66 = lVar66 + 1;
702: puVar58 = puVar60;
703: } while (puVar60 != puVar59 + (ulong)(uVar4 - 1) * 3 + 3);
704: }
705: }
706: break;
707: case 9:
708: case 0xd:
709: uVar61 = (ulong)uVar4;
710: uVar1 = uVar4 - 1;
711: while (param_5 = param_5 + -1, -1 < param_5) {
712: plVar65 = param_2 + 1;
713: uVar63 = (ulong)((int)uVar64 + 1);
714: puVar59 = (undefined *)*param_2;
715: puVar58 = *(undefined **)(*param_3 + uVar64 * 8);
716: puVar60 = *(undefined **)(param_3[1] + uVar64 * 8);
717: puVar6 = *(undefined **)(param_3[2] + uVar64 * 8);
718: uVar64 = uVar63;
719: param_2 = plVar65;
720: if (uVar4 != 0) {
721: puVar3 = puVar59 + uVar61 * 4;
722: if ((((((puVar59 < puVar58 + uVar61 && puVar58 < puVar3 ||
723: puVar59 < puVar60 + uVar61 && puVar60 < puVar3) || uVar4 < 0x10) ||
724: puVar59 < puVar6 + uVar61 && puVar6 < puVar3) ||
725: puVar60 < puVar58 + 0x10 && puVar58 < puVar60 + 0x10) ||
726: puVar6 < puVar58 + 0x10 && puVar58 < puVar6 + 0x10) ||
727: (puVar6 < puVar60 + 0x10 && puVar60 < puVar6 + 0x10)) {
728: lVar57 = 0;
729: do {
730: puVar58[lVar57] = puVar59[lVar57 * 4 + 2];
731: puVar60[lVar57] = puVar59[lVar57 * 4 + 1];
732: puVar6[lVar57] = puVar59[lVar57 * 4];
733: lVar57 = lVar57 + 1;
734: } while (lVar57 != (ulong)uVar1 + 1);
735: }
736: else {
737: if (uVar1 < 0x10) {
738: uVar70 = 0;
739: }
740: else {
741: lVar57 = 0;
742: uVar70 = 0;
743: do {
744: auVar72 = *(undefined (*) [16])(puVar59 + lVar57 * 4);
745: uVar70 = uVar70 + 1;
746: auVar88 = *(undefined (*) [16])(puVar59 + lVar57 * 4 + 0x10);
747: auVar86 = auVar56 & auVar72;
748: uVar71 = SUB162(auVar72,0) >> 8;
749: uVar73 = SUB162(auVar72 >> 0x10,0) >> 8;
750: uVar74 = SUB162(auVar72 >> 0x20,0) >> 8;
751: uVar75 = SUB162(auVar72 >> 0x30,0) >> 8;
752: uVar76 = SUB162(auVar72 >> 0x40,0) >> 8;
753: uVar77 = SUB162(auVar72 >> 0x50,0) >> 8;
754: uVar78 = SUB162(auVar72 >> 0x60,0) >> 8;
755: uVar79 = SUB162(auVar72 >> 0x78,0);
756: auVar102 = auVar56 & auVar88;
757: uVar111 = SUB162(auVar88,0) >> 8;
758: uVar112 = SUB162(auVar88 >> 0x10,0) >> 8;
759: uVar113 = SUB162(auVar88 >> 0x20,0) >> 8;
760: uVar114 = SUB162(auVar88 >> 0x30,0) >> 8;
761: uVar115 = SUB162(auVar88 >> 0x40,0) >> 8;
762: uVar116 = SUB162(auVar88 >> 0x50,0) >> 8;
763: uVar117 = SUB162(auVar88 >> 0x60,0) >> 8;
764: uVar118 = SUB162(auVar88 >> 0x78,0);
765: auVar120 = *(undefined (*) [16])(puVar59 + lVar57 * 4 + 0x20);
766: auVar121 = *(undefined (*) [16])(puVar59 + lVar57 * 4 + 0x30);
767: sVar24 = SUB162(auVar86,0);
768: sVar25 = SUB162(auVar86 >> 0x10,0);
769: cVar15 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x10,0) - (0xff < sVar25);
770: sVar25 = SUB162(auVar86 >> 0x20,0);
771: sVar29 = SUB162(auVar86 >> 0x30,0);
772: cVar14 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar86 >> 0x30,0) - (0xff < sVar29);
773: uVar80 = CONCAT13(cVar14,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
774: SUB161(auVar86 >> 0x20,0) - (0xff < sVar25),
775: CONCAT11(cVar15,(0 < sVar24) * (sVar24 < 0xff) *
776: SUB161(auVar86,0) - (0xff < sVar24))
777: ));
778: sVar24 = SUB162(auVar86 >> 0x40,0);
779: sVar25 = SUB162(auVar86 >> 0x50,0);
780: cVar13 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x50,0) - (0xff < sVar25);
781: uVar81 = CONCAT15(cVar13,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
782: SUB161(auVar86 >> 0x40,0) - (0xff < sVar24),uVar80))
783: ;
784: sVar24 = SUB162(auVar86 >> 0x60,0);
785: sVar25 = SUB162(auVar86 >> 0x70,0);
786: cVar12 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x70,0) - (0xff < sVar25);
787: uVar82 = CONCAT17(cVar12,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
788: SUB161(auVar86 >> 0x60,0) - (0xff < sVar24),uVar81))
789: ;
790: sVar24 = SUB162(auVar102,0);
791: sVar25 = SUB162(auVar102 >> 0x10,0);
792: cVar11 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
793: ;
794: Var83 = CONCAT19(cVar11,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar102,0) -
795: (0xff < sVar24),uVar82));
796: sVar24 = SUB162(auVar102 >> 0x20,0);
797: sVar25 = SUB162(auVar102 >> 0x30,0);
798: cVar10 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar25)
799: ;
800: auVar84 = CONCAT111(cVar10,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
801: SUB161(auVar102 >> 0x20,0) - (0xff < sVar24),
802: Var83));
803: sVar24 = SUB162(auVar102 >> 0x40,0);
804: sVar25 = SUB162(auVar102 >> 0x50,0);
805: cVar9 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25);
806: auVar85 = CONCAT113(cVar9,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
807: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),
808: auVar84));
809: sVar24 = SUB162(auVar102 >> 0x60,0);
810: sVar25 = SUB162(auVar102 >> 0x70,0);
811: cVar8 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25);
812: auVar86 = CONCAT115(cVar8,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
813: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),
814: auVar85));
815: auVar119 = auVar56 & auVar121;
816: uVar103 = SUB162(auVar121,0) >> 8;
817: uVar104 = SUB162(auVar121 >> 0x10,0) >> 8;
818: uVar105 = SUB162(auVar121 >> 0x20,0) >> 8;
819: uVar106 = SUB162(auVar121 >> 0x30,0) >> 8;
820: uVar107 = SUB162(auVar121 >> 0x40,0) >> 8;
821: uVar108 = SUB162(auVar121 >> 0x50,0) >> 8;
822: uVar109 = SUB162(auVar121 >> 0x60,0) >> 8;
823: uVar110 = SUB162(auVar121 >> 0x78,0);
824: auVar102 = auVar56 & auVar120;
825: uVar87 = SUB162(auVar120,0) >> 8;
826: uVar89 = SUB162(auVar120 >> 0x10,0) >> 8;
827: uVar90 = SUB162(auVar120 >> 0x20,0) >> 8;
828: uVar91 = SUB162(auVar120 >> 0x30,0) >> 8;
829: uVar92 = SUB162(auVar120 >> 0x40,0) >> 8;
830: uVar93 = SUB162(auVar120 >> 0x50,0) >> 8;
831: uVar94 = SUB162(auVar120 >> 0x60,0) >> 8;
832: uVar95 = SUB162(auVar120 >> 0x78,0);
833: auVar72 = CONCAT115((uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar88 >> 0x78,0) -
834: (0xff < uVar118),
835: CONCAT114((uVar117 != 0) * (uVar117 < 0xff) *
836: SUB161(auVar88 >> 0x68,0) - (0xff < uVar117),
837: CONCAT113((uVar116 != 0) * (uVar116 < 0xff) *
838: SUB161(auVar88 >> 0x58,0) - (0xff < uVar116),
839: CONCAT112((uVar115 != 0) * (uVar115 < 0xff) *
840: SUB161(auVar88 >> 0x48,0) -
841: (0xff < uVar115),
842: CONCAT111((uVar114 != 0) *
843: (uVar114 < 0xff) *
844: SUB161(auVar88 >> 0x38,0)
845: - (0xff < uVar114),
846: CONCAT110((uVar113 != 0) *
847: (uVar113 < 0xff)
848: * SUB161(auVar88
849: >> 0x28
850: ,0) - (0xff < uVar113),
851: CONCAT19((uVar112 != 0) * (uVar112 < 0xff) *
852: SUB161(auVar88 >> 0x18,0) -
853: (0xff < uVar112),
854: CONCAT18((uVar111 != 0) *
855: (uVar111 < 0xff) *
856: SUB161(auVar88 >> 8,0) -
857: (0xff < uVar111),
858: CONCAT17((uVar79 != 0) *
859: (uVar79 < 0xff) *
860: SUB161(auVar72 >> 0x78,
861: 0) -
862: (0xff < uVar79),
863: CONCAT16((uVar78 != 0)
864: * (uVar78 < 
865: 0xff) * SUB161(auVar72 >> 0x68,0) -
866: (0xff < uVar78),
867: CONCAT15((uVar77 != 0) * (uVar77 < 0xff) *
868: SUB161(auVar72 >> 0x58,0) -
869: (0xff < uVar77),
870: CONCAT14((uVar76 != 0) * (uVar76 < 0xff)
871: * SUB161(auVar72 >> 0x48,0) -
872: (0xff < uVar76),
873: CONCAT13((uVar75 != 0) *
874: (uVar75 < 0xff) *
875: SUB161(auVar72 >> 0x38,
876: 0) -
877: (0xff < uVar75),
878: CONCAT12((uVar74 != 0)
879: * (uVar74 < 
880: 0xff) * SUB161(auVar72 >> 0x28,0) -
881: (0xff < uVar74),
882: CONCAT11((uVar73 != 0) * (uVar73 < 0xff) *
883: SUB161(auVar72 >> 0x18,0) -
884: (0xff < uVar73),
885: (uVar71 != 0) * (uVar71 < 0xff) *
886: SUB161(auVar72 >> 8,0) - (0xff < uVar71))
887: )))))))))))))) & auVar56;
888: sVar24 = SUB162(auVar102,0);
889: sVar25 = SUB162(auVar102 >> 0x10,0);
890: cVar23 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
891: ;
892: sVar25 = SUB162(auVar102 >> 0x20,0);
893: sVar29 = SUB162(auVar102 >> 0x30,0);
894: cVar22 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar29)
895: ;
896: uVar96 = CONCAT13(cVar22,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
897: SUB161(auVar102 >> 0x20,0) - (0xff < sVar25),
898: CONCAT11(cVar23,(0 < sVar24) * (sVar24 < 0xff) *
899: SUB161(auVar102,0) - (0xff < sVar24)
900: )));
901: sVar24 = SUB162(auVar102 >> 0x40,0);
902: sVar25 = SUB162(auVar102 >> 0x50,0);
903: cVar21 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25)
904: ;
905: uVar97 = CONCAT15(cVar21,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
906: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),uVar96)
907: );
908: sVar24 = SUB162(auVar102 >> 0x60,0);
909: sVar25 = SUB162(auVar102 >> 0x70,0);
910: cVar20 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25)
911: ;
912: uVar98 = CONCAT17(cVar20,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
913: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),uVar97)
914: );
915: sVar24 = SUB162(auVar119,0);
916: sVar25 = SUB162(auVar119 >> 0x10,0);
917: cVar19 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x10,0) - (0xff < sVar25)
918: ;
919: Var99 = CONCAT19(cVar19,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar119,0) -
920: (0xff < sVar24),uVar98));
921: sVar24 = SUB162(auVar119 >> 0x20,0);
922: sVar25 = SUB162(auVar119 >> 0x30,0);
923: cVar18 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x30,0) - (0xff < sVar25)
924: ;
925: auVar100 = CONCAT111(cVar18,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
926: SUB161(auVar119 >> 0x20,0) - (0xff < sVar24),
927: Var99));
928: sVar24 = SUB162(auVar119 >> 0x40,0);
929: sVar25 = SUB162(auVar119 >> 0x50,0);
930: cVar17 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x50,0) - (0xff < sVar25)
931: ;
932: auVar101 = CONCAT113(cVar17,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
933: SUB161(auVar119 >> 0x40,0) - (0xff < sVar24),
934: auVar100));
935: sVar24 = SUB162(auVar119 >> 0x60,0);
936: sVar25 = SUB162(auVar119 >> 0x70,0);
937: cVar16 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x70,0) - (0xff < sVar25)
938: ;
939: auVar102 = CONCAT115(cVar16,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
940: SUB161(auVar119 >> 0x60,0) - (0xff < sVar24),
941: auVar101));
942: auVar120 = CONCAT115((uVar110 != 0) * (uVar110 < 0xff) * SUB161(auVar121 >> 0x78,0) -
943: (0xff < uVar110),
944: CONCAT114((uVar109 != 0) * (uVar109 < 0xff) *
945: SUB161(auVar121 >> 0x68,0) - (0xff < uVar109),
946: CONCAT113((uVar108 != 0) * (uVar108 < 0xff) *
947: SUB161(auVar121 >> 0x58,0) - (0xff < uVar108)
948: ,CONCAT112((uVar107 != 0) * (uVar107 < 0xff)
949: * SUB161(auVar121 >> 0x48,0) -
950: (0xff < uVar107),
951: CONCAT111((uVar106 != 0) *
952: (uVar106 < 0xff) *
953: SUB161(auVar121 >> 0x38,
954: 0) -
955: (0xff < uVar106),
956: CONCAT110((uVar105 != 0)
957: * (uVar105 <
958: 0xff) * 
959: SUB161(auVar121 >> 0x28,0) - (0xff < uVar105),
960: CONCAT19((uVar104 != 0) * (uVar104 < 0xff) *
961: SUB161(auVar121 >> 0x18,0) -
962: (0xff < uVar104),
963: CONCAT18((uVar103 != 0) *
964: (uVar103 < 0xff) *
965: SUB161(auVar121 >> 8,0) -
966: (0xff < uVar103),
967: CONCAT17((uVar95 != 0) *
968: (uVar95 < 0xff) *
969: SUB161(auVar120 >> 0x78
970: ,0) -
971: (0xff < uVar95),
972: CONCAT16((uVar94 != 0)
973: * (uVar94 < 
974: 0xff) * SUB161(auVar120 >> 0x68,0) -
975: (0xff < uVar94),
976: CONCAT15((uVar93 != 0) * (uVar93 < 0xff) *
977: SUB161(auVar120 >> 0x58,0) -
978: (0xff < uVar93),
979: CONCAT14((uVar92 != 0) * (uVar92 < 0xff)
980: * SUB161(auVar120 >> 0x48,0) -
981: (0xff < uVar92),
982: CONCAT13((uVar91 != 0) *
983: (uVar91 < 0xff) *
984: SUB161(auVar120 >> 0x38
985: ,0) -
986: (0xff < uVar91),
987: CONCAT12((uVar90 != 0)
988: * (uVar90 < 
989: 0xff) * SUB161(auVar120 >> 0x28,0) -
990: (0xff < uVar90),
991: CONCAT11((uVar89 != 0) * (uVar89 < 0xff) *
992: SUB161(auVar120 >> 0x18,0) -
993: (0xff < uVar89),
994: (uVar87 != 0) * (uVar87 < 0xff) *
995: SUB161(auVar120 >> 8,0) - (0xff < uVar87)
996: ))))))))))))))) & auVar56;
997: auVar88 = auVar86 & auVar56;
998: uVar71 = (ushort)((uint)uVar80 >> 0x18);
999: uVar73 = (ushort)((uint6)uVar81 >> 0x28);
1000: uVar74 = (ushort)((ulong)uVar82 >> 0x38);
1001: uVar75 = (ushort)((unkuint10)Var83 >> 0x48);
1002: uVar76 = SUB122(auVar84 >> 0x58,0);
1003: uVar77 = SUB142(auVar85 >> 0x68,0);
1004: uVar78 = SUB162(auVar86 >> 0x78,0);
1005: auVar121 = auVar102 & auVar56;
1006: sVar24 = SUB162(auVar72,0);
1007: sVar29 = SUB162(auVar72 >> 0x10,0);
1008: sVar27 = SUB162(auVar72 >> 0x20,0);
1009: sVar30 = SUB162(auVar72 >> 0x30,0);
1010: sVar32 = SUB162(auVar72 >> 0x40,0);
1011: sVar34 = SUB162(auVar72 >> 0x50,0);
1012: sVar36 = SUB162(auVar72 >> 0x60,0);
1013: sVar38 = SUB162(auVar72 >> 0x70,0);
1014: sVar40 = SUB162(auVar120,0);
1015: sVar42 = SUB162(auVar120 >> 0x10,0);
1016: sVar44 = SUB162(auVar120 >> 0x20,0);
1017: sVar46 = SUB162(auVar120 >> 0x30,0);
1018: sVar48 = SUB162(auVar120 >> 0x40,0);
1019: sVar50 = SUB162(auVar120 >> 0x50,0);
1020: sVar52 = SUB162(auVar120 >> 0x60,0);
1021: sVar54 = SUB162(auVar120 >> 0x70,0);
1022: uVar79 = (ushort)((uint)uVar96 >> 0x18);
1023: uVar87 = (ushort)((uint6)uVar97 >> 0x28);
1024: uVar89 = (ushort)((ulong)uVar98 >> 0x38);
1025: uVar90 = (ushort)((unkuint10)Var99 >> 0x48);
1026: uVar91 = SUB122(auVar100 >> 0x58,0);
1027: uVar92 = SUB142(auVar101 >> 0x68,0);
1028: uVar93 = SUB162(auVar102 >> 0x78,0);
1029: sVar25 = SUB162(auVar88,0);
1030: sVar26 = SUB162(auVar88 >> 0x10,0);
1031: sVar28 = SUB162(auVar88 >> 0x20,0);
1032: sVar31 = SUB162(auVar88 >> 0x30,0);
1033: sVar33 = SUB162(auVar88 >> 0x40,0);
1034: sVar35 = SUB162(auVar88 >> 0x50,0);
1035: sVar37 = SUB162(auVar88 >> 0x60,0);
1036: sVar39 = SUB162(auVar88 >> 0x70,0);
1037: sVar41 = SUB162(auVar121,0);
1038: sVar43 = SUB162(auVar121 >> 0x10,0);
1039: sVar45 = SUB162(auVar121 >> 0x20,0);
1040: sVar47 = SUB162(auVar121 >> 0x30,0);
1041: sVar49 = SUB162(auVar121 >> 0x40,0);
1042: sVar51 = SUB162(auVar121 >> 0x50,0);
1043: sVar53 = SUB162(auVar121 >> 0x60,0);
1044: sVar55 = SUB162(auVar121 >> 0x70,0);
1045: pcVar2 = puVar58 + lVar57;
1046: *pcVar2 = (cVar15 != '\0') * (cVar15 != -1) * cVar15;
1047: pcVar2[1] = (uVar71 != 0) * (uVar71 < 0xff) * cVar14 - (0xff < uVar71);
1048: pcVar2[2] = (uVar73 != 0) * (uVar73 < 0xff) * cVar13 - (0xff < uVar73);
1049: pcVar2[3] = (uVar74 != 0) * (uVar74 < 0xff) * cVar12 - (0xff < uVar74);
1050: pcVar2[4] = (uVar75 != 0) * (uVar75 < 0xff) * cVar11 - (0xff < uVar75);
1051: pcVar2[5] = (uVar76 != 0) * (uVar76 < 0xff) * cVar10 - (0xff < uVar76);
1052: pcVar2[6] = (uVar77 != 0) * (uVar77 < 0xff) * cVar9 - (0xff < uVar77);
1053: pcVar2[7] = (uVar78 != 0) * (uVar78 < 0xff) * cVar8 - (0xff < uVar78);
1054: pcVar2[8] = (cVar23 != '\0') * (cVar23 != -1) * cVar23;
1055: pcVar2[9] = (uVar79 != 0) * (uVar79 < 0xff) * cVar22 - (0xff < uVar79);
1056: pcVar2[10] = (uVar87 != 0) * (uVar87 < 0xff) * cVar21 - (0xff < uVar87);
1057: pcVar2[0xb] = (uVar89 != 0) * (uVar89 < 0xff) * cVar20 - (0xff < uVar89);
1058: pcVar2[0xc] = (uVar90 != 0) * (uVar90 < 0xff) * cVar19 - (0xff < uVar90);
1059: pcVar2[0xd] = (uVar91 != 0) * (uVar91 < 0xff) * cVar18 - (0xff < uVar91);
1060: pcVar2[0xe] = (uVar92 != 0) * (uVar92 < 0xff) * cVar17 - (0xff < uVar92);
1061: pcVar2[0xf] = (uVar93 != 0) * (uVar93 < 0xff) * cVar16 - (0xff < uVar93);
1062: pcVar2 = puVar60 + lVar57;
1063: *pcVar2 = (0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar72,0) - (0xff < sVar24);
1064: pcVar2[1] = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar72 >> 0x10,0) -
1065: (0xff < sVar29);
1066: pcVar2[2] = (0 < sVar27) * (sVar27 < 0xff) * SUB161(auVar72 >> 0x20,0) -
1067: (0xff < sVar27);
1068: pcVar2[3] = (0 < sVar30) * (sVar30 < 0xff) * SUB161(auVar72 >> 0x30,0) -
1069: (0xff < sVar30);
1070: pcVar2[4] = (0 < sVar32) * (sVar32 < 0xff) * SUB161(auVar72 >> 0x40,0) -
1071: (0xff < sVar32);
1072: pcVar2[5] = (0 < sVar34) * (sVar34 < 0xff) * SUB161(auVar72 >> 0x50,0) -
1073: (0xff < sVar34);
1074: pcVar2[6] = (0 < sVar36) * (sVar36 < 0xff) * SUB161(auVar72 >> 0x60,0) -
1075: (0xff < sVar36);
1076: pcVar2[7] = (0 < sVar38) * (sVar38 < 0xff) * SUB161(auVar72 >> 0x70,0) -
1077: (0xff < sVar38);
1078: pcVar2[8] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar120,0) - (0xff < sVar40);
1079: pcVar2[9] = (0 < sVar42) * (sVar42 < 0xff) * SUB161(auVar120 >> 0x10,0) -
1080: (0xff < sVar42);
1081: pcVar2[10] = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar120 >> 0x20,0) -
1082: (0xff < sVar44);
1083: pcVar2[0xb] = (0 < sVar46) * (sVar46 < 0xff) * SUB161(auVar120 >> 0x30,0) -
1084: (0xff < sVar46);
1085: pcVar2[0xc] = (0 < sVar48) * (sVar48 < 0xff) * SUB161(auVar120 >> 0x40,0) -
1086: (0xff < sVar48);
1087: pcVar2[0xd] = (0 < sVar50) * (sVar50 < 0xff) * SUB161(auVar120 >> 0x50,0) -
1088: (0xff < sVar50);
1089: pcVar2[0xe] = (0 < sVar52) * (sVar52 < 0xff) * SUB161(auVar120 >> 0x60,0) -
1090: (0xff < sVar52);
1091: pcVar2[0xf] = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar120 >> 0x70,0) -
1092: (0xff < sVar54);
1093: pcVar2 = puVar6 + lVar57;
1094: *pcVar2 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar88,0) - (0xff < sVar25);
1095: pcVar2[1] = (0 < sVar26) * (sVar26 < 0xff) * SUB161(auVar88 >> 0x10,0) -
1096: (0xff < sVar26);
1097: pcVar2[2] = (0 < sVar28) * (sVar28 < 0xff) * SUB161(auVar88 >> 0x20,0) -
1098: (0xff < sVar28);
1099: pcVar2[3] = (0 < sVar31) * (sVar31 < 0xff) * SUB161(auVar88 >> 0x30,0) -
1100: (0xff < sVar31);
1101: pcVar2[4] = (0 < sVar33) * (sVar33 < 0xff) * SUB161(auVar88 >> 0x40,0) -
1102: (0xff < sVar33);
1103: pcVar2[5] = (0 < sVar35) * (sVar35 < 0xff) * SUB161(auVar88 >> 0x50,0) -
1104: (0xff < sVar35);
1105: pcVar2[6] = (0 < sVar37) * (sVar37 < 0xff) * SUB161(auVar88 >> 0x60,0) -
1106: (0xff < sVar37);
1107: pcVar2[7] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar88 >> 0x70,0) -
1108: (0xff < sVar39);
1109: pcVar2[8] = (0 < sVar41) * (sVar41 < 0xff) * SUB161(auVar121,0) - (0xff < sVar41);
1110: pcVar2[9] = (0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar121 >> 0x10,0) -
1111: (0xff < sVar43);
1112: pcVar2[10] = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar121 >> 0x20,0) -
1113: (0xff < sVar45);
1114: pcVar2[0xb] = (0 < sVar47) * (sVar47 < 0xff) * SUB161(auVar121 >> 0x30,0) -
1115: (0xff < sVar47);
1116: pcVar2[0xc] = (0 < sVar49) * (sVar49 < 0xff) * SUB161(auVar121 >> 0x40,0) -
1117: (0xff < sVar49);
1118: pcVar2[0xd] = (0 < sVar51) * (sVar51 < 0xff) * SUB161(auVar121 >> 0x50,0) -
1119: (0xff < sVar51);
1120: pcVar2[0xe] = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar121 >> 0x60,0) -
1121: (0xff < sVar53);
1122: pcVar2[0xf] = (0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar121 >> 0x70,0) -
1123: (0xff < sVar55);
1124: lVar57 = lVar57 + 0x10;
1125: } while (uVar70 < uVar1 >> 4);
1126: puVar59 = puVar59 + (ulong)(uVar1 & 0xfffffff0) * 4;
1127: uVar70 = uVar1 & 0xfffffff0;
1128: }
1129: uVar63 = (ulong)uVar70;
1130: puVar58[uVar63] = puVar59[2];
1131: puVar60[uVar63] = puVar59[1];
1132: puVar6[uVar63] = *puVar59;
1133: uVar63 = (ulong)(uVar70 + 1);
1134: if (uVar70 + 1 < uVar4) {
1135: puVar58[uVar63] = puVar59[6];
1136: puVar60[uVar63] = puVar59[5];
1137: puVar6[uVar63] = puVar59[4];
1138: uVar63 = (ulong)(uVar70 + 2);
1139: if (uVar70 + 2 < uVar4) {
1140: puVar58[uVar63] = puVar59[10];
1141: puVar60[uVar63] = puVar59[9];
1142: puVar6[uVar63] = puVar59[8];
1143: uVar63 = (ulong)(uVar70 + 3);
1144: if (uVar70 + 3 < uVar4) {
1145: puVar58[uVar63] = puVar59[0xe];
1146: puVar60[uVar63] = puVar59[0xd];
1147: puVar6[uVar63] = puVar59[0xc];
1148: uVar63 = (ulong)(uVar70 + 4);
1149: if (uVar70 + 4 < uVar4) {
1150: puVar58[uVar63] = puVar59[0x12];
1151: puVar60[uVar63] = puVar59[0x11];
1152: puVar6[uVar63] = puVar59[0x10];
1153: uVar63 = (ulong)(uVar70 + 5);
1154: if (uVar70 + 5 < uVar4) {
1155: puVar58[uVar63] = puVar59[0x16];
1156: puVar60[uVar63] = puVar59[0x15];
1157: puVar6[uVar63] = puVar59[0x14];
1158: uVar63 = (ulong)(uVar70 + 6);
1159: if (uVar70 + 6 < uVar4) {
1160: puVar58[uVar63] = puVar59[0x1a];
1161: puVar60[uVar63] = puVar59[0x19];
1162: puVar6[uVar63] = puVar59[0x18];
1163: uVar63 = (ulong)(uVar70 + 7);
1164: if (uVar70 + 7 < uVar4) {
1165: puVar58[uVar63] = puVar59[0x1e];
1166: puVar60[uVar63] = puVar59[0x1d];
1167: puVar6[uVar63] = puVar59[0x1c];
1168: uVar63 = (ulong)(uVar70 + 8);
1169: if (uVar70 + 8 < uVar4) {
1170: puVar58[uVar63] = puVar59[0x22];
1171: puVar60[uVar63] = puVar59[0x21];
1172: puVar6[uVar63] = puVar59[0x20];
1173: uVar63 = (ulong)(uVar70 + 9);
1174: if (uVar70 + 9 < uVar4) {
1175: puVar58[uVar63] = puVar59[0x26];
1176: puVar60[uVar63] = puVar59[0x25];
1177: puVar6[uVar63] = puVar59[0x24];
1178: uVar63 = (ulong)(uVar70 + 10);
1179: if (uVar70 + 10 < uVar4) {
1180: puVar58[uVar63] = puVar59[0x2a];
1181: puVar60[uVar63] = puVar59[0x29];
1182: puVar6[uVar63] = puVar59[0x28];
1183: uVar63 = (ulong)(uVar70 + 0xb);
1184: if (uVar70 + 0xb < uVar4) {
1185: puVar58[uVar63] = puVar59[0x2e];
1186: puVar60[uVar63] = puVar59[0x2d];
1187: puVar6[uVar63] = puVar59[0x2c];
1188: uVar63 = (ulong)(uVar70 + 0xc);
1189: if (uVar70 + 0xc < uVar4) {
1190: puVar58[uVar63] = puVar59[0x32];
1191: puVar60[uVar63] = puVar59[0x31];
1192: puVar6[uVar63] = puVar59[0x30];
1193: uVar63 = (ulong)(uVar70 + 0xd);
1194: if (uVar70 + 0xd < uVar4) {
1195: puVar58[uVar63] = puVar59[0x36];
1196: puVar60[uVar63] = puVar59[0x35];
1197: puVar6[uVar63] = puVar59[0x34];
1198: uVar63 = (ulong)(uVar70 + 0xe);
1199: if (uVar70 + 0xe < uVar4) {
1200: uVar69 = (ulong)(uVar70 + 0xf);
1201: puVar58[uVar63] = puVar59[0x3a];
1202: puVar60[uVar63] = puVar59[0x39];
1203: puVar6[uVar63] = puVar59[0x38];
1204: if (uVar70 + 0xf < uVar4) {
1205: puVar58[uVar69] = puVar59[0x3e];
1206: puVar60[uVar69] = puVar59[0x3d];
1207: puVar6[uVar69] = puVar59[0x3c];
1208: }
1209: }
1210: }
1211: }
1212: }
1213: }
1214: }
1215: }
1216: }
1217: }
1218: }
1219: }
1220: }
1221: }
1222: }
1223: }
1224: }
1225: }
1226: break;
1227: case 10:
1228: case 0xe:
1229: uVar61 = (ulong)uVar4;
1230: uVar1 = uVar4 - 1;
1231: while (param_5 = param_5 + -1, -1 < param_5) {
1232: plVar65 = param_2 + 1;
1233: uVar62 = (ulong)((int)uVar64 + 1);
1234: lVar57 = *param_2;
1235: uVar63 = *(ulong *)(*param_3 + uVar64 * 8);
1236: uVar69 = *(ulong *)(param_3[1] + uVar64 * 8);
1237: uVar5 = *(ulong *)(param_3[2] + uVar64 * 8);
1238: uVar64 = uVar62;
1239: param_2 = plVar65;
1240: if (uVar4 != 0) {
1241: uVar62 = lVar57 + 1;
1242: uVar67 = lVar57 + uVar61 * 4 + 1;
1243: if ((((((uVar62 < uVar63 + uVar61 && uVar63 < uVar67 ||
1244: uVar62 < uVar69 + uVar61 && uVar69 < uVar67) || uVar4 < 0x10) ||
1245: uVar62 < uVar5 + uVar61 && uVar5 < uVar67) ||
1246: uVar69 < uVar63 + 0x10 && uVar63 < uVar69 + 0x10) ||
1247: uVar5 < uVar63 + 0x10 && uVar63 < uVar5 + 0x10) ||
1248: (uVar5 < uVar69 + 0x10 && uVar69 < uVar5 + 0x10)) {
1249: lVar68 = 0;
1250: do {
1251: *(undefined *)(uVar63 + lVar68) = *(undefined *)(lVar57 + 3 + lVar68 * 4);
1252: *(undefined *)(uVar69 + lVar68) = *(undefined *)(lVar57 + 2 + lVar68 * 4);
1253: *(undefined *)(uVar5 + lVar68) = *(undefined *)(lVar57 + 1 + lVar68 * 4);
1254: lVar68 = lVar68 + 1;
1255: } while (lVar68 != (ulong)uVar1 + 1);
1256: }
1257: else {
1258: if (uVar1 < 0x10) {
1259: uVar70 = 0;
1260: }
1261: else {
1262: lVar68 = 0;
1263: uVar70 = 0;
1264: do {
1265: auVar72 = *(undefined (*) [16])(lVar57 + 1 + lVar68 * 4);
1266: uVar70 = uVar70 + 1;
1267: auVar88 = *(undefined (*) [16])(lVar57 + 0x11 + lVar68 * 4);
1268: auVar86 = auVar56 & auVar72;
1269: uVar71 = SUB162(auVar72,0) >> 8;
1270: uVar73 = SUB162(auVar72 >> 0x10,0) >> 8;
1271: uVar74 = SUB162(auVar72 >> 0x20,0) >> 8;
1272: uVar75 = SUB162(auVar72 >> 0x30,0) >> 8;
1273: uVar76 = SUB162(auVar72 >> 0x40,0) >> 8;
1274: uVar77 = SUB162(auVar72 >> 0x50,0) >> 8;
1275: uVar78 = SUB162(auVar72 >> 0x60,0) >> 8;
1276: uVar79 = SUB162(auVar72 >> 0x78,0);
1277: auVar102 = auVar56 & auVar88;
1278: uVar111 = SUB162(auVar88,0) >> 8;
1279: uVar112 = SUB162(auVar88 >> 0x10,0) >> 8;
1280: uVar113 = SUB162(auVar88 >> 0x20,0) >> 8;
1281: uVar114 = SUB162(auVar88 >> 0x30,0) >> 8;
1282: uVar115 = SUB162(auVar88 >> 0x40,0) >> 8;
1283: uVar116 = SUB162(auVar88 >> 0x50,0) >> 8;
1284: uVar117 = SUB162(auVar88 >> 0x60,0) >> 8;
1285: uVar118 = SUB162(auVar88 >> 0x78,0);
1286: auVar120 = *(undefined (*) [16])(lVar57 + 0x21 + lVar68 * 4);
1287: auVar121 = *(undefined (*) [16])(lVar57 + 0x31 + lVar68 * 4);
1288: sVar24 = SUB162(auVar86,0);
1289: sVar25 = SUB162(auVar86 >> 0x10,0);
1290: cVar15 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x10,0) - (0xff < sVar25);
1291: sVar25 = SUB162(auVar86 >> 0x20,0);
1292: sVar29 = SUB162(auVar86 >> 0x30,0);
1293: cVar14 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar86 >> 0x30,0) - (0xff < sVar29);
1294: uVar80 = CONCAT13(cVar14,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
1295: SUB161(auVar86 >> 0x20,0) - (0xff < sVar25),
1296: CONCAT11(cVar15,(0 < sVar24) * (sVar24 < 0xff) *
1297: SUB161(auVar86,0) - (0xff < sVar24))
1298: ));
1299: sVar24 = SUB162(auVar86 >> 0x40,0);
1300: sVar25 = SUB162(auVar86 >> 0x50,0);
1301: cVar13 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x50,0) - (0xff < sVar25);
1302: uVar81 = CONCAT15(cVar13,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
1303: SUB161(auVar86 >> 0x40,0) - (0xff < sVar24),uVar80))
1304: ;
1305: sVar24 = SUB162(auVar86 >> 0x60,0);
1306: sVar25 = SUB162(auVar86 >> 0x70,0);
1307: cVar12 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x70,0) - (0xff < sVar25);
1308: uVar82 = CONCAT17(cVar12,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
1309: SUB161(auVar86 >> 0x60,0) - (0xff < sVar24),uVar81))
1310: ;
1311: sVar24 = SUB162(auVar102,0);
1312: sVar25 = SUB162(auVar102 >> 0x10,0);
1313: cVar11 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
1314: ;
1315: Var83 = CONCAT19(cVar11,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar102,0) -
1316: (0xff < sVar24),uVar82));
1317: sVar24 = SUB162(auVar102 >> 0x20,0);
1318: sVar25 = SUB162(auVar102 >> 0x30,0);
1319: cVar10 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar25)
1320: ;
1321: auVar84 = CONCAT111(cVar10,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
1322: SUB161(auVar102 >> 0x20,0) - (0xff < sVar24),
1323: Var83));
1324: sVar24 = SUB162(auVar102 >> 0x40,0);
1325: sVar25 = SUB162(auVar102 >> 0x50,0);
1326: cVar9 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25);
1327: auVar85 = CONCAT113(cVar9,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
1328: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),
1329: auVar84));
1330: sVar24 = SUB162(auVar102 >> 0x60,0);
1331: sVar25 = SUB162(auVar102 >> 0x70,0);
1332: cVar8 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25);
1333: auVar86 = CONCAT115(cVar8,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
1334: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),
1335: auVar85));
1336: auVar119 = auVar56 & auVar121;
1337: uVar103 = SUB162(auVar121,0) >> 8;
1338: uVar104 = SUB162(auVar121 >> 0x10,0) >> 8;
1339: uVar105 = SUB162(auVar121 >> 0x20,0) >> 8;
1340: uVar106 = SUB162(auVar121 >> 0x30,0) >> 8;
1341: uVar107 = SUB162(auVar121 >> 0x40,0) >> 8;
1342: uVar108 = SUB162(auVar121 >> 0x50,0) >> 8;
1343: uVar109 = SUB162(auVar121 >> 0x60,0) >> 8;
1344: uVar110 = SUB162(auVar121 >> 0x78,0);
1345: auVar102 = auVar56 & auVar120;
1346: uVar87 = SUB162(auVar120,0) >> 8;
1347: uVar89 = SUB162(auVar120 >> 0x10,0) >> 8;
1348: uVar90 = SUB162(auVar120 >> 0x20,0) >> 8;
1349: uVar91 = SUB162(auVar120 >> 0x30,0) >> 8;
1350: uVar92 = SUB162(auVar120 >> 0x40,0) >> 8;
1351: uVar93 = SUB162(auVar120 >> 0x50,0) >> 8;
1352: uVar94 = SUB162(auVar120 >> 0x60,0) >> 8;
1353: uVar95 = SUB162(auVar120 >> 0x78,0);
1354: auVar72 = CONCAT115((uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar88 >> 0x78,0) -
1355: (0xff < uVar118),
1356: CONCAT114((uVar117 != 0) * (uVar117 < 0xff) *
1357: SUB161(auVar88 >> 0x68,0) - (0xff < uVar117),
1358: CONCAT113((uVar116 != 0) * (uVar116 < 0xff) *
1359: SUB161(auVar88 >> 0x58,0) - (0xff < uVar116),
1360: CONCAT112((uVar115 != 0) * (uVar115 < 0xff) *
1361: SUB161(auVar88 >> 0x48,0) -
1362: (0xff < uVar115),
1363: CONCAT111((uVar114 != 0) *
1364: (uVar114 < 0xff) *
1365: SUB161(auVar88 >> 0x38,0)
1366: - (0xff < uVar114),
1367: CONCAT110((uVar113 != 0) *
1368: (uVar113 < 0xff)
1369: * SUB161(auVar88
1370: >> 0x28
1371: ,0) - (0xff < uVar113),
1372: CONCAT19((uVar112 != 0) * (uVar112 < 0xff) *
1373: SUB161(auVar88 >> 0x18,0) -
1374: (0xff < uVar112),
1375: CONCAT18((uVar111 != 0) *
1376: (uVar111 < 0xff) *
1377: SUB161(auVar88 >> 8,0) -
1378: (0xff < uVar111),
1379: CONCAT17((uVar79 != 0) *
1380: (uVar79 < 0xff) *
1381: SUB161(auVar72 >> 0x78,
1382: 0) -
1383: (0xff < uVar79),
1384: CONCAT16((uVar78 != 0)
1385: * (uVar78 < 
1386: 0xff) * SUB161(auVar72 >> 0x68,0) -
1387: (0xff < uVar78),
1388: CONCAT15((uVar77 != 0) * (uVar77 < 0xff) *
1389: SUB161(auVar72 >> 0x58,0) -
1390: (0xff < uVar77),
1391: CONCAT14((uVar76 != 0) * (uVar76 < 0xff)
1392: * SUB161(auVar72 >> 0x48,0) -
1393: (0xff < uVar76),
1394: CONCAT13((uVar75 != 0) *
1395: (uVar75 < 0xff) *
1396: SUB161(auVar72 >> 0x38,
1397: 0) -
1398: (0xff < uVar75),
1399: CONCAT12((uVar74 != 0)
1400: * (uVar74 < 
1401: 0xff) * SUB161(auVar72 >> 0x28,0) -
1402: (0xff < uVar74),
1403: CONCAT11((uVar73 != 0) * (uVar73 < 0xff) *
1404: SUB161(auVar72 >> 0x18,0) -
1405: (0xff < uVar73),
1406: (uVar71 != 0) * (uVar71 < 0xff) *
1407: SUB161(auVar72 >> 8,0) - (0xff < uVar71))
1408: )))))))))))))) & auVar56;
1409: sVar24 = SUB162(auVar102,0);
1410: sVar25 = SUB162(auVar102 >> 0x10,0);
1411: cVar23 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
1412: ;
1413: sVar25 = SUB162(auVar102 >> 0x20,0);
1414: sVar29 = SUB162(auVar102 >> 0x30,0);
1415: cVar22 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar29)
1416: ;
1417: uVar96 = CONCAT13(cVar22,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
1418: SUB161(auVar102 >> 0x20,0) - (0xff < sVar25),
1419: CONCAT11(cVar23,(0 < sVar24) * (sVar24 < 0xff) *
1420: SUB161(auVar102,0) - (0xff < sVar24)
1421: )));
1422: sVar24 = SUB162(auVar102 >> 0x40,0);
1423: sVar25 = SUB162(auVar102 >> 0x50,0);
1424: cVar21 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25)
1425: ;
1426: uVar97 = CONCAT15(cVar21,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
1427: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),uVar96)
1428: );
1429: sVar24 = SUB162(auVar102 >> 0x60,0);
1430: sVar25 = SUB162(auVar102 >> 0x70,0);
1431: cVar20 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25)
1432: ;
1433: uVar98 = CONCAT17(cVar20,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
1434: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),uVar97)
1435: );
1436: sVar24 = SUB162(auVar119,0);
1437: sVar25 = SUB162(auVar119 >> 0x10,0);
1438: cVar19 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x10,0) - (0xff < sVar25)
1439: ;
1440: Var99 = CONCAT19(cVar19,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar119,0) -
1441: (0xff < sVar24),uVar98));
1442: sVar24 = SUB162(auVar119 >> 0x20,0);
1443: sVar25 = SUB162(auVar119 >> 0x30,0);
1444: cVar18 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x30,0) - (0xff < sVar25)
1445: ;
1446: auVar100 = CONCAT111(cVar18,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
1447: SUB161(auVar119 >> 0x20,0) - (0xff < sVar24),
1448: Var99));
1449: sVar24 = SUB162(auVar119 >> 0x40,0);
1450: sVar25 = SUB162(auVar119 >> 0x50,0);
1451: cVar17 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x50,0) - (0xff < sVar25)
1452: ;
1453: auVar101 = CONCAT113(cVar17,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
1454: SUB161(auVar119 >> 0x40,0) - (0xff < sVar24),
1455: auVar100));
1456: sVar24 = SUB162(auVar119 >> 0x60,0);
1457: sVar25 = SUB162(auVar119 >> 0x70,0);
1458: cVar16 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x70,0) - (0xff < sVar25)
1459: ;
1460: auVar102 = CONCAT115(cVar16,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
1461: SUB161(auVar119 >> 0x60,0) - (0xff < sVar24),
1462: auVar101));
1463: auVar120 = CONCAT115((uVar110 != 0) * (uVar110 < 0xff) * SUB161(auVar121 >> 0x78,0) -
1464: (0xff < uVar110),
1465: CONCAT114((uVar109 != 0) * (uVar109 < 0xff) *
1466: SUB161(auVar121 >> 0x68,0) - (0xff < uVar109),
1467: CONCAT113((uVar108 != 0) * (uVar108 < 0xff) *
1468: SUB161(auVar121 >> 0x58,0) - (0xff < uVar108)
1469: ,CONCAT112((uVar107 != 0) * (uVar107 < 0xff)
1470: * SUB161(auVar121 >> 0x48,0) -
1471: (0xff < uVar107),
1472: CONCAT111((uVar106 != 0) *
1473: (uVar106 < 0xff) *
1474: SUB161(auVar121 >> 0x38,
1475: 0) -
1476: (0xff < uVar106),
1477: CONCAT110((uVar105 != 0)
1478: * (uVar105 <
1479: 0xff) * 
1480: SUB161(auVar121 >> 0x28,0) - (0xff < uVar105),
1481: CONCAT19((uVar104 != 0) * (uVar104 < 0xff) *
1482: SUB161(auVar121 >> 0x18,0) -
1483: (0xff < uVar104),
1484: CONCAT18((uVar103 != 0) *
1485: (uVar103 < 0xff) *
1486: SUB161(auVar121 >> 8,0) -
1487: (0xff < uVar103),
1488: CONCAT17((uVar95 != 0) *
1489: (uVar95 < 0xff) *
1490: SUB161(auVar120 >> 0x78
1491: ,0) -
1492: (0xff < uVar95),
1493: CONCAT16((uVar94 != 0)
1494: * (uVar94 < 
1495: 0xff) * SUB161(auVar120 >> 0x68,0) -
1496: (0xff < uVar94),
1497: CONCAT15((uVar93 != 0) * (uVar93 < 0xff) *
1498: SUB161(auVar120 >> 0x58,0) -
1499: (0xff < uVar93),
1500: CONCAT14((uVar92 != 0) * (uVar92 < 0xff)
1501: * SUB161(auVar120 >> 0x48,0) -
1502: (0xff < uVar92),
1503: CONCAT13((uVar91 != 0) *
1504: (uVar91 < 0xff) *
1505: SUB161(auVar120 >> 0x38
1506: ,0) -
1507: (0xff < uVar91),
1508: CONCAT12((uVar90 != 0)
1509: * (uVar90 < 
1510: 0xff) * SUB161(auVar120 >> 0x28,0) -
1511: (0xff < uVar90),
1512: CONCAT11((uVar89 != 0) * (uVar89 < 0xff) *
1513: SUB161(auVar120 >> 0x18,0) -
1514: (0xff < uVar89),
1515: (uVar87 != 0) * (uVar87 < 0xff) *
1516: SUB161(auVar120 >> 8,0) - (0xff < uVar87)
1517: ))))))))))))))) & auVar56;
1518: auVar88 = auVar86 & auVar56;
1519: uVar71 = (ushort)((uint)uVar80 >> 0x18);
1520: uVar73 = (ushort)((uint6)uVar81 >> 0x28);
1521: uVar74 = (ushort)((ulong)uVar82 >> 0x38);
1522: uVar75 = (ushort)((unkuint10)Var83 >> 0x48);
1523: uVar76 = SUB122(auVar84 >> 0x58,0);
1524: uVar77 = SUB142(auVar85 >> 0x68,0);
1525: uVar78 = SUB162(auVar86 >> 0x78,0);
1526: auVar121 = auVar102 & auVar56;
1527: sVar24 = SUB162(auVar72,0);
1528: sVar29 = SUB162(auVar72 >> 0x10,0);
1529: sVar27 = SUB162(auVar72 >> 0x20,0);
1530: sVar30 = SUB162(auVar72 >> 0x30,0);
1531: sVar32 = SUB162(auVar72 >> 0x40,0);
1532: sVar34 = SUB162(auVar72 >> 0x50,0);
1533: sVar36 = SUB162(auVar72 >> 0x60,0);
1534: sVar38 = SUB162(auVar72 >> 0x70,0);
1535: sVar40 = SUB162(auVar120,0);
1536: sVar42 = SUB162(auVar120 >> 0x10,0);
1537: sVar44 = SUB162(auVar120 >> 0x20,0);
1538: sVar46 = SUB162(auVar120 >> 0x30,0);
1539: sVar48 = SUB162(auVar120 >> 0x40,0);
1540: sVar50 = SUB162(auVar120 >> 0x50,0);
1541: sVar52 = SUB162(auVar120 >> 0x60,0);
1542: sVar54 = SUB162(auVar120 >> 0x70,0);
1543: uVar79 = (ushort)((uint)uVar96 >> 0x18);
1544: uVar87 = (ushort)((uint6)uVar97 >> 0x28);
1545: uVar89 = (ushort)((ulong)uVar98 >> 0x38);
1546: uVar90 = (ushort)((unkuint10)Var99 >> 0x48);
1547: uVar91 = SUB122(auVar100 >> 0x58,0);
1548: uVar92 = SUB142(auVar101 >> 0x68,0);
1549: uVar93 = SUB162(auVar102 >> 0x78,0);
1550: sVar25 = SUB162(auVar88,0);
1551: sVar26 = SUB162(auVar88 >> 0x10,0);
1552: sVar28 = SUB162(auVar88 >> 0x20,0);
1553: sVar31 = SUB162(auVar88 >> 0x30,0);
1554: sVar33 = SUB162(auVar88 >> 0x40,0);
1555: sVar35 = SUB162(auVar88 >> 0x50,0);
1556: sVar37 = SUB162(auVar88 >> 0x60,0);
1557: sVar39 = SUB162(auVar88 >> 0x70,0);
1558: sVar41 = SUB162(auVar121,0);
1559: sVar43 = SUB162(auVar121 >> 0x10,0);
1560: sVar45 = SUB162(auVar121 >> 0x20,0);
1561: sVar47 = SUB162(auVar121 >> 0x30,0);
1562: sVar49 = SUB162(auVar121 >> 0x40,0);
1563: sVar51 = SUB162(auVar121 >> 0x50,0);
1564: sVar53 = SUB162(auVar121 >> 0x60,0);
1565: sVar55 = SUB162(auVar121 >> 0x70,0);
1566: pcVar2 = (char *)(uVar63 + lVar68);
1567: *pcVar2 = (cVar15 != '\0') * (cVar15 != -1) * cVar15;
1568: pcVar2[1] = (uVar71 != 0) * (uVar71 < 0xff) * cVar14 - (0xff < uVar71);
1569: pcVar2[2] = (uVar73 != 0) * (uVar73 < 0xff) * cVar13 - (0xff < uVar73);
1570: pcVar2[3] = (uVar74 != 0) * (uVar74 < 0xff) * cVar12 - (0xff < uVar74);
1571: pcVar2[4] = (uVar75 != 0) * (uVar75 < 0xff) * cVar11 - (0xff < uVar75);
1572: pcVar2[5] = (uVar76 != 0) * (uVar76 < 0xff) * cVar10 - (0xff < uVar76);
1573: pcVar2[6] = (uVar77 != 0) * (uVar77 < 0xff) * cVar9 - (0xff < uVar77);
1574: pcVar2[7] = (uVar78 != 0) * (uVar78 < 0xff) * cVar8 - (0xff < uVar78);
1575: pcVar2[8] = (cVar23 != '\0') * (cVar23 != -1) * cVar23;
1576: pcVar2[9] = (uVar79 != 0) * (uVar79 < 0xff) * cVar22 - (0xff < uVar79);
1577: pcVar2[10] = (uVar87 != 0) * (uVar87 < 0xff) * cVar21 - (0xff < uVar87);
1578: pcVar2[0xb] = (uVar89 != 0) * (uVar89 < 0xff) * cVar20 - (0xff < uVar89);
1579: pcVar2[0xc] = (uVar90 != 0) * (uVar90 < 0xff) * cVar19 - (0xff < uVar90);
1580: pcVar2[0xd] = (uVar91 != 0) * (uVar91 < 0xff) * cVar18 - (0xff < uVar91);
1581: pcVar2[0xe] = (uVar92 != 0) * (uVar92 < 0xff) * cVar17 - (0xff < uVar92);
1582: pcVar2[0xf] = (uVar93 != 0) * (uVar93 < 0xff) * cVar16 - (0xff < uVar93);
1583: pcVar2 = (char *)(uVar69 + lVar68);
1584: *pcVar2 = (0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar72,0) - (0xff < sVar24);
1585: pcVar2[1] = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar72 >> 0x10,0) -
1586: (0xff < sVar29);
1587: pcVar2[2] = (0 < sVar27) * (sVar27 < 0xff) * SUB161(auVar72 >> 0x20,0) -
1588: (0xff < sVar27);
1589: pcVar2[3] = (0 < sVar30) * (sVar30 < 0xff) * SUB161(auVar72 >> 0x30,0) -
1590: (0xff < sVar30);
1591: pcVar2[4] = (0 < sVar32) * (sVar32 < 0xff) * SUB161(auVar72 >> 0x40,0) -
1592: (0xff < sVar32);
1593: pcVar2[5] = (0 < sVar34) * (sVar34 < 0xff) * SUB161(auVar72 >> 0x50,0) -
1594: (0xff < sVar34);
1595: pcVar2[6] = (0 < sVar36) * (sVar36 < 0xff) * SUB161(auVar72 >> 0x60,0) -
1596: (0xff < sVar36);
1597: pcVar2[7] = (0 < sVar38) * (sVar38 < 0xff) * SUB161(auVar72 >> 0x70,0) -
1598: (0xff < sVar38);
1599: pcVar2[8] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar120,0) - (0xff < sVar40);
1600: pcVar2[9] = (0 < sVar42) * (sVar42 < 0xff) * SUB161(auVar120 >> 0x10,0) -
1601: (0xff < sVar42);
1602: pcVar2[10] = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar120 >> 0x20,0) -
1603: (0xff < sVar44);
1604: pcVar2[0xb] = (0 < sVar46) * (sVar46 < 0xff) * SUB161(auVar120 >> 0x30,0) -
1605: (0xff < sVar46);
1606: pcVar2[0xc] = (0 < sVar48) * (sVar48 < 0xff) * SUB161(auVar120 >> 0x40,0) -
1607: (0xff < sVar48);
1608: pcVar2[0xd] = (0 < sVar50) * (sVar50 < 0xff) * SUB161(auVar120 >> 0x50,0) -
1609: (0xff < sVar50);
1610: pcVar2[0xe] = (0 < sVar52) * (sVar52 < 0xff) * SUB161(auVar120 >> 0x60,0) -
1611: (0xff < sVar52);
1612: pcVar2[0xf] = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar120 >> 0x70,0) -
1613: (0xff < sVar54);
1614: pcVar2 = (char *)(uVar5 + lVar68);
1615: *pcVar2 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar88,0) - (0xff < sVar25);
1616: pcVar2[1] = (0 < sVar26) * (sVar26 < 0xff) * SUB161(auVar88 >> 0x10,0) -
1617: (0xff < sVar26);
1618: pcVar2[2] = (0 < sVar28) * (sVar28 < 0xff) * SUB161(auVar88 >> 0x20,0) -
1619: (0xff < sVar28);
1620: pcVar2[3] = (0 < sVar31) * (sVar31 < 0xff) * SUB161(auVar88 >> 0x30,0) -
1621: (0xff < sVar31);
1622: pcVar2[4] = (0 < sVar33) * (sVar33 < 0xff) * SUB161(auVar88 >> 0x40,0) -
1623: (0xff < sVar33);
1624: pcVar2[5] = (0 < sVar35) * (sVar35 < 0xff) * SUB161(auVar88 >> 0x50,0) -
1625: (0xff < sVar35);
1626: pcVar2[6] = (0 < sVar37) * (sVar37 < 0xff) * SUB161(auVar88 >> 0x60,0) -
1627: (0xff < sVar37);
1628: pcVar2[7] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar88 >> 0x70,0) -
1629: (0xff < sVar39);
1630: pcVar2[8] = (0 < sVar41) * (sVar41 < 0xff) * SUB161(auVar121,0) - (0xff < sVar41);
1631: pcVar2[9] = (0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar121 >> 0x10,0) -
1632: (0xff < sVar43);
1633: pcVar2[10] = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar121 >> 0x20,0) -
1634: (0xff < sVar45);
1635: pcVar2[0xb] = (0 < sVar47) * (sVar47 < 0xff) * SUB161(auVar121 >> 0x30,0) -
1636: (0xff < sVar47);
1637: pcVar2[0xc] = (0 < sVar49) * (sVar49 < 0xff) * SUB161(auVar121 >> 0x40,0) -
1638: (0xff < sVar49);
1639: pcVar2[0xd] = (0 < sVar51) * (sVar51 < 0xff) * SUB161(auVar121 >> 0x50,0) -
1640: (0xff < sVar51);
1641: pcVar2[0xe] = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar121 >> 0x60,0) -
1642: (0xff < sVar53);
1643: pcVar2[0xf] = (0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar121 >> 0x70,0) -
1644: (0xff < sVar55);
1645: lVar68 = lVar68 + 0x10;
1646: } while (uVar70 < uVar1 >> 4);
1647: lVar57 = lVar57 + (ulong)(uVar1 & 0xfffffff0) * 4;
1648: uVar70 = uVar1 & 0xfffffff0;
1649: }
1650: uVar62 = (ulong)uVar70;
1651: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 3);
1652: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 2);
1653: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 1);
1654: uVar62 = (ulong)(uVar70 + 1);
1655: if (uVar70 + 1 < uVar4) {
1656: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 7);
1657: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 6);
1658: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 5);
1659: uVar62 = (ulong)(uVar70 + 2);
1660: if (uVar70 + 2 < uVar4) {
1661: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0xb);
1662: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 10);
1663: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 9);
1664: uVar62 = (ulong)(uVar70 + 3);
1665: if (uVar70 + 3 < uVar4) {
1666: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0xf);
1667: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0xe);
1668: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0xd);
1669: uVar62 = (ulong)(uVar70 + 4);
1670: if (uVar70 + 4 < uVar4) {
1671: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x13);
1672: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x12);
1673: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x11);
1674: uVar62 = (ulong)(uVar70 + 5);
1675: if (uVar70 + 5 < uVar4) {
1676: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x17);
1677: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x16);
1678: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x15);
1679: uVar62 = (ulong)(uVar70 + 6);
1680: if (uVar70 + 6 < uVar4) {
1681: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x1b);
1682: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x1a);
1683: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x19);
1684: uVar62 = (ulong)(uVar70 + 7);
1685: if (uVar70 + 7 < uVar4) {
1686: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x1f);
1687: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x1e);
1688: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x1d);
1689: uVar62 = (ulong)(uVar70 + 8);
1690: if (uVar70 + 8 < uVar4) {
1691: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x23);
1692: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x22);
1693: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x21);
1694: uVar62 = (ulong)(uVar70 + 9);
1695: if (uVar70 + 9 < uVar4) {
1696: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x27);
1697: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x26);
1698: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x25);
1699: uVar62 = (ulong)(uVar70 + 10);
1700: if (uVar70 + 10 < uVar4) {
1701: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x2b);
1702: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x2a);
1703: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x29);
1704: uVar62 = (ulong)(uVar70 + 0xb);
1705: if (uVar70 + 0xb < uVar4) {
1706: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x2f);
1707: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x2e);
1708: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x2d);
1709: uVar62 = (ulong)(uVar70 + 0xc);
1710: if (uVar70 + 0xc < uVar4) {
1711: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x33);
1712: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x32);
1713: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x31);
1714: uVar62 = (ulong)(uVar70 + 0xd);
1715: if (uVar70 + 0xd < uVar4) {
1716: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x37);
1717: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x36);
1718: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x35);
1719: uVar62 = (ulong)(uVar70 + 0xe);
1720: if (uVar70 + 0xe < uVar4) {
1721: uVar67 = (ulong)(uVar70 + 0xf);
1722: *(undefined *)(uVar63 + uVar62) =
1723: *(undefined *)(lVar57 + 0x3b);
1724: *(undefined *)(uVar69 + uVar62) =
1725: *(undefined *)(lVar57 + 0x3a);
1726: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x39)
1727: ;
1728: if (uVar70 + 0xf < uVar4) {
1729: *(undefined *)(uVar63 + uVar67) =
1730: *(undefined *)(lVar57 + 0x3f);
1731: *(undefined *)(uVar69 + uVar67) =
1732: *(undefined *)(lVar57 + 0x3e);
1733: *(undefined *)(uVar5 + uVar67) =
1734: *(undefined *)(lVar57 + 0x3d);
1735: }
1736: }
1737: }
1738: }
1739: }
1740: }
1741: }
1742: }
1743: }
1744: }
1745: }
1746: }
1747: }
1748: }
1749: }
1750: }
1751: }
1752: }
1753: break;
1754: case 0xb:
1755: case 0xf:
1756: uVar61 = (ulong)uVar4;
1757: uVar1 = uVar4 - 1;
1758: while (param_5 = param_5 + -1, -1 < param_5) {
1759: plVar65 = param_2 + 1;
1760: uVar62 = (ulong)((int)uVar64 + 1);
1761: lVar57 = *param_2;
1762: uVar63 = *(ulong *)(*param_3 + uVar64 * 8);
1763: uVar69 = *(ulong *)(param_3[1] + uVar64 * 8);
1764: uVar5 = *(ulong *)(param_3[2] + uVar64 * 8);
1765: uVar64 = uVar62;
1766: param_2 = plVar65;
1767: if (uVar4 != 0) {
1768: uVar62 = lVar57 + 1;
1769: uVar67 = lVar57 + uVar61 * 4 + 1;
1770: if ((((((uVar62 < uVar63 + uVar61 && uVar63 < uVar67 ||
1771: uVar62 < uVar69 + uVar61 && uVar69 < uVar67) || uVar4 < 0x10) ||
1772: uVar62 < uVar5 + uVar61 && uVar5 < uVar67) ||
1773: uVar69 < uVar63 + 0x10 && uVar63 < uVar69 + 0x10) ||
1774: uVar5 < uVar63 + 0x10 && uVar63 < uVar5 + 0x10) ||
1775: (uVar5 < uVar69 + 0x10 && uVar69 < uVar5 + 0x10)) {
1776: lVar68 = 0;
1777: do {
1778: *(undefined *)(uVar63 + lVar68) = *(undefined *)(lVar57 + 1 + lVar68 * 4);
1779: *(undefined *)(uVar69 + lVar68) = *(undefined *)(lVar57 + 2 + lVar68 * 4);
1780: *(undefined *)(uVar5 + lVar68) = *(undefined *)(lVar57 + 3 + lVar68 * 4);
1781: lVar68 = lVar68 + 1;
1782: } while (lVar68 != (ulong)uVar1 + 1);
1783: }
1784: else {
1785: if (uVar1 < 0x10) {
1786: uVar70 = 0;
1787: }
1788: else {
1789: lVar68 = 0;
1790: uVar70 = 0;
1791: do {
1792: auVar72 = *(undefined (*) [16])(lVar57 + 1 + lVar68 * 4);
1793: uVar70 = uVar70 + 1;
1794: auVar88 = *(undefined (*) [16])(lVar57 + 0x11 + lVar68 * 4);
1795: auVar86 = auVar56 & auVar72;
1796: uVar71 = SUB162(auVar72,0) >> 8;
1797: uVar73 = SUB162(auVar72 >> 0x10,0) >> 8;
1798: uVar74 = SUB162(auVar72 >> 0x20,0) >> 8;
1799: uVar75 = SUB162(auVar72 >> 0x30,0) >> 8;
1800: uVar76 = SUB162(auVar72 >> 0x40,0) >> 8;
1801: uVar77 = SUB162(auVar72 >> 0x50,0) >> 8;
1802: uVar78 = SUB162(auVar72 >> 0x60,0) >> 8;
1803: uVar79 = SUB162(auVar72 >> 0x78,0);
1804: auVar102 = auVar56 & auVar88;
1805: uVar111 = SUB162(auVar88,0) >> 8;
1806: uVar112 = SUB162(auVar88 >> 0x10,0) >> 8;
1807: uVar113 = SUB162(auVar88 >> 0x20,0) >> 8;
1808: uVar114 = SUB162(auVar88 >> 0x30,0) >> 8;
1809: uVar115 = SUB162(auVar88 >> 0x40,0) >> 8;
1810: uVar116 = SUB162(auVar88 >> 0x50,0) >> 8;
1811: uVar117 = SUB162(auVar88 >> 0x60,0) >> 8;
1812: uVar118 = SUB162(auVar88 >> 0x78,0);
1813: auVar120 = *(undefined (*) [16])(lVar57 + 0x21 + lVar68 * 4);
1814: auVar121 = *(undefined (*) [16])(lVar57 + 0x31 + lVar68 * 4);
1815: sVar24 = SUB162(auVar86,0);
1816: sVar25 = SUB162(auVar86 >> 0x10,0);
1817: cVar8 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x10,0) - (0xff < sVar25);
1818: sVar25 = SUB162(auVar86 >> 0x20,0);
1819: sVar29 = SUB162(auVar86 >> 0x30,0);
1820: cVar9 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar86 >> 0x30,0) - (0xff < sVar29);
1821: uVar80 = CONCAT13(cVar9,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
1822: SUB161(auVar86 >> 0x20,0) - (0xff < sVar25),
1823: CONCAT11(cVar8,(0 < sVar24) * (sVar24 < 0xff) *
1824: SUB161(auVar86,0) - (0xff < sVar24))))
1825: ;
1826: sVar24 = SUB162(auVar86 >> 0x40,0);
1827: sVar25 = SUB162(auVar86 >> 0x50,0);
1828: cVar10 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x50,0) - (0xff < sVar25);
1829: uVar81 = CONCAT15(cVar10,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
1830: SUB161(auVar86 >> 0x40,0) - (0xff < sVar24),uVar80))
1831: ;
1832: sVar24 = SUB162(auVar86 >> 0x60,0);
1833: sVar25 = SUB162(auVar86 >> 0x70,0);
1834: cVar11 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar86 >> 0x70,0) - (0xff < sVar25);
1835: uVar82 = CONCAT17(cVar11,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
1836: SUB161(auVar86 >> 0x60,0) - (0xff < sVar24),uVar81))
1837: ;
1838: sVar24 = SUB162(auVar102,0);
1839: sVar25 = SUB162(auVar102 >> 0x10,0);
1840: cVar12 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
1841: ;
1842: Var83 = CONCAT19(cVar12,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar102,0) -
1843: (0xff < sVar24),uVar82));
1844: sVar24 = SUB162(auVar102 >> 0x20,0);
1845: sVar25 = SUB162(auVar102 >> 0x30,0);
1846: cVar13 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar25)
1847: ;
1848: auVar84 = CONCAT111(cVar13,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
1849: SUB161(auVar102 >> 0x20,0) - (0xff < sVar24),
1850: Var83));
1851: sVar24 = SUB162(auVar102 >> 0x40,0);
1852: sVar25 = SUB162(auVar102 >> 0x50,0);
1853: cVar14 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25)
1854: ;
1855: auVar85 = CONCAT113(cVar14,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
1856: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),
1857: auVar84));
1858: sVar24 = SUB162(auVar102 >> 0x60,0);
1859: sVar25 = SUB162(auVar102 >> 0x70,0);
1860: cVar15 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25)
1861: ;
1862: auVar86 = CONCAT115(cVar15,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
1863: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),
1864: auVar85));
1865: auVar119 = auVar56 & auVar121;
1866: uVar103 = SUB162(auVar121,0) >> 8;
1867: uVar104 = SUB162(auVar121 >> 0x10,0) >> 8;
1868: uVar105 = SUB162(auVar121 >> 0x20,0) >> 8;
1869: uVar106 = SUB162(auVar121 >> 0x30,0) >> 8;
1870: uVar107 = SUB162(auVar121 >> 0x40,0) >> 8;
1871: uVar108 = SUB162(auVar121 >> 0x50,0) >> 8;
1872: uVar109 = SUB162(auVar121 >> 0x60,0) >> 8;
1873: uVar110 = SUB162(auVar121 >> 0x78,0);
1874: auVar102 = auVar56 & auVar120;
1875: uVar87 = SUB162(auVar120,0) >> 8;
1876: uVar89 = SUB162(auVar120 >> 0x10,0) >> 8;
1877: uVar90 = SUB162(auVar120 >> 0x20,0) >> 8;
1878: uVar91 = SUB162(auVar120 >> 0x30,0) >> 8;
1879: uVar92 = SUB162(auVar120 >> 0x40,0) >> 8;
1880: uVar93 = SUB162(auVar120 >> 0x50,0) >> 8;
1881: uVar94 = SUB162(auVar120 >> 0x60,0) >> 8;
1882: uVar95 = SUB162(auVar120 >> 0x78,0);
1883: auVar72 = CONCAT115((uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar88 >> 0x78,0) -
1884: (0xff < uVar118),
1885: CONCAT114((uVar117 != 0) * (uVar117 < 0xff) *
1886: SUB161(auVar88 >> 0x68,0) - (0xff < uVar117),
1887: CONCAT113((uVar116 != 0) * (uVar116 < 0xff) *
1888: SUB161(auVar88 >> 0x58,0) - (0xff < uVar116),
1889: CONCAT112((uVar115 != 0) * (uVar115 < 0xff) *
1890: SUB161(auVar88 >> 0x48,0) -
1891: (0xff < uVar115),
1892: CONCAT111((uVar114 != 0) *
1893: (uVar114 < 0xff) *
1894: SUB161(auVar88 >> 0x38,0)
1895: - (0xff < uVar114),
1896: CONCAT110((uVar113 != 0) *
1897: (uVar113 < 0xff)
1898: * SUB161(auVar88
1899: >> 0x28
1900: ,0) - (0xff < uVar113),
1901: CONCAT19((uVar112 != 0) * (uVar112 < 0xff) *
1902: SUB161(auVar88 >> 0x18,0) -
1903: (0xff < uVar112),
1904: CONCAT18((uVar111 != 0) *
1905: (uVar111 < 0xff) *
1906: SUB161(auVar88 >> 8,0) -
1907: (0xff < uVar111),
1908: CONCAT17((uVar79 != 0) *
1909: (uVar79 < 0xff) *
1910: SUB161(auVar72 >> 0x78,
1911: 0) -
1912: (0xff < uVar79),
1913: CONCAT16((uVar78 != 0)
1914: * (uVar78 < 
1915: 0xff) * SUB161(auVar72 >> 0x68,0) -
1916: (0xff < uVar78),
1917: CONCAT15((uVar77 != 0) * (uVar77 < 0xff) *
1918: SUB161(auVar72 >> 0x58,0) -
1919: (0xff < uVar77),
1920: CONCAT14((uVar76 != 0) * (uVar76 < 0xff)
1921: * SUB161(auVar72 >> 0x48,0) -
1922: (0xff < uVar76),
1923: CONCAT13((uVar75 != 0) *
1924: (uVar75 < 0xff) *
1925: SUB161(auVar72 >> 0x38,
1926: 0) -
1927: (0xff < uVar75),
1928: CONCAT12((uVar74 != 0)
1929: * (uVar74 < 
1930: 0xff) * SUB161(auVar72 >> 0x28,0) -
1931: (0xff < uVar74),
1932: CONCAT11((uVar73 != 0) * (uVar73 < 0xff) *
1933: SUB161(auVar72 >> 0x18,0) -
1934: (0xff < uVar73),
1935: (uVar71 != 0) * (uVar71 < 0xff) *
1936: SUB161(auVar72 >> 8,0) - (0xff < uVar71))
1937: )))))))))))))) & auVar56;
1938: sVar24 = SUB162(auVar102,0);
1939: sVar25 = SUB162(auVar102 >> 0x10,0);
1940: cVar16 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x10,0) - (0xff < sVar25)
1941: ;
1942: sVar25 = SUB162(auVar102 >> 0x20,0);
1943: sVar29 = SUB162(auVar102 >> 0x30,0);
1944: cVar17 = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar102 >> 0x30,0) - (0xff < sVar29)
1945: ;
1946: uVar96 = CONCAT13(cVar17,CONCAT12((0 < sVar25) * (sVar25 < 0xff) *
1947: SUB161(auVar102 >> 0x20,0) - (0xff < sVar25),
1948: CONCAT11(cVar16,(0 < sVar24) * (sVar24 < 0xff) *
1949: SUB161(auVar102,0) - (0xff < sVar24)
1950: )));
1951: sVar24 = SUB162(auVar102 >> 0x40,0);
1952: sVar25 = SUB162(auVar102 >> 0x50,0);
1953: cVar18 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x50,0) - (0xff < sVar25)
1954: ;
1955: uVar97 = CONCAT15(cVar18,CONCAT14((0 < sVar24) * (sVar24 < 0xff) *
1956: SUB161(auVar102 >> 0x40,0) - (0xff < sVar24),uVar96)
1957: );
1958: sVar24 = SUB162(auVar102 >> 0x60,0);
1959: sVar25 = SUB162(auVar102 >> 0x70,0);
1960: cVar19 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar102 >> 0x70,0) - (0xff < sVar25)
1961: ;
1962: uVar98 = CONCAT17(cVar19,CONCAT16((0 < sVar24) * (sVar24 < 0xff) *
1963: SUB161(auVar102 >> 0x60,0) - (0xff < sVar24),uVar97)
1964: );
1965: sVar24 = SUB162(auVar119,0);
1966: sVar25 = SUB162(auVar119 >> 0x10,0);
1967: cVar20 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x10,0) - (0xff < sVar25)
1968: ;
1969: Var99 = CONCAT19(cVar20,CONCAT18((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar119,0) -
1970: (0xff < sVar24),uVar98));
1971: sVar24 = SUB162(auVar119 >> 0x20,0);
1972: sVar25 = SUB162(auVar119 >> 0x30,0);
1973: cVar21 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x30,0) - (0xff < sVar25)
1974: ;
1975: auVar100 = CONCAT111(cVar21,CONCAT110((0 < sVar24) * (sVar24 < 0xff) *
1976: SUB161(auVar119 >> 0x20,0) - (0xff < sVar24),
1977: Var99));
1978: sVar24 = SUB162(auVar119 >> 0x40,0);
1979: sVar25 = SUB162(auVar119 >> 0x50,0);
1980: cVar22 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x50,0) - (0xff < sVar25)
1981: ;
1982: auVar101 = CONCAT113(cVar22,CONCAT112((0 < sVar24) * (sVar24 < 0xff) *
1983: SUB161(auVar119 >> 0x40,0) - (0xff < sVar24),
1984: auVar100));
1985: sVar24 = SUB162(auVar119 >> 0x60,0);
1986: sVar25 = SUB162(auVar119 >> 0x70,0);
1987: cVar23 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar119 >> 0x70,0) - (0xff < sVar25)
1988: ;
1989: auVar102 = CONCAT115(cVar23,CONCAT114((0 < sVar24) * (sVar24 < 0xff) *
1990: SUB161(auVar119 >> 0x60,0) - (0xff < sVar24),
1991: auVar101));
1992: auVar88 = CONCAT115((uVar110 != 0) * (uVar110 < 0xff) * SUB161(auVar121 >> 0x78,0) -
1993: (0xff < uVar110),
1994: CONCAT114((uVar109 != 0) * (uVar109 < 0xff) *
1995: SUB161(auVar121 >> 0x68,0) - (0xff < uVar109),
1996: CONCAT113((uVar108 != 0) * (uVar108 < 0xff) *
1997: SUB161(auVar121 >> 0x58,0) - (0xff < uVar108),
1998: CONCAT112((uVar107 != 0) * (uVar107 < 0xff) *
1999: SUB161(auVar121 >> 0x48,0) -
2000: (0xff < uVar107),
2001: CONCAT111((uVar106 != 0) *
2002: (uVar106 < 0xff) *
2003: SUB161(auVar121 >> 0x38,0)
2004: - (0xff < uVar106),
2005: CONCAT110((uVar105 != 0) *
2006: (uVar105 < 0xff)
2007: * SUB161(
2008: auVar121 >> 0x28,0) - (0xff < uVar105),
2009: CONCAT19((uVar104 != 0) * (uVar104 < 0xff) *
2010: SUB161(auVar121 >> 0x18,0) -
2011: (0xff < uVar104),
2012: CONCAT18((uVar103 != 0) *
2013: (uVar103 < 0xff) *
2014: SUB161(auVar121 >> 8,0) -
2015: (0xff < uVar103),
2016: CONCAT17((uVar95 != 0) *
2017: (uVar95 < 0xff) *
2018: SUB161(auVar120 >> 0x78
2019: ,0) -
2020: (0xff < uVar95),
2021: CONCAT16((uVar94 != 0)
2022: * (uVar94 < 
2023: 0xff) * SUB161(auVar120 >> 0x68,0) -
2024: (0xff < uVar94),
2025: CONCAT15((uVar93 != 0) * (uVar93 < 0xff) *
2026: SUB161(auVar120 >> 0x58,0) -
2027: (0xff < uVar93),
2028: CONCAT14((uVar92 != 0) * (uVar92 < 0xff)
2029: * SUB161(auVar120 >> 0x48,0) -
2030: (0xff < uVar92),
2031: CONCAT13((uVar91 != 0) *
2032: (uVar91 < 0xff) *
2033: SUB161(auVar120 >> 0x38
2034: ,0) -
2035: (0xff < uVar91),
2036: CONCAT12((uVar90 != 0)
2037: * (uVar90 < 
2038: 0xff) * SUB161(auVar120 >> 0x28,0) -
2039: (0xff < uVar90),
2040: CONCAT11((uVar89 != 0) * (uVar89 < 0xff) *
2041: SUB161(auVar120 >> 0x18,0) -
2042: (0xff < uVar89),
2043: (uVar87 != 0) * (uVar87 < 0xff) *
2044: SUB161(auVar120 >> 8,0) - (0xff < uVar87)
2045: ))))))))))))))) & auVar56;
2046: auVar120 = auVar56 & auVar86;
2047: uVar71 = (ushort)((uint)uVar80 >> 0x18);
2048: uVar73 = (ushort)((uint6)uVar81 >> 0x28);
2049: uVar74 = (ushort)((ulong)uVar82 >> 0x38);
2050: uVar75 = (ushort)((unkuint10)Var83 >> 0x48);
2051: uVar76 = SUB122(auVar84 >> 0x58,0);
2052: uVar77 = SUB142(auVar85 >> 0x68,0);
2053: uVar78 = SUB162(auVar86 >> 0x78,0);
2054: auVar121 = auVar56 & auVar102;
2055: uVar79 = (ushort)((uint)uVar96 >> 0x18);
2056: uVar87 = (ushort)((uint6)uVar97 >> 0x28);
2057: uVar89 = (ushort)((ulong)uVar98 >> 0x38);
2058: uVar90 = (ushort)((unkuint10)Var99 >> 0x48);
2059: uVar91 = SUB122(auVar100 >> 0x58,0);
2060: uVar92 = SUB142(auVar101 >> 0x68,0);
2061: uVar93 = SUB162(auVar102 >> 0x78,0);
2062: sVar24 = SUB162(auVar72,0);
2063: sVar29 = SUB162(auVar72 >> 0x10,0);
2064: sVar27 = SUB162(auVar72 >> 0x20,0);
2065: sVar30 = SUB162(auVar72 >> 0x30,0);
2066: sVar32 = SUB162(auVar72 >> 0x40,0);
2067: sVar34 = SUB162(auVar72 >> 0x50,0);
2068: sVar36 = SUB162(auVar72 >> 0x60,0);
2069: sVar38 = SUB162(auVar72 >> 0x70,0);
2070: sVar40 = SUB162(auVar88,0);
2071: sVar42 = SUB162(auVar88 >> 0x10,0);
2072: sVar44 = SUB162(auVar88 >> 0x20,0);
2073: sVar46 = SUB162(auVar88 >> 0x30,0);
2074: sVar48 = SUB162(auVar88 >> 0x40,0);
2075: sVar50 = SUB162(auVar88 >> 0x50,0);
2076: sVar52 = SUB162(auVar88 >> 0x60,0);
2077: sVar54 = SUB162(auVar88 >> 0x70,0);
2078: sVar25 = SUB162(auVar120,0);
2079: sVar26 = SUB162(auVar120 >> 0x10,0);
2080: sVar28 = SUB162(auVar120 >> 0x20,0);
2081: sVar31 = SUB162(auVar120 >> 0x30,0);
2082: sVar33 = SUB162(auVar120 >> 0x40,0);
2083: sVar35 = SUB162(auVar120 >> 0x50,0);
2084: sVar37 = SUB162(auVar120 >> 0x60,0);
2085: sVar39 = SUB162(auVar120 >> 0x70,0);
2086: sVar41 = SUB162(auVar121,0);
2087: sVar43 = SUB162(auVar121 >> 0x10,0);
2088: sVar45 = SUB162(auVar121 >> 0x20,0);
2089: sVar47 = SUB162(auVar121 >> 0x30,0);
2090: sVar49 = SUB162(auVar121 >> 0x40,0);
2091: sVar51 = SUB162(auVar121 >> 0x50,0);
2092: sVar53 = SUB162(auVar121 >> 0x60,0);
2093: sVar55 = SUB162(auVar121 >> 0x70,0);
2094: pcVar2 = (char *)(uVar63 + lVar68);
2095: *pcVar2 = (0 < sVar25) * (sVar25 < 0xff) * SUB161(auVar120,0) - (0xff < sVar25);
2096: pcVar2[1] = (0 < sVar26) * (sVar26 < 0xff) * SUB161(auVar120 >> 0x10,0) -
2097: (0xff < sVar26);
2098: pcVar2[2] = (0 < sVar28) * (sVar28 < 0xff) * SUB161(auVar120 >> 0x20,0) -
2099: (0xff < sVar28);
2100: pcVar2[3] = (0 < sVar31) * (sVar31 < 0xff) * SUB161(auVar120 >> 0x30,0) -
2101: (0xff < sVar31);
2102: pcVar2[4] = (0 < sVar33) * (sVar33 < 0xff) * SUB161(auVar120 >> 0x40,0) -
2103: (0xff < sVar33);
2104: pcVar2[5] = (0 < sVar35) * (sVar35 < 0xff) * SUB161(auVar120 >> 0x50,0) -
2105: (0xff < sVar35);
2106: pcVar2[6] = (0 < sVar37) * (sVar37 < 0xff) * SUB161(auVar120 >> 0x60,0) -
2107: (0xff < sVar37);
2108: pcVar2[7] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar120 >> 0x70,0) -
2109: (0xff < sVar39);
2110: pcVar2[8] = (0 < sVar41) * (sVar41 < 0xff) * SUB161(auVar121,0) - (0xff < sVar41);
2111: pcVar2[9] = (0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar121 >> 0x10,0) -
2112: (0xff < sVar43);
2113: pcVar2[10] = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar121 >> 0x20,0) -
2114: (0xff < sVar45);
2115: pcVar2[0xb] = (0 < sVar47) * (sVar47 < 0xff) * SUB161(auVar121 >> 0x30,0) -
2116: (0xff < sVar47);
2117: pcVar2[0xc] = (0 < sVar49) * (sVar49 < 0xff) * SUB161(auVar121 >> 0x40,0) -
2118: (0xff < sVar49);
2119: pcVar2[0xd] = (0 < sVar51) * (sVar51 < 0xff) * SUB161(auVar121 >> 0x50,0) -
2120: (0xff < sVar51);
2121: pcVar2[0xe] = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar121 >> 0x60,0) -
2122: (0xff < sVar53);
2123: pcVar2[0xf] = (0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar121 >> 0x70,0) -
2124: (0xff < sVar55);
2125: pcVar2 = (char *)(uVar69 + lVar68);
2126: *pcVar2 = (0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar72,0) - (0xff < sVar24);
2127: pcVar2[1] = (0 < sVar29) * (sVar29 < 0xff) * SUB161(auVar72 >> 0x10,0) -
2128: (0xff < sVar29);
2129: pcVar2[2] = (0 < sVar27) * (sVar27 < 0xff) * SUB161(auVar72 >> 0x20,0) -
2130: (0xff < sVar27);
2131: pcVar2[3] = (0 < sVar30) * (sVar30 < 0xff) * SUB161(auVar72 >> 0x30,0) -
2132: (0xff < sVar30);
2133: pcVar2[4] = (0 < sVar32) * (sVar32 < 0xff) * SUB161(auVar72 >> 0x40,0) -
2134: (0xff < sVar32);
2135: pcVar2[5] = (0 < sVar34) * (sVar34 < 0xff) * SUB161(auVar72 >> 0x50,0) -
2136: (0xff < sVar34);
2137: pcVar2[6] = (0 < sVar36) * (sVar36 < 0xff) * SUB161(auVar72 >> 0x60,0) -
2138: (0xff < sVar36);
2139: pcVar2[7] = (0 < sVar38) * (sVar38 < 0xff) * SUB161(auVar72 >> 0x70,0) -
2140: (0xff < sVar38);
2141: pcVar2[8] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar88,0) - (0xff < sVar40);
2142: pcVar2[9] = (0 < sVar42) * (sVar42 < 0xff) * SUB161(auVar88 >> 0x10,0) -
2143: (0xff < sVar42);
2144: pcVar2[10] = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar88 >> 0x20,0) -
2145: (0xff < sVar44);
2146: pcVar2[0xb] = (0 < sVar46) * (sVar46 < 0xff) * SUB161(auVar88 >> 0x30,0) -
2147: (0xff < sVar46);
2148: pcVar2[0xc] = (0 < sVar48) * (sVar48 < 0xff) * SUB161(auVar88 >> 0x40,0) -
2149: (0xff < sVar48);
2150: pcVar2[0xd] = (0 < sVar50) * (sVar50 < 0xff) * SUB161(auVar88 >> 0x50,0) -
2151: (0xff < sVar50);
2152: pcVar2[0xe] = (0 < sVar52) * (sVar52 < 0xff) * SUB161(auVar88 >> 0x60,0) -
2153: (0xff < sVar52);
2154: pcVar2[0xf] = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar88 >> 0x70,0) -
2155: (0xff < sVar54);
2156: pcVar2 = (char *)(uVar5 + lVar68);
2157: *pcVar2 = (cVar8 != '\0') * (cVar8 != -1) * cVar8;
2158: pcVar2[1] = (uVar71 != 0) * (uVar71 < 0xff) * cVar9 - (0xff < uVar71);
2159: pcVar2[2] = (uVar73 != 0) * (uVar73 < 0xff) * cVar10 - (0xff < uVar73);
2160: pcVar2[3] = (uVar74 != 0) * (uVar74 < 0xff) * cVar11 - (0xff < uVar74);
2161: pcVar2[4] = (uVar75 != 0) * (uVar75 < 0xff) * cVar12 - (0xff < uVar75);
2162: pcVar2[5] = (uVar76 != 0) * (uVar76 < 0xff) * cVar13 - (0xff < uVar76);
2163: pcVar2[6] = (uVar77 != 0) * (uVar77 < 0xff) * cVar14 - (0xff < uVar77);
2164: pcVar2[7] = (uVar78 != 0) * (uVar78 < 0xff) * cVar15 - (0xff < uVar78);
2165: pcVar2[8] = (cVar16 != '\0') * (cVar16 != -1) * cVar16;
2166: pcVar2[9] = (uVar79 != 0) * (uVar79 < 0xff) * cVar17 - (0xff < uVar79);
2167: pcVar2[10] = (uVar87 != 0) * (uVar87 < 0xff) * cVar18 - (0xff < uVar87);
2168: pcVar2[0xb] = (uVar89 != 0) * (uVar89 < 0xff) * cVar19 - (0xff < uVar89);
2169: pcVar2[0xc] = (uVar90 != 0) * (uVar90 < 0xff) * cVar20 - (0xff < uVar90);
2170: pcVar2[0xd] = (uVar91 != 0) * (uVar91 < 0xff) * cVar21 - (0xff < uVar91);
2171: pcVar2[0xe] = (uVar92 != 0) * (uVar92 < 0xff) * cVar22 - (0xff < uVar92);
2172: pcVar2[0xf] = (uVar93 != 0) * (uVar93 < 0xff) * cVar23 - (0xff < uVar93);
2173: lVar68 = lVar68 + 0x10;
2174: } while (uVar70 < uVar1 >> 4);
2175: lVar57 = lVar57 + (ulong)(uVar1 & 0xfffffff0) * 4;
2176: uVar70 = uVar1 & 0xfffffff0;
2177: }
2178: uVar62 = (ulong)uVar70;
2179: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 1);
2180: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 2);
2181: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 3);
2182: uVar62 = (ulong)(uVar70 + 1);
2183: if (uVar70 + 1 < uVar4) {
2184: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 5);
2185: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 6);
2186: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 7);
2187: uVar62 = (ulong)(uVar70 + 2);
2188: if (uVar70 + 2 < uVar4) {
2189: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 9);
2190: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 10);
2191: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0xb);
2192: uVar62 = (ulong)(uVar70 + 3);
2193: if (uVar70 + 3 < uVar4) {
2194: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0xd);
2195: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0xe);
2196: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0xf);
2197: uVar62 = (ulong)(uVar70 + 4);
2198: if (uVar70 + 4 < uVar4) {
2199: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x11);
2200: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x12);
2201: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x13);
2202: uVar62 = (ulong)(uVar70 + 5);
2203: if (uVar70 + 5 < uVar4) {
2204: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x15);
2205: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x16);
2206: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x17);
2207: uVar62 = (ulong)(uVar70 + 6);
2208: if (uVar70 + 6 < uVar4) {
2209: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x19);
2210: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x1a);
2211: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x1b);
2212: uVar62 = (ulong)(uVar70 + 7);
2213: if (uVar70 + 7 < uVar4) {
2214: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x1d);
2215: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x1e);
2216: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x1f);
2217: uVar62 = (ulong)(uVar70 + 8);
2218: if (uVar70 + 8 < uVar4) {
2219: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x21);
2220: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x22);
2221: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x23);
2222: uVar62 = (ulong)(uVar70 + 9);
2223: if (uVar70 + 9 < uVar4) {
2224: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x25);
2225: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x26);
2226: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x27);
2227: uVar62 = (ulong)(uVar70 + 10);
2228: if (uVar70 + 10 < uVar4) {
2229: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x29);
2230: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x2a);
2231: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x2b);
2232: uVar62 = (ulong)(uVar70 + 0xb);
2233: if (uVar70 + 0xb < uVar4) {
2234: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x2d);
2235: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x2e);
2236: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x2f);
2237: uVar62 = (ulong)(uVar70 + 0xc);
2238: if (uVar70 + 0xc < uVar4) {
2239: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x31);
2240: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x32);
2241: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x33);
2242: uVar62 = (ulong)(uVar70 + 0xd);
2243: if (uVar70 + 0xd < uVar4) {
2244: *(undefined *)(uVar63 + uVar62) = *(undefined *)(lVar57 + 0x35);
2245: *(undefined *)(uVar69 + uVar62) = *(undefined *)(lVar57 + 0x36);
2246: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x37);
2247: uVar62 = (ulong)(uVar70 + 0xe);
2248: if (uVar70 + 0xe < uVar4) {
2249: uVar67 = (ulong)(uVar70 + 0xf);
2250: *(undefined *)(uVar63 + uVar62) =
2251: *(undefined *)(lVar57 + 0x39);
2252: *(undefined *)(uVar69 + uVar62) =
2253: *(undefined *)(lVar57 + 0x3a);
2254: *(undefined *)(uVar5 + uVar62) = *(undefined *)(lVar57 + 0x3b)
2255: ;
2256: if (uVar70 + 0xf < uVar4) {
2257: *(undefined *)(uVar63 + uVar67) =
2258: *(undefined *)(lVar57 + 0x3d);
2259: *(undefined *)(uVar69 + uVar67) =
2260: *(undefined *)(lVar57 + 0x3e);
2261: *(undefined *)(uVar5 + uVar67) =
2262: *(undefined *)(lVar57 + 0x3f);
2263: }
2264: }
2265: }
2266: }
2267: }
2268: }
2269: }
2270: }
2271: }
2272: }
2273: }
2274: }
2275: }
2276: }
2277: }
2278: }
2279: }
2280: }
2281: break;
2282: default:
2283: while (param_5 = param_5 + -1, -1 < param_5) {
2284: plVar65 = param_2 + 1;
2285: uVar61 = (ulong)((int)uVar64 + 1);
2286: puVar59 = (undefined *)*param_2;
2287: lVar57 = *(long *)(*param_3 + uVar64 * 8);
2288: lVar68 = *(long *)(param_3[1] + uVar64 * 8);
2289: lVar7 = *(long *)(param_3[2] + uVar64 * 8);
2290: param_2 = plVar65;
2291: uVar64 = uVar61;
2292: if (uVar4 != 0) {
2293: lVar66 = 0;
2294: puVar58 = puVar59;
2295: do {
2296: puVar60 = puVar58 + 3;
2297: *(undefined *)(lVar57 + lVar66) = *puVar58;
2298: *(undefined *)(lVar68 + lVar66) = puVar58[1];
2299: *(undefined *)(lVar7 + lVar66) = puVar58[2];
2300: lVar66 = lVar66 + 1;
2301: puVar58 = puVar60;
2302: } while (puVar60 != puVar59 + (ulong)(uVar4 - 1) * 3 + 3);
2303: }
2304: }
2305: }
2306: /* WARNING: Read-only address (ram,0x0016c610) is written */
2307: return;
2308: }
2309: 

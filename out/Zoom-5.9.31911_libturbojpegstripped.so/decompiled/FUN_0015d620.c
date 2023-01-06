1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0015d620(undefined (*param_1) [16])
5: 
6: {
7: ulong uVar1;
8: ulong uVar2;
9: ulong uVar3;
10: ulong uVar4;
11: ulong uVar5;
12: short sVar6;
13: short sVar7;
14: short sVar8;
15: short sVar9;
16: short sVar10;
17: short sVar11;
18: short sVar12;
19: short sVar13;
20: short sVar14;
21: short sVar15;
22: short sVar16;
23: short sVar17;
24: short sVar18;
25: short sVar19;
26: short sVar20;
27: short sVar21;
28: short sVar22;
29: short sVar23;
30: short sVar24;
31: short sVar25;
32: short sVar26;
33: short sVar27;
34: short sVar28;
35: short sVar29;
36: short sVar30;
37: short sVar31;
38: short sVar32;
39: short sVar33;
40: undefined auVar34 [16];
41: short sVar35;
42: short sVar36;
43: short sVar37;
44: short sVar38;
45: short sVar39;
46: short sVar40;
47: short sVar41;
48: short sVar42;
49: short sVar43;
50: short sVar44;
51: short sVar45;
52: short sVar46;
53: short sVar47;
54: short sVar48;
55: short sVar49;
56: short sVar50;
57: short sVar51;
58: short sVar52;
59: short sVar53;
60: short sVar54;
61: short sVar55;
62: short sVar56;
63: short sVar57;
64: short sVar58;
65: short sVar61;
66: short sVar62;
67: short sVar63;
68: short sVar65;
69: undefined auVar59 [16];
70: undefined auVar60 [16];
71: ulong uVar64;
72: short sVar66;
73: short sVar67;
74: short sVar69;
75: short sVar70;
76: short sVar71;
77: short sVar72;
78: short sVar73;
79: short sVar74;
80: short sVar75;
81: short sVar76;
82: short sVar77;
83: short sVar78;
84: short sVar79;
85: short sVar80;
86: short sVar81;
87: short sVar82;
88: short sVar83;
89: short sVar84;
90: short sVar85;
91: short sVar86;
92: short sVar87;
93: undefined auVar68 [16];
94: short sVar88;
95: short sVar89;
96: short sVar90;
97: short sVar91;
98: short sVar92;
99: short sVar93;
100: short sVar94;
101: short sVar95;
102: short sStack48;
103: short sStack46;
104: short sStack42;
105: short sStack32;
106: short sStack30;
107: 
108: auVar68 = *param_1;
109: sVar69 = *(short *)(param_1[1] + 2);
110: sVar61 = *(short *)(param_1[1] + 4);
111: sVar10 = *(short *)(param_1[1] + 6);
112: auVar34 = param_1[2];
113: sVar12 = *(short *)(param_1[3] + 6);
114: sVar52 = SUB162(auVar68 >> 0x30,0);
115: sVar67 = SUB162(auVar68 >> 0x20,0);
116: sVar70 = SUB162(auVar68 >> 0x50,0);
117: sVar25 = SUB162(auVar68 >> 0x60,0);
118: sVar41 = SUB162(auVar68 >> 0x70,0);
119: sVar53 = SUB162(auVar34 >> 0x30,0);
120: sVar62 = SUB162(auVar34 >> 0x20,0);
121: sVar78 = SUB162(auVar34 >> 0x40,0);
122: sVar15 = SUB162(auVar34 >> 0x50,0);
123: sVar27 = SUB162(auVar34 >> 0x60,0);
124: sVar40 = SUB162(auVar34 >> 0x70,0);
125: auVar59 = param_1[4];
126: sVar81 = *(short *)(param_1[5] + 2);
127: sVar16 = *(short *)(param_1[5] + 6);
128: auVar60 = param_1[6];
129: sVar19 = *(short *)(param_1[7] + 6);
130: sVar73 = SUB162(auVar59 >> 0x30,0);
131: uVar64 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(sVar16,CONCAT212(sVar73,SUB1612(
132: auVar59,0))) >> 0x60,0),
133: CONCAT210(*(undefined2 *)(param_1[5] + 4),
134: SUB1610(auVar59,0))) >> 0x50,0),
135: CONCAT28(SUB162(auVar59 >> 0x20,0),SUB168(auVar59,0))) >> 0x40,0);
136: sVar54 = SUB162(auVar59 >> 0x50,0);
137: sVar21 = SUB162(auVar59 >> 0x60,0);
138: sVar23 = SUB162(auVar59 >> 0x70,0);
139: sVar37 = SUB162(auVar60 >> 0x30,0);
140: sVar65 = SUB162(auVar60 >> 0x20,0);
141: sVar84 = SUB162(auVar60 >> 0x10,0);
142: sVar72 = SUB162(auVar60 >> 0x40,0);
143: sVar18 = SUB162(auVar60 >> 0x50,0);
144: sVar31 = SUB162(auVar60 >> 0x60,0);
145: sVar48 = SUB162(auVar60 >> 0x70,0);
146: uVar1 = SUB168(CONCAT124(SUB1612((ZEXT1016(CONCAT82(uVar64,sVar81)) << 0x30) >> 0x20,0),
147: SUB164(auVar59,0) & 0xffff | (uint)*(ushort *)param_1[5] << 0x10),0) &
148: 0xffffffff;
149: uVar64 = uVar64 & 0xffffffff;
150: uVar2 = (ulong)CONCAT24(sVar54,CONCAT22(*(undefined2 *)(param_1[5] + 8),SUB162(auVar59 >> 0x40,0))
151: ) & 0xffffffff;
152: sStack32 = (short)uVar2;
153: sStack30 = (short)(uVar2 >> 0x10);
154: uVar2 = SUB168(CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
155: CONCAT214(sVar10,CONCAT212(sVar52,SUB1612(auVar68,
156: 0))) >> 0x60,0),
157: CONCAT210(sVar61,SUB1610(auVar68,0))) >> 0x50,0),
158: CONCAT28(sVar67,SUB168(auVar68,0))) >> 0x40,0),
159: sVar69)) << 0x30) >> 0x20,0),
160: SUB164(auVar68,0) & 0xffff | (uint)*(ushort *)param_1[1] << 0x10),0) &
161: 0xffffffff;
162: uVar3 = (ulong)CONCAT24(sVar70,CONCAT22(*(undefined2 *)(param_1[1] + 8),SUB162(auVar68 >> 0x40,0))
163: ) & 0xffffffff;
164: sVar66 = SUB162(auVar68 >> 0x10,0);
165: sVar20 = sVar66 - sVar25;
166: sVar22 = sVar69 - *(short *)(param_1[1] + 0xc);
167: sVar71 = SUB162(auVar34 >> 0x10,0);
168: sVar24 = sVar71 - sVar27;
169: sVar26 = *(short *)(param_1[3] + 2) - *(short *)(param_1[3] + 0xc);
170: sVar77 = SUB162(auVar59 >> 0x10,0);
171: sVar28 = sVar77 - sVar21;
172: sVar29 = sVar81 - *(short *)(param_1[5] + 0xc);
173: sVar30 = sVar84 - sVar31;
174: sVar32 = *(short *)(param_1[7] + 2) - *(short *)(param_1[7] + 0xc);
175: sVar35 = (short)uVar2;
176: sVar6 = sVar35 - sVar41;
177: sVar38 = (short)(uVar2 >> 0x10);
178: sVar7 = sVar38 - *(short *)(param_1[1] + 0xe);
179: sVar8 = SUB162(auVar34,0) - sVar40;
180: sVar9 = *(short *)param_1[3] - *(short *)(param_1[3] + 0xe);
181: sVar44 = (short)uVar1;
182: sVar11 = sVar44 - sVar23;
183: sVar46 = (short)(uVar1 >> 0x10);
184: sVar13 = sVar46 - *(short *)(param_1[5] + 0xe);
185: sVar14 = SUB162(auVar60,0) - sVar48;
186: sVar17 = *(short *)param_1[7] - *(short *)(param_1[7] + 0xe);
187: sVar66 = sVar66 + sVar25;
188: sVar69 = sVar69 + *(short *)(param_1[1] + 0xc);
189: sVar71 = sVar71 + sVar27;
190: sVar74 = *(short *)(param_1[3] + 2) + *(short *)(param_1[3] + 0xc);
191: sVar77 = sVar77 + sVar21;
192: sVar81 = sVar81 + *(short *)(param_1[5] + 0xc);
193: sVar84 = sVar84 + sVar31;
194: sVar87 = *(short *)(param_1[7] + 2) + *(short *)(param_1[7] + 0xc);
195: sVar35 = sVar35 + sVar41;
196: sVar38 = sVar38 + *(short *)(param_1[1] + 0xe);
197: sVar40 = SUB162(auVar34,0) + sVar40;
198: sVar42 = *(short *)param_1[3] + *(short *)(param_1[3] + 0xe);
199: sVar44 = sVar44 + sVar23;
200: sVar46 = sVar46 + *(short *)(param_1[5] + 0xe);
201: sVar48 = SUB162(auVar60,0) + sVar48;
202: sVar50 = *(short *)param_1[7] + *(short *)(param_1[7] + 0xe);
203: sStack48 = (short)uVar64;
204: sStack46 = (short)(uVar64 >> 0x10);
205: sStack42 = (short)((ulong)(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(sVar19,CONCAT212(
206: sVar37,SUB1612(auVar60,0))) >> 0x60,0),
207: CONCAT210(*(undefined2 *)(param_1[7] + 4),
208: SUB1610(auVar60,0))) >> 0x50,0),
209: CONCAT28(sVar65,SUB168(auVar60,0))) >> 0x40,0) << 0x20
210: ) >> 0x30);
211: sVar56 = (short)uVar3;
212: sVar21 = sVar52 + sVar56;
213: sVar58 = (short)(uVar3 >> 0x10);
214: sVar23 = sVar10 + sVar58;
215: sVar25 = sVar53 + sVar78;
216: sVar27 = sVar12 + *(short *)(param_1[3] + 8);
217: sVar31 = sVar37 + sVar72;
218: sVar33 = sVar19 + *(short *)(param_1[7] + 8);
219: sVar90 = sVar61 + *(short *)(param_1[1] + 10);
220: sVar91 = sVar62 + sVar15;
221: sVar63 = (short)((ulong)(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(sVar12,CONCAT212(
222: sVar53,SUB1612(auVar34,0))) >> 0x60,0),
223: CONCAT210(*(undefined2 *)(param_1[3] + 4),
224: SUB1610(auVar34,0))) >> 0x50,0),
225: CONCAT28(sVar62,SUB168(auVar34,0))) >> 0x40,0) << 0x20)
226: >> 0x30);
227: sVar92 = sVar63 + *(short *)(param_1[3] + 10);
228: sVar93 = sStack46 + *(short *)(param_1[5] + 10);
229: sVar94 = sVar65 + sVar18;
230: sVar95 = sStack42 + *(short *)(param_1[7] + 10);
231: sVar61 = sVar61 - *(short *)(param_1[1] + 10);
232: sVar62 = sVar62 - sVar15;
233: sVar63 = sVar63 - *(short *)(param_1[3] + 10);
234: sStack46 = sStack46 - *(short *)(param_1[5] + 10);
235: sVar65 = sVar65 - sVar18;
236: sStack42 = sStack42 - *(short *)(param_1[7] + 10);
237: sVar36 = sVar35 - sVar21;
238: sVar39 = sVar38 - sVar23;
239: sVar41 = sVar40 - sVar25;
240: sVar43 = sVar42 - sVar27;
241: sVar45 = sVar44 - (sVar73 + sStack32);
242: sVar47 = sVar46 - (sVar16 + sStack30);
243: sVar49 = sVar48 - sVar31;
244: sVar51 = sVar50 - sVar33;
245: sVar35 = sVar35 + sVar21;
246: sVar38 = sVar38 + sVar23;
247: sVar40 = sVar40 + sVar25;
248: sVar42 = sVar42 + sVar27;
249: sVar44 = sVar44 + sVar73 + sStack32;
250: sVar46 = sVar46 + sVar16 + sStack30;
251: sVar48 = sVar48 + sVar31;
252: sVar50 = sVar50 + sVar33;
253: sVar21 = sVar66 + sVar67 + sVar70;
254: sVar23 = sVar69 + sVar90;
255: sVar25 = sVar71 + sVar91;
256: sVar27 = sVar74 + sVar92;
257: sVar31 = sVar77 + sStack48 + sVar54;
258: sVar33 = sVar81 + sVar93;
259: sVar15 = sVar84 + sVar94;
260: sVar18 = sVar87 + sVar95;
261: auVar68 = psllw(CONCAT214((sVar87 - sVar95) + sVar51,
262: CONCAT212((sVar84 - sVar94) + sVar49,
263: CONCAT210((sVar81 - sVar93) + sVar47,
264: CONCAT28((sVar77 - (sStack48 + sVar54)) + sVar45,
265: CONCAT26((sVar74 - sVar92) + sVar43,
266: CONCAT24((sVar71 - sVar91) +
267: sVar41,CONCAT22((sVar69 -
268: sVar90) +
269: sVar39,(
270: sVar66 - (sVar67 + sVar70)) + sVar36))))))),2);
271: auVar68 = pmulhw(auVar68,_DAT_0019ca20);
272: sVar93 = sVar38 - sVar23;
273: sVar94 = sVar42 - sVar27;
274: sVar95 = sVar46 - sVar33;
275: sVar55 = sVar48 - sVar15;
276: sVar57 = sVar50 - sVar18;
277: sVar71 = sVar36 - SUB162(auVar68,0);
278: sVar84 = SUB162(auVar68 >> 0x10,0);
279: sVar77 = sVar39 - sVar84;
280: sVar69 = SUB162(auVar68 >> 0x20,0);
281: sVar66 = sVar41 - sVar69;
282: sVar81 = SUB162(auVar68 >> 0x30,0);
283: sVar74 = sVar43 - sVar81;
284: sVar75 = SUB162(auVar68 >> 0x40,0);
285: sVar87 = sVar45 - sVar75;
286: sVar76 = SUB162(auVar68 >> 0x50,0);
287: sVar90 = sVar47 - sVar76;
288: sVar79 = SUB162(auVar68 >> 0x60,0);
289: sVar91 = sVar49 - sVar79;
290: sVar80 = SUB162(auVar68 >> 0x70,0);
291: sVar92 = sVar51 - sVar80;
292: sVar38 = sVar38 + sVar23;
293: sVar23 = sVar40 + sVar25;
294: sVar42 = sVar42 + sVar27;
295: sVar46 = sVar46 + sVar33;
296: sVar48 = sVar48 + sVar15;
297: sVar50 = sVar50 + sVar18;
298: sVar36 = sVar36 + SUB162(auVar68,0);
299: sVar39 = sVar39 + sVar84;
300: sVar41 = sVar41 + sVar69;
301: sVar43 = sVar43 + sVar81;
302: sVar45 = sVar45 + sVar75;
303: sVar47 = sVar47 + sVar76;
304: sVar49 = sVar49 + sVar79;
305: sVar51 = sVar51 + sVar80;
306: auVar34 = psllw(CONCAT214((sVar19 - *(short *)(param_1[7] + 8)) + sStack42,
307: CONCAT212((sVar37 - sVar72) + sVar65,
308: CONCAT210((sVar16 - sStack30) + sStack46,
309: CONCAT28((sVar73 - sStack32) + (sStack48 - sVar54),
310: CONCAT26((sVar12 - *(short *)(param_1[3] +
311: 8)) + sVar63,
312: CONCAT24((sVar53 - sVar78) +
313: sVar62,CONCAT22((sVar10 -
314: sVar58) +
315: sVar61,(
316: sVar52 - sVar56) + (sVar67 - sVar70)))))))),2);
317: auVar68 = psllw(CONCAT214(sVar32 + sVar17,
318: CONCAT212(sVar30 + sVar14,
319: CONCAT210(sVar29 + sVar13,
320: CONCAT28(sVar28 + sVar11,
321: CONCAT26(sVar26 + sVar9,
322: CONCAT24(sVar24 + sVar8,
323: CONCAT22(sVar22 + sVar7,
324: sVar20 + sVar6))
325: ))))),2);
326: auVar59 = psllw(CONCAT214(sStack42 + sVar32,
327: CONCAT212(sVar65 + sVar30,
328: CONCAT210(sStack46 + sVar29,
329: CONCAT28((sStack48 - sVar54) + sVar28,
330: CONCAT26(sVar63 + sVar26,
331: CONCAT24(sVar62 + sVar24,
332: CONCAT22(sVar61 + sVar22,
333: (sVar67 - sVar70
334: ) + sVar20))))))
335: ),2);
336: auVar60 = pmulhw(auVar59,_DAT_0019ca20);
337: auVar59 = pmulhw(CONCAT214(SUB162(auVar34 >> 0x70,0) - SUB162(auVar68 >> 0x70,0),
338: CONCAT212(SUB162(auVar34 >> 0x60,0) - SUB162(auVar68 >> 0x60,0),
339: CONCAT210(SUB162(auVar34 >> 0x50,0) -
340: SUB162(auVar68 >> 0x50,0),
341: CONCAT28(SUB162(auVar34 >> 0x40,0) -
342: SUB162(auVar68 >> 0x40,0),
343: CONCAT26(SUB162(auVar34 >> 0x30,0) -
344: SUB162(auVar68 >> 0x30,0),
345: CONCAT24(SUB162(auVar34 >> 0x20,0
346: ) - SUB162(auVar68
347: >> 0x20
348: ,0),CONCAT22(SUB162(auVar34 >> 0x10,0) -
349: SUB162(auVar68 >> 0x10,0),
350: SUB162(auVar34,0) - SUB162(auVar68,0)
351: ))))))),_DAT_0019ca30);
352: auVar34 = pmulhw(auVar34,_DAT_0019ca40);
353: auVar68 = pmulhw(auVar68,_DAT_0019ca50);
354: sVar52 = SUB162(auVar34,0) + SUB162(auVar59,0);
355: sVar69 = SUB162(auVar59 >> 0x10,0);
356: sVar27 = SUB162(auVar34 >> 0x10,0) + sVar69;
357: sVar61 = SUB162(auVar59 >> 0x20,0);
358: sVar29 = SUB162(auVar34 >> 0x20,0) + sVar61;
359: sVar10 = SUB162(auVar59 >> 0x30,0);
360: sVar33 = SUB162(auVar34 >> 0x30,0) + sVar10;
361: sVar12 = SUB162(auVar59 >> 0x40,0);
362: sVar53 = SUB162(auVar34 >> 0x40,0) + sVar12;
363: sVar81 = SUB162(auVar59 >> 0x50,0);
364: sVar54 = SUB162(auVar34 >> 0x50,0) + sVar81;
365: sVar16 = SUB162(auVar59 >> 0x60,0);
366: sVar56 = SUB162(auVar34 >> 0x60,0) + sVar16;
367: sVar19 = SUB162(auVar59 >> 0x70,0);
368: sVar58 = SUB162(auVar34 >> 0x70,0) + sVar19;
369: sVar84 = SUB162(auVar68,0) + SUB162(auVar59,0);
370: sVar69 = SUB162(auVar68 >> 0x10,0) + sVar69;
371: sVar61 = SUB162(auVar68 >> 0x20,0) + sVar61;
372: sVar10 = SUB162(auVar68 >> 0x30,0) + sVar10;
373: sVar12 = SUB162(auVar68 >> 0x40,0) + sVar12;
374: sVar81 = SUB162(auVar68 >> 0x50,0) + sVar81;
375: sVar16 = SUB162(auVar68 >> 0x60,0) + sVar16;
376: sVar19 = SUB162(auVar68 >> 0x70,0) + sVar19;
377: sVar67 = sVar6 - SUB162(auVar60,0);
378: sVar65 = SUB162(auVar60 >> 0x10,0);
379: sVar63 = sVar7 - sVar65;
380: sVar24 = SUB162(auVar60 >> 0x20,0);
381: sVar72 = sVar8 - sVar24;
382: sVar37 = SUB162(auVar60 >> 0x30,0);
383: sVar18 = sVar9 - sVar37;
384: sVar26 = SUB162(auVar60 >> 0x40,0);
385: sVar78 = sVar11 - sVar26;
386: sVar28 = SUB162(auVar60 >> 0x50,0);
387: sVar20 = sVar13 - sVar28;
388: sVar30 = SUB162(auVar60 >> 0x60,0);
389: sVar15 = sVar14 - sVar30;
390: sVar32 = SUB162(auVar60 >> 0x70,0);
391: sVar22 = sVar17 - sVar32;
392: sVar6 = sVar6 + SUB162(auVar60,0);
393: sVar7 = sVar7 + sVar65;
394: sVar8 = sVar8 + sVar24;
395: sVar9 = sVar9 + sVar37;
396: sVar11 = sVar11 + sVar26;
397: sVar13 = sVar13 + sVar28;
398: sVar14 = sVar14 + sVar30;
399: sVar17 = sVar17 + sVar32;
400: sVar32 = sVar67 - sVar52;
401: sVar70 = sVar63 - sVar27;
402: sVar75 = sVar18 - sVar33;
403: sVar79 = sVar78 - sVar53;
404: sVar82 = sVar20 - sVar54;
405: sVar85 = sVar15 - sVar56;
406: sVar88 = sVar22 - sVar58;
407: sVar37 = sVar6 - sVar84;
408: sVar26 = sVar7 - sVar69;
409: sVar30 = sVar9 - sVar10;
410: sVar62 = sVar11 - sVar12;
411: sVar28 = sVar13 - sVar81;
412: sVar65 = sVar14 - sVar16;
413: sVar24 = sVar17 - sVar19;
414: sVar67 = sVar67 + sVar52;
415: sVar52 = sVar72 + sVar29;
416: sVar18 = sVar18 + sVar33;
417: sVar20 = sVar20 + sVar54;
418: sVar15 = sVar15 + sVar56;
419: sVar22 = sVar22 + sVar58;
420: sVar6 = sVar6 + sVar84;
421: sVar84 = sVar8 + sVar61;
422: sVar9 = sVar9 + sVar10;
423: sVar13 = sVar13 + sVar81;
424: sVar14 = sVar14 + sVar16;
425: sVar17 = sVar17 + sVar19;
426: uVar4 = (ulong)CONCAT24(sVar84,CONCAT22(sVar7 + sVar69,sVar6)) & 0xffff0000;
427: uVar64 = (ulong)(CONCAT64(CONCAT42(CONCAT22(sVar18,sVar94),sVar52),
428: CONCAT22(sVar40 - sVar25,sVar94)) >> 0x10);
429: uVar5 = (ulong)CONCAT24(sVar52,CONCAT22(sVar63 + sVar27,sVar67)) & 0xffff0000;
430: uVar1 = SUB168(CONCAT124(SUB1612(CONCAT88(uVar64,(uVar5 >> 0x10) << 0x30) >> 0x20,0) &
431: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
432: CONCAT22(sVar67,sVar35 - sVar21)),0) & 0xffffffff;
433: uVar64 = uVar64 & 0xffffffff;
434: uVar2 = (ulong)CONCAT24(sVar95,CONCAT22(sVar78 + sVar53,sVar44 - sVar31)) & 0xffffffff;
435: sStack32 = (short)uVar2;
436: sStack30 = (short)(uVar2 >> 0x10);
437: uVar2 = SUB168(CONCAT124(SUB1612(CONCAT88((long)(CONCAT64(CONCAT42(CONCAT22(sVar9,sVar42),sVar84),
438: CONCAT22(sVar23,sVar42)) >> 0x10),
439: (uVar4 >> 0x10) << 0x30) >> 0x20,0) &
440: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
441: CONCAT22(sVar6,sVar35 + sVar21)),0) & 0xffffffff;
442: uVar3 = (ulong)CONCAT24(sVar46,CONCAT22(sVar11 + sVar12,sVar44 + sVar31)) & 0xffffffff;
443: sVar63 = sVar38 - sVar48;
444: sVar56 = (short)(uVar4 >> 0x10);
445: sVar78 = sVar56 - sVar14;
446: sVar73 = sVar39 - sVar49;
447: sVar76 = sVar70 - sVar85;
448: sVar80 = sVar93 - sVar55;
449: sVar58 = (short)(uVar5 >> 0x10);
450: sVar83 = sVar58 - sVar15;
451: sVar86 = sVar77 - sVar91;
452: sVar89 = sVar26 - sVar65;
453: sVar10 = (short)uVar2;
454: sVar19 = sVar10 - sVar50;
455: sVar12 = (short)(uVar2 >> 0x10);
456: sVar35 = sVar12 - sVar17;
457: sVar7 = sVar36 - sVar51;
458: sVar67 = sVar32 - sVar88;
459: sVar21 = (short)uVar1;
460: sVar25 = sVar21 - sVar57;
461: sVar27 = (short)(uVar1 >> 0x10);
462: sVar52 = sVar27 - sVar22;
463: sVar11 = sVar71 - sVar92;
464: sVar33 = sVar37 - sVar24;
465: sVar38 = sVar38 + sVar48;
466: sVar56 = sVar56 + sVar14;
467: sVar39 = sVar39 + sVar49;
468: sVar70 = sVar70 + sVar85;
469: sVar93 = sVar93 + sVar55;
470: sVar58 = sVar58 + sVar15;
471: sVar77 = sVar77 + sVar91;
472: sVar26 = sVar26 + sVar65;
473: sVar10 = sVar10 + sVar50;
474: sVar12 = sVar12 + sVar17;
475: sVar36 = sVar36 + sVar51;
476: sVar32 = sVar32 + sVar88;
477: sVar21 = sVar21 + sVar57;
478: sVar27 = sVar27 + sVar22;
479: sVar71 = sVar71 + sVar92;
480: sVar37 = sVar37 + sVar24;
481: sStack48 = (short)uVar64;
482: sStack46 = (short)(uVar64 >> 0x10);
483: sStack42 = (short)((ulong)((long)(((unkuint10)CONCAT42(CONCAT22(sVar30,sVar74),sVar8 - sVar61) <<
484: 0x20) >> 0x10) << 0x20) >> 0x30);
485: sVar49 = (short)uVar3;
486: sVar61 = sVar42 + sVar49;
487: sVar91 = (short)(uVar3 >> 0x10);
488: sVar81 = sVar9 + sVar91;
489: sVar16 = sVar43 + sVar45;
490: sVar6 = sVar75 + sVar79;
491: sVar8 = sVar74 + sVar87;
492: sVar44 = sVar30 + sVar62;
493: sVar14 = sVar84 + sVar13;
494: sVar15 = sVar41 + sVar47;
495: sVar69 = (short)((ulong)((long)(((unkuint10)CONCAT42(CONCAT22(sVar75,sVar43),sVar72 - sVar29) <<
496: 0x20) >> 0x10) << 0x20) >> 0x30);
497: sVar17 = sVar69 + sVar82;
498: sVar22 = sStack46 + sVar20;
499: sVar65 = sVar66 + sVar90;
500: sVar24 = sStack42 + sVar28;
501: sVar84 = sVar84 - sVar13;
502: sVar41 = sVar41 - sVar47;
503: sVar69 = sVar69 - sVar82;
504: sStack46 = sStack46 - sVar20;
505: sVar66 = sVar66 - sVar90;
506: sStack42 = sStack42 - sVar28;
507: sVar20 = sVar10 - sVar61;
508: sVar28 = sVar12 - sVar81;
509: sVar29 = sVar36 - sVar16;
510: sVar48 = sVar32 - sVar6;
511: sVar50 = sVar21 - (sVar94 + sStack32);
512: sVar53 = sVar27 - (sVar18 + sStack30);
513: sVar54 = sVar71 - sVar8;
514: sVar40 = sVar37 - sVar44;
515: sVar10 = sVar10 + sVar61;
516: sVar12 = sVar12 + sVar81;
517: sVar36 = sVar36 + sVar16;
518: sVar32 = sVar32 + sVar6;
519: sVar21 = sVar21 + sVar94 + sStack32;
520: sVar27 = sVar27 + sVar18 + sStack30;
521: sVar71 = sVar71 + sVar8;
522: sVar37 = sVar37 + sVar44;
523: sVar61 = sVar38 + sVar23 + sVar46;
524: sVar81 = sVar56 + sVar14;
525: sVar16 = sVar39 + sVar15;
526: sVar6 = sVar70 + sVar17;
527: sVar8 = sVar93 + sStack48 + sVar95;
528: sVar44 = sVar58 + sVar22;
529: sVar31 = sVar77 + sVar65;
530: sVar13 = sVar26 + sVar24;
531: auVar68 = psllw(CONCAT214((sVar26 - sVar24) + sVar40,
532: CONCAT212((sVar77 - sVar65) + sVar54,
533: CONCAT210((sVar58 - sVar22) + sVar53,
534: CONCAT28((sVar93 - (sStack48 + sVar95)) + sVar50,
535: CONCAT26((sVar70 - sVar17) + sVar48,
536: CONCAT24((sVar39 - sVar15) +
537: sVar29,CONCAT22((sVar56 -
538: sVar14) +
539: sVar28,(
540: sVar38 - (sVar23 + sVar46)) + sVar20))))))),2);
541: auVar68 = pmulhw(auVar68,_DAT_0019ca20);
542: sVar38 = SUB162(auVar68 >> 0x10,0);
543: sVar14 = SUB162(auVar68 >> 0x20,0);
544: sVar15 = SUB162(auVar68 >> 0x30,0);
545: sVar17 = SUB162(auVar68 >> 0x40,0);
546: sVar22 = SUB162(auVar68 >> 0x50,0);
547: sVar65 = SUB162(auVar68 >> 0x60,0);
548: sVar24 = SUB162(auVar68 >> 0x70,0);
549: *(short *)param_1[4] = sVar10 - sVar61;
550: *(short *)(param_1[4] + 2) = sVar12 - sVar81;
551: *(short *)(param_1[4] + 4) = sVar36 - sVar16;
552: *(short *)(param_1[4] + 6) = sVar32 - sVar6;
553: *(short *)(param_1[4] + 8) = sVar21 - sVar8;
554: *(short *)(param_1[4] + 10) = sVar27 - sVar44;
555: *(short *)(param_1[4] + 0xc) = sVar71 - sVar31;
556: *(short *)(param_1[4] + 0xe) = sVar37 - sVar13;
557: *(short *)param_1[6] = sVar20 - SUB162(auVar68,0);
558: *(short *)(param_1[6] + 2) = sVar28 - sVar38;
559: *(short *)(param_1[6] + 4) = sVar29 - sVar14;
560: *(short *)(param_1[6] + 6) = sVar48 - sVar15;
561: *(short *)(param_1[6] + 8) = sVar50 - sVar17;
562: *(short *)(param_1[6] + 10) = sVar53 - sVar22;
563: *(short *)(param_1[6] + 0xc) = sVar54 - sVar65;
564: *(short *)(param_1[6] + 0xe) = sVar40 - sVar24;
565: *(short *)*param_1 = sVar10 + sVar61;
566: *(short *)(*param_1 + 2) = sVar12 + sVar81;
567: *(short *)(*param_1 + 4) = sVar36 + sVar16;
568: *(short *)(*param_1 + 6) = sVar32 + sVar6;
569: *(short *)(*param_1 + 8) = sVar21 + sVar8;
570: *(short *)(*param_1 + 10) = sVar27 + sVar44;
571: *(short *)(*param_1 + 0xc) = sVar71 + sVar31;
572: *(short *)(*param_1 + 0xe) = sVar37 + sVar13;
573: *(short *)param_1[2] = sVar20 + SUB162(auVar68,0);
574: *(short *)(param_1[2] + 2) = sVar28 + sVar38;
575: *(short *)(param_1[2] + 4) = sVar29 + sVar14;
576: *(short *)(param_1[2] + 6) = sVar48 + sVar15;
577: *(short *)(param_1[2] + 8) = sVar50 + sVar17;
578: *(short *)(param_1[2] + 10) = sVar53 + sVar22;
579: *(short *)(param_1[2] + 0xc) = sVar54 + sVar65;
580: *(short *)(param_1[2] + 0xe) = sVar40 + sVar24;
581: auVar59 = psllw(CONCAT214((sVar30 - sVar62) + sStack42,
582: CONCAT212((sVar74 - sVar87) + sVar66,
583: CONCAT210((sVar18 - sStack30) + sStack46,
584: CONCAT28((sVar94 - sStack32) + (sStack48 - sVar95),
585: CONCAT26((sVar75 - sVar79) + sVar69,
586: CONCAT24((sVar43 - sVar45) +
587: sVar41,CONCAT22((sVar9 - 
588: sVar91) + sVar84,
589: (sVar42 - sVar49) + (sVar23 - sVar46)))))))),2);
590: auVar34 = psllw(CONCAT214(sVar89 + sVar33,
591: CONCAT212(sVar86 + sVar11,
592: CONCAT210(sVar83 + sVar52,
593: CONCAT28(sVar80 + sVar25,
594: CONCAT26(sVar76 + sVar67,
595: CONCAT24(sVar73 + sVar7,
596: CONCAT22(sVar78 + sVar35,
597: sVar63 + sVar19)
598: )))))),2);
599: auVar68 = psllw(CONCAT214(sStack42 + sVar89,
600: CONCAT212(sVar66 + sVar86,
601: CONCAT210(sStack46 + sVar83,
602: CONCAT28((sStack48 - sVar95) + sVar80,
603: CONCAT26(sVar69 + sVar76,
604: CONCAT24(sVar41 + sVar73,
605: CONCAT22(sVar84 + sVar78,
606: (sVar23 - sVar46
607: ) + sVar63))))))
608: ),2);
609: auVar68 = pmulhw(auVar68,_DAT_0019ca20);
610: auVar60 = pmulhw(CONCAT214(SUB162(auVar59 >> 0x70,0) - SUB162(auVar34 >> 0x70,0),
611: CONCAT212(SUB162(auVar59 >> 0x60,0) - SUB162(auVar34 >> 0x60,0),
612: CONCAT210(SUB162(auVar59 >> 0x50,0) -
613: SUB162(auVar34 >> 0x50,0),
614: CONCAT28(SUB162(auVar59 >> 0x40,0) -
615: SUB162(auVar34 >> 0x40,0),
616: CONCAT26(SUB162(auVar59 >> 0x30,0) -
617: SUB162(auVar34 >> 0x30,0),
618: CONCAT24(SUB162(auVar59 >> 0x20,0
619: ) - SUB162(auVar34
620: >> 0x20
621: ,0),CONCAT22(SUB162(auVar59 >> 0x10,0) -
622: SUB162(auVar34 >> 0x10,0),
623: SUB162(auVar59,0) - SUB162(auVar34,0)
624: ))))))),_DAT_0019ca30);
625: auVar59 = pmulhw(auVar59,_DAT_0019ca40);
626: auVar34 = pmulhw(auVar34,_DAT_0019ca50);
627: sVar44 = SUB162(auVar59,0) + SUB162(auVar60,0);
628: sVar21 = SUB162(auVar60 >> 0x10,0);
629: sVar31 = SUB162(auVar59 >> 0x10,0) + sVar21;
630: sVar38 = SUB162(auVar60 >> 0x20,0);
631: sVar13 = SUB162(auVar59 >> 0x20,0) + sVar38;
632: sVar23 = SUB162(auVar60 >> 0x30,0);
633: sVar46 = SUB162(auVar59 >> 0x30,0) + sVar23;
634: sVar8 = SUB162(auVar60 >> 0x40,0);
635: sVar14 = SUB162(auVar59 >> 0x40,0) + sVar8;
636: sVar41 = SUB162(auVar60 >> 0x50,0);
637: sVar15 = SUB162(auVar59 >> 0x50,0) + sVar41;
638: sVar9 = SUB162(auVar60 >> 0x60,0);
639: sVar66 = SUB162(auVar59 >> 0x60,0) + sVar9;
640: sVar27 = SUB162(auVar60 >> 0x70,0);
641: sVar17 = SUB162(auVar59 >> 0x70,0) + sVar27;
642: sVar6 = SUB162(auVar34,0) + SUB162(auVar60,0);
643: sVar21 = SUB162(auVar34 >> 0x10,0) + sVar21;
644: sVar38 = SUB162(auVar34 >> 0x20,0) + sVar38;
645: sVar23 = SUB162(auVar34 >> 0x30,0) + sVar23;
646: sVar8 = SUB162(auVar34 >> 0x40,0) + sVar8;
647: sVar41 = SUB162(auVar34 >> 0x50,0) + sVar41;
648: sVar9 = SUB162(auVar34 >> 0x60,0) + sVar9;
649: sVar27 = SUB162(auVar34 >> 0x70,0) + sVar27;
650: sVar18 = sVar19 - SUB162(auVar68,0);
651: sVar84 = SUB162(auVar68 >> 0x10,0);
652: sVar20 = sVar35 - sVar84;
653: sVar69 = SUB162(auVar68 >> 0x20,0);
654: sVar22 = sVar7 - sVar69;
655: sVar61 = SUB162(auVar68 >> 0x30,0);
656: sVar65 = sVar67 - sVar61;
657: sVar10 = SUB162(auVar68 >> 0x40,0);
658: sVar24 = sVar25 - sVar10;
659: sVar12 = SUB162(auVar68 >> 0x50,0);
660: sVar71 = sVar52 - sVar12;
661: sVar81 = SUB162(auVar68 >> 0x60,0);
662: sVar37 = sVar11 - sVar81;
663: sVar16 = SUB162(auVar68 >> 0x70,0);
664: sVar26 = sVar33 - sVar16;
665: sVar19 = sVar19 + SUB162(auVar68,0);
666: sVar35 = sVar35 + sVar84;
667: sVar7 = sVar7 + sVar69;
668: sVar67 = sVar67 + sVar61;
669: sVar25 = sVar25 + sVar10;
670: sVar52 = sVar52 + sVar12;
671: sVar11 = sVar11 + sVar81;
672: sVar33 = sVar33 + sVar16;
673: *(short *)param_1[3] = sVar18 - sVar44;
674: *(short *)(param_1[3] + 2) = sVar20 - sVar31;
675: *(short *)(param_1[3] + 4) = sVar22 - sVar13;
676: *(short *)(param_1[3] + 6) = sVar65 - sVar46;
677: *(short *)(param_1[3] + 8) = sVar24 - sVar14;
678: *(short *)(param_1[3] + 10) = sVar71 - sVar15;
679: *(short *)(param_1[3] + 0xc) = sVar37 - sVar66;
680: *(short *)(param_1[3] + 0xe) = sVar26 - sVar17;
681: *(short *)param_1[7] = sVar19 - sVar6;
682: *(short *)(param_1[7] + 2) = sVar35 - sVar21;
683: *(short *)(param_1[7] + 4) = sVar7 - sVar38;
684: *(short *)(param_1[7] + 6) = sVar67 - sVar23;
685: *(short *)(param_1[7] + 8) = sVar25 - sVar8;
686: *(short *)(param_1[7] + 10) = sVar52 - sVar41;
687: *(short *)(param_1[7] + 0xc) = sVar11 - sVar9;
688: *(short *)(param_1[7] + 0xe) = sVar33 - sVar27;
689: *(short *)param_1[5] = sVar18 + sVar44;
690: *(short *)(param_1[5] + 2) = sVar20 + sVar31;
691: *(short *)(param_1[5] + 4) = sVar22 + sVar13;
692: *(short *)(param_1[5] + 6) = sVar65 + sVar46;
693: *(short *)(param_1[5] + 8) = sVar24 + sVar14;
694: *(short *)(param_1[5] + 10) = sVar71 + sVar15;
695: *(short *)(param_1[5] + 0xc) = sVar37 + sVar66;
696: *(short *)(param_1[5] + 0xe) = sVar26 + sVar17;
697: *(short *)param_1[1] = sVar19 + sVar6;
698: *(short *)(param_1[1] + 2) = sVar35 + sVar21;
699: *(short *)(param_1[1] + 4) = sVar7 + sVar38;
700: *(short *)(param_1[1] + 6) = sVar67 + sVar23;
701: *(short *)(param_1[1] + 8) = sVar25 + sVar8;
702: *(short *)(param_1[1] + 10) = sVar52 + sVar41;
703: *(short *)(param_1[1] + 0xc) = sVar11 + sVar9;
704: *(short *)(param_1[1] + 0xe) = sVar33 + sVar27;
705: return;
706: }
707: 

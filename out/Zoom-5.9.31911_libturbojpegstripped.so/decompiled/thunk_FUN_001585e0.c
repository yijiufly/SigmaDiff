1: 
2: char * thunk_FUN_001585e0(long param_1,char *param_2,short *param_3,int param_4,long param_5,
3: uint *param_6)
4: 
5: {
6: byte bVar1;
7: byte bVar2;
8: byte bVar3;
9: char *pcVar4;
10: char *pcVar5;
11: byte bVar6;
12: char cVar7;
13: char cVar8;
14: uint uVar9;
15: ushort *puVar10;
16: uint uVar11;
17: ulong uVar12;
18: int iVar13;
19: uint uVar14;
20: ulong uVar15;
21: long lVar16;
22: uint uVar17;
23: short sVar19;
24: short sVar20;
25: short sVar21;
26: short sVar22;
27: short sVar23;
28: short sVar24;
29: undefined auVar18 [16];
30: undefined in_XMM0 [16];
31: short sVar26;
32: short sVar27;
33: short sVar28;
34: short sVar29;
35: short sVar30;
36: short sVar31;
37: undefined auVar25 [16];
38: undefined in_XMM1 [16];
39: short sVar33;
40: short sVar34;
41: short sVar35;
42: short sVar36;
43: short sVar37;
44: short sVar38;
45: undefined auVar32 [16];
46: undefined in_XMM2 [16];
47: short sVar40;
48: short sVar41;
49: short sVar42;
50: short sVar43;
51: short sVar44;
52: short sVar45;
53: undefined auVar39 [16];
54: undefined in_XMM3 [16];
55: undefined in_XMM4 [16];
56: undefined in_XMM5 [16];
57: undefined in_XMM6 [16];
58: undefined in_XMM7 [16];
59: ushort uStack144;
60: ushort uStack142;
61: ushort uStack140;
62: ushort uStack138;
63: ushort uStack136;
64: ushort uStack134;
65: ushort uStack132;
66: ushort uStack130;
67: ushort uStack128;
68: ushort uStack126;
69: ushort uStack124;
70: ushort uStack122;
71: ushort uStack120;
72: ushort uStack118;
73: ushort uStack116;
74: ushort uStack114;
75: ushort uStack112;
76: ushort uStack110;
77: ushort uStack108;
78: ushort uStack106;
79: ushort uStack104;
80: ushort uStack102;
81: ushort uStack100;
82: ushort uStack98;
83: ushort uStack96;
84: ushort uStack94;
85: ushort uStack92;
86: ushort uStack90;
87: ushort uStack88;
88: ushort uStack86;
89: ushort uStack84;
90: ushort uStack82;
91: ushort uStack80;
92: ushort uStack78;
93: ushort uStack76;
94: ushort uStack74;
95: ushort uStack72;
96: ushort uStack70;
97: ushort uStack68;
98: ushort uStack66;
99: ushort uStack64;
100: ushort uStack62;
101: ushort uStack60;
102: ushort uStack58;
103: ushort uStack56;
104: ushort uStack54;
105: ushort uStack52;
106: ushort uStack50;
107: ushort uStack48;
108: ushort uStack46;
109: ushort uStack44;
110: ushort uStack42;
111: ushort uStack40;
112: ushort uStack38;
113: ushort uStack36;
114: ushort uStack34;
115: ushort uStack32;
116: ushort uStack30;
117: ushort uStack28;
118: ushort uStack26;
119: ushort uStack24;
120: ushort uStack22;
121: ushort uStack20;
122: ushort uStack18;
123: undefined *puStack16;
124: 
125: puStack16 = &stack0xfffffffffffffff8;
126: uVar12 = *(ulong *)(param_1 + 0x10);
127: iVar13 = *(int *)(param_1 + 0x18);
128: uVar11 = *param_3 - param_4;
129: uVar9 = (int)uVar11 >> 0x1f;
130: bVar1 = (&DAT_0018c900)[(uVar11 ^ uVar9) - uVar9];
131: uVar14 = *(uint *)(param_5 + (ulong)bVar1 * 4);
132: bVar2 = *(byte *)(param_5 + 0x400 + (ulong)bVar1);
133: if (0x2f < iVar13) {
134: cVar8 = (char)iVar13;
135: cVar7 = (char)(uVar12 >> (cVar8 - 8U & 0x3f));
136: *param_2 = cVar7;
137: pcVar4 = param_2 + 1;
138: if (cVar7 == -1) {
139: *pcVar4 = '\0';
140: pcVar4 = param_2 + 2;
141: }
142: cVar7 = (char)(uVar12 >> (cVar8 - 0x10U & 0x3f));
143: *pcVar4 = cVar7;
144: pcVar5 = pcVar4 + 1;
145: if (cVar7 == -1) {
146: *pcVar5 = '\0';
147: pcVar5 = pcVar4 + 2;
148: }
149: cVar7 = (char)(uVar12 >> (cVar8 - 0x18U & 0x3f));
150: *pcVar5 = cVar7;
151: pcVar4 = pcVar5 + 1;
152: if (cVar7 == -1) {
153: *pcVar4 = '\0';
154: pcVar4 = pcVar5 + 2;
155: }
156: cVar7 = (char)(uVar12 >> (cVar8 - 0x20U & 0x3f));
157: *pcVar4 = cVar7;
158: pcVar5 = pcVar4 + 1;
159: if (cVar7 == -1) {
160: *pcVar5 = '\0';
161: pcVar5 = pcVar4 + 2;
162: }
163: cVar8 = (char)(uVar12 >> (cVar8 - 0x28U & 0x3f));
164: *pcVar5 = cVar8;
165: pcVar4 = pcVar5 + 1;
166: if (cVar8 == -1) {
167: *pcVar4 = '\0';
168: pcVar4 = pcVar5 + 2;
169: }
170: iVar13 = iVar13 + -0x30;
171: cVar8 = (char)(uVar12 >> ((byte)iVar13 & 0x3f));
172: *pcVar4 = cVar8;
173: param_2 = pcVar4 + 1;
174: if (cVar8 == -1) {
175: *param_2 = '\0';
176: param_2 = pcVar4 + 2;
177: }
178: }
179: iVar13 = iVar13 + (uint)bVar2;
180: uVar12 = uVar12 << (bVar2 & 0x3f) | (ulong)uVar14;
181: if (0x2f < iVar13) {
182: cVar8 = (char)iVar13;
183: cVar7 = (char)(uVar12 >> (cVar8 - 8U & 0x3f));
184: *param_2 = cVar7;
185: pcVar4 = param_2 + 1;
186: if (cVar7 == -1) {
187: *pcVar4 = '\0';
188: pcVar4 = param_2 + 2;
189: }
190: cVar7 = (char)(uVar12 >> (cVar8 - 0x10U & 0x3f));
191: *pcVar4 = cVar7;
192: pcVar5 = pcVar4 + 1;
193: if (cVar7 == -1) {
194: *pcVar5 = '\0';
195: pcVar5 = pcVar4 + 2;
196: }
197: cVar7 = (char)(uVar12 >> (cVar8 - 0x18U & 0x3f));
198: *pcVar5 = cVar7;
199: pcVar4 = pcVar5 + 1;
200: if (cVar7 == -1) {
201: *pcVar4 = '\0';
202: pcVar4 = pcVar5 + 2;
203: }
204: cVar7 = (char)(uVar12 >> (cVar8 - 0x20U & 0x3f));
205: *pcVar4 = cVar7;
206: pcVar5 = pcVar4 + 1;
207: if (cVar7 == -1) {
208: *pcVar5 = '\0';
209: pcVar5 = pcVar4 + 2;
210: }
211: cVar8 = (char)(uVar12 >> (cVar8 - 0x28U & 0x3f));
212: *pcVar5 = cVar8;
213: pcVar4 = pcVar5 + 1;
214: if (cVar8 == -1) {
215: *pcVar4 = '\0';
216: pcVar4 = pcVar5 + 2;
217: }
218: iVar13 = iVar13 + -0x30;
219: cVar8 = (char)(uVar12 >> ((byte)iVar13 & 0x3f));
220: *pcVar4 = cVar8;
221: param_2 = pcVar4 + 1;
222: if (cVar8 == -1) {
223: *param_2 = '\0';
224: param_2 = pcVar4 + 2;
225: }
226: }
227: iVar13 = iVar13 + (uint)bVar1;
228: uVar12 = uVar12 << (bVar1 & 0x3f) | (ulong)(uVar11 + uVar9 & (1 << (bVar1 & 0x1f)) - 1U);
229: auVar18 = pinsrw(in_XMM0,param_3[1],0);
230: auVar25 = pinsrw(in_XMM1,param_3[0x18],0);
231: auVar32 = pinsrw(in_XMM2,param_3[0x13],0);
232: auVar39 = pinsrw(in_XMM3,param_3[0x14],0);
233: auVar18 = pinsrw(auVar18,param_3[8],1);
234: auVar25 = pinsrw(auVar25,param_3[0x20],1);
235: auVar32 = pinsrw(auVar32,param_3[0x1a],1);
236: auVar39 = pinsrw(auVar39,param_3[0xd],1);
237: auVar18 = pinsrw(auVar18,param_3[0x10],2);
238: auVar25 = pinsrw(auVar25,param_3[0x19],2);
239: auVar32 = pinsrw(auVar32,param_3[0x21],2);
240: auVar39 = pinsrw(auVar39,param_3[6],2);
241: auVar18 = pinsrw(auVar18,param_3[9],3);
242: auVar25 = pinsrw(auVar25,param_3[0x12],3);
243: auVar32 = pinsrw(auVar32,param_3[0x28],3);
244: auVar39 = pinsrw(auVar39,param_3[7],3);
245: auVar18 = pinsrw(auVar18,param_3[2],4);
246: auVar25 = pinsrw(auVar25,param_3[0xb],4);
247: auVar32 = pinsrw(auVar32,param_3[0x30],4);
248: auVar39 = pinsrw(auVar39,param_3[0xe],4);
249: auVar18 = pinsrw(auVar18,param_3[3],5);
250: auVar25 = pinsrw(auVar25,param_3[4],5);
251: auVar32 = pinsrw(auVar32,param_3[0x29],5);
252: auVar39 = pinsrw(auVar39,param_3[0x15],5);
253: auVar18 = pinsrw(auVar18,param_3[10],6);
254: auVar25 = pinsrw(auVar25,param_3[5],6);
255: auVar32 = pinsrw(auVar32,param_3[0x22],6);
256: auVar39 = pinsrw(auVar39,param_3[0x1c],6);
257: auVar18 = pinsrw(auVar18,param_3[0x11],7);
258: auVar25 = pinsrw(auVar25,param_3[0xc],7);
259: auVar32 = pinsrw(auVar32,param_3[0x1b],7);
260: auVar39 = pinsrw(auVar39,param_3[0x23],7);
261: uStack144 = -(ushort)(SUB162(auVar18,0) < 0);
262: sVar19 = SUB162(auVar18 >> 0x10,0);
263: uStack142 = -(ushort)(sVar19 < 0);
264: sVar20 = SUB162(auVar18 >> 0x20,0);
265: uStack140 = -(ushort)(sVar20 < 0);
266: sVar21 = SUB162(auVar18 >> 0x30,0);
267: uStack138 = -(ushort)(sVar21 < 0);
268: sVar22 = SUB162(auVar18 >> 0x40,0);
269: uStack136 = -(ushort)(sVar22 < 0);
270: sVar23 = SUB162(auVar18 >> 0x50,0);
271: uStack134 = -(ushort)(sVar23 < 0);
272: sVar24 = SUB162(auVar18 >> 0x60,0);
273: uStack132 = -(ushort)(sVar24 < 0);
274: uStack128 = -(ushort)(SUB162(auVar25,0) < 0);
275: sVar26 = SUB162(auVar25 >> 0x10,0);
276: uStack126 = -(ushort)(sVar26 < 0);
277: sVar27 = SUB162(auVar25 >> 0x20,0);
278: uStack124 = -(ushort)(sVar27 < 0);
279: sVar28 = SUB162(auVar25 >> 0x30,0);
280: uStack122 = -(ushort)(sVar28 < 0);
281: sVar29 = SUB162(auVar25 >> 0x40,0);
282: uStack120 = -(ushort)(sVar29 < 0);
283: sVar30 = SUB162(auVar25 >> 0x50,0);
284: uStack118 = -(ushort)(sVar30 < 0);
285: sVar31 = SUB162(auVar25 >> 0x60,0);
286: uStack116 = -(ushort)(sVar31 < 0);
287: uStack112 = -(ushort)(SUB162(auVar32,0) < 0);
288: sVar33 = SUB162(auVar32 >> 0x10,0);
289: uStack110 = -(ushort)(sVar33 < 0);
290: sVar34 = SUB162(auVar32 >> 0x20,0);
291: uStack108 = -(ushort)(sVar34 < 0);
292: sVar35 = SUB162(auVar32 >> 0x30,0);
293: uStack106 = -(ushort)(sVar35 < 0);
294: sVar36 = SUB162(auVar32 >> 0x40,0);
295: uStack104 = -(ushort)(sVar36 < 0);
296: sVar37 = SUB162(auVar32 >> 0x50,0);
297: uStack102 = -(ushort)(sVar37 < 0);
298: sVar38 = SUB162(auVar32 >> 0x60,0);
299: uStack100 = -(ushort)(sVar38 < 0);
300: uStack96 = -(ushort)(SUB162(auVar39,0) < 0);
301: sVar40 = SUB162(auVar39 >> 0x10,0);
302: uStack94 = -(ushort)(sVar40 < 0);
303: sVar41 = SUB162(auVar39 >> 0x20,0);
304: uStack92 = -(ushort)(sVar41 < 0);
305: sVar42 = SUB162(auVar39 >> 0x30,0);
306: uStack90 = -(ushort)(sVar42 < 0);
307: sVar43 = SUB162(auVar39 >> 0x40,0);
308: uStack88 = -(ushort)(sVar43 < 0);
309: sVar44 = SUB162(auVar39 >> 0x50,0);
310: uStack86 = -(ushort)(sVar44 < 0);
311: sVar45 = SUB162(auVar39 >> 0x60,0);
312: uStack84 = -(ushort)(sVar45 < 0);
313: uStack144 = SUB162(auVar18,0) + uStack144 ^ uStack144;
314: uStack142 = sVar19 + uStack142 ^ uStack142;
315: uStack140 = sVar20 + uStack140 ^ uStack140;
316: uStack138 = sVar21 + uStack138 ^ uStack138;
317: uStack136 = sVar22 + uStack136 ^ uStack136;
318: uStack134 = sVar23 + uStack134 ^ uStack134;
319: uStack132 = sVar24 + uStack132 ^ uStack132;
320: uStack130 = SUB162(auVar18 >> 0x70,0) + -(ushort)(auVar18 < (undefined  [16])0x0) ^
321: -(ushort)(auVar18 < (undefined  [16])0x0);
322: uStack128 = SUB162(auVar25,0) + uStack128 ^ uStack128;
323: uStack126 = sVar26 + uStack126 ^ uStack126;
324: uStack124 = sVar27 + uStack124 ^ uStack124;
325: uStack122 = sVar28 + uStack122 ^ uStack122;
326: uStack120 = sVar29 + uStack120 ^ uStack120;
327: uStack118 = sVar30 + uStack118 ^ uStack118;
328: uStack116 = sVar31 + uStack116 ^ uStack116;
329: uStack114 = SUB162(auVar25 >> 0x70,0) + -(ushort)(auVar25 < (undefined  [16])0x0) ^
330: -(ushort)(auVar25 < (undefined  [16])0x0);
331: uStack112 = SUB162(auVar32,0) + uStack112 ^ uStack112;
332: uStack110 = sVar33 + uStack110 ^ uStack110;
333: uStack108 = sVar34 + uStack108 ^ uStack108;
334: uStack106 = sVar35 + uStack106 ^ uStack106;
335: uStack104 = sVar36 + uStack104 ^ uStack104;
336: uStack102 = sVar37 + uStack102 ^ uStack102;
337: uStack100 = sVar38 + uStack100 ^ uStack100;
338: uStack98 = SUB162(auVar32 >> 0x70,0) + -(ushort)(auVar32 < (undefined  [16])0x0) ^
339: -(ushort)(auVar32 < (undefined  [16])0x0);
340: uStack96 = SUB162(auVar39,0) + uStack96 ^ uStack96;
341: uStack94 = sVar40 + uStack94 ^ uStack94;
342: uStack92 = sVar41 + uStack92 ^ uStack92;
343: uStack90 = sVar42 + uStack90 ^ uStack90;
344: uStack88 = sVar43 + uStack88 ^ uStack88;
345: uStack86 = sVar44 + uStack86 ^ uStack86;
346: uStack84 = sVar45 + uStack84 ^ uStack84;
347: uStack82 = SUB162(auVar39 >> 0x70,0) + -(ushort)(auVar39 < (undefined  [16])0x0) ^
348: -(ushort)(auVar39 < (undefined  [16])0x0);
349: auVar18 = pinsrw(in_XMM4,param_3[0x2a],0);
350: auVar25 = pinsrw(in_XMM5,param_3[0x16],0);
351: auVar32 = pinsrw(in_XMM6,param_3[0x3b],0);
352: auVar39 = pinsrw(in_XMM7,param_3[0x3c],0);
353: auVar18 = pinsrw(auVar18,param_3[0x31],1);
354: auVar25 = pinsrw(auVar25,param_3[0xf],1);
355: auVar32 = pinsrw(auVar32,param_3[0x34],1);
356: auVar39 = pinsrw(auVar39,param_3[0x3d],1);
357: auVar18 = pinsrw(auVar18,param_3[0x38],2);
358: auVar25 = pinsrw(auVar25,param_3[0x17],2);
359: auVar32 = pinsrw(auVar32,param_3[0x2d],2);
360: auVar39 = pinsrw(auVar39,param_3[0x36],2);
361: auVar18 = pinsrw(auVar18,param_3[0x39],3);
362: auVar25 = pinsrw(auVar25,param_3[0x1e],3);
363: auVar32 = pinsrw(auVar32,param_3[0x26],3);
364: auVar39 = pinsrw(auVar39,param_3[0x2f],3);
365: auVar18 = pinsrw(auVar18,param_3[0x32],4);
366: auVar25 = pinsrw(auVar25,param_3[0x25],4);
367: auVar32 = pinsrw(auVar32,param_3[0x1f],4);
368: auVar39 = pinsrw(auVar39,param_3[0x37],4);
369: auVar18 = pinsrw(auVar18,param_3[0x2b],5);
370: auVar25 = pinsrw(auVar25,param_3[0x2c],5);
371: auVar32 = pinsrw(auVar32,param_3[0x27],5);
372: auVar39 = pinsrw(auVar39,param_3[0x3e],5);
373: auVar18 = pinsrw(auVar18,param_3[0x24],6);
374: auVar25 = pinsrw(auVar25,param_3[0x33],6);
375: auVar32 = pinsrw(auVar32,param_3[0x2e],6);
376: auVar39 = pinsrw(auVar39,param_3[0x3f],6);
377: auVar18 = pinsrw(auVar18,param_3[0x1d],7);
378: auVar25 = pinsrw(auVar25,param_3[0x3a],7);
379: auVar32 = pinsrw(auVar32,param_3[0x35],7);
380: auVar39 = pinsrw(auVar39,0,7);
381: uStack80 = -(ushort)(SUB162(auVar18,0) < 0);
382: sVar19 = SUB162(auVar18 >> 0x10,0);
383: uStack78 = -(ushort)(sVar19 < 0);
384: sVar20 = SUB162(auVar18 >> 0x20,0);
385: uStack76 = -(ushort)(sVar20 < 0);
386: sVar21 = SUB162(auVar18 >> 0x30,0);
387: uStack74 = -(ushort)(sVar21 < 0);
388: sVar22 = SUB162(auVar18 >> 0x40,0);
389: uStack72 = -(ushort)(sVar22 < 0);
390: sVar23 = SUB162(auVar18 >> 0x50,0);
391: uStack70 = -(ushort)(sVar23 < 0);
392: sVar24 = SUB162(auVar18 >> 0x60,0);
393: uStack68 = -(ushort)(sVar24 < 0);
394: uStack64 = -(ushort)(SUB162(auVar25,0) < 0);
395: sVar26 = SUB162(auVar25 >> 0x10,0);
396: uStack62 = -(ushort)(sVar26 < 0);
397: sVar27 = SUB162(auVar25 >> 0x20,0);
398: uStack60 = -(ushort)(sVar27 < 0);
399: sVar28 = SUB162(auVar25 >> 0x30,0);
400: uStack58 = -(ushort)(sVar28 < 0);
401: sVar29 = SUB162(auVar25 >> 0x40,0);
402: uStack56 = -(ushort)(sVar29 < 0);
403: sVar30 = SUB162(auVar25 >> 0x50,0);
404: uStack54 = -(ushort)(sVar30 < 0);
405: sVar31 = SUB162(auVar25 >> 0x60,0);
406: uStack52 = -(ushort)(sVar31 < 0);
407: uStack48 = -(ushort)(SUB162(auVar32,0) < 0);
408: sVar33 = SUB162(auVar32 >> 0x10,0);
409: uStack46 = -(ushort)(sVar33 < 0);
410: sVar34 = SUB162(auVar32 >> 0x20,0);
411: uStack44 = -(ushort)(sVar34 < 0);
412: sVar35 = SUB162(auVar32 >> 0x30,0);
413: uStack42 = -(ushort)(sVar35 < 0);
414: sVar36 = SUB162(auVar32 >> 0x40,0);
415: uStack40 = -(ushort)(sVar36 < 0);
416: sVar37 = SUB162(auVar32 >> 0x50,0);
417: uStack38 = -(ushort)(sVar37 < 0);
418: sVar38 = SUB162(auVar32 >> 0x60,0);
419: uStack36 = -(ushort)(sVar38 < 0);
420: uStack32 = -(ushort)(SUB162(auVar39,0) < 0);
421: sVar40 = SUB162(auVar39 >> 0x10,0);
422: uStack30 = -(ushort)(sVar40 < 0);
423: sVar41 = SUB162(auVar39 >> 0x20,0);
424: uStack28 = -(ushort)(sVar41 < 0);
425: sVar42 = SUB162(auVar39 >> 0x30,0);
426: uStack26 = -(ushort)(sVar42 < 0);
427: sVar43 = SUB162(auVar39 >> 0x40,0);
428: uStack24 = -(ushort)(sVar43 < 0);
429: sVar44 = SUB162(auVar39 >> 0x50,0);
430: uStack22 = -(ushort)(sVar44 < 0);
431: sVar45 = SUB162(auVar39 >> 0x60,0);
432: uStack20 = -(ushort)(sVar45 < 0);
433: uStack80 = SUB162(auVar18,0) + uStack80 ^ uStack80;
434: uStack78 = sVar19 + uStack78 ^ uStack78;
435: uStack76 = sVar20 + uStack76 ^ uStack76;
436: uStack74 = sVar21 + uStack74 ^ uStack74;
437: uStack72 = sVar22 + uStack72 ^ uStack72;
438: uStack70 = sVar23 + uStack70 ^ uStack70;
439: uStack68 = sVar24 + uStack68 ^ uStack68;
440: uStack66 = SUB162(auVar18 >> 0x70,0) + -(ushort)(auVar18 < (undefined  [16])0x0) ^
441: -(ushort)(auVar18 < (undefined  [16])0x0);
442: uStack64 = SUB162(auVar25,0) + uStack64 ^ uStack64;
443: uStack62 = sVar26 + uStack62 ^ uStack62;
444: uStack60 = sVar27 + uStack60 ^ uStack60;
445: uStack58 = sVar28 + uStack58 ^ uStack58;
446: uStack56 = sVar29 + uStack56 ^ uStack56;
447: uStack54 = sVar30 + uStack54 ^ uStack54;
448: uStack52 = sVar31 + uStack52 ^ uStack52;
449: uStack50 = SUB162(auVar25 >> 0x70,0) + -(ushort)(auVar25 < (undefined  [16])0x0) ^
450: -(ushort)(auVar25 < (undefined  [16])0x0);
451: uStack48 = SUB162(auVar32,0) + uStack48 ^ uStack48;
452: uStack46 = sVar33 + uStack46 ^ uStack46;
453: uStack44 = sVar34 + uStack44 ^ uStack44;
454: uStack42 = sVar35 + uStack42 ^ uStack42;
455: uStack40 = sVar36 + uStack40 ^ uStack40;
456: uStack38 = sVar37 + uStack38 ^ uStack38;
457: uStack36 = sVar38 + uStack36 ^ uStack36;
458: uStack34 = SUB162(auVar32 >> 0x70,0) + -(ushort)(auVar32 < (undefined  [16])0x0) ^
459: -(ushort)(auVar32 < (undefined  [16])0x0);
460: uStack32 = SUB162(auVar39,0) + uStack32 ^ uStack32;
461: uStack30 = sVar40 + uStack30 ^ uStack30;
462: uStack28 = sVar41 + uStack28 ^ uStack28;
463: uStack26 = sVar42 + uStack26 ^ uStack26;
464: uStack24 = sVar43 + uStack24 ^ uStack24;
465: uStack22 = sVar44 + uStack22 ^ uStack22;
466: uStack20 = sVar45 + uStack20 ^ uStack20;
467: uStack18 = SUB162(auVar39 >> 0x70,0) + -(ushort)(auVar39 < (undefined  [16])0x0) ^
468: -(ushort)(auVar39 < (undefined  [16])0x0);
469: auVar18 = packsswb(CONCAT214(-(ushort)(uStack130 == 0),
470: CONCAT212(-(ushort)(uStack132 == 0),
471: CONCAT210(-(ushort)(uStack134 == 0),
472: CONCAT28(-(ushort)(uStack136 == 0),
473: CONCAT26(-(ushort)(uStack138 == 0),
474: CONCAT24(-(ushort)(uStack140 ==
475: 0),
476: CONCAT22(-(ushort)(
477: uStack142 == 0),-(ushort)(uStack144 == 0)))))))),
478: CONCAT214(-(ushort)(uStack114 == 0),
479: CONCAT212(-(ushort)(uStack116 == 0),
480: CONCAT210(-(ushort)(uStack118 == 0),
481: CONCAT28(-(ushort)(uStack120 == 0),
482: CONCAT26(-(ushort)(uStack122 == 0),
483: CONCAT24(-(ushort)(uStack124 ==
484: 0),
485: CONCAT22(-(ushort)(
486: uStack126 == 0),-(ushort)(uStack128 == 0)))))))));
487: auVar25 = packsswb(CONCAT214(-(ushort)(uStack98 == 0),
488: CONCAT212(-(ushort)(uStack100 == 0),
489: CONCAT210(-(ushort)(uStack102 == 0),
490: CONCAT28(-(ushort)(uStack104 == 0),
491: CONCAT26(-(ushort)(uStack106 == 0),
492: CONCAT24(-(ushort)(uStack108 ==
493: 0),
494: CONCAT22(-(ushort)(
495: uStack110 == 0),-(ushort)(uStack112 == 0)))))))),
496: CONCAT214(-(ushort)(uStack82 == 0),
497: CONCAT212(-(ushort)(uStack84 == 0),
498: CONCAT210(-(ushort)(uStack86 == 0),
499: CONCAT28(-(ushort)(uStack88 == 0),
500: CONCAT26(-(ushort)(uStack90 == 0),
501: CONCAT24(-(ushort)(uStack92 ==
502: 0),
503: CONCAT22(-(ushort)(
504: uStack94 == 0),-(ushort)(uStack96 == 0)))))))));
505: auVar32 = packsswb(CONCAT214(-(ushort)(uStack66 == 0),
506: CONCAT212(-(ushort)(uStack68 == 0),
507: CONCAT210(-(ushort)(uStack70 == 0),
508: CONCAT28(-(ushort)(uStack72 == 0),
509: CONCAT26(-(ushort)(uStack74 == 0),
510: CONCAT24(-(ushort)(uStack76 ==
511: 0),
512: CONCAT22(-(ushort)(
513: uStack78 == 0),-(ushort)(uStack80 == 0)))))))),
514: CONCAT214(-(ushort)(uStack50 == 0),
515: CONCAT212(-(ushort)(uStack52 == 0),
516: CONCAT210(-(ushort)(uStack54 == 0),
517: CONCAT28(-(ushort)(uStack56 == 0),
518: CONCAT26(-(ushort)(uStack58 == 0),
519: CONCAT24(-(ushort)(uStack60 ==
520: 0),
521: CONCAT22(-(ushort)(
522: uStack62 == 0),-(ushort)(uStack64 == 0)))))))));
523: auVar39 = packsswb(CONCAT214(-(ushort)(uStack34 == 0),
524: CONCAT212(-(ushort)(uStack36 == 0),
525: CONCAT210(-(ushort)(uStack38 == 0),
526: CONCAT28(-(ushort)(uStack40 == 0),
527: CONCAT26(-(ushort)(uStack42 == 0),
528: CONCAT24(-(ushort)(uStack44 ==
529: 0),
530: CONCAT22(-(ushort)(
531: uStack46 == 0),-(ushort)(uStack48 == 0)))))))),
532: CONCAT214(-(ushort)(uStack18 == 0),
533: CONCAT212(-(ushort)(uStack20 == 0),
534: CONCAT210(-(ushort)(uStack22 == 0),
535: CONCAT28(-(ushort)(uStack24 == 0),
536: CONCAT26(-(ushort)(uStack26 == 0),
537: CONCAT24(-(ushort)(uStack28 ==
538: 0),
539: CONCAT22(-(ushort)(
540: uStack30 == 0),-(ushort)(uStack32 == 0)))))))));
541: uVar14 = pmovmskb(uVar14,auVar18);
542: uVar9 = pmovmskb((int)param_3,auVar25);
543: uVar11 = pmovmskb(param_4,auVar32);
544: uVar17 = pmovmskb((int)param_5,auVar39);
545: uVar15 = ~((ulong)uVar14 | ((ulong)param_3 & 0xffffffff00000000 | (ulong)uVar9) << 0x10 |
546: ((ulong)uVar11 | (ulong)uVar17 << 0x10) << 0x20);
547: uVar14 = param_6[0xf0];
548: bVar1 = *(byte *)(param_6 + 0x13c);
549: puVar10 = &uStack144;
550: while( true ) {
551: lVar16 = 0;
552: if (uVar15 != 0) {
553: while ((uVar15 >> lVar16 & 1) == 0) {
554: lVar16 = lVar16 + 1;
555: }
556: }
557: if (uVar15 == 0) break;
558: puVar10 = puVar10 + lVar16;
559: bVar6 = (byte)lVar16;
560: bVar2 = (&DAT_0018c900)[*puVar10];
561: while (cVar8 = (char)iVar13, 0xf < lVar16) {
562: if (0x2f < iVar13) {
563: cVar7 = (char)(uVar12 >> (cVar8 - 8U & 0x3f));
564: *param_2 = cVar7;
565: pcVar4 = param_2 + 1;
566: if (cVar7 == -1) {
567: *pcVar4 = '\0';
568: pcVar4 = param_2 + 2;
569: }
570: cVar7 = (char)(uVar12 >> (cVar8 - 0x10U & 0x3f));
571: *pcVar4 = cVar7;
572: pcVar5 = pcVar4 + 1;
573: if (cVar7 == -1) {
574: *pcVar5 = '\0';
575: pcVar5 = pcVar4 + 2;
576: }
577: cVar7 = (char)(uVar12 >> (cVar8 - 0x18U & 0x3f));
578: *pcVar5 = cVar7;
579: pcVar4 = pcVar5 + 1;
580: if (cVar7 == -1) {
581: *pcVar4 = '\0';
582: pcVar4 = pcVar5 + 2;
583: }
584: cVar7 = (char)(uVar12 >> (cVar8 - 0x20U & 0x3f));
585: *pcVar4 = cVar7;
586: pcVar5 = pcVar4 + 1;
587: if (cVar7 == -1) {
588: *pcVar5 = '\0';
589: pcVar5 = pcVar4 + 2;
590: }
591: cVar8 = (char)(uVar12 >> (cVar8 - 0x28U & 0x3f));
592: *pcVar5 = cVar8;
593: pcVar4 = pcVar5 + 1;
594: if (cVar8 == -1) {
595: *pcVar4 = '\0';
596: pcVar4 = pcVar5 + 2;
597: }
598: iVar13 = iVar13 + -0x30;
599: cVar8 = (char)(uVar12 >> ((byte)iVar13 & 0x3f));
600: *pcVar4 = cVar8;
601: param_2 = pcVar4 + 1;
602: if (cVar8 == -1) {
603: *param_2 = '\0';
604: param_2 = pcVar4 + 2;
605: }
606: }
607: iVar13 = iVar13 + (uint)bVar1;
608: uVar12 = uVar12 << (bVar1 & 0x3f) | (ulong)uVar14;
609: lVar16 = lVar16 + -0x10;
610: }
611: if (0x1f < iVar13) {
612: cVar7 = (char)(uVar12 >> (cVar8 - 8U & 0x3f));
613: *param_2 = cVar7;
614: pcVar4 = param_2 + 1;
615: if (cVar7 == -1) {
616: *pcVar4 = '\0';
617: pcVar4 = param_2 + 2;
618: }
619: cVar7 = (char)(uVar12 >> (cVar8 - 0x10U & 0x3f));
620: *pcVar4 = cVar7;
621: pcVar5 = pcVar4 + 1;
622: if (cVar7 == -1) {
623: *pcVar5 = '\0';
624: pcVar5 = pcVar4 + 2;
625: }
626: cVar8 = (char)(uVar12 >> (cVar8 - 0x18U & 0x3f));
627: *pcVar5 = cVar8;
628: pcVar4 = pcVar5 + 1;
629: if (cVar8 == -1) {
630: *pcVar4 = '\0';
631: pcVar4 = pcVar5 + 2;
632: }
633: iVar13 = iVar13 + -0x20;
634: cVar8 = (char)(uVar12 >> ((byte)iVar13 & 0x3f));
635: *pcVar4 = cVar8;
636: param_2 = pcVar4 + 1;
637: if (cVar8 == -1) {
638: *param_2 = '\0';
639: param_2 = pcVar4 + 2;
640: }
641: }
642: lVar16 = lVar16 * 0x10 + (ulong)bVar2;
643: bVar3 = *(byte *)((long)param_6 + lVar16 + 0x400);
644: iVar13 = iVar13 + (uint)bVar3 + (uint)bVar2;
645: uVar12 = (uVar12 << (bVar3 & 0x3f) | (ulong)param_6[lVar16]) << (bVar2 & 0x3f) |
646: (ulong)(uint)(int)(short)puVar10[-0x40] & (1 << (bVar2 & 0x3f)) - 1U;
647: uVar15 = (uVar15 >> (bVar6 & 0x3f)) >> 1;
648: puVar10 = puVar10 + 1;
649: }
650: if (&uStack18 != puVar10) {
651: uVar14 = *param_6;
652: bVar1 = *(byte *)(param_6 + 0x100);
653: if (0x2f < iVar13) {
654: cVar8 = (char)iVar13;
655: cVar7 = (char)(uVar12 >> (cVar8 - 8U & 0x3f));
656: *param_2 = cVar7;
657: pcVar4 = param_2 + 1;
658: if (cVar7 == -1) {
659: *pcVar4 = '\0';
660: pcVar4 = param_2 + 2;
661: }
662: cVar7 = (char)(uVar12 >> (cVar8 - 0x10U & 0x3f));
663: *pcVar4 = cVar7;
664: pcVar5 = pcVar4 + 1;
665: if (cVar7 == -1) {
666: *pcVar5 = '\0';
667: pcVar5 = pcVar4 + 2;
668: }
669: cVar7 = (char)(uVar12 >> (cVar8 - 0x18U & 0x3f));
670: *pcVar5 = cVar7;
671: pcVar4 = pcVar5 + 1;
672: if (cVar7 == -1) {
673: *pcVar4 = '\0';
674: pcVar4 = pcVar5 + 2;
675: }
676: cVar7 = (char)(uVar12 >> (cVar8 - 0x20U & 0x3f));
677: *pcVar4 = cVar7;
678: pcVar5 = pcVar4 + 1;
679: if (cVar7 == -1) {
680: *pcVar5 = '\0';
681: pcVar5 = pcVar4 + 2;
682: }
683: cVar8 = (char)(uVar12 >> (cVar8 - 0x28U & 0x3f));
684: *pcVar5 = cVar8;
685: pcVar4 = pcVar5 + 1;
686: if (cVar8 == -1) {
687: *pcVar4 = '\0';
688: pcVar4 = pcVar5 + 2;
689: }
690: iVar13 = iVar13 + -0x30;
691: cVar8 = (char)(uVar12 >> ((byte)iVar13 & 0x3f));
692: *pcVar4 = cVar8;
693: param_2 = pcVar4 + 1;
694: if (cVar8 == -1) {
695: *param_2 = '\0';
696: param_2 = pcVar4 + 2;
697: }
698: }
699: iVar13 = iVar13 + (uint)bVar1;
700: uVar12 = uVar12 << (bVar1 & 0x3f) | (ulong)uVar14;
701: }
702: *(ulong *)(param_1 + 0x10) = uVar12;
703: *(int *)(param_1 + 0x18) = iVar13;
704: return param_2;
705: }
706: 

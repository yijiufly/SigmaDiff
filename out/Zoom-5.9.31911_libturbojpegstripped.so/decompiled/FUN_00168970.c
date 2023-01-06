1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
4: 
5: void FUN_00168970(undefined8 param_1,long param_2,short *param_3,long *param_4,uint param_5)
6: 
7: {
8: short *psVar1;
9: ulong uVar2;
10: uint3 uVar3;
11: int iVar4;
12: short sVar13;
13: short sVar14;
14: undefined8 uVar9;
15: short sVar15;
16: short sVar16;
17: short sVar18;
18: short sVar19;
19: short sVar20;
20: ulong uVar17;
21: short sVar22;
22: char cVar23;
23: char cVar29;
24: char cVar30;
25: char cVar31;
26: char cVar32;
27: char cVar33;
28: char cVar34;
29: char cVar35;
30: char cVar36;
31: char cVar37;
32: char cVar38;
33: undefined auVar28 [16];
34: undefined2 uVar39;
35: short sVar40;
36: short sVar41;
37: undefined4 uVar42;
38: short sVar48;
39: undefined8 uVar43;
40: short sVar46;
41: short sVar47;
42: short sVar49;
43: short sVar50;
44: short sVar51;
45: short sVar52;
46: short sVar53;
47: short sVar54;
48: short sVar55;
49: short sVar56;
50: short sVar57;
51: short sVar58;
52: short sVar59;
53: undefined auVar44 [16];
54: undefined auVar45 [16];
55: char cVar60;
56: char cVar67;
57: uint6 uVar63;
58: char cVar68;
59: char cVar69;
60: undefined auVar66 [16];
61: uint uVar70;
62: uint6 uVar71;
63: short sVar77;
64: short sVar78;
65: short sVar79;
66: short sVar80;
67: undefined auVar74 [16];
68: undefined auVar75 [16];
69: undefined auVar76 [16];
70: char cVar81;
71: short sVar82;
72: short sVar83;
73: undefined4 uVar85;
74: char cVar102;
75: uint6 uVar87;
76: char cVar106;
77: ulong uVar89;
78: short sVar100;
79: short sVar101;
80: short sVar103;
81: short sVar104;
82: short sVar107;
83: short sVar108;
84: char cVar110;
85: short sVar111;
86: short sVar112;
87: char cVar115;
88: short sVar116;
89: short sVar117;
90: char cVar121;
91: short sVar122;
92: short sVar123;
93: short sVar127;
94: short sVar128;
95: long lVar113;
96: short sVar118;
97: short sVar119;
98: short sVar124;
99: short sVar125;
100: short sVar129;
101: short sVar130;
102: undefined auVar94 [16];
103: char cVar105;
104: char cVar109;
105: char cVar114;
106: char cVar120;
107: char cVar126;
108: undefined auVar95 [16];
109: short sVar132;
110: short sVar133;
111: short sVar136;
112: short sVar138;
113: ulong uVar134;
114: short sVar137;
115: short sVar139;
116: short sVar140;
117: short sVar141;
118: short sVar142;
119: short sVar143;
120: short sVar144;
121: short sVar145;
122: short sVar146;
123: short sVar147;
124: short sVar148;
125: short sVar149;
126: undefined auVar135 [14];
127: undefined4 uVar150;
128: short sVar151;
129: short sVar152;
130: short sVar153;
131: char cVar154;
132: char cVar160;
133: uint6 uVar157;
134: char cVar161;
135: char cVar162;
136: long lVar163;
137: undefined auVar158 [16];
138: undefined auVar159 [16];
139: undefined auStack48 [4];
140: undefined4 uStack44;
141: short sStack40;
142: short sStack38;
143: short sStack36;
144: short sStack34;
145: undefined auStack32 [4];
146: undefined4 uStack28;
147: undefined8 uStack24;
148: uint6 uVar5;
149: undefined6 uVar6;
150: uint7 uVar7;
151: ulong uVar8;
152: unkbyte10 Var10;
153: undefined auVar11 [12];
154: undefined auVar12 [14];
155: uint uVar21;
156: uint5 uVar24;
157: unkbyte9 Var25;
158: undefined auVar26 [11];
159: undefined auVar27 [13];
160: uint3 uVar61;
161: uint5 uVar62;
162: undefined8 uVar64;
163: undefined auVar65 [12];
164: undefined8 uVar72;
165: undefined auVar73 [12];
166: uint3 uVar84;
167: uint5 uVar86;
168: uint7 uVar88;
169: unkbyte9 Var90;
170: unkbyte10 Var91;
171: undefined auVar92 [11];
172: undefined auVar93 [13];
173: undefined auVar96 [16];
174: undefined auVar97 [16];
175: undefined auVar98 [16];
176: undefined auVar99 [16];
177: undefined2 uVar131;
178: uint3 uVar155;
179: uint5 uVar156;
180: undefined4 uVar164;
181: 
182: psVar1 = *(short **)(param_2 + 0x58);
183: uVar2 = (ulong)param_5;
184: if ((*(uint *)(param_3 + 8) | *(uint *)(param_3 + 0x10)) == 0) {
185: auVar28 = *(undefined (*) [16])(param_3 + 0x10) | *(undefined (*) [16])(param_3 + 0x20) |
186: *(undefined (*) [16])(param_3 + 0x30) |
187: *(undefined (*) [16])(param_3 + 8) | *(undefined (*) [16])(param_3 + 0x18) |
188: *(undefined (*) [16])(param_3 + 0x28) | *(undefined (*) [16])(param_3 + 0x38);
189: auVar28 = packsswb(auVar28,auVar28);
190: auVar28 = packsswb(auVar28,auVar28);
191: if (SUB164(auVar28,0) == 0) {
192: iVar4 = CONCAT22(param_3[1] * psVar1[1],*param_3 * *psVar1);
193: sVar13 = param_3[2] * psVar1[2];
194: uVar5 = CONCAT24(sVar13,iVar4);
195: sVar14 = param_3[3] * psVar1[3];
196: uVar8 = CONCAT26(sVar14,uVar5);
197: sVar15 = param_3[4] * psVar1[4];
198: sVar18 = param_3[5] * psVar1[5];
199: uVar21 = SUB164(CONCAT214(sVar14,CONCAT212(sVar14,CONCAT210(sVar18,CONCAT28(sVar15,uVar8))))
200: >> 0x60,0);
201: auVar28 = CONCAT610(SUB166(CONCAT412(uVar21,CONCAT210(sVar13,CONCAT28(sVar15,uVar8))) >> 0x50,
202: 0),CONCAT28(sVar13,uVar8));
203: uVar17 = SUB168(auVar28 >> 0x40,0);
204: uVar70 = (uint)(ushort)(*param_3 * *psVar1) | iVar4 << 0x10;
205: uVar150 = CONCAT22(sVar15,sVar15);
206: uVar63 = CONCAT24(sVar18,uVar150);
207: uVar89 = CONCAT26(sVar18,uVar63);
208: auVar11 = CONCAT210(param_3[6] * psVar1[6],CONCAT28(param_3[6] * psVar1[6],uVar89));
209: auVar75 = CONCAT412(uVar70,CONCAT48(uVar70,CONCAT44(uVar70,uVar70)));
210: uVar42 = SUB164(CONCAT106(SUB1610(CONCAT88(uVar17,(uVar8 >> 0x10) << 0x30) >> 0x30,0),
211: (uVar5 >> 0x10) << 0x20) >> 0x20,0);
212: uVar85 = SUB164(auVar28 >> 0x40,0);
213: auVar74 = CONCAT412(uVar85,CONCAT48(uVar85,uVar17 & 0xffffffff | uVar17 << 0x20));
214: _auStack32 = CONCAT412(uVar21,CONCAT48(uVar21,uVar17 & 0xffffffff00000000 | (ulong)uVar21));
215: auVar28 = CONCAT412(uVar150,CONCAT48(uVar150,(ulong)uVar63 & 0xffffffff |
216: (ulong)uVar63 << 0x20));
217: uVar70 = (uint)(uVar89 >> 0x20);
218: auVar45 = CONCAT412(uVar70,CONCAT48(uVar70,uVar89 & 0xffffffff00000000 | (ulong)uVar70));
219: uVar85 = SUB124(auVar11 >> 0x40,0);
220: auVar44 = CONCAT412(uVar85,CONCAT48(uVar85,CONCAT44(uVar85,uVar85)));
221: uVar85 = SUB164(CONCAT214(param_3[7] * psVar1[7],CONCAT212(param_3[7] * psVar1[7],auVar11)) >>
222: 0x60,0);
223: auVar76 = CONCAT412(uVar85,CONCAT48(uVar85,CONCAT44(uVar85,uVar85)));
224: _auStack48 = CONCAT412(uVar42,CONCAT48(uVar42,CONCAT44(uVar42,uVar42)));
225: goto LAB_0015e88c;
226: }
227: }
228: sVar13 = *param_3 * *psVar1 - param_3[0x20] * psVar1[0x20];
229: sVar16 = param_3[1] * psVar1[1] - param_3[0x21] * psVar1[0x21];
230: sVar22 = param_3[2] * psVar1[2] - param_3[0x22] * psVar1[0x22];
231: sVar50 = param_3[3] * psVar1[3] - param_3[0x23] * psVar1[0x23];
232: sVar56 = param_3[4] * psVar1[4] - param_3[0x24] * psVar1[0x24];
233: sVar82 = param_3[5] * psVar1[5] - param_3[0x25] * psVar1[0x25];
234: sVar49 = param_3[6] * psVar1[6] - param_3[0x26] * psVar1[0x26];
235: sVar107 = param_3[7] * psVar1[7] - param_3[0x27] * psVar1[0x27];
236: sVar55 = *param_3 * *psVar1 + param_3[0x20] * psVar1[0x20];
237: sVar144 = param_3[1] * psVar1[1] + param_3[0x21] * psVar1[0x21];
238: sVar118 = param_3[2] * psVar1[2] + param_3[0x22] * psVar1[0x22];
239: sVar78 = param_3[3] * psVar1[3] + param_3[0x23] * psVar1[0x23];
240: sVar79 = param_3[4] * psVar1[4] + param_3[0x24] * psVar1[0x24];
241: sVar83 = param_3[5] * psVar1[5] + param_3[0x25] * psVar1[0x25];
242: sVar108 = param_3[6] * psVar1[6] + param_3[0x26] * psVar1[0x26];
243: sVar125 = param_3[7] * psVar1[7] + param_3[0x27] * psVar1[0x27];
244: sVar57 = param_3[0x10] * psVar1[0x10] + param_3[0x30] * psVar1[0x30];
245: sVar124 = param_3[0x11] * psVar1[0x11] + param_3[0x31] * psVar1[0x31];
246: sVar59 = param_3[0x12] * psVar1[0x12] + param_3[0x32] * psVar1[0x32];
247: sVar129 = param_3[0x13] * psVar1[0x13] + param_3[0x33] * psVar1[0x33];
248: sVar132 = param_3[0x14] * psVar1[0x14] + param_3[0x34] * psVar1[0x34];
249: sVar136 = param_3[0x15] * psVar1[0x15] + param_3[0x35] * psVar1[0x35];
250: sVar138 = param_3[0x16] * psVar1[0x16] + param_3[0x36] * psVar1[0x36];
251: sVar140 = param_3[0x17] * psVar1[0x17] + param_3[0x37] * psVar1[0x37];
252: auVar28 = psllw(CONCAT214(param_3[0x17] * psVar1[0x17] - param_3[0x37] * psVar1[0x37],
253: CONCAT212(param_3[0x16] * psVar1[0x16] - param_3[0x36] * psVar1[0x36],
254: CONCAT210(param_3[0x15] * psVar1[0x15] -
255: param_3[0x35] * psVar1[0x35],
256: CONCAT28(param_3[0x14] * psVar1[0x14] -
257: param_3[0x34] * psVar1[0x34],
258: CONCAT26(param_3[0x13] * psVar1[0x13] -
259: param_3[0x33] * psVar1[0x33],
260: CONCAT24(param_3[0x12] *
261: psVar1[0x12] -
262: param_3[0x32] *
263: psVar1[0x32],
264: CONCAT22(param_3[0x11] *
265: psVar1[0x11] -
266: param_3[0x31] *
267: psVar1[0x31],
268: param_3[0x10] *
269: psVar1[0x10] -
270: param_3[0x30] *
271: psVar1[0x30]))))
272: ))),2);
273: auVar28 = pmulhw(auVar28,_DAT_0019cb80);
274: sVar15 = SUB162(auVar28,0) - sVar57;
275: sVar20 = SUB162(auVar28 >> 0x10,0) - sVar124;
276: sVar46 = SUB162(auVar28 >> 0x20,0) - sVar59;
277: sVar54 = SUB162(auVar28 >> 0x30,0) - sVar129;
278: sVar41 = SUB162(auVar28 >> 0x40,0) - sVar132;
279: sVar100 = SUB162(auVar28 >> 0x50,0) - sVar136;
280: sVar51 = SUB162(auVar28 >> 0x60,0) - sVar138;
281: sVar111 = SUB162(auVar28 >> 0x70,0) - sVar140;
282: sVar18 = sVar55 - sVar57;
283: sVar147 = sVar144 - sVar124;
284: sVar48 = sVar118 - sVar59;
285: sVar146 = sVar78 - sVar129;
286: sVar80 = sVar79 - sVar132;
287: sVar101 = sVar83 - sVar136;
288: sVar112 = sVar108 - sVar138;
289: sVar130 = sVar125 - sVar140;
290: sVar14 = sVar13 - sVar15;
291: sVar19 = sVar16 - sVar20;
292: sVar40 = sVar22 - sVar46;
293: sVar52 = sVar50 - sVar54;
294: sVar58 = sVar56 - sVar41;
295: sVar47 = sVar82 - sVar100;
296: sVar103 = sVar49 - sVar51;
297: sVar53 = sVar107 - sVar111;
298: sVar55 = sVar55 + sVar57;
299: sVar144 = sVar144 + sVar124;
300: sVar118 = sVar118 + sVar59;
301: sVar78 = sVar78 + sVar129;
302: sVar79 = sVar79 + sVar132;
303: sVar83 = sVar83 + sVar136;
304: sVar108 = sVar108 + sVar138;
305: sVar125 = sVar125 + sVar140;
306: sVar13 = sVar13 + sVar15;
307: sVar16 = sVar16 + sVar20;
308: sVar22 = sVar22 + sVar46;
309: sVar50 = sVar50 + sVar54;
310: sVar56 = sVar56 + sVar41;
311: sVar82 = sVar82 + sVar100;
312: sVar49 = sVar49 + sVar51;
313: sVar107 = sVar107 + sVar111;
314: sVar137 = param_3[0x28] * psVar1[0x28] - param_3[0x18] * psVar1[0x18];
315: sVar139 = param_3[0x29] * psVar1[0x29] - param_3[0x19] * psVar1[0x19];
316: sVar141 = param_3[0x2a] * psVar1[0x2a] - param_3[0x1a] * psVar1[0x1a];
317: sVar143 = param_3[0x2b] * psVar1[0x2b] - param_3[0x1b] * psVar1[0x1b];
318: sVar148 = param_3[0x2c] * psVar1[0x2c] - param_3[0x1c] * psVar1[0x1c];
319: sVar116 = param_3[0x2d] * psVar1[0x2d] - param_3[0x1d] * psVar1[0x1d];
320: sVar122 = param_3[0x2e] * psVar1[0x2e] - param_3[0x1e] * psVar1[0x1e];
321: sVar127 = param_3[0x2f] * psVar1[0x2f] - param_3[0x1f] * psVar1[0x1f];
322: sVar142 = param_3[8] * psVar1[8] + param_3[0x38] * psVar1[0x38];
323: sVar151 = param_3[9] * psVar1[9] + param_3[0x39] * psVar1[0x39];
324: sVar77 = param_3[10] * psVar1[10] + param_3[0x3a] * psVar1[0x3a];
325: sVar149 = param_3[0xb] * psVar1[0xb] + param_3[0x3b] * psVar1[0x3b];
326: sVar153 = param_3[0xc] * psVar1[0xc] + param_3[0x3c] * psVar1[0x3c];
327: sVar104 = param_3[0xd] * psVar1[0xd] + param_3[0x3d] * psVar1[0x3d];
328: sVar119 = param_3[0xe] * psVar1[0xe] + param_3[0x3e] * psVar1[0x3e];
329: sVar133 = param_3[0xf] * psVar1[0xf] + param_3[0x3f] * psVar1[0x3f];
330: sVar15 = param_3[0x28] * psVar1[0x28] + param_3[0x18] * psVar1[0x18];
331: sVar20 = param_3[0x29] * psVar1[0x29] + param_3[0x19] * psVar1[0x19];
332: sVar46 = param_3[0x2a] * psVar1[0x2a] + param_3[0x1a] * psVar1[0x1a];
333: sVar54 = param_3[0x2b] * psVar1[0x2b] + param_3[0x1b] * psVar1[0x1b];
334: sVar41 = param_3[0x2c] * psVar1[0x2c] + param_3[0x1c] * psVar1[0x1c];
335: sVar100 = param_3[0x2d] * psVar1[0x2d] + param_3[0x1d] * psVar1[0x1d];
336: sVar51 = param_3[0x2e] * psVar1[0x2e] + param_3[0x1e] * psVar1[0x1e];
337: sVar111 = param_3[0x2f] * psVar1[0x2f] + param_3[0x1f] * psVar1[0x1f];
338: auVar44 = psllw(CONCAT214(param_3[0xf] * psVar1[0xf] - param_3[0x3f] * psVar1[0x3f],
339: CONCAT212(param_3[0xe] * psVar1[0xe] - param_3[0x3e] * psVar1[0x3e],
340: CONCAT210(param_3[0xd] * psVar1[0xd] -
341: param_3[0x3d] * psVar1[0x3d],
342: CONCAT28(param_3[0xc] * psVar1[0xc] -
343: param_3[0x3c] * psVar1[0x3c],
344: CONCAT26(param_3[0xb] * psVar1[0xb] -
345: param_3[0x3b] * psVar1[0x3b],
346: CONCAT24(param_3[10] * psVar1[10]
347: - param_3[0x3a] *
348: psVar1[0x3a],
349: CONCAT22(param_3[9] *
350: psVar1[9] -
351: param_3[0x39] *
352: psVar1[0x39],
353: param_3[8] *
354: psVar1[8] -
355: param_3[0x38] *
356: psVar1[0x38]))))
357: ))),2);
358: auVar74 = psllw(CONCAT214(sVar127,CONCAT212(sVar122,CONCAT210(sVar116,CONCAT28(sVar148,CONCAT26(
359: sVar143,CONCAT24(sVar141,CONCAT22(sVar139,sVar137)
360: )))))),2);
361: sVar57 = sVar142 + sVar15;
362: sVar59 = sVar151 + sVar20;
363: sVar124 = sVar77 + sVar46;
364: sVar129 = sVar149 + sVar54;
365: sVar132 = sVar153 + sVar41;
366: sVar136 = sVar104 + sVar100;
367: sVar138 = sVar119 + sVar51;
368: sVar140 = sVar133 + sVar111;
369: auVar28 = psllw(CONCAT214(sVar133 - sVar111,
370: CONCAT212(sVar119 - sVar51,
371: CONCAT210(sVar104 - sVar100,
372: CONCAT28(sVar153 - sVar41,
373: CONCAT26(sVar149 - sVar54,
374: CONCAT24(sVar77 - sVar46,
375: CONCAT22(sVar151 - sVar20
376: ,sVar142 - 
377: sVar15))))))),2);
378: auVar45 = pmulhw(auVar28,_DAT_0019cb80);
379: auVar75 = pmulhw(CONCAT214(SUB162(auVar74 >> 0x70,0) + SUB162(auVar44 >> 0x70,0),
380: CONCAT212(SUB162(auVar74 >> 0x60,0) + SUB162(auVar44 >> 0x60,0),
381: CONCAT210(SUB162(auVar74 >> 0x50,0) +
382: SUB162(auVar44 >> 0x50,0),
383: CONCAT28(SUB162(auVar74 >> 0x40,0) +
384: SUB162(auVar44 >> 0x40,0),
385: CONCAT26(SUB162(auVar74 >> 0x30,0) +
386: SUB162(auVar44 >> 0x30,0),
387: CONCAT24(SUB162(auVar74 >> 0x20,0
388: ) + SUB162(auVar44
389: >> 0x20
390: ,0),CONCAT22(SUB162(auVar74 >> 0x10,0) +
391: SUB162(auVar44 >> 0x10,0),
392: SUB162(auVar74,0) + SUB162(auVar44,0)
393: ))))))),_DAT_0019cb90);
394: auVar28 = pmulhw(auVar74,_DAT_0019cba0);
395: auVar44 = pmulhw(auVar44,_DAT_0019cbb0);
396: sVar119 = SUB162(auVar75 >> 0x10,0);
397: sVar133 = SUB162(auVar75 >> 0x20,0);
398: sVar145 = SUB162(auVar75 >> 0x30,0);
399: sVar152 = SUB162(auVar75 >> 0x40,0);
400: sVar117 = SUB162(auVar75 >> 0x50,0);
401: sVar123 = SUB162(auVar75 >> 0x60,0);
402: sVar128 = SUB162(auVar75 >> 0x70,0);
403: sVar15 = ((SUB162(auVar28,0) - sVar137) + SUB162(auVar75,0)) - sVar57;
404: sVar20 = ((SUB162(auVar28 >> 0x10,0) - sVar139) + sVar119) - sVar59;
405: sVar46 = ((SUB162(auVar28 >> 0x20,0) - sVar141) + sVar133) - sVar124;
406: sVar54 = ((SUB162(auVar28 >> 0x30,0) - sVar143) + sVar145) - sVar129;
407: sVar41 = ((SUB162(auVar28 >> 0x40,0) - sVar148) + sVar152) - sVar132;
408: sVar100 = ((SUB162(auVar28 >> 0x50,0) - sVar116) + sVar117) - sVar136;
409: sVar51 = ((SUB162(auVar28 >> 0x60,0) - sVar122) + sVar123) - sVar138;
410: sVar111 = ((SUB162(auVar28 >> 0x70,0) - sVar127) + sVar128) - sVar140;
411: sVar139 = sVar55 + sVar57;
412: sVar141 = sVar118 + sVar124;
413: uVar5 = CONCAT24(sVar141,CONCAT22(sVar144 + sVar59,sVar139));
414: sVar143 = sVar78 + sVar129;
415: uVar43 = CONCAT26(sVar143,uVar5);
416: sVar148 = sVar79 + sVar132;
417: Var91 = CONCAT28(sVar148,uVar43);
418: sVar116 = sVar83 + sVar136;
419: sVar122 = sVar13 + sVar15;
420: sVar127 = sVar22 + sVar46;
421: sVar55 = sVar55 - sVar57;
422: sVar118 = sVar118 - sVar124;
423: sVar13 = sVar13 - sVar15;
424: sVar22 = sVar22 - sVar46;
425: uVar87 = CONCAT24(sVar22,CONCAT22(sVar16 - sVar20,sVar13));
426: sVar57 = sVar50 - sVar54;
427: uVar9 = CONCAT26(sVar57,uVar87);
428: sVar124 = sVar56 - sVar41;
429: Var10 = CONCAT28(sVar124,uVar9);
430: sVar137 = sVar82 - sVar100;
431: sVar15 = SUB162(auVar45,0) - sVar15;
432: sVar142 = SUB162(auVar45 >> 0x10,0) - sVar20;
433: sVar46 = SUB162(auVar45 >> 0x20,0) - sVar46;
434: sVar151 = SUB162(auVar45 >> 0x30,0) - sVar54;
435: sVar77 = SUB162(auVar45 >> 0x40,0) - sVar41;
436: sVar149 = SUB162(auVar45 >> 0x50,0) - sVar100;
437: sVar153 = SUB162(auVar45 >> 0x60,0) - sVar51;
438: sVar104 = SUB162(auVar45 >> 0x70,0) - sVar111;
439: uVar150 = SUB164(CONCAT214(sVar50 + sVar54,CONCAT212(sVar143,CONCAT210(sVar116,Var91))) >> 0x60,0)
440: ;
441: uVar8 = SUB168(CONCAT610(SUB166(CONCAT412(uVar150,CONCAT210(sVar127,Var91)) >> 0x50,0),
442: CONCAT28(sVar141,uVar43)) >> 0x40,0);
443: auVar45 = CONCAT106(SUB1610(CONCAT88(uVar8,(((ulong)CONCAT24(sVar127,CONCAT22(sVar16 + sVar20,
444: sVar122)) &
445: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
446: (uVar5 >> 0x10) << 0x20);
447: uVar63 = CONCAT24(sVar116,CONCAT22(sVar56 + sVar41,sVar148));
448: uVar64 = CONCAT26(sVar82 + sVar100,uVar63);
449: auVar65 = CONCAT210(sVar49 + sVar51,CONCAT28(sVar108 + sVar138,uVar64));
450: uVar85 = SUB164(CONCAT214(sVar78 - sVar129,CONCAT212(sVar57,CONCAT210(sVar137,Var10))) >> 0x60,0);
451: lVar113 = SUB168(CONCAT610(SUB166(CONCAT412(uVar85,CONCAT210(sVar118,Var10)) >> 0x50,0),
452: CONCAT28(sVar22,uVar9)) >> 0x40,0);
453: _auStack32 = CONCAT24(sVar137,CONCAT22(sVar79 - sVar132,sVar124));
454: _auStack32 = CONCAT26(sVar83 - sVar136,_auStack32);
455: _auStack32 = CONCAT210(sVar108 - sVar138,CONCAT28(sVar49 - sVar51,_auStack32));
456: _auStack32 = CONCAT214(sVar125 - sVar140,CONCAT212(sVar107 - sVar111,_auStack32));
457: sVar56 = (SUB162(auVar44,0) - SUB162(auVar75,0)) + sVar15;
458: sVar41 = (SUB162(auVar44 >> 0x10,0) - sVar119) + sVar142;
459: sVar82 = (SUB162(auVar44 >> 0x20,0) - sVar133) + sVar46;
460: sVar100 = (SUB162(auVar44 >> 0x30,0) - sVar145) + sVar151;
461: sVar49 = (SUB162(auVar44 >> 0x40,0) - sVar152) + sVar77;
462: sVar51 = (SUB162(auVar44 >> 0x50,0) - sVar117) + sVar149;
463: sVar57 = (SUB162(auVar44 >> 0x60,0) - sVar123) + sVar153;
464: sVar124 = (SUB162(auVar44 >> 0x70,0) - sVar128) + sVar104;
465: sVar129 = sVar14 + sVar15;
466: sVar132 = sVar40 + sVar46;
467: uVar157 = CONCAT24(sVar132,CONCAT22(sVar19 + sVar142,sVar129));
468: sVar136 = sVar52 + sVar151;
469: uVar43 = CONCAT26(sVar136,uVar157);
470: sVar138 = sVar58 + sVar77;
471: Var91 = CONCAT28(sVar138,uVar43);
472: sVar78 = sVar47 + sVar149;
473: sVar16 = sVar18 + sVar56;
474: sVar20 = sVar48 + sVar82;
475: uVar5 = CONCAT24(sVar20,CONCAT22(sVar147 + sVar41,sVar16));
476: sVar22 = sVar146 + sVar100;
477: uVar9 = CONCAT26(sVar22,uVar5);
478: sVar50 = sVar80 + sVar49;
479: Var10 = CONCAT28(sVar50,uVar9);
480: sVar54 = sVar101 + sVar51;
481: sVar14 = sVar14 - sVar15;
482: sVar40 = sVar40 - sVar46;
483: sVar18 = sVar18 - sVar56;
484: sVar48 = sVar48 - sVar82;
485: uVar164 = SUB164(CONCAT214(sVar146 - sVar100,CONCAT212(sVar136,CONCAT210(sVar78,Var91))) >> 0x60,0
486: );
487: lVar163 = SUB168(CONCAT610(SUB166(CONCAT412(uVar164,CONCAT210(sVar48,Var91)) >> 0x50,0),
488: CONCAT28(sVar132,uVar43)) >> 0x40,0);
489: uVar71 = CONCAT24(sVar78,CONCAT22(sVar80 - sVar49,sVar138));
490: uVar72 = CONCAT26(sVar101 - sVar51,uVar71);
491: auVar73 = CONCAT210(sVar112 - sVar57,CONCAT28(sVar103 + sVar153,uVar72));
492: uVar42 = SUB164(CONCAT214(sVar52 - sVar151,CONCAT212(sVar22,CONCAT210(sVar54,Var10))) >> 0x60,0);
493: uVar17 = SUB168(CONCAT610(SUB166(CONCAT412(uVar42,CONCAT210(sVar40,Var10)) >> 0x50,0),
494: CONCAT28(sVar20,uVar9)) >> 0x40,0);
495: auVar28 = CONCAT106(SUB1610(CONCAT88(uVar17,(((ulong)CONCAT24(sVar40,CONCAT22(sVar19 - sVar142,
496: sVar14)) &
497: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
498: (uVar5 >> 0x10) << 0x20);
499: uVar5 = CONCAT24(sVar54,CONCAT22(sVar58 - sVar77,sVar50));
500: uVar43 = CONCAT26(sVar47 - sVar149,uVar5);
501: auVar11 = CONCAT210(sVar103 - sVar153,CONCAT28(sVar112 + sVar57,uVar43));
502: uVar134 = SUB168(CONCAT124(SUB1612(auVar45 >> 0x20,0),CONCAT22(sVar122,sVar139)),0);
503: uVar89 = uVar8 & 0xffffffff | lVar163 << 0x20;
504: uStack44 = SUB164(CONCAT106(SUB1610(CONCAT88(lVar113,(((ulong)CONCAT24(sVar118,CONCAT22(sVar144 - 
505: sVar59,sVar55)) & 0xffff0000) >> 0x10) << 0x30) >>
506: 0x30,0),(uVar87 >> 0x10) << 0x20) >> 0x20,0);
507: _auStack32 = CONCAT44(SUB124(auVar73 >> 0x40,0),SUB124(auVar65 >> 0x40,0));
508: _auStack32 = CONCAT48(SUB164(CONCAT214(sVar107 + sVar111,CONCAT212(sVar125 + sVar140,auVar65)) >>
509: 0x60,0),_auStack32);
510: _auStack32 = CONCAT412(SUB164(CONCAT214(sVar130 - sVar124,CONCAT212(sVar53 + sVar104,auVar73)) >>
511: 0x60,0),_auStack32);
512: uVar8 = SUB168(CONCAT124(SUB1612(auVar28 >> 0x20,0),CONCAT22(sVar14,sVar16)),0);
513: uVar17 = uVar17 & 0xffffffff | lVar113 << 0x20;
514: uVar9 = CONCAT44((undefined4)uStack24,SUB124(auVar11 >> 0x40,0));
515: auVar75 = CONCAT88(uVar8 & 0xffffffff | (ulong)CONCAT22(sVar55,sVar13) << 0x20,
516: uVar134 & 0xffffffff | (ulong)CONCAT22(sVar18,sVar129) << 0x20);
517: auVar74 = CONCAT88(uVar17,uVar89);
518: _auStack48 = CONCAT88(SUB168(CONCAT412(uStack44,CONCAT48(SUB164(auVar28 >> 0x20,0),uVar8)) >> 0x40
519: ,0),
520: SUB168(CONCAT412(SUB164(CONCAT106(SUB1610(CONCAT88(lVar163,(((ulong)CONCAT24
521: (sVar48,CONCAT22(sVar147 - sVar41,sVar18)) &
522: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
523: (uVar157 >> 0x10) << 0x20) >> 0x20,0),
524: CONCAT48(SUB164(auVar45 >> 0x20,0),uVar134)) >> 0x40,0));
525: _auStack32 = CONCAT88(SUB168(CONCAT412(uVar85,CONCAT48(uVar42,uVar17)) >> 0x40,0),
526: SUB168(CONCAT412(uVar164,CONCAT48(uVar150,uVar89)) >> 0x40,0));
527: auVar28 = CONCAT88((ulong)uVar5 & 0xffffffff | (ulong)_auStack32 << 0x20,
528: (ulong)uVar63 & 0xffffffff | (ulong)uVar71 << 0x20);
529: auVar45 = CONCAT88(SUB168(CONCAT412(uStack28,CONCAT48((int)((ulong)uVar43 >> 0x20),uVar43)) >>
530: 0x40,0),
531: SUB168(CONCAT412((int)((ulong)uVar72 >> 0x20),
532: CONCAT48((int)((ulong)uVar64 >> 0x20),uVar64)) >> 0x40,0));
533: auVar44 = CONCAT88(uVar9,_auStack32);
534: auVar76 = CONCAT88(SUB168(CONCAT412(uStack24._4_4_,
535: CONCAT48(SUB164(CONCAT214(sVar53 - sVar104,
536: CONCAT212(sVar130 + sVar124,auVar11)
537: ) >> 0x60,0),uVar9)) >> 0x40,0),
538: uStack24);
539: LAB_0015e88c:
540: sVar132 = SUB162(auVar75,0) - SUB162(auVar28,0);
541: sVar13 = SUB162(auVar28 >> 0x10,0);
542: sVar46 = SUB162(auVar75 >> 0x10,0);
543: sVar136 = sVar46 - sVar13;
544: sVar14 = SUB162(auVar28 >> 0x20,0);
545: sVar48 = SUB162(auVar75 >> 0x20,0);
546: sVar138 = sVar48 - sVar14;
547: sVar15 = SUB162(auVar28 >> 0x30,0);
548: sVar50 = SUB162(auVar75 >> 0x30,0);
549: sVar140 = sVar50 - sVar15;
550: sVar18 = SUB162(auVar28 >> 0x40,0);
551: sVar52 = SUB162(auVar75 >> 0x40,0);
552: sVar142 = sVar52 - sVar18;
553: sVar16 = SUB162(auVar28 >> 0x50,0);
554: sVar54 = SUB162(auVar75 >> 0x50,0);
555: sVar144 = sVar54 - sVar16;
556: sVar19 = SUB162(auVar28 >> 0x60,0);
557: sVar56 = SUB162(auVar75 >> 0x60,0);
558: sVar58 = SUB162(auVar75 >> 0x70,0);
559: sVar147 = sVar56 - sVar19;
560: sVar20 = SUB162(auVar28 >> 0x70,0);
561: sVar151 = sVar58 - sVar20;
562: sVar41 = SUB162(auVar44 >> 0x10,0);
563: sVar107 = SUB162(auVar74 >> 0x10,0);
564: sVar82 = SUB162(auVar44 >> 0x20,0);
565: sVar53 = SUB162(auVar74 >> 0x20,0);
566: sVar47 = SUB162(auVar44 >> 0x30,0);
567: sVar111 = SUB162(auVar74 >> 0x30,0);
568: sVar100 = SUB162(auVar44 >> 0x40,0);
569: sVar55 = SUB162(auVar74 >> 0x40,0);
570: sVar49 = SUB162(auVar44 >> 0x50,0);
571: sVar118 = SUB162(auVar74 >> 0x50,0);
572: sVar103 = SUB162(auVar44 >> 0x60,0);
573: sVar57 = SUB162(auVar74 >> 0x60,0);
574: sVar124 = SUB162(auVar74 >> 0x70,0);
575: sVar51 = SUB162(auVar44 >> 0x70,0);
576: sVar40 = SUB162(auVar75,0) + SUB162(auVar28,0);
577: sVar46 = sVar46 + sVar13;
578: sVar48 = sVar48 + sVar14;
579: sVar50 = sVar50 + sVar15;
580: sVar52 = sVar52 + sVar18;
581: sVar54 = sVar54 + sVar16;
582: sVar56 = sVar56 + sVar19;
583: sVar58 = sVar58 + sVar20;
584: sVar13 = SUB162(auVar74,0) + SUB162(auVar44,0);
585: sVar14 = sVar107 + sVar41;
586: sVar15 = sVar53 + sVar82;
587: sVar18 = sVar111 + sVar47;
588: sVar16 = sVar55 + sVar100;
589: sVar19 = sVar118 + sVar49;
590: sVar20 = sVar57 + sVar103;
591: sVar22 = sVar124 + sVar51;
592: auVar28 = psllw(CONCAT214(sVar124 - sVar51,
593: CONCAT212(sVar57 - sVar103,
594: CONCAT210(sVar118 - sVar49,
595: CONCAT28(sVar55 - sVar100,
596: CONCAT26(sVar111 - sVar47,
597: CONCAT24(sVar53 - sVar82,
598: CONCAT22(sVar107 - sVar41
599: ,SUB162(auVar74,
600: 0) - SUB162(auVar44,0)))))))),2);
601: auVar28 = pmulhw(auVar28,_DAT_0019cb80);
602: sVar82 = SUB162(auVar28,0) - sVar13;
603: sVar100 = SUB162(auVar28 >> 0x10,0) - sVar14;
604: sVar103 = SUB162(auVar28 >> 0x20,0) - sVar15;
605: sVar107 = SUB162(auVar28 >> 0x30,0) - sVar18;
606: sVar111 = SUB162(auVar28 >> 0x40,0) - sVar16;
607: sVar118 = SUB162(auVar28 >> 0x50,0) - sVar19;
608: sVar124 = SUB162(auVar28 >> 0x60,0) - sVar20;
609: sVar129 = SUB162(auVar28 >> 0x70,0) - sVar22;
610: sVar41 = sVar40 - sVar13;
611: sVar47 = sVar46 - sVar14;
612: sVar49 = sVar48 - sVar15;
613: sVar51 = sVar50 - sVar18;
614: sVar53 = sVar52 - sVar16;
615: sVar55 = sVar54 - sVar19;
616: sVar57 = sVar56 - sVar20;
617: sVar59 = sVar58 - sVar22;
618: sVar133 = sVar132 - sVar82;
619: sVar137 = sVar136 - sVar100;
620: sVar139 = sVar138 - sVar103;
621: sVar141 = sVar140 - sVar107;
622: sVar143 = sVar142 - sVar111;
623: sVar145 = sVar144 - sVar118;
624: sVar148 = sVar147 - sVar124;
625: sVar152 = sVar151 - sVar129;
626: sVar40 = sVar40 + sVar13;
627: sVar46 = sVar46 + sVar14;
628: sVar48 = sVar48 + sVar15;
629: sVar50 = sVar50 + sVar18;
630: sVar52 = sVar52 + sVar16;
631: sVar54 = sVar54 + sVar19;
632: sVar56 = sVar56 + sVar20;
633: sVar58 = sVar58 + sVar22;
634: sVar132 = sVar132 + sVar82;
635: sVar136 = sVar136 + sVar100;
636: sVar138 = sVar138 + sVar103;
637: sVar140 = sVar140 + sVar107;
638: sVar142 = sVar142 + sVar111;
639: sVar144 = sVar144 + sVar118;
640: sVar147 = sVar147 + sVar124;
641: sVar151 = sVar151 + sVar129;
642: sVar83 = SUB162(auVar76 >> 0x10,0);
643: sVar101 = SUB162(auVar76 >> 0x20,0);
644: sVar104 = SUB162(auVar76 >> 0x30,0);
645: sVar108 = SUB162(auVar76 >> 0x40,0);
646: sVar112 = SUB162(auVar76 >> 0x50,0);
647: sVar119 = SUB162(auVar76 >> 0x60,0);
648: sVar125 = SUB162(auVar76 >> 0x70,0);
649: sVar82 = SUB162(auVar45,0) - auStack32._0_2_;
650: sVar100 = SUB162(auVar45 >> 0x10,0);
651: sVar103 = sVar100 - auStack32._2_2_;
652: sVar107 = SUB162(auVar45 >> 0x20,0);
653: sVar111 = sVar107 - (short)uStack28;
654: sVar118 = SUB162(auVar45 >> 0x30,0);
655: sVar124 = sVar118 - uStack28._2_2_;
656: sVar129 = SUB162(auVar45 >> 0x40,0);
657: sVar77 = sVar129 - (short)uStack24;
658: sVar146 = SUB162(auVar45 >> 0x50,0);
659: sVar78 = sVar146 - uStack24._2_2_;
660: sVar149 = SUB162(auVar45 >> 0x60,0);
661: sVar153 = SUB162(auVar45 >> 0x70,0);
662: sVar79 = sVar149 - uStack24._4_2_;
663: sVar80 = sVar153 - uStack24._6_2_;
664: sVar13 = auStack48._0_2_ + SUB162(auVar76,0);
665: sVar14 = auStack48._2_2_ + sVar83;
666: sVar15 = (short)uStack44 + sVar101;
667: sVar18 = uStack44._2_2_ + sVar104;
668: sVar16 = sStack40 + sVar108;
669: sVar19 = sStack38 + sVar112;
670: sVar20 = sStack36 + sVar119;
671: sVar22 = sStack34 + sVar125;
672: auStack32._0_2_ = SUB162(auVar45,0) + auStack32._0_2_;
673: sVar100 = sVar100 + auStack32._2_2_;
674: sVar107 = sVar107 + (short)uStack28;
675: sVar118 = sVar118 + uStack28._2_2_;
676: sVar129 = sVar129 + (short)uStack24;
677: sVar146 = sVar146 + uStack24._2_2_;
678: sVar149 = sVar149 + uStack24._4_2_;
679: sVar153 = sVar153 + uStack24._6_2_;
680: auVar28 = psllw(CONCAT214(sStack34 - sVar125,
681: CONCAT212(sStack36 - sVar119,
682: CONCAT210(sStack38 - sVar112,
683: CONCAT28(sStack40 - sVar108,
684: CONCAT26(uStack44._2_2_ - sVar104,
685: CONCAT24((short)uStack44 - sVar101
686: ,CONCAT22(auStack48._2_2_
687: - sVar83,
688: auStack48._0_2_ - SUB162(auVar76,0)))))))),2);
689: auVar74 = psllw(CONCAT214(sVar80,CONCAT212(sVar79,CONCAT210(sVar78,CONCAT28(sVar77,CONCAT26(
690: sVar124,CONCAT24(sVar111,CONCAT22(sVar103,sVar82))
691: ))))),2);
692: sVar83 = sVar13 + auStack32._0_2_;
693: sVar101 = sVar14 + sVar100;
694: sVar104 = sVar15 + sVar107;
695: sVar108 = sVar18 + sVar118;
696: sVar112 = sVar16 + sVar129;
697: sVar119 = sVar19 + sVar146;
698: sVar125 = sVar20 + sVar149;
699: sVar130 = sVar22 + sVar153;
700: auVar44 = psllw(CONCAT214(sVar22 - sVar153,
701: CONCAT212(sVar20 - sVar149,
702: CONCAT210(sVar19 - sVar146,
703: CONCAT28(sVar16 - sVar129,
704: CONCAT26(sVar18 - sVar118,
705: CONCAT24(sVar15 - sVar107,
706: CONCAT22(sVar14 - sVar100
707: ,sVar13 - 
708: auStack32._0_2_))))))),2);
709: auVar45 = pmulhw(auVar44,_DAT_0019cb80);
710: auVar75 = pmulhw(CONCAT214(SUB162(auVar74 >> 0x70,0) + SUB162(auVar28 >> 0x70,0),
711: CONCAT212(SUB162(auVar74 >> 0x60,0) + SUB162(auVar28 >> 0x60,0),
712: CONCAT210(SUB162(auVar74 >> 0x50,0) +
713: SUB162(auVar28 >> 0x50,0),
714: CONCAT28(SUB162(auVar74 >> 0x40,0) +
715: SUB162(auVar28 >> 0x40,0),
716: CONCAT26(SUB162(auVar74 >> 0x30,0) +
717: SUB162(auVar28 >> 0x30,0),
718: CONCAT24(SUB162(auVar74 >> 0x20,0
719: ) + SUB162(auVar28
720: >> 0x20
721: ,0),CONCAT22(SUB162(auVar74 >> 0x10,0) +
722: SUB162(auVar28 >> 0x10,0),
723: SUB162(auVar74,0) + SUB162(auVar28,0)
724: ))))))),_DAT_0019cb90);
725: auVar44 = pmulhw(auVar74,_DAT_0019cba0);
726: auVar28 = pmulhw(auVar28,_DAT_0019cbb0);
727: sVar14 = SUB162(auVar75 >> 0x10,0);
728: sVar15 = SUB162(auVar75 >> 0x20,0);
729: sVar18 = SUB162(auVar75 >> 0x30,0);
730: sVar16 = SUB162(auVar75 >> 0x40,0);
731: sVar19 = SUB162(auVar75 >> 0x50,0);
732: sVar20 = SUB162(auVar75 >> 0x60,0);
733: sVar22 = SUB162(auVar75 >> 0x70,0);
734: sVar82 = ((SUB162(auVar44,0) - sVar82) + SUB162(auVar75,0)) - sVar83;
735: sVar100 = ((SUB162(auVar44 >> 0x10,0) - sVar103) + sVar14) - sVar101;
736: sVar103 = ((SUB162(auVar44 >> 0x20,0) - sVar111) + sVar15) - sVar104;
737: sVar107 = ((SUB162(auVar44 >> 0x30,0) - sVar124) + sVar18) - sVar108;
738: sVar111 = ((SUB162(auVar44 >> 0x40,0) - sVar77) + sVar16) - sVar112;
739: sVar118 = ((SUB162(auVar44 >> 0x50,0) - sVar78) + sVar19) - sVar119;
740: sVar124 = ((SUB162(auVar44 >> 0x60,0) - sVar79) + sVar20) - sVar125;
741: sVar129 = ((SUB162(auVar44 >> 0x70,0) - sVar80) + sVar22) - sVar130;
742: auVar44 = psraw(CONCAT214(sVar58 + sVar130,
743: CONCAT212(sVar56 + sVar125,
744: CONCAT210(sVar54 + sVar119,
745: CONCAT28(sVar52 + sVar112,
746: CONCAT26(sVar50 + sVar108,
747: CONCAT24(sVar48 + sVar104,
748: CONCAT22(sVar46 + sVar101
749: ,sVar40 + sVar83
750: ))))))),5);
751: auVar74 = psraw(CONCAT214(sVar151 + sVar129,
752: CONCAT212(sVar147 + sVar124,
753: CONCAT210(sVar144 + sVar118,
754: CONCAT28(sVar142 + sVar111,
755: CONCAT26(sVar140 + sVar107,
756: CONCAT24(sVar138 + sVar103,
757: CONCAT22(sVar136 + 
758: sVar100,sVar132 + sVar82))))))),5);
759: auVar158 = psraw(CONCAT214(sVar58 - sVar130,
760: CONCAT212(sVar56 - sVar125,
761: CONCAT210(sVar54 - sVar119,
762: CONCAT28(sVar52 - sVar112,
763: CONCAT26(sVar50 - sVar108,
764: CONCAT24(sVar48 - sVar104,
765: CONCAT22(sVar46 - 
766: sVar101,sVar40 - sVar83))))))),5);
767: auVar76 = psraw(CONCAT214(sVar151 - sVar129,
768: CONCAT212(sVar147 - sVar124,
769: CONCAT210(sVar144 - sVar118,
770: CONCAT28(sVar142 - sVar111,
771: CONCAT26(sVar140 - sVar107,
772: CONCAT24(sVar138 - sVar103,
773: CONCAT22(sVar136 - 
774: sVar100,sVar132 - sVar82))))))),5);
775: sVar82 = SUB162(auVar45,0) - sVar82;
776: sVar100 = SUB162(auVar45 >> 0x10,0) - sVar100;
777: sVar103 = SUB162(auVar45 >> 0x20,0) - sVar103;
778: sVar107 = SUB162(auVar45 >> 0x30,0) - sVar107;
779: sVar111 = SUB162(auVar45 >> 0x40,0) - sVar111;
780: sVar118 = SUB162(auVar45 >> 0x50,0) - sVar118;
781: sVar124 = SUB162(auVar45 >> 0x60,0) - sVar124;
782: sVar129 = SUB162(auVar45 >> 0x70,0) - sVar129;
783: auVar44 = packsswb(auVar44,auVar76);
784: auVar66 = packsswb(auVar74,auVar158);
785: sVar13 = (SUB162(auVar28,0) - SUB162(auVar75,0)) + sVar82;
786: sVar14 = (SUB162(auVar28 >> 0x10,0) - sVar14) + sVar100;
787: sVar15 = (SUB162(auVar28 >> 0x20,0) - sVar15) + sVar103;
788: sVar18 = (SUB162(auVar28 >> 0x30,0) - sVar18) + sVar107;
789: sVar16 = (SUB162(auVar28 >> 0x40,0) - sVar16) + sVar111;
790: sVar19 = (SUB162(auVar28 >> 0x50,0) - sVar19) + sVar118;
791: sVar20 = (SUB162(auVar28 >> 0x60,0) - sVar20) + sVar124;
792: sVar22 = (SUB162(auVar28 >> 0x70,0) - sVar22) + sVar129;
793: auVar45 = psraw(CONCAT214(sVar152 + sVar129,
794: CONCAT212(sVar148 + sVar124,
795: CONCAT210(sVar145 + sVar118,
796: CONCAT28(sVar143 + sVar111,
797: CONCAT26(sVar141 + sVar107,
798: CONCAT24(sVar139 + sVar103,
799: CONCAT22(sVar137 + 
800: sVar100,sVar133 + sVar82))))))),5);
801: auVar74 = psraw(CONCAT214(sVar59 + sVar22,
802: CONCAT212(sVar57 + sVar20,
803: CONCAT210(sVar55 + sVar19,
804: CONCAT28(sVar53 + sVar16,
805: CONCAT26(sVar51 + sVar18,
806: CONCAT24(sVar49 + sVar15,
807: CONCAT22(sVar47 + sVar14,
808: sVar41 + sVar13)
809: )))))),5);
810: auVar28 = psraw(CONCAT214(sVar152 - sVar129,
811: CONCAT212(sVar148 - sVar124,
812: CONCAT210(sVar145 - sVar118,
813: CONCAT28(sVar143 - sVar111,
814: CONCAT26(sVar141 - sVar107,
815: CONCAT24(sVar139 - sVar103,
816: CONCAT22(sVar137 - 
817: sVar100,sVar133 - sVar82))))))),5);
818: auVar75 = psraw(CONCAT214(sVar59 - sVar22,
819: CONCAT212(sVar57 - sVar20,
820: CONCAT210(sVar55 - sVar19,
821: CONCAT28(sVar53 - sVar16,
822: CONCAT26(sVar51 - sVar18,
823: CONCAT24(sVar49 - sVar15,
824: CONCAT22(sVar47 - sVar14,
825: sVar41 - sVar13)
826: )))))),5);
827: auVar94 = packsswb(auVar45,auVar74);
828: auVar159 = packsswb(auVar75,auVar28);
829: cVar23 = SUB161(auVar44,0) + -0x80;
830: uVar3 = CONCAT12(SUB161(auVar44 >> 0x10,0) + -0x80,CONCAT11(SUB161(auVar44 >> 8,0) + -0x80,cVar23)
831: );
832: cVar29 = SUB161(auVar44 >> 0x20,0) + -0x80;
833: uVar24 = CONCAT14(cVar29,CONCAT13(SUB161(auVar44 >> 0x18,0) + -0x80,uVar3));
834: cVar30 = SUB161(auVar44 >> 0x28,0) + -0x80;
835: cVar31 = SUB161(auVar44 >> 0x30,0) + -0x80;
836: uVar7 = CONCAT16(cVar31,CONCAT15(cVar30,uVar24));
837: cVar32 = SUB161(auVar44 >> 0x38,0) + -0x80;
838: uVar9 = CONCAT17(cVar32,uVar7);
839: cVar33 = SUB161(auVar44 >> 0x40,0) + -0x80;
840: Var25 = CONCAT18(cVar33,uVar9);
841: cVar34 = SUB161(auVar44 >> 0x48,0) + -0x80;
842: Var10 = CONCAT19(cVar34,Var25);
843: cVar35 = SUB161(auVar44 >> 0x50,0) + -0x80;
844: auVar26 = CONCAT110(cVar35,Var10);
845: cVar36 = SUB161(auVar44 >> 0x58,0) + -0x80;
846: auVar11 = CONCAT111(cVar36,auVar26);
847: cVar37 = SUB161(auVar44 >> 0x60,0) + -0x80;
848: auVar27 = CONCAT112(cVar37,auVar11);
849: cVar38 = SUB161(auVar44 >> 0x68,0) + -0x80;
850: cVar60 = SUB161(auVar66,0) + -0x80;
851: uVar61 = CONCAT12(SUB161(auVar66 >> 0x10,0) + -0x80,
852: CONCAT11(SUB161(auVar66 >> 8,0) + -0x80,cVar60));
853: cVar67 = SUB161(auVar66 >> 0x20,0) + -0x80;
854: uVar62 = CONCAT14(cVar67,CONCAT13(SUB161(auVar66 >> 0x18,0) + -0x80,uVar61));
855: cVar68 = SUB161(auVar66 >> 0x28,0) + -0x80;
856: cVar69 = SUB161(auVar66 >> 0x30,0) + -0x80;
857: cVar81 = SUB161(auVar94,0) + -0x80;
858: uVar84 = CONCAT12(SUB161(auVar94 >> 0x10,0) + -0x80,
859: CONCAT11(SUB161(auVar94 >> 8,0) + -0x80,cVar81));
860: cVar102 = SUB161(auVar94 >> 0x20,0) + -0x80;
861: uVar86 = CONCAT14(cVar102,CONCAT13(SUB161(auVar94 >> 0x18,0) + -0x80,uVar84));
862: cVar105 = SUB161(auVar94 >> 0x28,0) + -0x80;
863: cVar106 = SUB161(auVar94 >> 0x30,0) + -0x80;
864: uVar88 = CONCAT16(cVar106,CONCAT15(cVar105,uVar86));
865: cVar109 = SUB161(auVar94 >> 0x38,0) + -0x80;
866: uVar43 = CONCAT17(cVar109,uVar88);
867: cVar110 = SUB161(auVar94 >> 0x40,0) + -0x80;
868: Var90 = CONCAT18(cVar110,uVar43);
869: cVar114 = SUB161(auVar94 >> 0x48,0) + -0x80;
870: Var91 = CONCAT19(cVar114,Var90);
871: cVar115 = SUB161(auVar94 >> 0x50,0) + -0x80;
872: auVar92 = CONCAT110(cVar115,Var91);
873: cVar120 = SUB161(auVar94 >> 0x58,0) + -0x80;
874: auVar65 = CONCAT111(cVar120,auVar92);
875: cVar121 = SUB161(auVar94 >> 0x60,0) + -0x80;
876: auVar93 = CONCAT112(cVar121,auVar65);
877: cVar126 = SUB161(auVar94 >> 0x68,0) + -0x80;
878: cVar154 = SUB161(auVar159,0) + -0x80;
879: uVar155 = CONCAT12(SUB161(auVar159 >> 0x10,0) + -0x80,
880: CONCAT11(SUB161(auVar159 >> 8,0) + -0x80,cVar154));
881: cVar160 = SUB161(auVar159 >> 0x20,0) + -0x80;
882: uVar156 = CONCAT14(cVar160,CONCAT13(SUB161(auVar159 >> 0x18,0) + -0x80,uVar155));
883: cVar161 = SUB161(auVar159 >> 0x28,0) + -0x80;
884: cVar162 = SUB161(auVar159 >> 0x30,0) + -0x80;
885: uVar39 = SUB162(CONCAT115(SUB161(auVar66 >> 0x38,0) + -0x80,
886: CONCAT114(cVar32,CONCAT113(cVar38,auVar27))) >> 0x70,0);
887: auVar28 = CONCAT313(SUB163(CONCAT214(uVar39,CONCAT113(cVar69,auVar27)) >> 0x68,0),
888: CONCAT112(cVar31,auVar11));
889: auVar45 = CONCAT511(SUB165(CONCAT412(SUB164(auVar28 >> 0x60,0),CONCAT111(cVar68,auVar26)) >> 0x58,
890: 0),CONCAT110(cVar30,Var10));
891: auVar74 = CONCAT79(SUB167(CONCAT610(SUB166(auVar45 >> 0x50,0),CONCAT19(cVar67,Var25)) >> 0x48,0),
892: CONCAT18(cVar29,uVar9));
893: auVar75 = CONCAT97(SUB169(CONCAT88(SUB168(auVar74 >> 0x40,0),
894: (((ulong)CONCAT16(cVar69,CONCAT15(cVar68,uVar62)) & 0xff000000)
895: >> 0x18) << 0x38) >> 0x38,0),(uVar7 >> 0x18) << 0x30);
896: auVar158 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar75 >> 0x30,0),
897: (((uint6)uVar62 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0),
898: (uVar24 >> 0x10) << 0x20);
899: auVar76 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(auVar158 >> 0x20,0),
900: ((uVar61 & 0xff00) >> 8) << 0x18) >> 0x18,
901: 0),(uVar3 >> 8) << 0x10) >> 0x10,0),
902: CONCAT11(cVar60,cVar23));
903: uVar3 = CONCAT12(cVar34,CONCAT11(SUB161(auVar66 >> 0x40,0) + -0x80,cVar33));
904: uVar6 = CONCAT15(SUB161(auVar66 >> 0x50,0) + -0x80,
905: CONCAT14(cVar35,CONCAT13(SUB161(auVar66 >> 0x48,0) + -0x80,uVar3)));
906: uVar7 = CONCAT16(cVar36,uVar6);
907: uVar9 = CONCAT17(SUB161(auVar66 >> 0x58,0) + -0x80,uVar7);
908: Var10 = CONCAT19(SUB161(auVar66 >> 0x60,0) + -0x80,CONCAT18(cVar37,uVar9));
909: auVar11 = CONCAT111(SUB161(auVar66 >> 0x68,0) + -0x80,CONCAT110(cVar38,Var10));
910: auVar12 = CONCAT113(SUB161(auVar66 >> 0x70,0) + -0x80,
911: CONCAT112(SUB161(auVar44 >> 0x70,0) + -0x80,auVar11));
912: uVar131 = SUB162(CONCAT115(SUB161(auVar159 >> 0x38,0) + -0x80,
913: CONCAT114(cVar109,CONCAT113(cVar126,auVar93))) >> 0x70,0);
914: auVar99 = CONCAT313(SUB163(CONCAT214(uVar131,CONCAT113(cVar162,auVar93)) >> 0x68,0),
915: CONCAT112(cVar106,auVar65));
916: auVar98 = CONCAT511(SUB165(CONCAT412(SUB164(auVar99 >> 0x60,0),CONCAT111(cVar161,auVar92)) >> 0x58
917: ,0),CONCAT110(cVar105,Var91));
918: auVar97 = CONCAT79(SUB167(CONCAT610(SUB166(auVar98 >> 0x50,0),CONCAT19(cVar160,Var90)) >> 0x48,0),
919: CONCAT18(cVar102,uVar43));
920: auVar96 = CONCAT97(SUB169(CONCAT88(SUB168(auVar97 >> 0x40,0),
921: (((ulong)CONCAT16(cVar162,CONCAT15(cVar161,uVar156)) &
922: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
923: (uVar88 >> 0x18) << 0x30);
924: auVar95 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar96 >> 0x30,0),
925: (((uint6)uVar156 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0),
926: (uVar86 >> 0x10) << 0x20);
927: uVar61 = CONCAT12(cVar114,CONCAT11(SUB161(auVar159 >> 0x40,0) + -0x80,cVar110));
928: uVar71 = CONCAT15(SUB161(auVar159 >> 0x50,0) + -0x80,
929: CONCAT14(cVar115,CONCAT13(SUB161(auVar159 >> 0x48,0) + -0x80,uVar61)));
930: uVar64 = CONCAT17(SUB161(auVar159 >> 0x58,0) + -0x80,CONCAT16(cVar120,uVar71));
931: Var91 = CONCAT19(SUB161(auVar159 >> 0x60,0) + -0x80,CONCAT18(cVar121,uVar64));
932: auVar73 = CONCAT111(SUB161(auVar159 >> 0x68,0) + -0x80,CONCAT110(cVar126,Var91));
933: auVar135 = CONCAT113(SUB161(auVar159 >> 0x70,0) + -0x80,
934: CONCAT112(SUB161(auVar94 >> 0x70,0) + -0x80,auVar73));
935: uVar17 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(SUB162(auVar96 >> 0x30,0),
936: CONCAT212(SUB162(auVar75 >> 0x30,0),
937: SUB1612(auVar76,0))) >> 0x60
938: ,0),
939: CONCAT210(SUB162(auVar95 >> 0x20,0),SUB1610(auVar76,0))
940: ) >> 0x50,0),
941: CONCAT28(SUB162(auVar158 >> 0x20,0),SUB168(auVar76,0))) >> 0x40,0);
942: auVar75 = CONCAT106(CONCAT82(uVar17,SUB162(CONCAT133(SUB1613(CONCAT124(SUB1612(auVar95 >> 0x20,0),
943: ((uVar155 & 0xff00) >> 8)
944: << 0x18) >> 0x18,0),
945: (uVar84 >> 8) << 0x10) >> 0x10,0)),
946: (SUB166(auVar76,0) >> 0x10) << 0x20);
947: uVar63 = CONCAT24(SUB162(auVar45 >> 0x50,0),
948: CONCAT22(SUB162(auVar97 >> 0x40,0),SUB162(auVar74 >> 0x40,0)));
949: uVar43 = CONCAT26(SUB162(auVar98 >> 0x50,0),uVar63);
950: auVar65 = CONCAT210(SUB162(auVar99 >> 0x60,0),CONCAT28(SUB162(auVar28 >> 0x60,0),uVar43));
951: uVar89 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)((ulong)uVar9 >> 0x30),
952: CONCAT212((short)((ulong)uVar64 >>
953: 0x30),auVar73)) >>
954: 0x60,0),
955: CONCAT210((short)((uint6)uVar6 >> 0x20),Var91)) >> 0x50
956: ,0),CONCAT28((short)(uVar71 >> 0x20),uVar64)) >> 0x40,0);
957: uVar5 = CONCAT24(SUB122(auVar73 >> 0x50,0),
958: CONCAT22((short)((unkuint10)Var10 >> 0x40),(short)((unkuint10)Var91 >> 0x40)));
959: uVar9 = CONCAT26(SUB122(auVar11 >> 0x50,0),uVar5);
960: auVar11 = CONCAT210(SUB142(auVar12 >> 0x60,0),CONCAT28(SUB142(auVar135 >> 0x60,0),uVar9));
961: uVar8 = SUB168(CONCAT124(SUB1612(auVar75 >> 0x20,0),
962: SUB164(auVar76,0) & 0xffff | (uint)CONCAT11(cVar154,cVar81) << 0x10),0);
963: lVar113 = param_4[2];
964: *(ulong *)(*param_4 + uVar2) =
965: uVar8 & 0xffffffff | (ulong)(uVar61 & 0xffff | (uint)uVar3 << 0x10) << 0x20;
966: *(ulong *)(lVar113 + uVar2) = uVar17 & 0xffffffff | uVar89 << 0x20;
967: lVar113 = param_4[6];
968: *(ulong *)(param_4[4] + uVar2) = (ulong)uVar63 & 0xffffffff | (ulong)uVar5 << 0x20;
969: *(ulong *)(lVar113 + uVar2) = CONCAT44(SUB124(auVar11 >> 0x40,0),SUB124(auVar65 >> 0x40,0));
970: lVar113 = param_4[3];
971: *(long *)(param_4[1] + uVar2) =
972: SUB168(CONCAT412(SUB164(CONCAT106(SUB1610(CONCAT88(uVar89,(((ulong)uVar7 & 0xffff0000) >>
973: 0x10) << 0x30) >> 0x30,0),
974: (uVar71 >> 0x10) << 0x20) >> 0x20,0),
975: CONCAT48(SUB164(auVar75 >> 0x20,0),uVar8)) >> 0x40,0);
976: *(ulong *)(lVar113 + uVar2) = uVar89 & 0xffffffff00000000 | uVar17 >> 0x20;
977: lVar113 = param_4[7];
978: *(long *)(param_4[5] + uVar2) =
979: SUB168(CONCAT412((int)((ulong)uVar9 >> 0x20),CONCAT48((int)((ulong)uVar43 >> 0x20),uVar43))
980: >> 0x40,0);
981: *(ulong *)(lVar113 + uVar2) =
982: CONCAT44(SUB164(CONCAT214(SUB162(CONCAT115(SUB161(auVar66 >> 0x78,0) + -0x80,
983: CONCAT114(SUB161(auVar44 >> 0x78,0) + -0x80,
984: auVar12)) >> 0x70,0),
985: CONCAT212(SUB162(CONCAT115(SUB161(auVar159 >> 0x78,0) + -0x80,
986: CONCAT114(SUB161(auVar94 >> 0x78,0) +
987: -0x80,auVar135)) >> 0x70,0),
988: auVar11)) >> 0x60,0),
989: SUB164(CONCAT214(uVar131,CONCAT212(uVar39,auVar65)) >> 0x60,0));
990: return;
991: }
992: 

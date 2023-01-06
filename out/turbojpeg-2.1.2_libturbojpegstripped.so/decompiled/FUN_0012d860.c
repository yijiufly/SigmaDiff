1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0012d860(long param_1,long *param_2,uint param_3,ushort **param_4,int param_5)
5: 
6: {
7: uint *puVar1;
8: byte bVar2;
9: byte bVar3;
10: ushort *puVar4;
11: ushort *puVar5;
12: ushort **ppuVar6;
13: char cVar7;
14: char cVar17;
15: char cVar27;
16: char cVar38;
17: byte bVar45;
18: byte bVar46;
19: short sVar53;
20: short sVar54;
21: short sVar55;
22: short sVar56;
23: short sVar57;
24: undefined auVar58 [16];
25: undefined auVar59 [14];
26: ulong uVar60;
27: long lVar61;
28: uint uVar62;
29: uint uVar63;
30: ushort *puVar64;
31: ushort *puVar65;
32: ushort *puVar66;
33: ushort *puVar67;
34: ushort uVar68;
35: undefined2 uVar69;
36: ushort uVar80;
37: uint uVar71;
38: uint uVar72;
39: ushort uVar81;
40: ushort uVar82;
41: ushort uVar83;
42: ushort uVar84;
43: ushort uVar85;
44: ushort uVar86;
45: undefined2 uVar87;
46: uint uVar90;
47: uint uVar91;
48: undefined auVar100 [16];
49: undefined auVar101 [16];
50: ushort uVar102;
51: undefined2 uVar103;
52: ushort uVar118;
53: uint uVar106;
54: uint uVar107;
55: ushort uVar119;
56: ushort uVar120;
57: ushort uVar121;
58: ushort uVar122;
59: ushort uVar123;
60: ushort uVar124;
61: uint uVar125;
62: undefined auVar127 [12];
63: undefined auVar128 [16];
64: ushort uVar130;
65: uint uVar131;
66: uint5 uVar132;
67: undefined auVar136 [16];
68: uint uVar137;
69: uint uVar138;
70: undefined auVar143 [16];
71: undefined auVar144 [13];
72: unkuint10 Var145;
73: unkuint10 Var146;
74: unkuint10 Var147;
75: unkuint10 Var148;
76: unkuint10 Var149;
77: unkuint10 Var150;
78: undefined auVar151 [16];
79: undefined auVar152 [14];
80: undefined auVar153 [16];
81: undefined auVar154 [16];
82: uint uVar156;
83: undefined auVar158 [16];
84: undefined auVar160 [13];
85: undefined auVar161 [14];
86: undefined auVar162 [16];
87: undefined auVar163 [16];
88: uint uStack68;
89: char cVar8;
90: char cVar9;
91: char cVar10;
92: char cVar11;
93: char cVar12;
94: char cVar13;
95: char cVar14;
96: char cVar15;
97: char cVar16;
98: char cVar18;
99: char cVar19;
100: char cVar20;
101: byte bVar21;
102: char cVar22;
103: char cVar23;
104: char cVar24;
105: char cVar25;
106: byte bVar26;
107: char cVar28;
108: char cVar29;
109: char cVar30;
110: byte bVar31;
111: char cVar32;
112: char cVar33;
113: char cVar34;
114: char cVar35;
115: char cVar36;
116: byte bVar37;
117: char cVar39;
118: char cVar40;
119: char cVar41;
120: byte bVar42;
121: char cVar43;
122: byte bVar44;
123: char cVar47;
124: char cVar48;
125: char cVar49;
126: char cVar50;
127: char cVar51;
128: byte bVar52;
129: undefined4 uVar70;
130: uint5 uVar73;
131: undefined6 uVar74;
132: uint7 uVar75;
133: undefined8 uVar76;
134: unkbyte10 Var77;
135: undefined auVar78 [12];
136: undefined auVar79 [14];
137: uint3 uVar88;
138: undefined4 uVar89;
139: uint5 uVar92;
140: undefined6 uVar93;
141: uint7 uVar94;
142: undefined8 uVar95;
143: ulong uVar96;
144: unkbyte10 Var97;
145: undefined auVar98 [12];
146: undefined auVar99 [14];
147: uint3 uVar104;
148: undefined4 uVar105;
149: uint5 uVar108;
150: uint5 uVar109;
151: undefined6 uVar110;
152: uint7 uVar111;
153: undefined8 uVar112;
154: ulong uVar113;
155: unkbyte10 Var114;
156: undefined auVar115 [12];
157: undefined auVar116 [12];
158: undefined auVar117 [14];
159: ulong uVar126;
160: undefined auVar129 [16];
161: ulong uVar133;
162: undefined auVar134 [12];
163: undefined auVar135 [14];
164: uint5 uVar139;
165: ulong uVar140;
166: undefined auVar141 [12];
167: undefined auVar142 [14];
168: undefined auVar155 [13];
169: undefined auVar157 [14];
170: undefined auVar159 [13];
171: undefined auVar164 [13];
172: 
173: uStack68 = *(uint *)(param_1 + 0x88);
174: while (param_5 = param_5 + -1, -1 < param_5) {
175: /* WARNING: Read-only address (ram,0x0016c610) is written */
176: /* WARNING: Read-only address (ram,0x0018d090) is written */
177: /* WARNING: Read-only address (ram,0x0018d0a0) is written */
178: uVar60 = (ulong)param_3;
179: ppuVar6 = param_4 + 1;
180: puVar66 = *(ushort **)(*param_2 + uVar60 * 8);
181: param_3 = param_3 + 1;
182: puVar65 = *(ushort **)(param_2[1] + uVar60 * 8);
183: puVar4 = *(ushort **)(param_2[2] + uVar60 * 8);
184: puVar5 = *param_4;
185: puVar64 = puVar5;
186: puVar67 = puVar4;
187: if (((ulong)puVar5 & 3) != 0) {
188: bVar2 = *(byte *)puVar66;
189: bVar3 = *(byte *)puVar65;
190: puVar64 = puVar5 + 1;
191: uStack68 = uStack68 - 1;
192: puVar67 = (ushort *)((long)puVar4 + 1);
193: puVar65 = (ushort *)((long)puVar65 + 1);
194: puVar66 = (ushort *)((long)puVar66 + 1);
195: *puVar5 = (ushort)((bVar2 & 0xf8) << 8) | (ushort)((bVar3 & 0xfc) << 3) |
196: (ushort)(*(byte *)puVar4 >> 3);
197: }
198: uVar63 = uStack68 >> 1;
199: if (uVar63 != 0) {
200: uVar60 = (ulong)uVar63;
201: puVar4 = puVar64 + uVar60 * 2;
202: if (((puVar65 < puVar4 && puVar64 < puVar65 + uVar60 ||
203: puVar64 < puVar66 + uVar60 && puVar66 < puVar4) || uVar63 < 0x10) ||
204: (puVar64 < puVar67 + uVar60 && puVar67 < puVar4)) {
205: uVar60 = (ulong)(uVar63 - 1);
206: lVar61 = 0;
207: do {
208: *(uint *)(puVar64 + lVar61) =
209: ((*(byte *)((long)puVar65 + lVar61 + 1) & 0xfc) << 3 |
210: (*(byte *)((long)puVar66 + lVar61 + 1) & 0xf8) << 8 |
211: (uint)(*(byte *)((long)puVar67 + lVar61 + 1) >> 3)) << 0x10 |
212: (*(byte *)((long)puVar65 + lVar61) & 0xfc) << 3 |
213: (*(byte *)((long)puVar66 + lVar61) & 0xf8) << 8 |
214: (uint)(*(byte *)((long)puVar67 + lVar61) >> 3);
215: lVar61 = lVar61 + 2;
216: } while (lVar61 != uVar60 * 2 + 2);
217: }
218: else {
219: lVar61 = 0;
220: uVar62 = 0;
221: do {
222: auVar101 = *(undefined (*) [16])((long)puVar66 + lVar61);
223: uVar62 = uVar62 + 1;
224: auVar129 = *(undefined (*) [16])((long)puVar66 + lVar61 + 0x10);
225: auVar100 = _DAT_0016c610 & auVar101;
226: uVar68 = SUB162(auVar101,0) >> 8;
227: uVar80 = SUB162(auVar101 >> 0x10,0) >> 8;
228: uVar81 = SUB162(auVar101 >> 0x20,0) >> 8;
229: uVar82 = SUB162(auVar101 >> 0x30,0) >> 8;
230: uVar83 = SUB162(auVar101 >> 0x40,0) >> 8;
231: uVar84 = SUB162(auVar101 >> 0x50,0) >> 8;
232: uVar85 = SUB162(auVar101 >> 0x60,0) >> 8;
233: uVar86 = SUB162(auVar101 >> 0x78,0);
234: auVar128 = _DAT_0016c610 & auVar129;
235: uVar102 = SUB162(auVar129,0) >> 8;
236: uVar118 = SUB162(auVar129 >> 0x10,0) >> 8;
237: uVar119 = SUB162(auVar129 >> 0x20,0) >> 8;
238: uVar120 = SUB162(auVar129 >> 0x30,0) >> 8;
239: uVar121 = SUB162(auVar129 >> 0x40,0) >> 8;
240: uVar122 = SUB162(auVar129 >> 0x50,0) >> 8;
241: uVar123 = SUB162(auVar129 >> 0x60,0) >> 8;
242: uVar124 = SUB162(auVar129 >> 0x78,0);
243: cVar7 = (uVar80 != 0) * (uVar80 < 0xff) * SUB161(auVar101 >> 0x18,0) - (0xff < uVar80);
244: uVar69 = CONCAT11(cVar7,(uVar68 != 0) * (uVar68 < 0xff) * SUB161(auVar101 >> 8,0) -
245: (0xff < uVar68));
246: uVar70 = CONCAT13((uVar82 != 0) * (uVar82 < 0xff) * SUB161(auVar101 >> 0x38,0) -
247: (0xff < uVar82),
248: CONCAT12((uVar81 != 0) * (uVar81 < 0xff) * SUB161(auVar101 >> 0x28,0) -
249: (0xff < uVar81),uVar69));
250: cVar8 = (uVar83 != 0) * (uVar83 < 0xff) * SUB161(auVar101 >> 0x48,0) - (0xff < uVar83);
251: uVar73 = CONCAT14(cVar8,uVar70);
252: cVar9 = (uVar84 != 0) * (uVar84 < 0xff) * SUB161(auVar101 >> 0x58,0) - (0xff < uVar84);
253: uVar74 = CONCAT15(cVar9,uVar73);
254: cVar10 = (uVar85 != 0) * (uVar85 < 0xff) * SUB161(auVar101 >> 0x68,0) - (0xff < uVar85);
255: uVar75 = CONCAT16(cVar10,uVar74);
256: cVar11 = (uVar86 != 0) * (uVar86 < 0xff) * SUB161(auVar101 >> 0x78,0) - (0xff < uVar86);
257: uVar76 = CONCAT17(cVar11,uVar75);
258: bVar2 = (uVar102 != 0) * (uVar102 < 0xff) * SUB161(auVar129 >> 8,0) - (0xff < uVar102);
259: cVar12 = (uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar129 >> 0x18,0) - (0xff < uVar118)
260: ;
261: Var77 = CONCAT19(cVar12,CONCAT18(bVar2,uVar76));
262: cVar13 = (uVar119 != 0) * (uVar119 < 0xff) * SUB161(auVar129 >> 0x28,0) - (0xff < uVar119)
263: ;
264: cVar14 = (uVar120 != 0) * (uVar120 < 0xff) * SUB161(auVar129 >> 0x38,0) - (0xff < uVar120)
265: ;
266: auVar78 = CONCAT111(cVar14,CONCAT110(cVar13,Var77));
267: cVar15 = (uVar121 != 0) * (uVar121 < 0xff) * SUB161(auVar129 >> 0x48,0) - (0xff < uVar121)
268: ;
269: cVar16 = (uVar122 != 0) * (uVar122 < 0xff) * SUB161(auVar129 >> 0x58,0) - (0xff < uVar122)
270: ;
271: bVar3 = (uVar124 != 0) * (uVar124 < 0xff) * SUB161(auVar129 >> 0x78,0) - (0xff < uVar124);
272: sVar53 = SUB162(auVar100,0);
273: sVar54 = SUB162(auVar100 >> 0x10,0);
274: uVar87 = CONCAT11((0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar100 >> 0x10,0) -
275: (0xff < sVar54),
276: (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100,0) - (0xff < sVar53));
277: sVar53 = SUB162(auVar100 >> 0x20,0);
278: uVar88 = CONCAT12((0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x20,0) -
279: (0xff < sVar53),uVar87);
280: sVar53 = SUB162(auVar100 >> 0x30,0);
281: uVar89 = CONCAT13((0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x30,0) -
282: (0xff < sVar53),uVar88);
283: sVar53 = SUB162(auVar100 >> 0x40,0);
284: cVar17 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x40,0) - (0xff < sVar53);
285: uVar92 = CONCAT14(cVar17,uVar89);
286: sVar53 = SUB162(auVar100 >> 0x50,0);
287: cVar18 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x50,0) - (0xff < sVar53);
288: uVar93 = CONCAT15(cVar18,uVar92);
289: sVar53 = SUB162(auVar100 >> 0x60,0);
290: cVar19 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x60,0) - (0xff < sVar53);
291: uVar94 = CONCAT16(cVar19,uVar93);
292: sVar53 = SUB162(auVar100 >> 0x70,0);
293: cVar20 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x70,0) - (0xff < sVar53);
294: uVar95 = CONCAT17(cVar20,uVar94);
295: sVar53 = SUB162(auVar128,0);
296: bVar21 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar128,0) - (0xff < sVar53);
297: sVar53 = SUB162(auVar128 >> 0x10,0);
298: cVar22 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar128 >> 0x10,0) - (0xff < sVar53);
299: Var97 = CONCAT19(cVar22,CONCAT18(bVar21,uVar95));
300: sVar53 = SUB162(auVar128 >> 0x20,0);
301: cVar23 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar128 >> 0x20,0) - (0xff < sVar53);
302: sVar53 = SUB162(auVar128 >> 0x30,0);
303: cVar24 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar128 >> 0x30,0) - (0xff < sVar53);
304: auVar98 = CONCAT111(cVar24,CONCAT110(cVar23,Var97));
305: sVar53 = SUB162(auVar128 >> 0x40,0);
306: cVar25 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar128 >> 0x40,0) - (0xff < sVar53);
307: sVar55 = SUB162(auVar128 >> 0x50,0);
308: sVar56 = SUB162(auVar128 >> 0x60,0);
309: sVar53 = SUB162(auVar128 >> 0x70,0);
310: bVar26 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar128 >> 0x70,0) - (0xff < sVar53);
311: auVar101 = *(undefined (*) [16])((long)puVar65 + lVar61);
312: auVar100 = *(undefined (*) [16])((long)puVar65 + lVar61 + 0x10);
313: auVar143 = _DAT_0016c610 & auVar101;
314: uVar68 = SUB162(auVar101,0) >> 8;
315: uVar80 = SUB162(auVar101 >> 0x10,0) >> 8;
316: uVar81 = SUB162(auVar101 >> 0x20,0) >> 8;
317: uVar82 = SUB162(auVar101 >> 0x30,0) >> 8;
318: uVar83 = SUB162(auVar101 >> 0x40,0) >> 8;
319: uVar84 = SUB162(auVar101 >> 0x50,0) >> 8;
320: uVar85 = SUB162(auVar101 >> 0x60,0) >> 8;
321: uVar86 = SUB162(auVar101 >> 0x78,0);
322: auVar136 = _DAT_0016c610 & auVar100;
323: uVar102 = SUB162(auVar100,0) >> 8;
324: uVar118 = SUB162(auVar100 >> 0x10,0) >> 8;
325: uVar119 = SUB162(auVar100 >> 0x20,0) >> 8;
326: uVar120 = SUB162(auVar100 >> 0x30,0) >> 8;
327: uVar121 = SUB162(auVar100 >> 0x40,0) >> 8;
328: uVar122 = SUB162(auVar100 >> 0x50,0) >> 8;
329: uVar124 = SUB162(auVar100 >> 0x60,0) >> 8;
330: uVar130 = SUB162(auVar100 >> 0x78,0);
331: auVar151 = *(undefined (*) [16])((long)puVar67 + lVar61 + 0x10);
332: uVar103 = CONCAT11((uVar80 != 0) * (uVar80 < 0xff) * SUB161(auVar101 >> 0x18,0) -
333: (0xff < uVar80),
334: (uVar68 != 0) * (uVar68 < 0xff) * SUB161(auVar101 >> 8,0) -
335: (0xff < uVar68));
336: uVar104 = CONCAT12((uVar81 != 0) * (uVar81 < 0xff) * SUB161(auVar101 >> 0x28,0) -
337: (0xff < uVar81),uVar103);
338: uVar105 = CONCAT13((uVar82 != 0) * (uVar82 < 0xff) * SUB161(auVar101 >> 0x38,0) -
339: (0xff < uVar82),uVar104);
340: cVar27 = (uVar83 != 0) * (uVar83 < 0xff) * SUB161(auVar101 >> 0x48,0) - (0xff < uVar83);
341: uVar108 = CONCAT14(cVar27,uVar105);
342: cVar28 = (uVar84 != 0) * (uVar84 < 0xff) * SUB161(auVar101 >> 0x58,0) - (0xff < uVar84);
343: uVar110 = CONCAT15(cVar28,uVar108);
344: cVar29 = (uVar85 != 0) * (uVar85 < 0xff) * SUB161(auVar101 >> 0x68,0) - (0xff < uVar85);
345: uVar111 = CONCAT16(cVar29,uVar110);
346: cVar30 = (uVar86 != 0) * (uVar86 < 0xff) * SUB161(auVar101 >> 0x78,0) - (0xff < uVar86);
347: uVar112 = CONCAT17(cVar30,uVar111);
348: bVar31 = (uVar102 != 0) * (uVar102 < 0xff) * SUB161(auVar100 >> 8,0) - (0xff < uVar102);
349: cVar32 = (uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar100 >> 0x18,0) - (0xff < uVar118)
350: ;
351: Var114 = CONCAT19(cVar32,CONCAT18(bVar31,uVar112));
352: cVar33 = (uVar119 != 0) * (uVar119 < 0xff) * SUB161(auVar100 >> 0x28,0) - (0xff < uVar119)
353: ;
354: cVar34 = (uVar120 != 0) * (uVar120 < 0xff) * SUB161(auVar100 >> 0x38,0) - (0xff < uVar120)
355: ;
356: auVar115 = CONCAT111(cVar34,CONCAT110(cVar33,Var114));
357: cVar35 = (uVar121 != 0) * (uVar121 < 0xff) * SUB161(auVar100 >> 0x48,0) - (0xff < uVar121)
358: ;
359: cVar36 = (uVar122 != 0) * (uVar122 < 0xff) * SUB161(auVar100 >> 0x58,0) - (0xff < uVar122)
360: ;
361: bVar37 = (uVar130 != 0) * (uVar130 < 0xff) * SUB161(auVar100 >> 0x78,0) - (0xff < uVar130)
362: ;
363: auVar163 = CONCAT106(SUB1610(CONCAT97((unkuint9)
364: SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
365: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
366: (SUB152(CONCAT114(cVar20,ZEXT1314(CONCAT112(cVar25
367: ,auVar98))) >> 0x68,0),CONCAT112(cVar19,auVar98))
368: >> 0x60,0),auVar98) >> 0x58,0),
369: CONCAT110(cVar18,Var97)) >> 0x50,0),Var97) >> 0x48
370: ,0),CONCAT18(cVar17,uVar95)) >> 0x40,0),uVar95) >>
371: 0x38,0) &
372: SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0
373: ) & SUB169((undefined  [16])0xffffffffffffffff
374: >> 0x38,0) &
375: SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0
376: ),(uVar94 >> 0x18) << 0x30) >> 0x30,0),uVar93)
377: & (undefined  [16])0xffff00ffffffffff;
378: auVar154 = CONCAT124(SUB1612(CONCAT115(SUB1611(auVar163 >> 0x28,0),
379: (uVar92 >> 0x10) << 0x20) >> 0x20,0),uVar89) &
380: (undefined  [16])0xffffffff00ffffff;
381: auVar58 = CONCAT142(SUB1614(CONCAT133(SUB1613(auVar154 >> 0x18,0),(uVar88 >> 8) << 0x10)
382: >> 0x10,0),uVar87) & (undefined  [16])0xffffffffffff00ff;
383: sVar53 = SUB162(auVar143,0);
384: sVar54 = SUB162(auVar143 >> 0x10,0);
385: uVar87 = CONCAT11((0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar143 >> 0x10,0) -
386: (0xff < sVar54),
387: (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143,0) - (0xff < sVar53));
388: sVar53 = SUB162(auVar143 >> 0x20,0);
389: uVar88 = CONCAT12((0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x20,0) -
390: (0xff < sVar53),uVar87);
391: sVar53 = SUB162(auVar143 >> 0x30,0);
392: uVar89 = CONCAT13((0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x30,0) -
393: (0xff < sVar53),uVar88);
394: sVar53 = SUB162(auVar143 >> 0x40,0);
395: cVar38 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x40,0) - (0xff < sVar53);
396: uVar92 = CONCAT14(cVar38,uVar89);
397: sVar53 = SUB162(auVar143 >> 0x50,0);
398: cVar39 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x50,0) - (0xff < sVar53);
399: uVar93 = CONCAT15(cVar39,uVar92);
400: sVar53 = SUB162(auVar143 >> 0x60,0);
401: cVar40 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x60,0) - (0xff < sVar53);
402: uVar94 = CONCAT16(cVar40,uVar93);
403: sVar53 = SUB162(auVar143 >> 0x70,0);
404: cVar41 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x70,0) - (0xff < sVar53);
405: uVar95 = CONCAT17(cVar41,uVar94);
406: sVar53 = SUB162(auVar136,0);
407: bVar42 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136,0) - (0xff < sVar53);
408: sVar53 = SUB162(auVar136 >> 0x10,0);
409: cVar43 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136 >> 0x10,0) - (0xff < sVar53);
410: Var97 = CONCAT19(cVar43,CONCAT18(bVar42,uVar95));
411: sVar53 = SUB162(auVar136 >> 0x20,0);
412: cVar17 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136 >> 0x20,0) - (0xff < sVar53);
413: sVar53 = SUB162(auVar136 >> 0x30,0);
414: cVar18 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136 >> 0x30,0) - (0xff < sVar53);
415: auVar98 = CONCAT111(cVar18,CONCAT110(cVar17,Var97));
416: sVar53 = SUB162(auVar136 >> 0x40,0);
417: cVar19 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136 >> 0x40,0) - (0xff < sVar53);
418: sVar53 = SUB162(auVar136 >> 0x50,0);
419: cVar20 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136 >> 0x50,0) - (0xff < sVar53);
420: sVar57 = SUB162(auVar136 >> 0x60,0);
421: sVar53 = SUB162(auVar136 >> 0x70,0);
422: bVar44 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar136 >> 0x70,0) - (0xff < sVar53);
423: auVar101 = *(undefined (*) [16])((long)puVar67 + lVar61);
424: uVar106 = (uint)CONCAT12(cVar32,(ushort)bVar31);
425: uVar109 = CONCAT14(cVar33,uVar106);
426: uVar113 = (ulong)CONCAT16(cVar34,(uint6)uVar109);
427: auVar116 = ZEXT1112(CONCAT110(cVar36,(unkuint10)CONCAT18(cVar35,uVar113)));
428: auVar117 = ZEXT1314(CONCAT112((uVar124 != 0) * (uVar124 < 0xff) *
429: SUB161(auVar100 >> 0x68,0) - (0xff < uVar124),auVar116));
430: auVar159 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
431: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
432: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
433: (CONCAT213(SUB152(CONCAT114(cVar30,CONCAT113(
434: cVar36,CONCAT112(cVar35,auVar115))) >> 0x68,0),
435: CONCAT112(cVar29,auVar115)) >> 0x60,0),auVar115)
436: >> 0x58,0),CONCAT110(cVar28,Var114)) >> 0x50,0),
437: Var114) >> 0x48,0),CONCAT18(cVar27,uVar112)) >>
438: 0x40,0),uVar112) >> 0x38,0) &
439: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
440: ,0) &
441: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
442: ,0) &
443: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
444: ,0) &
445: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
446: ,0),(uVar111 >> 0x18) << 0x30) >> 0x30,0),
447: uVar110) >> 0x28,0) &
448: SUB1611((undefined  [16])0xffff00ffffffffff >>
449: 0x28,0),(uVar108 >> 0x10) << 0x20) >> 0x20
450: ,0),uVar105) >> 0x18,0) &
451: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
452: auVar158 = CONCAT142(SUB1614(CONCAT133(auVar159,(uVar104 >> 8) << 0x10) >> 0x10,0),uVar103
453: ) & (undefined  [16])0xffffffffffff00ff;
454: auVar100 = _DAT_0016c610 & auVar101;
455: uVar68 = SUB162(auVar101,0) >> 8;
456: uVar80 = SUB162(auVar101 >> 0x10,0) >> 8;
457: uVar81 = SUB162(auVar101 >> 0x20,0) >> 8;
458: uVar82 = SUB162(auVar101 >> 0x30,0) >> 8;
459: uVar83 = SUB162(auVar101 >> 0x40,0) >> 8;
460: uVar84 = SUB162(auVar101 >> 0x50,0) >> 8;
461: uVar85 = SUB162(auVar101 >> 0x60,0) >> 8;
462: uVar86 = SUB162(auVar101 >> 0x78,0);
463: auVar143 = _DAT_0016c610 & auVar151;
464: uVar102 = SUB162(auVar151,0) >> 8;
465: uVar118 = SUB162(auVar151 >> 0x10,0) >> 8;
466: uVar119 = SUB162(auVar151 >> 0x20,0) >> 8;
467: uVar120 = SUB162(auVar151 >> 0x30,0) >> 8;
468: uVar121 = SUB162(auVar151 >> 0x40,0) >> 8;
469: uVar122 = SUB162(auVar151 >> 0x50,0) >> 8;
470: uVar124 = SUB162(auVar151 >> 0x60,0) >> 8;
471: uVar130 = SUB162(auVar151 >> 0x78,0);
472: uVar103 = CONCAT11((uVar80 != 0) * (uVar80 < 0xff) * SUB161(auVar101 >> 0x18,0) -
473: (0xff < uVar80),
474: (uVar68 != 0) * (uVar68 < 0xff) * SUB161(auVar101 >> 8,0) -
475: (0xff < uVar68));
476: uVar104 = CONCAT12((uVar81 != 0) * (uVar81 < 0xff) * SUB161(auVar101 >> 0x28,0) -
477: (0xff < uVar81),uVar103);
478: uVar105 = CONCAT13((uVar82 != 0) * (uVar82 < 0xff) * SUB161(auVar101 >> 0x38,0) -
479: (0xff < uVar82),uVar104);
480: cVar27 = (uVar83 != 0) * (uVar83 < 0xff) * SUB161(auVar101 >> 0x48,0) - (0xff < uVar83);
481: uVar132 = CONCAT14(cVar27,uVar105);
482: cVar28 = (uVar84 != 0) * (uVar84 < 0xff) * SUB161(auVar101 >> 0x58,0) - (0xff < uVar84);
483: uVar110 = CONCAT15(cVar28,uVar132);
484: cVar29 = (uVar85 != 0) * (uVar85 < 0xff) * SUB161(auVar101 >> 0x68,0) - (0xff < uVar85);
485: uVar111 = CONCAT16(cVar29,uVar110);
486: cVar30 = (uVar86 != 0) * (uVar86 < 0xff) * SUB161(auVar101 >> 0x78,0) - (0xff < uVar86);
487: uVar112 = CONCAT17(cVar30,uVar111);
488: bVar31 = (uVar102 != 0) * (uVar102 < 0xff) * SUB161(auVar151 >> 8,0) - (0xff < uVar102);
489: cVar32 = (uVar118 != 0) * (uVar118 < 0xff) * SUB161(auVar151 >> 0x18,0) - (0xff < uVar118)
490: ;
491: Var114 = CONCAT19(cVar32,CONCAT18(bVar31,uVar112));
492: cVar33 = (uVar119 != 0) * (uVar119 < 0xff) * SUB161(auVar151 >> 0x28,0) - (0xff < uVar119)
493: ;
494: cVar34 = (uVar120 != 0) * (uVar120 < 0xff) * SUB161(auVar151 >> 0x38,0) - (0xff < uVar120)
495: ;
496: auVar127 = CONCAT111(cVar34,CONCAT110(cVar33,Var114));
497: cVar35 = (uVar121 != 0) * (uVar121 < 0xff) * SUB161(auVar151 >> 0x48,0) - (0xff < uVar121)
498: ;
499: cVar36 = (uVar122 != 0) * (uVar122 < 0xff) * SUB161(auVar151 >> 0x58,0) - (0xff < uVar122)
500: ;
501: bVar45 = (uVar130 != 0) * (uVar130 < 0xff) * SUB161(auVar151 >> 0x78,0) - (0xff < uVar130)
502: ;
503: auVar155 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
504: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
505: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
506: (CONCAT213(SUB152(CONCAT114(cVar41,CONCAT113(
507: cVar20,CONCAT112(cVar19,auVar98))) >> 0x68,0),
508: CONCAT112(cVar40,auVar98)) >> 0x60,0),auVar98) >>
509: 0x58,0),CONCAT110(cVar39,Var97)) >> 0x50,0),Var97)
510: >> 0x48,0),CONCAT18(cVar38,uVar95)) >> 0x40,0),
511: uVar95) >> 0x38,0) &
512: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
513: ,0) &
514: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
515: ,0) &
516: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
517: ,0) &
518: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
519: ,0),(uVar94 >> 0x18) << 0x30) >> 0x30,0),
520: uVar93) >> 0x28,0) &
521: SUB1611((undefined  [16])0xffff00ffffffffff >>
522: 0x28,0),(uVar92 >> 0x10) << 0x20) >> 0x20,
523: 0),uVar89) >> 0x18,0) &
524: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
525: auVar153 = CONCAT142(SUB1614(CONCAT133(auVar155,(uVar88 >> 8) << 0x10) >> 0x10,0),uVar87)
526: & (undefined  [16])0xffffffffffff00ff;
527: sVar53 = SUB162(auVar100,0);
528: sVar54 = SUB162(auVar100 >> 0x10,0);
529: uVar87 = CONCAT11((0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar100 >> 0x10,0) -
530: (0xff < sVar54),
531: (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100,0) - (0xff < sVar53));
532: sVar53 = SUB162(auVar100 >> 0x20,0);
533: uVar88 = CONCAT12((0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x20,0) -
534: (0xff < sVar53),uVar87);
535: sVar53 = SUB162(auVar100 >> 0x30,0);
536: uVar89 = CONCAT13((0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x30,0) -
537: (0xff < sVar53),uVar88);
538: sVar53 = SUB162(auVar100 >> 0x40,0);
539: cVar41 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x40,0) - (0xff < sVar53);
540: uVar92 = CONCAT14(cVar41,uVar89);
541: sVar53 = SUB162(auVar100 >> 0x50,0);
542: cVar40 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x50,0) - (0xff < sVar53);
543: uVar93 = CONCAT15(cVar40,uVar92);
544: sVar53 = SUB162(auVar100 >> 0x60,0);
545: cVar39 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x60,0) - (0xff < sVar53);
546: uVar94 = CONCAT16(cVar39,uVar93);
547: sVar53 = SUB162(auVar100 >> 0x70,0);
548: cVar38 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x70,0) - (0xff < sVar53);
549: uVar95 = CONCAT17(cVar38,uVar94);
550: sVar53 = SUB162(auVar143,0);
551: bVar46 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143,0) - (0xff < sVar53);
552: sVar53 = SUB162(auVar143 >> 0x10,0);
553: cVar47 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x10,0) - (0xff < sVar53);
554: Var97 = CONCAT19(cVar47,CONCAT18(bVar46,uVar95));
555: sVar53 = SUB162(auVar143 >> 0x20,0);
556: cVar48 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x20,0) - (0xff < sVar53);
557: sVar53 = SUB162(auVar143 >> 0x30,0);
558: cVar49 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x30,0) - (0xff < sVar53);
559: auVar98 = CONCAT111(cVar49,CONCAT110(cVar48,Var97));
560: sVar53 = SUB162(auVar143 >> 0x40,0);
561: cVar50 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x40,0) - (0xff < sVar53);
562: sVar53 = SUB162(auVar143 >> 0x50,0);
563: cVar51 = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar143 >> 0x50,0) - (0xff < sVar53);
564: sVar53 = SUB162(auVar143 >> 0x60,0);
565: sVar54 = SUB162(auVar143 >> 0x70,0);
566: bVar52 = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar143 >> 0x70,0) - (0xff < sVar54);
567: auVar144 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
568: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
569: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
570: (CONCAT213(SUB152(CONCAT114(cVar11,CONCAT113(
571: cVar16,CONCAT112(cVar15,auVar78))) >> 0x68,0),
572: CONCAT112(cVar10,auVar78)) >> 0x60,0),auVar78) >>
573: 0x58,0),CONCAT110(cVar9,Var77)) >> 0x50,0),Var77)
574: >> 0x48,0),CONCAT18(cVar8,uVar76)) >> 0x40,0),
575: uVar76) >> 0x38,0) &
576: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
577: ,0) &
578: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
579: ,0) &
580: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
581: ,0) &
582: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
583: ,0),(uVar75 >> 0x18) << 0x30) >> 0x30,0),
584: uVar74) >> 0x28,0) &
585: SUB1611((undefined  [16])0xffff00ffffffffff >>
586: 0x28,0),(uVar73 >> 0x10) << 0x20) >> 0x20,
587: 0),uVar70) >> 0x18,0) &
588: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
589: auVar101 = CONCAT142(CONCAT131(auVar144,cVar7),uVar69) &
590: (undefined  [16])0xffffffffffff00ff;
591: uVar71 = (uint)CONCAT12(cVar12,(ushort)bVar2);
592: uVar73 = CONCAT14(cVar13,uVar71);
593: uVar60 = (ulong)CONCAT16(cVar14,(uint6)uVar73);
594: auVar78 = ZEXT1112(CONCAT110(cVar16,(unkuint10)CONCAT18(cVar15,uVar60)));
595: auVar79 = ZEXT1314(CONCAT112((uVar123 != 0) * (uVar123 < 0xff) *
596: SUB161(auVar129 >> 0x68,0) - (0xff < uVar123),auVar78));
597: uVar125 = (uint)CONCAT12(cVar47,(ushort)bVar46);
598: uVar108 = CONCAT14(cVar48,uVar125);
599: uVar126 = (ulong)CONCAT16(cVar49,(uint6)uVar108);
600: auVar115 = ZEXT1112(CONCAT110(cVar51,(unkuint10)CONCAT18(cVar50,uVar126)));
601: auVar129 = ZEXT1516(CONCAT114(bVar52,ZEXT1314(CONCAT112((0 < sVar53) * (sVar53 < 0xff) *
602: SUB161(auVar143 >> 0x60,0) -
603: (0xff < sVar53),auVar115))));
604: auVar164 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
605: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
606: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
607: (CONCAT213(SUB152(CONCAT114(cVar30,CONCAT113(
608: cVar36,CONCAT112(cVar35,auVar127))) >> 0x68,0),
609: CONCAT112(cVar29,auVar127)) >> 0x60,0),auVar127)
610: >> 0x58,0),CONCAT110(cVar28,Var114)) >> 0x50,0),
611: Var114) >> 0x48,0),CONCAT18(cVar27,uVar112)) >>
612: 0x40,0),uVar112) >> 0x38,0) &
613: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
614: ,0) &
615: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
616: ,0) &
617: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
618: ,0) &
619: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
620: ,0),(uVar111 >> 0x18) << 0x30) >> 0x30,0),
621: uVar110) >> 0x28,0) &
622: SUB1611((undefined  [16])0xffff00ffffffffff >>
623: 0x28,0),(uVar132 >> 0x10) << 0x20) >> 0x20
624: ,0),uVar105) >> 0x18,0) &
625: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
626: auVar162 = CONCAT142(SUB1614(CONCAT133(auVar164,(uVar104 >> 8) << 0x10) >> 0x10,0),uVar103
627: ) & (undefined  [16])0xffffffffffff00ff;
628: uVar107 = SUB144(CONCAT212(SUB162(auVar101 >> 0x30,0),ZEXT1012(SUB1610(auVar101,0))) >>
629: 0x50,0);
630: auVar59 = CONCAT410(uVar107,CONCAT28(SUB162(auVar101 >> 0x20,0),SUB168(auVar101,0)));
631: auVar160 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
632: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
633: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
634: (CONCAT213(SUB152(CONCAT114(cVar38,CONCAT113(
635: cVar51,CONCAT112(cVar50,auVar98))) >> 0x68,0),
636: CONCAT112(cVar39,auVar98)) >> 0x60,0),auVar98) >>
637: 0x58,0),CONCAT110(cVar40,Var97)) >> 0x50,0),Var97)
638: >> 0x48,0),CONCAT18(cVar41,uVar95)) >> 0x40,0),
639: uVar95) >> 0x38,0) &
640: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
641: ,0) &
642: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
643: ,0) &
644: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
645: ,0) &
646: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
647: ,0),(uVar94 >> 0x18) << 0x30) >> 0x30,0),
648: uVar93) >> 0x28,0) &
649: SUB1611((undefined  [16])0xffff00ffffffffff >>
650: 0x28,0),(uVar92 >> 0x10) << 0x20) >> 0x20,
651: 0),uVar89) >> 0x18,0) &
652: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
653: auVar143 = CONCAT142(SUB1614(CONCAT133(auVar160,(uVar88 >> 8) << 0x10) >> 0x10,0),uVar87)
654: & (undefined  [16])0xffffffffffff00ff;
655: Var145 = (unkuint10)
656: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar158 >> 0x30,0),
657: SUB1612(auVar158,0)) >> 0x50,0)
658: ,CONCAT28(SUB162(auVar158 >> 0x20,0),
659: SUB168(auVar158,0))) >> 0x40,0),
660: SUB168(auVar158,0)) >> 0x30,0) &
661: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
662: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
663: uVar72 = (uint)SUB132(auVar144 >> 0x28,0);
664: auVar127 = ZEXT1012(CONCAT28(SUB132(auVar144 >> 0x48,0),
665: (ulong)CONCAT24(SUB132(auVar144 >> 0x38,0),uVar72)));
666: uVar68 = SUB132(auVar144 >> 0x58,0);
667: uVar156 = (uint)SUB132(auVar159 >> 0x28,0);
668: uVar81 = SUB132(auVar159 >> 0x58,0);
669: auVar157 = CONCAT212(uVar81,ZEXT1012(CONCAT28(SUB132(auVar159 >> 0x48,0),
670: (ulong)CONCAT24(SUB132(auVar159 >> 0x38,0),
671: uVar156))));
672: uVar131 = (uint)CONCAT12(cVar32,(ushort)bVar31);
673: uVar132 = CONCAT14(cVar33,uVar131);
674: uVar133 = (ulong)CONCAT16(cVar34,(uint6)uVar132);
675: auVar134 = ZEXT1112(CONCAT110(cVar36,(unkuint10)CONCAT18(cVar35,uVar133)));
676: auVar135 = ZEXT1314(CONCAT112((uVar124 != 0) * (uVar124 < 0xff) *
677: SUB161(auVar151 >> 0x68,0) - (0xff < uVar124),auVar134));
678: uVar91 = SUB144(CONCAT212(SUB162(auVar162 >> 0x30,0),SUB1612(auVar162,0)) >> 0x50,0);
679: auVar151 = ZEXT1416(CONCAT410(uVar91,CONCAT28(SUB162(auVar162 >> 0x20,0),
680: SUB168(auVar162,0)))) &
681: (undefined  [16])0xffffffffffffffff;
682: uVar90 = (uint)SUB162(auVar163 >> 0x40,0);
683: uVar80 = SUB162(auVar163 >> 0x70,0);
684: auVar99 = CONCAT212(uVar80,ZEXT1012(CONCAT28(SUB162(auVar163 >> 0x60,0),
685: (ulong)CONCAT24(SUB162(auVar163 >> 0x50,0),
686: uVar90))));
687: uVar82 = SUB132(auVar164 >> 0x58,0);
688: auVar161 = CONCAT212(uVar82,ZEXT1012(CONCAT28(SUB132(auVar164 >> 0x48,0),
689: (ulong)SUB132(auVar164 >> 0x38,0) << 0x20)))
690: ;
691: Var146 = (unkuint10)
692: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar163 >> 0x30,0),
693: SUB1612(auVar58,0)) >> 0x50,0),
694: CONCAT28(SUB162(auVar154 >> 0x20,0),
695: SUB168(auVar58,0))) >> 0x40,0),
696: SUB168(auVar58,0)) >> 0x30,0) &
697: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
698: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
699: auVar100 = CONCAT412((uint)uVar80 << 8,
700: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar99 >> 0x20,0)) >> 0x20,0) << 8,
701: CONCAT44(SUB164(ZEXT1416(auVar99) >> 0x20,0) << 8,
702: uVar90 << 8))) & _DAT_0018d090;
703: uVar90 = (uint)CONCAT12(cVar22,(ushort)bVar21);
704: uVar92 = CONCAT14(cVar23,uVar90);
705: uVar96 = (ulong)CONCAT16(cVar24,(uint6)uVar92);
706: auVar98 = ZEXT1112(CONCAT110((0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar128 >> 0x50,0) -
707: (0xff < sVar55),(unkuint10)CONCAT18(cVar25,uVar96)));
708: auVar99 = ZEXT1314(CONCAT112((0 < sVar56) * (sVar56 < 0xff) * SUB161(auVar128 >> 0x60,0) -
709: (0xff < sVar56),auVar98));
710: uVar137 = (uint)CONCAT12(cVar43,(ushort)bVar42);
711: uVar139 = CONCAT14(cVar17,uVar137);
712: uVar140 = (ulong)CONCAT16(cVar18,(uint6)uVar139);
713: auVar141 = ZEXT1112(CONCAT110(cVar20,(unkuint10)CONCAT18(cVar19,uVar140)));
714: auVar142 = ZEXT1314(CONCAT112((0 < sVar57) * (sVar57 < 0xff) * SUB161(auVar136 >> 0x60,0)
715: - (0xff < sVar57),auVar141));
716: uVar138 = (uint)SUB132(auVar155 >> 0x28,0);
717: uVar80 = SUB132(auVar155 >> 0x58,0);
718: auVar152 = CONCAT212(uVar80,ZEXT1012(CONCAT28(SUB132(auVar155 >> 0x48,0),
719: (ulong)CONCAT24(SUB132(auVar155 >> 0x38,0),
720: uVar138))));
721: Var147 = (unkuint10)
722: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar153 >> 0x30,0),
723: ZEXT1012(SUB1610(auVar153,0)))
724: >> 0x50,0),
725: CONCAT28(SUB162(auVar153 >> 0x20,0),
726: SUB168(auVar153,0))) >> 0x40,0),
727: SUB168(auVar153,0)) >> 0x30,0) &
728: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
729: auVar163 = ZEXT1416(CONCAT212(uVar82 >> 3,
730: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar161 >> 0x20,0)) >>
731: 0x20,0) >> 3,
732: CONCAT44(SUB164(ZEXT1416(auVar161) >> 0x20,0) >> 3,
733: (uint)(ushort)(SUB132(auVar164 >> 0x28,0)
734: >> 3))))) |
735: CONCAT412((uint)uVar68 << 8,
736: CONCAT48(SUB164(ZEXT1416(CONCAT212(uVar68,auVar127)) >> 0x40,0) << 8,
737: CONCAT44(SUB124(auVar127 >> 0x20,0) << 8,uVar72 << 8))) &
738: _DAT_0018d090 |
739: CONCAT412((uint)uVar81 << 3,
740: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar157 >> 0x20,0)) >> 0x20,0) << 3
741: ,CONCAT44(SUB164(ZEXT1416(auVar157) >> 0x20,0) << 3,
742: uVar156 << 3))) & _DAT_0018d0a0;
743: auVar154 = CONCAT412((uint)uVar80 << 3,
744: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar152 >> 0x20,0)) >> 0x20,0) << 3
745: ,CONCAT44(SUB164(ZEXT1416(auVar152) >> 0x20,0) << 3,
746: uVar138 << 3))) & _DAT_0018d0a0;
747: uVar68 = SUB132(auVar160 >> 0x58,0);
748: auVar152 = CONCAT212(uVar68,ZEXT1012(CONCAT28(SUB132(auVar160 >> 0x48,0),
749: (ulong)SUB132(auVar160 >> 0x38,0) << 0x20)))
750: ;
751: Var149 = (unkuint10)
752: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar143 >> 0x30,0),
753: SUB1612(auVar143,0)) >> 0x50,0)
754: ,CONCAT28(SUB162(auVar143 >> 0x20,0),
755: SUB168(auVar143,0))) >> 0x40,0),
756: SUB168(auVar143,0)) >> 0x30,0) &
757: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
758: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
759: uVar72 = (uint)SUB142(auVar79 >> 0x40,0);
760: auVar144 = CONCAT112(bVar3,ZEXT1012(CONCAT28((short)((unkuint10)
761: SUB159(CONCAT114(bVar3,auVar79) >>
762: 0x30,0) >> 0x30),
763: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
764: CONCAT114(bVar3,auVar79) >> 0x10,0)) >> 0x40,0),
765: uVar72))));
766: Var148 = (unkuint10)
767: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar79 >> 0x30,0),
768: auVar78) >> 0x50,0),
769: CONCAT28(SUB122(auVar78 >> 0x20,0),uVar60)) >>
770: 0x40,0),uVar60) >> 0x30,0) &
771: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
772: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
773: uVar138 = (uint)SUB142(auVar142 >> 0x40,0);
774: auVar155 = CONCAT112(bVar44,ZEXT1012(CONCAT28((short)((unkuint10)
775: SUB159(CONCAT114(bVar44,auVar142) >>
776: 0x30,0) >> 0x30),
777: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
778: CONCAT114(bVar44,auVar142) >> 0x10,0)) >> 0x40,0),
779: uVar138))));
780: puVar1 = (uint *)(puVar64 + lVar61);
781: *puVar1 = ((SUB164(auVar158,0) & 0xfc) << 3 | (SUB164(auVar101,0) & 0xf8) << 8 |
782: (SUB164(auVar162,0) & 0xffff) >> 3) << 0x10 |
783: (SUB164(auVar153,0) & 0xfc) << 3 | (SUB164(auVar58,0) & 0xf8) << 8 |
784: (SUB164(auVar143,0) & 0xffff) >> 3;
785: puVar1[1] = ((SUB164(CONCAT106(Var145,(SUB166(auVar158,0) >> 0x10) << 0x20) >> 0x20,0) &
786: 0xfc) << 3 |
787: (SUB164(CONCAT106((unkuint10)
788: SUB148(CONCAT68(SUB146(auVar59 >> 0x40,0),
789: SUB168(auVar101,0)) >> 0x30,0) &
790: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
791: (SUB166(auVar101,0) >> 0x10) << 0x20) >> 0x20,0) & 0xf8) <<
792: 8 | SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar151 >> 0x40,0),
793: SUB168(auVar162,0)) >> 0x30,0) &
794: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
795: (SUB166(auVar162,0) >> 0x10) << 0x20) >> 0x20,0) >> 3)
796: << 0x10 | (SUB164(CONCAT106(Var147,(SUB166(auVar153,0) >> 0x10) << 0x20) >>
797: 0x20,0) & 0xfc) << 3 |
798: (SUB164(CONCAT106(Var146,(SUB166(auVar58,0) >> 0x10) << 0x20) >>
799: 0x20,0) & 0xf8) << 8 |
800: SUB164(CONCAT106(Var149,(SUB166(auVar143,0) >> 0x10) << 0x20) >>
801: 0x20,0) >> 3;
802: puVar1[2] = (((uint)(Var145 >> 0x10) & 0xfc) << 3 |
803: (SUB164(ZEXT1416(auVar59) >> 0x40,0) & 0xf8) << 8 |
804: SUB164(auVar151 >> 0x40,0) >> 3) << 0x10 |
805: ((uint)(Var147 >> 0x10) & 0xfc) << 3 | ((uint)(Var146 >> 0x10) & 0xf8) << 8 |
806: (uint)(Var149 >> 0x10) >> 3;
807: puVar1[3] = (((uint)(Var145 >> 0x30) & 0xfc) << 3 | (uVar107 >> 0x10 & 0xf8) << 8 |
808: uVar91 >> 0x13) << 0x10 |
809: ((uint)(Var147 >> 0x30) & 0xfc) << 3 | ((uint)(Var146 >> 0x30) & 0xf8) << 8 |
810: (uint)(Var149 >> 0x33);
811: Var149 = (unkuint10)
812: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar142 >> 0x30,0),
813: auVar141) >> 0x50,0),
814: CONCAT28(SUB122(auVar141 >> 0x20,0),uVar140)) >>
815: 0x40,0),uVar140) >> 0x30,0) &
816: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
817: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
818: Var145 = (unkuint10)
819: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar117 >> 0x30,0),
820: auVar116) >> 0x50,0),
821: CONCAT28(SUB122(auVar116 >> 0x20,0),uVar113)) >>
822: 0x40,0),uVar113) >> 0x30,0) &
823: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
824: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
825: *(undefined (*) [16])(puVar64 + lVar61 + 8) =
826: CONCAT412(SUB164(auVar163 >> 0x60,0) << 0x10,
827: CONCAT48(SUB164(auVar163 >> 0x40,0) << 0x10,
828: CONCAT44(SUB164(auVar163 >> 0x20,0) << 0x10,
829: SUB164(auVar163,0) << 0x10))) |
830: ZEXT1416(CONCAT212(uVar68 >> 3,
831: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar152 >> 0x20,0)) >> 0x20,0)
832: >> 3,CONCAT44(SUB164(ZEXT1416(auVar152) >> 0x20,0) >> 3,
833: (uint)(ushort)(SUB132(auVar160 >> 0x28,0)
834: >> 3))))) |
835: auVar100 | auVar154;
836: uVar107 = (uint)SUB142(auVar117 >> 0x40,0);
837: auVar159 = CONCAT112(bVar37,ZEXT1012(CONCAT28(SUB162(ZEXT1516(CONCAT114(bVar37,auVar117))
838: >> 0x60,0),
839: (ulong)CONCAT24(SUB162(ZEXT1516(CONCAT114(
840: bVar37,auVar117)) >> 0x50,0),uVar107))));
841: Var146 = (unkuint10)
842: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar135 >> 0x30,0),
843: auVar134) >> 0x50,0),
844: CONCAT28(SUB122(auVar134 >> 0x20,0),uVar133)) >>
845: 0x40,0),uVar133) >> 0x30,0) &
846: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
847: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
848: uVar91 = (uint)SUB142(auVar99 >> 0x40,0);
849: auVar160 = CONCAT112(bVar26,ZEXT1012(CONCAT28((short)((unkuint10)
850: SUB159(CONCAT114(bVar26,auVar99) >>
851: 0x30,0) >> 0x30),
852: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
853: CONCAT114(bVar26,auVar99) >> 0x10,0)) >> 0x40,0),
854: uVar91))));
855: auVar164 = CONCAT112(bVar45,ZEXT1012(CONCAT28((short)((unkuint10)
856: SUB159(CONCAT114(bVar45,auVar135) >>
857: 0x30,0) >> 0x30),
858: (ulong)SUB142(ZEXT1314(SUB1513(CONCAT114(
859: bVar45,auVar135) >> 0x10,0)) >> 0x40,0) << 0x20)))
860: ;
861: Var147 = (unkuint10)
862: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar99 >> 0x30,0),
863: auVar98) >> 0x50,0),
864: CONCAT28(SUB122(auVar98 >> 0x20,0),uVar96)) >>
865: 0x40,0),uVar96) >> 0x30,0) &
866: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
867: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
868: auVar101 = CONCAT412((uint)bVar26 << 8,
869: CONCAT48(SUB124(ZEXT912(SUB139(auVar160 >> 0x20,0)) >> 0x20,0) << 8,
870: CONCAT44(SUB164(ZEXT1316(auVar160) >> 0x20,0) << 8,
871: uVar91 << 8))) & _DAT_0018d090;
872: auVar100 = ZEXT1316(CONCAT112(bVar45 >> 3,
873: CONCAT48(SUB124(ZEXT912(SUB139(auVar164 >> 0x20,0)) >> 0x20,
874: 0) >> 3,
875: CONCAT44(SUB164(ZEXT1316(auVar164) >> 0x20,0) >> 3,
876: (uint)(ushort)(SUB142(auVar135 >> 0x40,0)
877: >> 3))))) |
878: CONCAT412((uint)bVar3 << 8,
879: CONCAT48(SUB124(ZEXT912(SUB139(auVar144 >> 0x20,0)) >> 0x20,0) << 8,
880: CONCAT44(SUB164(ZEXT1316(auVar144) >> 0x20,0) << 8,
881: uVar72 << 8))) & _DAT_0018d090 |
882: CONCAT412((uint)bVar37 << 3,
883: CONCAT48(SUB124(ZEXT912(SUB139(auVar159 >> 0x20,0)) >> 0x20,0) << 3,
884: CONCAT44(SUB164(ZEXT1316(auVar159) >> 0x20,0) << 3,
885: uVar107 << 3))) & _DAT_0018d0a0;
886: Var150 = (unkuint10)
887: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar129 >> 0x30,0),
888: auVar115) >> 0x50,0),
889: CONCAT28(SUB162(auVar129 >> 0x20,0),uVar126)) >>
890: 0x40,0),uVar126) >> 0x30,0) &
891: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
892: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
893: puVar1 = (uint *)(puVar64 + lVar61 + 0x10);
894: *puVar1 = ((uVar71 & 0xf8) << 8 | (uVar106 & 0xfc) << 3 | (uVar131 & 0xffff) >> 3) << 0x10
895: | (uVar90 & 0xf8) << 8 | (uVar137 & 0xfc) << 3 | (uVar125 & 0xffff) >> 3;
896: puVar1[1] = ((SUB164(CONCAT106(Var148,(uint6)(uVar73 >> 0x10) << 0x20) >> 0x20,0) & 0xf8)
897: << 8 | (SUB164(CONCAT106(Var145,(uint6)(uVar109 >> 0x10) << 0x20) >> 0x20,0)
898: & 0xfc) << 3 |
899: SUB164(CONCAT106(Var146,(uint6)(uVar132 >> 0x10) << 0x20) >> 0x20,0) >> 3) <<
900: 0x10 | (SUB164(CONCAT106(Var147,(uint6)(uVar92 >> 0x10) << 0x20) >> 0x20,0) &
901: 0xf8) << 8 |
902: (SUB164(CONCAT106(Var149,(uint6)(uVar139 >> 0x10) << 0x20) >> 0x20,0) &
903: 0xfc) << 3 |
904: SUB164(CONCAT106(Var150,(uint6)(uVar108 >> 0x10) << 0x20) >> 0x20,0) >>
905: 3;
906: puVar1[2] = (((uint)(Var148 >> 0x10) & 0xf8) << 8 | ((uint)(Var145 >> 0x10) & 0xfc) << 3 |
907: (uint)(Var146 >> 0x10) >> 3) << 0x10 |
908: ((uint)(Var147 >> 0x10) & 0xf8) << 8 | ((uint)(Var149 >> 0x10) & 0xfc) << 3 |
909: (uint)(Var150 >> 0x10) >> 3;
910: puVar1[3] = (((uint)(Var148 >> 0x30) & 0xf8) << 8 | ((uint)(Var145 >> 0x30) & 0xfc) << 3 |
911: (uint)(Var146 >> 0x33)) << 0x10 |
912: ((uint)(Var147 >> 0x30) & 0xf8) << 8 | ((uint)(Var149 >> 0x30) & 0xfc) << 3 |
913: (uint)(Var150 >> 0x33);
914: auVar144 = CONCAT112(bVar52,ZEXT1012(CONCAT28(SUB162(auVar129 >> 0x60,0),
915: (ulong)SUB162(auVar129 >> 0x50,0) << 0x20)))
916: ;
917: *(undefined (*) [16])(puVar64 + lVar61 + 0x18) =
918: CONCAT412(SUB164(auVar100 >> 0x60,0) << 0x10,
919: CONCAT48(SUB164(auVar100 >> 0x40,0) << 0x10,
920: CONCAT44(SUB164(auVar100 >> 0x20,0) << 0x10,
921: SUB164(auVar100,0) << 0x10))) |
922: auVar101 |
923: CONCAT412((uint)bVar44 << 3,
924: CONCAT48(SUB124(ZEXT912(SUB139(auVar155 >> 0x20,0)) >> 0x20,0) << 3,
925: CONCAT44(SUB164(ZEXT1316(auVar155) >> 0x20,0) << 3,uVar138 << 3)))
926: & _DAT_0018d0a0 |
927: ZEXT1316(CONCAT112(bVar52 >> 3,
928: CONCAT48(SUB124(ZEXT912(SUB139(auVar144 >> 0x20,0)) >> 0x20,0) >>
929: 3,CONCAT44(SUB164(ZEXT1316(auVar144) >> 0x20,0) >> 3,
930: (uint)(ushort)(SUB162(auVar129 >> 0x40,0) >> 3
931: )))));
932: lVar61 = lVar61 + 0x20;
933: } while (uVar62 < uStack68 >> 5);
934: uVar62 = (uStack68 >> 5) * 0x10;
935: uVar60 = (ulong)uVar62;
936: lVar61 = 0;
937: if (uVar63 != uVar62) {
938: do {
939: *(uint *)(puVar64 + uVar60 * 2 + lVar61 * 2) =
940: ((*(byte *)((long)(puVar65 + uVar60) + lVar61 * 2 + 1) & 0xfc) << 3 |
941: (*(byte *)((long)(puVar66 + uVar60) + lVar61 * 2 + 1) & 0xf8) << 8 |
942: (uint)(*(byte *)((long)(puVar67 + uVar60) + lVar61 * 2 + 1) >> 3)) << 0x10 |
943: (*(byte *)(puVar66 + uVar60 + lVar61) & 0xf8) << 8 |
944: (*(byte *)(puVar65 + uVar60 + lVar61) & 0xfc) << 3 |
945: (uint)(*(byte *)(puVar67 + uVar60 + lVar61) >> 3);
946: lVar61 = lVar61 + 1;
947: } while (uVar62 + (int)lVar61 < uVar63);
948: }
949: uVar60 = (ulong)(uVar63 - 1);
950: }
951: lVar61 = uVar60 + 1;
952: puVar64 = puVar64 + lVar61 * 2;
953: puVar66 = puVar66 + lVar61;
954: puVar65 = puVar65 + lVar61;
955: puVar67 = puVar67 + lVar61;
956: }
957: param_4 = ppuVar6;
958: if ((uStack68 & 1) != 0) {
959: *puVar64 = (ushort)((*(byte *)puVar66 & 0xf8) << 8) | (ushort)((*(byte *)puVar65 & 0xfc) << 3)
960: | (ushort)(*(byte *)puVar67 >> 3);
961: }
962: }
963: /* WARNING: Read-only address (ram,0x0016c610) is written */
964: /* WARNING: Read-only address (ram,0x0018d090) is written */
965: /* WARNING: Read-only address (ram,0x0018d0a0) is written */
966: return;
967: }
968: 

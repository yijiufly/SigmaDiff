1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_001067f0(long param_1,long *param_2,long *param_3,uint param_4,int param_5)
5: 
6: {
7: undefined *puVar1;
8: undefined *puVar2;
9: undefined *puVar3;
10: char *pcVar4;
11: undefined uVar5;
12: int iVar6;
13: uint uVar7;
14: undefined *puVar8;
15: long lVar9;
16: long lVar10;
17: char cVar11;
18: char cVar19;
19: char cVar27;
20: char cVar35;
21: short sVar43;
22: short sVar44;
23: short sVar45;
24: short sVar46;
25: short sVar47;
26: short sVar48;
27: short sVar49;
28: short sVar50;
29: short sVar51;
30: short sVar52;
31: short sVar53;
32: short sVar54;
33: short sVar55;
34: short sVar56;
35: short sVar57;
36: short sVar58;
37: undefined auVar59 [16];
38: undefined *puVar60;
39: undefined *puVar61;
40: undefined *puVar62;
41: undefined *puVar63;
42: long lVar64;
43: ulong uVar65;
44: ulong uVar66;
45: ulong uVar67;
46: uint uVar68;
47: long lVar69;
48: ulong uVar70;
49: long *plVar71;
50: uint uVar72;
51: ushort uVar73;
52: ushort uVar81;
53: undefined4 uVar74;
54: ushort uVar82;
55: ushort uVar83;
56: ushort uVar84;
57: ushort uVar85;
58: ushort uVar86;
59: ushort uVar87;
60: undefined4 uVar88;
61: undefined4 uVar94;
62: ushort uVar101;
63: ushort uVar102;
64: ushort uVar103;
65: ushort uVar104;
66: undefined auVar100 [16];
67: ushort uVar105;
68: ushort uVar106;
69: ushort uVar113;
70: undefined4 uVar107;
71: ushort uVar114;
72: ushort uVar115;
73: ushort uVar116;
74: ushort uVar117;
75: ushort uVar118;
76: ushort uVar119;
77: ushort uVar120;
78: ushort uVar121;
79: ushort uVar122;
80: ushort uVar123;
81: ushort uVar124;
82: ushort uVar125;
83: ushort uVar126;
84: undefined auVar127 [16];
85: undefined auVar128 [16];
86: undefined auVar129 [16];
87: undefined auVar130 [16];
88: char cVar12;
89: char cVar13;
90: char cVar14;
91: char cVar15;
92: char cVar16;
93: char cVar17;
94: char cVar18;
95: char cVar20;
96: char cVar21;
97: char cVar22;
98: char cVar23;
99: char cVar24;
100: char cVar25;
101: char cVar26;
102: char cVar28;
103: char cVar29;
104: char cVar30;
105: char cVar31;
106: char cVar32;
107: char cVar33;
108: char cVar34;
109: char cVar36;
110: char cVar37;
111: char cVar38;
112: char cVar39;
113: char cVar40;
114: char cVar41;
115: char cVar42;
116: undefined6 uVar75;
117: undefined8 uVar76;
118: unkbyte10 Var77;
119: undefined auVar78 [12];
120: undefined auVar79 [14];
121: undefined auVar80 [16];
122: undefined6 uVar89;
123: undefined8 uVar90;
124: unkbyte10 Var91;
125: undefined auVar92 [12];
126: undefined auVar93 [14];
127: undefined6 uVar95;
128: undefined8 uVar96;
129: unkbyte10 Var97;
130: undefined auVar98 [12];
131: undefined auVar99 [14];
132: undefined6 uVar108;
133: undefined8 uVar109;
134: unkbyte10 Var110;
135: undefined auVar111 [12];
136: undefined auVar112 [14];
137: 
138: auVar59 = _DAT_0016c610;
139: uVar65 = (ulong)param_4;
140: iVar6 = *(int *)(param_1 + 0x4c);
141: uVar7 = *(uint *)(param_1 + 0x30);
142: if (iVar6 == 3) {
143: while (param_5 = param_5 + -1, -1 < param_5) {
144: plVar71 = param_2 + 1;
145: uVar70 = (ulong)((int)uVar65 + 1);
146: puVar62 = (undefined *)*param_2;
147: lVar69 = *(long *)(*param_3 + uVar65 * 8);
148: lVar9 = *(long *)(param_3[1] + uVar65 * 8);
149: lVar10 = *(long *)(param_3[2] + uVar65 * 8);
150: param_2 = plVar71;
151: uVar65 = uVar70;
152: if (uVar7 != 0) {
153: lVar64 = 0;
154: puVar60 = puVar62;
155: do {
156: puVar63 = puVar60 + 3;
157: *(undefined *)(lVar69 + lVar64) = *puVar60;
158: *(undefined *)(lVar9 + lVar64) = puVar60[1];
159: *(undefined *)(lVar10 + lVar64) = puVar60[2];
160: lVar64 = lVar64 + 1;
161: puVar60 = puVar63;
162: } while (puVar62 + (ulong)(uVar7 - 1) * 3 + 3 != puVar63);
163: }
164: }
165: }
166: else {
167: if (iVar6 == 4) {
168: uVar70 = (ulong)uVar7;
169: uVar72 = uVar7 & 0xfffffff0;
170: uVar65 = (ulong)param_4;
171: LAB_001068f0:
172: while( true ) {
173: do {
174: param_5 = param_5 + -1;
175: if (param_5 < 0) {
176: return;
177: }
178: plVar71 = param_2 + 1;
179: uVar66 = (ulong)((int)uVar65 + 1);
180: puVar62 = (undefined *)*param_2;
181: puVar60 = *(undefined **)(*param_3 + uVar65 * 8);
182: puVar63 = *(undefined **)(param_3[1] + uVar65 * 8);
183: puVar61 = *(undefined **)(param_3[2] + uVar65 * 8);
184: puVar8 = *(undefined **)(param_3[3] + uVar65 * 8);
185: uVar65 = uVar66;
186: param_2 = plVar71;
187: } while (uVar7 == 0);
188: puVar1 = puVar61 + 0x10;
189: puVar3 = puVar62 + uVar70 * 4;
190: puVar2 = puVar60 + 0x10;
191: if (((((((((0xf < uVar7 &&
192: ((puVar3 <= puVar60 || puVar60 + uVar70 <= puVar62) &&
193: (puVar63 + uVar70 <= puVar62 || puVar3 <= puVar63))) &&
194: (puVar61 + uVar70 <= puVar62 || puVar3 <= puVar61)) &&
195: (puVar3 <= puVar8 || puVar8 + uVar70 <= puVar62)) &&
196: (puVar63 + 0x10 <= puVar60 || puVar2 <= puVar63)) &&
197: (puVar1 <= puVar60 || puVar2 <= puVar61)) &&
198: (puVar8 + 0x10 <= puVar60 || puVar2 <= puVar8)) &&
199: (puVar1 <= puVar63 || puVar63 + 0x10 <= puVar61)) &&
200: (puVar63 + 0x10 <= puVar8 || puVar8 + 0x10 <= puVar63)) &&
201: (puVar1 <= puVar8 || puVar8 + 0x10 <= puVar61)) break;
202: lVar69 = 0;
203: do {
204: puVar60[lVar69] = *puVar62;
205: puVar63[lVar69] = puVar62[1];
206: puVar61[lVar69] = puVar62[2];
207: puVar8[lVar69] = puVar62[3];
208: lVar69 = lVar69 + 1;
209: puVar62 = puVar62 + 4;
210: } while (lVar69 != (ulong)(uVar7 - 1) + 1);
211: }
212: if (0xe < uVar7 - 1) goto code_r0x00106a5c;
213: uVar68 = 0;
214: goto LAB_00106b4b;
215: }
216: if (((0 < param_5) && (0 < iVar6)) && (uVar7 != 0)) {
217: do {
218: lVar69 = 0;
219: do {
220: puVar62 = *(undefined **)(param_3[lVar69] + uVar65 * 8);
221: puVar63 = (undefined *)(*param_2 + lVar69);
222: puVar60 = puVar62;
223: do {
224: uVar5 = *puVar63;
225: puVar61 = puVar60 + 1;
226: puVar63 = puVar63 + iVar6;
227: *puVar60 = uVar5;
228: puVar60 = puVar61;
229: } while (puVar61 != puVar62 + (ulong)(uVar7 - 1) + 1);
230: lVar69 = lVar69 + 1;
231: } while (lVar69 != (ulong)(iVar6 - 1) + 1);
232: uVar72 = (int)uVar65 + 1;
233: uVar65 = (ulong)uVar72;
234: param_2 = param_2 + 1;
235: } while (uVar72 != param_5 + param_4);
236: }
237: }
238: /* WARNING: Read-only address (ram,0x0016c610) is written */
239: return;
240: code_r0x00106a5c:
241: lVar69 = 0;
242: uVar68 = 0;
243: do {
244: auVar127 = *(undefined (*) [16])(puVar62 + lVar69 * 4);
245: uVar68 = uVar68 + 1;
246: auVar80 = *(undefined (*) [16])(puVar62 + lVar69 * 4 + 0x10);
247: auVar100 = auVar59 & auVar127;
248: uVar73 = SUB162(auVar127,0) >> 8;
249: uVar81 = SUB162(auVar127 >> 0x10,0) >> 8;
250: uVar82 = SUB162(auVar127 >> 0x20,0) >> 8;
251: uVar83 = SUB162(auVar127 >> 0x30,0) >> 8;
252: uVar84 = SUB162(auVar127 >> 0x40,0) >> 8;
253: uVar85 = SUB162(auVar127 >> 0x50,0) >> 8;
254: uVar86 = SUB162(auVar127 >> 0x60,0) >> 8;
255: uVar87 = SUB162(auVar127 >> 0x78,0);
256: auVar128 = auVar59 & auVar80;
257: auVar130 = *(undefined (*) [16])(puVar62 + lVar69 * 4 + 0x20);
258: uVar106 = SUB162(auVar80,0) >> 8;
259: uVar113 = SUB162(auVar80 >> 0x10,0) >> 8;
260: uVar115 = SUB162(auVar80 >> 0x20,0) >> 8;
261: uVar117 = SUB162(auVar80 >> 0x30,0) >> 8;
262: uVar119 = SUB162(auVar80 >> 0x40,0) >> 8;
263: uVar121 = SUB162(auVar80 >> 0x50,0) >> 8;
264: uVar123 = SUB162(auVar80 >> 0x60,0) >> 8;
265: uVar125 = SUB162(auVar80 >> 0x78,0);
266: cVar11 = (uVar81 != 0) * (uVar81 < 0xff) * SUB161(auVar127 >> 0x18,0) - (0xff < uVar81);
267: cVar12 = (uVar83 != 0) * (uVar83 < 0xff) * SUB161(auVar127 >> 0x38,0) - (0xff < uVar83);
268: uVar74 = CONCAT13(cVar12,CONCAT12((uVar82 != 0) * (uVar82 < 0xff) * SUB161(auVar127 >> 0x28,0) -
269: (0xff < uVar82),
270: CONCAT11(cVar11,(uVar73 != 0) * (uVar73 < 0xff) *
271: SUB161(auVar127 >> 8,0) - (0xff < uVar73))));
272: cVar13 = (uVar85 != 0) * (uVar85 < 0xff) * SUB161(auVar127 >> 0x58,0) - (0xff < uVar85);
273: uVar75 = CONCAT15(cVar13,CONCAT14((uVar84 != 0) * (uVar84 < 0xff) * SUB161(auVar127 >> 0x48,0) -
274: (0xff < uVar84),uVar74));
275: cVar14 = (uVar87 != 0) * (uVar87 < 0xff) * SUB161(auVar127 >> 0x78,0) - (0xff < uVar87);
276: uVar76 = CONCAT17(cVar14,CONCAT16((uVar86 != 0) * (uVar86 < 0xff) * SUB161(auVar127 >> 0x68,0) -
277: (0xff < uVar86),uVar75));
278: cVar15 = (uVar113 != 0) * (uVar113 < 0xff) * SUB161(auVar80 >> 0x18,0) - (0xff < uVar113);
279: Var77 = CONCAT19(cVar15,CONCAT18((uVar106 != 0) * (uVar106 < 0xff) * SUB161(auVar80 >> 8,0) -
280: (0xff < uVar106),uVar76));
281: cVar16 = (uVar117 != 0) * (uVar117 < 0xff) * SUB161(auVar80 >> 0x38,0) - (0xff < uVar117);
282: auVar78 = CONCAT111(cVar16,CONCAT110((uVar115 != 0) * (uVar115 < 0xff) *
283: SUB161(auVar80 >> 0x28,0) - (0xff < uVar115),Var77));
284: cVar17 = (uVar121 != 0) * (uVar121 < 0xff) * SUB161(auVar80 >> 0x58,0) - (0xff < uVar121);
285: auVar79 = CONCAT113(cVar17,CONCAT112((uVar119 != 0) * (uVar119 < 0xff) *
286: SUB161(auVar80 >> 0x48,0) - (0xff < uVar119),auVar78));
287: cVar18 = (uVar125 != 0) * (uVar125 < 0xff) * SUB161(auVar80 >> 0x78,0) - (0xff < uVar125);
288: auVar80 = CONCAT115(cVar18,CONCAT114((uVar123 != 0) * (uVar123 < 0xff) *
289: SUB161(auVar80 >> 0x68,0) - (0xff < uVar123),auVar79));
290: auVar127 = *(undefined (*) [16])(puVar62 + lVar69 * 4 + 0x30);
291: sVar43 = SUB162(auVar100,0);
292: sVar44 = SUB162(auVar100 >> 0x10,0);
293: cVar19 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar100 >> 0x10,0) - (0xff < sVar44);
294: sVar44 = SUB162(auVar100 >> 0x20,0);
295: sVar45 = SUB162(auVar100 >> 0x30,0);
296: cVar20 = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar100 >> 0x30,0) - (0xff < sVar45);
297: uVar94 = CONCAT13(cVar20,CONCAT12((0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar100 >> 0x20,0) -
298: (0xff < sVar44),
299: CONCAT11(cVar19,(0 < sVar43) * (sVar43 < 0xff) *
300: SUB161(auVar100,0) - (0xff < sVar43))));
301: sVar43 = SUB162(auVar100 >> 0x40,0);
302: sVar44 = SUB162(auVar100 >> 0x50,0);
303: cVar21 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar100 >> 0x50,0) - (0xff < sVar44);
304: uVar95 = CONCAT15(cVar21,CONCAT14((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar100 >> 0x40,0) -
305: (0xff < sVar43),uVar94));
306: sVar43 = SUB162(auVar100 >> 0x60,0);
307: sVar44 = SUB162(auVar100 >> 0x70,0);
308: cVar22 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar100 >> 0x70,0) - (0xff < sVar44);
309: uVar96 = CONCAT17(cVar22,CONCAT16((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar100 >> 0x60,0) -
310: (0xff < sVar43),uVar95));
311: sVar43 = SUB162(auVar128,0);
312: sVar44 = SUB162(auVar128 >> 0x10,0);
313: cVar23 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x10,0) - (0xff < sVar44);
314: Var97 = CONCAT19(cVar23,CONCAT18((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar128,0) -
315: (0xff < sVar43),uVar96));
316: sVar43 = SUB162(auVar128 >> 0x20,0);
317: sVar44 = SUB162(auVar128 >> 0x30,0);
318: cVar24 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x30,0) - (0xff < sVar44);
319: auVar98 = CONCAT111(cVar24,CONCAT110((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar128 >> 0x20,0)
320: - (0xff < sVar43),Var97));
321: sVar43 = SUB162(auVar128 >> 0x40,0);
322: sVar44 = SUB162(auVar128 >> 0x50,0);
323: cVar25 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x50,0) - (0xff < sVar44);
324: auVar99 = CONCAT113(cVar25,CONCAT112((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar128 >> 0x40,0)
325: - (0xff < sVar43),auVar98));
326: sVar43 = SUB162(auVar128 >> 0x60,0);
327: sVar44 = SUB162(auVar128 >> 0x70,0);
328: cVar26 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x70,0) - (0xff < sVar44);
329: auVar100 = CONCAT115(cVar26,CONCAT114((0 < sVar43) * (sVar43 < 0xff) *
330: SUB161(auVar128 >> 0x60,0) - (0xff < sVar43),auVar99));
331: auVar128 = auVar59 & auVar130;
332: uVar73 = SUB162(auVar130,0) >> 8;
333: uVar81 = SUB162(auVar130 >> 0x10,0) >> 8;
334: uVar82 = SUB162(auVar130 >> 0x20,0) >> 8;
335: uVar83 = SUB162(auVar130 >> 0x30,0) >> 8;
336: uVar84 = SUB162(auVar130 >> 0x40,0) >> 8;
337: uVar85 = SUB162(auVar130 >> 0x50,0) >> 8;
338: uVar86 = SUB162(auVar130 >> 0x60,0) >> 8;
339: uVar87 = SUB162(auVar130 >> 0x78,0);
340: auVar129 = auVar59 & auVar127;
341: uVar106 = SUB162(auVar127,0) >> 8;
342: uVar113 = SUB162(auVar127 >> 0x10,0) >> 8;
343: uVar115 = SUB162(auVar127 >> 0x20,0) >> 8;
344: uVar117 = SUB162(auVar127 >> 0x30,0) >> 8;
345: uVar119 = SUB162(auVar127 >> 0x40,0) >> 8;
346: uVar121 = SUB162(auVar127 >> 0x50,0) >> 8;
347: uVar123 = SUB162(auVar127 >> 0x60,0) >> 8;
348: uVar125 = SUB162(auVar127 >> 0x78,0);
349: cVar27 = (uVar81 != 0) * (uVar81 < 0xff) * SUB161(auVar130 >> 0x18,0) - (0xff < uVar81);
350: cVar28 = (uVar83 != 0) * (uVar83 < 0xff) * SUB161(auVar130 >> 0x38,0) - (0xff < uVar83);
351: uVar88 = CONCAT13(cVar28,CONCAT12((uVar82 != 0) * (uVar82 < 0xff) * SUB161(auVar130 >> 0x28,0) -
352: (0xff < uVar82),
353: CONCAT11(cVar27,(uVar73 != 0) * (uVar73 < 0xff) *
354: SUB161(auVar130 >> 8,0) - (0xff < uVar73))));
355: cVar29 = (uVar85 != 0) * (uVar85 < 0xff) * SUB161(auVar130 >> 0x58,0) - (0xff < uVar85);
356: uVar89 = CONCAT15(cVar29,CONCAT14((uVar84 != 0) * (uVar84 < 0xff) * SUB161(auVar130 >> 0x48,0) -
357: (0xff < uVar84),uVar88));
358: cVar30 = (uVar87 != 0) * (uVar87 < 0xff) * SUB161(auVar130 >> 0x78,0) - (0xff < uVar87);
359: uVar90 = CONCAT17(cVar30,CONCAT16((uVar86 != 0) * (uVar86 < 0xff) * SUB161(auVar130 >> 0x68,0) -
360: (0xff < uVar86),uVar89));
361: cVar31 = (uVar113 != 0) * (uVar113 < 0xff) * SUB161(auVar127 >> 0x18,0) - (0xff < uVar113);
362: Var91 = CONCAT19(cVar31,CONCAT18((uVar106 != 0) * (uVar106 < 0xff) * SUB161(auVar127 >> 8,0) -
363: (0xff < uVar106),uVar90));
364: cVar32 = (uVar117 != 0) * (uVar117 < 0xff) * SUB161(auVar127 >> 0x38,0) - (0xff < uVar117);
365: auVar92 = CONCAT111(cVar32,CONCAT110((uVar115 != 0) * (uVar115 < 0xff) *
366: SUB161(auVar127 >> 0x28,0) - (0xff < uVar115),Var91));
367: cVar33 = (uVar121 != 0) * (uVar121 < 0xff) * SUB161(auVar127 >> 0x58,0) - (0xff < uVar121);
368: auVar93 = CONCAT113(cVar33,CONCAT112((uVar119 != 0) * (uVar119 < 0xff) *
369: SUB161(auVar127 >> 0x48,0) - (0xff < uVar119),auVar92));
370: cVar34 = (uVar125 != 0) * (uVar125 < 0xff) * SUB161(auVar127 >> 0x78,0) - (0xff < uVar125);
371: auVar127 = CONCAT115(cVar34,CONCAT114((uVar123 != 0) * (uVar123 < 0xff) *
372: SUB161(auVar127 >> 0x68,0) - (0xff < uVar123),auVar93));
373: sVar43 = SUB162(auVar128,0);
374: sVar44 = SUB162(auVar128 >> 0x10,0);
375: cVar35 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x10,0) - (0xff < sVar44);
376: sVar44 = SUB162(auVar128 >> 0x20,0);
377: sVar45 = SUB162(auVar128 >> 0x30,0);
378: cVar36 = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar128 >> 0x30,0) - (0xff < sVar45);
379: uVar107 = CONCAT13(cVar36,CONCAT12((0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x20,0) -
380: (0xff < sVar44),
381: CONCAT11(cVar35,(0 < sVar43) * (sVar43 < 0xff) *
382: SUB161(auVar128,0) - (0xff < sVar43))));
383: sVar43 = SUB162(auVar128 >> 0x40,0);
384: sVar44 = SUB162(auVar128 >> 0x50,0);
385: cVar37 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x50,0) - (0xff < sVar44);
386: uVar108 = CONCAT15(cVar37,CONCAT14((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar128 >> 0x40,0) -
387: (0xff < sVar43),uVar107));
388: sVar43 = SUB162(auVar128 >> 0x60,0);
389: sVar44 = SUB162(auVar128 >> 0x70,0);
390: cVar38 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x70,0) - (0xff < sVar44);
391: uVar109 = CONCAT17(cVar38,CONCAT16((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar128 >> 0x60,0) -
392: (0xff < sVar43),uVar108));
393: sVar43 = SUB162(auVar129,0);
394: sVar44 = SUB162(auVar129 >> 0x10,0);
395: cVar39 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar129 >> 0x10,0) - (0xff < sVar44);
396: Var110 = CONCAT19(cVar39,CONCAT18((0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar129,0) -
397: (0xff < sVar43),uVar109));
398: sVar43 = SUB162(auVar129 >> 0x20,0);
399: sVar44 = SUB162(auVar129 >> 0x30,0);
400: cVar40 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar129 >> 0x30,0) - (0xff < sVar44);
401: auVar111 = CONCAT111(cVar40,CONCAT110((0 < sVar43) * (sVar43 < 0xff) *
402: SUB161(auVar129 >> 0x20,0) - (0xff < sVar43),Var110));
403: sVar43 = SUB162(auVar129 >> 0x40,0);
404: sVar44 = SUB162(auVar129 >> 0x50,0);
405: cVar41 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar129 >> 0x50,0) - (0xff < sVar44);
406: auVar112 = CONCAT113(cVar41,CONCAT112((0 < sVar43) * (sVar43 < 0xff) *
407: SUB161(auVar129 >> 0x40,0) - (0xff < sVar43),auVar111));
408: sVar43 = SUB162(auVar129 >> 0x60,0);
409: sVar44 = SUB162(auVar129 >> 0x70,0);
410: cVar42 = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar129 >> 0x70,0) - (0xff < sVar44);
411: auVar130 = CONCAT115(cVar42,CONCAT114((0 < sVar43) * (sVar43 < 0xff) *
412: SUB161(auVar129 >> 0x60,0) - (0xff < sVar43),auVar112));
413: auVar128 = auVar59 & auVar100;
414: uVar123 = (ushort)((uint)uVar94 >> 0x18);
415: uVar125 = (ushort)((uint6)uVar95 >> 0x28);
416: uVar101 = (ushort)((ulong)uVar96 >> 0x38);
417: uVar102 = (ushort)((unkuint10)Var97 >> 0x48);
418: uVar103 = SUB122(auVar98 >> 0x58,0);
419: uVar104 = SUB142(auVar99 >> 0x68,0);
420: uVar105 = SUB162(auVar100 >> 0x78,0);
421: auVar100 = auVar59 & auVar130;
422: uVar114 = (ushort)((uint)uVar107 >> 0x18);
423: uVar116 = (ushort)((uint6)uVar108 >> 0x28);
424: uVar118 = (ushort)((ulong)uVar109 >> 0x38);
425: uVar120 = (ushort)((unkuint10)Var110 >> 0x48);
426: uVar122 = SUB122(auVar111 >> 0x58,0);
427: uVar124 = SUB142(auVar112 >> 0x68,0);
428: uVar126 = SUB162(auVar130 >> 0x78,0);
429: sVar43 = SUB162(auVar128,0);
430: sVar44 = SUB162(auVar128 >> 0x10,0);
431: sVar45 = SUB162(auVar128 >> 0x20,0);
432: sVar46 = SUB162(auVar128 >> 0x30,0);
433: sVar47 = SUB162(auVar128 >> 0x40,0);
434: sVar48 = SUB162(auVar128 >> 0x50,0);
435: sVar49 = SUB162(auVar128 >> 0x60,0);
436: sVar50 = SUB162(auVar128 >> 0x70,0);
437: sVar51 = SUB162(auVar100,0);
438: sVar52 = SUB162(auVar100 >> 0x10,0);
439: sVar53 = SUB162(auVar100 >> 0x20,0);
440: sVar54 = SUB162(auVar100 >> 0x30,0);
441: sVar55 = SUB162(auVar100 >> 0x40,0);
442: sVar56 = SUB162(auVar100 >> 0x50,0);
443: sVar57 = SUB162(auVar100 >> 0x60,0);
444: sVar58 = SUB162(auVar100 >> 0x70,0);
445: pcVar4 = puVar60 + lVar69;
446: *pcVar4 = (0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar128,0) - (0xff < sVar43);
447: pcVar4[1] = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar128 >> 0x10,0) - (0xff < sVar44);
448: pcVar4[2] = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar128 >> 0x20,0) - (0xff < sVar45);
449: pcVar4[3] = (0 < sVar46) * (sVar46 < 0xff) * SUB161(auVar128 >> 0x30,0) - (0xff < sVar46);
450: pcVar4[4] = (0 < sVar47) * (sVar47 < 0xff) * SUB161(auVar128 >> 0x40,0) - (0xff < sVar47);
451: pcVar4[5] = (0 < sVar48) * (sVar48 < 0xff) * SUB161(auVar128 >> 0x50,0) - (0xff < sVar48);
452: pcVar4[6] = (0 < sVar49) * (sVar49 < 0xff) * SUB161(auVar128 >> 0x60,0) - (0xff < sVar49);
453: pcVar4[7] = (0 < sVar50) * (sVar50 < 0xff) * SUB161(auVar128 >> 0x70,0) - (0xff < sVar50);
454: pcVar4[8] = (0 < sVar51) * (sVar51 < 0xff) * SUB161(auVar100,0) - (0xff < sVar51);
455: pcVar4[9] = (0 < sVar52) * (sVar52 < 0xff) * SUB161(auVar100 >> 0x10,0) - (0xff < sVar52);
456: pcVar4[10] = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar100 >> 0x20,0) - (0xff < sVar53);
457: pcVar4[0xb] = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar100 >> 0x30,0) - (0xff < sVar54);
458: pcVar4[0xc] = (0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar100 >> 0x40,0) - (0xff < sVar55);
459: pcVar4[0xd] = (0 < sVar56) * (sVar56 < 0xff) * SUB161(auVar100 >> 0x50,0) - (0xff < sVar56);
460: pcVar4[0xe] = (0 < sVar57) * (sVar57 < 0xff) * SUB161(auVar100 >> 0x60,0) - (0xff < sVar57);
461: pcVar4[0xf] = (0 < sVar58) * (sVar58 < 0xff) * SUB161(auVar100 >> 0x70,0) - (0xff < sVar58);
462: auVar130 = auVar59 & auVar127;
463: uVar87 = (ushort)((uint)uVar88 >> 0x18);
464: uVar106 = (ushort)((uint6)uVar89 >> 0x28);
465: uVar113 = (ushort)((ulong)uVar90 >> 0x38);
466: uVar115 = (ushort)((unkuint10)Var91 >> 0x48);
467: uVar117 = SUB122(auVar92 >> 0x58,0);
468: uVar119 = SUB142(auVar93 >> 0x68,0);
469: uVar121 = SUB162(auVar127 >> 0x78,0);
470: auVar127 = auVar59 & auVar80;
471: uVar73 = (ushort)((uint)uVar74 >> 0x18);
472: uVar81 = (ushort)((uint6)uVar75 >> 0x28);
473: uVar82 = (ushort)((ulong)uVar76 >> 0x38);
474: uVar83 = (ushort)((unkuint10)Var77 >> 0x48);
475: uVar84 = SUB122(auVar78 >> 0x58,0);
476: uVar85 = SUB142(auVar79 >> 0x68,0);
477: uVar86 = SUB162(auVar80 >> 0x78,0);
478: sVar43 = SUB162(auVar127,0);
479: sVar44 = SUB162(auVar127 >> 0x10,0);
480: sVar45 = SUB162(auVar127 >> 0x20,0);
481: sVar46 = SUB162(auVar127 >> 0x30,0);
482: sVar47 = SUB162(auVar127 >> 0x40,0);
483: sVar48 = SUB162(auVar127 >> 0x50,0);
484: sVar49 = SUB162(auVar127 >> 0x60,0);
485: sVar50 = SUB162(auVar127 >> 0x70,0);
486: sVar51 = SUB162(auVar130,0);
487: sVar52 = SUB162(auVar130 >> 0x10,0);
488: sVar53 = SUB162(auVar130 >> 0x20,0);
489: sVar54 = SUB162(auVar130 >> 0x30,0);
490: sVar55 = SUB162(auVar130 >> 0x40,0);
491: sVar56 = SUB162(auVar130 >> 0x50,0);
492: sVar57 = SUB162(auVar130 >> 0x60,0);
493: sVar58 = SUB162(auVar130 >> 0x70,0);
494: pcVar4 = puVar63 + lVar69;
495: *pcVar4 = (0 < sVar43) * (sVar43 < 0xff) * SUB161(auVar127,0) - (0xff < sVar43);
496: pcVar4[1] = (0 < sVar44) * (sVar44 < 0xff) * SUB161(auVar127 >> 0x10,0) - (0xff < sVar44);
497: pcVar4[2] = (0 < sVar45) * (sVar45 < 0xff) * SUB161(auVar127 >> 0x20,0) - (0xff < sVar45);
498: pcVar4[3] = (0 < sVar46) * (sVar46 < 0xff) * SUB161(auVar127 >> 0x30,0) - (0xff < sVar46);
499: pcVar4[4] = (0 < sVar47) * (sVar47 < 0xff) * SUB161(auVar127 >> 0x40,0) - (0xff < sVar47);
500: pcVar4[5] = (0 < sVar48) * (sVar48 < 0xff) * SUB161(auVar127 >> 0x50,0) - (0xff < sVar48);
501: pcVar4[6] = (0 < sVar49) * (sVar49 < 0xff) * SUB161(auVar127 >> 0x60,0) - (0xff < sVar49);
502: pcVar4[7] = (0 < sVar50) * (sVar50 < 0xff) * SUB161(auVar127 >> 0x70,0) - (0xff < sVar50);
503: pcVar4[8] = (0 < sVar51) * (sVar51 < 0xff) * SUB161(auVar130,0) - (0xff < sVar51);
504: pcVar4[9] = (0 < sVar52) * (sVar52 < 0xff) * SUB161(auVar130 >> 0x10,0) - (0xff < sVar52);
505: pcVar4[10] = (0 < sVar53) * (sVar53 < 0xff) * SUB161(auVar130 >> 0x20,0) - (0xff < sVar53);
506: pcVar4[0xb] = (0 < sVar54) * (sVar54 < 0xff) * SUB161(auVar130 >> 0x30,0) - (0xff < sVar54);
507: pcVar4[0xc] = (0 < sVar55) * (sVar55 < 0xff) * SUB161(auVar130 >> 0x40,0) - (0xff < sVar55);
508: pcVar4[0xd] = (0 < sVar56) * (sVar56 < 0xff) * SUB161(auVar130 >> 0x50,0) - (0xff < sVar56);
509: pcVar4[0xe] = (0 < sVar57) * (sVar57 < 0xff) * SUB161(auVar130 >> 0x60,0) - (0xff < sVar57);
510: pcVar4[0xf] = (0 < sVar58) * (sVar58 < 0xff) * SUB161(auVar130 >> 0x70,0) - (0xff < sVar58);
511: pcVar4 = puVar61 + lVar69;
512: *pcVar4 = (cVar19 != '\0') * (cVar19 != -1) * cVar19;
513: pcVar4[1] = (uVar123 != 0) * (uVar123 < 0xff) * cVar20 - (0xff < uVar123);
514: pcVar4[2] = (uVar125 != 0) * (uVar125 < 0xff) * cVar21 - (0xff < uVar125);
515: pcVar4[3] = (uVar101 != 0) * (uVar101 < 0xff) * cVar22 - (0xff < uVar101);
516: pcVar4[4] = (uVar102 != 0) * (uVar102 < 0xff) * cVar23 - (0xff < uVar102);
517: pcVar4[5] = (uVar103 != 0) * (uVar103 < 0xff) * cVar24 - (0xff < uVar103);
518: pcVar4[6] = (uVar104 != 0) * (uVar104 < 0xff) * cVar25 - (0xff < uVar104);
519: pcVar4[7] = (uVar105 != 0) * (uVar105 < 0xff) * cVar26 - (0xff < uVar105);
520: pcVar4[8] = (cVar35 != '\0') * (cVar35 != -1) * cVar35;
521: pcVar4[9] = (uVar114 != 0) * (uVar114 < 0xff) * cVar36 - (0xff < uVar114);
522: pcVar4[10] = (uVar116 != 0) * (uVar116 < 0xff) * cVar37 - (0xff < uVar116);
523: pcVar4[0xb] = (uVar118 != 0) * (uVar118 < 0xff) * cVar38 - (0xff < uVar118);
524: pcVar4[0xc] = (uVar120 != 0) * (uVar120 < 0xff) * cVar39 - (0xff < uVar120);
525: pcVar4[0xd] = (uVar122 != 0) * (uVar122 < 0xff) * cVar40 - (0xff < uVar122);
526: pcVar4[0xe] = (uVar124 != 0) * (uVar124 < 0xff) * cVar41 - (0xff < uVar124);
527: pcVar4[0xf] = (uVar126 != 0) * (uVar126 < 0xff) * cVar42 - (0xff < uVar126);
528: pcVar4 = puVar8 + lVar69;
529: *pcVar4 = (cVar11 != '\0') * (cVar11 != -1) * cVar11;
530: pcVar4[1] = (uVar73 != 0) * (uVar73 < 0xff) * cVar12 - (0xff < uVar73);
531: pcVar4[2] = (uVar81 != 0) * (uVar81 < 0xff) * cVar13 - (0xff < uVar81);
532: pcVar4[3] = (uVar82 != 0) * (uVar82 < 0xff) * cVar14 - (0xff < uVar82);
533: pcVar4[4] = (uVar83 != 0) * (uVar83 < 0xff) * cVar15 - (0xff < uVar83);
534: pcVar4[5] = (uVar84 != 0) * (uVar84 < 0xff) * cVar16 - (0xff < uVar84);
535: pcVar4[6] = (uVar85 != 0) * (uVar85 < 0xff) * cVar17 - (0xff < uVar85);
536: pcVar4[7] = (uVar86 != 0) * (uVar86 < 0xff) * cVar18 - (0xff < uVar86);
537: pcVar4[8] = (cVar27 != '\0') * (cVar27 != -1) * cVar27;
538: pcVar4[9] = (uVar87 != 0) * (uVar87 < 0xff) * cVar28 - (0xff < uVar87);
539: pcVar4[10] = (uVar106 != 0) * (uVar106 < 0xff) * cVar29 - (0xff < uVar106);
540: pcVar4[0xb] = (uVar113 != 0) * (uVar113 < 0xff) * cVar30 - (0xff < uVar113);
541: pcVar4[0xc] = (uVar115 != 0) * (uVar115 < 0xff) * cVar31 - (0xff < uVar115);
542: pcVar4[0xd] = (uVar117 != 0) * (uVar117 < 0xff) * cVar32 - (0xff < uVar117);
543: pcVar4[0xe] = (uVar119 != 0) * (uVar119 < 0xff) * cVar33 - (0xff < uVar119);
544: pcVar4[0xf] = (uVar121 != 0) * (uVar121 < 0xff) * cVar34 - (0xff < uVar121);
545: lVar69 = lVar69 + 0x10;
546: } while (uVar68 < uVar7 >> 4);
547: puVar62 = puVar62 + (ulong)uVar72 * 4;
548: uVar68 = uVar72;
549: if (uVar7 != uVar72) {
550: LAB_00106b4b:
551: uVar66 = (ulong)uVar68;
552: puVar60[uVar66] = *puVar62;
553: puVar63[uVar66] = puVar62[1];
554: puVar61[uVar66] = puVar62[2];
555: puVar8[uVar66] = puVar62[3];
556: uVar66 = (ulong)(uVar68 + 1);
557: if (uVar68 + 1 < uVar7) {
558: puVar60[uVar66] = puVar62[4];
559: puVar63[uVar66] = puVar62[5];
560: puVar61[uVar66] = puVar62[6];
561: puVar8[uVar66] = puVar62[7];
562: uVar66 = (ulong)(uVar68 + 2);
563: if (uVar68 + 2 < uVar7) {
564: puVar60[uVar66] = puVar62[8];
565: puVar63[uVar66] = puVar62[9];
566: puVar61[uVar66] = puVar62[10];
567: puVar8[uVar66] = puVar62[0xb];
568: uVar66 = (ulong)(uVar68 + 3);
569: if (uVar68 + 3 < uVar7) {
570: puVar60[uVar66] = puVar62[0xc];
571: puVar63[uVar66] = puVar62[0xd];
572: puVar61[uVar66] = puVar62[0xe];
573: puVar8[uVar66] = puVar62[0xf];
574: uVar66 = (ulong)(uVar68 + 4);
575: if (uVar68 + 4 < uVar7) {
576: puVar60[uVar66] = puVar62[0x10];
577: puVar63[uVar66] = puVar62[0x11];
578: puVar61[uVar66] = puVar62[0x12];
579: puVar8[uVar66] = puVar62[0x13];
580: uVar66 = (ulong)(uVar68 + 5);
581: if (uVar68 + 5 < uVar7) {
582: puVar60[uVar66] = puVar62[0x14];
583: puVar63[uVar66] = puVar62[0x15];
584: puVar61[uVar66] = puVar62[0x16];
585: puVar8[uVar66] = puVar62[0x17];
586: uVar66 = (ulong)(uVar68 + 6);
587: if (uVar68 + 6 < uVar7) {
588: puVar60[uVar66] = puVar62[0x18];
589: puVar63[uVar66] = puVar62[0x19];
590: puVar61[uVar66] = puVar62[0x1a];
591: puVar8[uVar66] = puVar62[0x1b];
592: uVar66 = (ulong)(uVar68 + 7);
593: if (uVar68 + 7 < uVar7) {
594: puVar60[uVar66] = puVar62[0x1c];
595: puVar63[uVar66] = puVar62[0x1d];
596: puVar61[uVar66] = puVar62[0x1e];
597: puVar8[uVar66] = puVar62[0x1f];
598: uVar66 = (ulong)(uVar68 + 8);
599: if (uVar68 + 8 < uVar7) {
600: puVar60[uVar66] = puVar62[0x20];
601: puVar63[uVar66] = puVar62[0x21];
602: puVar61[uVar66] = puVar62[0x22];
603: puVar8[uVar66] = puVar62[0x23];
604: uVar66 = (ulong)(uVar68 + 9);
605: if (uVar68 + 9 < uVar7) {
606: puVar60[uVar66] = puVar62[0x24];
607: puVar63[uVar66] = puVar62[0x25];
608: puVar61[uVar66] = puVar62[0x26];
609: puVar8[uVar66] = puVar62[0x27];
610: uVar66 = (ulong)(uVar68 + 10);
611: if (uVar68 + 10 < uVar7) {
612: puVar60[uVar66] = puVar62[0x28];
613: puVar63[uVar66] = puVar62[0x29];
614: puVar61[uVar66] = puVar62[0x2a];
615: puVar8[uVar66] = puVar62[0x2b];
616: uVar66 = (ulong)(uVar68 + 0xb);
617: if (uVar68 + 0xb < uVar7) {
618: puVar60[uVar66] = puVar62[0x2c];
619: puVar63[uVar66] = puVar62[0x2d];
620: puVar61[uVar66] = puVar62[0x2e];
621: puVar8[uVar66] = puVar62[0x2f];
622: uVar66 = (ulong)(uVar68 + 0xc);
623: if (uVar68 + 0xc < uVar7) {
624: puVar60[uVar66] = puVar62[0x30];
625: puVar63[uVar66] = puVar62[0x31];
626: puVar61[uVar66] = puVar62[0x32];
627: puVar8[uVar66] = puVar62[0x33];
628: uVar66 = (ulong)(uVar68 + 0xd);
629: if (uVar68 + 0xd < uVar7) {
630: uVar67 = (ulong)(uVar68 + 0xe);
631: puVar60[uVar66] = puVar62[0x34];
632: puVar63[uVar66] = puVar62[0x35];
633: puVar61[uVar66] = puVar62[0x36];
634: puVar8[uVar66] = puVar62[0x37];
635: if (uVar68 + 0xe < uVar7) {
636: puVar60[uVar67] = puVar62[0x38];
637: puVar63[uVar67] = puVar62[0x39];
638: puVar61[uVar67] = puVar62[0x3a];
639: puVar8[uVar67] = puVar62[0x3b];
640: }
641: }
642: }
643: }
644: }
645: }
646: }
647: }
648: }
649: }
650: }
651: }
652: }
653: }
654: }
655: goto LAB_001068f0;
656: }
657: 

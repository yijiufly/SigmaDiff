1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0012e0b0(long param_1,long *param_2,uint param_3,undefined (**param_4) [16],int param_5)
5: 
6: {
7: byte bVar1;
8: char cVar2;
9: char cVar12;
10: short sVar23;
11: short sVar24;
12: undefined *puVar25;
13: undefined auVar26 [16];
14: undefined auVar27 [16];
15: undefined auVar28 [16];
16: undefined (*pauVar29) [16];
17: undefined (*pauVar30) [16];
18: undefined (*pauVar31) [16];
19: undefined (*pauVar32) [16];
20: uint uVar33;
21: byte *pbVar34;
22: uint uVar35;
23: ulong uVar36;
24: uint *puVar37;
25: uint uVar38;
26: ushort uVar39;
27: undefined2 uVar40;
28: ushort uVar54;
29: uint uVar43;
30: uint uVar44;
31: ushort uVar55;
32: ushort uVar56;
33: ushort uVar57;
34: ushort uVar58;
35: ushort uVar59;
36: ushort uVar60;
37: undefined2 uVar61;
38: uint uVar64;
39: uint uVar65;
40: undefined auVar74 [16];
41: ushort uVar75;
42: ushort uVar76;
43: ushort uVar77;
44: ushort uVar79;
45: uint uVar78;
46: ushort uVar80;
47: ushort uVar82;
48: uint uVar81;
49: ushort uVar83;
50: ushort uVar85;
51: uint uVar84;
52: uint uVar86;
53: undefined auVar88 [16];
54: undefined auVar89 [13];
55: unkuint10 Var90;
56: unkuint10 Var91;
57: uint uVar92;
58: undefined auVar95 [16];
59: undefined auVar97 [16];
60: uint uVar98;
61: unkuint10 Var99;
62: uint uVar100;
63: uint uVar101;
64: uint uVar102;
65: char cVar3;
66: char cVar4;
67: char cVar5;
68: char cVar6;
69: char cVar7;
70: char cVar8;
71: char cVar9;
72: char cVar10;
73: byte bVar11;
74: char cVar13;
75: char cVar14;
76: char cVar15;
77: byte bVar16;
78: char cVar17;
79: char cVar18;
80: char cVar19;
81: char cVar20;
82: char cVar21;
83: byte bVar22;
84: uint3 uVar41;
85: undefined4 uVar42;
86: uint5 uVar45;
87: uint5 uVar46;
88: undefined6 uVar47;
89: uint7 uVar48;
90: undefined8 uVar49;
91: unkbyte10 Var50;
92: undefined auVar51 [12];
93: undefined auVar52 [12];
94: undefined auVar53 [14];
95: uint3 uVar62;
96: undefined4 uVar63;
97: uint5 uVar66;
98: undefined6 uVar67;
99: uint7 uVar68;
100: undefined8 uVar69;
101: ulong uVar70;
102: unkbyte10 Var71;
103: undefined auVar72 [12];
104: undefined auVar73 [14];
105: undefined auVar87 [14];
106: undefined auVar93 [12];
107: undefined auVar94 [14];
108: undefined auVar96 [13];
109: 
110: auVar28 = _DAT_0018d0a0;
111: auVar27 = _DAT_0018d090;
112: auVar26 = _DAT_0016c610;
113: param_5 = param_5 + -1;
114: uVar38 = *(uint *)(param_1 + 0x88);
115: while (-1 < param_5) {
116: pauVar29 = *param_4;
117: pauVar32 = *(undefined (**) [16])(*param_2 + (ulong)param_3 * 8);
118: pauVar31 = pauVar29;
119: if (((ulong)pauVar29 & 3) != 0) {
120: bVar1 = (*pauVar32)[0];
121: pauVar31 = (undefined (*) [16])(*pauVar29 + 2);
122: uVar38 = uVar38 - 1;
123: pauVar32 = (undefined (*) [16])(*pauVar32 + 1);
124: *(ushort *)*pauVar29 =
125: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
126: }
127: uVar35 = uVar38 >> 1;
128: if (uVar35 != 0) {
129: if ((pauVar32 < (undefined (*) [16])(*pauVar31 + (ulong)uVar35 * 4) &&
130: pauVar31 < (undefined (*) [16])(*pauVar32 + (ulong)uVar35 * 2)) || (uVar35 < 0x10)) {
131: uVar36 = (ulong)(uVar35 - 1);
132: pauVar29 = pauVar32;
133: pauVar30 = pauVar31;
134: do {
135: bVar1 = (*pauVar29)[0];
136: puVar25 = *pauVar30;
137: bVar11 = (*pauVar29)[1];
138: *(uint *)*pauVar30 =
139: ((uint)bVar11 * 8 & 0x7e0 | (bVar11 & 0xf8) << 8 | (uint)(bVar11 >> 3)) << 0x10 |
140: (uint)bVar1 * 8 & 0x7e0 | (bVar1 & 0xf8) << 8 | (uint)(bVar1 >> 3);
141: pauVar29 = (undefined (*) [16])(*pauVar29 + 2);
142: pauVar30 = (undefined (*) [16])(puVar25 + 4);
143: } while ((undefined (*) [16])(*pauVar31 + uVar36 * 4 + 4) !=
144: (undefined (*) [16])(puVar25 + 4));
145: }
146: else {
147: uVar33 = 0;
148: pauVar29 = pauVar31;
149: pauVar30 = pauVar32;
150: do {
151: auVar97 = *pauVar30;
152: uVar33 = uVar33 + 1;
153: auVar95 = pauVar30[1];
154: auVar74 = auVar26 & auVar97;
155: uVar39 = SUB162(auVar97,0) >> 8;
156: uVar54 = SUB162(auVar97 >> 0x10,0) >> 8;
157: uVar55 = SUB162(auVar97 >> 0x20,0) >> 8;
158: uVar56 = SUB162(auVar97 >> 0x30,0) >> 8;
159: uVar57 = SUB162(auVar97 >> 0x40,0) >> 8;
160: uVar58 = SUB162(auVar97 >> 0x50,0) >> 8;
161: uVar59 = SUB162(auVar97 >> 0x60,0) >> 8;
162: uVar60 = SUB162(auVar97 >> 0x78,0);
163: pauVar30 = pauVar30[2];
164: auVar88 = auVar26 & auVar95;
165: uVar75 = SUB162(auVar95,0) >> 8;
166: uVar76 = SUB162(auVar95 >> 0x10,0) >> 8;
167: uVar77 = SUB162(auVar95 >> 0x20,0) >> 8;
168: uVar79 = SUB162(auVar95 >> 0x30,0) >> 8;
169: uVar80 = SUB162(auVar95 >> 0x40,0) >> 8;
170: uVar82 = SUB162(auVar95 >> 0x50,0) >> 8;
171: uVar83 = SUB162(auVar95 >> 0x60,0) >> 8;
172: uVar85 = SUB162(auVar95 >> 0x78,0);
173: uVar40 = CONCAT11((uVar54 != 0) * (uVar54 < 0xff) * SUB161(auVar97 >> 0x18,0) -
174: (0xff < uVar54),
175: (uVar39 != 0) * (uVar39 < 0xff) * SUB161(auVar97 >> 8,0) -
176: (0xff < uVar39));
177: uVar41 = CONCAT12((uVar55 != 0) * (uVar55 < 0xff) * SUB161(auVar97 >> 0x28,0) -
178: (0xff < uVar55),uVar40);
179: uVar42 = CONCAT13((uVar56 != 0) * (uVar56 < 0xff) * SUB161(auVar97 >> 0x38,0) -
180: (0xff < uVar56),uVar41);
181: cVar2 = (uVar57 != 0) * (uVar57 < 0xff) * SUB161(auVar97 >> 0x48,0) - (0xff < uVar57);
182: uVar45 = CONCAT14(cVar2,uVar42);
183: cVar3 = (uVar58 != 0) * (uVar58 < 0xff) * SUB161(auVar97 >> 0x58,0) - (0xff < uVar58);
184: uVar47 = CONCAT15(cVar3,uVar45);
185: cVar4 = (uVar59 != 0) * (uVar59 < 0xff) * SUB161(auVar97 >> 0x68,0) - (0xff < uVar59);
186: uVar48 = CONCAT16(cVar4,uVar47);
187: cVar5 = (uVar60 != 0) * (uVar60 < 0xff) * SUB161(auVar97 >> 0x78,0) - (0xff < uVar60);
188: uVar49 = CONCAT17(cVar5,uVar48);
189: bVar1 = (uVar75 != 0) * (uVar75 < 0xff) * SUB161(auVar95 >> 8,0) - (0xff < uVar75);
190: cVar6 = (uVar76 != 0) * (uVar76 < 0xff) * SUB161(auVar95 >> 0x18,0) - (0xff < uVar76);
191: Var50 = CONCAT19(cVar6,CONCAT18(bVar1,uVar49));
192: cVar7 = (uVar77 != 0) * (uVar77 < 0xff) * SUB161(auVar95 >> 0x28,0) - (0xff < uVar77);
193: cVar8 = (uVar79 != 0) * (uVar79 < 0xff) * SUB161(auVar95 >> 0x38,0) - (0xff < uVar79);
194: auVar52 = CONCAT111(cVar8,CONCAT110(cVar7,Var50));
195: cVar9 = (uVar80 != 0) * (uVar80 < 0xff) * SUB161(auVar95 >> 0x48,0) - (0xff < uVar80);
196: cVar10 = (uVar82 != 0) * (uVar82 < 0xff) * SUB161(auVar95 >> 0x58,0) - (0xff < uVar82);
197: bVar11 = (uVar85 != 0) * (uVar85 < 0xff) * SUB161(auVar95 >> 0x78,0) - (0xff < uVar85);
198: sVar23 = SUB162(auVar74,0);
199: sVar24 = SUB162(auVar74 >> 0x10,0);
200: uVar61 = CONCAT11((0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar74 >> 0x10,0) -
201: (0xff < sVar24),
202: (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74,0) - (0xff < sVar23));
203: sVar23 = SUB162(auVar74 >> 0x20,0);
204: uVar62 = CONCAT12((0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74 >> 0x20,0) -
205: (0xff < sVar23),uVar61);
206: sVar23 = SUB162(auVar74 >> 0x30,0);
207: uVar63 = CONCAT13((0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74 >> 0x30,0) -
208: (0xff < sVar23),uVar62);
209: sVar23 = SUB162(auVar74 >> 0x40,0);
210: cVar12 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74 >> 0x40,0) - (0xff < sVar23);
211: uVar66 = CONCAT14(cVar12,uVar63);
212: sVar23 = SUB162(auVar74 >> 0x50,0);
213: cVar13 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74 >> 0x50,0) - (0xff < sVar23);
214: uVar67 = CONCAT15(cVar13,uVar66);
215: sVar23 = SUB162(auVar74 >> 0x60,0);
216: cVar14 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74 >> 0x60,0) - (0xff < sVar23);
217: uVar68 = CONCAT16(cVar14,uVar67);
218: sVar23 = SUB162(auVar74 >> 0x70,0);
219: cVar15 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar74 >> 0x70,0) - (0xff < sVar23);
220: uVar69 = CONCAT17(cVar15,uVar68);
221: sVar23 = SUB162(auVar88,0);
222: bVar16 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88,0) - (0xff < sVar23);
223: sVar23 = SUB162(auVar88 >> 0x10,0);
224: cVar17 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88 >> 0x10,0) - (0xff < sVar23);
225: Var71 = CONCAT19(cVar17,CONCAT18(bVar16,uVar69));
226: sVar23 = SUB162(auVar88 >> 0x20,0);
227: cVar18 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88 >> 0x20,0) - (0xff < sVar23);
228: sVar23 = SUB162(auVar88 >> 0x30,0);
229: cVar19 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88 >> 0x30,0) - (0xff < sVar23);
230: auVar72 = CONCAT111(cVar19,CONCAT110(cVar18,Var71));
231: sVar23 = SUB162(auVar88 >> 0x40,0);
232: cVar20 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88 >> 0x40,0) - (0xff < sVar23);
233: sVar23 = SUB162(auVar88 >> 0x50,0);
234: cVar21 = (0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88 >> 0x50,0) - (0xff < sVar23);
235: sVar23 = SUB162(auVar88 >> 0x60,0);
236: sVar24 = SUB162(auVar88 >> 0x70,0);
237: bVar22 = (0 < sVar24) * (sVar24 < 0xff) * SUB161(auVar88 >> 0x70,0) - (0xff < sVar24);
238: uVar43 = (uint)CONCAT12(cVar6,(ushort)bVar1);
239: uVar46 = CONCAT14(cVar7,uVar43);
240: uVar36 = (ulong)CONCAT16(cVar8,(uint6)uVar46);
241: auVar51 = ZEXT1112(CONCAT110(cVar10,(unkuint10)CONCAT18(cVar9,uVar36)));
242: auVar53 = ZEXT1314(CONCAT112((uVar83 != 0) * (uVar83 < 0xff) * SUB161(auVar95 >> 0x68,0) -
243: (0xff < uVar83),auVar51));
244: auVar89 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
245: )SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
246: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
247: (SUB152(CONCAT114(cVar5,CONCAT113(cVar10,CONCAT112
248: (cVar9,auVar52))) >> 0x68,0),
249: CONCAT112(cVar4,auVar52)) >> 0x60,0),auVar52) >>
250: 0x58,0),CONCAT110(cVar3,Var50)) >> 0x50,0),Var50)
251: >> 0x48,0),CONCAT18(cVar2,uVar49)) >> 0x40,0),
252: uVar49) >> 0x38,0) &
253: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
254: ,0) &
255: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
256: ,0) &
257: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
258: ,0) &
259: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
260: ,0),(uVar48 >> 0x18) << 0x30) >> 0x30,0),
261: uVar47) >> 0x28,0) &
262: SUB1611((undefined  [16])0xffff00ffffffffff >>
263: 0x28,0),(uVar45 >> 0x10) << 0x20) >> 0x20,
264: 0),uVar42) >> 0x18,0) &
265: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
266: auVar97 = CONCAT142(SUB1614(CONCAT133(auVar89,(uVar41 >> 8) << 0x10) >> 0x10,0),uVar40) &
267: (undefined  [16])0xffffffffffff00ff;
268: uVar64 = (uint)CONCAT12(cVar17,(ushort)bVar16);
269: uVar45 = CONCAT14(cVar18,uVar64);
270: uVar70 = (ulong)CONCAT16(cVar19,(uint6)uVar45);
271: auVar52 = ZEXT1112(CONCAT110(cVar21,(unkuint10)CONCAT18(cVar20,uVar70)));
272: auVar73 = ZEXT1314(CONCAT112((0 < sVar23) * (sVar23 < 0xff) * SUB161(auVar88 >> 0x60,0) -
273: (0xff < sVar23),auVar52));
274: auVar96 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
275: )SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
276: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
277: (SUB152(CONCAT114(cVar15,CONCAT113(cVar21,
278: CONCAT112(cVar20,auVar72))) >> 0x68,0),
279: CONCAT112(cVar14,auVar72)) >> 0x60,0),auVar72) >>
280: 0x58,0),CONCAT110(cVar13,Var71)) >> 0x50,0),Var71)
281: >> 0x48,0),CONCAT18(cVar12,uVar69)) >> 0x40,0),
282: uVar69) >> 0x38,0) &
283: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
284: ,0) &
285: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
286: ,0) &
287: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
288: ,0) &
289: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
290: ,0),(uVar68 >> 0x18) << 0x30) >> 0x30,0),
291: uVar67) >> 0x28,0) &
292: SUB1611((undefined  [16])0xffff00ffffffffff >>
293: 0x28,0),(uVar66 >> 0x10) << 0x20) >> 0x20,
294: 0),uVar63) >> 0x18,0) &
295: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
296: auVar95 = CONCAT142(SUB1614(CONCAT133(auVar96,(uVar62 >> 8) << 0x10) >> 0x10,0),uVar61) &
297: (undefined  [16])0xffffffffffff00ff;
298: uVar57 = SUB132(auVar89 >> 0x28,0);
299: uVar86 = (uint)uVar57;
300: uVar58 = SUB132(auVar89 >> 0x48,0);
301: auVar72 = ZEXT1012(CONCAT28(uVar58,(ulong)CONCAT24(SUB132(auVar89 >> 0x38,0),uVar86)));
302: uVar59 = SUB132(auVar89 >> 0x58,0);
303: auVar87 = CONCAT212(uVar59,auVar72);
304: Var90 = (unkuint10)
305: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar97 >> 0x30,0),
306: SUB1612(auVar97,0)) >> 0x50,0),
307: CONCAT28(SUB162(auVar97 >> 0x20,0),
308: SUB168(auVar97,0))) >> 0x40,0),
309: SUB168(auVar97,0)) >> 0x30,0) &
310: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
311: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
312: uVar65 = SUB164(auVar97,0) & 0xffff;
313: uVar60 = SUB132(auVar96 >> 0x28,0);
314: uVar92 = (uint)uVar60;
315: uVar75 = SUB132(auVar96 >> 0x48,0);
316: auVar93 = ZEXT1012(CONCAT28(uVar75,(ulong)CONCAT24(SUB132(auVar96 >> 0x38,0),uVar92)));
317: uVar76 = SUB132(auVar96 >> 0x58,0);
318: auVar94 = CONCAT212(uVar76,auVar93);
319: uVar100 = SUB164(CONCAT106(Var90,(SUB166(auVar97,0) >> 0x10) << 0x20) >> 0x20,0);
320: uVar101 = (uint)(Var90 >> 0x10);
321: uVar102 = (uint)(Var90 >> 0x30);
322: Var99 = (unkuint10)
323: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar95 >> 0x30,0),
324: SUB1612(auVar95,0)) >> 0x50,0),
325: CONCAT28(SUB162(auVar95 >> 0x20,0),
326: SUB168(auVar95,0))) >> 0x40,0),
327: SUB168(auVar95,0)) >> 0x30,0) &
328: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
329: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
330: uVar98 = SUB164(auVar95,0) & 0xffff;
331: Var91 = (unkuint10)
332: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar53 >> 0x30,0),
333: auVar51) >> 0x50,0),
334: CONCAT28(SUB122(auVar51 >> 0x20,0),uVar36)) >>
335: 0x40,0),uVar36) >> 0x30,0) &
336: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
337: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
338: uVar43 = uVar43 & 0xffff;
339: Var90 = (unkuint10)
340: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar73 >> 0x30,0),
341: auVar52) >> 0x50,0),
342: CONCAT28(SUB122(auVar52 >> 0x20,0),uVar70)) >>
343: 0x40,0),uVar70) >> 0x30,0) &
344: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
345: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
346: uVar64 = uVar64 & 0xffff;
347: uVar39 = SUB142(auVar53 >> 0x40,0);
348: uVar44 = (uint)uVar39;
349: uVar54 = SUB162(ZEXT1516(CONCAT114(bVar11,auVar53)) >> 0x60,0);
350: auVar52 = ZEXT1012(CONCAT28(uVar54,(ulong)CONCAT24(SUB162(ZEXT1516(CONCAT114(bVar11,
351: auVar53)) >> 0x50,0),uVar44)));
352: auVar89 = CONCAT112(bVar11,auVar52);
353: uVar78 = SUB164(CONCAT106(Var99,(SUB166(auVar95,0) >> 0x10) << 0x20) >> 0x20,0);
354: uVar81 = (uint)(Var99 >> 0x10);
355: uVar84 = (uint)(Var99 >> 0x30);
356: auVar97 = CONCAT412(uVar102 << 8,CONCAT48(uVar101 << 8,CONCAT44(uVar100 << 8,uVar65 << 8))
357: ) & auVar27 |
358: CONCAT412(uVar102 << 3,CONCAT48(uVar101 << 3,CONCAT44(uVar100 << 3,uVar65 << 3))
359: ) & auVar28 |
360: CONCAT412(uVar102 >> 3,CONCAT48(uVar101 >> 3,CONCAT44(uVar100 >> 3,uVar65 >> 3))
361: );
362: uVar55 = SUB142(auVar73 >> 0x40,0);
363: uVar65 = (uint)uVar55;
364: uVar56 = (ushort)((unkuint10)SUB159(CONCAT114(bVar22,auVar73) >> 0x30,0) >> 0x30);
365: auVar51 = ZEXT1012(CONCAT28(uVar56,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(CONCAT114(
366: bVar22,auVar73) >> 0x10,0)) >> 0x40,0),uVar65)));
367: auVar96 = CONCAT112(bVar22,auVar51);
368: *pauVar29 = CONCAT412(SUB164(auVar97 >> 0x60,0) << 0x10,
369: CONCAT48(SUB164(auVar97 >> 0x40,0) << 0x10,
370: CONCAT44(SUB164(auVar97 >> 0x20,0) << 0x10,
371: SUB164(auVar97,0) << 0x10))) |
372: CONCAT412(uVar84 << 3,CONCAT48(uVar81 << 3,CONCAT44(uVar78 << 3,uVar98 << 3)))
373: & auVar28 |
374: CONCAT412(uVar84 << 8,CONCAT48(uVar81 << 8,CONCAT44(uVar78 << 8,uVar98 << 8)))
375: & auVar27 |
376: CONCAT412(uVar84 >> 3,CONCAT48(uVar81 >> 3,CONCAT44(uVar78 >> 3,uVar98 >> 3)))
377: ;
378: uVar78 = SUB164(ZEXT1416(auVar87) >> 0x20,0);
379: uVar81 = SUB124(ZEXT1012(SUB1410(auVar87 >> 0x20,0)) >> 0x20,0);
380: auVar97 = CONCAT412((uint)uVar59 << 8,
381: CONCAT48(uVar81 << 8,CONCAT44(uVar78 << 8,uVar86 << 8))) & auVar27 |
382: CONCAT412((uint)uVar59 << 3,
383: CONCAT48((uint)uVar58 << 3,
384: CONCAT44(SUB124(auVar72 >> 0x20,0) << 3,uVar86 << 3))) &
385: auVar28 | ZEXT1416(CONCAT212(uVar59 >> 3,
386: CONCAT48(uVar81 >> 3,
387: CONCAT44(uVar78 >> 3,(uint)(uVar57 >> 3)))
388: ));
389: uVar78 = SUB164(ZEXT1416(auVar94) >> 0x20,0);
390: uVar81 = SUB124(ZEXT1012(SUB1410(auVar94 >> 0x20,0)) >> 0x20,0);
391: pauVar29[1] = CONCAT412((uint)uVar76 << 8,
392: CONCAT48((uint)uVar75 << 8,
393: CONCAT44(SUB124(auVar93 >> 0x20,0) << 8,uVar92 << 8))) &
394: auVar27 | CONCAT412((uint)uVar76 << 3,
395: CONCAT48(uVar81 << 3,CONCAT44(uVar78 << 3,uVar92 << 3)))
396: & auVar28 |
397: ZEXT1416(CONCAT212(uVar76 >> 3,
398: CONCAT48(uVar81 >> 3,
399: CONCAT44(uVar78 >> 3,(uint)(uVar60 >> 3))))) |
400: CONCAT412(SUB164(auVar97 >> 0x60,0) << 0x10,
401: CONCAT48(SUB164(auVar97 >> 0x40,0) << 0x10,
402: CONCAT44(SUB164(auVar97 >> 0x20,0) << 0x10,
403: SUB164(auVar97,0) << 0x10)));
404: uVar78 = SUB164(CONCAT106(Var91,(uint6)(uVar46 >> 0x10) << 0x20) >> 0x20,0);
405: uVar81 = (uint)(Var91 >> 0x10);
406: uVar84 = (uint)(Var91 >> 0x30);
407: auVar97 = CONCAT412(uVar84 << 8,CONCAT48(uVar81 << 8,CONCAT44(uVar78 << 8,uVar43 << 8))) &
408: auVar27 | CONCAT412(uVar84 << 3,
409: CONCAT48(uVar81 << 3,CONCAT44(uVar78 << 3,uVar43 << 3))) &
410: auVar28 |
411: CONCAT412(uVar84 >> 3,CONCAT48(uVar81 >> 3,CONCAT44(uVar78 >> 3,uVar43 >> 3)));
412: uVar43 = SUB164(CONCAT106(Var90,(uint6)(uVar45 >> 0x10) << 0x20) >> 0x20,0);
413: uVar78 = (uint)(Var90 >> 0x10);
414: uVar81 = (uint)(Var90 >> 0x30);
415: pauVar29[2] = CONCAT412(SUB164(auVar97 >> 0x60,0) << 0x10,
416: CONCAT48(SUB164(auVar97 >> 0x40,0) << 0x10,
417: CONCAT44(SUB164(auVar97 >> 0x20,0) << 0x10,
418: SUB164(auVar97,0) << 0x10))) |
419: CONCAT412(uVar81 << 8,
420: CONCAT48(uVar78 << 8,CONCAT44(uVar43 << 8,uVar64 << 8))) & auVar27
421: | CONCAT412(uVar81 << 3,
422: CONCAT48(uVar78 << 3,CONCAT44(uVar43 << 3,uVar64 << 3))) &
423: auVar28 |
424: CONCAT412(uVar81 >> 3,
425: CONCAT48(uVar78 >> 3,CONCAT44(uVar43 >> 3,uVar64 >> 3)));
426: uVar43 = SUB164(ZEXT1316(auVar89) >> 0x20,0);
427: uVar64 = SUB124(ZEXT912(SUB139(auVar89 >> 0x20,0)) >> 0x20,0);
428: auVar97 = ZEXT1316(CONCAT112(bVar11 >> 3,
429: CONCAT48(uVar64 >> 3,
430: CONCAT44(uVar43 >> 3,(uint)(uVar39 >> 3))))) |
431: CONCAT412((uint)bVar11 << 8,
432: CONCAT48((uint)uVar54 << 8,
433: CONCAT44(SUB124(auVar52 >> 0x20,0) << 8,uVar44 << 8))) &
434: auVar27 | CONCAT412((uint)bVar11 << 3,
435: CONCAT48(uVar64 << 3,CONCAT44(uVar43 << 3,uVar44 << 3))) &
436: auVar28;
437: uVar43 = SUB164(ZEXT1316(auVar96) >> 0x20,0);
438: uVar44 = SUB124(ZEXT912(SUB139(auVar96 >> 0x20,0)) >> 0x20,0);
439: pauVar29[3] = ZEXT1316(CONCAT112(bVar22 >> 3,
440: CONCAT48(uVar44 >> 3,
441: CONCAT44(uVar43 >> 3,(uint)(uVar55 >> 3))))) |
442: CONCAT412((uint)bVar22 << 8,
443: CONCAT48((uint)uVar56 << 8,
444: CONCAT44(SUB124(auVar51 >> 0x20,0) << 8,uVar65 << 8))) &
445: auVar27 | CONCAT412((uint)bVar22 << 3,
446: CONCAT48(uVar44 << 3,CONCAT44(uVar43 << 3,uVar65 << 3)))
447: & auVar28 |
448: CONCAT412(SUB164(auVar97 >> 0x60,0) << 0x10,
449: CONCAT48(SUB164(auVar97 >> 0x40,0) << 0x10,
450: CONCAT44(SUB164(auVar97 >> 0x20,0) << 0x10,
451: SUB164(auVar97,0) << 0x10)));
452: pauVar29 = pauVar29[4];
453: } while (uVar33 < uVar38 >> 5);
454: uVar33 = (uVar38 >> 5) << 4;
455: pbVar34 = *pauVar32 + (ulong)uVar33 * 2;
456: puVar37 = (uint *)(*pauVar31 + (ulong)uVar33 * 4);
457: if (uVar35 != uVar33) {
458: do {
459: bVar1 = *pbVar34;
460: uVar33 = uVar33 + 1;
461: bVar11 = pbVar34[1];
462: *puVar37 = ((uint)bVar11 * 8 & 0x7e0 | (bVar11 & 0xf8) << 8 | (uint)(bVar11 >> 3)) <<
463: 0x10 | (uint)bVar1 * 8 & 0x7e0 | (bVar1 & 0xf8) << 8 | (uint)(bVar1 >> 3);
464: pbVar34 = pbVar34 + 2;
465: puVar37 = puVar37 + 1;
466: } while (uVar33 < uVar35);
467: }
468: uVar36 = (ulong)(uVar35 - 1);
469: }
470: pauVar32 = (undefined (*) [16])(*pauVar32 + uVar36 * 2 + 2);
471: pauVar31 = (undefined (*) [16])(*pauVar31 + uVar36 * 4 + 4);
472: }
473: if ((uVar38 & 1) != 0) {
474: bVar1 = (*pauVar32)[0];
475: *(ushort *)*pauVar31 =
476: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
477: }
478: param_5 = param_5 + -1;
479: param_4 = param_4 + 1;
480: param_3 = param_3 + 1;
481: }
482: return;
483: }
484: 

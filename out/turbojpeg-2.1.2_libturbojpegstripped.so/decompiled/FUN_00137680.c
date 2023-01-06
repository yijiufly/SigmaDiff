1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00137680(code **param_1)
5: 
6: {
7: char *pcVar1;
8: code **ppcVar2;
9: undefined4 *puVar3;
10: code **ppcVar4;
11: code *pcVar5;
12: ushort uVar6;
13: ushort uVar7;
14: ushort uVar8;
15: short sVar9;
16: short sVar10;
17: short sVar11;
18: ushort uVar12;
19: ushort uVar13;
20: ushort uVar14;
21: short sVar15;
22: short sVar16;
23: short sVar17;
24: short sVar18;
25: short sVar19;
26: undefined8 uVar20;
27: undefined8 uVar21;
28: undefined4 uVar22;
29: undefined4 uVar23;
30: undefined4 uVar24;
31: short sVar25;
32: uint uVar26;
33: int iVar27;
34: int iVar28;
35: undefined8 *puVar29;
36: int iVar30;
37: ulong uVar31;
38: uint uVar32;
39: undefined8 *puVar33;
40: byte bVar34;
41: undefined8 uVar35;
42: undefined auVar36 [16];
43: undefined auVar37 [16];
44: short sVar39;
45: undefined auVar38 [16];
46: short sVar40;
47: short sVar41;
48: short sVar42;
49: uint uVar43;
50: undefined auVar44 [16];
51: uint uStack28;
52: 
53: bVar34 = 0;
54: ppcVar2 = (code **)param_1[0x44];
55: *ppcVar2 = FUN_00136c40;
56: *(undefined4 *)(ppcVar2 + 2) = 0;
57: *(undefined4 *)((long)ppcVar2 + 0x6c) = 0;
58: ppcVar2[1] = FUN_00136df0;
59: FUN_00136eb0();
60: puVar29 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x580);
61: param_1[0x35] = (code *)(puVar29 + 0x20);
62: *puVar29 = 0;
63: iVar28 = (int)puVar29;
64: puVar29[0x1f] = 0;
65: uVar31 = (ulong)((iVar28 - (int)(undefined8 *)((ulong)(puVar29 + 1) & 0xfffffffffffffff8)) +
66: 0x100U >> 3);
67: puVar33 = (undefined8 *)((ulong)(puVar29 + 1) & 0xfffffffffffffff8);
68: while (uVar31 != 0) {
69: uVar31 = uVar31 - 1;
70: *puVar33 = 0;
71: puVar33 = puVar33 + (ulong)bVar34 * -2 + 1;
72: }
73: uVar26 = -(int)(puVar29 + 0x20) & 0xf;
74: if (uVar26 == 0) {
75: iVar30 = 0x100;
76: uStack28 = 0;
77: }
78: else {
79: *(undefined *)(puVar29 + 0x20) = 0;
80: if (uVar26 == 1) {
81: iVar30 = 0xff;
82: uStack28 = 1;
83: }
84: else {
85: *(undefined *)((long)puVar29 + 0x101) = 1;
86: if (uVar26 == 2) {
87: iVar30 = 0xfe;
88: uStack28 = 2;
89: }
90: else {
91: *(undefined *)((long)puVar29 + 0x102) = 2;
92: if (uVar26 == 3) {
93: iVar30 = 0xfd;
94: uStack28 = 3;
95: }
96: else {
97: *(undefined *)((long)puVar29 + 0x103) = 3;
98: if (uVar26 == 4) {
99: iVar30 = 0xfc;
100: uStack28 = 4;
101: }
102: else {
103: *(undefined *)((long)puVar29 + 0x104) = 4;
104: if (uVar26 == 5) {
105: iVar30 = 0xfb;
106: uStack28 = 5;
107: }
108: else {
109: *(undefined *)((long)puVar29 + 0x105) = 5;
110: if (uVar26 == 6) {
111: iVar30 = 0xfa;
112: uStack28 = 6;
113: }
114: else {
115: *(undefined *)((long)puVar29 + 0x106) = 6;
116: if (uVar26 == 7) {
117: iVar30 = 0xf9;
118: uStack28 = 7;
119: }
120: else {
121: *(undefined *)((long)puVar29 + 0x107) = 7;
122: if (uVar26 == 8) {
123: iVar30 = 0xf8;
124: uStack28 = 8;
125: }
126: else {
127: *(undefined *)(puVar29 + 0x21) = 8;
128: if (uVar26 == 9) {
129: iVar30 = 0xf7;
130: uStack28 = 9;
131: }
132: else {
133: *(undefined *)((long)puVar29 + 0x109) = 9;
134: if (uVar26 == 10) {
135: iVar30 = 0xf6;
136: uStack28 = 10;
137: }
138: else {
139: *(undefined *)((long)puVar29 + 0x10a) = 10;
140: if (uVar26 == 0xb) {
141: iVar30 = 0xf5;
142: uStack28 = 0xb;
143: }
144: else {
145: *(undefined *)((long)puVar29 + 0x10b) = 0xb;
146: if (uVar26 == 0xc) {
147: iVar30 = 0xf4;
148: uStack28 = 0xc;
149: }
150: else {
151: *(undefined *)((long)puVar29 + 0x10c) = 0xc;
152: if (uVar26 == 0xd) {
153: iVar30 = 0xf3;
154: uStack28 = 0xd;
155: }
156: else {
157: *(undefined *)((long)puVar29 + 0x10d) = 0xd;
158: if (uVar26 == 0xf) {
159: *(undefined *)((long)puVar29 + 0x10e) = 0xe;
160: iVar30 = 0xf1;
161: uStack28 = 0xf;
162: }
163: else {
164: iVar30 = 0xf2;
165: uStack28 = 0xe;
166: }
167: }
168: }
169: }
170: }
171: }
172: }
173: }
174: }
175: }
176: }
177: }
178: }
179: }
180: }
181: auVar36 = _DAT_0016c610;
182: uVar32 = 0x100 - uVar26;
183: pcVar1 = (char *)((long)puVar29 + (ulong)uVar26 + 0x100);
184: sVar25 = (short)uStack28;
185: sVar39 = sVar25 + 5;
186: uVar26 = uStack28 + 2;
187: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
188: 0x60,0),
189: CONCAT210(sVar39,(unkuint10)uVar26
190: << 0x40)) >> 0x50,0
191: ),(short)(uStack28 + 1))) << 0x40) >> 0x30,0) &
192: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
193: (undefined  [16])0xffffffff00000000;
194: sVar40 = sVar25 + 0xd;
195: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
196: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
197: (unkuint10)0) >> 0x20,0) &
198: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
199: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
200: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
201: sVar42 = sVar25 + 0x1d;
202: uVar26 = uStack28 + 10;
203: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
204: 0x60,0),
205: CONCAT210(sVar40,(unkuint10)uVar26
206: << 0x40)) >> 0x50,0
207: ),(short)(uStack28 + 9))) << 0x40) >> 0x30,0) &
208: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
209: (undefined  [16])0xffffffff00000000;
210: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
211: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
212: (unkuint10)0) >> 0x20,0) &
213: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
214: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
215: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
216: uVar35 = SUB168(_DAT_0016c610,0);
217: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
218: CONCAT214(sVar25 + 7,
219: CONCAT212((short)((ulong)((uStack28 + 6)
220: * 0x10000) >>
221: 0x10),
222: SUB1612(auVar37,0))) >> 0x60,0
223: ),CONCAT210(sVar39,SUB1610(auVar37,0))) >> 0x50,0)
224: ,CONCAT28((short)((uStack28 + 4) * 0x10000 >> 0x10
225: ),SUB168(auVar37,0))) >> 0x40,0),
226: (((ulong)CONCAT24(sVar39,(uStack28 + 3) * 0x10000)
227: & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
228: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
229: uStack28 | (uStack28 + 1) * 0x10000) & _DAT_0016c610;
230: sVar41 = sVar25 + 0x15;
231: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
232: CONCAT214(sVar25 + 0xf,
233: CONCAT212((short)((ulong)((uStack28 +
234: 0xe) * 0x10000
235: ) >> 0x10),
236: SUB1612(auVar38,0))) >> 0x60,0
237: ),CONCAT210(sVar40,SUB1610(auVar38,0))) >> 0x50,0)
238: ,CONCAT28((short)((uStack28 + 0xc) * 0x10000 >>
239: 0x10),SUB168(auVar38,0))) >> 0x40
240: ,0),(((ulong)CONCAT24(sVar40,(uStack28 + 0xb) *
241: 0x10000) & 0xffff0000
242: ) >> 0x10) << 0x30) >> 0x30,0),
243: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
244: uStack28 + 8 | (uStack28 + 9) * 0x10000) & _DAT_0016c610;
245: uVar6 = SUB162(auVar37,0);
246: uVar7 = SUB162(auVar37 >> 0x10,0);
247: uVar8 = SUB162(auVar37 >> 0x20,0);
248: sVar39 = SUB162(auVar37 >> 0x30,0);
249: sVar40 = SUB162(auVar37 >> 0x40,0);
250: sVar9 = SUB162(auVar37 >> 0x50,0);
251: sVar10 = SUB162(auVar37 >> 0x60,0);
252: sVar11 = SUB162(auVar37 >> 0x70,0);
253: uVar12 = SUB162(auVar38,0);
254: uVar13 = SUB162(auVar38 >> 0x10,0);
255: uVar14 = SUB162(auVar38 >> 0x20,0);
256: sVar15 = SUB162(auVar38 >> 0x30,0);
257: sVar16 = SUB162(auVar38 >> 0x40,0);
258: sVar17 = SUB162(auVar38 >> 0x50,0);
259: sVar18 = SUB162(auVar38 >> 0x60,0);
260: sVar19 = SUB162(auVar38 >> 0x70,0);
261: *pcVar1 = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
262: pcVar1[1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
263: pcVar1[2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
264: pcVar1[3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
265: pcVar1[4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
266: pcVar1[5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
267: pcVar1[6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
268: pcVar1[7] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
269: pcVar1[8] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
270: pcVar1[9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
271: pcVar1[10] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
272: pcVar1[0xb] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
273: pcVar1[0xc] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
274: pcVar1[0xd] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
275: pcVar1[0xe] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
276: pcVar1[0xf] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
277: uVar26 = uStack28 + 0x12;
278: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
279: 0x60,0),
280: CONCAT210(sVar41,(unkuint10)uVar26
281: << 0x40)) >> 0x50,0
282: ),(short)(uStack28 + 0x11))) << 0x40) >> 0x30,0
283: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
284: (undefined  [16])0xffffffff00000000;
285: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
286: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
287: (unkuint10)0) >> 0x20,0) &
288: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
289: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
290: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
291: uVar26 = uStack28 + 0x1a;
292: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
293: 0x60,0),
294: CONCAT210(sVar42,(unkuint10)uVar26
295: << 0x40)) >> 0x50,0
296: ),(short)(uStack28 + 0x19))) << 0x40) >> 0x30,0
297: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
298: (undefined  [16])0xffffffff00000000;
299: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
300: CONCAT214(sVar25 + 0x17,
301: CONCAT212((short)((ulong)((uStack28 +
302: 0x16) * 
303: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
304: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
305: CONCAT28((short)((uStack28 + 0x14) * 0x10000 >>
306: 0x10),SUB168(auVar37,0))) >> 0x40,
307: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x13) *
308: 0x10000) & 0xffff0000)
309: >> 0x10) << 0x30) >> 0x30,0),
310: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
311: uStack28 + 0x10 | (uStack28 + 0x11) * 0x10000) & auVar36;
312: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
313: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
314: (unkuint10)0) >> 0x20,0) &
315: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
316: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
317: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
318: sVar41 = sVar25 + 0x25;
319: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
320: CONCAT214(sVar25 + 0x1f,
321: CONCAT212((short)((ulong)((uStack28 +
322: 0x1e) * 
323: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
324: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
325: CONCAT28((short)((uStack28 + 0x1c) * 0x10000 >>
326: 0x10),SUB168(auVar38,0))) >> 0x40,
327: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x1b) *
328: 0x10000) & 0xffff0000)
329: >> 0x10) << 0x30) >> 0x30,0),
330: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
331: uStack28 + 0x18 | (uStack28 + 0x19) * 0x10000) & auVar36;
332: sVar42 = sVar25 + 0x2d;
333: uVar6 = SUB162(auVar37,0);
334: uVar7 = SUB162(auVar37 >> 0x10,0);
335: uVar8 = SUB162(auVar37 >> 0x20,0);
336: sVar39 = SUB162(auVar37 >> 0x30,0);
337: sVar40 = SUB162(auVar37 >> 0x40,0);
338: sVar9 = SUB162(auVar37 >> 0x50,0);
339: sVar10 = SUB162(auVar37 >> 0x60,0);
340: sVar11 = SUB162(auVar37 >> 0x70,0);
341: uVar12 = SUB162(auVar38,0);
342: uVar13 = SUB162(auVar38 >> 0x10,0);
343: uVar14 = SUB162(auVar38 >> 0x20,0);
344: sVar15 = SUB162(auVar38 >> 0x30,0);
345: sVar16 = SUB162(auVar38 >> 0x40,0);
346: sVar17 = SUB162(auVar38 >> 0x50,0);
347: sVar18 = SUB162(auVar38 >> 0x60,0);
348: sVar19 = SUB162(auVar38 >> 0x70,0);
349: pcVar1[0x10] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
350: pcVar1[0x11] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
351: pcVar1[0x12] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
352: pcVar1[0x13] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
353: pcVar1[0x14] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
354: pcVar1[0x15] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
355: pcVar1[0x16] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
356: pcVar1[0x17] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
357: pcVar1[0x18] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
358: pcVar1[0x19] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
359: pcVar1[0x1a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
360: pcVar1[0x1b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
361: pcVar1[0x1c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
362: pcVar1[0x1d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
363: pcVar1[0x1e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
364: pcVar1[0x1f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
365: uVar26 = uStack28 + 0x22;
366: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
367: 0x60,0),
368: CONCAT210(sVar41,(unkuint10)uVar26
369: << 0x40)) >> 0x50,0
370: ),(short)(uStack28 + 0x21))) << 0x40) >> 0x30,0
371: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
372: (undefined  [16])0xffffffff00000000;
373: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
374: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
375: (unkuint10)0) >> 0x20,0) &
376: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
377: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
378: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
379: uVar26 = uStack28 + 0x2a;
380: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
381: 0x60,0),
382: CONCAT210(sVar42,(unkuint10)uVar26
383: << 0x40)) >> 0x50,0
384: ),(short)(uStack28 + 0x29))) << 0x40) >> 0x30,0
385: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
386: (undefined  [16])0xffffffff00000000;
387: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
388: CONCAT214(sVar25 + 0x27,
389: CONCAT212((short)((ulong)((uStack28 +
390: 0x26) * 
391: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
392: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
393: CONCAT28((short)((uStack28 + 0x24) * 0x10000 >>
394: 0x10),SUB168(auVar37,0))) >> 0x40,
395: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x23) *
396: 0x10000) & 0xffff0000)
397: >> 0x10) << 0x30) >> 0x30,0),
398: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
399: uStack28 + 0x20 | (uStack28 + 0x21) * 0x10000) & auVar36;
400: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
401: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
402: (unkuint10)0) >> 0x20,0) &
403: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
404: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
405: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
406: sVar41 = sVar25 + 0x35;
407: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
408: CONCAT214(sVar25 + 0x2f,
409: CONCAT212((short)((ulong)((uStack28 +
410: 0x2e) * 
411: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
412: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
413: CONCAT28((short)((uStack28 + 0x2c) * 0x10000 >>
414: 0x10),SUB168(auVar38,0))) >> 0x40,
415: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x2b) *
416: 0x10000) & 0xffff0000)
417: >> 0x10) << 0x30) >> 0x30,0),
418: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
419: uStack28 + 0x28 | (uStack28 + 0x29) * 0x10000) & auVar36;
420: sVar42 = sVar25 + 0x3d;
421: uVar6 = SUB162(auVar37,0);
422: uVar7 = SUB162(auVar37 >> 0x10,0);
423: uVar8 = SUB162(auVar37 >> 0x20,0);
424: sVar39 = SUB162(auVar37 >> 0x30,0);
425: sVar40 = SUB162(auVar37 >> 0x40,0);
426: sVar9 = SUB162(auVar37 >> 0x50,0);
427: sVar10 = SUB162(auVar37 >> 0x60,0);
428: sVar11 = SUB162(auVar37 >> 0x70,0);
429: uVar12 = SUB162(auVar38,0);
430: uVar13 = SUB162(auVar38 >> 0x10,0);
431: uVar14 = SUB162(auVar38 >> 0x20,0);
432: sVar15 = SUB162(auVar38 >> 0x30,0);
433: sVar16 = SUB162(auVar38 >> 0x40,0);
434: sVar17 = SUB162(auVar38 >> 0x50,0);
435: sVar18 = SUB162(auVar38 >> 0x60,0);
436: sVar19 = SUB162(auVar38 >> 0x70,0);
437: pcVar1[0x20] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
438: pcVar1[0x21] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
439: pcVar1[0x22] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
440: pcVar1[0x23] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
441: pcVar1[0x24] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
442: pcVar1[0x25] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
443: pcVar1[0x26] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
444: pcVar1[0x27] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
445: pcVar1[0x28] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
446: pcVar1[0x29] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
447: pcVar1[0x2a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
448: pcVar1[0x2b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
449: pcVar1[0x2c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
450: pcVar1[0x2d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
451: pcVar1[0x2e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
452: pcVar1[0x2f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
453: uVar26 = uStack28 + 0x32;
454: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
455: 0x60,0),
456: CONCAT210(sVar41,(unkuint10)uVar26
457: << 0x40)) >> 0x50,0
458: ),(short)(uStack28 + 0x31))) << 0x40) >> 0x30,0
459: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
460: (undefined  [16])0xffffffff00000000;
461: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
462: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
463: (unkuint10)0) >> 0x20,0) &
464: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
465: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
466: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
467: uVar26 = uStack28 + 0x3a;
468: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
469: 0x60,0),
470: CONCAT210(sVar42,(unkuint10)uVar26
471: << 0x40)) >> 0x50,0
472: ),(short)(uStack28 + 0x39))) << 0x40) >> 0x30,0
473: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
474: (undefined  [16])0xffffffff00000000;
475: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
476: CONCAT214(sVar25 + 0x37,
477: CONCAT212((short)((ulong)((uStack28 +
478: 0x36) * 
479: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
480: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
481: CONCAT28((short)((uStack28 + 0x34) * 0x10000 >>
482: 0x10),SUB168(auVar37,0))) >> 0x40,
483: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x33) *
484: 0x10000) & 0xffff0000)
485: >> 0x10) << 0x30) >> 0x30,0),
486: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
487: uStack28 + 0x30 | (uStack28 + 0x31) * 0x10000) & auVar36;
488: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
489: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
490: (unkuint10)0) >> 0x20,0) &
491: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
492: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
493: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
494: sVar41 = sVar25 + 0x45;
495: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
496: CONCAT214(sVar25 + 0x3f,
497: CONCAT212((short)((ulong)((uStack28 +
498: 0x3e) * 
499: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
500: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
501: CONCAT28((short)((uStack28 + 0x3c) * 0x10000 >>
502: 0x10),SUB168(auVar38,0))) >> 0x40,
503: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x3b) *
504: 0x10000) & 0xffff0000)
505: >> 0x10) << 0x30) >> 0x30,0),
506: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
507: uStack28 + 0x38 | (uStack28 + 0x39) * 0x10000) & auVar36;
508: sVar42 = sVar25 + 0x4d;
509: uVar6 = SUB162(auVar37,0);
510: uVar7 = SUB162(auVar37 >> 0x10,0);
511: uVar8 = SUB162(auVar37 >> 0x20,0);
512: sVar39 = SUB162(auVar37 >> 0x30,0);
513: sVar40 = SUB162(auVar37 >> 0x40,0);
514: sVar9 = SUB162(auVar37 >> 0x50,0);
515: sVar10 = SUB162(auVar37 >> 0x60,0);
516: sVar11 = SUB162(auVar37 >> 0x70,0);
517: uVar12 = SUB162(auVar38,0);
518: uVar13 = SUB162(auVar38 >> 0x10,0);
519: uVar14 = SUB162(auVar38 >> 0x20,0);
520: sVar15 = SUB162(auVar38 >> 0x30,0);
521: sVar16 = SUB162(auVar38 >> 0x40,0);
522: sVar17 = SUB162(auVar38 >> 0x50,0);
523: sVar18 = SUB162(auVar38 >> 0x60,0);
524: sVar19 = SUB162(auVar38 >> 0x70,0);
525: pcVar1[0x30] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
526: pcVar1[0x31] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
527: pcVar1[0x32] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
528: pcVar1[0x33] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
529: pcVar1[0x34] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
530: pcVar1[0x35] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
531: pcVar1[0x36] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
532: pcVar1[0x37] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
533: pcVar1[0x38] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
534: pcVar1[0x39] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
535: pcVar1[0x3a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
536: pcVar1[0x3b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
537: pcVar1[0x3c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
538: pcVar1[0x3d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
539: pcVar1[0x3e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
540: pcVar1[0x3f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
541: uVar26 = uStack28 + 0x42;
542: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
543: 0x60,0),
544: CONCAT210(sVar41,(unkuint10)uVar26
545: << 0x40)) >> 0x50,0
546: ),(short)(uStack28 + 0x41))) << 0x40) >> 0x30,0
547: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
548: (undefined  [16])0xffffffff00000000;
549: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
550: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
551: (unkuint10)0) >> 0x20,0) &
552: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
553: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
554: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
555: uVar26 = uStack28 + 0x4a;
556: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
557: 0x60,0),
558: CONCAT210(sVar42,(unkuint10)uVar26
559: << 0x40)) >> 0x50,0
560: ),(short)(uStack28 + 0x49))) << 0x40) >> 0x30,0
561: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
562: (undefined  [16])0xffffffff00000000;
563: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
564: CONCAT214(sVar25 + 0x47,
565: CONCAT212((short)((ulong)((uStack28 +
566: 0x46) * 
567: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
568: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
569: CONCAT28((short)((uStack28 + 0x44) * 0x10000 >>
570: 0x10),SUB168(auVar37,0))) >> 0x40,
571: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x43) *
572: 0x10000) & 0xffff0000)
573: >> 0x10) << 0x30) >> 0x30,0),
574: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
575: uStack28 + 0x40 | (uStack28 + 0x41) * 0x10000) & auVar36;
576: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
577: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
578: (unkuint10)0) >> 0x20,0) &
579: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
580: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
581: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
582: sVar41 = sVar25 + 0x55;
583: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
584: CONCAT214(sVar25 + 0x4f,
585: CONCAT212((short)((ulong)((uStack28 +
586: 0x4e) * 
587: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
588: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
589: CONCAT28((short)((uStack28 + 0x4c) * 0x10000 >>
590: 0x10),SUB168(auVar38,0))) >> 0x40,
591: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x4b) *
592: 0x10000) & 0xffff0000)
593: >> 0x10) << 0x30) >> 0x30,0),
594: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
595: uStack28 + 0x48 | (uStack28 + 0x49) * 0x10000) & auVar36;
596: sVar42 = sVar25 + 0x5d;
597: uVar6 = SUB162(auVar37,0);
598: uVar7 = SUB162(auVar37 >> 0x10,0);
599: uVar8 = SUB162(auVar37 >> 0x20,0);
600: sVar39 = SUB162(auVar37 >> 0x30,0);
601: sVar40 = SUB162(auVar37 >> 0x40,0);
602: sVar9 = SUB162(auVar37 >> 0x50,0);
603: sVar10 = SUB162(auVar37 >> 0x60,0);
604: sVar11 = SUB162(auVar37 >> 0x70,0);
605: uVar12 = SUB162(auVar38,0);
606: uVar13 = SUB162(auVar38 >> 0x10,0);
607: uVar14 = SUB162(auVar38 >> 0x20,0);
608: sVar15 = SUB162(auVar38 >> 0x30,0);
609: sVar16 = SUB162(auVar38 >> 0x40,0);
610: sVar17 = SUB162(auVar38 >> 0x50,0);
611: sVar18 = SUB162(auVar38 >> 0x60,0);
612: sVar19 = SUB162(auVar38 >> 0x70,0);
613: pcVar1[0x40] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
614: pcVar1[0x41] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
615: pcVar1[0x42] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
616: pcVar1[0x43] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
617: pcVar1[0x44] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
618: pcVar1[0x45] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
619: pcVar1[0x46] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
620: pcVar1[0x47] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
621: pcVar1[0x48] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
622: pcVar1[0x49] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
623: pcVar1[0x4a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
624: pcVar1[0x4b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
625: pcVar1[0x4c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
626: pcVar1[0x4d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
627: pcVar1[0x4e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
628: pcVar1[0x4f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
629: uVar26 = uStack28 + 0x52;
630: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
631: 0x60,0),
632: CONCAT210(sVar41,(unkuint10)uVar26
633: << 0x40)) >> 0x50,0
634: ),(short)(uStack28 + 0x51))) << 0x40) >> 0x30,0
635: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
636: (undefined  [16])0xffffffff00000000;
637: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
638: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
639: (unkuint10)0) >> 0x20,0) &
640: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
641: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
642: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
643: uVar26 = uStack28 + 0x5a;
644: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
645: 0x60,0),
646: CONCAT210(sVar42,(unkuint10)uVar26
647: << 0x40)) >> 0x50,0
648: ),(short)(uStack28 + 0x59))) << 0x40) >> 0x30,0
649: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
650: (undefined  [16])0xffffffff00000000;
651: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
652: CONCAT214(sVar25 + 0x57,
653: CONCAT212((short)((ulong)((uStack28 +
654: 0x56) * 
655: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
656: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
657: CONCAT28((short)((uStack28 + 0x54) * 0x10000 >>
658: 0x10),SUB168(auVar37,0))) >> 0x40,
659: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x53) *
660: 0x10000) & 0xffff0000)
661: >> 0x10) << 0x30) >> 0x30,0),
662: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
663: uStack28 + 0x50 | (uStack28 + 0x51) * 0x10000) & auVar36;
664: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
665: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
666: (unkuint10)0) >> 0x20,0) &
667: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
668: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
669: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
670: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
671: CONCAT214(sVar25 + 0x5f,
672: CONCAT212((short)((ulong)((uStack28 +
673: 0x5e) * 
674: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
675: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
676: CONCAT28((short)((uStack28 + 0x5c) * 0x10000 >>
677: 0x10),SUB168(auVar38,0))) >> 0x40,
678: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x5b) *
679: 0x10000) & 0xffff0000)
680: >> 0x10) << 0x30) >> 0x30,0),
681: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
682: uStack28 + 0x58 | (uStack28 + 0x59) * 0x10000) & auVar36;
683: uVar6 = SUB162(auVar37,0);
684: uVar7 = SUB162(auVar37 >> 0x10,0);
685: uVar8 = SUB162(auVar37 >> 0x20,0);
686: sVar39 = SUB162(auVar37 >> 0x30,0);
687: sVar40 = SUB162(auVar37 >> 0x40,0);
688: sVar9 = SUB162(auVar37 >> 0x50,0);
689: sVar10 = SUB162(auVar37 >> 0x60,0);
690: sVar11 = SUB162(auVar37 >> 0x70,0);
691: uVar12 = SUB162(auVar38,0);
692: uVar13 = SUB162(auVar38 >> 0x10,0);
693: uVar14 = SUB162(auVar38 >> 0x20,0);
694: sVar15 = SUB162(auVar38 >> 0x30,0);
695: sVar16 = SUB162(auVar38 >> 0x40,0);
696: sVar17 = SUB162(auVar38 >> 0x50,0);
697: sVar18 = SUB162(auVar38 >> 0x60,0);
698: sVar19 = SUB162(auVar38 >> 0x70,0);
699: pcVar1[0x50] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
700: pcVar1[0x51] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
701: pcVar1[0x52] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
702: pcVar1[0x53] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
703: pcVar1[0x54] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
704: pcVar1[0x55] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
705: pcVar1[0x56] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
706: pcVar1[0x57] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
707: pcVar1[0x58] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
708: pcVar1[0x59] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
709: pcVar1[0x5a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
710: pcVar1[0x5b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
711: pcVar1[0x5c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
712: pcVar1[0x5d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
713: pcVar1[0x5e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
714: pcVar1[0x5f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
715: uVar26 = uStack28 + 0x62;
716: sVar39 = sVar25 + 0x65;
717: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
718: 0x60,0),
719: CONCAT210(sVar39,(unkuint10)uVar26
720: << 0x40)) >> 0x50,0
721: ),(short)(uStack28 + 0x61))) << 0x40) >> 0x30,0
722: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
723: (undefined  [16])0xffffffff00000000;
724: sVar40 = sVar25 + 0x6d;
725: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
726: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
727: (unkuint10)0) >> 0x20,0) &
728: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
729: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
730: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
731: uVar26 = uStack28 + 0x6a;
732: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
733: 0x60,0),
734: CONCAT210(sVar40,(unkuint10)uVar26
735: << 0x40)) >> 0x50,0
736: ),(short)(uStack28 + 0x69))) << 0x40) >> 0x30,0
737: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
738: (undefined  [16])0xffffffff00000000;
739: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
740: CONCAT214(sVar25 + 0x67,
741: CONCAT212((short)((ulong)((uStack28 +
742: 0x66) * 
743: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
744: CONCAT210(sVar39,SUB1610(auVar37,0))) >> 0x50,0),
745: CONCAT28((short)((uStack28 + 100) * 0x10000 >>
746: 0x10),SUB168(auVar37,0))) >> 0x40,
747: 0),(((ulong)CONCAT24(sVar39,(uStack28 + 99) *
748: 0x10000) & 0xffff0000)
749: >> 0x10) << 0x30) >> 0x30,0),
750: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
751: uStack28 + 0x60 | (uStack28 + 0x61) * 0x10000) & auVar36;
752: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
753: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
754: (unkuint10)0) >> 0x20,0) &
755: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
756: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
757: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
758: sVar41 = sVar25 + 0x75;
759: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
760: CONCAT214(sVar25 + 0x6f,
761: CONCAT212((short)((ulong)((uStack28 +
762: 0x6e) * 
763: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
764: CONCAT210(sVar40,SUB1610(auVar38,0))) >> 0x50,0),
765: CONCAT28((short)((uStack28 + 0x6c) * 0x10000 >>
766: 0x10),SUB168(auVar38,0))) >> 0x40,
767: 0),(((ulong)CONCAT24(sVar40,(uStack28 + 0x6b) *
768: 0x10000) & 0xffff0000)
769: >> 0x10) << 0x30) >> 0x30,0),
770: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
771: uStack28 + 0x68 | (uStack28 + 0x69) * 0x10000) & auVar36;
772: sVar42 = sVar25 + 0x7d;
773: uVar6 = SUB162(auVar37,0);
774: uVar7 = SUB162(auVar37 >> 0x10,0);
775: uVar8 = SUB162(auVar37 >> 0x20,0);
776: sVar39 = SUB162(auVar37 >> 0x30,0);
777: sVar40 = SUB162(auVar37 >> 0x40,0);
778: sVar9 = SUB162(auVar37 >> 0x50,0);
779: sVar10 = SUB162(auVar37 >> 0x60,0);
780: sVar11 = SUB162(auVar37 >> 0x70,0);
781: uVar12 = SUB162(auVar38,0);
782: uVar13 = SUB162(auVar38 >> 0x10,0);
783: uVar14 = SUB162(auVar38 >> 0x20,0);
784: sVar15 = SUB162(auVar38 >> 0x30,0);
785: sVar16 = SUB162(auVar38 >> 0x40,0);
786: sVar17 = SUB162(auVar38 >> 0x50,0);
787: sVar18 = SUB162(auVar38 >> 0x60,0);
788: sVar19 = SUB162(auVar38 >> 0x70,0);
789: pcVar1[0x60] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
790: pcVar1[0x61] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
791: pcVar1[0x62] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
792: pcVar1[99] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
793: pcVar1[100] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
794: pcVar1[0x65] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
795: pcVar1[0x66] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
796: pcVar1[0x67] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
797: pcVar1[0x68] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
798: pcVar1[0x69] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
799: pcVar1[0x6a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
800: pcVar1[0x6b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
801: pcVar1[0x6c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
802: pcVar1[0x6d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
803: pcVar1[0x6e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
804: pcVar1[0x6f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
805: uVar26 = uStack28 + 0x72;
806: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
807: 0x60,0),
808: CONCAT210(sVar41,(unkuint10)uVar26
809: << 0x40)) >> 0x50,0
810: ),(short)(uStack28 + 0x71))) << 0x40) >> 0x30,0
811: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
812: (undefined  [16])0xffffffff00000000;
813: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
814: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
815: (unkuint10)0) >> 0x20,0) &
816: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
817: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
818: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
819: uVar26 = uStack28 + 0x7a;
820: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
821: 0x60,0),
822: CONCAT210(sVar42,(unkuint10)uVar26
823: << 0x40)) >> 0x50,0
824: ),(short)(uStack28 + 0x79))) << 0x40) >> 0x30,0
825: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
826: (undefined  [16])0xffffffff00000000;
827: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
828: CONCAT214(sVar25 + 0x77,
829: CONCAT212((short)((ulong)((uStack28 +
830: 0x76) * 
831: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
832: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
833: CONCAT28((short)((uStack28 + 0x74) * 0x10000 >>
834: 0x10),SUB168(auVar37,0))) >> 0x40,
835: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x73) *
836: 0x10000) & 0xffff0000)
837: >> 0x10) << 0x30) >> 0x30,0),
838: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
839: uStack28 + 0x70 | (uStack28 + 0x71) * 0x10000) & auVar36;
840: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
841: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
842: (unkuint10)0) >> 0x20,0) &
843: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
844: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
845: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
846: sVar41 = sVar25 + 0x85;
847: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
848: CONCAT214(sVar25 + 0x7f,
849: CONCAT212((short)((ulong)((uStack28 +
850: 0x7e) * 
851: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
852: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
853: CONCAT28((short)((uStack28 + 0x7c) * 0x10000 >>
854: 0x10),SUB168(auVar38,0))) >> 0x40,
855: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x7b) *
856: 0x10000) & 0xffff0000)
857: >> 0x10) << 0x30) >> 0x30,0),
858: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
859: uStack28 + 0x78 | (uStack28 + 0x79) * 0x10000) & auVar36;
860: sVar42 = sVar25 + 0x8d;
861: uVar6 = SUB162(auVar37,0);
862: uVar7 = SUB162(auVar37 >> 0x10,0);
863: uVar8 = SUB162(auVar37 >> 0x20,0);
864: sVar39 = SUB162(auVar37 >> 0x30,0);
865: sVar40 = SUB162(auVar37 >> 0x40,0);
866: sVar9 = SUB162(auVar37 >> 0x50,0);
867: sVar10 = SUB162(auVar37 >> 0x60,0);
868: sVar11 = SUB162(auVar37 >> 0x70,0);
869: uVar12 = SUB162(auVar38,0);
870: uVar13 = SUB162(auVar38 >> 0x10,0);
871: uVar14 = SUB162(auVar38 >> 0x20,0);
872: sVar15 = SUB162(auVar38 >> 0x30,0);
873: sVar16 = SUB162(auVar38 >> 0x40,0);
874: sVar17 = SUB162(auVar38 >> 0x50,0);
875: sVar18 = SUB162(auVar38 >> 0x60,0);
876: sVar19 = SUB162(auVar38 >> 0x70,0);
877: pcVar1[0x70] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
878: pcVar1[0x71] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
879: pcVar1[0x72] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
880: pcVar1[0x73] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
881: pcVar1[0x74] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
882: pcVar1[0x75] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
883: pcVar1[0x76] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
884: pcVar1[0x77] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
885: pcVar1[0x78] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
886: pcVar1[0x79] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
887: pcVar1[0x7a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
888: pcVar1[0x7b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
889: pcVar1[0x7c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
890: pcVar1[0x7d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
891: pcVar1[0x7e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
892: pcVar1[0x7f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
893: uVar26 = uStack28 + 0x82;
894: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
895: 0x60,0),
896: CONCAT210(sVar41,(unkuint10)uVar26
897: << 0x40)) >> 0x50,0
898: ),(short)(uStack28 + 0x81))) << 0x40) >> 0x30,0
899: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
900: (undefined  [16])0xffffffff00000000;
901: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
902: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
903: (unkuint10)0) >> 0x20,0) &
904: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
905: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
906: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
907: uVar26 = uStack28 + 0x8a;
908: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
909: 0x60,0),
910: CONCAT210(sVar42,(unkuint10)uVar26
911: << 0x40)) >> 0x50,0
912: ),(short)(uStack28 + 0x89))) << 0x40) >> 0x30,0
913: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
914: (undefined  [16])0xffffffff00000000;
915: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
916: CONCAT214(sVar25 + 0x87,
917: CONCAT212((short)((ulong)((uStack28 +
918: 0x86) * 
919: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
920: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
921: CONCAT28((short)((uStack28 + 0x84) * 0x10000 >>
922: 0x10),SUB168(auVar37,0))) >> 0x40,
923: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x83) *
924: 0x10000) & 0xffff0000)
925: >> 0x10) << 0x30) >> 0x30,0),
926: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
927: uStack28 + 0x80 | (uStack28 + 0x81) * 0x10000) & auVar36;
928: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
929: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
930: (unkuint10)0) >> 0x20,0) &
931: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
932: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
933: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
934: sVar41 = sVar25 + 0x95;
935: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
936: CONCAT214(sVar25 + 0x8f,
937: CONCAT212((short)((ulong)((uStack28 +
938: 0x8e) * 
939: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
940: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
941: CONCAT28((short)((uStack28 + 0x8c) * 0x10000 >>
942: 0x10),SUB168(auVar38,0))) >> 0x40,
943: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x8b) *
944: 0x10000) & 0xffff0000)
945: >> 0x10) << 0x30) >> 0x30,0),
946: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
947: uStack28 + 0x88 | (uStack28 + 0x89) * 0x10000) & auVar36;
948: sVar42 = sVar25 + 0x9d;
949: uVar6 = SUB162(auVar37,0);
950: uVar7 = SUB162(auVar37 >> 0x10,0);
951: uVar8 = SUB162(auVar37 >> 0x20,0);
952: sVar39 = SUB162(auVar37 >> 0x30,0);
953: sVar40 = SUB162(auVar37 >> 0x40,0);
954: sVar9 = SUB162(auVar37 >> 0x50,0);
955: sVar10 = SUB162(auVar37 >> 0x60,0);
956: sVar11 = SUB162(auVar37 >> 0x70,0);
957: uVar12 = SUB162(auVar38,0);
958: uVar13 = SUB162(auVar38 >> 0x10,0);
959: uVar14 = SUB162(auVar38 >> 0x20,0);
960: sVar15 = SUB162(auVar38 >> 0x30,0);
961: sVar16 = SUB162(auVar38 >> 0x40,0);
962: sVar17 = SUB162(auVar38 >> 0x50,0);
963: sVar18 = SUB162(auVar38 >> 0x60,0);
964: sVar19 = SUB162(auVar38 >> 0x70,0);
965: pcVar1[0x80] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
966: pcVar1[0x81] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
967: pcVar1[0x82] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
968: pcVar1[0x83] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
969: pcVar1[0x84] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
970: pcVar1[0x85] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
971: pcVar1[0x86] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
972: pcVar1[0x87] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
973: pcVar1[0x88] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
974: pcVar1[0x89] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
975: pcVar1[0x8a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
976: pcVar1[0x8b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
977: pcVar1[0x8c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
978: pcVar1[0x8d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
979: pcVar1[0x8e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
980: pcVar1[0x8f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
981: uVar26 = uStack28 + 0x92;
982: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
983: 0x60,0),
984: CONCAT210(sVar41,(unkuint10)uVar26
985: << 0x40)) >> 0x50,0
986: ),(short)(uStack28 + 0x91))) << 0x40) >> 0x30,0
987: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
988: (undefined  [16])0xffffffff00000000;
989: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
990: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
991: (unkuint10)0) >> 0x20,0) &
992: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
993: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
994: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
995: uVar26 = uStack28 + 0x9a;
996: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
997: 0x60,0),
998: CONCAT210(sVar42,(unkuint10)uVar26
999: << 0x40)) >> 0x50,0
1000: ),(short)(uStack28 + 0x99))) << 0x40) >> 0x30,0
1001: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1002: (undefined  [16])0xffffffff00000000;
1003: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1004: CONCAT214(sVar25 + 0x97,
1005: CONCAT212((short)((ulong)((uStack28 +
1006: 0x96) * 
1007: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1008: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
1009: CONCAT28((short)((uStack28 + 0x94) * 0x10000 >>
1010: 0x10),SUB168(auVar37,0))) >> 0x40,
1011: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0x93) *
1012: 0x10000) & 0xffff0000)
1013: >> 0x10) << 0x30) >> 0x30,0),
1014: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1015: uStack28 + 0x90 | (uStack28 + 0x91) * 0x10000) & auVar36;
1016: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
1017: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
1018: (unkuint10)0) >> 0x20,0) &
1019: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1020: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1021: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1022: sVar41 = sVar25 + 0xa5;
1023: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1024: CONCAT214(sVar25 + 0x9f,
1025: CONCAT212((short)((ulong)((uStack28 +
1026: 0x9e) * 
1027: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
1028: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
1029: CONCAT28((short)((uStack28 + 0x9c) * 0x10000 >>
1030: 0x10),SUB168(auVar38,0))) >> 0x40,
1031: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0x9b) *
1032: 0x10000) & 0xffff0000)
1033: >> 0x10) << 0x30) >> 0x30,0),
1034: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
1035: uStack28 + 0x98 | (uStack28 + 0x99) * 0x10000) & auVar36;
1036: sVar42 = sVar25 + 0xad;
1037: uVar6 = SUB162(auVar37,0);
1038: uVar7 = SUB162(auVar37 >> 0x10,0);
1039: uVar8 = SUB162(auVar37 >> 0x20,0);
1040: sVar39 = SUB162(auVar37 >> 0x30,0);
1041: sVar40 = SUB162(auVar37 >> 0x40,0);
1042: sVar9 = SUB162(auVar37 >> 0x50,0);
1043: sVar10 = SUB162(auVar37 >> 0x60,0);
1044: sVar11 = SUB162(auVar37 >> 0x70,0);
1045: uVar12 = SUB162(auVar38,0);
1046: uVar13 = SUB162(auVar38 >> 0x10,0);
1047: uVar14 = SUB162(auVar38 >> 0x20,0);
1048: sVar15 = SUB162(auVar38 >> 0x30,0);
1049: sVar16 = SUB162(auVar38 >> 0x40,0);
1050: sVar17 = SUB162(auVar38 >> 0x50,0);
1051: sVar18 = SUB162(auVar38 >> 0x60,0);
1052: sVar19 = SUB162(auVar38 >> 0x70,0);
1053: pcVar1[0x90] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
1054: pcVar1[0x91] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
1055: pcVar1[0x92] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
1056: pcVar1[0x93] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
1057: pcVar1[0x94] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
1058: pcVar1[0x95] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
1059: pcVar1[0x96] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
1060: pcVar1[0x97] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
1061: pcVar1[0x98] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
1062: pcVar1[0x99] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
1063: pcVar1[0x9a] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
1064: pcVar1[0x9b] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
1065: pcVar1[0x9c] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
1066: pcVar1[0x9d] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
1067: pcVar1[0x9e] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
1068: pcVar1[0x9f] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
1069: uVar26 = uStack28 + 0xa2;
1070: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1071: 0x60,0),
1072: CONCAT210(sVar41,(unkuint10)uVar26
1073: << 0x40)) >> 0x50,0
1074: ),(short)(uStack28 + 0xa1))) << 0x40) >> 0x30,0
1075: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1076: (undefined  [16])0xffffffff00000000;
1077: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
1078: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
1079: (unkuint10)0) >> 0x20,0) &
1080: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1081: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1082: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1083: uVar26 = uStack28 + 0xaa;
1084: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1085: 0x60,0),
1086: CONCAT210(sVar42,(unkuint10)uVar26
1087: << 0x40)) >> 0x50,0
1088: ),(short)(uStack28 + 0xa9))) << 0x40) >> 0x30,0
1089: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1090: (undefined  [16])0xffffffff00000000;
1091: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1092: CONCAT214(sVar25 + 0xa7,
1093: CONCAT212((short)((ulong)((uStack28 +
1094: 0xa6) * 
1095: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1096: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
1097: CONCAT28((short)((uStack28 + 0xa4) * 0x10000 >>
1098: 0x10),SUB168(auVar37,0))) >> 0x40,
1099: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0xa3) *
1100: 0x10000) & 0xffff0000)
1101: >> 0x10) << 0x30) >> 0x30,0),
1102: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1103: uStack28 + 0xa0 | (uStack28 + 0xa1) * 0x10000) & auVar36;
1104: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
1105: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
1106: (unkuint10)0) >> 0x20,0) &
1107: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1108: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1109: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1110: sVar41 = sVar25 + 0xb5;
1111: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1112: CONCAT214(sVar25 + 0xaf,
1113: CONCAT212((short)((ulong)((uStack28 +
1114: 0xae) * 
1115: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
1116: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
1117: CONCAT28((short)((uStack28 + 0xac) * 0x10000 >>
1118: 0x10),SUB168(auVar38,0))) >> 0x40,
1119: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0xab) *
1120: 0x10000) & 0xffff0000)
1121: >> 0x10) << 0x30) >> 0x30,0),
1122: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
1123: uStack28 + 0xa8 | (uStack28 + 0xa9) * 0x10000) & auVar36;
1124: sVar42 = sVar25 + 0xbd;
1125: uVar6 = SUB162(auVar37,0);
1126: uVar7 = SUB162(auVar37 >> 0x10,0);
1127: uVar8 = SUB162(auVar37 >> 0x20,0);
1128: sVar39 = SUB162(auVar37 >> 0x30,0);
1129: sVar40 = SUB162(auVar37 >> 0x40,0);
1130: sVar9 = SUB162(auVar37 >> 0x50,0);
1131: sVar10 = SUB162(auVar37 >> 0x60,0);
1132: sVar11 = SUB162(auVar37 >> 0x70,0);
1133: uVar12 = SUB162(auVar38,0);
1134: uVar13 = SUB162(auVar38 >> 0x10,0);
1135: uVar14 = SUB162(auVar38 >> 0x20,0);
1136: sVar15 = SUB162(auVar38 >> 0x30,0);
1137: sVar16 = SUB162(auVar38 >> 0x40,0);
1138: sVar17 = SUB162(auVar38 >> 0x50,0);
1139: sVar18 = SUB162(auVar38 >> 0x60,0);
1140: sVar19 = SUB162(auVar38 >> 0x70,0);
1141: pcVar1[0xa0] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
1142: pcVar1[0xa1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
1143: pcVar1[0xa2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
1144: pcVar1[0xa3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
1145: pcVar1[0xa4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
1146: pcVar1[0xa5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
1147: pcVar1[0xa6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
1148: pcVar1[0xa7] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
1149: pcVar1[0xa8] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
1150: pcVar1[0xa9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
1151: pcVar1[0xaa] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
1152: pcVar1[0xab] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
1153: pcVar1[0xac] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
1154: pcVar1[0xad] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
1155: pcVar1[0xae] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
1156: pcVar1[0xaf] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
1157: uVar26 = uStack28 + 0xb2;
1158: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1159: 0x60,0),
1160: CONCAT210(sVar41,(unkuint10)uVar26
1161: << 0x40)) >> 0x50,0
1162: ),(short)(uStack28 + 0xb1))) << 0x40) >> 0x30,0
1163: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1164: (undefined  [16])0xffffffff00000000;
1165: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
1166: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
1167: (unkuint10)0) >> 0x20,0) &
1168: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1169: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1170: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1171: uVar26 = uStack28 + 0xba;
1172: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1173: 0x60,0),
1174: CONCAT210(sVar42,(unkuint10)uVar26
1175: << 0x40)) >> 0x50,0
1176: ),(short)(uStack28 + 0xb9))) << 0x40) >> 0x30,0
1177: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1178: (undefined  [16])0xffffffff00000000;
1179: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1180: CONCAT214(sVar25 + 0xb7,
1181: CONCAT212((short)((ulong)((uStack28 +
1182: 0xb6) * 
1183: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1184: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
1185: CONCAT28((short)((uStack28 + 0xb4) * 0x10000 >>
1186: 0x10),SUB168(auVar37,0))) >> 0x40,
1187: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0xb3) *
1188: 0x10000) & 0xffff0000)
1189: >> 0x10) << 0x30) >> 0x30,0),
1190: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1191: uStack28 + 0xb0 | (uStack28 + 0xb1) * 0x10000) & auVar36;
1192: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
1193: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
1194: (unkuint10)0) >> 0x20,0) &
1195: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1196: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1197: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1198: sVar41 = sVar25 + 0xc5;
1199: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1200: CONCAT214(sVar25 + 0xbf,
1201: CONCAT212((short)((ulong)((uStack28 +
1202: 0xbe) * 
1203: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
1204: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
1205: CONCAT28((short)((uStack28 + 0xbc) * 0x10000 >>
1206: 0x10),SUB168(auVar38,0))) >> 0x40,
1207: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0xbb) *
1208: 0x10000) & 0xffff0000)
1209: >> 0x10) << 0x30) >> 0x30,0),
1210: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
1211: uStack28 + 0xb8 | (uStack28 + 0xb9) * 0x10000) & auVar36;
1212: uVar6 = SUB162(auVar37,0);
1213: uVar7 = SUB162(auVar37 >> 0x10,0);
1214: uVar8 = SUB162(auVar37 >> 0x20,0);
1215: sVar39 = SUB162(auVar37 >> 0x30,0);
1216: sVar40 = SUB162(auVar37 >> 0x40,0);
1217: sVar9 = SUB162(auVar37 >> 0x50,0);
1218: sVar10 = SUB162(auVar37 >> 0x60,0);
1219: sVar11 = SUB162(auVar37 >> 0x70,0);
1220: uVar12 = SUB162(auVar38,0);
1221: uVar13 = SUB162(auVar38 >> 0x10,0);
1222: uVar14 = SUB162(auVar38 >> 0x20,0);
1223: sVar15 = SUB162(auVar38 >> 0x30,0);
1224: sVar16 = SUB162(auVar38 >> 0x40,0);
1225: sVar17 = SUB162(auVar38 >> 0x50,0);
1226: sVar18 = SUB162(auVar38 >> 0x60,0);
1227: sVar19 = SUB162(auVar38 >> 0x70,0);
1228: pcVar1[0xb0] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
1229: pcVar1[0xb1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
1230: pcVar1[0xb2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
1231: pcVar1[0xb3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
1232: pcVar1[0xb4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
1233: pcVar1[0xb5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
1234: pcVar1[0xb6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
1235: pcVar1[0xb7] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
1236: pcVar1[0xb8] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
1237: pcVar1[0xb9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
1238: pcVar1[0xba] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
1239: pcVar1[0xbb] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
1240: pcVar1[0xbc] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
1241: pcVar1[0xbd] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
1242: pcVar1[0xbe] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
1243: pcVar1[0xbf] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
1244: uVar26 = uStack28 + 0xc2;
1245: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1246: 0x60,0),
1247: CONCAT210(sVar41,(unkuint10)uVar26
1248: << 0x40)) >> 0x50,0
1249: ),(short)(uStack28 + 0xc1))) << 0x40) >> 0x30,0
1250: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1251: (undefined  [16])0xffffffff00000000;
1252: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
1253: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
1254: (unkuint10)0) >> 0x20,0) &
1255: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1256: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1257: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1258: uVar26 = uStack28 + 0xca;
1259: sVar39 = sVar25 + 0xcd;
1260: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1261: 0x60,0),
1262: CONCAT210(sVar39,(unkuint10)uVar26
1263: << 0x40)) >> 0x50,0
1264: ),(short)(uStack28 + 0xc9))) << 0x40) >> 0x30,0
1265: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1266: (undefined  [16])0xffffffff00000000;
1267: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1268: CONCAT214(sVar25 + 199,
1269: CONCAT212((short)((ulong)((uStack28 +
1270: 0xc6) * 
1271: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1272: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
1273: CONCAT28((short)((uStack28 + 0xc4) * 0x10000 >>
1274: 0x10),SUB168(auVar37,0))) >> 0x40,
1275: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0xc3) *
1276: 0x10000) & 0xffff0000)
1277: >> 0x10) << 0x30) >> 0x30,0),
1278: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1279: uStack28 + 0xc0 | (uStack28 + 0xc1) * 0x10000) & auVar36;
1280: uVar43 = uStack28 + 0xf2;
1281: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
1282: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
1283: (unkuint10)0) >> 0x20,0) &
1284: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1285: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1286: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1287: sVar41 = sVar25 + 0xd5;
1288: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1289: CONCAT214(sVar25 + 0xcf,
1290: CONCAT212((short)((ulong)((uStack28 +
1291: 0xce) * 
1292: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
1293: CONCAT210(sVar39,SUB1610(auVar38,0))) >> 0x50,0),
1294: CONCAT28((short)((uStack28 + 0xcc) * 0x10000 >>
1295: 0x10),SUB168(auVar38,0))) >> 0x40,
1296: 0),(((ulong)CONCAT24(sVar39,(uStack28 + 0xcb) *
1297: 0x10000) & 0xffff0000)
1298: >> 0x10) << 0x30) >> 0x30,0),
1299: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
1300: uStack28 + 200 | (uStack28 + 0xc9) * 0x10000) & auVar36;
1301: sVar42 = sVar25 + 0xdd;
1302: uVar6 = SUB162(auVar37,0);
1303: uVar7 = SUB162(auVar37 >> 0x10,0);
1304: uVar8 = SUB162(auVar37 >> 0x20,0);
1305: sVar39 = SUB162(auVar37 >> 0x30,0);
1306: sVar40 = SUB162(auVar37 >> 0x40,0);
1307: sVar9 = SUB162(auVar37 >> 0x50,0);
1308: sVar10 = SUB162(auVar37 >> 0x60,0);
1309: sVar11 = SUB162(auVar37 >> 0x70,0);
1310: uVar12 = SUB162(auVar38,0);
1311: uVar13 = SUB162(auVar38 >> 0x10,0);
1312: uVar14 = SUB162(auVar38 >> 0x20,0);
1313: sVar15 = SUB162(auVar38 >> 0x30,0);
1314: sVar16 = SUB162(auVar38 >> 0x40,0);
1315: sVar17 = SUB162(auVar38 >> 0x50,0);
1316: sVar18 = SUB162(auVar38 >> 0x60,0);
1317: sVar19 = SUB162(auVar38 >> 0x70,0);
1318: pcVar1[0xc0] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
1319: pcVar1[0xc1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
1320: pcVar1[0xc2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
1321: pcVar1[0xc3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
1322: pcVar1[0xc4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
1323: pcVar1[0xc5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
1324: pcVar1[0xc6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
1325: pcVar1[199] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
1326: pcVar1[200] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
1327: pcVar1[0xc9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
1328: pcVar1[0xca] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
1329: pcVar1[0xcb] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
1330: pcVar1[0xcc] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
1331: pcVar1[0xcd] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
1332: pcVar1[0xce] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
1333: pcVar1[0xcf] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
1334: uVar26 = uStack28 + 0xd2;
1335: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1336: 0x60,0),
1337: CONCAT210(sVar41,(unkuint10)uVar26
1338: << 0x40)) >> 0x50,0
1339: ),(short)(uStack28 + 0xd1))) << 0x40) >> 0x30,0
1340: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1341: (undefined  [16])0xffffffff00000000;
1342: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
1343: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
1344: (unkuint10)0) >> 0x20,0) &
1345: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1346: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1347: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1348: uVar26 = uStack28 + 0xda;
1349: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1350: 0x60,0),
1351: CONCAT210(sVar42,(unkuint10)uVar26
1352: << 0x40)) >> 0x50,0
1353: ),(short)(uStack28 + 0xd9))) << 0x40) >> 0x30,0
1354: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1355: (undefined  [16])0xffffffff00000000;
1356: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1357: CONCAT214(sVar25 + 0xd7,
1358: CONCAT212((short)((ulong)((uStack28 +
1359: 0xd6) * 
1360: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1361: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
1362: CONCAT28((short)((uStack28 + 0xd4) * 0x10000 >>
1363: 0x10),SUB168(auVar37,0))) >> 0x40,
1364: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0xd3) *
1365: 0x10000) & 0xffff0000)
1366: >> 0x10) << 0x30) >> 0x30,0),
1367: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1368: uStack28 + 0xd0 | (uStack28 + 0xd1) * 0x10000) & auVar36;
1369: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
1370: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
1371: (unkuint10)0) >> 0x20,0) &
1372: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1373: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1374: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1375: sVar41 = sVar25 + 0xe5;
1376: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1377: CONCAT214(sVar25 + 0xdf,
1378: CONCAT212((short)((ulong)((uStack28 +
1379: 0xde) * 
1380: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
1381: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
1382: CONCAT28((short)((uStack28 + 0xdc) * 0x10000 >>
1383: 0x10),SUB168(auVar38,0))) >> 0x40,
1384: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0xdb) *
1385: 0x10000) & 0xffff0000)
1386: >> 0x10) << 0x30) >> 0x30,0),
1387: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
1388: uStack28 + 0xd8 | (uStack28 + 0xd9) * 0x10000) & auVar36;
1389: sVar42 = sVar25 + 0xed;
1390: uVar6 = SUB162(auVar37,0);
1391: uVar7 = SUB162(auVar37 >> 0x10,0);
1392: uVar8 = SUB162(auVar37 >> 0x20,0);
1393: sVar39 = SUB162(auVar37 >> 0x30,0);
1394: sVar40 = SUB162(auVar37 >> 0x40,0);
1395: sVar9 = SUB162(auVar37 >> 0x50,0);
1396: sVar10 = SUB162(auVar37 >> 0x60,0);
1397: sVar11 = SUB162(auVar37 >> 0x70,0);
1398: uVar12 = SUB162(auVar38,0);
1399: uVar13 = SUB162(auVar38 >> 0x10,0);
1400: uVar14 = SUB162(auVar38 >> 0x20,0);
1401: sVar15 = SUB162(auVar38 >> 0x30,0);
1402: sVar16 = SUB162(auVar38 >> 0x40,0);
1403: sVar17 = SUB162(auVar38 >> 0x50,0);
1404: sVar18 = SUB162(auVar38 >> 0x60,0);
1405: sVar19 = SUB162(auVar38 >> 0x70,0);
1406: pcVar1[0xd0] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
1407: pcVar1[0xd1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
1408: pcVar1[0xd2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
1409: pcVar1[0xd3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
1410: pcVar1[0xd4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
1411: pcVar1[0xd5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
1412: pcVar1[0xd6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
1413: pcVar1[0xd7] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
1414: pcVar1[0xd8] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
1415: pcVar1[0xd9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
1416: pcVar1[0xda] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
1417: pcVar1[0xdb] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
1418: pcVar1[0xdc] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
1419: pcVar1[0xdd] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
1420: pcVar1[0xde] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
1421: pcVar1[0xdf] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
1422: uVar26 = uStack28 + 0xe2;
1423: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1424: 0x60,0),
1425: CONCAT210(sVar41,(unkuint10)uVar26
1426: << 0x40)) >> 0x50,0
1427: ),(short)(uStack28 + 0xe1))) << 0x40) >> 0x30,0
1428: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1429: (undefined  [16])0xffffffff00000000;
1430: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
1431: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
1432: (unkuint10)0) >> 0x20,0) &
1433: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1434: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1435: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1436: uVar26 = uStack28 + 0xea;
1437: auVar38 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40) >>
1438: 0x60,0),
1439: CONCAT210(sVar42,(unkuint10)uVar26
1440: << 0x40)) >> 0x50,0
1441: ),(short)(uStack28 + 0xe9))) << 0x40) >> 0x30,0
1442: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
1443: (undefined  [16])0xffffffff00000000;
1444: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1445: CONCAT214(sVar25 + 0xe7,
1446: CONCAT212((short)((ulong)((uStack28 +
1447: 0xe6) * 
1448: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1449: CONCAT210(sVar41,SUB1610(auVar37,0))) >> 0x50,0),
1450: CONCAT28((short)((uStack28 + 0xe4) * 0x10000 >>
1451: 0x10),SUB168(auVar37,0))) >> 0x40,
1452: 0),(((ulong)CONCAT24(sVar41,(uStack28 + 0xe3) *
1453: 0x10000) & 0xffff0000)
1454: >> 0x10) << 0x30) >> 0x30,0),
1455: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1456: uStack28 + 0xe0 | (uStack28 + 0xe1) * 0x10000) & auVar36;
1457: auVar38 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar38 >> 0x60,0),
1458: ZEXT1012(SUB1610(auVar38,0))) >> 0x50,0),
1459: (unkuint10)0) >> 0x20,0) &
1460: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1461: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1462: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1463: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1464: CONCAT214(sVar25 + 0xef,
1465: CONCAT212((short)((ulong)((uStack28 +
1466: 0xee) * 
1467: 0x10000) >> 0x10),SUB1612(auVar38,0))) >> 0x60,0),
1468: CONCAT210(sVar42,SUB1610(auVar38,0))) >> 0x50,0),
1469: CONCAT28((short)((uStack28 + 0xec) * 0x10000 >>
1470: 0x10),SUB168(auVar38,0))) >> 0x40,
1471: 0),(((ulong)CONCAT24(sVar42,(uStack28 + 0xeb) *
1472: 0x10000) & 0xffff0000)
1473: >> 0x10) << 0x30) >> 0x30,0),
1474: (SUB166(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
1475: uStack28 + 0xe8 | (uStack28 + 0xe9) * 0x10000) & auVar36;
1476: uVar6 = SUB162(auVar37,0);
1477: uVar7 = SUB162(auVar37 >> 0x10,0);
1478: uVar8 = SUB162(auVar37 >> 0x20,0);
1479: sVar39 = SUB162(auVar37 >> 0x30,0);
1480: sVar40 = SUB162(auVar37 >> 0x40,0);
1481: sVar9 = SUB162(auVar37 >> 0x50,0);
1482: sVar10 = SUB162(auVar37 >> 0x60,0);
1483: sVar11 = SUB162(auVar37 >> 0x70,0);
1484: uVar12 = SUB162(auVar38,0);
1485: uVar13 = SUB162(auVar38 >> 0x10,0);
1486: uVar14 = SUB162(auVar38 >> 0x20,0);
1487: sVar15 = SUB162(auVar38 >> 0x30,0);
1488: sVar16 = SUB162(auVar38 >> 0x40,0);
1489: sVar17 = SUB162(auVar38 >> 0x50,0);
1490: sVar18 = SUB162(auVar38 >> 0x60,0);
1491: sVar19 = SUB162(auVar38 >> 0x70,0);
1492: pcVar1[0xe0] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar37,0) - (0xff < uVar6);
1493: pcVar1[0xe1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar37 >> 0x10,0) - (0xff < uVar7);
1494: pcVar1[0xe2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar37 >> 0x20,0) - (0xff < uVar8);
1495: pcVar1[0xe3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar37 >> 0x30,0) - (0xff < sVar39);
1496: pcVar1[0xe4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar37 >> 0x40,0) - (0xff < sVar40);
1497: pcVar1[0xe5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar37 >> 0x50,0) - (0xff < sVar9);
1498: pcVar1[0xe6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar37 >> 0x60,0) - (0xff < sVar10);
1499: pcVar1[0xe7] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar37 >> 0x70,0) - (0xff < sVar11);
1500: pcVar1[0xe8] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar38,0) - (0xff < uVar12);
1501: pcVar1[0xe9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar13);
1502: pcVar1[0xea] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar14);
1503: pcVar1[0xeb] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar15);
1504: pcVar1[0xec] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar16);
1505: pcVar1[0xed] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar17);
1506: pcVar1[0xee] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar18);
1507: pcVar1[0xef] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar19);
1508: if (uVar32 >> 4 == 0x10) {
1509: sVar40 = sVar25 + 0xf5;
1510: auVar37 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar43) << 0x40)
1511: >> 0x60,0),
1512: CONCAT210(sVar40,(unkuint10)uVar43
1513: << 0x40)) >> 0x50
1514: ,0),(short)(uStack28 + 0xf1))) << 0x40) >>
1515: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) <<
1516: 0x30 & (undefined  [16])0xffffffff00000000;
1517: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar37 >> 0x60,0),
1518: ZEXT1012(SUB1610(auVar37,0))) >> 0x50,0),
1519: (unkuint10)0) >> 0x20,0) &
1520: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1521: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1522: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar43 * 0x10000);
1523: uVar26 = uStack28 + 0xfa;
1524: sVar39 = sVar25 + 0xfd;
1525: auVar44 = ZEXT1016(SUB1610((ZEXT816(CONCAT62(SUB166(CONCAT412(SUB164((ZEXT416(uVar26) << 0x40)
1526: >> 0x60,0),
1527: CONCAT210(sVar39,(unkuint10)uVar26
1528: << 0x40)) >> 0x50
1529: ,0),(short)(uStack28 + 0xf9))) << 0x40) >>
1530: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) <<
1531: 0x30 & (undefined  [16])0xffffffff00000000;
1532: auVar38 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
1533: CONCAT214(sVar25 + 0xf7,
1534: CONCAT212((short)((ulong)((uStack28 +
1535: 0xf6) * 
1536: 0x10000) >> 0x10),SUB1612(auVar37,0))) >> 0x60,0),
1537: CONCAT210(sVar40,SUB1610(auVar37,0))) >> 0x50,0),
1538: CONCAT28((short)((uStack28 + 0xf4) * 0x10000 >>
1539: 0x10),SUB168(auVar37,0))) >> 0x40,
1540: 0),(((ulong)CONCAT24(sVar40,(uStack28 + 0xf3) *
1541: 0x10000) & 0xffff0000)
1542: >> 0x10) << 0x30) >> 0x30,0),
1543: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1544: uStack28 + 0xf0 | (uStack28 + 0xf1) * 0x10000) & auVar36;
1545: auVar37 = CONCAT124(SUB1612(CONCAT610(SUB166(CONCAT412(SUB164(auVar44 >> 0x60,0),
1546: ZEXT1012(SUB1610(auVar44,0))) >> 0x50,0),
1547: (unkuint10)0) >> 0x20,0) &
1548: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1549: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1550: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),uVar26 * 0x10000);
1551: auVar36 = auVar36 & CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(
1552: CONCAT412(SUB164(CONCAT214(sVar25 + 0xff,
1553: CONCAT212((short)((
1554: ulong)((uStack28 + 0xfe) * 0x10000) >> 0x10),
1555: SUB1612(auVar37,0))) >> 0x60,0),
1556: CONCAT210(sVar39,SUB1610(auVar37,0))) >> 0x50,0),
1557: CONCAT28((short)((uStack28 + 0xfc) * 0x10000 >>
1558: 0x10),SUB168(auVar37,0))) >> 0x40,
1559: 0),(((ulong)CONCAT24(sVar39,(uStack28 + 0xfb) *
1560: 0x10000) & 0xffff0000)
1561: >> 0x10) << 0x30) >> 0x30,0),
1562: (SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
1563: uStack28 + 0xf8 | (uStack28 + 0xf9) * 0x10000);
1564: uVar35 = SUB168(auVar36,0);
1565: uVar6 = SUB162(auVar38,0);
1566: uVar7 = SUB162(auVar38 >> 0x10,0);
1567: uVar8 = SUB162(auVar38 >> 0x20,0);
1568: sVar39 = SUB162(auVar38 >> 0x30,0);
1569: sVar40 = SUB162(auVar38 >> 0x40,0);
1570: sVar9 = SUB162(auVar38 >> 0x50,0);
1571: sVar10 = SUB162(auVar38 >> 0x60,0);
1572: sVar11 = SUB162(auVar38 >> 0x70,0);
1573: uVar12 = SUB162(auVar36,0);
1574: uVar13 = SUB162(auVar36 >> 0x10,0);
1575: uVar14 = SUB162(auVar36 >> 0x20,0);
1576: sVar15 = SUB162(auVar36 >> 0x30,0);
1577: sVar16 = SUB162(auVar36 >> 0x40,0);
1578: sVar17 = SUB162(auVar36 >> 0x50,0);
1579: sVar18 = SUB162(auVar36 >> 0x60,0);
1580: sVar19 = SUB162(auVar36 >> 0x70,0);
1581: pcVar1[0xf0] = (uVar6 != 0) * (uVar6 < 0xff) * SUB161(auVar38,0) - (0xff < uVar6);
1582: pcVar1[0xf1] = (uVar7 != 0) * (uVar7 < 0xff) * SUB161(auVar38 >> 0x10,0) - (0xff < uVar7);
1583: pcVar1[0xf2] = (uVar8 != 0) * (uVar8 < 0xff) * SUB161(auVar38 >> 0x20,0) - (0xff < uVar8);
1584: pcVar1[0xf3] = (0 < sVar39) * (sVar39 < 0xff) * SUB161(auVar38 >> 0x30,0) - (0xff < sVar39);
1585: pcVar1[0xf4] = (0 < sVar40) * (sVar40 < 0xff) * SUB161(auVar38 >> 0x40,0) - (0xff < sVar40);
1586: pcVar1[0xf5] = (0 < sVar9) * (sVar9 < 0xff) * SUB161(auVar38 >> 0x50,0) - (0xff < sVar9);
1587: pcVar1[0xf6] = (0 < sVar10) * (sVar10 < 0xff) * SUB161(auVar38 >> 0x60,0) - (0xff < sVar10);
1588: pcVar1[0xf7] = (0 < sVar11) * (sVar11 < 0xff) * SUB161(auVar38 >> 0x70,0) - (0xff < sVar11);
1589: pcVar1[0xf8] = (uVar12 != 0) * (uVar12 < 0xff) * SUB161(auVar36,0) - (0xff < uVar12);
1590: pcVar1[0xf9] = (uVar13 != 0) * (uVar13 < 0xff) * SUB161(auVar36 >> 0x10,0) - (0xff < uVar13);
1591: pcVar1[0xfa] = (uVar14 != 0) * (uVar14 < 0xff) * SUB161(auVar36 >> 0x20,0) - (0xff < uVar14);
1592: pcVar1[0xfb] = (0 < sVar15) * (sVar15 < 0xff) * SUB161(auVar36 >> 0x30,0) - (0xff < sVar15);
1593: pcVar1[0xfc] = (0 < sVar16) * (sVar16 < 0xff) * SUB161(auVar36 >> 0x40,0) - (0xff < sVar16);
1594: pcVar1[0xfd] = (0 < sVar17) * (sVar17 < 0xff) * SUB161(auVar36 >> 0x50,0) - (0xff < sVar17);
1595: pcVar1[0xfe] = (0 < sVar18) * (sVar18 < 0xff) * SUB161(auVar36 >> 0x60,0) - (0xff < sVar18);
1596: pcVar1[0xff] = (0 < sVar19) * (sVar19 < 0xff) * SUB161(auVar36 >> 0x70,0) - (0xff < sVar19);
1597: }
1598: uVar26 = uVar32 & 0xfffffff0;
1599: iVar30 = iVar30 - uVar26;
1600: iVar27 = uStack28 + uVar26;
1601: if (uVar32 != uVar26) {
1602: *(char *)((long)puVar29 + (long)iVar27 + 0x100) = (char)iVar27;
1603: if (iVar30 != 1) {
1604: *(char *)((long)puVar29 + (long)(iVar27 + 1) + 0x100) = (char)(iVar27 + 1);
1605: if (iVar30 != 2) {
1606: *(char *)((long)puVar29 + (long)(iVar27 + 2) + 0x100) = (char)(iVar27 + 2);
1607: if (iVar30 != 3) {
1608: *(char *)((long)puVar29 + (long)(iVar27 + 3) + 0x100) = (char)(iVar27 + 3);
1609: if (iVar30 != 4) {
1610: *(char *)((long)puVar29 + (long)(iVar27 + 4) + 0x100) = (char)(iVar27 + 4);
1611: if (iVar30 != 5) {
1612: *(char *)((long)puVar29 + (long)(iVar27 + 5) + 0x100) = (char)(iVar27 + 5);
1613: if (iVar30 != 6) {
1614: *(char *)((long)puVar29 + (long)(iVar27 + 6) + 0x100) = (char)(iVar27 + 6);
1615: if (iVar30 != 7) {
1616: *(char *)((long)puVar29 + (long)(iVar27 + 7) + 0x100) = (char)(iVar27 + 7);
1617: if (iVar30 != 8) {
1618: *(char *)((long)puVar29 + (long)(iVar27 + 8) + 0x100) = (char)(iVar27 + 8);
1619: if (iVar30 != 9) {
1620: *(char *)((long)puVar29 + (long)(iVar27 + 9) + 0x100) = (char)(iVar27 + 9);
1621: if (iVar30 != 10) {
1622: *(char *)((long)puVar29 + (long)(iVar27 + 10) + 0x100) = (char)(iVar27 + 10)
1623: ;
1624: if (iVar30 != 0xb) {
1625: *(char *)((long)puVar29 + (long)(iVar27 + 0xb) + 0x100) =
1626: (char)(iVar27 + 0xb);
1627: if (iVar30 != 0xc) {
1628: *(char *)((long)puVar29 + (long)(iVar27 + 0xc) + 0x100) =
1629: (char)(iVar27 + 0xc);
1630: if (iVar30 != 0xd) {
1631: *(char *)((long)puVar29 + (long)(iVar27 + 0xd) + 0x100) =
1632: (char)(iVar27 + 0xd);
1633: if (iVar30 != 0xe) {
1634: *(char *)((long)puVar29 + (long)(iVar27 + 0xe) + 0x100) =
1635: (char)(iVar27 + 0xe);
1636: }
1637: }
1638: }
1639: }
1640: }
1641: }
1642: }
1643: }
1644: }
1645: }
1646: }
1647: }
1648: }
1649: }
1650: }
1651: puVar29[0x40] = 0xffffffffffffffff;
1652: puVar29[0x6f] = 0xffffffffffffffff;
1653: uVar31 = (ulong)((iVar28 - (int)(undefined8 *)((ulong)(puVar29 + 0x41) & 0xfffffffffffffff8)) +
1654: 0x380U >> 3);
1655: puVar33 = (undefined8 *)((ulong)(puVar29 + 0x41) & 0xfffffffffffffff8);
1656: while (uVar31 != 0) {
1657: uVar31 = uVar31 - 1;
1658: *puVar33 = 0xffffffffffffffff;
1659: puVar33 = puVar33 + (ulong)bVar34 * -2 + 1;
1660: }
1661: puVar29[0x70] = 0;
1662: puVar29[0x9f] = 0;
1663: uVar31 = (ulong)((iVar28 - (int)(undefined8 *)((ulong)(puVar29 + 0x71) & 0xfffffffffffffff8)) +
1664: 0x500U >> 3);
1665: puVar33 = (undefined8 *)((ulong)(puVar29 + 0x71) & 0xfffffffffffffff8);
1666: while (uVar31 != 0) {
1667: uVar31 = uVar31 - 1;
1668: *puVar33 = 0;
1669: puVar33 = puVar33 + (ulong)bVar34 * -2 + 1;
1670: }
1671: puVar3 = (undefined4 *)param_1[0x35];
1672: uVar22 = puVar3[1];
1673: uVar23 = puVar3[2];
1674: uVar24 = puVar3[3];
1675: *(undefined4 *)(puVar29 + 0xa0) = *puVar3;
1676: *(undefined4 *)((long)puVar29 + 0x504) = uVar22;
1677: *(undefined4 *)(puVar29 + 0xa1) = uVar23;
1678: *(undefined4 *)((long)puVar29 + 0x50c) = uVar24;
1679: uVar22 = puVar3[5];
1680: uVar23 = puVar3[6];
1681: uVar24 = puVar3[7];
1682: *(undefined4 *)(puVar29 + 0xa2) = puVar3[4];
1683: *(undefined4 *)((long)puVar29 + 0x514) = uVar22;
1684: *(undefined4 *)(puVar29 + 0xa3) = uVar23;
1685: *(undefined4 *)((long)puVar29 + 0x51c) = uVar24;
1686: uVar22 = puVar3[9];
1687: uVar23 = puVar3[10];
1688: uVar24 = puVar3[0xb];
1689: *(undefined4 *)(puVar29 + 0xa4) = puVar3[8];
1690: *(undefined4 *)((long)puVar29 + 0x524) = uVar22;
1691: *(undefined4 *)(puVar29 + 0xa5) = uVar23;
1692: *(undefined4 *)((long)puVar29 + 0x52c) = uVar24;
1693: uVar22 = puVar3[0xd];
1694: uVar23 = puVar3[0xe];
1695: uVar24 = puVar3[0xf];
1696: *(undefined4 *)(puVar29 + 0xa6) = puVar3[0xc];
1697: *(undefined4 *)((long)puVar29 + 0x534) = uVar22;
1698: *(undefined4 *)(puVar29 + 0xa7) = uVar23;
1699: *(undefined4 *)((long)puVar29 + 0x53c) = uVar24;
1700: uVar22 = puVar3[0x11];
1701: uVar23 = puVar3[0x12];
1702: uVar24 = puVar3[0x13];
1703: *(undefined4 *)(puVar29 + 0xa8) = puVar3[0x10];
1704: *(undefined4 *)((long)puVar29 + 0x544) = uVar22;
1705: *(undefined4 *)(puVar29 + 0xa9) = uVar23;
1706: *(undefined4 *)((long)puVar29 + 0x54c) = uVar24;
1707: uVar22 = puVar3[0x15];
1708: uVar23 = puVar3[0x16];
1709: uVar24 = puVar3[0x17];
1710: *(undefined4 *)(puVar29 + 0xaa) = puVar3[0x14];
1711: *(undefined4 *)((long)puVar29 + 0x554) = uVar22;
1712: *(undefined4 *)(puVar29 + 0xab) = uVar23;
1713: *(undefined4 *)((long)puVar29 + 0x55c) = uVar24;
1714: uVar22 = puVar3[0x19];
1715: uVar23 = puVar3[0x1a];
1716: uVar24 = puVar3[0x1b];
1717: *(undefined4 *)(puVar29 + 0xac) = puVar3[0x18];
1718: *(undefined4 *)((long)puVar29 + 0x564) = uVar22;
1719: *(undefined4 *)(puVar29 + 0xad) = uVar23;
1720: *(undefined4 *)((long)puVar29 + 0x56c) = uVar24;
1721: uVar20 = *(undefined8 *)(puVar3 + 0x1c);
1722: uVar21 = *(undefined8 *)(puVar3 + 0x1e);
1723: puVar29[0xae] = uVar20;
1724: puVar29[0xaf] = uVar21;
1725: if ((ulong)*(uint *)(param_1 + 0x11) * (long)*(int *)(param_1 + 0x12) -
1726: ((ulong)*(uint *)(param_1 + 0x11) * (long)*(int *)(param_1 + 0x12) & 0xffffffff) != 0) {
1727: ppcVar4 = (code **)*param_1;
1728: *(undefined4 *)(ppcVar4 + 5) = 0x46;
1729: (**ppcVar4)(uVar20,uVar35);
1730: }
1731: iVar28 = *(int *)((long)param_1 + 100);
1732: *(undefined4 *)(ppcVar2 + 0xf) = 0;
1733: if (iVar28 == 0) {
1734: if ((*(int *)(param_1 + 0x31) == 0) && (param_1[7] == (code *)0x300000003)) {
1735: iVar28 = FUN_00136e10(param_1);
1736: }
1737: }
1738: else {
1739: iVar28 = 0;
1740: }
1741: iVar30 = *(int *)((long)param_1 + 0x6c);
1742: *(int *)((long)ppcVar2 + 0x7c) = iVar28;
1743: ppcVar2[0x10] = (code *)0x0;
1744: ppcVar2[0x11] = (code *)0x0;
1745: if (iVar30 == 0) {
1746: *(undefined8 *)((long)param_1 + 0x7c) = 0;
1747: *(undefined4 *)((long)param_1 + 0x84) = 0;
1748: goto LAB_001382f1;
1749: }
1750: if (*(int *)(param_1 + 0xb) == 0) {
1751: *(undefined8 *)((long)param_1 + 0x7c) = 0;
1752: *(undefined4 *)((long)param_1 + 0x84) = 0;
1753: }
1754: if (*(int *)((long)param_1 + 0x5c) != 0) {
1755: ppcVar4 = (code **)*param_1;
1756: *(undefined4 *)(ppcVar4 + 5) = 0x2f;
1757: (**ppcVar4)(param_1);
1758: }
1759: if (*(int *)(param_1 + 0x12) == 3) {
1760: if (param_1[0x14] == (code *)0x0) {
1761: if (*(int *)((long)param_1 + 0x74) == 0) {
1762: *(undefined4 *)((long)param_1 + 0x7c) = 1;
1763: goto LAB_001382cd;
1764: }
1765: *(undefined4 *)((long)param_1 + 0x84) = 1;
1766: }
1767: else {
1768: *(undefined4 *)(param_1 + 0x10) = 1;
1769: }
1770: if (*(int *)((long)param_1 + 0x7c) != 0) goto LAB_001382cd;
1771: pcVar5 = param_1[0x10];
1772: }
1773: else {
1774: *(undefined8 *)((long)param_1 + 0x7c) = 1;
1775: *(undefined4 *)((long)param_1 + 0x84) = 0;
1776: param_1[0x14] = (code *)0x0;
1777: LAB_001382cd:
1778: FUN_00145d10(param_1);
1779: pcVar5 = param_1[0x10];
1780: ppcVar2[0x10] = param_1[0x4e];
1781: }
1782: if (pcVar5 != (code *)0x0) {
1783: /* WARNING: Read-only address (ram,0x0016c610) is written */
1784: FUN_00148820(param_1);
1785: ppcVar2[0x11] = param_1[0x4e];
1786: }
1787: LAB_001382f1:
1788: if (*(int *)((long)param_1 + 0x5c) == 0) {
1789: if (*(int *)((long)ppcVar2 + 0x7c) == 0) {
1790: FUN_0012e720(param_1);
1791: FUN_0013d9c0(param_1);
1792: }
1793: else {
1794: FUN_0013ada0();
1795: }
1796: FUN_0013c7e0(param_1,*(undefined4 *)((long)param_1 + 0x84));
1797: }
1798: FUN_0012fa40(param_1);
1799: if (*(int *)((long)param_1 + 0x13c) == 0) {
1800: if (*(int *)(param_1 + 0x27) == 0) {
1801: FUN_00132390();
1802: }
1803: else {
1804: FUN_0013c3d0();
1805: }
1806: }
1807: else {
1808: FUN_0014e140(param_1);
1809: }
1810: FUN_00129eb0(param_1);
1811: if (*(int *)((long)param_1 + 0x5c) == 0) {
1812: FUN_00134190(param_1);
1813: }
1814: (**(code **)(param_1[1] + 0x30))(param_1);
1815: (**(code **)(param_1[0x48] + 0x10))();
1816: iVar28 = *(int *)(param_1 + 0x3b);
1817: pcVar5 = param_1[0x44];
1818: *(undefined4 *)(pcVar5 + 0x14) = 0;
1819: *(undefined4 *)(pcVar5 + 0x70) = 0;
1820: *(int *)(pcVar5 + 0x18) = iVar28 + -1;
1821: pcVar5 = param_1[2];
1822: if (((pcVar5 != (code *)0x0) && (*(int *)(param_1 + 0xb) == 0)) &&
1823: (*(int *)(param_1[0x48] + 0x20) != 0)) {
1824: iVar28 = *(int *)(param_1 + 7);
1825: if (*(int *)(param_1 + 0x27) != 0) {
1826: iVar28 = iVar28 * 3 + 2;
1827: }
1828: uVar26 = *(uint *)((long)param_1 + 0x1a4);
1829: *(undefined8 *)(pcVar5 + 8) = 0;
1830: *(undefined4 *)(pcVar5 + 0x18) = 0;
1831: iVar30 = *(int *)((long)param_1 + 0x84);
1832: *(ulong *)(pcVar5 + 0x10) = (long)iVar28 * (ulong)uVar26;
1833: *(uint *)(pcVar5 + 0x1c) = (iVar30 != 0) + 2;
1834: *(int *)(ppcVar2 + 0xf) = *(int *)(ppcVar2 + 0xf) + 1;
1835: }
1836: return;
1837: }
1838: 

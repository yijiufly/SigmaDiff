1: 
2: /* WARNING: Removing unreachable block (ram,0x001255a8) */
3: 
4: void FUN_00125450(code **param_1,int param_2,uint param_3,long *param_4)
5: 
6: {
7: code cVar1;
8: char cVar2;
9: code **ppcVar3;
10: byte bVar4;
11: uint uVar5;
12: uint uVar6;
13: uint uVar7;
14: uint uVar8;
15: long lVar9;
16: byte bVar10;
17: undefined (*pauVar11) [16];
18: uint uVar12;
19: code *pcVar13;
20: long lVar14;
21: ulong uVar15;
22: int iVar16;
23: int iVar17;
24: int iVar18;
25: undefined4 *puVar19;
26: undefined (*pauVar20) [16];
27: long lVar21;
28: int iVar22;
29: code *pcVar23;
30: long in_FS_OFFSET;
31: uint uVar24;
32: uint5 uVar25;
33: undefined8 uVar26;
34: undefined uVar30;
35: undefined auVar31 [16];
36: long lStack1408;
37: int iStack1380;
38: uint auStack1368 [260];
39: char acStack328 [264];
40: long lStack64;
41: undefined auVar27 [12];
42: undefined auVar28 [12];
43: undefined auVar29 [14];
44: undefined auVar32 [13];
45: 
46: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
47: if (3 < param_3) {
48: pcVar23 = *param_1;
49: *(undefined4 *)(pcVar23 + 0x28) = 0x32;
50: *(uint *)(pcVar23 + 0x2c) = param_3;
51: (**(code **)*param_1)();
52: }
53: if (param_2 == 0) {
54: pcVar23 = param_1[(long)(int)param_3 + 0x21];
55: }
56: else {
57: pcVar23 = param_1[(long)(int)param_3 + 0x1d];
58: }
59: if (pcVar23 == (code *)0x0) {
60: pcVar13 = *param_1;
61: *(undefined4 *)(pcVar13 + 0x28) = 0x32;
62: *(uint *)(pcVar13 + 0x2c) = param_3;
63: (**(code **)*param_1)();
64: }
65: lVar9 = *param_4;
66: if (lVar9 == 0) {
67: lVar9 = (**(code **)param_1[1])(param_1,1,0x528);
68: *param_4 = lVar9;
69: }
70: *(code **)(lVar9 + 0x120) = pcVar23;
71: lVar14 = 0;
72: iStack1380 = 0;
73: do {
74: cVar1 = pcVar23[lVar14 + 1];
75: if (0x100 < (int)(iStack1380 + (uint)(byte)cVar1)) {
76: *(undefined4 *)(*param_1 + 0x28) = 8;
77: (**(code **)*param_1)();
78: }
79: if (cVar1 != (code)0x0) {
80: memset(acStack328 + iStack1380,(int)lVar14 + 1,(ulong)(byte)cVar1);
81: iStack1380 = iStack1380 + (uint)(byte)cVar1;
82: }
83: lVar14 = lVar14 + 1;
84: } while (lVar14 != 0x10);
85: acStack328[iStack1380] = '\0';
86: iVar22 = (int)acStack328[0];
87: if (acStack328[0] != '\0') {
88: uVar15 = 0;
89: lVar14 = 0;
90: iVar16 = iVar22;
91: LAB_001255b3:
92: while( true ) {
93: iVar17 = (int)lVar14 + 1;
94: auStack1368[lVar14] = (uint)uVar15;
95: uVar6 = (uint)uVar15 + 1;
96: uVar15 = (ulong)uVar6;
97: cVar2 = acStack328[iVar17];
98: iVar18 = (int)cVar2;
99: if (iVar18 != iVar16) break;
100: lVar14 = (long)iVar17;
101: }
102: if (1 << ((byte)iVar22 & 0x3f) <= (long)uVar15) goto LAB_00125609;
103: while (cVar2 != '\0') {
104: while( true ) {
105: uVar6 = uVar6 * 2;
106: iVar22 = iVar22 + 1;
107: uVar15 = (ulong)uVar6;
108: lVar14 = (long)iVar17;
109: iVar16 = iVar18;
110: if (iVar18 == iVar22) goto LAB_001255b3;
111: if ((long)uVar15 < 1 << ((byte)iVar22 & 0x3f)) break;
112: LAB_00125609:
113: ppcVar3 = (code **)*param_1;
114: *(undefined4 *)(ppcVar3 + 5) = 8;
115: (**ppcVar3)();
116: if (cVar2 == '\0') goto LAB_0012562a;
117: }
118: }
119: }
120: LAB_0012562a:
121: lVar14 = 0;
122: iVar22 = 0;
123: do {
124: while (pcVar23[lVar14 + 1] == (code)0x0) {
125: *(undefined8 *)(lVar9 + 8 + lVar14 * 8) = 0xffffffffffffffff;
126: lVar14 = lVar14 + 1;
127: if (lVar14 == 0x10) goto LAB_0012567e;
128: }
129: *(ulong *)(lVar9 + 0x98 + lVar14 * 8) = (long)iVar22 - (ulong)auStack1368[iVar22];
130: iVar22 = iVar22 + (uint)(byte)pcVar23[lVar14 + 1];
131: *(ulong *)(lVar9 + 8 + lVar14 * 8) = (ulong)auStack1368[iVar22 + -1];
132: lVar14 = lVar14 + 1;
133: } while (lVar14 != 0x10);
134: LAB_0012567e:
135: *(undefined8 *)(lVar9 + 0x118) = 0;
136: *(undefined8 *)(lVar9 + 0x88) = 0xfffff;
137: uVar6 = -(((int)lVar9 + 0x128U & 0xf) >> 2) & 3;
138: if (uVar6 == 0) {
139: iVar22 = 0x100;
140: iVar16 = 0;
141: }
142: else {
143: *(undefined4 *)(lVar9 + 0x128) = 0x900;
144: if (uVar6 < 2) {
145: iVar22 = 0xff;
146: iVar16 = 1;
147: }
148: else {
149: *(undefined4 *)(lVar9 + 300) = 0x900;
150: if (uVar6 < 3) {
151: iVar22 = 0xfe;
152: iVar16 = 2;
153: }
154: else {
155: *(undefined4 *)(lVar9 + 0x130) = 0x900;
156: iVar22 = 0xfd;
157: iVar16 = 3;
158: }
159: }
160: }
161: uVar12 = 0x100 - uVar6;
162: uVar7 = 0;
163: puVar19 = (undefined4 *)(lVar9 + 0x128 + (ulong)uVar6 * 4);
164: do {
165: uVar7 = uVar7 + 1;
166: *puVar19 = 0x900;
167: puVar19[1] = 0x900;
168: puVar19[2] = 0x900;
169: puVar19[3] = 0x900;
170: puVar19 = puVar19 + 4;
171: } while (uVar7 < uVar12 >> 2);
172: iVar16 = iVar16 + (uVar12 & 0xfffffffc);
173: iVar22 = iVar22 + (uVar12 >> 2) * -4;
174: if (uVar12 != (uVar12 & 0xfffffffc)) {
175: *(undefined4 *)(lVar9 + 0x128 + (long)iVar16 * 4) = 0x900;
176: if (iVar22 != 1) {
177: *(undefined4 *)(lVar9 + 0x128 + (long)(iVar16 + 1) * 4) = 0x900;
178: if (iVar22 != 2) {
179: *(undefined4 *)(lVar9 + 0x128 + (long)(iVar16 + 2) * 4) = 0x900;
180: }
181: }
182: }
183: lStack1408 = 0;
184: iVar22 = 0;
185: do {
186: if (pcVar23[lStack1408 + 1] != (code)0x0) {
187: uVar7 = ((int)lStack1408 + 1) * 0x100;
188: bVar10 = 7 - (char)lStack1408;
189: iVar16 = 1;
190: uVar12 = 1 << (bVar10 & 0x1f);
191: lVar14 = (long)iVar22;
192: pauVar20 = (undefined (*) [16])(pcVar23 + lVar14 + 0x12);
193: uVar6 = uVar12 & 0xfffffff0;
194: do {
195: bVar4 = bVar10 & 0x1f;
196: iVar17 = auStack1368[lVar14] << bVar4;
197: pauVar11 = (undefined (*) [16])(lVar9 + 0x128 + (long)iVar17 * 4);
198: if ((pauVar20[-1] + 0xf < *pauVar11 + (long)(int)uVar12 * 4 && pauVar11 < pauVar20) ||
199: (uVar12 < 0x10)) {
200: iVar18 = iVar17 + uVar12;
201: do {
202: lVar21 = (long)iVar17;
203: iVar17 = iVar17 + 1;
204: *(uint *)(lVar9 + 0x128 + lVar21 * 4) = (byte)pcVar23[lVar14 + 0x11] | uVar7;
205: } while (iVar17 != iVar18);
206: }
207: else {
208: uVar8 = uVar12;
209: if (uVar12 >> 4 != 0) {
210: uVar8 = 0 << bVar4;
211: do {
212: cVar1 = pcVar23[lVar14 + 0x11];
213: uVar8 = uVar8 + 1;
214: uVar24 = SUB164(CONCAT142(ZEXT614(0) &
215: SUB1614((undefined  [16])0xffffffffff00ffff >> 0x10,0),
216: CONCAT11(cVar1,cVar1)),0);
217: uVar5 = uVar24 << 0x10;
218: uVar24 = uVar24 | uVar5;
219: uVar26 = CONCAT44(uVar24,uVar24);
220: auVar27 = CONCAT48(uVar24,uVar26);
221: uVar25 = CONCAT14(cVar1,(uint)CONCAT12(cVar1,(ushort)(byte)cVar1));
222: uVar30 = (undefined)(uVar5 >> 0x18);
223: uVar15 = (ulong)CONCAT16(uVar30,(uint6)uVar25);
224: auVar28 = ZEXT1112(CONCAT110(cVar1,(unkuint10)CONCAT18(cVar1,uVar15)));
225: auVar29 = ZEXT1314(CONCAT112(cVar1,auVar28));
226: auVar32 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
227: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
228: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
229: (CONCAT213(SUB152(CONCAT114(uVar30,SUB1614(
230: CONCAT412(uVar24,auVar27),0)) >> 0x68,0),
231: CONCAT112(cVar1,auVar27)) >> 0x60,0),auVar27) >>
232: 0x58,0),CONCAT110(cVar1,SUB1210(auVar27,0))) >>
233: 0x50,0),SUB1210(auVar27,0)) >> 0x48,0),
234: CONCAT18(cVar1,uVar26)) >> 0x40,0),uVar26) >> 0x38
235: ,0) & SUB169((undefined  [16])0xffffffffffffffff
236: >> 0x38,0) &
237: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
238: ,0) &
239: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
240: ,0) &
241: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
242: ,0),((uint7)uVar26 >> 0x18) << 0x30) >>
243: 0x30,0),(int6)uVar26) >> 0x28,0) &
244: SUB1611((undefined  [16])0xffff00ffffffffff >>
245: 0x28,0),((uint5)uVar26 >> 0x10) << 0x20)
246: >> 0x20,0),uVar24) >> 0x18,0) &
247: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
248: auVar31 = CONCAT142(SUB1614(CONCAT133(auVar32,((uint3)uVar24 >> 8) << 0x10) >> 0x10,0)
249: ,CONCAT11(cVar1,cVar1)) & (undefined  [16])0xffffffffffff00ff;
250: pauVar11[1] = ZEXT1416(CONCAT212(SUB132(auVar32 >> 0x58,0),
251: ZEXT1012(CONCAT28(SUB132(auVar32 >> 0x48,0),
252: (ulong)CONCAT24(SUB132(auVar32 >>
253: 0x38,0),
254: (uint)SUB132(
255: auVar32 >> 0x28,0)))))) |
256: CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
257: *pauVar11 = CONCAT124(SUB1612(CONCAT106((unkuint10)
258: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(
259: CONCAT212(SUB162(auVar31 >> 0x30,0),
260: SUB1612(auVar31,0)) >> 0x50,0),
261: CONCAT28(SUB162(auVar31 >> 0x20,0),
262: SUB168(auVar31,0))) >> 0x40,0),
263: SUB168(auVar31,0)) >> 0x30,0) &
264: SUB1610((undefined  [16])0xffffffffffffffff >>
265: 0x30,0) &
266: SUB1610((undefined  [16])0xffffffffffffffff >>
267: 0x30,0),
268: (SUB166(auVar31,0) >> 0x10) << 0x20) >> 0x20,0),
269: SUB164(auVar31,0)) & (undefined  [16])0xffffffff0000ffff |
270: CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
271: pauVar11[2] = CONCAT124(SUB1612(CONCAT106((unkuint10)
272: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(
273: CONCAT212(SUB142(auVar29 >> 0x30,0),auVar28) >>
274: 0x50,0),CONCAT28(SUB122(auVar28 >> 0x20,0),uVar15)
275: ) >> 0x40,0),uVar15) >> 0x30,0) &
276: SUB1610((undefined  [16])0xffffffffffffffff >>
277: 0x30,0) &
278: SUB1610((undefined  [16])0xffffffffffffffff >>
279: 0x30,0),(uint6)(uVar25 >> 0x10) << 0x20)
280: >> 0x20,0),(uint)CONCAT12(cVar1,(ushort)(byte)cVar1))
281: & (undefined  [16])0xffffffff0000ffff |
282: CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
283: pauVar11[3] = ZEXT1316(CONCAT112(uVar30,ZEXT1012(CONCAT28(SUB162(ZEXT1516(CONCAT114(
284: uVar30,auVar29)) >> 0x60,0),
285: (ulong)CONCAT24(SUB162(ZEXT1516(CONCAT114(uVar30,
286: auVar29)) >> 0x50,0),
287: (uint)SUB142(auVar29 >> 0x40,0)))))) |
288: CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
289: pauVar11 = pauVar11[4];
290: } while (uVar8 < uVar12 >> 4);
291: iVar17 = iVar17 + uVar6;
292: uVar8 = uVar12 - uVar6;
293: if (uVar6 == uVar12) goto LAB_00125a8c;
294: }
295: *(uint *)(lVar9 + 0x128 + (long)iVar17 * 4) = (byte)pcVar23[lVar14 + 0x11] | uVar7;
296: if (uVar8 != 1) {
297: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 1) * 4) = (byte)pcVar23[lVar14 + 0x11] | uVar7
298: ;
299: if (uVar8 != 2) {
300: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 2) * 4) =
301: (byte)pcVar23[lVar14 + 0x11] | uVar7;
302: if (uVar8 != 3) {
303: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 3) * 4) =
304: (byte)pcVar23[lVar14 + 0x11] | uVar7;
305: if (uVar8 != 4) {
306: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 4) * 4) =
307: (byte)pcVar23[lVar14 + 0x11] | uVar7;
308: if (uVar8 != 5) {
309: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 5) * 4) =
310: (byte)pcVar23[lVar14 + 0x11] | uVar7;
311: if (uVar8 != 6) {
312: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 6) * 4) =
313: (byte)pcVar23[lVar14 + 0x11] | uVar7;
314: if (uVar8 != 7) {
315: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 7) * 4) =
316: (byte)pcVar23[lVar14 + 0x11] | uVar7;
317: if (uVar8 != 8) {
318: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 8) * 4) =
319: (byte)pcVar23[lVar14 + 0x11] | uVar7;
320: if (uVar8 != 9) {
321: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 9) * 4) =
322: (byte)pcVar23[lVar14 + 0x11] | uVar7;
323: if (uVar8 != 10) {
324: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 10) * 4) =
325: (byte)pcVar23[lVar14 + 0x11] | uVar7;
326: if (uVar8 != 0xb) {
327: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 0xb) * 4) =
328: (byte)pcVar23[lVar14 + 0x11] | uVar7;
329: if (uVar8 != 0xc) {
330: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 0xc) * 4) =
331: (byte)pcVar23[lVar14 + 0x11] | uVar7;
332: if (uVar8 != 0xd) {
333: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 0xd) * 4) =
334: (byte)pcVar23[lVar14 + 0x11] | uVar7;
335: if (uVar8 != 0xe) {
336: *(uint *)(lVar9 + 0x128 + (long)(iVar17 + 0xe) * 4) =
337: (byte)pcVar23[lVar14 + 0x11] | uVar7;
338: }
339: }
340: }
341: }
342: }
343: }
344: }
345: }
346: }
347: }
348: }
349: }
350: }
351: }
352: }
353: LAB_00125a8c:
354: iVar16 = iVar16 + 1;
355: iVar22 = iVar22 + 1;
356: pauVar20 = (undefined (*) [16])(*pauVar20 + 1);
357: if ((int)(uint)(byte)pcVar23[lStack1408 + 1] < iVar16) break;
358: lVar14 = (long)iVar22;
359: } while( true );
360: }
361: lStack1408 = lStack1408 + 1;
362: } while (lStack1408 != 8);
363: if ((param_2 != 0) && (iStack1380 != 0)) {
364: pcVar13 = pcVar23 + 0x11;
365: do {
366: while (0xf < (byte)*pcVar13) {
367: pcVar13 = pcVar13 + 1;
368: *(undefined4 *)(*param_1 + 0x28) = 8;
369: (**(code **)*param_1)(param_1);
370: if (pcVar13 == pcVar23 + (ulong)(iStack1380 - 1) + 0x12) goto LAB_00125b6b;
371: }
372: pcVar13 = pcVar13 + 1;
373: } while (pcVar13 != pcVar23 + (ulong)(iStack1380 - 1) + 0x12);
374: }
375: LAB_00125b6b:
376: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
377: return;
378: }
379: /* WARNING: Subroutine does not return */
380: __stack_chk_fail();
381: }
382: 

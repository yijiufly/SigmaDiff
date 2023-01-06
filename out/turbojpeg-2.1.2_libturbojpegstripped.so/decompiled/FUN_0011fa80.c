1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0011fa80(code **param_1)
5: 
6: {
7: code **ppcVar1;
8: uint uVar2;
9: code *pcVar3;
10: undefined4 *puVar4;
11: code **ppcVar5;
12: code **ppcVar6;
13: int iVar7;
14: unkuint10 Var8;
15: undefined auVar9 [16];
16: undefined auVar10 [16];
17: uint uVar12;
18: uint uVar13;
19: ushort uVar19;
20: byte bVar20;
21: uint uVar21;
22: ushort uVar22;
23: undefined auVar11 [13];
24: uint5 uVar14;
25: ulong uVar15;
26: undefined auVar16 [12];
27: undefined auVar17 [14];
28: undefined auVar18 [15];
29: 
30: iVar7 = *(int *)((long)param_1 + 0x24);
31: if (iVar7 != 100) {
32: ppcVar6 = (code **)*param_1;
33: *(undefined4 *)(ppcVar6 + 5) = 0x14;
34: *(int *)((long)ppcVar6 + 0x2c) = iVar7;
35: (**ppcVar6)();
36: }
37: if (param_1[0xb] == (code *)0x0) {
38: pcVar3 = (code *)(**(code **)param_1[1])(param_1,0,0x3c0);
39: param_1[0xb] = pcVar3;
40: }
41: *(undefined4 *)(param_1 + 9) = 8;
42: FUN_0011f6c0(param_1,0x4b,1);
43: if (*(int *)(param_1 + 4) == 0) {
44: ppcVar6 = param_1 + 0x10;
45: ppcVar5 = param_1 + 0x14;
46: pcVar3 = param_1[0x10];
47: }
48: else {
49: pcVar3 = param_1[0x1d];
50: ppcVar6 = param_1 + 0x1d;
51: ppcVar5 = param_1 + 0x21;
52: }
53: if (pcVar3 == (code *)0x0) {
54: puVar4 = (undefined4 *)FUN_0011f530(param_1);
55: *ppcVar6 = (code *)puVar4;
56: auVar9 = _DAT_0017ca41;
57: *puVar4 = 0x5010000;
58: puVar4[1] = 0x1010101;
59: puVar4[2] = 0x101;
60: puVar4[3] = 0;
61: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
62: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
63: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
64: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
65: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
66: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
67: bVar20 = SUB161(auVar9 >> 0x78,0);
68: auVar18 = CONCAT114(bVar20,auVar17);
69: *(undefined *)(puVar4 + 4) = 0;
70: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
71: SUB158(CONCAT78
72: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
73: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
74: CONCAT114(SUB161(auVar9 >> 0x38,0),
75: SUB1614(auVar9,0)) >> 0x68,0),
76: CONCAT112(SUB161(auVar9 >> 0x30,0),
77: SUB1612(auVar9,0))) >> 0x60,0),
78: SUB1612(auVar9,0)) >> 0x58,0),
79: CONCAT110(SUB161(auVar9 >> 0x28,0),
80: SUB1610(auVar9,0))) >> 0x50,0),
81: SUB1610(auVar9,0)) >> 0x48,0),
82: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
83: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
84: & SUB169((undefined  [16])0xffffffffffffffff >>
85: 0x38,0) &
86: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
87: ,0) &
88: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
89: ,0) &
90: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
91: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
92: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
93: SUB1611((undefined  [16])0xffff00ffffffffff >>
94: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
95: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
96: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
97: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
98: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
99: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
100: uVar22 = SUB132(auVar11 >> 0x48,0);
101: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
102: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
103: (undefined  [16])0xffffffffffffffff;
104: Var8 = (unkuint10)
105: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
106: SUB1612(auVar9,0)) >> 0x50,0),
107: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
108: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
109: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
110: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
111: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
112: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
113: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
114: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
115: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
116: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
117: 0x20,0) +
118: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
119: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
120: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
121: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
122: 0)) >> 0x40,0),
123: uVar13))) >> 0x20,0) +
124: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
125: if (0xff < iVar7 - 1U) {
126: ppcVar1 = (code **)*param_1;
127: *(undefined4 *)(ppcVar1 + 5) = 8;
128: (**ppcVar1)(param_1);
129: }
130: memcpy(*ppcVar6 + 0x11,&DAT_0017ca28,(long)iVar7);
131: memset(*ppcVar6 + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
132: *(undefined4 *)(*ppcVar6 + 0x114) = 0;
133: }
134: if (*ppcVar5 == (code *)0x0) {
135: puVar4 = (undefined4 *)FUN_0011f530(param_1);
136: *ppcVar5 = (code *)puVar4;
137: auVar9 = _DAT_0017ca11;
138: *puVar4 = 0x1020000;
139: puVar4[1] = 0x4020303;
140: puVar4[2] = 0x4050503;
141: puVar4[3] = 0x1000004;
142: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
143: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
144: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
145: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
146: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
147: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
148: bVar20 = SUB161(auVar9 >> 0x78,0);
149: auVar18 = CONCAT114(bVar20,auVar17);
150: *(undefined *)(puVar4 + 4) = 0x7d;
151: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
152: SUB158(CONCAT78
153: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
154: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
155: CONCAT114(SUB161(auVar9 >> 0x38,0),
156: SUB1614(auVar9,0)) >> 0x68,0),
157: CONCAT112(SUB161(auVar9 >> 0x30,0),
158: SUB1612(auVar9,0))) >> 0x60,0),
159: SUB1612(auVar9,0)) >> 0x58,0),
160: CONCAT110(SUB161(auVar9 >> 0x28,0),
161: SUB1610(auVar9,0))) >> 0x50,0),
162: SUB1610(auVar9,0)) >> 0x48,0),
163: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
164: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
165: & SUB169((undefined  [16])0xffffffffffffffff >>
166: 0x38,0) &
167: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
168: ,0) &
169: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
170: ,0) &
171: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
172: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
173: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
174: SUB1611((undefined  [16])0xffff00ffffffffff >>
175: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
176: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
177: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
178: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
179: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
180: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
181: uVar22 = SUB132(auVar11 >> 0x48,0);
182: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
183: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
184: (undefined  [16])0xffffffffffffffff;
185: Var8 = (unkuint10)
186: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
187: SUB1612(auVar9,0)) >> 0x50,0),
188: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
189: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
190: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
191: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
192: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
193: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
194: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
195: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
196: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
197: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
198: 0x20,0) +
199: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
200: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
201: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
202: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
203: 0)) >> 0x40,0),
204: uVar13))) >> 0x20,0) +
205: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
206: if (0xff < iVar7 - 1U) {
207: ppcVar1 = (code **)*param_1;
208: *(undefined4 *)(ppcVar1 + 5) = 8;
209: (**ppcVar1)(param_1);
210: }
211: memcpy(*ppcVar5 + 0x11,&DAT_0017c960,(long)iVar7);
212: memset(*ppcVar5 + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
213: *(undefined4 *)(*ppcVar5 + 0x114) = 0;
214: }
215: if (ppcVar6[1] == (code *)0x0) {
216: puVar4 = (undefined4 *)FUN_0011f530(param_1);
217: ppcVar6[1] = (code *)puVar4;
218: auVar9 = _DAT_0017c941;
219: *puVar4 = 0x1030000;
220: puVar4[1] = 0x1010101;
221: puVar4[2] = 0x1010101;
222: puVar4[3] = 0;
223: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
224: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
225: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
226: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
227: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
228: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
229: bVar20 = SUB161(auVar9 >> 0x78,0);
230: auVar18 = CONCAT114(bVar20,auVar17);
231: *(undefined *)(puVar4 + 4) = 0;
232: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
233: SUB158(CONCAT78
234: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
235: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
236: CONCAT114(SUB161(auVar9 >> 0x38,0),
237: SUB1614(auVar9,0)) >> 0x68,0),
238: CONCAT112(SUB161(auVar9 >> 0x30,0),
239: SUB1612(auVar9,0))) >> 0x60,0),
240: SUB1612(auVar9,0)) >> 0x58,0),
241: CONCAT110(SUB161(auVar9 >> 0x28,0),
242: SUB1610(auVar9,0))) >> 0x50,0),
243: SUB1610(auVar9,0)) >> 0x48,0),
244: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
245: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
246: & SUB169((undefined  [16])0xffffffffffffffff >>
247: 0x38,0) &
248: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
249: ,0) &
250: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
251: ,0) &
252: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
253: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
254: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
255: SUB1611((undefined  [16])0xffff00ffffffffff >>
256: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
257: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
258: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
259: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
260: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
261: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
262: uVar22 = SUB132(auVar11 >> 0x48,0);
263: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
264: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
265: (undefined  [16])0xffffffffffffffff;
266: Var8 = (unkuint10)
267: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
268: SUB1612(auVar9,0)) >> 0x50,0),
269: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
270: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
271: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
272: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
273: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
274: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
275: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
276: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
277: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
278: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
279: 0x20,0) +
280: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
281: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
282: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
283: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
284: 0)) >> 0x40,0),
285: uVar13))) >> 0x20,0) +
286: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
287: if (0xff < iVar7 - 1U) {
288: ppcVar1 = (code **)*param_1;
289: *(undefined4 *)(ppcVar1 + 5) = 8;
290: (**ppcVar1)(param_1);
291: }
292: memcpy(ppcVar6[1] + 0x11,&DAT_0017c928,(long)iVar7);
293: memset(ppcVar6[1] + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
294: *(undefined4 *)(ppcVar6[1] + 0x114) = 0;
295: }
296: if (ppcVar5[1] == (code *)0x0) {
297: puVar4 = (undefined4 *)FUN_0011f530(param_1);
298: ppcVar5[1] = (code *)puVar4;
299: auVar9 = _DAT_0017c911;
300: *puVar4 = 0x1020000;
301: puVar4[1] = 0x3040402;
302: puVar4[2] = 0x4050704;
303: puVar4[3] = 0x2010004;
304: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
305: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
306: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
307: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
308: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
309: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
310: bVar20 = SUB161(auVar9 >> 0x78,0);
311: auVar18 = CONCAT114(bVar20,auVar17);
312: *(undefined *)(puVar4 + 4) = 0x77;
313: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
314: SUB158(CONCAT78
315: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
316: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
317: CONCAT114(SUB161(auVar9 >> 0x38,0),
318: SUB1614(auVar9,0)) >> 0x68,0),
319: CONCAT112(SUB161(auVar9 >> 0x30,0),
320: SUB1612(auVar9,0))) >> 0x60,0),
321: SUB1612(auVar9,0)) >> 0x58,0),
322: CONCAT110(SUB161(auVar9 >> 0x28,0),
323: SUB1610(auVar9,0))) >> 0x50,0),
324: SUB1610(auVar9,0)) >> 0x48,0),
325: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
326: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
327: & SUB169((undefined  [16])0xffffffffffffffff >>
328: 0x38,0) &
329: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
330: ,0) &
331: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
332: ,0) &
333: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
334: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
335: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
336: SUB1611((undefined  [16])0xffff00ffffffffff >>
337: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
338: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
339: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
340: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
341: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
342: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
343: uVar22 = SUB132(auVar11 >> 0x48,0);
344: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
345: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
346: (undefined  [16])0xffffffffffffffff;
347: Var8 = (unkuint10)
348: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
349: SUB1612(auVar9,0)) >> 0x50,0),
350: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
351: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
352: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
353: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
354: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
355: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
356: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
357: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
358: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
359: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
360: 0x20,0) +
361: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
362: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
363: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
364: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
365: 0)) >> 0x40,0),
366: uVar13))) >> 0x20,0) +
367: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
368: if (0xff < iVar7 - 1U) {
369: ppcVar6 = (code **)*param_1;
370: *(undefined4 *)(ppcVar6 + 5) = 8;
371: (**ppcVar6)(param_1);
372: }
373: memcpy(ppcVar5[1] + 0x11,&DAT_0017c860,(long)iVar7);
374: memset(ppcVar5[1] + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
375: *(undefined4 *)(ppcVar5[1] + 0x114) = 0;
376: }
377: *(undefined4 *)(param_1 + 0x1e) = 0;
378: param_1[0x1f] = (code *)0x0;
379: param_1[0x20] = (code *)0x0;
380: *(undefined4 *)(param_1 + 0x21) = 0;
381: *(undefined (*) [16])(param_1 + 0x18) = (undefined  [16])0x0;
382: *(undefined4 *)(param_1 + 0x1a) = 0x1010101;
383: *(undefined4 *)((long)param_1 + 0xd4) = 0x1010101;
384: *(undefined4 *)(param_1 + 0x1b) = 0x1010101;
385: *(undefined4 *)((long)param_1 + 0xdc) = 0x1010101;
386: param_1[0x1c] = (code *)0x505050505050505;
387: param_1[0x1d] = (code *)0x505050505050505;
388: if (8 < *(int *)(param_1 + 9)) {
389: *(undefined4 *)(param_1 + 0x21) = 1;
390: }
391: *(undefined8 *)((long)param_1 + 0x10c) = 0;
392: *(undefined4 *)((long)param_1 + 0x114) = 0;
393: param_1[0x23] = (code *)0x0;
394: *(undefined2 *)((long)param_1 + 0x124) = 0x101;
395: *(undefined *)((long)param_1 + 0x126) = 0;
396: *(undefined4 *)(param_1 + 0x25) = 0x10001;
397: FUN_0011fa00(0x505050505050505,param_1);
398: return;
399: }
400: 

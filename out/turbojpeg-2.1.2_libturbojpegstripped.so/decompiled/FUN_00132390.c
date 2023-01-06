1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00132390(code **param_1)
5: 
6: {
7: code **ppcVar1;
8: uint uVar2;
9: code *pcVar3;
10: code **ppcVar4;
11: undefined4 *puVar5;
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
30: if (*(int *)(param_1 + 4) == 0) {
31: ppcVar4 = param_1 + 0x10;
32: ppcVar6 = param_1 + 0x14;
33: pcVar3 = param_1[0x10];
34: }
35: else {
36: pcVar3 = param_1[0x1d];
37: ppcVar4 = param_1 + 0x1d;
38: ppcVar6 = param_1 + 0x21;
39: }
40: if (pcVar3 == (code *)0x0) {
41: puVar5 = (undefined4 *)FUN_0011f530(param_1);
42: *ppcVar4 = (code *)puVar5;
43: auVar9 = _DAT_0018d3c1;
44: *puVar5 = 0x5010000;
45: puVar5[1] = 0x1010101;
46: puVar5[2] = 0x101;
47: puVar5[3] = 0;
48: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
49: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
50: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
51: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
52: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
53: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
54: bVar20 = SUB161(auVar9 >> 0x78,0);
55: auVar18 = CONCAT114(bVar20,auVar17);
56: *(undefined *)(puVar5 + 4) = 0;
57: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
58: SUB158(CONCAT78
59: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
60: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
61: CONCAT114(SUB161(auVar9 >> 0x38,0),
62: SUB1614(auVar9,0)) >> 0x68,0),
63: CONCAT112(SUB161(auVar9 >> 0x30,0),
64: SUB1612(auVar9,0))) >> 0x60,0),
65: SUB1612(auVar9,0)) >> 0x58,0),
66: CONCAT110(SUB161(auVar9 >> 0x28,0),
67: SUB1610(auVar9,0))) >> 0x50,0),
68: SUB1610(auVar9,0)) >> 0x48,0),
69: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
70: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
71: & SUB169((undefined  [16])0xffffffffffffffff >>
72: 0x38,0) &
73: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
74: ,0) &
75: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
76: ,0) &
77: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
78: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
79: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
80: SUB1611((undefined  [16])0xffff00ffffffffff >>
81: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
82: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
83: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
84: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
85: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
86: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
87: uVar22 = SUB132(auVar11 >> 0x48,0);
88: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
89: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
90: (undefined  [16])0xffffffffffffffff;
91: Var8 = (unkuint10)
92: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
93: SUB1612(auVar9,0)) >> 0x50,0),
94: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
95: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
96: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
97: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
98: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
99: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
100: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
101: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
102: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
103: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
104: 0x20,0) +
105: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
106: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
107: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
108: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
109: 0)) >> 0x40,0),
110: uVar13))) >> 0x20,0) +
111: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
112: if (0xff < iVar7 - 1U) {
113: ppcVar1 = (code **)*param_1;
114: *(undefined4 *)(ppcVar1 + 5) = 8;
115: (**ppcVar1)(param_1);
116: }
117: memcpy(*ppcVar4 + 0x11,&DAT_0018d3a8,(long)iVar7);
118: memset(*ppcVar4 + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
119: *(undefined4 *)(*ppcVar4 + 0x114) = 0;
120: }
121: if (*ppcVar6 == (code *)0x0) {
122: puVar5 = (undefined4 *)FUN_0011f530(param_1);
123: *ppcVar6 = (code *)puVar5;
124: auVar9 = _DAT_0018d391;
125: *puVar5 = 0x1020000;
126: puVar5[1] = 0x4020303;
127: puVar5[2] = 0x4050503;
128: puVar5[3] = 0x1000004;
129: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
130: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
131: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
132: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
133: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
134: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
135: bVar20 = SUB161(auVar9 >> 0x78,0);
136: auVar18 = CONCAT114(bVar20,auVar17);
137: *(undefined *)(puVar5 + 4) = 0x7d;
138: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
139: SUB158(CONCAT78
140: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
141: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
142: CONCAT114(SUB161(auVar9 >> 0x38,0),
143: SUB1614(auVar9,0)) >> 0x68,0),
144: CONCAT112(SUB161(auVar9 >> 0x30,0),
145: SUB1612(auVar9,0))) >> 0x60,0),
146: SUB1612(auVar9,0)) >> 0x58,0),
147: CONCAT110(SUB161(auVar9 >> 0x28,0),
148: SUB1610(auVar9,0))) >> 0x50,0),
149: SUB1610(auVar9,0)) >> 0x48,0),
150: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
151: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
152: & SUB169((undefined  [16])0xffffffffffffffff >>
153: 0x38,0) &
154: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
155: ,0) &
156: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
157: ,0) &
158: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
159: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
160: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
161: SUB1611((undefined  [16])0xffff00ffffffffff >>
162: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
163: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
164: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
165: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
166: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
167: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
168: uVar22 = SUB132(auVar11 >> 0x48,0);
169: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
170: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
171: (undefined  [16])0xffffffffffffffff;
172: Var8 = (unkuint10)
173: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
174: SUB1612(auVar9,0)) >> 0x50,0),
175: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
176: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
177: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
178: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
179: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
180: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
181: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
182: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
183: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
184: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
185: 0x20,0) +
186: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
187: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
188: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
189: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
190: 0)) >> 0x40,0),
191: uVar13))) >> 0x20,0) +
192: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
193: if (0xff < iVar7 - 1U) {
194: ppcVar1 = (code **)*param_1;
195: *(undefined4 *)(ppcVar1 + 5) = 8;
196: (**ppcVar1)(param_1);
197: }
198: memcpy(*ppcVar6 + 0x11,&DAT_0018d2e0,(long)iVar7);
199: memset(*ppcVar6 + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
200: *(undefined4 *)(*ppcVar6 + 0x114) = 0;
201: }
202: if (ppcVar4[1] == (code *)0x0) {
203: puVar5 = (undefined4 *)FUN_0011f530(param_1);
204: ppcVar4[1] = (code *)puVar5;
205: auVar9 = _DAT_0018d2c1;
206: *puVar5 = 0x1030000;
207: puVar5[1] = 0x1010101;
208: puVar5[2] = 0x1010101;
209: puVar5[3] = 0;
210: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
211: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
212: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
213: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
214: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
215: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
216: bVar20 = SUB161(auVar9 >> 0x78,0);
217: auVar18 = CONCAT114(bVar20,auVar17);
218: *(undefined *)(puVar5 + 4) = 0;
219: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
220: SUB158(CONCAT78
221: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
222: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
223: CONCAT114(SUB161(auVar9 >> 0x38,0),
224: SUB1614(auVar9,0)) >> 0x68,0),
225: CONCAT112(SUB161(auVar9 >> 0x30,0),
226: SUB1612(auVar9,0))) >> 0x60,0),
227: SUB1612(auVar9,0)) >> 0x58,0),
228: CONCAT110(SUB161(auVar9 >> 0x28,0),
229: SUB1610(auVar9,0))) >> 0x50,0),
230: SUB1610(auVar9,0)) >> 0x48,0),
231: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
232: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
233: & SUB169((undefined  [16])0xffffffffffffffff >>
234: 0x38,0) &
235: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
236: ,0) &
237: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
238: ,0) &
239: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
240: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
241: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
242: SUB1611((undefined  [16])0xffff00ffffffffff >>
243: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
244: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
245: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
246: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
247: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
248: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
249: uVar22 = SUB132(auVar11 >> 0x48,0);
250: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
251: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
252: (undefined  [16])0xffffffffffffffff;
253: Var8 = (unkuint10)
254: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
255: SUB1612(auVar9,0)) >> 0x50,0),
256: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
257: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
258: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
259: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
260: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
261: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
262: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
263: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
264: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
265: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
266: 0x20,0) +
267: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
268: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
269: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
270: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
271: 0)) >> 0x40,0),
272: uVar13))) >> 0x20,0) +
273: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
274: if (0xff < iVar7 - 1U) {
275: ppcVar1 = (code **)*param_1;
276: *(undefined4 *)(ppcVar1 + 5) = 8;
277: (**ppcVar1)(param_1);
278: }
279: memcpy(ppcVar4[1] + 0x11,&DAT_0018d2a8,(long)iVar7);
280: memset(ppcVar4[1] + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
281: *(undefined4 *)(ppcVar4[1] + 0x114) = 0;
282: }
283: if (ppcVar6[1] == (code *)0x0) {
284: puVar5 = (undefined4 *)FUN_0011f530(param_1);
285: ppcVar6[1] = (code *)puVar5;
286: auVar9 = _DAT_0018d291;
287: *puVar5 = 0x1020000;
288: puVar5[1] = 0x3040402;
289: puVar5[2] = 0x4050704;
290: puVar5[3] = 0x2010004;
291: uVar12 = (uint)CONCAT12(SUB161(auVar9 >> 0x48,0),(ushort)SUB161(auVar9 >> 0x40,0));
292: uVar14 = CONCAT14(SUB161(auVar9 >> 0x50,0),uVar12);
293: uVar15 = (ulong)CONCAT16(SUB161(auVar9 >> 0x58,0),(uint6)uVar14);
294: auVar16 = ZEXT1112(CONCAT110(SUB161(auVar9 >> 0x68,0),
295: (unkuint10)CONCAT18(SUB161(auVar9 >> 0x60,0),uVar15)));
296: auVar17 = ZEXT1314(CONCAT112(SUB161(auVar9 >> 0x70,0),auVar16));
297: bVar20 = SUB161(auVar9 >> 0x78,0);
298: auVar18 = CONCAT114(bVar20,auVar17);
299: *(undefined *)(puVar5 + 4) = 0x77;
300: auVar11 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
301: SUB158(CONCAT78
302: (SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411
303: (SUB154(CONCAT312(SUB153(CONCAT213(SUB152(
304: CONCAT114(SUB161(auVar9 >> 0x38,0),
305: SUB1614(auVar9,0)) >> 0x68,0),
306: CONCAT112(SUB161(auVar9 >> 0x30,0),
307: SUB1612(auVar9,0))) >> 0x60,0),
308: SUB1612(auVar9,0)) >> 0x58,0),
309: CONCAT110(SUB161(auVar9 >> 0x28,0),
310: SUB1610(auVar9,0))) >> 0x50,0),
311: SUB1610(auVar9,0)) >> 0x48,0),
312: CONCAT18(SUB161(auVar9 >> 0x20,0),SUB168(auVar9,0)
313: )) >> 0x40,0),SUB168(auVar9,0)) >> 0x38,0)
314: & SUB169((undefined  [16])0xffffffffffffffff >>
315: 0x38,0) &
316: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
317: ,0) &
318: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
319: ,0) &
320: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
321: ,0),(SUB167(auVar9,0) >> 0x18) << 0x30) >>
322: 0x30,0),SUB166(auVar9,0)) >> 0x28,0) &
323: SUB1611((undefined  [16])0xffff00ffffffffff >>
324: 0x28,0),(SUB165(auVar9,0) >> 0x10) << 0x20
325: ) >> 0x20,0),SUB164(auVar9,0)) >> 0x18,0) &
326: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
327: auVar9 = CONCAT142(SUB1614(CONCAT133(auVar11,(SUB163(auVar9,0) >> 8) << 0x10) >> 0x10,0),
328: SUB162(auVar9,0)) & (undefined  [16])0xffffffffffff00ff;
329: uVar21 = (uint)SUB132(auVar11 >> 0x28,0);
330: uVar22 = SUB132(auVar11 >> 0x48,0);
331: uVar2 = SUB144(CONCAT212(SUB142(auVar17 >> 0x30,0),auVar16) >> 0x50,0);
332: auVar10 = ZEXT1416(CONCAT410(uVar2,CONCAT28(SUB122(auVar16 >> 0x20,0),uVar15))) &
333: (undefined  [16])0xffffffffffffffff;
334: Var8 = (unkuint10)
335: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar9 >> 0x30,0),
336: SUB1612(auVar9,0)) >> 0x50,0),
337: CONCAT28(SUB162(auVar9 >> 0x20,0),SUB168(auVar9,0))) >>
338: 0x40,0),SUB168(auVar9,0)) >> 0x30,0) &
339: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
340: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
341: uVar13 = (uint)SUB142(auVar17 >> 0x40,0);
342: uVar19 = (ushort)((unkuint10)SUB159(auVar18 >> 0x30,0) >> 0x30);
343: iVar7 = (SUB164(auVar9,0) & 0xffff) + uVar21 + (uVar12 & 0xffff) + uVar13 +
344: (int)(Var8 >> 0x10) + (uint)uVar22 + SUB164(auVar10 >> 0x40,0) + (uint)uVar19 +
345: SUB164(CONCAT106(Var8,(SUB166(auVar9,0) >> 0x10) << 0x20) >> 0x20,0) +
346: SUB124(ZEXT1012(CONCAT28(uVar22,(ulong)CONCAT24(SUB132(auVar11 >> 0x38,0),uVar21))) >>
347: 0x20,0) +
348: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar10 >> 0x40,0),uVar15) >> 0x30,0) &
349: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
350: (uint6)(uVar14 >> 0x10) << 0x20) >> 0x20,0) +
351: SUB124(ZEXT1012(CONCAT28(uVar19,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar18 >> 0x10,
352: 0)) >> 0x40,0),
353: uVar13))) >> 0x20,0) +
354: (int)(Var8 >> 0x30) + (uint)SUB132(auVar11 >> 0x58,0) + (uVar2 >> 0x10) + (uint)bVar20;
355: if (0xff < iVar7 - 1U) {
356: ppcVar4 = (code **)*param_1;
357: *(undefined4 *)(ppcVar4 + 5) = 8;
358: (**ppcVar4)(param_1);
359: }
360: memcpy(ppcVar6[1] + 0x11,&DAT_0018d1e0,(long)iVar7);
361: memset(ppcVar6[1] + (long)iVar7 + 0x11,0,(long)(0x100 - iVar7));
362: *(undefined4 *)(ppcVar6[1] + 0x114) = 0;
363: }
364: ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x170);
365: param_1[0x4a] = (code *)ppcVar4;
366: ppcVar4[0xc] = (code *)0x0;
367: ppcVar4[8] = (code *)0x0;
368: ppcVar4[0xd] = (code *)0x0;
369: *ppcVar4 = FUN_00130410;
370: ppcVar4[9] = (code *)0x0;
371: ppcVar4[0xe] = (code *)0x0;
372: ppcVar4[10] = (code *)0x0;
373: ppcVar4[1] = FUN_00130c50;
374: ppcVar4[0xf] = (code *)0x0;
375: ppcVar4[0xb] = (code *)0x0;
376: return;
377: }
378: 

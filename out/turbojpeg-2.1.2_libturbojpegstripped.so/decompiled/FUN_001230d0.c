1: 
2: void FUN_001230d0(long param_1,long param_2,long *param_3,long param_4)
3: 
4: {
5: int iVar1;
6: undefined auVar2 [16];
7: int iVar3;
8: undefined *puVar4;
9: int iVar5;
10: int iVar6;
11: undefined auVar7 [16];
12: uint uVar8;
13: uint6 uVar9;
14: int iVar10;
15: long lVar11;
16: int iVar12;
17: undefined (*pauVar13) [16];
18: byte *pbVar14;
19: undefined *puVar15;
20: undefined *puVar16;
21: uint uVar17;
22: uint uVar18;
23: void *__s;
24: long *plVar19;
25: long *plVar20;
26: ulong uVar21;
27: uint uVar22;
28: ulong uVar25;
29: ushort uVar29;
30: byte bVar30;
31: undefined auVar31 [16];
32: ulong uVar33;
33: ushort uVar34;
34: long lVar35;
35: long lVar36;
36: long *plStack128;
37: long lStack96;
38: uint5 uVar23;
39: ulong uVar24;
40: undefined auVar26 [12];
41: undefined auVar27 [14];
42: undefined auVar28 [16];
43: unkuint10 Var32;
44: 
45: uVar17 = *(uint *)(param_1 + 0x30);
46: iVar12 = *(int *)(param_2 + 0xc);
47: iVar1 = *(int *)(param_2 + 0x1c) * 8;
48: iVar6 = *(int *)(param_1 + 0x138) / *(int *)(param_2 + 8);
49: iVar3 = *(int *)(param_1 + 0x13c);
50: iVar5 = iVar3 / iVar12;
51: iVar10 = iVar6 * iVar1 - uVar17;
52: if ((0 < iVar10) && (0 < iVar3)) {
53: plVar20 = param_3;
54: do {
55: lVar11 = *plVar20;
56: plVar20 = plVar20 + 1;
57: __s = (void *)(lVar11 + (ulong)uVar17);
58: memset(__s,(uint)*(byte *)((long)__s + -1),(long)(iVar10 + -1) + 1);
59: } while (param_3 + (ulong)(iVar3 - 1) + 1 != plVar20);
60: iVar12 = *(int *)(param_2 + 0xc);
61: }
62: if ((0 < iVar12) && (iVar1 != 0)) {
63: lStack96 = 1;
64: plVar20 = param_3 + (ulong)(iVar5 - 1) + 1;
65: plStack128 = param_3;
66: do {
67: uVar21 = 0;
68: puVar4 = *(undefined **)(param_4 + -8 + lStack96 * 8);
69: puVar15 = puVar4;
70: do {
71: lVar11 = 0;
72: plVar19 = plStack128;
73: if (0 < iVar5) {
74: do {
75: pbVar14 = (byte *)(*plVar19 + uVar21);
76: if (0 < iVar6) {
77: uVar17 = -(int)pbVar14 & 0xf;
78: uVar18 = uVar17 + 0xf;
79: if (uVar18 < 0x12) {
80: uVar18 = 0x12;
81: }
82: if (iVar6 - 1U < uVar18) {
83: iVar12 = 0;
84: }
85: else {
86: if (uVar17 == 0) {
87: iVar12 = 0;
88: }
89: else {
90: lVar11 = lVar11 + (ulong)*pbVar14;
91: if (uVar17 == 1) {
92: iVar12 = 1;
93: pbVar14 = pbVar14 + 1;
94: }
95: else {
96: lVar11 = lVar11 + (ulong)pbVar14[1];
97: if (uVar17 == 2) {
98: iVar12 = 2;
99: pbVar14 = pbVar14 + 2;
100: }
101: else {
102: lVar11 = lVar11 + (ulong)pbVar14[2];
103: if (uVar17 == 3) {
104: iVar12 = 3;
105: pbVar14 = pbVar14 + 3;
106: }
107: else {
108: lVar11 = lVar11 + (ulong)pbVar14[3];
109: if (uVar17 == 4) {
110: iVar12 = 4;
111: pbVar14 = pbVar14 + 4;
112: }
113: else {
114: lVar11 = lVar11 + (ulong)pbVar14[4];
115: if (uVar17 == 5) {
116: iVar12 = 5;
117: pbVar14 = pbVar14 + 5;
118: }
119: else {
120: lVar11 = lVar11 + (ulong)pbVar14[5];
121: if (uVar17 == 6) {
122: iVar12 = 6;
123: pbVar14 = pbVar14 + 6;
124: }
125: else {
126: lVar11 = lVar11 + (ulong)pbVar14[6];
127: if (uVar17 == 7) {
128: iVar12 = 7;
129: pbVar14 = pbVar14 + 7;
130: }
131: else {
132: lVar11 = lVar11 + (ulong)pbVar14[7];
133: if (uVar17 == 8) {
134: iVar12 = 8;
135: pbVar14 = pbVar14 + 8;
136: }
137: else {
138: lVar11 = lVar11 + (ulong)pbVar14[8];
139: if (uVar17 == 9) {
140: iVar12 = 9;
141: pbVar14 = pbVar14 + 9;
142: }
143: else {
144: lVar11 = lVar11 + (ulong)pbVar14[9];
145: if (uVar17 == 10) {
146: iVar12 = 10;
147: pbVar14 = pbVar14 + 10;
148: }
149: else {
150: lVar11 = lVar11 + (ulong)pbVar14[10];
151: if (uVar17 == 0xb) {
152: iVar12 = 0xb;
153: pbVar14 = pbVar14 + 0xb;
154: }
155: else {
156: lVar11 = lVar11 + (ulong)pbVar14[0xb];
157: if (uVar17 == 0xc) {
158: iVar12 = 0xc;
159: pbVar14 = pbVar14 + 0xc;
160: }
161: else {
162: lVar11 = lVar11 + (ulong)pbVar14[0xc];
163: if (uVar17 == 0xd) {
164: iVar12 = 0xd;
165: pbVar14 = pbVar14 + 0xd;
166: }
167: else {
168: lVar11 = lVar11 + (ulong)pbVar14[0xd];
169: if (uVar17 == 0xf) {
170: lVar11 = lVar11 + (ulong)pbVar14[0xe];
171: iVar12 = 0xf;
172: pbVar14 = pbVar14 + 0xf;
173: }
174: else {
175: iVar12 = 0xe;
176: pbVar14 = pbVar14 + 0xe;
177: }
178: }
179: }
180: }
181: }
182: }
183: }
184: }
185: }
186: }
187: }
188: }
189: }
190: }
191: }
192: lVar35 = 0;
193: lVar36 = 0;
194: uVar18 = iVar6 - uVar17;
195: pauVar13 = (undefined (*) [16])(*plVar19 + uVar17 + uVar21);
196: uVar17 = 0;
197: do {
198: auVar2 = *pauVar13;
199: uVar17 = uVar17 + 1;
200: pauVar13 = pauVar13[1];
201: uVar22 = (uint)CONCAT12(SUB161(auVar2 >> 0x48,0),(ushort)SUB161(auVar2 >> 0x40,0))
202: ;
203: uVar23 = CONCAT14(SUB161(auVar2 >> 0x50,0),uVar22);
204: uVar24 = (ulong)CONCAT16(SUB161(auVar2 >> 0x58,0),(uint6)uVar23);
205: auVar26 = ZEXT1112(CONCAT110(SUB161(auVar2 >> 0x68,0),
206: (unkuint10)CONCAT18(SUB161(auVar2 >> 0x60,0),uVar24))
207: );
208: auVar27 = ZEXT1314(CONCAT112(SUB161(auVar2 >> 0x70,0),auVar26));
209: bVar30 = SUB161(auVar2 >> 0x78,0);
210: auVar28 = ZEXT1516(CONCAT114(bVar30,auVar27));
211: auVar7 = CONCAT97((unkuint9)
212: SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(SUB155(
213: CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213(SUB152
214: (CONCAT114(SUB161(auVar2 >> 0x38,0),
215: ZEXT1314(SUB1613(auVar2,0))) >> 0x68,0)
216: ,CONCAT112(SUB161(auVar2 >> 0x30,0),
217: SUB1612(auVar2,0))) >> 0x60,0),
218: ZEXT1112(SUB1611(auVar2,0))) >> 0x58,0),
219: CONCAT110(SUB161(auVar2 >> 0x28,0),
220: SUB1610(auVar2,0))) >> 0x50,0),
221: (unkuint10)SUB169(auVar2,0)) >> 0x48,0),
222: CONCAT18(SUB161(auVar2 >> 0x20,0),SUB168(auVar2,0)
223: )) >> 0x40,0),SUB168(auVar2,0)) >> 0x38,0)
224: & SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0),
225: (SUB167(auVar2,0) >> 0x18) << 0x30) &
226: (undefined  [16])0xffff000000000000;
227: auVar31 = CONCAT115(SUB1611(auVar7 >> 0x28,0),(SUB165(auVar2,0) >> 0x10) << 0x20)
228: & (undefined  [16])0xffffffff00000000;
229: auVar2 = CONCAT142(SUB1614(CONCAT133(SUB1613(auVar31 >> 0x18,0),
230: (SUB163(auVar2,0) >> 8) << 0x10) >> 0x10,0),
231: SUB162(auVar2,0)) & (undefined  [16])0xffffffffffff00ff;
232: uVar25 = (ulong)CONCAT24(SUB162(auVar28 >> 0x50,0),(uint)SUB142(auVar27 >> 0x40,0)
233: );
234: uVar29 = SUB162(auVar28 >> 0x60,0);
235: uVar33 = (ulong)CONCAT24(SUB162(auVar7 >> 0x50,0),(uint)SUB162(auVar7 >> 0x40,0));
236: uVar34 = SUB162(auVar7 >> 0x60,0);
237: uVar8 = SUB144(CONCAT212(SUB162(auVar7 >> 0x30,0),ZEXT1012(SUB1610(auVar2,0))) >>
238: 0x50,0);
239: uVar9 = SUB146(CONCAT410(uVar8,CONCAT28(SUB162(auVar31 >> 0x20,0),SUB168(auVar2,0)
240: )) >> 0x40,0);
241: auVar28 = CONCAT106((unkuint10)SUB148(CONCAT68(uVar9,SUB168(auVar2,0)) >> 0x30,0)
242: & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
243: (SUB166(auVar2,0) >> 0x10) << 0x20);
244: Var32 = (unkuint10)
245: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar27 >> 0x30,0
246: ),auVar26) >> 0x50
247: ,0),
248: CONCAT28(SUB122(auVar26 >> 0x20,0),uVar24
249: )) >> 0x40,0),uVar24) >> 0x30,0)
250: & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
251: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
252: auVar31 = CONCAT124(SUB1612(CONCAT106(Var32,(uint6)(uVar23 >> 0x10) << 0x20) >>
253: 0x20,0),uVar22) & (undefined  [16])0xffffffff0000ffff;
254: lVar35 = lVar35 + (SUB168(CONCAT124(SUB1612(auVar28 >> 0x20,0),SUB164(auVar2,0)),0
255: ) & 0xffff) + ((ulong)uVar9 & 0xffffffff) +
256: (uVar33 & 0xffffffff) + (ulong)uVar34 + (SUB168(auVar31,0) & 0xffffffff)
257: + (ulong)(uint)(Var32 >> 0x10) + (uVar25 & 0xffffffff) + (ulong)uVar29;
258: lVar36 = lVar36 + (ulong)SUB164(auVar28 >> 0x20,0) + (ulong)(uVar8 >> 0x10) +
259: (ulong)SUB124(ZEXT1012(CONCAT28(uVar34,uVar33)) >> 0x20,0) +
260: (ulong)SUB162(auVar7 >> 0x70,0) + (ulong)SUB164(auVar31 >> 0x20,0) +
261: (ulong)(uint)(Var32 >> 0x30) +
262: (ulong)SUB124(ZEXT1012(CONCAT28(uVar29,uVar25)) >> 0x20,0) +
263: (ulong)bVar30;
264: } while (uVar17 < uVar18 >> 4);
265: uVar17 = uVar18 & 0xfffffff0;
266: lVar11 = lVar11 + lVar35 + lVar36;
267: iVar12 = uVar17 + iVar12;
268: pbVar14 = pbVar14 + uVar17;
269: if (uVar17 == uVar18) goto LAB_0012348b;
270: }
271: do {
272: iVar12 = iVar12 + 1;
273: lVar11 = lVar11 + (ulong)*pbVar14;
274: pbVar14 = pbVar14 + 1;
275: } while (iVar12 < iVar6);
276: }
277: LAB_0012348b:
278: plVar19 = plVar19 + 1;
279: } while (plVar20 != plVar19);
280: }
281: puVar16 = puVar15 + 1;
282: uVar21 = (ulong)(uint)((int)uVar21 + iVar6);
283: *puVar15 = (char)((lVar11 + (iVar5 * iVar6) / 2) / (long)(iVar5 * iVar6));
284: puVar15 = puVar16;
285: } while (puVar16 != puVar4 + (ulong)(iVar1 - 1) + 1);
286: iVar12 = (int)lStack96;
287: lStack96 = lStack96 + 1;
288: plStack128 = plStack128 + iVar5;
289: plVar20 = plVar20 + iVar5;
290: } while (iVar12 < *(int *)(param_2 + 0xc));
291: }
292: return;
293: }
294: 

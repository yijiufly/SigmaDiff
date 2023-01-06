1: 
2: void FUN_0011a9a0(long param_1,long param_2,long *param_3,long *param_4)
3: 
4: {
5: int iVar1;
6: undefined *puVar2;
7: int iVar3;
8: uint uVar4;
9: undefined auVar5 [16];
10: int iVar6;
11: long lVar7;
12: int iVar8;
13: byte *pbVar9;
14: uint uVar11;
15: uint uVar12;
16: ulong uVar13;
17: long lVar14;
18: uint uVar15;
19: uint uVar16;
20: void *__s;
21: byte *pbVar17;
22: undefined (*pauVar18) [16];
23: undefined *puVar19;
24: undefined *puVar20;
25: long *plVar21;
26: long lVar22;
27: long lVar23;
28: uint uVar24;
29: ulong uVar27;
30: ushort uVar31;
31: byte bVar32;
32: undefined auVar33 [16];
33: ulong uVar35;
34: ushort uVar36;
35: undefined auVar37 [16];
36: long *plStack104;
37: int iStack92;
38: byte *pbVar10;
39: uint5 uVar25;
40: ulong uVar26;
41: undefined auVar28 [12];
42: undefined auVar29 [14];
43: undefined auVar30 [16];
44: unkuint10 Var34;
45: unkuint10 Var38;
46: 
47: uVar11 = *(uint *)(param_1 + 0x30);
48: iVar8 = *(int *)(param_2 + 0xc);
49: iVar6 = *(int *)(param_2 + 0x1c) * 8;
50: uVar4 = *(int *)(param_1 + 0x138) / *(int *)(param_2 + 8);
51: iVar1 = *(int *)(param_1 + 0x13c);
52: iVar3 = iVar1 / iVar8;
53: uVar12 = iVar6 * uVar4 - uVar11;
54: if ((0 < (int)uVar12) && (0 < iVar1)) {
55: plVar21 = param_3;
56: do {
57: __s = (void *)((ulong)uVar11 + *plVar21);
58: plVar21 = plVar21 + 1;
59: memset(__s,(uint)*(byte *)((long)__s + -1),(ulong)uVar12);
60: } while (plVar21 != param_3 + (ulong)(iVar1 - 1) + 1);
61: iVar8 = *(int *)(param_2 + 0xc);
62: }
63: if (0 < iVar8) {
64: iStack92 = 0;
65: plStack104 = param_4;
66: do {
67: puVar2 = (undefined *)*plStack104;
68: if (iVar6 != 0) {
69: uVar13 = 0;
70: puVar19 = puVar2;
71: do {
72: if (iVar3 < 1) {
73: lVar7 = 0;
74: }
75: else {
76: lVar14 = 0;
77: lVar7 = 0;
78: do {
79: pbVar17 = (byte *)(uVar13 + param_3[lVar14]);
80: if (0 < (int)uVar4) {
81: uVar11 = -(int)pbVar17 & 0xf;
82: if (uVar4 <= uVar11) {
83: uVar11 = uVar4;
84: }
85: uVar12 = uVar4;
86: if ((uVar4 < 0x14) || (uVar12 = uVar11, uVar11 != 0)) {
87: uVar11 = 0;
88: pbVar10 = pbVar17;
89: do {
90: pbVar9 = pbVar10 + 1;
91: uVar11 = uVar11 + 1;
92: lVar7 = lVar7 + (ulong)*pbVar10;
93: pbVar10 = pbVar9;
94: } while (uVar11 != uVar12);
95: if (uVar4 == uVar11) goto LAB_0011ad14;
96: }
97: else {
98: uVar12 = 0;
99: uVar11 = 0;
100: pbVar9 = pbVar17;
101: }
102: uVar15 = uVar4 - uVar12;
103: uVar16 = uVar15 & 0xfffffff0;
104: if (uVar15 >> 4 != 0) {
105: lVar22 = 0;
106: lVar23 = 0;
107: pauVar18 = (undefined (*) [16])(pbVar17 + uVar12);
108: uVar12 = 0;
109: do {
110: auVar33 = *pauVar18;
111: uVar12 = uVar12 + 1;
112: pauVar18 = pauVar18[1];
113: uVar24 = (uint)CONCAT12(SUB161(auVar33 >> 0x48,0),
114: (ushort)SUB161(auVar33 >> 0x40,0));
115: uVar25 = CONCAT14(SUB161(auVar33 >> 0x50,0),uVar24);
116: uVar26 = (ulong)CONCAT16(SUB161(auVar33 >> 0x58,0),(uint6)uVar25);
117: auVar28 = ZEXT1112(CONCAT110(SUB161(auVar33 >> 0x68,0),
118: (unkuint10)
119: CONCAT18(SUB161(auVar33 >> 0x60,0),uVar26)));
120: auVar29 = ZEXT1314(CONCAT112(SUB161(auVar33 >> 0x70,0),auVar28));
121: bVar32 = SUB161(auVar33 >> 0x78,0);
122: auVar30 = ZEXT1516(CONCAT114(bVar32,auVar29));
123: auVar5 = CONCAT97((unkuint9)
124: SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(SUB155(
125: CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213(SUB152
126: (CONCAT114(SUB161(auVar33 >> 0x38,0),
127: ZEXT1314(SUB1613(auVar33,0))) >> 0x68,0
128: ),CONCAT112(SUB161(auVar33 >> 0x30,0),
129: SUB1612(auVar33,0))) >> 0x60,0),
130: ZEXT1112(SUB1611(auVar33,0))) >> 0x58,0),
131: CONCAT110(SUB161(auVar33 >> 0x28,0),
132: SUB1610(auVar33,0))) >> 0x50,0),
133: (unkuint10)SUB169(auVar33,0)) >> 0x48,0),
134: CONCAT18(SUB161(auVar33 >> 0x20,0),
135: SUB168(auVar33,0))) >> 0x40,0),
136: SUB168(auVar33,0)) >> 0x38,0) &
137: SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0),
138: (SUB167(auVar33,0) >> 0x18) << 0x30) &
139: (undefined  [16])0xffff000000000000;
140: auVar37 = CONCAT115(SUB1611(auVar5 >> 0x28,0),
141: (SUB165(auVar33,0) >> 0x10) << 0x20) &
142: (undefined  [16])0xffffffff00000000;
143: auVar33 = CONCAT142(SUB1614(CONCAT133(SUB1613(auVar37 >> 0x18,0),
144: (SUB163(auVar33,0) >> 8) << 0x10) >> 0x10,
145: 0),SUB162(auVar33,0)) &
146: (undefined  [16])0xffffffffffff00ff;
147: uVar27 = (ulong)CONCAT24(SUB162(auVar30 >> 0x50,0),
148: (uint)SUB142(auVar29 >> 0x40,0));
149: uVar31 = SUB162(auVar30 >> 0x60,0);
150: Var38 = (unkuint10)
151: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar5 >> 0x30,
152: 0),
153: SUB1612(auVar33,0)) >>
154: 0x50,0),
155: CONCAT28(SUB162(auVar37 >> 0x20,0),
156: SUB168(auVar33,0))) >> 0x40,0)
157: ,SUB168(auVar33,0)) >> 0x30,0) &
158: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
159: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
160: auVar37 = CONCAT124(SUB1612(CONCAT106(Var38,(SUB166(auVar33,0) >> 0x10) << 0x20)
161: >> 0x20,0),SUB164(auVar33,0)) &
162: (undefined  [16])0xffffffff0000ffff;
163: uVar35 = (ulong)CONCAT24(SUB162(auVar5 >> 0x50,0),(uint)SUB162(auVar5 >> 0x40,0)
164: );
165: uVar36 = SUB162(auVar5 >> 0x60,0);
166: Var34 = (unkuint10)
167: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar29 >> 0x30
168: ,0),auVar28) >>
169: 0x50,0),
170: CONCAT28(SUB122(auVar28 >> 0x20,0),
171: uVar26)) >> 0x40,0),uVar26) >>
172: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)
173: & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
174: auVar33 = CONCAT124(SUB1612(CONCAT106(Var34,(uint6)(uVar25 >> 0x10) << 0x20) >>
175: 0x20,0),uVar24) &
176: (undefined  [16])0xffffffff0000ffff;
177: lVar22 = lVar22 + (SUB168(auVar37,0) & 0xffffffff) +
178: (ulong)(uint)(Var38 >> 0x10) + (uVar35 & 0xffffffff) + (ulong)uVar36 +
179: (SUB168(auVar33,0) & 0xffffffff) + (ulong)(uint)(Var34 >> 0x10) +
180: (uVar27 & 0xffffffff) + (ulong)uVar31;
181: lVar23 = lVar23 + (ulong)SUB164(auVar37 >> 0x20,0) +
182: (ulong)(uint)(Var38 >> 0x30) +
183: (ulong)SUB124(ZEXT1012(CONCAT28(uVar36,uVar35)) >> 0x20,0) +
184: (ulong)SUB162(auVar5 >> 0x70,0) + (ulong)SUB164(auVar33 >> 0x20,0) +
185: (ulong)(uint)(Var34 >> 0x30) +
186: (ulong)SUB124(ZEXT1012(CONCAT28(uVar31,uVar27)) >> 0x20,0) +
187: (ulong)bVar32;
188: } while (uVar12 < uVar15 >> 4);
189: uVar11 = uVar11 + uVar16;
190: pbVar9 = pbVar9 + uVar16;
191: lVar7 = lVar7 + lVar22 + lVar23;
192: if (uVar16 == uVar15) goto LAB_0011ad14;
193: }
194: lVar7 = lVar7 + (ulong)*pbVar9;
195: if ((((((int)(uVar11 + 1) < (int)uVar4) &&
196: (lVar7 = lVar7 + (ulong)pbVar9[1], (int)(uVar11 + 2) < (int)uVar4)) &&
197: (lVar7 = lVar7 + (ulong)pbVar9[2], (int)(uVar11 + 3) < (int)uVar4)) &&
198: ((((lVar7 = lVar7 + (ulong)pbVar9[3], (int)(uVar11 + 4) < (int)uVar4 &&
199: (lVar7 = lVar7 + (ulong)pbVar9[4], (int)(uVar11 + 5) < (int)uVar4)) &&
200: ((lVar7 = lVar7 + (ulong)pbVar9[5], (int)(uVar11 + 6) < (int)uVar4 &&
201: ((lVar7 = lVar7 + (ulong)pbVar9[6], (int)(uVar11 + 7) < (int)uVar4 &&
202: (lVar7 = lVar7 + (ulong)pbVar9[7], (int)(uVar11 + 8) < (int)uVar4)))))) &&
203: (lVar7 = lVar7 + (ulong)pbVar9[8], (int)(uVar11 + 9) < (int)uVar4)))) &&
204: ((((lVar7 = lVar7 + (ulong)pbVar9[9], (int)(uVar11 + 10) < (int)uVar4 &&
205: (lVar7 = lVar7 + (ulong)pbVar9[10], (int)(uVar11 + 0xb) < (int)uVar4)) &&
206: (lVar7 = lVar7 + (ulong)pbVar9[0xb], (int)(uVar11 + 0xc) < (int)uVar4)) &&
207: ((lVar7 = lVar7 + (ulong)pbVar9[0xc], (int)(uVar11 + 0xd) < (int)uVar4 &&
208: (lVar7 = lVar7 + (ulong)pbVar9[0xd], (int)(uVar11 + 0xe) < (int)uVar4)))))) {
209: lVar7 = lVar7 + (ulong)pbVar9[0xe];
210: }
211: }
212: LAB_0011ad14:
213: lVar14 = lVar14 + 1;
214: } while ((int)lVar14 < iVar3);
215: }
216: puVar20 = puVar19 + 1;
217: uVar13 = (ulong)((int)uVar13 + uVar4);
218: *puVar19 = (char)((lVar7 + (int)(uVar4 * iVar3) / 2) / (long)(int)(uVar4 * iVar3));
219: puVar19 = puVar20;
220: } while (puVar20 != puVar2 + (ulong)(iVar6 - 1) + 1);
221: iVar8 = *(int *)(param_2 + 0xc);
222: }
223: iStack92 = iStack92 + 1;
224: plStack104 = plStack104 + 1;
225: param_3 = param_3 + iVar3;
226: } while (iStack92 < iVar8);
227: }
228: return;
229: }
230: 

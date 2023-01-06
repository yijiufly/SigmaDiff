1: 
2: void FUN_0011c800(code **param_1,int param_2,int param_3)
3: 
4: {
5: long *plVar1;
6: undefined auVar2 [16];
7: code cVar3;
8: code **ppcVar4;
9: undefined8 *puVar5;
10: undefined *puVar6;
11: long *plVar7;
12: code **ppcVar8;
13: code *pcVar9;
14: uint uVar10;
15: undefined auVar11 [14];
16: int iVar12;
17: int iVar13;
18: code *pcVar14;
19: code *pcVar15;
20: code *pcVar16;
21: undefined auVar17 [16];
22: unkuint10 Var19;
23: uint uVar20;
24: uint uVar21;
25: ushort uVar27;
26: byte bVar28;
27: uint uVar29;
28: ushort uVar30;
29: undefined auVar18 [13];
30: uint5 uVar22;
31: ulong uVar23;
32: undefined auVar24 [12];
33: undefined auVar25 [14];
34: undefined auVar26 [15];
35: 
36: if (param_3 == 0) {
37: pcVar15 = param_1[(long)param_2 + 0x10];
38: }
39: else {
40: pcVar15 = param_1[(long)param_2 + 0x14];
41: param_2 = param_2 + 0x10;
42: }
43: if (pcVar15 == (code *)0x0) {
44: ppcVar4 = (code **)*param_1;
45: *(undefined4 *)(ppcVar4 + 5) = 0x32;
46: *(int *)((long)ppcVar4 + 0x2c) = param_2;
47: (**ppcVar4)(param_1);
48: }
49: if (*(int *)(pcVar15 + 0x114) != 0) {
50: return;
51: }
52: puVar5 = (undefined8 *)param_1[5];
53: puVar6 = (undefined *)*puVar5;
54: *puVar5 = puVar6 + 1;
55: *puVar6 = 0xff;
56: plVar1 = puVar5 + 1;
57: *plVar1 = *plVar1 + -1;
58: if (*plVar1 == 0) {
59: iVar12 = (*(code *)puVar5[3])(param_1);
60: if (iVar12 == 0) {
61: ppcVar4 = (code **)*param_1;
62: *(undefined4 *)(ppcVar4 + 5) = 0x18;
63: (**ppcVar4)(param_1);
64: }
65: }
66: puVar5 = (undefined8 *)param_1[5];
67: puVar6 = (undefined *)*puVar5;
68: *puVar5 = puVar6 + 1;
69: *puVar6 = 0xc4;
70: plVar1 = puVar5 + 1;
71: *plVar1 = *plVar1 + -1;
72: if (*plVar1 == 0) {
73: iVar12 = (*(code *)puVar5[3])(param_1);
74: if (iVar12 == 0) {
75: ppcVar4 = (code **)*param_1;
76: *(undefined4 *)(ppcVar4 + 5) = 0x18;
77: (**ppcVar4)(param_1);
78: }
79: }
80: auVar2 = *(undefined (*) [16])(pcVar15 + 1);
81: pcVar16 = pcVar15 + 1;
82: plVar7 = (long *)param_1[5];
83: auVar18 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
84: SUB158(CONCAT78(
85: SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411(
86: SUB154(CONCAT312(SUB153(CONCAT213(SUB152(CONCAT114
87: (SUB161(auVar2 >> 0x38,0),SUB1614(auVar2,0)) >>
88: 0x68,0),CONCAT112(SUB161(auVar2 >> 0x30,0),
89: SUB1612(auVar2,0))) >> 0x60,0),
90: SUB1612(auVar2,0)) >> 0x58,0),
91: CONCAT110(SUB161(auVar2 >> 0x28,0),
92: SUB1610(auVar2,0))) >> 0x50,0),
93: SUB1610(auVar2,0)) >> 0x48,0),
94: CONCAT18(SUB161(auVar2 >> 0x20,0),SUB168(auVar2,0)
95: )) >> 0x40,0),SUB168(auVar2,0)) >> 0x38,0)
96: & SUB169((undefined  [16])0xffffffffffffffff >>
97: 0x38,0) &
98: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
99: ,0) &
100: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
101: ,0) &
102: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
103: ,0),(SUB167(auVar2,0) >> 0x18) << 0x30) >>
104: 0x30,0),SUB166(auVar2,0)) >> 0x28,0) &
105: SUB1611((undefined  [16])0xffff00ffffffffff >> 0x28,
106: 0),(SUB165(auVar2,0) >> 0x10) << 0x20) >>
107: 0x20,0),SUB164(auVar2,0)) >> 0x18,0) &
108: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
109: auVar17 = CONCAT142(SUB1614(CONCAT133(auVar18,(SUB163(auVar2,0) >> 8) << 0x10) >> 0x10,0),
110: SUB162(auVar2,0)) & (undefined  [16])0xffffffffffff00ff;
111: puVar6 = (undefined *)*plVar7;
112: uVar20 = (uint)CONCAT12(SUB161(auVar2 >> 0x48,0),(ushort)SUB161(auVar2 >> 0x40,0));
113: uVar22 = CONCAT14(SUB161(auVar2 >> 0x50,0),uVar20);
114: uVar23 = (ulong)CONCAT16(SUB161(auVar2 >> 0x58,0),(uint6)uVar22);
115: auVar24 = ZEXT1112(CONCAT110(SUB161(auVar2 >> 0x68,0),
116: (unkuint10)CONCAT18(SUB161(auVar2 >> 0x60,0),uVar23)));
117: auVar25 = ZEXT1314(CONCAT112(SUB161(auVar2 >> 0x70,0),auVar24));
118: bVar28 = SUB161(auVar2 >> 0x78,0);
119: auVar26 = CONCAT114(bVar28,auVar25);
120: uVar29 = (uint)SUB132(auVar18 >> 0x28,0);
121: uVar30 = SUB132(auVar18 >> 0x48,0);
122: uVar10 = SUB144(CONCAT212(SUB162(auVar17 >> 0x30,0),ZEXT1012(SUB1610(auVar17,0))) >> 0x50,0);
123: auVar11 = CONCAT410(uVar10,CONCAT28(SUB162(auVar17 >> 0x20,0),SUB168(auVar17,0)));
124: *plVar7 = (long)(puVar6 + 1);
125: Var19 = (unkuint10)
126: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar25 >> 0x30,0),auVar24) >>
127: 0x50,0),CONCAT28(SUB122(auVar24 >> 0x20,0),uVar23)
128: ) >> 0x40,0),uVar23) >> 0x30,0) &
129: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
130: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
131: uVar21 = (uint)SUB142(auVar25 >> 0x40,0);
132: uVar27 = (ushort)((unkuint10)SUB159(auVar26 >> 0x30,0) >> 0x30);
133: iVar12 = (SUB164(auVar17,0) & 0xffff) + uVar29 + (uVar20 & 0xffff) + uVar21 +
134: SUB164(ZEXT1416(auVar11) >> 0x40,0) + (uint)uVar30 + (int)(Var19 >> 0x10) + (uint)uVar27
135: + SUB164(CONCAT106((unkuint10)
136: SUB148(CONCAT68(SUB146(auVar11 >> 0x40,0),SUB168(auVar17,0)) >> 0x30,0
137: ) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
138: (SUB166(auVar17,0) >> 0x10) << 0x20) >> 0x20,0) +
139: SUB124(ZEXT1012(CONCAT28(uVar30,(ulong)CONCAT24(SUB132(auVar18 >> 0x38,0),uVar29))) >>
140: 0x20,0) + SUB164(CONCAT106(Var19,(uint6)(uVar22 >> 0x10) << 0x20) >> 0x20,0) +
141: SUB124(ZEXT1012(CONCAT28(uVar27,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(auVar26 >> 0x10
142: ,0)) >> 0x40,0)
143: ,uVar21))) >> 0x20,0) +
144: (uVar10 >> 0x10) + (uint)SUB132(auVar18 >> 0x58,0) + (int)(Var19 >> 0x30) +
145: (uint)bVar28;
146: *puVar6 = (char)((uint)(iVar12 + 0x13) >> 8);
147: plVar1 = plVar7 + 1;
148: *plVar1 = *plVar1 + -1;
149: if (*plVar1 == 0) {
150: iVar13 = (*(code *)plVar7[3])(param_1);
151: if (iVar13 == 0) {
152: ppcVar4 = (code **)*param_1;
153: *(undefined4 *)(ppcVar4 + 5) = 0x18;
154: (**ppcVar4)(param_1);
155: }
156: }
157: plVar7 = (long *)param_1[5];
158: puVar6 = (undefined *)*plVar7;
159: *plVar7 = (long)(puVar6 + 1);
160: *puVar6 = (char)(iVar12 + 0x13);
161: plVar1 = plVar7 + 1;
162: *plVar1 = *plVar1 + -1;
163: if (*plVar1 == 0) {
164: iVar13 = (*(code *)plVar7[3])(param_1);
165: if (iVar13 == 0) {
166: ppcVar4 = (code **)*param_1;
167: *(undefined4 *)(ppcVar4 + 5) = 0x18;
168: (**ppcVar4)(param_1);
169: }
170: }
171: plVar7 = (long *)param_1[5];
172: puVar6 = (undefined *)*plVar7;
173: *plVar7 = (long)(puVar6 + 1);
174: *puVar6 = (char)param_2;
175: plVar1 = plVar7 + 1;
176: *plVar1 = *plVar1 + -1;
177: if (*plVar1 == 0) {
178: iVar13 = (*(code *)plVar7[3])(param_1);
179: if (iVar13 == 0) {
180: ppcVar4 = (code **)*param_1;
181: *(undefined4 *)(ppcVar4 + 5) = 0x18;
182: (**ppcVar4)(param_1);
183: }
184: }
185: pcVar14 = pcVar15 + 0x11;
186: do {
187: ppcVar8 = (code **)param_1[5];
188: cVar3 = *pcVar16;
189: pcVar9 = *ppcVar8;
190: *ppcVar8 = pcVar9 + 1;
191: *pcVar9 = cVar3;
192: ppcVar4 = ppcVar8 + 1;
193: *ppcVar4 = *ppcVar4 + -1;
194: if (*ppcVar4 == (code *)0x0) {
195: iVar13 = (*ppcVar8[3])(param_1);
196: if (iVar13 == 0) {
197: ppcVar4 = (code **)*param_1;
198: *(undefined4 *)(ppcVar4 + 5) = 0x18;
199: (**ppcVar4)(param_1);
200: }
201: }
202: pcVar16 = pcVar16 + 1;
203: } while (pcVar14 != pcVar16);
204: if (0 < iVar12) {
205: do {
206: ppcVar8 = (code **)param_1[5];
207: cVar3 = *pcVar14;
208: pcVar16 = *ppcVar8;
209: *ppcVar8 = pcVar16 + 1;
210: *pcVar16 = cVar3;
211: ppcVar4 = ppcVar8 + 1;
212: *ppcVar4 = *ppcVar4 + -1;
213: if (*ppcVar4 == (code *)0x0) {
214: iVar13 = (*ppcVar8[3])(param_1);
215: if (iVar13 == 0) {
216: ppcVar4 = (code **)*param_1;
217: *(undefined4 *)(ppcVar4 + 5) = 0x18;
218: (**ppcVar4)(param_1);
219: }
220: }
221: pcVar14 = pcVar14 + 1;
222: } while (pcVar15 + (ulong)(iVar12 - 1) + 0x12 != pcVar14);
223: }
224: *(undefined4 *)(pcVar15 + 0x114) = 1;
225: return;
226: }
227: 

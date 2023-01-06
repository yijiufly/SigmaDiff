1: 
2: void FUN_00120d10(long param_1,long *param_2,uint param_3,long *param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: undefined *puVar2;
7: undefined *puVar3;
8: undefined auVar4 [16];
9: undefined auVar5 [16];
10: int iVar6;
11: uint uVar7;
12: long lVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: undefined uVar11;
16: undefined uVar12;
17: undefined uVar13;
18: undefined uVar14;
19: undefined uVar15;
20: undefined uVar16;
21: undefined uVar17;
22: undefined uVar18;
23: undefined uVar19;
24: undefined uVar20;
25: undefined uVar21;
26: undefined uVar22;
27: undefined uVar23;
28: undefined uVar24;
29: undefined uVar25;
30: undefined uVar26;
31: undefined uVar27;
32: undefined uVar28;
33: undefined uVar29;
34: undefined uVar30;
35: long *plVar31;
36: uint uVar32;
37: long lVar33;
38: long lVar34;
39: ulong uVar35;
40: long lVar36;
41: ulong uVar37;
42: undefined *puVar38;
43: undefined *puVar39;
44: uint uVar40;
45: uint3 uVar41;
46: undefined uVar43;
47: undefined uVar44;
48: undefined uVar45;
49: uint3 uVar46;
50: undefined uVar55;
51: undefined uVar56;
52: undefined uVar57;
53: undefined uVar58;
54: undefined uVar59;
55: undefined uVar60;
56: undefined auVar61 [16];
57: uint5 uVar42;
58: uint5 uVar47;
59: uint7 uVar48;
60: undefined8 uVar49;
61: unkbyte9 Var50;
62: unkbyte10 Var51;
63: undefined auVar52 [11];
64: undefined auVar53 [12];
65: undefined auVar54 [13];
66: undefined uVar62;
67: undefined uVar63;
68: undefined uVar64;
69: undefined uVar65;
70: 
71: iVar6 = *(int *)(param_1 + 0x38);
72: uVar7 = *(uint *)(param_1 + 0x88);
73: if (iVar6 == 3) {
74: while (param_5 = param_5 + -1, -1 < param_5) {
75: uVar35 = (ulong)param_3;
76: plVar31 = param_4 + 1;
77: param_3 = param_3 + 1;
78: lVar33 = *(long *)(*param_2 + uVar35 * 8);
79: lVar8 = *(long *)(param_2[1] + uVar35 * 8);
80: lVar34 = *(long *)(param_2[2] + uVar35 * 8);
81: lVar36 = 0;
82: puVar39 = (undefined *)*param_4;
83: param_4 = plVar31;
84: if (uVar7 != 0) {
85: do {
86: *puVar39 = *(undefined *)(lVar33 + lVar36);
87: puVar39[1] = *(undefined *)(lVar8 + lVar36);
88: puVar1 = (undefined *)(lVar34 + lVar36);
89: lVar36 = lVar36 + 1;
90: puVar39[2] = *puVar1;
91: puVar39 = puVar39 + 3;
92: } while ((uint)lVar36 < uVar7);
93: }
94: }
95: }
96: else {
97: if (iVar6 == 4) {
98: uVar35 = (ulong)uVar7;
99: uVar32 = uVar7 & 0xfffffff0;
100: LAB_00120e23:
101: param_5 = param_5 + -1;
102: if (-1 < param_5) {
103: uVar37 = (ulong)param_3;
104: plVar31 = param_4 + 1;
105: param_3 = param_3 + 1;
106: puVar39 = *(undefined **)(*param_2 + uVar37 * 8);
107: puVar1 = *(undefined **)(param_2[1] + uVar37 * 8);
108: puVar9 = *(undefined **)(param_2[2] + uVar37 * 8);
109: puVar10 = *(undefined **)(param_2[3] + uVar37 * 8);
110: puVar38 = (undefined *)*param_4;
111: param_4 = plVar31;
112: if (uVar7 != 0) {
113: puVar2 = puVar38 + uVar35 * 4;
114: if (((0xf < uVar7 &&
115: ((puVar9 + uVar35 <= puVar38 || puVar2 <= puVar9) &&
116: (puVar1 + uVar35 <= puVar38 || puVar2 <= puVar1))) &&
117: (puVar39 + uVar35 <= puVar38 || puVar2 <= puVar39)) &&
118: (puVar10 + uVar35 <= puVar38 || puVar2 <= puVar10)) {
119: if (uVar32 == 0) {
120: uVar40 = 0;
121: }
122: else {
123: lVar33 = 0;
124: uVar40 = 0;
125: do {
126: auVar4 = *(undefined (*) [16])(puVar39 + lVar33);
127: uVar40 = uVar40 + 1;
128: puVar3 = puVar9 + lVar33;
129: uVar11 = puVar3[4];
130: uVar12 = puVar3[5];
131: uVar13 = puVar3[6];
132: uVar14 = puVar3[7];
133: uVar15 = puVar3[10];
134: uVar16 = puVar3[0xb];
135: uVar17 = puVar3[0xc];
136: uVar18 = puVar3[0xd];
137: uVar19 = puVar3[0xe];
138: uVar20 = puVar3[0xf];
139: auVar5 = *(undefined (*) [16])(puVar1 + lVar33);
140: uVar55 = SUB161(auVar4 >> 0x40,0);
141: uVar46 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar3[8],uVar55));
142: uVar56 = SUB161(auVar4 >> 0x50,0);
143: uVar47 = CONCAT14(uVar56,CONCAT13(puVar3[9],uVar46));
144: uVar57 = SUB161(auVar4 >> 0x58,0);
145: uVar48 = CONCAT16(uVar57,CONCAT15(uVar15,uVar47));
146: uVar49 = CONCAT17(uVar16,uVar48);
147: uVar58 = SUB161(auVar4 >> 0x60,0);
148: Var50 = CONCAT18(uVar58,uVar49);
149: Var51 = CONCAT19(uVar17,Var50);
150: uVar59 = SUB161(auVar4 >> 0x68,0);
151: auVar52 = CONCAT110(uVar59,Var51);
152: auVar53 = CONCAT111(uVar18,auVar52);
153: uVar60 = SUB161(auVar4 >> 0x70,0);
154: auVar54 = CONCAT112(uVar60,auVar53);
155: uVar65 = SUB161(auVar4 >> 0x38,0);
156: uVar64 = SUB161(auVar4 >> 0x30,0);
157: uVar63 = SUB161(auVar4 >> 0x28,0);
158: uVar62 = SUB161(auVar4 >> 0x20,0);
159: auVar61 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101
160: (SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
161: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
162: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
163: uVar14,CONCAT114(uVar65,SUB1614(auVar4,0))) >>
164: 0x70,0),CONCAT113(uVar13,SUB1613(auVar4,0))) >>
165: 0x68,0),CONCAT112(uVar64,SUB1612(auVar4,0))) >>
166: 0x60,0),CONCAT111(uVar12,SUB1611(auVar4,0))) >>
167: 0x58,0),CONCAT110(uVar63,SUB1610(auVar4,0))) >>
168: 0x50,0),CONCAT19(uVar11,SUB169(auVar4,0))) >> 0x48
169: ,0),CONCAT18(uVar62,SUB168(auVar4,0))) >> 0x40,0),
170: puVar3[3])) << 0x38) >> 0x30,0),puVar3[2])) <<
171: 0x28) >> 0x20,0),puVar3[1]),
172: (SUB163(auVar4,0) >> 8) << 0x10) >> 0x10,0),
173: *puVar3)) << 8;
174: puVar2 = puVar10 + lVar33;
175: uVar21 = puVar2[4];
176: uVar22 = puVar2[5];
177: uVar23 = puVar2[6];
178: uVar24 = puVar2[7];
179: uVar25 = puVar2[10];
180: uVar26 = puVar2[0xb];
181: uVar27 = puVar2[0xc];
182: uVar28 = puVar2[0xd];
183: uVar29 = puVar2[0xe];
184: uVar30 = puVar2[0xf];
185: uVar43 = SUB161(auVar5 >> 0x40,0);
186: uVar41 = CONCAT12(SUB161(auVar5 >> 0x48,0),CONCAT11(puVar2[8],uVar43));
187: uVar44 = SUB161(auVar5 >> 0x50,0);
188: uVar42 = CONCAT14(uVar44,CONCAT13(puVar2[9],uVar41));
189: uVar45 = SUB161(auVar5 >> 0x58,0);
190: *(undefined (*) [16])(puVar38 + lVar33 * 4) =
191: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
192: CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610
193: (SUB166(CONCAT511(SUB165(CONCAT412(SUB164(
194: CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(puVar2
195: [3],CONCAT114(puVar3[3],SUB1614(auVar61,0))) >>
196: 0x70,0),CONCAT113(SUB161(auVar5 >> 0x18,0),
197: SUB1613(auVar61,0))) >> 0x68,0),
198: CONCAT112(SUB161(auVar4 >> 0x18,0),
199: SUB1612(auVar61,0))) >> 0x60,0),
200: CONCAT111(puVar2[2],SUB1611(auVar61,0))) >> 0x58,0
201: ),CONCAT110(puVar3[2],SUB1610(auVar61,0))) >> 0x50
202: ,0),CONCAT19(SUB161(auVar5 >> 0x10,0),
203: SUB169(auVar61,0))) >> 0x48,0),
204: CONCAT18(SUB161(auVar4 >> 0x10,0),
205: SUB168(auVar61,0))) >> 0x40,0),puVar2[1])
206: ,(SUB167(auVar61,0) >> 0x18) << 0x30) >> 0x30,0),
207: SUB161(auVar5 >> 8,0)),
208: (SUB165(auVar61,0) >> 0x10) << 0x20) >> 0x20,0),
209: *puVar2),(SUB163(auVar61,0) >> 8) << 0x10) >> 0x10
210: ,0),SUB162(auVar4,0) & 0xff | SUB162(auVar5,0) << 8);
211: puVar2 = puVar38 + lVar33 * 4 + 0x10;
212: *puVar2 = uVar62;
213: puVar2[1] = SUB161(auVar5 >> 0x20,0);
214: puVar2[2] = uVar11;
215: puVar2[3] = uVar21;
216: puVar2[4] = uVar63;
217: puVar2[5] = SUB161(auVar5 >> 0x28,0);
218: puVar2[6] = uVar12;
219: puVar2[7] = uVar22;
220: puVar2[8] = uVar64;
221: puVar2[9] = SUB161(auVar5 >> 0x30,0);
222: puVar2[10] = uVar13;
223: puVar2[0xb] = uVar23;
224: puVar2[0xc] = uVar65;
225: puVar2[0xd] = SUB161(auVar5 >> 0x38,0);
226: puVar2[0xe] = uVar14;
227: puVar2[0xf] = uVar24;
228: *(undefined (*) [16])(puVar38 + lVar33 * 4 + 0x20) =
229: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(
230: CONCAT106(SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(
231: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
232: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
233: (CONCAT115(uVar26,CONCAT114(uVar16,CONCAT113(
234: uVar19,auVar54))) >> 0x70,0),
235: CONCAT113(uVar45,auVar54)) >> 0x68,0),
236: CONCAT112(uVar57,auVar53)) >> 0x60,0),
237: CONCAT111(uVar25,auVar52)) >> 0x58,0),
238: CONCAT110(uVar15,Var51)) >> 0x50,0),
239: CONCAT19(uVar44,Var50)) >> 0x48,0),
240: CONCAT18(uVar56,uVar49)) >> 0x40,0),
241: (((ulong)CONCAT16(uVar45,CONCAT15(uVar25,uVar42))
242: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
243: (uVar48 >> 0x18) << 0x30) >> 0x30,0),
244: (((uint6)uVar42 & 0xff0000) >> 0x10) << 0x28) >>
245: 0x28,0),(uVar47 >> 0x10) << 0x20) >> 0x20,0),
246: ((uVar41 & 0xff00) >> 8) << 0x18) >> 0x18,0),
247: (uVar46 >> 8) << 0x10) >> 0x10,0),
248: CONCAT11(uVar43,uVar55));
249: puVar2 = puVar38 + lVar33 * 4 + 0x30;
250: *puVar2 = uVar58;
251: puVar2[1] = SUB161(auVar5 >> 0x60,0);
252: puVar2[2] = uVar17;
253: puVar2[3] = uVar27;
254: puVar2[4] = uVar59;
255: puVar2[5] = SUB161(auVar5 >> 0x68,0);
256: puVar2[6] = uVar18;
257: puVar2[7] = uVar28;
258: puVar2[8] = uVar60;
259: puVar2[9] = SUB161(auVar5 >> 0x70,0);
260: puVar2[10] = uVar19;
261: puVar2[0xb] = uVar29;
262: puVar2[0xc] = SUB161(auVar4 >> 0x78,0);
263: puVar2[0xd] = SUB161(auVar5 >> 0x78,0);
264: puVar2[0xe] = uVar20;
265: puVar2[0xf] = uVar30;
266: lVar33 = lVar33 + 0x10;
267: } while (uVar40 < uVar7 >> 4);
268: puVar38 = puVar38 + (ulong)uVar32 * 4;
269: uVar40 = uVar32;
270: if (uVar7 == uVar32) goto LAB_00120e23;
271: }
272: do {
273: uVar37 = (ulong)uVar40;
274: uVar40 = uVar40 + 1;
275: *puVar38 = puVar39[uVar37];
276: puVar38[1] = puVar1[uVar37];
277: puVar38[2] = puVar9[uVar37];
278: puVar38[3] = puVar10[uVar37];
279: puVar38 = puVar38 + 4;
280: } while (uVar40 < uVar7);
281: goto LAB_00120e23;
282: }
283: lVar33 = 0;
284: do {
285: *puVar38 = puVar39[lVar33];
286: puVar38[1] = puVar1[lVar33];
287: puVar38[2] = puVar9[lVar33];
288: puVar2 = puVar10 + lVar33;
289: lVar33 = lVar33 + 1;
290: puVar38[3] = *puVar2;
291: puVar38 = puVar38 + 4;
292: } while ((uint)lVar33 < uVar7);
293: }
294: goto LAB_00120e23;
295: }
296: }
297: else {
298: if (0 < param_5) {
299: uVar32 = param_5 + param_3;
300: do {
301: if (0 < iVar6) {
302: lVar33 = 0;
303: do {
304: puVar39 = (undefined *)(lVar33 + *param_4);
305: lVar8 = *(long *)(param_2[lVar33] + (ulong)param_3 * 8);
306: lVar34 = 0;
307: if (uVar7 != 0) {
308: do {
309: puVar1 = (undefined *)(lVar8 + lVar34);
310: lVar34 = lVar34 + 1;
311: *puVar39 = *puVar1;
312: puVar39 = puVar39 + iVar6;
313: } while ((uint)lVar34 < uVar7);
314: }
315: lVar33 = lVar33 + 1;
316: } while ((int)lVar33 < iVar6);
317: }
318: param_3 = param_3 + 1;
319: param_4 = param_4 + 1;
320: } while (param_3 != uVar32);
321: }
322: }
323: }
324: return;
325: }
326: 

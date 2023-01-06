1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00168840(undefined8 param_1,long param_2,short *param_3,long *param_4,uint param_5)
5: 
6: {
7: char *pcVar1;
8: long lVar2;
9: short *psVar3;
10: ulong uVar4;
11: uint uVar5;
12: undefined2 uVar11;
13: uint6 uVar6;
14: undefined auVar9 [12];
15: undefined2 uVar12;
16: undefined auVar10 [16];
17: ulong uVar13;
18: undefined4 uVar15;
19: ulong uVar16;
20: undefined auVar14 [16];
21: int iVar17;
22: int iVar18;
23: uint6 uVar19;
24: int iVar25;
25: int iVar26;
26: unkint10 Var22;
27: int iVar27;
28: int iVar28;
29: int iVar30;
30: long lVar29;
31: undefined auVar24 [16];
32: int iVar31;
33: uint uVar32;
34: undefined4 uVar33;
35: int iVar34;
36: int iVar35;
37: int iVar36;
38: int iVar37;
39: int iVar38;
40: int iVar39;
41: int iVar40;
42: int iVar41;
43: int iVar42;
44: int iVar43;
45: int iVar44;
46: int iVar45;
47: int iVar46;
48: int iVar49;
49: int iVar50;
50: undefined auVar47 [16];
51: int iVar51;
52: undefined auVar48 [16];
53: int iVar52;
54: int iVar53;
55: int iVar55;
56: int iVar56;
57: int iVar57;
58: int iVar58;
59: int iVar59;
60: undefined auVar54 [16];
61: int iVar60;
62: int iVar61;
63: int iVar66;
64: undefined auVar62 [12];
65: int iVar65;
66: undefined auVar63 [16];
67: int iVar67;
68: undefined auVar64 [16];
69: undefined8 uVar7;
70: unkbyte10 Var8;
71: undefined8 uVar20;
72: unkbyte10 Var21;
73: undefined auVar23 [14];
74: 
75: psVar3 = *(short **)(param_2 + 0x58);
76: uVar4 = (ulong)param_5;
77: if ((*(uint *)(param_3 + 8) | *(uint *)(param_3 + 0x10)) == 0) {
78: auVar10 = *(undefined (*) [16])(param_3 + 8) | *(undefined (*) [16])(param_3 + 0x18) |
79: *(undefined (*) [16])(param_3 + 0x30) |
80: *(undefined (*) [16])(param_3 + 0x10) | *(undefined (*) [16])(param_3 + 0x28) |
81: *(undefined (*) [16])(param_3 + 0x38);
82: auVar10 = packsswb(auVar10,auVar10);
83: auVar10 = packsswb(auVar10,auVar10);
84: if (SUB164(auVar10,0) == 0) {
85: auVar10 = psllw(CONCAT214(param_3[7] * psVar3[7],
86: CONCAT212(param_3[6] * psVar3[6],
87: CONCAT210(param_3[5] * psVar3[5],
88: CONCAT28(param_3[4] * psVar3[4],
89: CONCAT26(param_3[3] * psVar3[3],
90: CONCAT24(param_3[2] *
91: psVar3[2],
92: CONCAT22(param_3[1] *
93: psVar3[1],
94: *param_3 *
95: *psVar3)))))
96: )),2);
97: uVar12 = SUB162(auVar10 >> 0x30,0);
98: uVar11 = SUB162(auVar10 >> 0x20,0);
99: uVar33 = SUB164(CONCAT214(uVar12,CONCAT212(uVar12,SUB1612(auVar10,0))) >> 0x60,0);
100: uVar13 = SUB168(CONCAT610(SUB166(CONCAT412(uVar33,CONCAT210(uVar11,SUB1610(auVar10,0))) >>
101: 0x50,0),CONCAT28(uVar11,SUB168(auVar10,0))) >> 0x40,0);
102: uVar5 = SUB164(auVar10,0) & 0xffff | SUB164(auVar10,0) << 0x10;
103: auVar24 = auVar10 & (undefined  [16])0xffffffffffff0000;
104: uVar32 = SUB144(CONCAT122(SUB1612(auVar24 >> 0x20,0),SUB162(auVar10 >> 0x40,0)),0) << 0x10;
105: uVar11 = SUB162(auVar24 >> 0x50,0);
106: uVar16 = CONCAT26(uVar11,CONCAT24(uVar11,uVar32));
107: uVar11 = SUB162(auVar24 >> 0x60,0);
108: auVar9 = CONCAT210(uVar11,CONCAT28(uVar11,uVar16));
109: uVar11 = SUB162(auVar24 >> 0x70,0);
110: uVar15 = SUB164(CONCAT106(SUB1610(CONCAT88(uVar13,(SUB168(auVar10,0) >> 0x10) << 0x30) >> 0x30
111: ,0),(SUB166(auVar10,0) >> 0x10) << 0x20) >> 0x20,0);
112: auVar24 = CONCAT412(uVar15,CONCAT48(uVar15,CONCAT44(uVar5,uVar5)));
113: auVar10 = CONCAT412(uVar33,CONCAT48(uVar33,uVar13 & 0xffffffff | uVar13 << 0x20));
114: uVar7 = SUB168((ZEXT1216(CONCAT48((int)(uVar16 >> 0x20),
115: uVar16 & 0xffffffff00000000 | (ulong)uVar32)) << 0x20) >>
116: 0x40,0);
117: uVar33 = SUB124(auVar9 >> 0x40,0);
118: uVar15 = SUB164(CONCAT214(uVar11,CONCAT212(uVar11,auVar9)) >> 0x60,0);
119: auVar64 = CONCAT412(uVar15,CONCAT48(uVar15,CONCAT44(uVar33,uVar33)));
120: goto LAB_0015f72c;
121: }
122: }
123: uVar6 = CONCAT24(param_3[10] * psVar3[10],CONCAT22(param_3[9] * psVar3[9],param_3[8] * psVar3[8]))
124: ;
125: uVar7 = CONCAT26(param_3[0xb] * psVar3[0xb],uVar6);
126: Var8 = CONCAT28(param_3[0xc] * psVar3[0xc],uVar7);
127: uVar19 = CONCAT24(param_3[0x2a] * psVar3[0x2a],
128: CONCAT22(param_3[0x29] * psVar3[0x29],param_3[0x28] * psVar3[0x28]));
129: uVar20 = CONCAT26(param_3[0x2b] * psVar3[0x2b],uVar19);
130: Var21 = CONCAT28(param_3[0x2c] * psVar3[0x2c],uVar20);
131: auVar10 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
132: CONCAT214(param_3[0x1b] * psVar3[0x1b],
133: CONCAT212(param_3[0xb] * psVar3[0xb],
134: CONCAT210(param_3[0xd] *
135: psVar3[0xd],Var8)))
136: >> 0x60,0),
137: CONCAT210(param_3[0x1a] * psVar3[0x1a],Var8)) >>
138: 0x50,0),CONCAT28(param_3[10] * psVar3[10],uVar7))
139: >> 0x40,0),
140: (((ulong)CONCAT24(param_3[0x1a] * psVar3[0x1a],
141: CONCAT22(param_3[0x19] *
142: psVar3[0x19],
143: param_3[0x18] *
144: psVar3[0x18])) &
145: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
146: (uVar6 >> 0x10) << 0x20) >> 0x20,0),
147: CONCAT22(param_3[0x18] * psVar3[0x18],param_3[8] * psVar3[8]));
148: auVar24 = CONCAT214(param_3[0x1f] * psVar3[0x1f],
149: CONCAT212(param_3[0xf] * psVar3[0xf],
150: CONCAT210(param_3[0x1e] * psVar3[0x1e],
151: CONCAT28(param_3[0xe] * psVar3[0xe],
152: CONCAT26(param_3[0x1d] * psVar3[0x1d],
153: CONCAT24(param_3[0xd] * psVar3[0xd],
154: CONCAT22(param_3[0x1c] *
155: psVar3[0x1c],
156: param_3[0xc] *
157: psVar3[0xc])))))));
158: auVar48 = pmaddwd(auVar10,_DAT_0019ccb0);
159: auVar47 = pmaddwd(auVar24,_DAT_0019ccb0);
160: auVar10 = pmaddwd(auVar10,_DAT_0019ccc0);
161: auVar24 = pmaddwd(auVar24,_DAT_0019ccc0);
162: auVar64 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
163: CONCAT214(param_3[0x3b] * psVar3[0x3b],
164: CONCAT212(param_3[0x2b] * psVar3[0x2b],
165: CONCAT210(param_3[0x2d] *
166: psVar3[0x2d],Var21))
167: ) >> 0x60,0),
168: CONCAT210(param_3[0x3a] * psVar3[0x3a],Var21)) >>
169: 0x50,0),CONCAT28(param_3[0x2a] * psVar3[0x2a],
170: uVar20)) >> 0x40,0),
171: (((ulong)CONCAT24(param_3[0x3a] * psVar3[0x3a],
172: CONCAT22(param_3[0x39] *
173: psVar3[0x39],
174: param_3[0x38] *
175: psVar3[0x38])) &
176: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
177: (uVar19 >> 0x10) << 0x20) >> 0x20,0),
178: CONCAT22(param_3[0x38] * psVar3[0x38],param_3[0x28] * psVar3[0x28]));
179: auVar14 = CONCAT214(param_3[0x3f] * psVar3[0x3f],
180: CONCAT212(param_3[0x2f] * psVar3[0x2f],
181: CONCAT210(param_3[0x3e] * psVar3[0x3e],
182: CONCAT28(param_3[0x2e] * psVar3[0x2e],
183: CONCAT26(param_3[0x3d] * psVar3[0x3d],
184: CONCAT24(param_3[0x2d] * psVar3[0x2d],
185: CONCAT22(param_3[0x3c] *
186: psVar3[0x3c],
187: param_3[0x2c] *
188: psVar3[0x2c])))))));
189: auVar54 = pmaddwd(auVar64,_DAT_0019ccd0);
190: auVar63 = pmaddwd(auVar14,_DAT_0019ccd0);
191: auVar64 = pmaddwd(auVar64,_DAT_0019cce0);
192: auVar14 = pmaddwd(auVar14,_DAT_0019cce0);
193: iVar52 = SUB164(auVar54,0) + SUB164(auVar48,0);
194: iVar55 = SUB164(auVar54 >> 0x20,0) + SUB164(auVar48 >> 0x20,0);
195: iVar57 = SUB164(auVar54 >> 0x40,0) + SUB164(auVar48 >> 0x40,0);
196: iVar59 = SUB164(auVar54 >> 0x60,0) + SUB164(auVar48 >> 0x60,0);
197: iVar61 = SUB164(auVar63,0) + SUB164(auVar47,0);
198: iVar65 = SUB164(auVar63 >> 0x20,0) + SUB164(auVar47 >> 0x20,0);
199: iVar66 = SUB164(auVar63 >> 0x40,0) + SUB164(auVar47 >> 0x40,0);
200: iVar67 = SUB164(auVar63 >> 0x60,0) + SUB164(auVar47 >> 0x60,0);
201: iVar44 = SUB164(auVar64,0) + SUB164(auVar10,0);
202: iVar46 = SUB164(auVar64 >> 0x20,0) + SUB164(auVar10 >> 0x20,0);
203: iVar56 = SUB164(auVar64 >> 0x40,0) + SUB164(auVar10 >> 0x40,0);
204: iVar60 = SUB164(auVar64 >> 0x60,0) + SUB164(auVar10 >> 0x60,0);
205: iVar34 = SUB164(auVar14,0) + SUB164(auVar24,0);
206: iVar35 = SUB164(auVar14 >> 0x20,0) + SUB164(auVar24 >> 0x20,0);
207: iVar37 = SUB164(auVar14 >> 0x40,0) + SUB164(auVar24 >> 0x40,0);
208: iVar39 = SUB164(auVar14 >> 0x60,0) + SUB164(auVar24 >> 0x60,0);
209: uVar6 = CONCAT24(param_3[0x12] * psVar3[0x12],
210: CONCAT22(param_3[0x11] * psVar3[0x11],param_3[0x10] * psVar3[0x10]));
211: uVar7 = CONCAT26(param_3[0x13] * psVar3[0x13],uVar6);
212: Var8 = CONCAT28(param_3[0x14] * psVar3[0x14],uVar7);
213: Var22 = (unkuint10)CONCAT24(param_3[5] * psVar3[5],(uint)(ushort)(param_3[4] * psVar3[4])) << 0x10
214: ;
215: auVar23 = ZEXT1214(CONCAT210(param_3[6] * psVar3[6],Var22));
216: iVar26 = (int)((uint)(ushort)(*param_3 * *psVar3) << 0x10) >> 2;
217: iVar31 = (int)((long)((((ulong)CONCAT24(param_3[2] * psVar3[2],
218: CONCAT22(param_3[1] * psVar3[1],*param_3 * *psVar3)) &
219: 0xffff0000) >> 0x10) << 0x30) >> 0x22);
220: iVar42 = SUB164(ZEXT1216(CONCAT210(param_3[2] * psVar3[2],(unkuint10)0)) >> 0x40,0) >> 2;
221: iVar17 = (int)Var22 >> 2;
222: iVar25 = SUB144(auVar23 >> 0x20,0) >> 2;
223: iVar27 = SUB144(auVar23 >> 0x40,0) >> 2;
224: iVar18 = SUB164(CONCAT214(param_3[7] * psVar3[7],auVar23) >> 0x62,0);
225: auVar24 = pmaddwd(CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
226: SUB164(CONCAT214(param_3[0x33] * psVar3[0x33],
227: CONCAT212(param_3[0x13] *
228: psVar3[0x13],
229: CONCAT210(param_3[0x15]
230: * psVar3[0x15
231: ],Var8))) >> 0x60,0),
232: CONCAT210(param_3[0x32] * psVar3[0x32],Var8)) >>
233: 0x50,0),CONCAT28(param_3[0x12] * psVar3[0x12],
234: uVar7)) >> 0x40,0),
235: (((ulong)CONCAT24(param_3[0x32] * psVar3[0x32],
236: CONCAT22(param_3[0x31] *
237: psVar3[0x31],
238: param_3[0x30] *
239: psVar3[0x30])) &
240: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
241: (uVar6 >> 0x10) << 0x20) >> 0x20,0),
242: CONCAT22(param_3[0x30] * psVar3[0x30],param_3[0x10] * psVar3[0x10])),
243: _DAT_0019cca0);
244: auVar10 = pmaddwd(CONCAT214(param_3[0x37] * psVar3[0x37],
245: CONCAT212(param_3[0x17] * psVar3[0x17],
246: CONCAT210(param_3[0x36] * psVar3[0x36],
247: CONCAT28(param_3[0x16] * psVar3[0x16],
248: CONCAT26(param_3[0x35] * psVar3[0x35],
249: CONCAT24(param_3[0x15] *
250: psVar3[0x15],
251: CONCAT22(param_3[0x34]
252: * psVar3[0x34]
253: ,param_3[0x14]
254: * psVar3[0x14
255: ]))))))),_DAT_0019cca0);
256: iVar28 = iVar26 + SUB164(auVar24,0);
257: iVar49 = SUB164(auVar24 >> 0x20,0);
258: iVar41 = iVar31 + iVar49;
259: iVar50 = SUB164(auVar24 >> 0x40,0);
260: iVar43 = iVar42 + iVar50;
261: iVar51 = SUB164(auVar24 >> 0x60,0);
262: iVar45 = iVar17 + SUB164(auVar10,0);
263: iVar36 = SUB164(auVar10 >> 0x20,0);
264: iVar53 = iVar25 + iVar36;
265: iVar38 = SUB164(auVar10 >> 0x40,0);
266: iVar58 = iVar27 + iVar38;
267: iVar40 = SUB164(auVar10 >> 0x60,0);
268: iVar30 = iVar18 + iVar40;
269: iVar26 = iVar26 - SUB164(auVar24,0);
270: iVar31 = iVar31 - iVar49;
271: iVar42 = iVar42 - iVar50;
272: iVar17 = iVar17 - SUB164(auVar10,0);
273: iVar25 = iVar25 - iVar36;
274: iVar27 = iVar27 - iVar38;
275: iVar18 = iVar18 - iVar40;
276: auVar10 = packssdw(CONCAT412(iVar51 + iVar59 + 0x800 >> 0xc,
277: CONCAT48(iVar43 + iVar57 + 0x800 >> 0xc,
278: CONCAT44(iVar41 + iVar55 + 0x800 >> 0xc,
279: iVar28 + iVar52 + 0x800 >> 0xc))),
280: CONCAT412(iVar30 + iVar67 + 0x800 >> 0xc,
281: CONCAT48(iVar58 + iVar66 + 0x800 >> 0xc,
282: CONCAT44(iVar53 + iVar65 + 0x800 >> 0xc,
283: iVar45 + iVar61 + 0x800 >> 0xc))));
284: auVar48 = packssdw(CONCAT412((iVar51 - iVar59) + 0x800 >> 0xc,
285: CONCAT48((iVar43 - iVar57) + 0x800 >> 0xc,
286: CONCAT44((iVar41 - iVar55) + 0x800 >> 0xc,
287: (iVar28 - iVar52) + 0x800 >> 0xc))),
288: CONCAT412((iVar30 - iVar67) + 0x800 >> 0xc,
289: CONCAT48((iVar58 - iVar66) + 0x800 >> 0xc,
290: CONCAT44((iVar53 - iVar65) + 0x800 >> 0xc,
291: (iVar45 - iVar61) + 0x800 >> 0xc))));
292: auVar14 = packssdw(CONCAT412(-iVar51 + iVar60 + 0x800 >> 0xc,
293: CONCAT48(iVar42 + iVar56 + 0x800 >> 0xc,
294: CONCAT44(iVar31 + iVar46 + 0x800 >> 0xc,
295: iVar26 + iVar44 + 0x800 >> 0xc))),
296: CONCAT412(iVar18 + iVar39 + 0x800 >> 0xc,
297: CONCAT48(iVar27 + iVar37 + 0x800 >> 0xc,
298: CONCAT44(iVar25 + iVar35 + 0x800 >> 0xc,
299: iVar17 + iVar34 + 0x800 >> 0xc))));
300: auVar64 = packssdw(CONCAT412((-iVar51 - iVar60) + 0x800 >> 0xc,
301: CONCAT48((iVar42 - iVar56) + 0x800 >> 0xc,
302: CONCAT44((iVar31 - iVar46) + 0x800 >> 0xc,
303: (iVar26 - iVar44) + 0x800 >> 0xc))),
304: CONCAT412((iVar18 - iVar39) + 0x800 >> 0xc,
305: CONCAT48((iVar27 - iVar37) + 0x800 >> 0xc,
306: CONCAT44((iVar25 - iVar35) + 0x800 >> 0xc,
307: (iVar17 - iVar34) + 0x800 >> 0xc))));
308: uVar33 = SUB164(CONCAT214(SUB162(auVar14 >> 0x30,0),
309: CONCAT212(SUB162(auVar10 >> 0x30,0),SUB1612(auVar10,0))) >> 0x60,0);
310: uVar16 = SUB168(CONCAT610(SUB166(CONCAT412(uVar33,CONCAT210(SUB162(auVar14 >> 0x20,0),
311: SUB1610(auVar10,0))) >> 0x50,0),
312: CONCAT28(SUB162(auVar10 >> 0x20,0),SUB168(auVar10,0))) >> 0x40,0);
313: auVar24 = CONCAT106(CONCAT82(uVar16,SUB162(auVar14 >> 0x10,0)),(SUB166(auVar10,0) >> 0x10) << 0x20
314: );
315: auVar47 = auVar10 & (undefined  [16])0xffffffff00000000;
316: uVar7 = CONCAT26(SUB162(auVar14 >> 0x50,0),
317: SUB126(CONCAT102(SUB1610(auVar47 >> 0x30,0),SUB162(auVar10 >> 0x50,0)),0) << 0x20
318: );
319: auVar9 = CONCAT210(SUB162(auVar14 >> 0x60,0),CONCAT28(SUB162(auVar47 >> 0x60,0),uVar7));
320: uVar15 = SUB164(CONCAT214(SUB162(auVar48 >> 0x30,0),
321: CONCAT212(SUB162(auVar64 >> 0x30,0),SUB1612(auVar64,0))) >> 0x60,0);
322: lVar29 = SUB168(CONCAT610(SUB166(CONCAT412(uVar15,CONCAT210(SUB162(auVar48 >> 0x20,0),
323: SUB1610(auVar64,0))) >> 0x50,0),
324: CONCAT28(SUB162(auVar64 >> 0x20,0),SUB168(auVar64,0))) >> 0x40,0);
325: auVar54 = auVar64 & (undefined  [16])0xffffffffffff0000;
326: iVar17 = SUB144(CONCAT122(SUB1612(auVar54 >> 0x20,0),SUB162(auVar48 >> 0x40,0)),0) << 0x10;
327: uVar20 = CONCAT26(SUB162(auVar48 >> 0x50,0),CONCAT24(SUB162(auVar54 >> 0x50,0),iVar17));
328: auVar62 = CONCAT210(SUB162(auVar48 >> 0x60,0),CONCAT28(SUB162(auVar54 >> 0x60,0),uVar20));
329: uVar13 = SUB168(CONCAT124(SUB1612(auVar24 >> 0x20,0),
330: SUB164(auVar10,0) & 0xffff | (uint)SUB162(auVar14,0) << 0x10),0);
331: auVar24 = CONCAT88(SUB168(CONCAT412(SUB164(CONCAT106(CONCAT82(lVar29,SUB162(auVar48 >> 0x10,0)),
332: (SUB166(auVar64,0) >> 0x10) << 0x20) >> 0x20,
333: 0),CONCAT48(SUB164(auVar24 >> 0x20,0),uVar13)) >> 0x40,
334: 0),
335: uVar13 & 0xffffffff |
336: (ulong)(SUB164(auVar64,0) & 0xffff | (uint)SUB162(auVar48,0) << 0x10) << 0x20);
337: auVar10 = CONCAT412(uVar15,CONCAT48(uVar33,uVar16 & 0xffffffff | lVar29 << 0x20));
338: uVar7 = SUB168((ZEXT1216(CONCAT84(SUB168(CONCAT412((int)((ulong)uVar20 >> 0x20),
339: CONCAT48((int)((ulong)uVar7 >> 0x20),uVar7)) >>
340: 0x40,0),iVar17)) << 0x20) >> 0x40,0);
341: auVar64 = CONCAT412(SUB164(CONCAT214(SUB162(auVar48 >> 0x70,0),
342: CONCAT212(SUB162(auVar54 >> 0x70,0),auVar62)) >> 0x60,0),
343: CONCAT48(SUB164(CONCAT214(SUB162(auVar14 >> 0x70,0),
344: CONCAT212(SUB162(auVar47 >> 0x70,0),auVar9)) >> 0x60
345: ,0),
346: CONCAT44(SUB124(auVar62 >> 0x40,0),SUB124(auVar9 >> 0x40,0))));
347: LAB_0015f72c:
348: auVar9 = CONCAT210(SUB162(auVar24 >> 0x20,0),(unkuint10)0);
349: iVar41 = (int)((uint)SUB162(auVar24,0) << 0x10) >> 2;
350: iVar43 = SUB164((ZEXT616(CONCAT42(SUB124(auVar9 >> 0x40,0),SUB162(auVar24 >> 0x10,0))) << 0x30) >>
351: 0x20,0) >> 2;
352: iVar45 = SUB164(ZEXT1216(auVar9) >> 0x40,0) >> 2;
353: auVar24 = CONCAT214(SUB162(auVar10 >> 0x70,0),
354: CONCAT212(SUB162(auVar24 >> 0x70,0),
355: CONCAT210(SUB162(auVar10 >> 0x60,0),
356: CONCAT28(SUB162(auVar24 >> 0x60,0),
357: CONCAT26(SUB162(auVar10 >> 0x50,0),
358: CONCAT24(SUB162(auVar24 >> 0x50,0),
359: CONCAT22(SUB162(auVar10 >> 0x40
360: ,0),
361: SUB162(auVar24 >> 0x40
362: ,0))))))));
363: auVar47 = CONCAT214(SUB162(auVar64 >> 0x70,0),
364: CONCAT212((short)((ulong)uVar7 >> 0x30),
365: CONCAT210(SUB162(auVar64 >> 0x60,0),
366: CONCAT28((short)((ulong)uVar7 >> 0x20),
367: CONCAT26(SUB162(auVar64 >> 0x50,0),
368: CONCAT24((short)((ulong)uVar7 >> 0x10),
369: CONCAT22(SUB162(auVar64 >> 0x40
370: ,0),
371: (short)uVar7)))))));
372: auVar14 = pmaddwd(auVar24,_DAT_0019ccb0);
373: auVar54 = pmaddwd(auVar47,_DAT_0019ccd0);
374: auVar48 = pmaddwd(auVar24,_DAT_0019ccc0);
375: auVar24 = pmaddwd(auVar47,_DAT_0019cce0);
376: iVar53 = SUB164(auVar54,0) + SUB164(auVar14,0);
377: iVar56 = SUB164(auVar54 >> 0x20,0) + SUB164(auVar14 >> 0x20,0);
378: iVar58 = SUB164(auVar54 >> 0x40,0) + SUB164(auVar14 >> 0x40,0);
379: iVar60 = SUB164(auVar54 >> 0x60,0) + SUB164(auVar14 >> 0x60,0);
380: iVar18 = SUB164(auVar24,0) + SUB164(auVar48,0);
381: iVar26 = SUB164(auVar24 >> 0x20,0) + SUB164(auVar48 >> 0x20,0);
382: iVar28 = SUB164(auVar24 >> 0x40,0) + SUB164(auVar48 >> 0x40,0);
383: iVar31 = SUB164(auVar24 >> 0x60,0) + SUB164(auVar48 >> 0x60,0);
384: auVar10 = pmaddwd(CONCAT124(SUB1612(CONCAT106(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
385: CONCAT214(SUB162(auVar64 >> 0x30,0),
386: CONCAT212(SUB162(auVar10 >> 0x30,0),
387: SUB1612(auVar10,0))) >> 0x60,0
388: ),CONCAT210(SUB162(auVar64 >> 0x20,0),
389: SUB1610(auVar10,0))) >> 0x50,0),
390: CONCAT28(SUB162(auVar10 >> 0x20,0),
391: SUB168(auVar10,0))) >> 0x40,0),
392: SUB162(auVar64 >> 0x10,0)),
393: (SUB166(auVar10,0) >> 0x10) << 0x20) >> 0x20,0),
394: SUB164(auVar10,0) & 0xffff | (uint)SUB162(auVar64,0) << 0x10),
395: _DAT_0019cca0);
396: iVar42 = iVar41 + SUB164(auVar10,0);
397: iVar17 = SUB164(auVar10 >> 0x20,0);
398: iVar44 = iVar43 + iVar17;
399: iVar25 = SUB164(auVar10 >> 0x40,0);
400: iVar46 = iVar45 + iVar25;
401: iVar27 = SUB164(auVar10 >> 0x60,0);
402: iVar41 = iVar41 - SUB164(auVar10,0);
403: iVar43 = iVar43 - iVar17;
404: iVar45 = iVar45 - iVar25;
405: auVar10 = packssdw(CONCAT412(iVar27 + iVar60 + 0x40000 >> 0x13,
406: CONCAT48(iVar46 + iVar58 + 0x40000 >> 0x13,
407: CONCAT44(iVar44 + iVar56 + 0x40000 >> 0x13,
408: iVar42 + iVar53 + 0x40000 >> 0x13))),
409: CONCAT412((-iVar27 - iVar31) + 0x40000 >> 0x13,
410: CONCAT48((iVar45 - iVar28) + 0x40000 >> 0x13,
411: CONCAT44((iVar43 - iVar26) + 0x40000 >> 0x13,
412: (iVar41 - iVar18) + 0x40000 >> 0x13))));
413: auVar64 = packssdw(CONCAT412(-iVar27 + iVar31 + 0x40000 >> 0x13,
414: CONCAT48(iVar45 + iVar28 + 0x40000 >> 0x13,
415: CONCAT44(iVar43 + iVar26 + 0x40000 >> 0x13,
416: iVar41 + iVar18 + 0x40000 >> 0x13))),
417: CONCAT412((iVar27 - iVar60) + 0x40000 >> 0x13,
418: CONCAT48((iVar46 - iVar58) + 0x40000 >> 0x13,
419: CONCAT44((iVar44 - iVar56) + 0x40000 >> 0x13,
420: (iVar42 - iVar53) + 0x40000 >> 0x13))));
421: uVar33 = SUB164(CONCAT214(SUB162(auVar64 >> 0x30,0),
422: CONCAT212(SUB162(auVar10 >> 0x30,0),SUB1612(auVar10,0))) >> 0x60,0);
423: uVar16 = SUB168(CONCAT610(SUB166(CONCAT412(uVar33,CONCAT210(SUB162(auVar64 >> 0x20,0),
424: SUB1610(auVar10,0))) >> 0x50,0),
425: CONCAT28(SUB162(auVar10 >> 0x20,0),SUB168(auVar10,0))) >> 0x40,0);
426: auVar24 = CONCAT106(CONCAT82(uVar16,SUB162(auVar64 >> 0x10,0)),(SUB166(auVar10,0) >> 0x10) << 0x20
427: );
428: uVar6 = CONCAT24(SUB162(auVar10 >> 0x50,0),
429: CONCAT22(SUB162(auVar64 >> 0x40,0),SUB162(auVar10 >> 0x40,0)));
430: uVar7 = CONCAT26(SUB162(auVar64 >> 0x50,0),uVar6);
431: auVar9 = CONCAT210(SUB162(auVar64 >> 0x60,0),CONCAT28(SUB162(auVar10 >> 0x60,0),uVar7));
432: uVar13 = SUB168(CONCAT124(SUB1612(auVar24 >> 0x20,0),
433: SUB164(auVar10,0) & 0xffff | (uint)SUB162(auVar64,0) << 0x10),0);
434: auVar10 = packsswb(CONCAT88(SUB168(CONCAT412((int)((ulong)uVar7 >> 0x20),
435: CONCAT48(SUB164(auVar24 >> 0x20,0),uVar13)) >> 0x40,0
436: ),uVar13 & 0xffffffff | (ulong)uVar6 << 0x20),
437: CONCAT412(SUB164(CONCAT214(SUB162(auVar64 >> 0x70,0),
438: CONCAT212(SUB162(auVar10 >> 0x70,0),auVar9)) >> 0x60
439: ,0),
440: CONCAT48(uVar33,uVar16 & 0xffffffff |
441: (ulong)SUB124(auVar9 >> 0x40,0) << 0x20)));
442: lVar29 = param_4[1];
443: pcVar1 = (char *)(*param_4 + uVar4);
444: *pcVar1 = SUB161(auVar10,0) + -0x80;
445: pcVar1[1] = SUB161(auVar10 >> 8,0) + -0x80;
446: pcVar1[2] = SUB161(auVar10 >> 0x10,0) + -0x80;
447: pcVar1[3] = SUB161(auVar10 >> 0x18,0) + -0x80;
448: lVar29 = lVar29 + uVar4;
449: *(char *)(lVar29 + 4) = SUB161(auVar10 >> 0x20,0) + -0x80;
450: *(char *)(lVar29 + 5) = SUB161(auVar10 >> 0x28,0) + -0x80;
451: *(char *)(lVar29 + 6) = SUB161(auVar10 >> 0x30,0) + -0x80;
452: *(char *)(lVar29 + 7) = SUB161(auVar10 >> 0x38,0) + -0x80;
453: lVar2 = param_4[3];
454: lVar29 = param_4[2] + uVar4;
455: *(char *)(lVar29 + 8) = SUB161(auVar10 >> 0x40,0) + -0x80;
456: *(char *)(lVar29 + 9) = SUB161(auVar10 >> 0x48,0) + -0x80;
457: *(char *)(lVar29 + 10) = SUB161(auVar10 >> 0x50,0) + -0x80;
458: *(char *)(lVar29 + 0xb) = SUB161(auVar10 >> 0x58,0) + -0x80;
459: lVar2 = lVar2 + uVar4;
460: *(char *)(lVar2 + 0xc) = SUB161(auVar10 >> 0x60,0) + -0x80;
461: *(char *)(lVar2 + 0xd) = SUB161(auVar10 >> 0x68,0) + -0x80;
462: *(char *)(lVar2 + 0xe) = SUB161(auVar10 >> 0x70,0) + -0x80;
463: *(char *)(lVar2 + 0xf) = SUB161(auVar10 >> 0x78,0) + -0x80;
464: return;
465: }
466: 

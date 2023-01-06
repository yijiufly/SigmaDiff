1: 
2: void FUN_0011d6f0(code **param_1)
3: 
4: {
5: long *plVar1;
6: undefined uVar2;
7: undefined4 uVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: undefined8 *puVar6;
11: undefined *puVar7;
12: long *plVar8;
13: char **ppcVar9;
14: undefined4 *puVar10;
15: int iVar11;
16: int iVar12;
17: char **ppcVar13;
18: code *pcVar14;
19: char *pcVar15;
20: char cVar16;
21: char *pcVar17;
22: long lVar18;
23: long in_FS_OFFSET;
24: uint3 uVar19;
25: char cVar27;
26: char cVar28;
27: char cVar29;
28: undefined8 uVar22;
29: char cVar30;
30: char cVar31;
31: char cVar32;
32: char cVar33;
33: char cVar34;
34: char cVar35;
35: char cVar36;
36: byte bVar37;
37: uint3 uVar38;
38: char cVar47;
39: char cVar48;
40: char cVar49;
41: undefined8 uVar42;
42: char cVar50;
43: char cVar51;
44: char cVar52;
45: char cVar53;
46: char cVar54;
47: ushort uVar55;
48: uint3 uVar56;
49: char cVar57;
50: char cVar59;
51: short sVar58;
52: char cVar60;
53: short sVar68;
54: short sVar69;
55: short sVar70;
56: undefined auVar61 [16];
57: int iVar71;
58: int iVar72;
59: int iVar74;
60: ushort uVar77;
61: short sVar85;
62: short sVar86;
63: short sVar87;
64: short sVar88;
65: short sVar89;
66: short sVar90;
67: undefined auVar78 [16];
68: int iVar91;
69: ushort uVar93;
70: short sVar94;
71: int iVar95;
72: ushort uVar96;
73: short sVar97;
74: int iVar98;
75: undefined auStack88 [16];
76: undefined auStack72 [16];
77: long lStack48;
78: uint6 uVar20;
79: undefined8 uVar21;
80: unkbyte10 Var23;
81: undefined auVar24 [12];
82: undefined auVar25 [12];
83: undefined auVar26 [14];
84: uint5 uVar39;
85: uint6 uVar40;
86: undefined8 uVar41;
87: unkbyte10 Var43;
88: undefined auVar44 [12];
89: undefined auVar45 [12];
90: undefined auVar46 [14];
91: undefined auVar62 [16];
92: undefined auVar63 [16];
93: undefined auVar64 [16];
94: undefined auVar65 [16];
95: undefined auVar66 [16];
96: undefined auVar67 [16];
97: undefined2 uVar73;
98: undefined8 uVar75;
99: undefined auVar76 [12];
100: undefined auVar79 [16];
101: undefined auVar80 [16];
102: undefined auVar81 [16];
103: undefined auVar82 [16];
104: undefined auVar83 [16];
105: undefined auVar84 [16];
106: undefined2 uVar92;
107: undefined8 uVar99;
108: undefined auVar100 [12];
109: 
110: pcVar4 = param_1[0x3a];
111: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
112: iVar11 = *(int *)((long)param_1 + 0x144);
113: if (*(int *)((long)param_1 + 0x104) == 0) {
114: if (0 < iVar11) {
115: pcVar14 = param_1[0x29];
116: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
117: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x14),0);
118: }
119: if (*(int *)(param_1 + 0x34) == 0) {
120: iVar11 = *(int *)((long)param_1 + 0x144);
121: }
122: else {
123: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x18),1);
124: iVar11 = *(int *)((long)param_1 + 0x144);
125: }
126: if (1 < iVar11) {
127: pcVar14 = param_1[0x2a];
128: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
129: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x14),0);
130: }
131: if (*(int *)(param_1 + 0x34) != 0) {
132: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x18),1);
133: }
134: if (2 < *(int *)((long)param_1 + 0x144)) {
135: pcVar14 = param_1[0x2b];
136: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
137: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x14),0);
138: }
139: if (*(int *)(param_1 + 0x34) != 0) {
140: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x18),1);
141: }
142: if (3 < *(int *)((long)param_1 + 0x144)) {
143: pcVar14 = param_1[0x2c];
144: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
145: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x14),0);
146: }
147: if (*(int *)(param_1 + 0x34) != 0) {
148: FUN_0011c800(param_1,*(undefined4 *)(pcVar14 + 0x18),1);
149: }
150: }
151: }
152: }
153: }
154: ppcVar13 = (char **)param_1[5];
155: pcVar17 = *ppcVar13;
156: pcVar15 = pcVar17 + 1;
157: goto LAB_0011d812;
158: }
159: auStack72 = (undefined  [16])0x0;
160: auStack88 = (undefined  [16])0x0;
161: if (0 < iVar11) {
162: if (*(int *)((long)param_1 + 0x19c) == 0) {
163: pcVar14 = param_1[0x29];
164: if (*(int *)(param_1 + 0x34) == 0) {
165: if (((*(int *)((long)param_1 + 0x1a4) == 0) &&
166: (auStack88[*(int *)(pcVar14 + 0x14)] = 1, iVar11 != 1)) &&
167: ((auStack88[*(int *)(param_1[0x2a] + 0x14)] = 1, 2 < iVar11 &&
168: (auStack88[*(int *)(param_1[0x2b] + 0x14)] = 1, 3 < iVar11)))) {
169: auStack88[*(int *)(param_1[0x2c] + 0x14)] = 1;
170: }
171: }
172: else {
173: if (*(int *)((long)param_1 + 0x1a4) == 0) {
174: iVar12 = *(int *)(pcVar14 + 0x18);
175: auStack88[*(int *)(pcVar14 + 0x14)] = 1;
176: auStack72[iVar12] = 1;
177: if (iVar11 != 1) {
178: iVar12 = *(int *)(param_1[0x2a] + 0x18);
179: auStack88[*(int *)(param_1[0x2a] + 0x14)] = 1;
180: auStack72[iVar12] = 1;
181: if (iVar11 != 2) {
182: iVar12 = *(int *)(param_1[0x2b] + 0x18);
183: auStack88[*(int *)(param_1[0x2b] + 0x14)] = 1;
184: auStack72[iVar12] = 1;
185: if (3 < iVar11) {
186: pcVar14 = param_1[0x2c];
187: auStack88[*(int *)(pcVar14 + 0x14)] = 1;
188: goto LAB_0011e10d;
189: }
190: }
191: }
192: }
193: else {
194: auStack72[*(int *)(pcVar14 + 0x18)] = 1;
195: if (((iVar11 != 1) && (auStack72[*(int *)(param_1[0x2a] + 0x18)] = 1, iVar11 != 2)) &&
196: (auStack72[*(int *)(param_1[0x2b] + 0x18)] = 1, iVar11 != 3)) {
197: pcVar14 = param_1[0x2c];
198: LAB_0011e10d:
199: auStack72[*(int *)(pcVar14 + 0x18)] = 1;
200: }
201: }
202: }
203: }
204: else {
205: if (((*(int *)(param_1 + 0x34) != 0) &&
206: (auStack72[*(int *)(param_1[0x29] + 0x18)] = 1, iVar11 != 1)) &&
207: ((auStack72[*(int *)(param_1[0x2a] + 0x18)] = 1, iVar11 != 2 &&
208: (auStack72[*(int *)(param_1[0x2b] + 0x18)] = 1, iVar11 != 3)))) {
209: auStack72[*(int *)(param_1[0x2c] + 0x18)] = 1;
210: }
211: }
212: }
213: ppcVar13 = (char **)param_1[5];
214: pcVar17 = *ppcVar13;
215: bVar37 = -(SUB161(auStack88,0) < '\0');
216: uVar19 = CONCAT12(-(SUB161(auStack88 >> 0x10,0) < '\0'),
217: CONCAT11(-(SUB161(auStack88 >> 8,0) < '\0'),bVar37));
218: cVar16 = SUB161(auStack88 >> 0x20,0);
219: cVar47 = -(cVar16 < '\0');
220: uVar39 = CONCAT14(cVar47,CONCAT13(-(SUB161(auStack88 >> 0x18,0) < '\0'),uVar19));
221: cVar27 = SUB161(auStack88 >> 0x28,0);
222: cVar48 = -(cVar27 < '\0');
223: cVar28 = SUB161(auStack88 >> 0x30,0);
224: cVar49 = -(cVar28 < '\0');
225: cVar29 = SUB161(auStack88 >> 0x38,0);
226: cVar30 = SUB161(auStack88 >> 0x40,0);
227: cVar31 = SUB161(auStack88 >> 0x48,0);
228: cVar32 = SUB161(auStack88 >> 0x50,0);
229: cVar33 = SUB161(auStack88 >> 0x58,0);
230: cVar34 = SUB161(auStack88 >> 0x60,0);
231: cVar35 = SUB161(auStack88 >> 0x68,0);
232: cVar36 = SUB161(auStack88 >> 0x70,0);
233: uVar92 = SUB162(CONCAT115(-(cVar29 < '\0'),CONCAT114(cVar29,SUB1614(auStack88,0))) >> 0x70,0);
234: auVar84 = CONCAT313(SUB163(CONCAT214(uVar92,CONCAT113(cVar49,SUB1613(auStack88,0))) >> 0x68,0),
235: CONCAT112(cVar28,SUB1612(auStack88,0)));
236: auVar83 = CONCAT511(SUB165(CONCAT412(SUB164(auVar84 >> 0x60,0),
237: CONCAT111(cVar48,SUB1611(auStack88,0))) >> 0x58,0),
238: CONCAT110(cVar27,SUB1610(auStack88,0)));
239: auVar82 = CONCAT79(SUB167(CONCAT610(SUB166(auVar83 >> 0x50,0),CONCAT19(cVar47,SUB169(auStack88,0))
240: ) >> 0x48,0),CONCAT18(cVar16,SUB168(auStack88,0)));
241: auVar81 = CONCAT97(SUB169(CONCAT88(SUB168(auVar82 >> 0x40,0),
242: (((ulong)CONCAT16(cVar49,CONCAT15(cVar48,uVar39)) & 0xff000000)
243: >> 0x18) << 0x38) >> 0x38,0),
244: (SUB167(auStack88,0) >> 0x18) << 0x30);
245: auVar80 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar81 >> 0x30,0),
246: (((uint6)uVar39 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0),
247: (SUB165(auStack88,0) >> 0x10) << 0x20);
248: auVar79 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar80 >> 0x20,0),((uVar19 & 0xff00) >> 8) << 0x18)
249: >> 0x18,0),(SUB163(auStack88,0) >> 8) << 0x10);
250: uVar77 = SUB162(auStack88,0) & 0xff | (ushort)bVar37 << 8;
251: auVar78 = CONCAT142(SUB1614(auVar79 >> 0x10,0),uVar77);
252: pcVar15 = pcVar17 + 1;
253: uVar19 = CONCAT12(cVar31,CONCAT11(-(cVar30 < '\0'),cVar30));
254: uVar20 = CONCAT15(-(cVar32 < '\0'),CONCAT14(cVar32,CONCAT13(-(cVar31 < '\0'),uVar19)));
255: uVar21 = CONCAT17(-(cVar33 < '\0'),CONCAT16(cVar33,uVar20));
256: Var23 = CONCAT19(-(cVar34 < '\0'),CONCAT18(cVar34,uVar21));
257: auVar24 = CONCAT111(-(cVar35 < '\0'),CONCAT110(cVar35,Var23));
258: auVar26 = CONCAT113(-(cVar36 < '\0'),CONCAT112(cVar36,auVar24));
259: bVar37 = -(SUB161(auStack72,0) < '\0');
260: uVar56 = CONCAT12(-(SUB161(auStack72 >> 0x10,0) < '\0'),
261: CONCAT11(-(SUB161(auStack72 >> 8,0) < '\0'),bVar37));
262: cVar16 = SUB161(auStack72 >> 0x20,0);
263: cVar57 = -(cVar16 < '\0');
264: uVar39 = CONCAT14(cVar57,CONCAT13(-(SUB161(auStack72 >> 0x18,0) < '\0'),uVar56));
265: cVar27 = SUB161(auStack72 >> 0x28,0);
266: cVar59 = -(cVar27 < '\0');
267: cVar28 = SUB161(auStack72 >> 0x30,0);
268: cVar60 = -(cVar28 < '\0');
269: cVar47 = SUB161(auStack72 >> 0x38,0);
270: cVar48 = SUB161(auStack72 >> 0x40,0);
271: cVar49 = SUB161(auStack72 >> 0x48,0);
272: cVar50 = SUB161(auStack72 >> 0x50,0);
273: cVar51 = SUB161(auStack72 >> 0x58,0);
274: cVar52 = SUB161(auStack72 >> 0x60,0);
275: cVar53 = SUB161(auStack72 >> 0x68,0);
276: cVar54 = SUB161(auStack72 >> 0x70,0);
277: uVar38 = CONCAT12(cVar49,CONCAT11(-(cVar48 < '\0'),cVar48));
278: uVar40 = CONCAT15(-(cVar50 < '\0'),CONCAT14(cVar50,CONCAT13(-(cVar49 < '\0'),uVar38)));
279: uVar41 = CONCAT17(-(cVar51 < '\0'),CONCAT16(cVar51,uVar40));
280: Var43 = CONCAT19(-(cVar52 < '\0'),CONCAT18(cVar52,uVar41));
281: auVar44 = CONCAT111(-(cVar53 < '\0'),CONCAT110(cVar53,Var43));
282: auVar46 = CONCAT113(-(cVar54 < '\0'),CONCAT112(cVar54,auVar44));
283: uVar73 = SUB162(CONCAT115(-(cVar47 < '\0'),CONCAT114(cVar47,SUB1614(auStack72,0))) >> 0x70,0);
284: auVar67 = CONCAT313(SUB163(CONCAT214(uVar73,CONCAT113(cVar60,SUB1613(auStack72,0))) >> 0x68,0),
285: CONCAT112(cVar28,SUB1612(auStack72,0)));
286: auVar66 = CONCAT511(SUB165(CONCAT412(SUB164(auVar67 >> 0x60,0),
287: CONCAT111(cVar59,SUB1611(auStack72,0))) >> 0x58,0),
288: CONCAT110(cVar27,SUB1610(auStack72,0)));
289: auVar65 = CONCAT79(SUB167(CONCAT610(SUB166(auVar66 >> 0x50,0),CONCAT19(cVar57,SUB169(auStack72,0))
290: ) >> 0x48,0),CONCAT18(cVar16,SUB168(auStack72,0)));
291: auVar64 = CONCAT97(SUB169(CONCAT88(SUB168(auVar65 >> 0x40,0),
292: (((ulong)CONCAT16(cVar60,CONCAT15(cVar59,uVar39)) & 0xff000000)
293: >> 0x18) << 0x38) >> 0x38,0),
294: (SUB167(auStack72,0) >> 0x18) << 0x30);
295: auVar63 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar64 >> 0x30,0),
296: (((uint6)uVar39 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0),
297: (SUB165(auStack72,0) >> 0x10) << 0x20);
298: auVar62 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar63 >> 0x20,0),((uVar56 & 0xff00) >> 8) << 0x18)
299: >> 0x18,0),(SUB163(auStack72,0) >> 8) << 0x10);
300: uVar55 = SUB162(auStack72,0) & 0xff | (ushort)bVar37 << 8;
301: auVar61 = CONCAT142(SUB1614(auVar62 >> 0x10,0),uVar55);
302: uVar96 = -(ushort)((short)uVar77 < 0);
303: sVar85 = SUB162(auVar80 >> 0x20,0);
304: sVar97 = -(ushort)(sVar85 < 0);
305: sVar87 = SUB162(auVar81 >> 0x30,0);
306: sVar88 = SUB162(auVar82 >> 0x40,0);
307: sVar89 = SUB162(auVar83 >> 0x50,0);
308: sVar90 = SUB162(auVar84 >> 0x60,0);
309: uVar93 = -(ushort)((short)uVar55 < 0);
310: sVar58 = SUB162(auVar63 >> 0x20,0);
311: sVar94 = -(ushort)(sVar58 < 0);
312: sVar86 = SUB162(auVar64 >> 0x30,0);
313: sVar68 = SUB162(auVar65 >> 0x40,0);
314: sVar69 = SUB162(auVar66 >> 0x50,0);
315: sVar70 = SUB162(auVar67 >> 0x60,0);
316: iVar91 = SUB164(CONCAT214(-(ushort)(sVar87 < 0),CONCAT212(sVar87,SUB1612(auVar78,0))) >> 0x60,0);
317: auVar65 = CONCAT610(SUB166(CONCAT412(iVar91,CONCAT210(sVar97,SUB1610(auVar78,0))) >> 0x50,0),
318: CONCAT28(sVar85,SUB168(auVar78,0)));
319: iVar71 = SUB164(CONCAT214(-(ushort)(sVar86 < 0),CONCAT212(sVar86,SUB1612(auVar61,0))) >> 0x60,0);
320: auVar63 = CONCAT610(SUB166(CONCAT412(iVar71,CONCAT210(sVar94,SUB1610(auVar61,0))) >> 0x50,0),
321: CONCAT28(sVar58,SUB168(auVar61,0)));
322: iVar74 = CONCAT22(-(ushort)(sVar68 < 0),sVar68);
323: uVar75 = CONCAT26(-(ushort)(sVar69 < 0),CONCAT24(sVar69,iVar74));
324: auVar76 = CONCAT210(-(ushort)(sVar70 < 0),CONCAT28(sVar70,uVar75));
325: iVar98 = CONCAT22(-(ushort)(sVar88 < 0),sVar88);
326: uVar99 = CONCAT26(-(ushort)(sVar89 < 0),CONCAT24(sVar89,iVar98));
327: auVar100 = CONCAT210(-(ushort)(sVar90 < 0),CONCAT28(sVar90,uVar99));
328: uVar55 = -(ushort)(cVar30 < '\0');
329: sVar58 = -(ushort)(cVar32 < '\0');
330: uVar77 = -(ushort)(cVar48 < '\0');
331: sVar86 = -(ushort)(cVar50 < '\0');
332: iVar11 = CONCAT22(-(ushort)(cVar34 < '\0'),(short)((unkuint10)Var23 >> 0x40));
333: uVar22 = CONCAT26(-(ushort)(cVar35 < '\0'),CONCAT24(SUB122(auVar24 >> 0x50,0),iVar11));
334: auVar25 = CONCAT210(-(ushort)(cVar36 < '\0'),CONCAT28(SUB142(auVar26 >> 0x60,0),uVar22));
335: iVar12 = CONCAT22(-(ushort)(cVar52 < '\0'),(short)((unkuint10)Var43 >> 0x40));
336: uVar42 = CONCAT26(-(ushort)(cVar53 < '\0'),CONCAT24(SUB122(auVar44 >> 0x50,0),iVar12));
337: auVar45 = CONCAT210(-(ushort)(cVar54 < '\0'),CONCAT28(SUB142(auVar46 >> 0x60,0),uVar42));
338: iVar95 = SUB164(CONCAT214(-(ushort)(cVar51 < '\0'),
339: CONCAT212((short)((ulong)uVar41 >> 0x30),auVar44)) >> 0x60,0);
340: auVar66 = CONCAT610(SUB166(CONCAT412(iVar95,CONCAT210(sVar86,Var43)) >> 0x50,0),
341: CONCAT28((short)(uVar40 >> 0x20),uVar41));
342: iVar72 = SUB164(CONCAT214(-(ushort)(cVar33 < '\0'),
343: CONCAT212((short)((ulong)uVar21 >> 0x30),auVar24)) >> 0x60,0);
344: auVar64 = CONCAT610(SUB166(CONCAT412(iVar72,CONCAT210(sVar58,Var23)) >> 0x50,0),
345: CONCAT28((short)(uVar20 >> 0x20),uVar21));
346: iVar11 = iVar11 + iVar12 +
347: (uVar19 & 0xffff | (uint)uVar55 << 0x10) + (uVar38 & 0xffff | (uint)uVar77 << 0x10) +
348: iVar74 + iVar98 +
349: (SUB164(auVar61,0) & 0xffff | (uint)uVar93 << 0x10) +
350: (SUB164(auVar78,0) & 0xffff | (uint)uVar96 << 0x10) +
351: SUB124(auVar25 >> 0x40,0) + SUB124(auVar45 >> 0x40,0) +
352: SUB164(auVar64 >> 0x40,0) + SUB164(auVar66 >> 0x40,0) +
353: SUB124(auVar76 >> 0x40,0) + SUB124(auVar100 >> 0x40,0) +
354: SUB164(auVar63 >> 0x40,0) + SUB164(auVar65 >> 0x40,0) +
355: (int)((ulong)uVar22 >> 0x20) + (int)((ulong)uVar42 >> 0x20) +
356: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar64 >> 0x40,0),
357: (((ulong)CONCAT24(sVar58,CONCAT22(-(ushort)(cVar31 < 
358: '\0'),uVar55)) & 0xffff0000) >> 0x10) << 0x30) >>
359: 0x30,0),(uVar20 >> 0x10) << 0x20) >> 0x20,0) +
360: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar66 >> 0x40,0),
361: (((ulong)CONCAT24(sVar86,CONCAT22(-(ushort)(cVar49 < 
362: '\0'),uVar77)) & 0xffff0000) >> 0x10) << 0x30) >>
363: 0x30,0),(uVar40 >> 0x10) << 0x20) >> 0x20,0) +
364: (int)((ulong)uVar75 >> 0x20) + (int)((ulong)uVar99 >> 0x20) +
365: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar63 >> 0x40,0),
366: (((ulong)CONCAT24(sVar94,CONCAT22(-(ushort)(SUB162(
367: auVar62 >> 0x10,0) < 0),uVar93)) & 0xffff0000) >>
368: 0x10) << 0x30) >> 0x30,0),
369: (SUB166(auVar61,0) >> 0x10) << 0x20) >> 0x20,0) +
370: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar65 >> 0x40,0),
371: (((ulong)CONCAT24(sVar97,CONCAT22(-(ushort)(SUB162(
372: auVar79 >> 0x10,0) < 0),uVar96)) & 0xffff0000) >>
373: 0x10) << 0x30) >> 0x30,0),
374: (SUB166(auVar78,0) >> 0x10) << 0x20) >> 0x20,0) +
375: SUB164(CONCAT214(-(ushort)(auStack88 < (undefined  [16])0x0),
376: CONCAT212(SUB162(CONCAT115(-(auStack88 < (undefined  [16])0x0),
377: CONCAT114(SUB161(auStack88 >> 0x78,0),auVar26
378: )) >> 0x70,0),auVar25)) >> 0x60,0) +
379: SUB164(CONCAT214(-(ushort)(auStack72 < (undefined  [16])0x0),
380: CONCAT212(SUB162(CONCAT115(-(auStack72 < (undefined  [16])0x0),
381: CONCAT114(SUB161(auStack72 >> 0x78,0),auVar46
382: )) >> 0x70,0),auVar45)) >> 0x60,0) +
383: iVar72 + iVar95 +
384: SUB164(CONCAT214(-(ushort)(cVar47 < '\0'),CONCAT212(uVar73,auVar76)) >> 0x60,0) +
385: SUB164(CONCAT214(-(ushort)(cVar29 < '\0'),CONCAT212(uVar92,auVar100)) >> 0x60,0) +
386: iVar71 + iVar91;
387: if (iVar11 != 0) {
388: *ppcVar13 = pcVar15;
389: *pcVar17 = -1;
390: ppcVar9 = ppcVar13 + 1;
391: *ppcVar9 = *ppcVar9 + -1;
392: if ((*ppcVar9 == (char *)0x0) && (iVar12 = (*(code *)ppcVar13[3])(param_1), iVar12 == 0)) {
393: ppcVar5 = (code **)*param_1;
394: *(undefined4 *)(ppcVar5 + 5) = 0x18;
395: (**ppcVar5)(param_1);
396: }
397: puVar6 = (undefined8 *)param_1[5];
398: puVar7 = (undefined *)*puVar6;
399: *puVar6 = puVar7 + 1;
400: *puVar7 = 0xcc;
401: plVar1 = puVar6 + 1;
402: *plVar1 = *plVar1 + -1;
403: if ((*plVar1 == 0) && (iVar12 = (*(code *)puVar6[3])(param_1), iVar12 == 0)) {
404: ppcVar5 = (code **)*param_1;
405: *(undefined4 *)(ppcVar5 + 5) = 0x18;
406: (**ppcVar5)(param_1);
407: }
408: plVar8 = (long *)param_1[5];
409: iVar11 = iVar11 * 2 + 2;
410: puVar7 = (undefined *)*plVar8;
411: *plVar8 = (long)(puVar7 + 1);
412: *puVar7 = (char)((uint)iVar11 >> 8);
413: plVar1 = plVar8 + 1;
414: *plVar1 = *plVar1 + -1;
415: if ((*plVar1 == 0) && (iVar12 = (*(code *)plVar8[3])(param_1), iVar12 == 0)) {
416: ppcVar5 = (code **)*param_1;
417: *(undefined4 *)(ppcVar5 + 5) = 0x18;
418: (**ppcVar5)(param_1);
419: }
420: plVar8 = (long *)param_1[5];
421: puVar7 = (undefined *)*plVar8;
422: *plVar8 = (long)(puVar7 + 1);
423: *puVar7 = (char)iVar11;
424: plVar1 = plVar8 + 1;
425: *plVar1 = *plVar1 + -1;
426: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
427: ppcVar5 = (code **)*param_1;
428: *(undefined4 *)(ppcVar5 + 5) = 0x18;
429: (**ppcVar5)(param_1);
430: }
431: ppcVar13 = (char **)param_1[5];
432: lVar18 = 0;
433: pcVar17 = *ppcVar13;
434: pcVar15 = pcVar17 + 1;
435: do {
436: if (auStack88[lVar18] == '\0') {
437: cVar16 = auStack72[lVar18];
438: }
439: else {
440: *ppcVar13 = pcVar15;
441: *pcVar17 = (char)lVar18;
442: ppcVar9 = ppcVar13 + 1;
443: *ppcVar9 = *ppcVar9 + -1;
444: if ((*ppcVar9 == (char *)0x0) && (iVar11 = (*(code *)ppcVar13[3])(param_1), iVar11 == 0)) {
445: ppcVar5 = (code **)*param_1;
446: *(undefined4 *)(ppcVar5 + 5) = 0x18;
447: (**ppcVar5)(param_1);
448: }
449: cVar16 = *(char *)((long)param_1 + lVar18 + 0xd0);
450: cVar27 = *(char *)((long)param_1 + lVar18 + 0xc0);
451: ppcVar9 = (char **)param_1[5];
452: pcVar15 = *ppcVar9;
453: *ppcVar9 = pcVar15 + 1;
454: *pcVar15 = cVar16 * '\x10' + cVar27;
455: ppcVar13 = ppcVar9 + 1;
456: *ppcVar13 = *ppcVar13 + -1;
457: if ((*ppcVar13 == (char *)0x0) && (iVar11 = (*(code *)ppcVar9[3])(param_1), iVar11 == 0)) {
458: ppcVar5 = (code **)*param_1;
459: *(undefined4 *)(ppcVar5 + 5) = 0x18;
460: (**ppcVar5)(param_1);
461: }
462: ppcVar13 = (char **)param_1[5];
463: cVar16 = auStack72[lVar18];
464: pcVar17 = *ppcVar13;
465: pcVar15 = pcVar17 + 1;
466: }
467: if (cVar16 != '\0') {
468: *ppcVar13 = pcVar15;
469: *pcVar17 = (char)lVar18 + '\x10';
470: ppcVar9 = ppcVar13 + 1;
471: *ppcVar9 = *ppcVar9 + -1;
472: if ((*ppcVar9 == (char *)0x0) && (iVar11 = (*(code *)ppcVar13[3])(param_1), iVar11 == 0)) {
473: ppcVar5 = (code **)*param_1;
474: *(undefined4 *)(ppcVar5 + 5) = 0x18;
475: (**ppcVar5)(param_1);
476: }
477: plVar8 = (long *)param_1[5];
478: uVar2 = *(undefined *)((long)param_1 + lVar18 + 0xe0);
479: puVar7 = (undefined *)*plVar8;
480: *plVar8 = (long)(puVar7 + 1);
481: *puVar7 = uVar2;
482: plVar1 = plVar8 + 1;
483: *plVar1 = *plVar1 + -1;
484: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
485: ppcVar5 = (code **)*param_1;
486: *(undefined4 *)(ppcVar5 + 5) = 0x18;
487: (**ppcVar5)(param_1);
488: }
489: ppcVar13 = (char **)param_1[5];
490: pcVar17 = *ppcVar13;
491: pcVar15 = pcVar17 + 1;
492: }
493: lVar18 = lVar18 + 1;
494: } while (lVar18 != 0x10);
495: }
496: LAB_0011d812:
497: if (*(int *)(param_1 + 0x23) != *(int *)(pcVar4 + 0x38)) {
498: *ppcVar13 = pcVar15;
499: *pcVar17 = -1;
500: ppcVar9 = ppcVar13 + 1;
501: *ppcVar9 = *ppcVar9 + -1;
502: if ((*ppcVar9 == (char *)0x0) && (iVar11 = (*(code *)ppcVar13[3])(param_1), iVar11 == 0)) {
503: ppcVar5 = (code **)*param_1;
504: *(undefined4 *)(ppcVar5 + 5) = 0x18;
505: (**ppcVar5)(param_1);
506: }
507: puVar6 = (undefined8 *)param_1[5];
508: puVar7 = (undefined *)*puVar6;
509: *puVar6 = puVar7 + 1;
510: *puVar7 = 0xdd;
511: plVar1 = puVar6 + 1;
512: *plVar1 = *plVar1 + -1;
513: if ((*plVar1 == 0) && (iVar11 = (*(code *)puVar6[3])(param_1), iVar11 == 0)) {
514: ppcVar5 = (code **)*param_1;
515: *(undefined4 *)(ppcVar5 + 5) = 0x18;
516: (**ppcVar5)(param_1);
517: }
518: puVar6 = (undefined8 *)param_1[5];
519: puVar7 = (undefined *)*puVar6;
520: *puVar6 = puVar7 + 1;
521: *puVar7 = 0;
522: plVar1 = puVar6 + 1;
523: *plVar1 = *plVar1 + -1;
524: if ((*plVar1 == 0) && (iVar11 = (*(code *)puVar6[3])(param_1), iVar11 == 0)) {
525: ppcVar5 = (code **)*param_1;
526: *(undefined4 *)(ppcVar5 + 5) = 0x18;
527: (**ppcVar5)(param_1);
528: }
529: puVar6 = (undefined8 *)param_1[5];
530: puVar7 = (undefined *)*puVar6;
531: *puVar6 = puVar7 + 1;
532: *puVar7 = 4;
533: plVar1 = puVar6 + 1;
534: *plVar1 = *plVar1 + -1;
535: if ((*plVar1 == 0) && (iVar11 = (*(code *)puVar6[3])(param_1), iVar11 == 0)) {
536: ppcVar5 = (code **)*param_1;
537: *(undefined4 *)(ppcVar5 + 5) = 0x18;
538: (**ppcVar5)(param_1);
539: }
540: plVar8 = (long *)param_1[5];
541: uVar3 = *(undefined4 *)(param_1 + 0x23);
542: puVar7 = (undefined *)*plVar8;
543: *plVar8 = (long)(puVar7 + 1);
544: *puVar7 = (char)((uint)uVar3 >> 8);
545: plVar1 = plVar8 + 1;
546: *plVar1 = *plVar1 + -1;
547: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
548: ppcVar5 = (code **)*param_1;
549: *(undefined4 *)(ppcVar5 + 5) = 0x18;
550: (**ppcVar5)(param_1);
551: }
552: plVar8 = (long *)param_1[5];
553: puVar7 = (undefined *)*plVar8;
554: *plVar8 = (long)(puVar7 + 1);
555: *puVar7 = (char)uVar3;
556: plVar1 = plVar8 + 1;
557: *plVar1 = *plVar1 + -1;
558: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
559: ppcVar5 = (code **)*param_1;
560: *(undefined4 *)(ppcVar5 + 5) = 0x18;
561: (**ppcVar5)(param_1);
562: }
563: *(undefined4 *)(pcVar4 + 0x38) = *(undefined4 *)(param_1 + 0x23);
564: ppcVar13 = (char **)param_1[5];
565: pcVar17 = *ppcVar13;
566: pcVar15 = pcVar17 + 1;
567: }
568: *ppcVar13 = pcVar15;
569: *pcVar17 = -1;
570: ppcVar9 = ppcVar13 + 1;
571: *ppcVar9 = *ppcVar9 + -1;
572: if ((*ppcVar9 == (char *)0x0) && (iVar11 = (*(code *)ppcVar13[3])(param_1), iVar11 == 0)) {
573: ppcVar5 = (code **)*param_1;
574: *(undefined4 *)(ppcVar5 + 5) = 0x18;
575: (**ppcVar5)(param_1);
576: }
577: puVar6 = (undefined8 *)param_1[5];
578: puVar7 = (undefined *)*puVar6;
579: *puVar6 = puVar7 + 1;
580: *puVar7 = 0xda;
581: plVar1 = puVar6 + 1;
582: *plVar1 = *plVar1 + -1;
583: if ((*plVar1 == 0) && (iVar11 = (*(code *)puVar6[3])(param_1), iVar11 == 0)) {
584: ppcVar5 = (code **)*param_1;
585: *(undefined4 *)(ppcVar5 + 5) = 0x18;
586: (**ppcVar5)(param_1);
587: }
588: iVar11 = *(int *)((long)param_1 + 0x144) * 2 + 6;
589: plVar8 = (long *)param_1[5];
590: puVar7 = (undefined *)*plVar8;
591: *plVar8 = (long)(puVar7 + 1);
592: *puVar7 = (char)((uint)iVar11 >> 8);
593: plVar1 = plVar8 + 1;
594: *plVar1 = *plVar1 + -1;
595: if ((*plVar1 == 0) && (iVar12 = (*(code *)plVar8[3])(param_1), iVar12 == 0)) {
596: ppcVar5 = (code **)*param_1;
597: *(undefined4 *)(ppcVar5 + 5) = 0x18;
598: (**ppcVar5)(param_1);
599: }
600: plVar8 = (long *)param_1[5];
601: puVar7 = (undefined *)*plVar8;
602: *plVar8 = (long)(puVar7 + 1);
603: *puVar7 = (char)iVar11;
604: plVar1 = plVar8 + 1;
605: *plVar1 = *plVar1 + -1;
606: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
607: ppcVar5 = (code **)*param_1;
608: *(undefined4 *)(ppcVar5 + 5) = 0x18;
609: (**ppcVar5)(param_1);
610: }
611: plVar8 = (long *)param_1[5];
612: uVar3 = *(undefined4 *)((long)param_1 + 0x144);
613: puVar7 = (undefined *)*plVar8;
614: *plVar8 = (long)(puVar7 + 1);
615: *puVar7 = (char)uVar3;
616: plVar1 = plVar8 + 1;
617: *plVar1 = *plVar1 + -1;
618: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
619: ppcVar5 = (code **)*param_1;
620: *(undefined4 *)(ppcVar5 + 5) = 0x18;
621: (**ppcVar5)(param_1);
622: }
623: if (0 < *(int *)((long)param_1 + 0x144)) {
624: lVar18 = 1;
625: do {
626: plVar8 = (long *)param_1[5];
627: puVar10 = (undefined4 *)param_1[lVar18 + 0x28];
628: puVar7 = (undefined *)*plVar8;
629: uVar3 = *puVar10;
630: *plVar8 = (long)(puVar7 + 1);
631: *puVar7 = (char)uVar3;
632: plVar1 = plVar8 + 1;
633: *plVar1 = *plVar1 + -1;
634: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
635: ppcVar5 = (code **)*param_1;
636: *(undefined4 *)(ppcVar5 + 5) = 0x18;
637: (**ppcVar5)(param_1);
638: }
639: iVar11 = *(int *)((long)param_1 + 0x19c);
640: if (iVar11 == 0) {
641: if (*(int *)((long)param_1 + 0x1a4) == 0) {
642: iVar11 = puVar10[5] << 4;
643: }
644: }
645: else {
646: iVar11 = 0;
647: }
648: cVar16 = (char)iVar11;
649: if (*(int *)(param_1 + 0x34) != 0) {
650: cVar16 = cVar16 + (char)puVar10[6];
651: }
652: ppcVar9 = (char **)param_1[5];
653: pcVar15 = *ppcVar9;
654: *ppcVar9 = pcVar15 + 1;
655: *pcVar15 = cVar16;
656: ppcVar13 = ppcVar9 + 1;
657: *ppcVar13 = *ppcVar13 + -1;
658: if ((*ppcVar13 == (char *)0x0) && (iVar11 = (*(code *)ppcVar9[3])(param_1), iVar11 == 0)) {
659: ppcVar5 = (code **)*param_1;
660: *(undefined4 *)(ppcVar5 + 5) = 0x18;
661: (**ppcVar5)(param_1);
662: }
663: iVar11 = (int)lVar18;
664: lVar18 = lVar18 + 1;
665: } while (iVar11 < *(int *)((long)param_1 + 0x144));
666: }
667: plVar8 = (long *)param_1[5];
668: uVar3 = *(undefined4 *)((long)param_1 + 0x19c);
669: puVar7 = (undefined *)*plVar8;
670: *plVar8 = (long)(puVar7 + 1);
671: *puVar7 = (char)uVar3;
672: plVar1 = plVar8 + 1;
673: *plVar1 = *plVar1 + -1;
674: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
675: ppcVar5 = (code **)*param_1;
676: *(undefined4 *)(ppcVar5 + 5) = 0x18;
677: (**ppcVar5)(param_1);
678: }
679: plVar8 = (long *)param_1[5];
680: uVar3 = *(undefined4 *)(param_1 + 0x34);
681: puVar7 = (undefined *)*plVar8;
682: *plVar8 = (long)(puVar7 + 1);
683: *puVar7 = (char)uVar3;
684: plVar1 = plVar8 + 1;
685: *plVar1 = *plVar1 + -1;
686: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar8[3])(param_1), iVar11 == 0)) {
687: ppcVar5 = (code **)*param_1;
688: *(undefined4 *)(ppcVar5 + 5) = 0x18;
689: (**ppcVar5)(param_1);
690: }
691: ppcVar9 = (char **)param_1[5];
692: iVar11 = *(int *)((long)param_1 + 0x1a4);
693: pcVar15 = *ppcVar9;
694: uVar3 = *(undefined4 *)(param_1 + 0x35);
695: *ppcVar9 = pcVar15 + 1;
696: *pcVar15 = (char)(iVar11 << 4) + (char)uVar3;
697: ppcVar13 = ppcVar9 + 1;
698: *ppcVar13 = *ppcVar13 + -1;
699: if ((*ppcVar13 == (char *)0x0) && (iVar11 = (*(code *)ppcVar9[3])(param_1), iVar11 == 0)) {
700: ppcVar5 = (code **)*param_1;
701: lVar18 = *(long *)(in_FS_OFFSET + 0x28);
702: *(undefined4 *)(ppcVar5 + 5) = 0x18;
703: if (lStack48 == lVar18) {
704: /* WARNING: Could not recover jumptable at 0x0011dbf4. Too many branches */
705: /* WARNING: Treating indirect jump as call */
706: (**ppcVar5)(param_1);
707: return;
708: }
709: }
710: else {
711: if (lStack48 == *(long *)(in_FS_OFFSET + 0x28)) {
712: return;
713: }
714: }
715: /* WARNING: Subroutine does not return */
716: __stack_chk_fail();
717: }
718: 

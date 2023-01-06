1: 
2: void FUN_00168990(undefined8 param_1,long param_2,ulong *param_3,long *param_4,uint param_5)
3: 
4: {
5: ulong uVar1;
6: ulong uVar2;
7: long lVar3;
8: long lVar4;
9: ulong uVar5;
10: float *pfVar6;
11: undefined (*pauVar7) [16];
12: float fVar8;
13: undefined2 uVar9;
14: float fVar10;
15: float fVar11;
16: float fVar12;
17: float fVar13;
18: float fVar14;
19: int iVar15;
20: float fVar16;
21: float fVar17;
22: uint3 uVar18;
23: float fVar19;
24: float fVar28;
25: float fVar29;
26: float fVar30;
27: undefined auVar26 [16];
28: undefined auVar27 [16];
29: float fVar32;
30: float fVar33;
31: float fVar34;
32: float fVar35;
33: float fVar36;
34: int iVar37;
35: float fVar38;
36: float fVar39;
37: float fVar41;
38: float fVar42;
39: undefined auVar40 [16];
40: float fVar44;
41: float fVar45;
42: float fVar46;
43: uint6 uVar47;
44: float fVar48;
45: float fVar49;
46: float fVar50;
47: float fVar51;
48: float fVar52;
49: float fVar53;
50: float fVar54;
51: float fVar55;
52: float fVar56;
53: float fVar57;
54: float fVar58;
55: float fVar59;
56: float fVar60;
57: float fVar61;
58: float fVar62;
59: float fVar63;
60: float fVar64;
61: float fVar65;
62: float fVar66;
63: float fVar67;
64: uint3 uVar68;
65: float fVar69;
66: ulong uVar71;
67: undefined auVar75 [16];
68: ulong uVar76;
69: float afStack304 [8];
70: float afStack272 [8];
71: float afStack240 [8];
72: float afStack208 [8];
73: float afStack176 [8];
74: float afStack144 [8];
75: float afStack112 [8];
76: float afStack80 [8];
77: undefined8 uStack48;
78: float fStack40;
79: float fStack36;
80: float fStack32;
81: float fStack28;
82: float fStack24;
83: float fStack20;
84: undefined *puStack16;
85: undefined6 uVar20;
86: uint7 uVar21;
87: undefined8 uVar22;
88: unkbyte10 Var23;
89: undefined auVar24 [12];
90: undefined auVar25 [14];
91: int iVar31;
92: int iVar43;
93: undefined8 uVar70;
94: unkbyte10 Var72;
95: undefined auVar73 [12];
96: undefined auVar74 [14];
97: undefined4 uVar77;
98: 
99: pfVar6 = *(float **)(param_2 + 0x58);
100: uVar5 = (ulong)param_5;
101: puStack16 = &stack0xfffffffffffffff8;
102: pauVar7 = (undefined (*) [16])afStack304;
103: lVar4 = 2;
104: do {
105: if (((*(uint *)(param_3 + 2) | *(uint *)(param_3 + 4)) == 0) &&
106: (auVar26 = ZEXT816(param_3[2] | param_3[4] | param_3[6] | param_3[8] |
107: param_3[10] | param_3[0xc] | param_3[0xe]),
108: auVar26 = packsswb(auVar26,auVar26), SUB164(auVar26,0) == 0)) {
109: uVar71 = *param_3;
110: uVar9 = SUB122(ZEXT812(uVar71) >> 0x20,0);
111: iVar15 = SUB164(CONCAT214(SUB162(ZEXT816(uVar71) >> 0x30,0),
112: CONCAT212(SUB142(ZEXT814(uVar71) >> 0x30,0),ZEXT812(uVar71))) >>
113: 0x60,0);
114: auVar26 = CONCAT610(SUB166(CONCAT412(iVar15,CONCAT210(uVar9,(unkuint10)uVar71)) >> 0x50,0),
115: CONCAT28(uVar9,uVar71));
116: fVar8 = (float)((int)((uint)uVar71 & 0xffff | (uint)uVar71 << 0x10) >> 0x10) * *pfVar6;
117: fVar10 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar26 >> 0x40,0),
118: (uVar71 >> 0x10) << 0x30) >> 0x30,0),
119: ((uint6)uVar71 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
120: pfVar6[1];
121: fVar13 = (float)(SUB164(auVar26 >> 0x40,0) >> 0x10) * pfVar6[2];
122: fVar16 = (float)(iVar15 >> 0x10) * pfVar6[3];
123: auVar26 = CONCAT412(fVar8,CONCAT48(fVar8,CONCAT44(fVar8,fVar8)));
124: auVar27 = CONCAT412(fVar10,CONCAT48(fVar10,CONCAT44(fVar10,fVar10)));
125: *pauVar7 = auVar26;
126: pauVar7[1] = auVar26;
127: pauVar7[2] = auVar27;
128: pauVar7[3] = auVar27;
129: *(float *)pauVar7[4] = fVar13;
130: *(float *)(pauVar7[4] + 4) = fVar13;
131: *(float *)(pauVar7[4] + 8) = fVar13;
132: *(float *)(pauVar7[4] + 0xc) = fVar13;
133: *(float *)pauVar7[5] = fVar13;
134: *(float *)(pauVar7[5] + 4) = fVar13;
135: *(float *)(pauVar7[5] + 8) = fVar13;
136: *(float *)(pauVar7[5] + 0xc) = fVar13;
137: *(float *)pauVar7[6] = fVar16;
138: *(float *)(pauVar7[6] + 4) = fVar16;
139: *(float *)(pauVar7[6] + 8) = fVar16;
140: *(float *)(pauVar7[6] + 0xc) = fVar16;
141: *(float *)pauVar7[7] = fVar16;
142: *(float *)(pauVar7[7] + 4) = fVar16;
143: *(float *)(pauVar7[7] + 8) = fVar16;
144: *(float *)(pauVar7[7] + 0xc) = fVar16;
145: }
146: else {
147: uVar71 = *param_3;
148: uVar76 = param_3[4];
149: uVar1 = param_3[8];
150: uVar2 = param_3[0xc];
151: uVar9 = SUB122(ZEXT812(uVar71) >> 0x20,0);
152: iVar15 = SUB164(CONCAT214(SUB162(ZEXT816(uVar71) >> 0x30,0),
153: CONCAT212(SUB142(ZEXT814(uVar71) >> 0x30,0),ZEXT812(uVar71))) >>
154: 0x60,0);
155: auVar26 = CONCAT610(SUB166(CONCAT412(iVar15,CONCAT210(uVar9,(unkuint10)uVar71)) >> 0x50,0),
156: CONCAT28(uVar9,uVar71));
157: uVar9 = SUB122(ZEXT812(uVar76) >> 0x20,0);
158: iVar31 = SUB164(CONCAT214(SUB162(ZEXT816(uVar76) >> 0x30,0),
159: CONCAT212(SUB142(ZEXT814(uVar76) >> 0x30,0),ZEXT812(uVar76))) >>
160: 0x60,0);
161: auVar27 = CONCAT610(SUB166(CONCAT412(iVar31,CONCAT210(uVar9,(unkuint10)uVar76)) >> 0x50,0),
162: CONCAT28(uVar9,uVar76));
163: uVar9 = SUB122(ZEXT812(uVar1) >> 0x20,0);
164: iVar37 = SUB164(CONCAT214(SUB162(ZEXT816(uVar1) >> 0x30,0),
165: CONCAT212(SUB142(ZEXT814(uVar1) >> 0x30,0),ZEXT812(uVar1))) >> 0x60,
166: 0);
167: auVar75 = CONCAT610(SUB166(CONCAT412(iVar37,CONCAT210(uVar9,(unkuint10)uVar1)) >> 0x50,0),
168: CONCAT28(uVar9,uVar1));
169: uVar9 = SUB122(ZEXT812(uVar2) >> 0x20,0);
170: iVar43 = SUB164(CONCAT214(SUB162(ZEXT816(uVar2) >> 0x30,0),
171: CONCAT212(SUB142(ZEXT814(uVar2) >> 0x30,0),ZEXT812(uVar2))) >> 0x60,
172: 0);
173: auVar40 = CONCAT610(SUB166(CONCAT412(iVar43,CONCAT210(uVar9,(unkuint10)uVar2)) >> 0x50,0),
174: CONCAT28(uVar9,uVar2));
175: fVar8 = (float)((int)((uint)uVar71 & 0xffff | (uint)uVar71 << 0x10) >> 0x10) * *pfVar6;
176: fVar12 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar26 >> 0x40,0),
177: (uVar71 >> 0x10) << 0x30) >> 0x30,0),
178: ((uint6)uVar71 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
179: pfVar6[1];
180: fVar60 = (float)(SUB164(auVar26 >> 0x40,0) >> 0x10) * pfVar6[2];
181: fVar19 = (float)(iVar15 >> 0x10) * pfVar6[3];
182: fVar13 = (float)((int)((uint)uVar76 & 0xffff | (uint)uVar76 << 0x10) >> 0x10) * pfVar6[0x10];
183: fVar11 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar27 >> 0x40,0),
184: (uVar76 >> 0x10) << 0x30) >> 0x30,0),
185: ((uint6)uVar76 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
186: pfVar6[0x11];
187: fVar32 = (float)(SUB164(auVar27 >> 0x40,0) >> 0x10) * pfVar6[0x12];
188: fVar14 = (float)(iVar31 >> 0x10) * pfVar6[0x13];
189: fVar16 = (float)((int)((uint)uVar1 & 0xffff | (uint)uVar1 << 0x10) >> 0x10) * pfVar6[0x20];
190: fVar56 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar75 >> 0x40,0),
191: (uVar1 >> 0x10) << 0x30) >> 0x30,0),
192: ((uint6)uVar1 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
193: pfVar6[0x21];
194: fVar63 = (float)(SUB164(auVar75 >> 0x40,0) >> 0x10) * pfVar6[0x22];
195: fVar66 = (float)(iVar37 >> 0x10) * pfVar6[0x23];
196: fVar30 = (float)((int)((uint)uVar2 & 0xffff | (uint)uVar2 << 0x10) >> 0x10) * pfVar6[0x30];
197: fVar33 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar40 >> 0x40,0),
198: (uVar2 >> 0x10) << 0x30) >> 0x30,0),
199: ((uint6)uVar2 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
200: pfVar6[0x31];
201: fVar34 = (float)(SUB164(auVar40 >> 0x40,0) >> 0x10) * pfVar6[0x32];
202: fVar36 = (float)(iVar43 >> 0x10) * pfVar6[0x33];
203: fVar10 = fVar8 - fVar16;
204: fVar29 = fVar12 - fVar56;
205: fVar17 = fVar60 - fVar63;
206: fVar28 = fVar19 - fVar66;
207: fVar8 = fVar8 + fVar16;
208: fVar12 = fVar12 + fVar56;
209: fVar60 = fVar60 + fVar63;
210: fVar19 = fVar19 + fVar66;
211: fVar56 = fVar13 + fVar30;
212: fVar58 = fVar11 + fVar33;
213: fVar63 = fVar32 + fVar34;
214: fVar66 = fVar14 + fVar36;
215: fVar16 = (fVar13 - fVar30) * 1.414214 - fVar56;
216: fVar35 = (fVar11 - fVar33) * 1.414214 - fVar58;
217: fVar11 = (fVar32 - fVar34) * 1.414214 - fVar63;
218: fVar14 = (fVar14 - fVar36) * 1.414214 - fVar66;
219: fVar61 = fVar8 - fVar56;
220: fVar64 = fVar12 - fVar58;
221: fVar67 = fVar60 - fVar63;
222: fVar52 = fVar19 - fVar66;
223: fVar13 = fVar10 - fVar16;
224: fVar32 = fVar29 - fVar35;
225: fStack40 = fVar17 - fVar11;
226: fStack36 = fVar28 - fVar14;
227: fVar8 = fVar8 + fVar56;
228: fVar60 = fVar60 + fVar63;
229: fVar19 = fVar19 + fVar66;
230: fVar10 = fVar10 + fVar16;
231: fVar17 = fVar17 + fVar11;
232: fVar28 = fVar28 + fVar14;
233: uVar71 = param_3[2];
234: uVar76 = param_3[6];
235: uVar1 = param_3[10];
236: uVar2 = param_3[0xe];
237: uVar9 = SUB122(ZEXT812(uVar71) >> 0x20,0);
238: iVar31 = SUB164(CONCAT214(SUB162(ZEXT816(uVar71) >> 0x30,0),
239: CONCAT212(SUB142(ZEXT814(uVar71) >> 0x30,0),ZEXT812(uVar71))) >>
240: 0x60,0);
241: auVar27 = CONCAT610(SUB166(CONCAT412(iVar31,CONCAT210(uVar9,(unkuint10)uVar71)) >> 0x50,0),
242: CONCAT28(uVar9,uVar71));
243: uVar9 = SUB122(ZEXT812(uVar76) >> 0x20,0);
244: iVar37 = SUB164(CONCAT214(SUB162(ZEXT816(uVar76) >> 0x30,0),
245: CONCAT212(SUB142(ZEXT814(uVar76) >> 0x30,0),ZEXT812(uVar76))) >>
246: 0x60,0);
247: auVar75 = CONCAT610(SUB166(CONCAT412(iVar37,CONCAT210(uVar9,(unkuint10)uVar76)) >> 0x50,0),
248: CONCAT28(uVar9,uVar76));
249: uVar9 = SUB122(ZEXT812(uVar1) >> 0x20,0);
250: iVar43 = SUB164(CONCAT214(SUB162(ZEXT816(uVar1) >> 0x30,0),
251: CONCAT212(SUB142(ZEXT814(uVar1) >> 0x30,0),ZEXT812(uVar1))) >> 0x60,
252: 0);
253: auVar40 = CONCAT610(SUB166(CONCAT412(iVar43,CONCAT210(uVar9,(unkuint10)uVar1)) >> 0x50,0),
254: CONCAT28(uVar9,uVar1));
255: uVar9 = SUB122(ZEXT812(uVar2) >> 0x20,0);
256: iVar15 = SUB164(CONCAT214(SUB162(ZEXT816(uVar2) >> 0x30,0),
257: CONCAT212(SUB142(ZEXT814(uVar2) >> 0x30,0),ZEXT812(uVar2))) >> 0x60,
258: 0);
259: auVar26 = CONCAT610(SUB166(CONCAT412(iVar15,CONCAT210(uVar9,(unkuint10)uVar2)) >> 0x50,0),
260: CONCAT28(uVar9,uVar2));
261: fVar41 = (float)((int)((uint)uVar71 & 0xffff | (uint)uVar71 << 0x10) >> 0x10) * pfVar6[8];
262: fVar44 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar27 >> 0x40,0),
263: (uVar71 >> 0x10) << 0x30) >> 0x30,0),
264: ((uint6)uVar71 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
265: pfVar6[9];
266: fVar46 = (float)(SUB164(auVar27 >> 0x40,0) >> 0x10) * pfVar6[10];
267: fVar49 = (float)(iVar31 >> 0x10) * pfVar6[0xb];
268: fVar34 = (float)((int)((uint)uVar76 & 0xffff | (uint)uVar76 << 0x10) >> 0x10) * pfVar6[0x18];
269: fVar36 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar75 >> 0x40,0),
270: (uVar76 >> 0x10) << 0x30) >> 0x30,0),
271: ((uint6)uVar76 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
272: pfVar6[0x19];
273: fVar38 = (float)(SUB164(auVar75 >> 0x40,0) >> 0x10) * pfVar6[0x1a];
274: fVar39 = (float)(iVar37 >> 0x10) * pfVar6[0x1b];
275: fVar16 = (float)((int)((uint)uVar1 & 0xffff | (uint)uVar1 << 0x10) >> 0x10) * pfVar6[0x28];
276: fVar14 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar40 >> 0x40,0),
277: (uVar1 >> 0x10) << 0x30) >> 0x30,0),
278: ((uint6)uVar1 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
279: pfVar6[0x29];
280: fVar63 = (float)(SUB164(auVar40 >> 0x40,0) >> 0x10) * pfVar6[0x2a];
281: fVar30 = (float)(iVar43 >> 0x10) * pfVar6[0x2b];
282: fVar11 = (float)((int)((uint)uVar2 & 0xffff | (uint)uVar2 << 0x10) >> 0x10) * pfVar6[0x38];
283: fVar56 = (float)(SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar26 >> 0x40,0),
284: (uVar2 >> 0x10) << 0x30) >> 0x30,0),
285: ((uint6)uVar2 >> 0x10) << 0x20) >> 0x20,0) >> 0x10) *
286: pfVar6[0x39];
287: fVar66 = (float)(SUB164(auVar26 >> 0x40,0) >> 0x10) * pfVar6[0x3a];
288: fVar33 = (float)(iVar15 >> 0x10) * pfVar6[0x3b];
289: fVar42 = fVar41 + fVar11;
290: fVar45 = fVar44 + fVar56;
291: fVar48 = fVar46 + fVar66;
292: fVar50 = fVar49 + fVar33;
293: fVar55 = fVar16 + fVar34;
294: fVar59 = fVar14 + fVar36;
295: fVar62 = fVar63 + fVar38;
296: fVar65 = fVar30 + fVar39;
297: fVar41 = fVar41 - fVar11;
298: fVar44 = fVar44 - fVar56;
299: fVar46 = fVar46 - fVar66;
300: fVar49 = fVar49 - fVar33;
301: fVar16 = fVar16 - fVar34;
302: fVar14 = fVar14 - fVar36;
303: fVar63 = fVar63 - fVar38;
304: fVar30 = fVar30 - fVar39;
305: fVar34 = fVar42 + fVar55;
306: fVar36 = fVar45 + fVar59;
307: fVar38 = fVar48 + fVar62;
308: fVar39 = fVar50 + fVar65;
309: fVar11 = (fVar16 + fVar41) * 1.847759;
310: fVar56 = (fVar14 + fVar44) * 1.847759;
311: fVar66 = (fVar63 + fVar46) * 1.847759;
312: fVar33 = (fVar30 + fVar49) * 1.847759;
313: fVar51 = (fVar16 * -2.613126 + fVar11) - fVar34;
314: fVar53 = (fVar14 * -2.613126 + fVar56) - fVar36;
315: fVar54 = (fVar63 * -2.613126 + fVar66) - fVar38;
316: fVar57 = (fVar30 * -2.613126 + fVar33) - fVar39;
317: fVar69 = fVar8 + fVar34;
318: fVar36 = fVar12 + fVar58 + fVar36;
319: fVar8 = fVar8 - fVar34;
320: fStack28 = fVar60 - fVar38;
321: fStack20 = fVar19 - fVar39;
322: fVar16 = fVar10 - fVar51;
323: fStack32 = fVar17 - fVar54;
324: fStack24 = fVar28 - fVar57;
325: fVar12 = (fVar42 - fVar55) * 1.414214 - fVar51;
326: fVar14 = (fVar45 - fVar59) * 1.414214 - fVar53;
327: fVar63 = (fVar48 - fVar62) * 1.414214 - fVar54;
328: fVar30 = (fVar50 - fVar65) * 1.414214 - fVar57;
329: uStack48 = CONCAT44(fVar8,fVar16);
330: fVar11 = (fVar41 * 1.082392 - fVar11) + fVar12;
331: fVar56 = (fVar44 * 1.082392 - fVar56) + fVar14;
332: fVar66 = (fVar46 * 1.082392 - fVar66) + fVar63;
333: fVar33 = (fVar49 * 1.082392 - fVar33) + fVar30;
334: fVar34 = fVar61 + fVar11;
335: fVar41 = fVar64 + fVar56;
336: *pauVar7 = CONCAT412(fVar61 - fVar11,
337: CONCAT48(fVar13 + fVar12,CONCAT44(fVar10 + fVar51,fVar69)));
338: pauVar7[2] = CONCAT412(fVar64 - fVar56,
339: CONCAT48(fVar32 + fVar14,
340: SUB168(CONCAT412(fVar29 + fVar35 + fVar53,
341: CONCAT48(fVar36,CONCAT44(fVar36,fVar69))) >>
342: 0x40,0) & 0xffffffff00000000 | (ulong)(uint)fVar36));
343: pauVar7[4] = CONCAT412(fVar67 - fVar66,
344: CONCAT48(fStack40 + fVar63,CONCAT44(fVar17 + fVar54,fVar60 + fVar38)));
345: *(float *)pauVar7[6] = fVar19 + fVar39;
346: *(float *)(pauVar7[6] + 4) = fVar28 + fVar57;
347: *(float *)(pauVar7[6] + 8) = fStack36 + fVar30;
348: *(float *)(pauVar7[6] + 0xc) = fVar52 - fVar33;
349: pauVar7[1] = CONCAT412(fVar8,CONCAT48(fVar16,CONCAT44(fVar13 - fVar12,fVar34)));
350: pauVar7[3] = CONCAT412(fStack36,CONCAT48(fStack40,SUB168(CONCAT412(fVar32 - fVar14,
351: CONCAT48(fVar41,CONCAT44(
352: fVar41,fVar34))) >> 0x40,0) & 0xffffffff00000000 |
353: (ulong)(uint)fVar41));
354: pauVar7[5] = CONCAT412(fStack28,CONCAT48(fStack32,CONCAT44(fStack40 - fVar63,fVar67 + fVar66))
355: );
356: *(float *)pauVar7[7] = fVar52 + fVar33;
357: *(float *)(pauVar7[7] + 4) = fStack36 - fVar30;
358: *(float *)(pauVar7[7] + 8) = fStack24;
359: *(float *)(pauVar7[7] + 0xc) = fStack20;
360: }
361: param_3 = param_3 + 1;
362: pfVar6 = pfVar6 + 4;
363: pauVar7 = pauVar7[8];
364: lVar4 = lVar4 + -1;
365: } while (lVar4 != 0);
366: pfVar6 = afStack304;
367: lVar4 = 2;
368: do {
369: fVar8 = *pfVar6 - pfVar6[0x20];
370: fVar11 = pfVar6[1] - pfVar6[0x21];
371: fVar14 = pfVar6[2] - pfVar6[0x22];
372: fVar17 = pfVar6[3] - pfVar6[0x23];
373: fVar45 = *pfVar6 + pfVar6[0x20];
374: fVar48 = pfVar6[1] + pfVar6[0x21];
375: fVar50 = pfVar6[2] + pfVar6[0x22];
376: fVar53 = pfVar6[3] + pfVar6[0x23];
377: fVar56 = pfVar6[0x10] + pfVar6[0x30];
378: fVar60 = pfVar6[0x11] + pfVar6[0x31];
379: fVar63 = pfVar6[0x12] + pfVar6[0x32];
380: fVar66 = pfVar6[0x13] + pfVar6[0x33];
381: fVar13 = (pfVar6[0x10] - pfVar6[0x30]) * 1.414214 - fVar56;
382: fVar16 = (pfVar6[0x11] - pfVar6[0x31]) * 1.414214 - fVar60;
383: fVar29 = (pfVar6[0x12] - pfVar6[0x32]) * 1.414214 - fVar63;
384: fVar32 = (pfVar6[0x13] - pfVar6[0x33]) * 1.414214 - fVar66;
385: fStack32 = fVar45 - fVar56;
386: fStack28 = fVar48 - fVar60;
387: fStack24 = fVar50 - fVar63;
388: fStack20 = fVar53 - fVar66;
389: fVar10 = fVar8 - fVar13;
390: fVar12 = fVar11 - fVar16;
391: fStack40 = fVar14 - fVar29;
392: fStack36 = fVar17 - fVar32;
393: fVar45 = fVar45 + fVar56;
394: fVar48 = fVar48 + fVar60;
395: fVar50 = fVar50 + fVar63;
396: fVar53 = fVar53 + fVar66;
397: fVar8 = fVar8 + fVar13;
398: fVar11 = fVar11 + fVar16;
399: fVar14 = fVar14 + fVar29;
400: fVar17 = fVar17 + fVar32;
401: uStack48 = CONCAT44(fVar12,fVar10);
402: fVar34 = pfVar6[8] + pfVar6[0x38];
403: fVar35 = pfVar6[9] + pfVar6[0x39];
404: fVar36 = pfVar6[10] + pfVar6[0x3a];
405: fVar38 = pfVar6[0xb] + pfVar6[0x3b];
406: fVar57 = pfVar6[0x28] + pfVar6[0x18];
407: fVar61 = pfVar6[0x29] + pfVar6[0x19];
408: fVar64 = pfVar6[0x2a] + pfVar6[0x1a];
409: fVar67 = pfVar6[0x2b] + pfVar6[0x1b];
410: fVar46 = pfVar6[8] - pfVar6[0x38];
411: fVar49 = pfVar6[9] - pfVar6[0x39];
412: fVar51 = pfVar6[10] - pfVar6[0x3a];
413: fVar54 = pfVar6[0xb] - pfVar6[0x3b];
414: fVar13 = pfVar6[0x28] - pfVar6[0x18];
415: fVar29 = pfVar6[0x29] - pfVar6[0x19];
416: fVar56 = pfVar6[0x2a] - pfVar6[0x1a];
417: fVar63 = pfVar6[0x2b] - pfVar6[0x1b];
418: fVar19 = fVar34 + fVar57;
419: fVar28 = fVar35 + fVar61;
420: fVar30 = fVar36 + fVar64;
421: fVar33 = fVar38 + fVar67;
422: fVar16 = (fVar13 + fVar46) * 1.847759;
423: fVar32 = (fVar29 + fVar49) * 1.847759;
424: fVar60 = (fVar56 + fVar51) * 1.847759;
425: fVar66 = (fVar63 + fVar54) * 1.847759;
426: fVar39 = (fVar13 * -2.613126 + fVar16) - fVar19;
427: fVar41 = (fVar29 * -2.613126 + fVar32) - fVar28;
428: fVar42 = (fVar56 * -2.613126 + fVar60) - fVar30;
429: fVar44 = (fVar63 * -2.613126 + fVar66) - fVar33;
430: fVar13 = (fVar34 - fVar57) * 1.414214 - fVar39;
431: fVar29 = (fVar35 - fVar61) * 1.414214 - fVar41;
432: fVar56 = (fVar36 - fVar64) * 1.414214 - fVar42;
433: fVar63 = (fVar38 - fVar67) * 1.414214 - fVar44;
434: auVar26 = CONCAT412(0xffff,CONCAT48(0xffff,0xffff0000ffff));
435: fVar16 = (fVar46 * 1.082392 - fVar16) + fVar13;
436: fVar32 = (fVar49 * 1.082392 - fVar32) + fVar29;
437: fVar60 = (fVar51 * 1.082392 - fVar60) + fVar56;
438: fVar66 = (fVar54 * 1.082392 - fVar66) + fVar63;
439: auVar27 = CONCAT412(0xffff,CONCAT48(0xffff,0xffff0000ffff));
440: auVar75 = packsswb(CONCAT412(fVar53 + fVar33 + 1.006633e+08,
441: CONCAT48(fVar50 + fVar30 + 1.006633e+08,
442: CONCAT44(fVar48 + fVar28 + 1.006633e+08,
443: fVar45 + fVar19 + 1.006633e+08))) & auVar26 |
444: CONCAT412((int)(fVar17 + fVar44 + 1.006633e+08) << 0x10,
445: CONCAT48((int)(fVar14 + fVar42 + 1.006633e+08) << 0x10,
446: CONCAT44((int)(fVar11 + fVar41 + 1.006633e+08) << 0x10,
447: (int)(fVar8 + fVar39 + 1.006633e+08) << 0x10))),
448: CONCAT412(fStack20 + fVar66 + 1.006633e+08,
449: CONCAT48(fStack24 + fVar60 + 1.006633e+08,
450: CONCAT44(fStack28 + fVar32 + 1.006633e+08,
451: fStack32 + fVar16 + 1.006633e+08))) & auVar27 |
452: CONCAT412((int)((fStack36 - fVar63) + 1.006633e+08) << 0x10,
453: CONCAT48((int)((fStack40 - fVar56) + 1.006633e+08) << 0x10,
454: CONCAT44((int)((fVar12 - fVar29) + 1.006633e+08) << 0x10,
455: (int)((fVar10 - fVar13) + 1.006633e+08) << 0x10))
456: ));
457: auVar26 = packsswb(CONCAT412(fStack36 + fVar63 + 1.006633e+08,
458: CONCAT48(fStack40 + fVar56 + 1.006633e+08,
459: CONCAT44(fVar12 + fVar29 + 1.006633e+08,
460: fVar10 + fVar13 + 1.006633e+08))) & auVar27 |
461: CONCAT412((int)((fStack20 - fVar66) + 1.006633e+08) << 0x10,
462: CONCAT48((int)((fStack24 - fVar60) + 1.006633e+08) << 0x10,
463: CONCAT44((int)((fStack28 - fVar32) + 1.006633e+08) << 0x10
464: ,(int)((fStack32 - fVar16) + 1.006633e+08) <<
465: 0x10))),
466: CONCAT412((fVar17 - fVar44) + 1.006633e+08,
467: CONCAT48((fVar14 - fVar42) + 1.006633e+08,
468: CONCAT44((fVar11 - fVar41) + 1.006633e+08,
469: (fVar8 - fVar39) + 1.006633e+08))) & auVar26 |
470: CONCAT412((int)((fVar53 - fVar33) + 1.006633e+08) << 0x10,
471: CONCAT48((int)((fVar50 - fVar30) + 1.006633e+08) << 0x10,
472: CONCAT44((int)((fVar48 - fVar28) + 1.006633e+08) << 0x10,
473: (int)((fVar45 - fVar19) + 1.006633e+08) << 0x10))
474: ));
475: uVar68 = CONCAT12(SUB161(auVar75 >> 0x10,0) + -0x80,
476: CONCAT11(SUB161(auVar75 >> 8,0) + -0x80,SUB161(auVar75,0) + -0x80));
477: uVar47 = CONCAT15(SUB161(auVar75 >> 0x28,0) + -0x80,
478: CONCAT14(SUB161(auVar75 >> 0x20,0) + -0x80,
479: CONCAT13(SUB161(auVar75 >> 0x18,0) + -0x80,uVar68)));
480: uVar70 = CONCAT17(SUB161(auVar75 >> 0x38,0) + -0x80,
481: CONCAT16(SUB161(auVar75 >> 0x30,0) + -0x80,uVar47));
482: Var72 = CONCAT19(SUB161(auVar75 >> 0x48,0) + -0x80,
483: CONCAT18(SUB161(auVar75 >> 0x40,0) + -0x80,uVar70));
484: auVar73 = CONCAT111(SUB161(auVar75 >> 0x58,0) + -0x80,
485: CONCAT110(SUB161(auVar75 >> 0x50,0) + -0x80,Var72));
486: auVar74 = CONCAT113(SUB161(auVar75 >> 0x68,0) + -0x80,
487: CONCAT112(SUB161(auVar75 >> 0x60,0) + -0x80,auVar73));
488: uVar18 = CONCAT12(SUB161(auVar26 >> 0x10,0) + -0x80,
489: CONCAT11(SUB161(auVar26 >> 8,0) + -0x80,SUB161(auVar26,0) + -0x80));
490: uVar20 = CONCAT15(SUB161(auVar26 >> 0x28,0) + -0x80,
491: CONCAT14(SUB161(auVar26 >> 0x20,0) + -0x80,
492: CONCAT13(SUB161(auVar26 >> 0x18,0) + -0x80,uVar18)));
493: uVar21 = CONCAT16(SUB161(auVar26 >> 0x30,0) + -0x80,uVar20);
494: uVar22 = CONCAT17(SUB161(auVar26 >> 0x38,0) + -0x80,uVar21);
495: Var23 = CONCAT19(SUB161(auVar26 >> 0x48,0) + -0x80,
496: CONCAT18(SUB161(auVar26 >> 0x40,0) + -0x80,uVar22));
497: auVar24 = CONCAT111(SUB161(auVar26 >> 0x58,0) + -0x80,
498: CONCAT110(SUB161(auVar26 >> 0x50,0) + -0x80,Var23));
499: auVar25 = CONCAT113(SUB161(auVar26 >> 0x68,0) + -0x80,
500: CONCAT112(SUB161(auVar26 >> 0x60,0) + -0x80,auVar24));
501: uVar77 = SUB164(CONCAT214((short)((ulong)uVar22 >> 0x30),
502: CONCAT212((short)((ulong)uVar70 >> 0x30),auVar73)) >> 0x60,0);
503: uVar76 = SUB168(CONCAT610(SUB166(CONCAT412(uVar77,CONCAT210((short)((uint6)uVar20 >> 0x20),Var72
504: )) >> 0x50,0),
505: CONCAT28((short)(uVar47 >> 0x20),uVar70)) >> 0x40,0);
506: auVar27 = CONCAT106(SUB1610(CONCAT88(uVar76,(((ulong)uVar21 & 0xffff0000) >> 0x10) << 0x30) >>
507: 0x30,0),(uVar47 >> 0x10) << 0x20);
508: uVar47 = CONCAT24(SUB122(auVar73 >> 0x50,0),
509: CONCAT22((short)((unkuint10)Var23 >> 0x40),(short)((unkuint10)Var72 >> 0x40)))
510: ;
511: uVar22 = CONCAT26(SUB122(auVar24 >> 0x50,0),uVar47);
512: auVar24 = CONCAT210(SUB142(auVar25 >> 0x60,0),CONCAT28(SUB142(auVar74 >> 0x60,0),uVar22));
513: uVar71 = SUB168(CONCAT124(SUB1612(auVar27 >> 0x20,0),uVar68 & 0xffff | (uint)uVar18 << 0x10),0);
514: lVar3 = param_4[2];
515: *(ulong *)(*param_4 + uVar5) = uVar71 & 0xffffffff | (ulong)uVar47 << 0x20;
516: *(ulong *)(lVar3 + uVar5) = uVar76 & 0xffffffff | (ulong)SUB124(auVar24 >> 0x40,0) << 0x20;
517: lVar3 = param_4[3];
518: *(long *)(param_4[1] + uVar5) =
519: SUB168(CONCAT412((int)((ulong)uVar22 >> 0x20),CONCAT48(SUB164(auVar27 >> 0x20,0),uVar71))
520: >> 0x40,0);
521: *(ulong *)(lVar3 + uVar5) =
522: CONCAT44(SUB164(CONCAT214(SUB162(CONCAT115(SUB161(auVar26 >> 0x78,0) + -0x80,
523: CONCAT114(SUB161(auVar26 >> 0x70,0) + -0x80,
524: auVar25)) >> 0x70,0),
525: CONCAT212(SUB162(CONCAT115(SUB161(auVar75 >> 0x78,0) + -0x80,
526: CONCAT114(SUB161(auVar75 >> 0x70,0) +
527: -0x80,auVar74)) >> 0x70,0),
528: auVar24)) >> 0x60,0),uVar77);
529: pfVar6 = pfVar6 + 4;
530: param_4 = param_4 + 4;
531: lVar4 = lVar4 + -1;
532: } while (lVar4 != 0);
533: return;
534: }
535: 

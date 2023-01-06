1: 
2: void FUN_00114510(code **param_1)
3: 
4: {
5: undefined uVar1;
6: undefined4 uVar2;
7: code *pcVar3;
8: code *pcVar4;
9: undefined8 *puVar5;
10: undefined *puVar6;
11: long *plVar7;
12: undefined4 *puVar8;
13: char **ppcVar9;
14: char *pcVar10;
15: char **ppcVar11;
16: code **ppcVar12;
17: long lVar13;
18: int iVar14;
19: int iVar15;
20: long lVar16;
21: code **ppcVar17;
22: long in_FS_OFFSET;
23: uint3 uVar18;
24: char cVar24;
25: char cVar25;
26: char cVar26;
27: undefined8 uVar20;
28: char cVar27;
29: char cVar28;
30: char cVar29;
31: char cVar30;
32: char cVar31;
33: char cVar32;
34: char cVar33;
35: byte bVar34;
36: ushort uVar35;
37: char cVar37;
38: char cVar39;
39: short sVar38;
40: char cVar40;
41: byte bVar41;
42: char cVar45;
43: char cVar46;
44: char cVar47;
45: undefined auVar44 [16];
46: uint3 uVar48;
47: int iVar49;
48: char cVar57;
49: char cVar58;
50: char cVar59;
51: char cVar60;
52: char cVar61;
53: char cVar62;
54: char cVar63;
55: char cVar64;
56: char cVar65;
57: char cVar66;
58: int iVar67;
59: short sVar77;
60: short sVar78;
61: short sVar79;
62: undefined auVar70 [16];
63: ushort uVar81;
64: short sVar83;
65: undefined auVar82 [16];
66: ushort uVar85;
67: int iVar86;
68: short sVar89;
69: ushort uVar90;
70: short sVar96;
71: undefined auVar91 [16];
72: int iVar97;
73: int iVar98;
74: long lStack104;
75: long lStack96;
76: long lStack88;
77: long lStack80;
78: long lStack64;
79: uint6 uVar19;
80: unkbyte10 Var21;
81: undefined auVar22 [12];
82: undefined auVar23 [14];
83: uint5 uVar36;
84: uint3 uVar42;
85: uint5 uVar43;
86: uint6 uVar50;
87: undefined8 uVar51;
88: undefined8 uVar52;
89: unkbyte10 Var53;
90: undefined auVar54 [12];
91: undefined auVar55 [12];
92: undefined auVar56 [14];
93: undefined8 uVar68;
94: undefined auVar69 [12];
95: undefined auVar71 [16];
96: undefined auVar72 [16];
97: undefined auVar73 [16];
98: undefined auVar74 [16];
99: undefined auVar75 [16];
100: undefined auVar76 [16];
101: undefined2 uVar80;
102: int iVar84;
103: undefined8 uVar87;
104: undefined auVar88 [12];
105: undefined auVar92 [16];
106: undefined auVar93 [16];
107: undefined auVar94 [16];
108: undefined auVar95 [16];
109: undefined2 uVar99;
110: 
111: pcVar3 = param_1[0x3a];
112: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
113: if (*(int *)((long)param_1 + 0x104) == 0) {
114: if (0 < *(int *)((long)param_1 + 0x144)) {
115: pcVar4 = param_1[0x29];
116: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
117: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x14),0);
118: }
119: if (*(int *)(param_1 + 0x34) == 0) {
120: iVar15 = *(int *)((long)param_1 + 0x144);
121: }
122: else {
123: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x18),1);
124: iVar15 = *(int *)((long)param_1 + 0x144);
125: }
126: if (1 < iVar15) {
127: pcVar4 = param_1[0x2a];
128: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
129: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x14),0);
130: }
131: if (*(int *)(param_1 + 0x34) == 0) {
132: iVar15 = *(int *)((long)param_1 + 0x144);
133: }
134: else {
135: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x18),1);
136: iVar15 = *(int *)((long)param_1 + 0x144);
137: }
138: if (2 < iVar15) {
139: pcVar4 = param_1[0x2b];
140: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
141: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x14),0);
142: }
143: if (*(int *)(param_1 + 0x34) == 0) {
144: iVar15 = *(int *)((long)param_1 + 0x144);
145: }
146: else {
147: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x18),1);
148: iVar15 = *(int *)((long)param_1 + 0x144);
149: }
150: if (3 < iVar15) {
151: pcVar4 = param_1[0x2c];
152: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0)) {
153: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x14),0);
154: }
155: if (*(int *)(param_1 + 0x34) != 0) {
156: FUN_00113bf0(param_1,*(undefined4 *)(pcVar4 + 0x18),1);
157: }
158: }
159: }
160: }
161: }
162: }
163: else {
164: iVar15 = *(int *)((long)param_1 + 0x144);
165: lStack88 = 0;
166: lStack80 = 0;
167: lStack104 = 0;
168: lStack96 = 0;
169: if (0 < iVar15) {
170: if (*(int *)((long)param_1 + 0x19c) == 0) {
171: pcVar4 = param_1[0x29];
172: iVar14 = *(int *)((long)param_1 + 0x1a4);
173: if (*(int *)(param_1 + 0x34) == 0) {
174: if (iVar14 == 0) {
175: *(undefined *)((long)&lStack104 + (long)*(int *)(pcVar4 + 0x14)) = 1;
176: }
177: if (1 < iVar15) {
178: if (iVar14 == 0) {
179: *(undefined *)((long)&lStack104 + (long)*(int *)(param_1[0x2a] + 0x14)) = 1;
180: }
181: if (2 < iVar15) {
182: if (iVar14 == 0) {
183: *(undefined *)((long)&lStack104 + (long)*(int *)(param_1[0x2b] + 0x14)) = 1;
184: }
185: if ((3 < iVar15) && (iVar14 == 0)) {
186: *(undefined *)((long)&lStack104 + (long)*(int *)(param_1[0x2c] + 0x14)) = 1;
187: }
188: }
189: }
190: }
191: else {
192: if (iVar14 == 0) {
193: *(undefined *)((long)&lStack104 + (long)*(int *)(pcVar4 + 0x14)) = 1;
194: }
195: *(undefined *)((long)&lStack88 + (long)*(int *)(pcVar4 + 0x18)) = 1;
196: if (1 < iVar15) {
197: pcVar4 = param_1[0x2a];
198: if (iVar14 == 0) {
199: *(undefined *)((long)&lStack104 + (long)*(int *)(pcVar4 + 0x14)) = 1;
200: }
201: *(undefined *)((long)&lStack88 + (long)*(int *)(pcVar4 + 0x18)) = 1;
202: if (2 < iVar15) {
203: pcVar4 = param_1[0x2b];
204: if (iVar14 == 0) {
205: *(undefined *)((long)&lStack104 + (long)*(int *)(pcVar4 + 0x14)) = 1;
206: }
207: *(undefined *)((long)&lStack88 + (long)*(int *)(pcVar4 + 0x18)) = 1;
208: if (3 < iVar15) {
209: pcVar4 = param_1[0x2c];
210: if (iVar14 == 0) {
211: *(undefined *)((long)&lStack104 + (long)*(int *)(pcVar4 + 0x14)) = 1;
212: }
213: *(undefined *)((long)&lStack88 + (long)*(int *)(pcVar4 + 0x18)) = 1;
214: }
215: }
216: }
217: }
218: }
219: else {
220: if ((((*(int *)(param_1 + 0x34) != 0) &&
221: (*(undefined *)((long)&lStack88 + (long)*(int *)(param_1[0x29] + 0x18)) = 1, 1 < iVar15
222: )) && (*(undefined *)((long)&lStack88 + (long)*(int *)(param_1[0x2a] + 0x18)) = 1,
223: 2 < iVar15)) &&
224: (*(undefined *)((long)&lStack88 + (long)*(int *)(param_1[0x2b] + 0x18)) = 1, 3 < iVar15))
225: {
226: *(undefined *)((long)&lStack88 + (long)*(int *)(param_1[0x2c] + 0x18)) = 1;
227: }
228: }
229: }
230: auVar44 = CONCAT88(lStack96,lStack104);
231: auVar70 = CONCAT88(lStack80,lStack88);
232: bVar34 = -((char)lStack88 < '\0');
233: uVar18 = CONCAT12(-((char)((ulong)lStack88 >> 0x10) < '\0'),
234: CONCAT11(-((char)((ulong)lStack88 >> 8) < '\0'),bVar34));
235: cVar57 = (char)((ulong)lStack88 >> 0x20);
236: cVar37 = -(cVar57 < '\0');
237: uVar36 = CONCAT14(cVar37,CONCAT13(-((char)((ulong)lStack88 >> 0x18) < '\0'),uVar18));
238: cVar58 = (char)((ulong)lStack88 >> 0x28);
239: cVar39 = -(cVar58 < '\0');
240: cVar59 = (char)((ulong)lStack88 >> 0x30);
241: cVar40 = -(cVar59 < '\0');
242: cVar60 = (char)lStack80;
243: cVar61 = (char)((ulong)lStack80 >> 8);
244: cVar62 = (char)((ulong)lStack80 >> 0x10);
245: cVar63 = (char)((ulong)lStack80 >> 0x18);
246: cVar64 = (char)((ulong)lStack80 >> 0x20);
247: cVar65 = (char)((ulong)lStack80 >> 0x28);
248: cVar66 = (char)((ulong)lStack80 >> 0x30);
249: bVar41 = -((char)lStack104 < '\0');
250: uVar42 = CONCAT12(-((char)((ulong)lStack104 >> 0x10) < '\0'),
251: CONCAT11(-((char)((ulong)lStack104 >> 8) < '\0'),bVar41));
252: cVar24 = (char)((ulong)lStack104 >> 0x20);
253: cVar45 = -(cVar24 < '\0');
254: uVar43 = CONCAT14(cVar45,CONCAT13(-((char)((ulong)lStack104 >> 0x18) < '\0'),uVar42));
255: cVar25 = (char)((ulong)lStack104 >> 0x28);
256: cVar46 = -(cVar25 < '\0');
257: cVar26 = (char)((ulong)lStack104 >> 0x30);
258: cVar47 = -(cVar26 < '\0');
259: cVar27 = (char)lStack96;
260: cVar28 = (char)((ulong)lStack96 >> 8);
261: cVar29 = (char)((ulong)lStack96 >> 0x10);
262: cVar30 = (char)((ulong)lStack96 >> 0x18);
263: cVar31 = (char)((ulong)lStack96 >> 0x20);
264: cVar32 = (char)((ulong)lStack96 >> 0x28);
265: cVar33 = (char)((ulong)lStack96 >> 0x30);
266: uVar80 = SUB162(CONCAT115(-(lStack88 < 0),
267: CONCAT114((char)((ulong)lStack88 >> 0x38),SUB1614(auVar70,0))) >> 0x70
268: ,0);
269: auVar76 = CONCAT313(SUB163(CONCAT214(uVar80,CONCAT113(cVar40,SUB1613(auVar70,0))) >> 0x68,0),
270: CONCAT112(cVar59,SUB1612(auVar70,0)));
271: auVar75 = CONCAT511(SUB165(CONCAT412(SUB164(auVar76 >> 0x60,0),
272: CONCAT111(cVar39,SUB1611(auVar70,0))) >> 0x58,0),
273: CONCAT110(cVar58,SUB1610(auVar70,0)));
274: auVar74 = CONCAT79(SUB167(CONCAT610(SUB166(auVar75 >> 0x50,0),CONCAT19(cVar37,SUB169(auVar70,0))
275: ) >> 0x48,0),CONCAT18(cVar57,lStack88));
276: auVar73 = CONCAT97(SUB169(CONCAT88(SUB168(auVar74 >> 0x40,0),
277: (((ulong)CONCAT16(cVar40,CONCAT15(cVar39,uVar36)) &
278: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
279: ((uint7)lStack88 >> 0x18) << 0x30);
280: auVar72 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar73 >> 0x30,0),
281: (((uint6)uVar36 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0),
282: ((uint5)lStack88 >> 0x10) << 0x20);
283: auVar71 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar72 >> 0x20,0),
284: ((uVar18 & 0xff00) >> 8) << 0x18) >> 0x18,0),
285: ((uint3)lStack88 >> 8) << 0x10);
286: uVar35 = (ushort)lStack88 & 0xff | (ushort)bVar34 << 8;
287: auVar70 = CONCAT142(SUB1614(auVar71 >> 0x10,0),uVar35);
288: uVar48 = CONCAT12(cVar61,CONCAT11(-(cVar60 < '\0'),cVar60));
289: uVar50 = CONCAT15(-(cVar62 < '\0'),CONCAT14(cVar62,CONCAT13(-(cVar61 < '\0'),uVar48)));
290: uVar51 = CONCAT17(-(cVar63 < '\0'),CONCAT16(cVar63,uVar50));
291: Var53 = CONCAT19(-(cVar64 < '\0'),CONCAT18(cVar64,uVar51));
292: auVar54 = CONCAT111(-(cVar65 < '\0'),CONCAT110(cVar65,Var53));
293: auVar56 = CONCAT113(-(cVar66 < '\0'),CONCAT112(cVar66,auVar54));
294: uVar99 = SUB162(CONCAT115(-(lStack104 < 0),
295: CONCAT114((char)((ulong)lStack104 >> 0x38),SUB1614(auVar44,0))) >>
296: 0x70,0);
297: auVar95 = CONCAT313(SUB163(CONCAT214(uVar99,CONCAT113(cVar47,SUB1613(auVar44,0))) >> 0x68,0),
298: CONCAT112(cVar26,SUB1612(auVar44,0)));
299: auVar94 = CONCAT511(SUB165(CONCAT412(SUB164(auVar95 >> 0x60,0),
300: CONCAT111(cVar46,SUB1611(auVar44,0))) >> 0x58,0),
301: CONCAT110(cVar25,SUB1610(auVar44,0)));
302: auVar93 = CONCAT79(SUB167(CONCAT610(SUB166(auVar94 >> 0x50,0),CONCAT19(cVar45,SUB169(auVar44,0))
303: ) >> 0x48,0),CONCAT18(cVar24,lStack104));
304: auVar82 = CONCAT97(SUB169(CONCAT88(SUB168(auVar93 >> 0x40,0),
305: (((ulong)CONCAT16(cVar47,CONCAT15(cVar46,uVar43)) &
306: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
307: ((uint7)lStack104 >> 0x18) << 0x30);
308: auVar44 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar82 >> 0x30,0),
309: (((uint6)uVar43 & 0xff0000) >> 0x10) << 0x28) >> 0x28,0),
310: ((uint5)lStack104 >> 0x10) << 0x20);
311: auVar92 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar44 >> 0x20,0),
312: ((uVar42 & 0xff00) >> 8) << 0x18) >> 0x18,0),
313: ((uint3)lStack104 >> 8) << 0x10);
314: uVar81 = (ushort)lStack104 & 0xff | (ushort)bVar41 << 8;
315: auVar91 = CONCAT142(SUB1614(auVar92 >> 0x10,0),uVar81);
316: uVar18 = CONCAT12(cVar28,CONCAT11(-(cVar27 < '\0'),cVar27));
317: uVar19 = CONCAT15(-(cVar29 < '\0'),CONCAT14(cVar29,CONCAT13(-(cVar28 < '\0'),uVar18)));
318: uVar20 = CONCAT17(-(cVar30 < '\0'),CONCAT16(cVar30,uVar19));
319: Var21 = CONCAT19(-(cVar31 < '\0'),CONCAT18(cVar31,uVar20));
320: auVar22 = CONCAT111(-(cVar32 < '\0'),CONCAT110(cVar32,Var21));
321: auVar23 = CONCAT113(-(cVar33 < '\0'),CONCAT112(cVar33,auVar22));
322: uVar90 = -(ushort)((short)uVar81 < 0);
323: sVar38 = SUB162(auVar44 >> 0x20,0);
324: sVar96 = -(ushort)(sVar38 < 0);
325: sVar83 = SUB162(auVar82 >> 0x30,0);
326: sVar77 = SUB162(auVar93 >> 0x40,0);
327: sVar78 = SUB162(auVar94 >> 0x50,0);
328: sVar79 = SUB162(auVar95 >> 0x60,0);
329: iVar86 = CONCAT22(-(ushort)(sVar77 < 0),sVar77);
330: uVar87 = CONCAT26(-(ushort)(sVar78 < 0),CONCAT24(sVar78,iVar86));
331: auVar88 = CONCAT210(-(ushort)(sVar79 < 0),CONCAT28(sVar79,uVar87));
332: iVar84 = SUB164(CONCAT214(-(ushort)(sVar83 < 0),CONCAT212(sVar83,SUB1612(auVar91,0))) >> 0x60,0)
333: ;
334: auVar82 = CONCAT610(SUB166(CONCAT412(iVar84,CONCAT210(sVar96,SUB1610(auVar91,0))) >> 0x50,0),
335: CONCAT28(sVar38,SUB168(auVar91,0)));
336: uVar85 = -(ushort)((short)uVar35 < 0);
337: sVar38 = SUB162(auVar72 >> 0x20,0);
338: sVar89 = -(ushort)(sVar38 < 0);
339: sVar83 = SUB162(auVar73 >> 0x30,0);
340: sVar77 = SUB162(auVar74 >> 0x40,0);
341: sVar78 = SUB162(auVar75 >> 0x50,0);
342: sVar79 = SUB162(auVar76 >> 0x60,0);
343: iVar14 = SUB164(CONCAT214(-(ushort)(sVar83 < 0),CONCAT212(sVar83,SUB1612(auVar70,0))) >> 0x60,0)
344: ;
345: auVar44 = CONCAT610(SUB166(CONCAT412(iVar14,CONCAT210(sVar89,SUB1610(auVar70,0))) >> 0x50,0),
346: CONCAT28(sVar38,SUB168(auVar70,0)));
347: iVar67 = CONCAT22(-(ushort)(sVar77 < 0),sVar77);
348: uVar68 = CONCAT26(-(ushort)(sVar78 < 0),CONCAT24(sVar78,iVar67));
349: auVar69 = CONCAT210(-(ushort)(sVar79 < 0),CONCAT28(sVar79,uVar68));
350: uVar35 = -(ushort)(cVar60 < '\0');
351: sVar38 = -(ushort)(cVar62 < '\0');
352: uVar81 = -(ushort)(cVar27 < '\0');
353: sVar83 = -(ushort)(cVar29 < '\0');
354: iVar97 = SUB164(CONCAT214(-(ushort)(cVar30 < '\0'),
355: CONCAT212((short)((ulong)uVar20 >> 0x30),auVar22)) >> 0x60,0);
356: auVar72 = CONCAT610(SUB166(CONCAT412(iVar97,CONCAT210(sVar83,Var21)) >> 0x50,0),
357: CONCAT28((short)(uVar19 >> 0x20),uVar20));
358: iVar15 = CONCAT22(-(ushort)(cVar31 < '\0'),(short)((unkuint10)Var21 >> 0x40));
359: uVar20 = CONCAT26(-(ushort)(cVar32 < '\0'),CONCAT24(SUB122(auVar22 >> 0x50,0),iVar15));
360: auVar22 = CONCAT210(-(ushort)(cVar33 < '\0'),CONCAT28(SUB142(auVar23 >> 0x60,0),uVar20));
361: iVar49 = CONCAT22(-(ushort)(cVar64 < '\0'),(short)((unkuint10)Var53 >> 0x40));
362: uVar52 = CONCAT26(-(ushort)(cVar65 < '\0'),CONCAT24(SUB122(auVar54 >> 0x50,0),iVar49));
363: auVar55 = CONCAT210(-(ushort)(cVar66 < '\0'),CONCAT28(SUB142(auVar56 >> 0x60,0),uVar52));
364: iVar98 = SUB164(CONCAT214(-(ushort)(cVar63 < '\0'),
365: CONCAT212((short)((ulong)uVar51 >> 0x30),auVar54)) >> 0x60,0);
366: auVar73 = CONCAT610(SUB166(CONCAT412(iVar98,CONCAT210(sVar38,Var53)) >> 0x50,0),
367: CONCAT28((short)(uVar50 >> 0x20),uVar51));
368: iVar15 = iVar15 + iVar49 +
369: (uVar48 & 0xffff | (uint)uVar35 << 0x10) + (uVar18 & 0xffff | (uint)uVar81 << 0x10) +
370: iVar67 + iVar86 +
371: (SUB164(auVar70,0) & 0xffff | (uint)uVar85 << 0x10) +
372: (SUB164(auVar91,0) & 0xffff | (uint)uVar90 << 0x10) +
373: SUB124(auVar22 >> 0x40,0) + SUB124(auVar55 >> 0x40,0) +
374: SUB164(auVar73 >> 0x40,0) + SUB164(auVar72 >> 0x40,0) +
375: SUB124(auVar69 >> 0x40,0) + SUB124(auVar88 >> 0x40,0) +
376: SUB164(auVar44 >> 0x40,0) + SUB164(auVar82 >> 0x40,0) +
377: (int)((ulong)uVar20 >> 0x20) + (int)((ulong)uVar52 >> 0x20) +
378: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar73 >> 0x40,0),
379: (((ulong)CONCAT24(sVar38,CONCAT22(-(ushort)(cVar61 < 
380: '\0'),uVar35)) & 0xffff0000) >> 0x10) << 0x30) >>
381: 0x30,0),(uVar50 >> 0x10) << 0x20) >> 0x20,0) +
382: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar72 >> 0x40,0),
383: (((ulong)CONCAT24(sVar83,CONCAT22(-(ushort)(cVar28 < 
384: '\0'),uVar81)) & 0xffff0000) >> 0x10) << 0x30) >>
385: 0x30,0),(uVar19 >> 0x10) << 0x20) >> 0x20,0) +
386: (int)((ulong)uVar68 >> 0x20) + (int)((ulong)uVar87 >> 0x20) +
387: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar44 >> 0x40,0),
388: (((ulong)CONCAT24(sVar89,CONCAT22(-(ushort)(SUB162(
389: auVar71 >> 0x10,0) < 0),uVar85)) & 0xffff0000) >>
390: 0x10) << 0x30) >> 0x30,0),
391: (SUB166(auVar70,0) >> 0x10) << 0x20) >> 0x20,0) +
392: SUB164(CONCAT106(SUB1610(CONCAT88(SUB168(auVar82 >> 0x40,0),
393: (((ulong)CONCAT24(sVar96,CONCAT22(-(ushort)(SUB162(
394: auVar92 >> 0x10,0) < 0),uVar90)) & 0xffff0000) >>
395: 0x10) << 0x30) >> 0x30,0),
396: (SUB166(auVar91,0) >> 0x10) << 0x20) >> 0x20,0) +
397: SUB164(CONCAT214(-(ushort)(lStack96 < 0),
398: CONCAT212(SUB162(CONCAT115(-(lStack96 < 0),
399: CONCAT114((char)((ulong)lStack96 >> 0x38),
400: auVar23)) >> 0x70,0),auVar22)) >>
401: 0x60,0) +
402: SUB164(CONCAT214(-(ushort)(lStack80 < 0),
403: CONCAT212(SUB162(CONCAT115(-(lStack80 < 0),
404: CONCAT114((char)((ulong)lStack80 >> 0x38),
405: auVar56)) >> 0x70,0),auVar55)) >>
406: 0x60,0) +
407: iVar98 + iVar97 +
408: SUB164(CONCAT214(-(ushort)(lStack88 < 0),CONCAT212(uVar80,auVar69)) >> 0x60,0) +
409: SUB164(CONCAT214(-(ushort)(lStack104 < 0),CONCAT212(uVar99,auVar88)) >> 0x60,0) +
410: iVar14 + iVar84;
411: if (iVar15 != 0) {
412: puVar5 = (undefined8 *)param_1[5];
413: puVar6 = (undefined *)*puVar5;
414: *puVar5 = puVar6 + 1;
415: *puVar6 = 0xff;
416: lVar16 = puVar5[1];
417: puVar5[1] = lVar16 + -1;
418: if ((lVar16 + -1 == 0) && (iVar14 = (*(code *)puVar5[3])(param_1), iVar14 == 0)) {
419: ppcVar17 = (code **)*param_1;
420: *(undefined4 *)(ppcVar17 + 5) = 0x18;
421: (**ppcVar17)(param_1);
422: }
423: puVar5 = (undefined8 *)param_1[5];
424: puVar6 = (undefined *)*puVar5;
425: *puVar5 = puVar6 + 1;
426: *puVar6 = 0xcc;
427: lVar16 = puVar5[1];
428: puVar5[1] = lVar16 + -1;
429: if ((lVar16 + -1 == 0) && (iVar14 = (*(code *)puVar5[3])(param_1), iVar14 == 0)) {
430: ppcVar17 = (code **)*param_1;
431: *(undefined4 *)(ppcVar17 + 5) = 0x18;
432: (**ppcVar17)(param_1);
433: }
434: iVar15 = iVar15 * 2 + 2;
435: plVar7 = (long *)param_1[5];
436: puVar6 = (undefined *)*plVar7;
437: *plVar7 = (long)(puVar6 + 1);
438: *puVar6 = (char)((uint)iVar15 >> 8);
439: lVar16 = plVar7[1];
440: plVar7[1] = lVar16 + -1;
441: if ((lVar16 + -1 == 0) && (iVar14 = (*(code *)plVar7[3])(param_1), iVar14 == 0)) {
442: ppcVar17 = (code **)*param_1;
443: *(undefined4 *)(ppcVar17 + 5) = 0x18;
444: (**ppcVar17)(param_1);
445: }
446: plVar7 = (long *)param_1[5];
447: puVar6 = (undefined *)*plVar7;
448: *plVar7 = (long)(puVar6 + 1);
449: *puVar6 = (char)iVar15;
450: lVar16 = plVar7[1];
451: plVar7[1] = lVar16 + -1;
452: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
453: ppcVar17 = (code **)*param_1;
454: *(undefined4 *)(ppcVar17 + 5) = 0x18;
455: (**ppcVar17)(param_1);
456: }
457: lVar16 = 0;
458: ppcVar17 = param_1;
459: do {
460: if (*(char *)((long)&lStack104 + lVar16) != '\0') {
461: ppcVar9 = (char **)param_1[5];
462: pcVar10 = *ppcVar9;
463: *ppcVar9 = pcVar10 + 1;
464: *pcVar10 = (char)lVar16;
465: pcVar10 = ppcVar9[1];
466: ppcVar9[1] = pcVar10 + -1;
467: if ((pcVar10 + -1 == (char *)0x0) &&
468: (iVar15 = (*(code *)ppcVar9[3])(param_1), iVar15 == 0)) {
469: ppcVar12 = (code **)*param_1;
470: *(undefined4 *)(ppcVar12 + 5) = 0x18;
471: (**ppcVar12)(param_1);
472: }
473: cVar24 = *(char *)(ppcVar17 + 0x1a);
474: cVar25 = *(char *)(ppcVar17 + 0x18);
475: ppcVar9 = (char **)param_1[5];
476: pcVar10 = *ppcVar9;
477: *ppcVar9 = pcVar10 + 1;
478: *pcVar10 = cVar25 + cVar24 * '\x10';
479: pcVar10 = ppcVar9[1];
480: ppcVar9[1] = pcVar10 + -1;
481: if ((pcVar10 + -1 == (char *)0x0) &&
482: (iVar15 = (*(code *)ppcVar9[3])(param_1), iVar15 == 0)) {
483: ppcVar12 = (code **)*param_1;
484: *(undefined4 *)(ppcVar12 + 5) = 0x18;
485: (**ppcVar12)(param_1);
486: }
487: }
488: if (*(char *)((long)&lStack88 + lVar16) != '\0') {
489: ppcVar9 = (char **)param_1[5];
490: pcVar10 = *ppcVar9;
491: *ppcVar9 = pcVar10 + 1;
492: *pcVar10 = (char)lVar16 + '\x10';
493: pcVar10 = ppcVar9[1];
494: ppcVar9[1] = pcVar10 + -1;
495: if ((pcVar10 + -1 == (char *)0x0) &&
496: (iVar15 = (*(code *)ppcVar9[3])(param_1), iVar15 == 0)) {
497: ppcVar12 = (code **)*param_1;
498: *(undefined4 *)(ppcVar12 + 5) = 0x18;
499: (**ppcVar12)(param_1);
500: }
501: plVar7 = (long *)param_1[5];
502: uVar1 = *(undefined *)(ppcVar17 + 0x1c);
503: puVar6 = (undefined *)*plVar7;
504: *plVar7 = (long)(puVar6 + 1);
505: *puVar6 = uVar1;
506: lVar13 = plVar7[1];
507: plVar7[1] = lVar13 + -1;
508: if ((lVar13 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
509: ppcVar12 = (code **)*param_1;
510: *(undefined4 *)(ppcVar12 + 5) = 0x18;
511: (**ppcVar12)(param_1);
512: }
513: }
514: lVar16 = lVar16 + 1;
515: ppcVar17 = (code **)((long)ppcVar17 + 1);
516: } while (lVar16 != 0x10);
517: }
518: }
519: if (*(int *)(param_1 + 0x23) != *(int *)(pcVar3 + 0x38)) {
520: puVar5 = (undefined8 *)param_1[5];
521: puVar6 = (undefined *)*puVar5;
522: *puVar5 = puVar6 + 1;
523: *puVar6 = 0xff;
524: lVar16 = puVar5[1];
525: puVar5[1] = lVar16 + -1;
526: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)puVar5[3])(param_1), iVar15 == 0)) {
527: ppcVar17 = (code **)*param_1;
528: *(undefined4 *)(ppcVar17 + 5) = 0x18;
529: (**ppcVar17)(param_1);
530: }
531: puVar5 = (undefined8 *)param_1[5];
532: puVar6 = (undefined *)*puVar5;
533: *puVar5 = puVar6 + 1;
534: *puVar6 = 0xdd;
535: lVar16 = puVar5[1];
536: puVar5[1] = lVar16 + -1;
537: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)puVar5[3])(param_1), iVar15 == 0)) {
538: ppcVar17 = (code **)*param_1;
539: *(undefined4 *)(ppcVar17 + 5) = 0x18;
540: (**ppcVar17)(param_1);
541: }
542: puVar5 = (undefined8 *)param_1[5];
543: puVar6 = (undefined *)*puVar5;
544: *puVar5 = puVar6 + 1;
545: *puVar6 = 0;
546: lVar16 = puVar5[1];
547: puVar5[1] = lVar16 + -1;
548: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)puVar5[3])(param_1), iVar15 == 0)) {
549: ppcVar17 = (code **)*param_1;
550: *(undefined4 *)(ppcVar17 + 5) = 0x18;
551: (**ppcVar17)(param_1);
552: }
553: puVar5 = (undefined8 *)param_1[5];
554: puVar6 = (undefined *)*puVar5;
555: *puVar5 = puVar6 + 1;
556: *puVar6 = 4;
557: lVar16 = puVar5[1];
558: puVar5[1] = lVar16 + -1;
559: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)puVar5[3])(param_1), iVar15 == 0)) {
560: ppcVar17 = (code **)*param_1;
561: *(undefined4 *)(ppcVar17 + 5) = 0x18;
562: (**ppcVar17)(param_1);
563: }
564: plVar7 = (long *)param_1[5];
565: uVar2 = *(undefined4 *)(param_1 + 0x23);
566: puVar6 = (undefined *)*plVar7;
567: *plVar7 = (long)(puVar6 + 1);
568: *puVar6 = (char)((uint)uVar2 >> 8);
569: lVar16 = plVar7[1];
570: plVar7[1] = lVar16 + -1;
571: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
572: ppcVar17 = (code **)*param_1;
573: *(undefined4 *)(ppcVar17 + 5) = 0x18;
574: (**ppcVar17)(param_1);
575: }
576: plVar7 = (long *)param_1[5];
577: puVar6 = (undefined *)*plVar7;
578: *plVar7 = (long)(puVar6 + 1);
579: *puVar6 = (char)uVar2;
580: lVar16 = plVar7[1];
581: plVar7[1] = lVar16 + -1;
582: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
583: ppcVar17 = (code **)*param_1;
584: *(undefined4 *)(ppcVar17 + 5) = 0x18;
585: (**ppcVar17)(param_1);
586: }
587: *(undefined4 *)(pcVar3 + 0x38) = *(undefined4 *)(param_1 + 0x23);
588: }
589: puVar5 = (undefined8 *)param_1[5];
590: puVar6 = (undefined *)*puVar5;
591: *puVar5 = puVar6 + 1;
592: *puVar6 = 0xff;
593: lVar16 = puVar5[1];
594: puVar5[1] = lVar16 + -1;
595: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)puVar5[3])(param_1), iVar15 == 0)) {
596: ppcVar17 = (code **)*param_1;
597: *(undefined4 *)(ppcVar17 + 5) = 0x18;
598: (**ppcVar17)(param_1);
599: }
600: puVar5 = (undefined8 *)param_1[5];
601: puVar6 = (undefined *)*puVar5;
602: *puVar5 = puVar6 + 1;
603: *puVar6 = 0xda;
604: lVar16 = puVar5[1];
605: puVar5[1] = lVar16 + -1;
606: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)puVar5[3])(param_1), iVar15 == 0)) {
607: ppcVar17 = (code **)*param_1;
608: *(undefined4 *)(ppcVar17 + 5) = 0x18;
609: (**ppcVar17)(param_1);
610: }
611: iVar15 = *(int *)((long)param_1 + 0x144) * 2 + 6;
612: plVar7 = (long *)param_1[5];
613: puVar6 = (undefined *)*plVar7;
614: *plVar7 = (long)(puVar6 + 1);
615: *puVar6 = (char)((uint)iVar15 >> 8);
616: lVar16 = plVar7[1];
617: plVar7[1] = lVar16 + -1;
618: if ((lVar16 + -1 == 0) && (iVar14 = (*(code *)plVar7[3])(param_1), iVar14 == 0)) {
619: ppcVar17 = (code **)*param_1;
620: *(undefined4 *)(ppcVar17 + 5) = 0x18;
621: (**ppcVar17)(param_1);
622: }
623: plVar7 = (long *)param_1[5];
624: puVar6 = (undefined *)*plVar7;
625: *plVar7 = (long)(puVar6 + 1);
626: *puVar6 = (char)iVar15;
627: lVar16 = plVar7[1];
628: plVar7[1] = lVar16 + -1;
629: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
630: ppcVar17 = (code **)*param_1;
631: *(undefined4 *)(ppcVar17 + 5) = 0x18;
632: (**ppcVar17)(param_1);
633: }
634: plVar7 = (long *)param_1[5];
635: uVar2 = *(undefined4 *)((long)param_1 + 0x144);
636: puVar6 = (undefined *)*plVar7;
637: *plVar7 = (long)(puVar6 + 1);
638: *puVar6 = (char)uVar2;
639: lVar16 = plVar7[1];
640: plVar7[1] = lVar16 + -1;
641: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(), iVar15 == 0)) {
642: ppcVar17 = (code **)*param_1;
643: *(undefined4 *)(ppcVar17 + 5) = 0x18;
644: (**ppcVar17)();
645: }
646: iVar15 = 0;
647: ppcVar17 = param_1;
648: if (0 < *(int *)((long)param_1 + 0x144)) {
649: do {
650: plVar7 = (long *)param_1[5];
651: puVar8 = (undefined4 *)ppcVar17[0x29];
652: puVar6 = (undefined *)*plVar7;
653: uVar2 = *puVar8;
654: *plVar7 = (long)(puVar6 + 1);
655: *puVar6 = (char)uVar2;
656: lVar16 = plVar7[1];
657: plVar7[1] = lVar16 + -1;
658: if ((lVar16 + -1 == 0) && (iVar14 = (*(code *)plVar7[3])(param_1), iVar14 == 0)) {
659: ppcVar12 = (code **)*param_1;
660: *(undefined4 *)(ppcVar12 + 5) = 0x18;
661: (**ppcVar12)(param_1);
662: }
663: iVar14 = *(int *)((long)param_1 + 0x19c);
664: if (iVar14 == 0) {
665: if (*(int *)((long)param_1 + 0x1a4) == 0) {
666: iVar14 = puVar8[5] << 4;
667: }
668: }
669: else {
670: iVar14 = 0;
671: }
672: cVar24 = '\0';
673: if (*(int *)(param_1 + 0x34) != 0) {
674: cVar24 = (char)puVar8[6];
675: }
676: ppcVar9 = (char **)param_1[5];
677: pcVar10 = *ppcVar9;
678: *ppcVar9 = pcVar10 + 1;
679: *pcVar10 = (char)iVar14 + cVar24;
680: pcVar10 = ppcVar9[1];
681: ppcVar9[1] = pcVar10 + -1;
682: if ((pcVar10 + -1 == (char *)0x0) && (iVar14 = (*(code *)ppcVar9[3])(param_1), iVar14 == 0)) {
683: ppcVar12 = (code **)*param_1;
684: *(undefined4 *)(ppcVar12 + 5) = 0x18;
685: (**ppcVar12)(param_1);
686: }
687: iVar15 = iVar15 + 1;
688: ppcVar17 = ppcVar17 + 1;
689: } while (iVar15 < *(int *)((long)param_1 + 0x144));
690: }
691: plVar7 = (long *)param_1[5];
692: uVar2 = *(undefined4 *)((long)param_1 + 0x19c);
693: puVar6 = (undefined *)*plVar7;
694: *plVar7 = (long)(puVar6 + 1);
695: *puVar6 = (char)uVar2;
696: lVar16 = plVar7[1];
697: plVar7[1] = lVar16 + -1;
698: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
699: ppcVar17 = (code **)*param_1;
700: *(undefined4 *)(ppcVar17 + 5) = 0x18;
701: (**ppcVar17)(param_1);
702: }
703: plVar7 = (long *)param_1[5];
704: uVar2 = *(undefined4 *)(param_1 + 0x34);
705: puVar6 = (undefined *)*plVar7;
706: *plVar7 = (long)(puVar6 + 1);
707: *puVar6 = (char)uVar2;
708: lVar16 = plVar7[1];
709: plVar7[1] = lVar16 + -1;
710: if ((lVar16 + -1 == 0) && (iVar15 = (*(code *)plVar7[3])(param_1), iVar15 == 0)) {
711: ppcVar17 = (code **)*param_1;
712: *(undefined4 *)(ppcVar17 + 5) = 0x18;
713: (**ppcVar17)(param_1);
714: }
715: ppcVar11 = (char **)param_1[5];
716: iVar15 = *(int *)((long)param_1 + 0x1a4);
717: pcVar10 = *ppcVar11;
718: uVar2 = *(undefined4 *)(param_1 + 0x35);
719: *ppcVar11 = pcVar10 + 1;
720: *pcVar10 = (char)(iVar15 << 4) + (char)uVar2;
721: ppcVar9 = ppcVar11 + 1;
722: *ppcVar9 = *ppcVar9 + -1;
723: if ((*ppcVar9 == (char *)0x0) && (iVar15 = (*(code *)ppcVar11[3])(param_1), iVar15 == 0)) {
724: ppcVar17 = (code **)*param_1;
725: lVar16 = *(long *)(in_FS_OFFSET + 0x28);
726: *(undefined4 *)(ppcVar17 + 5) = 0x18;
727: if (lStack64 == lVar16) {
728: /* WARNING: Could not recover jumptable at 0x00114b18. Too many branches */
729: /* WARNING: Treating indirect jump as call */
730: (**ppcVar17)(param_1);
731: return;
732: }
733: }
734: else {
735: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
736: return;
737: }
738: }
739: /* WARNING: Subroutine does not return */
740: __stack_chk_fail();
741: }
742: 

1: 
2: /* WARNING: Type propagation algorithm not settling */
3: /* WARNING: Could not reconcile some variable overlaps */
4: 
5: undefined8 FUN_00134bf0(code **param_1)
6: 
7: {
8: undefined8 *puVar1;
9: byte bVar2;
10: byte bVar3;
11: byte **ppbVar4;
12: code *pcVar5;
13: code **ppcVar6;
14: int iVar7;
15: int iVar8;
16: uint uVar9;
17: byte *pbVar10;
18: uint *puVar11;
19: undefined8 uVar12;
20: ulong uVar13;
21: byte *pbVar14;
22: long lVar15;
23: uint **ppuVar16;
24: undefined8 *puVar17;
25: byte *pbVar18;
26: long lVar19;
27: uint uVar20;
28: byte *pbVar21;
29: byte *pbVar22;
30: undefined4 *puVar23;
31: undefined4 *puVar24;
32: long in_FS_OFFSET;
33: byte bVar25;
34: undefined4 uStack360;
35: uint uStack356;
36: uint uStack352;
37: uint uStack348;
38: undefined uStack344;
39: byte abStack343 [7];
40: undefined8 uStack336;
41: undefined8 uStack328;
42: undefined4 uStack320;
43: undefined4 uStack316;
44: undefined4 uStack312;
45: undefined4 uStack308;
46: undefined4 uStack304;
47: undefined4 uStack300;
48: undefined4 uStack296;
49: undefined4 uStack292;
50: undefined4 uStack288;
51: undefined4 uStack284;
52: undefined4 uStack280;
53: undefined4 uStack276;
54: undefined4 uStack272;
55: undefined4 uStack268;
56: undefined4 uStack264;
57: undefined4 uStack260;
58: undefined4 uStack256;
59: undefined4 uStack252;
60: undefined4 uStack248;
61: undefined4 uStack244;
62: undefined4 uStack240;
63: undefined4 uStack236;
64: undefined4 uStack232;
65: undefined4 uStack228;
66: undefined4 uStack224;
67: undefined4 uStack220;
68: undefined4 uStack216;
69: undefined4 uStack212;
70: undefined4 uStack208;
71: undefined4 uStack204;
72: undefined4 uStack200;
73: undefined4 uStack196;
74: undefined4 uStack192;
75: undefined4 uStack188;
76: undefined4 uStack184;
77: undefined4 uStack180;
78: undefined4 uStack176;
79: undefined4 uStack172;
80: undefined4 uStack168;
81: undefined4 uStack164;
82: undefined4 uStack160;
83: undefined4 uStack156;
84: undefined4 uStack152;
85: undefined4 uStack148;
86: undefined4 uStack144;
87: undefined4 uStack140;
88: undefined4 uStack136;
89: undefined4 uStack132;
90: undefined4 uStack128;
91: undefined4 uStack124;
92: undefined4 uStack120;
93: undefined4 uStack116;
94: undefined4 uStack112;
95: undefined4 uStack108;
96: undefined4 uStack104;
97: undefined4 uStack100;
98: undefined4 uStack96;
99: undefined4 uStack92;
100: undefined4 uStack88;
101: undefined4 uStack84;
102: undefined4 uStack80;
103: undefined4 uStack76;
104: long lStack64;
105: 
106: bVar25 = 0;
107: ppbVar4 = (byte **)param_1[5];
108: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
109: pbVar14 = ppbVar4[1];
110: if (pbVar14 == (byte *)0x0) {
111: iVar7 = (*(code *)ppbVar4[3])();
112: if (iVar7 != 0) {
113: pbVar10 = *ppbVar4;
114: pbVar14 = ppbVar4[1];
115: goto LAB_00134c3b;
116: }
117: LAB_00134d50:
118: uVar12 = 0;
119: }
120: else {
121: pbVar10 = *ppbVar4;
122: LAB_00134c3b:
123: pbVar14 = pbVar14 + -1;
124: bVar2 = *pbVar10;
125: if (pbVar14 == (byte *)0x0) {
126: iVar7 = (*(code *)ppbVar4[3])(param_1);
127: if (iVar7 == 0) goto LAB_00134d50;
128: pbVar10 = *ppbVar4;
129: pbVar14 = ppbVar4[1];
130: }
131: else {
132: pbVar10 = pbVar10 + 1;
133: }
134: pbVar18 = pbVar10 + 1;
135: pbVar14 = pbVar14 + -1;
136: lVar19 = (ulong)bVar2 * 0x100 + -2 + (ulong)*pbVar10;
137: if (0x10 < lVar19) {
138: do {
139: if (pbVar14 == (byte *)0x0) {
140: iVar7 = (*(code *)ppbVar4[3])(param_1);
141: if (iVar7 == 0) goto LAB_00134d50;
142: pbVar18 = *ppbVar4;
143: pbVar14 = ppbVar4[1];
144: }
145: bVar2 = *pbVar18;
146: pbVar14 = pbVar14 + -1;
147: iVar7 = 0;
148: uVar20 = (uint)bVar2;
149: pcVar5 = *param_1;
150: *(uint *)(pcVar5 + 0x2c) = uVar20;
151: *(undefined4 *)(pcVar5 + 0x28) = 0x50;
152: (**(code **)(pcVar5 + 8))(param_1,1);
153: uStack360 = uStack360 & 0xffffff00;
154: pbVar10 = pbVar18 + 1;
155: pbVar22 = (byte *)((long)&uStack360 + 1);
156: do {
157: if (pbVar14 == (byte *)0x0) {
158: iVar8 = (*(code *)ppbVar4[3])(param_1);
159: if (iVar8 == 0) goto LAB_00134d50;
160: pbVar10 = *ppbVar4;
161: pbVar14 = ppbVar4[1];
162: }
163: pbVar18 = pbVar10 + 1;
164: bVar3 = *pbVar10;
165: pbVar21 = pbVar22 + 1;
166: pbVar14 = pbVar14 + -1;
167: *pbVar22 = bVar3;
168: iVar7 = iVar7 + (uint)bVar3;
169: pbVar10 = pbVar18;
170: pbVar22 = pbVar21;
171: } while (abStack343 != pbVar21);
172: pcVar5 = *param_1;
173: *(uint *)(pcVar5 + 0x2c) = uStack360 >> 8 & 0xff;
174: *(undefined4 *)(pcVar5 + 0x28) = 0x56;
175: *(uint *)(pcVar5 + 0x30) = uStack360 >> 0x10 & 0xff;
176: *(uint *)(pcVar5 + 0x34) = uStack360 >> 0x18;
177: *(uint *)(pcVar5 + 0x38) = uStack356 & 0xff;
178: *(uint *)(pcVar5 + 0x3c) = uStack356 >> 8 & 0xff;
179: *(uint *)(pcVar5 + 0x40) = uStack356 >> 0x10 & 0xff;
180: *(uint *)(pcVar5 + 0x44) = uStack356 >> 0x18;
181: *(uint *)(pcVar5 + 0x48) = uStack352 & 0xff;
182: (**(code **)(pcVar5 + 8))(param_1,2);
183: pcVar5 = *param_1;
184: *(undefined4 *)(pcVar5 + 0x28) = 0x56;
185: *(uint *)(pcVar5 + 0x2c) = uStack352 >> 8 & 0xff;
186: *(uint *)(pcVar5 + 0x30) = uStack352 >> 0x10 & 0xff;
187: *(uint *)(pcVar5 + 0x34) = uStack352 >> 0x18;
188: *(uint *)(pcVar5 + 0x38) = uStack348 & 0xff;
189: *(uint *)(pcVar5 + 0x3c) = uStack348 >> 8 & 0xff;
190: *(uint *)(pcVar5 + 0x40) = uStack348 >> 0x10 & 0xff;
191: *(uint *)(pcVar5 + 0x44) = uStack348 >> 0x18;
192: *(uint *)(pcVar5 + 0x48) = (uint)(byte)uStack344;
193: (**(code **)(pcVar5 + 8))(param_1,2);
194: if ((0x100 < iVar7) || (lVar19 + -0x11 < (long)iVar7)) {
195: ppcVar6 = (code **)*param_1;
196: *(undefined4 *)(ppcVar6 + 5) = 8;
197: (**ppcVar6)(param_1);
198: }
199: if (iVar7 != 0) {
200: puVar24 = (undefined4 *)&uStack328;
201: do {
202: if (pbVar14 == (byte *)0x0) {
203: iVar8 = (*(code *)ppbVar4[3])(param_1);
204: if (iVar8 == 0) goto LAB_00134d50;
205: pbVar10 = *ppbVar4;
206: pbVar14 = ppbVar4[1];
207: }
208: pbVar18 = pbVar10 + 1;
209: puVar23 = (undefined4 *)((long)puVar24 + 1);
210: pbVar14 = pbVar14 + -1;
211: *(byte *)puVar24 = *pbVar10;
212: pbVar10 = pbVar18;
213: puVar24 = puVar23;
214: } while ((undefined4 *)((long)&uStack328 + (ulong)(iVar7 - 1) + 1) != puVar23);
215: }
216: uVar9 = 0x100 - iVar7;
217: lVar15 = (long)iVar7;
218: puVar1 = (undefined8 *)((long)&uStack328 + lVar15);
219: if (uVar9 < 8) {
220: if ((uVar9 & 4) == 0) {
221: if ((uVar9 != 0) && (*(undefined *)puVar1 = 0, (uVar9 & 2) != 0)) {
222: *(undefined2 *)((long)&uStack336 + (ulong)uVar9 + lVar15 + 6) = 0;
223: }
224: }
225: else {
226: *(undefined4 *)puVar1 = 0;
227: *(undefined4 *)((long)&uStack336 + (ulong)uVar9 + lVar15 + 4) = 0;
228: }
229: }
230: else {
231: *puVar1 = 0;
232: *(undefined8 *)((long)&uStack336 + (ulong)uVar9 + lVar15) = 0;
233: puVar17 = (undefined8 *)((long)&uStack320 + lVar15 & 0xfffffffffffffff8);
234: uVar13 = (ulong)(((int)puVar1 - (int)puVar17) + uVar9 >> 3);
235: while (uVar13 != 0) {
236: uVar13 = uVar13 - 1;
237: *puVar17 = 0;
238: puVar17 = puVar17 + (ulong)bVar25 * -2 + 1;
239: }
240: }
241: lVar19 = (lVar19 + -0x11) - lVar15;
242: if ((bVar2 & 0x10) == 0) {
243: if (3 < bVar2) {
244: ppcVar6 = (code **)*param_1;
245: *(undefined4 *)(ppcVar6 + 5) = 0x1e;
246: *(uint *)((long)ppcVar6 + 0x2c) = uVar20;
247: (**ppcVar6)(param_1);
248: }
249: lVar15 = (ulong)bVar2 + 0x1d;
250: }
251: else {
252: uVar20 = uVar20 - 0x10;
253: if (3 < uVar20) {
254: ppcVar6 = (code **)*param_1;
255: *(undefined4 *)(ppcVar6 + 5) = 0x1e;
256: *(uint *)((long)ppcVar6 + 0x2c) = uVar20;
257: (**ppcVar6)(param_1);
258: }
259: lVar15 = (long)(int)uVar20 + 0x21;
260: }
261: ppuVar16 = (uint **)(param_1 + lVar15);
262: puVar11 = *ppuVar16;
263: if (puVar11 == (uint *)0x0) {
264: puVar11 = (uint *)FUN_0011f530(param_1);
265: *ppuVar16 = puVar11;
266: *puVar11 = uStack360;
267: puVar11[1] = uStack356;
268: puVar11[2] = uStack352;
269: puVar11[3] = uStack348;
270: *(code *)(puVar11 + 4) = uStack344;
271: puVar11 = *ppuVar16;
272: *(undefined4 *)((long)puVar11 + 0x11) = (undefined4)uStack328;
273: *(undefined4 *)((long)puVar11 + 0x15) = uStack328._4_4_;
274: *(undefined4 *)((long)puVar11 + 0x19) = uStack320;
275: *(undefined4 *)((long)puVar11 + 0x1d) = uStack316;
276: *(undefined4 *)((long)puVar11 + 0x21) = uStack312;
277: *(undefined4 *)((long)puVar11 + 0x25) = uStack308;
278: *(undefined4 *)((long)puVar11 + 0x29) = uStack304;
279: *(undefined4 *)((long)puVar11 + 0x2d) = uStack300;
280: *(undefined4 *)((long)puVar11 + 0x31) = uStack296;
281: *(undefined4 *)((long)puVar11 + 0x35) = uStack292;
282: *(undefined4 *)((long)puVar11 + 0x39) = uStack288;
283: *(undefined4 *)((long)puVar11 + 0x3d) = uStack284;
284: *(undefined4 *)((long)puVar11 + 0x41) = uStack280;
285: *(undefined4 *)((long)puVar11 + 0x45) = uStack276;
286: *(undefined4 *)((long)puVar11 + 0x49) = uStack272;
287: *(undefined4 *)((long)puVar11 + 0x4d) = uStack268;
288: *(undefined4 *)((long)puVar11 + 0x51) = uStack264;
289: *(undefined4 *)((long)puVar11 + 0x55) = uStack260;
290: *(undefined4 *)((long)puVar11 + 0x59) = uStack256;
291: *(undefined4 *)((long)puVar11 + 0x5d) = uStack252;
292: *(undefined4 *)((long)puVar11 + 0x61) = uStack248;
293: *(undefined4 *)((long)puVar11 + 0x65) = uStack244;
294: *(undefined4 *)((long)puVar11 + 0x69) = uStack240;
295: *(undefined4 *)((long)puVar11 + 0x6d) = uStack236;
296: *(undefined4 *)((long)puVar11 + 0x71) = uStack232;
297: *(undefined4 *)((long)puVar11 + 0x75) = uStack228;
298: *(undefined4 *)((long)puVar11 + 0x79) = uStack224;
299: *(undefined4 *)((long)puVar11 + 0x7d) = uStack220;
300: *(undefined4 *)((long)puVar11 + 0x81) = uStack216;
301: *(undefined4 *)((long)puVar11 + 0x85) = uStack212;
302: *(undefined4 *)((long)puVar11 + 0x89) = uStack208;
303: *(undefined4 *)((long)puVar11 + 0x8d) = uStack204;
304: *(undefined4 *)((long)puVar11 + 0x91) = uStack200;
305: *(undefined4 *)((long)puVar11 + 0x95) = uStack196;
306: *(undefined4 *)((long)puVar11 + 0x99) = uStack192;
307: *(undefined4 *)((long)puVar11 + 0x9d) = uStack188;
308: *(undefined4 *)((long)puVar11 + 0xa1) = uStack184;
309: *(undefined4 *)((long)puVar11 + 0xa5) = uStack180;
310: *(undefined4 *)((long)puVar11 + 0xa9) = uStack176;
311: *(undefined4 *)((long)puVar11 + 0xad) = uStack172;
312: *(undefined4 *)((long)puVar11 + 0xb1) = uStack168;
313: *(undefined4 *)((long)puVar11 + 0xb5) = uStack164;
314: *(undefined4 *)((long)puVar11 + 0xb9) = uStack160;
315: *(undefined4 *)((long)puVar11 + 0xbd) = uStack156;
316: *(undefined4 *)((long)puVar11 + 0xc1) = uStack152;
317: *(undefined4 *)((long)puVar11 + 0xc5) = uStack148;
318: *(undefined4 *)((long)puVar11 + 0xc9) = uStack144;
319: *(undefined4 *)((long)puVar11 + 0xcd) = uStack140;
320: *(undefined4 *)((long)puVar11 + 0xd1) = uStack136;
321: *(undefined4 *)((long)puVar11 + 0xd5) = uStack132;
322: *(undefined4 *)((long)puVar11 + 0xd9) = uStack128;
323: *(undefined4 *)((long)puVar11 + 0xdd) = uStack124;
324: *(undefined4 *)((long)puVar11 + 0xe1) = uStack120;
325: *(undefined4 *)((long)puVar11 + 0xe5) = uStack116;
326: *(undefined4 *)((long)puVar11 + 0xe9) = uStack112;
327: *(undefined4 *)((long)puVar11 + 0xed) = uStack108;
328: *(undefined4 *)((long)puVar11 + 0xf1) = uStack104;
329: *(undefined4 *)((long)puVar11 + 0xf5) = uStack100;
330: *(undefined4 *)((long)puVar11 + 0xf9) = uStack96;
331: *(undefined4 *)((long)puVar11 + 0xfd) = uStack92;
332: *(undefined4 *)((long)puVar11 + 0x101) = uStack88;
333: *(undefined4 *)((long)puVar11 + 0x105) = uStack84;
334: *(undefined4 *)((long)puVar11 + 0x109) = uStack80;
335: *(undefined4 *)((long)puVar11 + 0x10d) = uStack76;
336: }
337: else {
338: *puVar11 = uStack360;
339: puVar11[1] = uStack356;
340: puVar11[2] = uStack352;
341: puVar11[3] = uStack348;
342: *(code *)(puVar11 + 4) = uStack344;
343: puVar11 = *ppuVar16;
344: *(undefined4 *)((long)puVar11 + 0x11) = (undefined4)uStack328;
345: *(undefined4 *)((long)puVar11 + 0x15) = uStack328._4_4_;
346: *(undefined4 *)((long)puVar11 + 0x19) = uStack320;
347: *(undefined4 *)((long)puVar11 + 0x1d) = uStack316;
348: *(undefined4 *)((long)puVar11 + 0x21) = uStack312;
349: *(undefined4 *)((long)puVar11 + 0x25) = uStack308;
350: *(undefined4 *)((long)puVar11 + 0x29) = uStack304;
351: *(undefined4 *)((long)puVar11 + 0x2d) = uStack300;
352: *(undefined4 *)((long)puVar11 + 0x31) = uStack296;
353: *(undefined4 *)((long)puVar11 + 0x35) = uStack292;
354: *(undefined4 *)((long)puVar11 + 0x39) = uStack288;
355: *(undefined4 *)((long)puVar11 + 0x3d) = uStack284;
356: *(undefined4 *)((long)puVar11 + 0x41) = uStack280;
357: *(undefined4 *)((long)puVar11 + 0x45) = uStack276;
358: *(undefined4 *)((long)puVar11 + 0x49) = uStack272;
359: *(undefined4 *)((long)puVar11 + 0x4d) = uStack268;
360: *(undefined4 *)((long)puVar11 + 0x51) = uStack264;
361: *(undefined4 *)((long)puVar11 + 0x55) = uStack260;
362: *(undefined4 *)((long)puVar11 + 0x59) = uStack256;
363: *(undefined4 *)((long)puVar11 + 0x5d) = uStack252;
364: *(undefined4 *)((long)puVar11 + 0x61) = uStack248;
365: *(undefined4 *)((long)puVar11 + 0x65) = uStack244;
366: *(undefined4 *)((long)puVar11 + 0x69) = uStack240;
367: *(undefined4 *)((long)puVar11 + 0x6d) = uStack236;
368: *(undefined4 *)((long)puVar11 + 0x71) = uStack232;
369: *(undefined4 *)((long)puVar11 + 0x75) = uStack228;
370: *(undefined4 *)((long)puVar11 + 0x79) = uStack224;
371: *(undefined4 *)((long)puVar11 + 0x7d) = uStack220;
372: *(undefined4 *)((long)puVar11 + 0x81) = uStack216;
373: *(undefined4 *)((long)puVar11 + 0x85) = uStack212;
374: *(undefined4 *)((long)puVar11 + 0x89) = uStack208;
375: *(undefined4 *)((long)puVar11 + 0x8d) = uStack204;
376: *(undefined4 *)((long)puVar11 + 0x91) = uStack200;
377: *(undefined4 *)((long)puVar11 + 0x95) = uStack196;
378: *(undefined4 *)((long)puVar11 + 0x99) = uStack192;
379: *(undefined4 *)((long)puVar11 + 0x9d) = uStack188;
380: *(undefined4 *)((long)puVar11 + 0xa1) = uStack184;
381: *(undefined4 *)((long)puVar11 + 0xa5) = uStack180;
382: *(undefined4 *)((long)puVar11 + 0xa9) = uStack176;
383: *(undefined4 *)((long)puVar11 + 0xad) = uStack172;
384: *(undefined4 *)((long)puVar11 + 0xb1) = uStack168;
385: *(undefined4 *)((long)puVar11 + 0xb5) = uStack164;
386: *(undefined4 *)((long)puVar11 + 0xb9) = uStack160;
387: *(undefined4 *)((long)puVar11 + 0xbd) = uStack156;
388: *(undefined4 *)((long)puVar11 + 0xc1) = uStack152;
389: *(undefined4 *)((long)puVar11 + 0xc5) = uStack148;
390: *(undefined4 *)((long)puVar11 + 0xc9) = uStack144;
391: *(undefined4 *)((long)puVar11 + 0xcd) = uStack140;
392: *(undefined4 *)((long)puVar11 + 0xd1) = uStack136;
393: *(undefined4 *)((long)puVar11 + 0xd5) = uStack132;
394: *(undefined4 *)((long)puVar11 + 0xd9) = uStack128;
395: *(undefined4 *)((long)puVar11 + 0xdd) = uStack124;
396: *(undefined4 *)((long)puVar11 + 0xe1) = uStack120;
397: *(undefined4 *)((long)puVar11 + 0xe5) = uStack116;
398: *(undefined4 *)((long)puVar11 + 0xe9) = uStack112;
399: *(undefined4 *)((long)puVar11 + 0xed) = uStack108;
400: *(undefined4 *)((long)puVar11 + 0xf1) = uStack104;
401: *(undefined4 *)((long)puVar11 + 0xf5) = uStack100;
402: *(undefined4 *)((long)puVar11 + 0xf9) = uStack96;
403: *(undefined4 *)((long)puVar11 + 0xfd) = uStack92;
404: *(undefined4 *)((long)puVar11 + 0x101) = uStack88;
405: *(undefined4 *)((long)puVar11 + 0x105) = uStack84;
406: *(undefined4 *)((long)puVar11 + 0x109) = uStack80;
407: *(undefined4 *)((long)puVar11 + 0x10d) = uStack76;
408: }
409: } while (0x10 < lVar19);
410: }
411: if (lVar19 != 0) {
412: ppcVar6 = (code **)*param_1;
413: *(undefined4 *)(ppcVar6 + 5) = 0xb;
414: (**ppcVar6)(param_1);
415: }
416: *ppbVar4 = pbVar18;
417: ppbVar4[1] = pbVar14;
418: uVar12 = 1;
419: }
420: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
421: return uVar12;
422: }
423: /* WARNING: Subroutine does not return */
424: __stack_chk_fail();
425: }
426: 

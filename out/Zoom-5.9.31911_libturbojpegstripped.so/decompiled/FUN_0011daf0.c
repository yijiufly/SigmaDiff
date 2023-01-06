1: 
2: uint FUN_0011daf0(code **param_1,uint param_2)
3: 
4: {
5: undefined8 *puVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: code *pcVar6;
11: uint uVar7;
12: code *pcVar8;
13: int iVar9;
14: uint uVar10;
15: undefined8 *puVar11;
16: uint uVar12;
17: long lVar13;
18: undefined8 *puVar14;
19: int iVar15;
20: code *pcVar16;
21: long lVar17;
22: uint uVar18;
23: uint uVar19;
24: int iVar20;
25: uint uStack88;
26: uint uStack84;
27: 
28: pcVar2 = param_1[0x45];
29: pcVar3 = param_1[0x46];
30: pcVar4 = param_1[0x4c];
31: if (*(int *)((long)param_1 + 0x24) != 0xcd) {
32: pcVar8 = *param_1;
33: *(int *)(pcVar8 + 0x2c) = *(int *)((long)param_1 + 0x24);
34: ppcVar5 = (code **)*param_1;
35: *(undefined4 *)(pcVar8 + 0x28) = 0x14;
36: (**ppcVar5)();
37: }
38: uVar19 = *(uint *)(param_1 + 0x15);
39: uVar7 = *(uint *)((long)param_1 + 0x8c);
40: if (uVar7 <= param_2 + uVar19) {
41: *(uint *)(param_1 + 0x15) = uVar7;
42: (**(code **)(param_1[0x48] + 0x18))(param_1);
43: *(undefined4 *)(param_1[0x48] + 0x24) = 1;
44: return *(int *)((long)param_1 + 0x8c) - *(int *)(param_1 + 0x15);
45: }
46: if (param_2 == 0) {
47: return 0;
48: }
49: iVar9 = *(int *)(param_1 + 0x34);
50: uVar12 = *(uint *)((long)param_1 + 0x19c);
51: uVar18 = iVar9 * uVar12;
52: uVar10 = (uVar18 - uVar19 % uVar18) % uVar18;
53: uStack84 = param_2 - uVar10;
54: pcVar8 = param_1[0x4c];
55: if (*(int *)(pcVar8 + 0x10) == 0) {
56: if (param_2 < uVar10) {
57: uVar7 = param_2 % uVar12;
58: *(uint *)(param_1[0x45] + 100) = *(int *)(param_1[0x45] + 100) + param_2 / uVar12;
59: pcVar2 = param_1[0x4d];
60: *(uint *)(param_1 + 0x15) = (param_2 + uVar19) - uVar7;
61: if (pcVar2 == (code *)0x0) {
62: lVar17 = 0;
63: }
64: else {
65: lVar17 = *(long *)(pcVar2 + 8);
66: if (lVar17 != 0) {
67: *(code **)(pcVar2 + 8) = FUN_0011d6a0;
68: }
69: }
70: pcVar2 = param_1[0x4e];
71: if (pcVar2 == (code *)0x0) {
72: lVar13 = 0;
73: }
74: else {
75: lVar13 = *(long *)(pcVar2 + 8);
76: if (lVar13 != 0) {
77: *(code **)(pcVar2 + 8) = FUN_0011d6b0;
78: }
79: }
80: uVar19 = 0;
81: if (uVar7 != 0) {
82: do {
83: uVar19 = uVar19 + 1;
84: FUN_0011da40(param_1,0,1);
85: } while (uVar19 != uVar7);
86: }
87: if (lVar17 != 0) {
88: *(long *)(param_1[0x4d] + 8) = lVar17;
89: }
90: goto LAB_0011e21e;
91: }
92: *(uint *)(param_1 + 0x15) = uVar10 + uVar19;
93: *(undefined4 *)(pcVar2 + 0x60) = 0;
94: *(undefined4 *)(pcVar2 + 100) = 0;
95: *(uint *)(pcVar4 + 0xb8) = uVar12;
96: *(uint *)(pcVar4 + 0xbc) = uVar7 - (uVar10 + uVar19);
97: }
98: else {
99: if (param_2 < uVar10 + 1) {
100: LAB_0011e1ac:
101: pcVar2 = param_1[0x4d];
102: if (pcVar2 == (code *)0x0) {
103: lVar17 = 0;
104: }
105: else {
106: lVar17 = *(long *)(pcVar2 + 8);
107: if (lVar17 != 0) {
108: *(code **)(pcVar2 + 8) = FUN_0011d6a0;
109: }
110: }
111: pcVar2 = param_1[0x4e];
112: if (pcVar2 == (code *)0x0) {
113: lVar13 = 0;
114: }
115: else {
116: lVar13 = *(long *)(pcVar2 + 8);
117: if (lVar13 != 0) {
118: *(code **)(pcVar2 + 8) = FUN_0011d6b0;
119: }
120: }
121: uVar19 = 0;
122: do {
123: FUN_0011da40(param_1,0,1);
124: uVar19 = uVar19 + 1;
125: } while (uVar19 != param_2);
126: if (lVar17 != 0) {
127: *(long *)(param_1[0x4d] + 8) = lVar17;
128: }
129: LAB_0011e21e:
130: if (lVar13 == 0) {
131: return param_2;
132: }
133: *(long *)(param_1[0x4e] + 8) = lVar13;
134: return param_2;
135: }
136: if ((uVar10 < 2) && (*(int *)(pcVar2 + 0x60) != 0)) {
137: if (uStack84 < uVar18 + 1) goto LAB_0011e1ac;
138: uVar19 = uVar19 + uVar18;
139: uStack84 = uStack84 - uVar18;
140: }
141: *(uint *)(param_1 + 0x15) = uVar10 + uVar19;
142: if ((*(int *)(pcVar2 + 0x84) == 0) || ((*(int *)(pcVar2 + 0x84) == 1 && (2 < uVar10)))) {
143: pcVar6 = param_1[0x45];
144: pcVar16 = param_1[0x26];
145: if (0 < *(int *)(param_1 + 7)) {
146: lVar17 = 0;
147: pcVar8 = pcVar16 + ((ulong)(*(int *)(param_1 + 7) - 1) * 3 + 3) * 0x20;
148: do {
149: puVar14 = *(undefined8 **)(*(long *)(pcVar6 + 0x70) + lVar17);
150: iVar20 = (*(int *)(pcVar16 + 0xc) * *(int *)(pcVar16 + 0x24)) / iVar9;
151: puVar11 = *(undefined8 **)(*(long *)(pcVar6 + 0x68) + lVar17);
152: if (0 < iVar20) {
153: iVar15 = iVar20 * (iVar9 + 1);
154: puVar1 = puVar11 + (ulong)(iVar20 - 1) + 1;
155: do {
156: puVar11[-iVar20] = puVar11[iVar15];
157: puVar14[-iVar20] = puVar14[iVar15];
158: puVar11[iVar15 + iVar20] = *puVar11;
159: puVar11 = puVar11 + 1;
160: puVar14[iVar15 + iVar20] = *puVar14;
161: puVar14 = puVar14 + 1;
162: } while (puVar11 != puVar1);
163: }
164: pcVar16 = pcVar16 + 0x60;
165: lVar17 = lVar17 + 8;
166: } while (pcVar16 != pcVar8);
167: pcVar8 = param_1[0x4c];
168: }
169: }
170: *(undefined4 *)(pcVar2 + 0x60) = 0;
171: *(undefined4 *)(pcVar2 + 100) = 0;
172: *(undefined4 *)(pcVar2 + 0x7c) = 0;
173: *(uint *)(pcVar4 + 0xb8) = uVar12;
174: *(uint *)(pcVar4 + 0xbc) = uVar7 - (uVar10 + uVar19);
175: }
176: iVar9 = *(int *)(pcVar8 + 0x10);
177: if (iVar9 == 0) {
178: uStack88 = (uStack84 / uVar18) * uVar18;
179: uStack84 = uStack84 - uStack88;
180: if (*(int *)(param_1[0x48] + 0x20) == 0) goto LAB_0011de82;
181: iVar9 = *(int *)(param_1 + 0x15);
182: *(uint *)(param_1 + 0x17) = *(int *)(param_1 + 0x17) + uStack88 / uVar18;
183: uVar19 = uStack84 % uVar12;
184: *(uint *)(param_1[0x45] + 100) = *(int *)(param_1[0x45] + 100) + uStack84 / uVar12;
185: *(uint *)(param_1 + 0x15) = (uStack84 + iVar9 + uStack88) - uVar19;
186: pcVar2 = param_1[0x4d];
187: if (pcVar2 == (code *)0x0) {
188: lVar17 = 0;
189: }
190: else {
191: lVar17 = *(long *)(pcVar2 + 8);
192: if (lVar17 != 0) {
193: *(code **)(pcVar2 + 8) = FUN_0011d6a0;
194: }
195: }
196: pcVar2 = param_1[0x4e];
197: if (pcVar2 == (code *)0x0) {
198: lVar13 = 0;
199: }
200: else {
201: lVar13 = *(long *)(pcVar2 + 8);
202: if (lVar13 != 0) {
203: *(code **)(pcVar2 + 8) = FUN_0011d6b0;
204: }
205: }
206: uVar12 = 0;
207: if (uVar19 != 0) {
208: do {
209: uVar12 = uVar12 + 1;
210: FUN_0011da40(param_1,0,1);
211: } while (uVar12 != uVar19);
212: uVar7 = *(uint *)((long)param_1 + 0x8c);
213: }
214: if (lVar17 != 0) {
215: *(long *)(param_1[0x4d] + 8) = lVar17;
216: }
217: if (lVar13 != 0) {
218: *(long *)(param_1[0x4e] + 8) = lVar13;
219: }
220: }
221: else {
222: uStack88 = ((uStack84 - 1) / uVar18) * uVar18;
223: uStack84 = uStack84 - uStack88;
224: if (*(int *)(param_1[0x48] + 0x20) == 0) {
225: LAB_0011de82:
226: uVar19 = uVar18;
227: if (uStack88 != 0) {
228: while( true ) {
229: iVar9 = *(int *)(pcVar3 + 0x30);
230: if (0 < iVar9) {
231: uVar7 = *(uint *)(param_1 + 0x3b);
232: iVar20 = 0;
233: do {
234: if (uVar7 != 0) {
235: uVar12 = 0;
236: do {
237: uVar12 = uVar12 + 1;
238: (**(code **)(param_1[0x4a] + 8))(param_1);
239: uVar7 = *(uint *)(param_1 + 0x3b);
240: } while (uVar12 < uVar7);
241: iVar9 = *(int *)(pcVar3 + 0x30);
242: }
243: iVar20 = iVar20 + 1;
244: } while (iVar20 < iVar9);
245: }
246: *(int *)(param_1 + 0x17) = *(int *)(param_1 + 0x17) + 1;
247: uVar7 = *(int *)(param_1 + 0x16) + 1;
248: *(uint *)(param_1 + 0x16) = uVar7;
249: if (uVar7 < *(uint *)((long)param_1 + 0x1a4)) {
250: pcVar8 = param_1[0x46];
251: if (*(int *)(param_1 + 0x36) < 2) {
252: if (uVar7 < *(uint *)((long)param_1 + 0x1a4) - 1) {
253: *(undefined4 *)(pcVar8 + 0x30) = *(undefined4 *)(param_1[0x37] + 0xc);
254: }
255: else {
256: *(undefined4 *)(pcVar8 + 0x30) = *(undefined4 *)(param_1[0x37] + 0x48);
257: }
258: }
259: else {
260: *(undefined4 *)(pcVar8 + 0x30) = 1;
261: }
262: *(undefined4 *)(pcVar8 + 0x28) = 0;
263: *(undefined4 *)(pcVar8 + 0x2c) = 0;
264: }
265: else {
266: (**(code **)(param_1[0x48] + 0x18))(param_1);
267: }
268: if (uStack88 <= uVar19) break;
269: uVar19 = uVar19 + uVar18;
270: }
271: iVar9 = *(int *)(param_1[0x4c] + 0x10);
272: }
273: iVar20 = *(int *)(param_1 + 0x15);
274: *(uint *)(param_1 + 0x15) = uStack88 + iVar20;
275: if (iVar9 == 0) {
276: uVar19 = uStack84 % *(uint *)((long)param_1 + 0x19c);
277: *(uint *)(param_1[0x45] + 100) =
278: *(int *)(param_1[0x45] + 100) + uStack84 / *(uint *)((long)param_1 + 0x19c);
279: *(uint *)(param_1 + 0x15) = (uStack84 + uStack88 + iVar20) - uVar19;
280: pcVar2 = param_1[0x4d];
281: if (pcVar2 == (code *)0x0) {
282: lVar17 = 0;
283: }
284: else {
285: lVar17 = *(long *)(pcVar2 + 8);
286: if (lVar17 != 0) {
287: *(code **)(pcVar2 + 8) = FUN_0011d6a0;
288: }
289: }
290: pcVar2 = param_1[0x4e];
291: if (pcVar2 == (code *)0x0) {
292: lVar13 = 0;
293: }
294: else {
295: lVar13 = *(long *)(pcVar2 + 8);
296: if (lVar13 != 0) {
297: *(code **)(pcVar2 + 8) = FUN_0011d6b0;
298: }
299: }
300: uVar7 = 0;
301: if (uVar19 != 0) {
302: do {
303: uVar7 = uVar7 + 1;
304: FUN_0011da40(param_1,0,1);
305: } while (uVar7 != uVar19);
306: }
307: if (lVar17 != 0) {
308: *(long *)(param_1[0x4d] + 8) = lVar17;
309: }
310: if (lVar13 != 0) {
311: *(long *)(param_1[0x4e] + 8) = lVar13;
312: }
313: }
314: else {
315: *(uint *)(pcVar2 + 0x84) = *(int *)(pcVar2 + 0x84) + uStack88 / uVar18;
316: pcVar2 = param_1[0x4d];
317: if (pcVar2 == (code *)0x0) {
318: lVar17 = 0;
319: }
320: else {
321: lVar17 = *(long *)(pcVar2 + 8);
322: if (lVar17 != 0) {
323: *(code **)(pcVar2 + 8) = FUN_0011d6a0;
324: }
325: }
326: pcVar2 = param_1[0x4e];
327: if (pcVar2 == (code *)0x0) {
328: lVar13 = 0;
329: }
330: else {
331: lVar13 = *(long *)(pcVar2 + 8);
332: if (lVar13 != 0) {
333: *(code **)(pcVar2 + 8) = FUN_0011d6b0;
334: }
335: }
336: uVar19 = 0;
337: if (uStack84 != 0) {
338: do {
339: uVar19 = uVar19 + 1;
340: FUN_0011da40(param_1,0,1);
341: } while (uVar19 != uStack84);
342: }
343: if (lVar17 != 0) {
344: *(long *)(param_1[0x4d] + 8) = lVar17;
345: }
346: if (lVar13 != 0) {
347: *(long *)(param_1[0x4e] + 8) = lVar13;
348: }
349: }
350: *(int *)(pcVar4 + 0xbc) = *(int *)((long)param_1 + 0x8c) - *(int *)(param_1 + 0x15);
351: return param_2;
352: }
353: *(uint *)(param_1 + 0x15) = *(int *)(param_1 + 0x15) + uStack88;
354: *(uint *)(param_1 + 0x17) = *(int *)(param_1 + 0x17) + uStack88 / uVar18;
355: *(uint *)(pcVar2 + 0x84) = *(int *)(pcVar2 + 0x84) + uStack88 / uVar18;
356: pcVar2 = param_1[0x4d];
357: if (pcVar2 == (code *)0x0) {
358: lVar17 = 0;
359: }
360: else {
361: lVar17 = *(long *)(pcVar2 + 8);
362: if (lVar17 != 0) {
363: *(code **)(pcVar2 + 8) = FUN_0011d6a0;
364: }
365: }
366: pcVar2 = param_1[0x4e];
367: if (pcVar2 == (code *)0x0) {
368: lVar13 = 0;
369: }
370: else {
371: lVar13 = *(long *)(pcVar2 + 8);
372: if (lVar13 != 0) {
373: *(code **)(pcVar2 + 8) = FUN_0011d6b0;
374: }
375: }
376: uVar19 = 0;
377: if (uStack84 != 0) {
378: do {
379: uVar19 = uVar19 + 1;
380: FUN_0011da40(param_1,0,1);
381: } while (uVar19 != uStack84);
382: uVar7 = *(uint *)((long)param_1 + 0x8c);
383: }
384: if (lVar17 != 0) {
385: *(long *)(param_1[0x4d] + 8) = lVar17;
386: }
387: if (lVar13 != 0) {
388: *(long *)(param_1[0x4e] + 8) = lVar13;
389: }
390: }
391: *(uint *)(pcVar4 + 0xbc) = uVar7 - *(int *)(param_1 + 0x15);
392: return param_2;
393: }
394: 

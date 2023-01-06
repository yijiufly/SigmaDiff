1: 
2: void FUN_00116eb0(code **param_1)
3: 
4: {
5: undefined2 uVar1;
6: undefined4 uVar2;
7: uint uVar3;
8: undefined8 *puVar4;
9: code *pcVar5;
10: ulong uVar6;
11: ulong uVar7;
12: long lVar8;
13: code **ppcVar9;
14: undefined8 *puVar10;
15: undefined8 *puVar11;
16: code **ppcVar12;
17: bool bVar13;
18: byte bVar14;
19: 
20: bVar14 = 0;
21: if (*(int *)((long)param_1 + 0x24) != 100) {
22: pcVar5 = *param_1;
23: *(int *)(pcVar5 + 0x2c) = *(int *)((long)param_1 + 0x24);
24: ppcVar12 = (code **)*param_1;
25: *(undefined4 *)(pcVar5 + 0x28) = 0x14;
26: (**ppcVar12)();
27: }
28: if (param_1[0xb] == (code *)0x0) {
29: pcVar5 = (code *)(**(code **)param_1[1])(param_1,0,0x3c0);
30: param_1[0xb] = pcVar5;
31: }
32: *(undefined4 *)(param_1 + 9) = 8;
33: FUN_00116980(param_1,0x4b,1);
34: if (*(int *)(param_1 + 4) == 0) {
35: ppcVar12 = param_1 + 0x10;
36: ppcVar9 = param_1 + 0x14;
37: }
38: else {
39: ppcVar12 = param_1 + 0x1d;
40: ppcVar9 = param_1 + 0x21;
41: }
42: if (*ppcVar12 == (code *)0x0) {
43: puVar4 = (undefined8 *)FUN_00116780(param_1);
44: *ppcVar12 = (code *)puVar4;
45: *puVar4 = 0x101010105010000;
46: puVar4[1] = 0x101;
47: *(undefined *)(puVar4 + 2) = 0;
48: pcVar5 = *ppcVar12;
49: *(undefined8 *)(pcVar5 + 0x11) = 0x706050403020100;
50: *(undefined4 *)(pcVar5 + 0x19) = 0xb0a0908;
51: pcVar5 = *ppcVar12;
52: uVar6 = 0xf4;
53: puVar4 = (undefined8 *)(pcVar5 + 0x1d);
54: bVar13 = ((ulong)puVar4 & 1) != 0;
55: if (bVar13) {
56: pcVar5[0x1d] = (code)0x0;
57: puVar4 = (undefined8 *)(pcVar5 + 0x1e);
58: uVar6 = 0xf3;
59: }
60: puVar10 = puVar4;
61: if (((ulong)puVar4 & 2) != 0) {
62: puVar10 = (undefined8 *)((long)puVar4 + 2);
63: uVar6 = (ulong)((int)uVar6 - 2);
64: *(undefined2 *)puVar4 = 0;
65: }
66: if (((ulong)puVar10 & 4) != 0) {
67: *(undefined4 *)puVar10 = 0;
68: uVar6 = (ulong)((int)uVar6 - 4);
69: puVar10 = (undefined8 *)((long)puVar10 + 4);
70: }
71: uVar7 = uVar6 >> 3;
72: while (uVar7 != 0) {
73: uVar7 = uVar7 - 1;
74: *puVar10 = 0;
75: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
76: }
77: if ((uVar6 & 4) != 0) {
78: *(undefined4 *)puVar10 = 0;
79: puVar10 = (undefined8 *)((long)puVar10 + 4);
80: }
81: puVar4 = puVar10;
82: if ((uVar6 & 2) != 0) {
83: puVar4 = (undefined8 *)((long)puVar10 + 2);
84: *(undefined2 *)puVar10 = 0;
85: }
86: if (bVar13) {
87: *(undefined *)puVar4 = 0;
88: }
89: *(undefined4 *)(*ppcVar12 + 0x114) = 0;
90: }
91: if (*ppcVar9 == (code *)0x0) {
92: puVar4 = (undefined8 *)FUN_00116780(param_1);
93: *ppcVar9 = (code *)puVar4;
94: puVar10 = (undefined8 *)&DAT_00179120;
95: *puVar4 = 0x402030301020000;
96: puVar4[1] = 0x100000404050503;
97: *(undefined *)(puVar4 + 2) = 0x7d;
98: pcVar5 = *ppcVar9;
99: uVar3 = 0xa2;
100: puVar4 = (undefined8 *)(pcVar5 + 0x11);
101: bVar13 = ((ulong)puVar4 & 1) != 0;
102: if (bVar13) {
103: puVar4 = (undefined8 *)(pcVar5 + 0x12);
104: puVar10 = (undefined8 *)&DAT_00179121;
105: pcVar5[0x11] = (code)0x1;
106: uVar3 = 0xa1;
107: }
108: puVar11 = puVar4;
109: if (((ulong)puVar4 & 2) != 0) {
110: uVar1 = *(undefined2 *)puVar10;
111: puVar11 = (undefined8 *)((long)puVar4 + 2);
112: puVar10 = (undefined8 *)((long)puVar10 + 2);
113: uVar3 = uVar3 - 2;
114: *(undefined2 *)puVar4 = uVar1;
115: }
116: puVar4 = puVar11;
117: if (((ulong)puVar11 & 4) != 0) {
118: uVar2 = *(undefined4 *)puVar10;
119: puVar4 = (undefined8 *)((long)puVar11 + 4);
120: puVar10 = (undefined8 *)((long)puVar10 + 4);
121: uVar3 = uVar3 - 4;
122: *(undefined4 *)puVar11 = uVar2;
123: }
124: lVar8 = 0;
125: uVar6 = (ulong)(uVar3 >> 3);
126: while (uVar6 != 0) {
127: uVar6 = uVar6 - 1;
128: *puVar4 = *puVar10;
129: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
130: puVar4 = puVar4 + (ulong)bVar14 * -2 + 1;
131: }
132: if ((uVar3 & 4) != 0) {
133: *(undefined4 *)puVar4 = *(undefined4 *)puVar10;
134: lVar8 = 4;
135: }
136: if ((uVar3 & 2) != 0) {
137: *(undefined2 *)((long)puVar4 + lVar8) = *(undefined2 *)((long)puVar10 + lVar8);
138: lVar8 = lVar8 + 2;
139: }
140: if (bVar13) {
141: *(undefined *)((long)puVar4 + lVar8) = *(undefined *)((long)puVar10 + lVar8);
142: }
143: pcVar5 = *ppcVar9;
144: uVar6 = 0x5e;
145: puVar4 = (undefined8 *)(pcVar5 + 0xb3);
146: bVar13 = ((ulong)puVar4 & 1) != 0;
147: if (bVar13) {
148: pcVar5[0xb3] = (code)0x0;
149: puVar4 = (undefined8 *)(pcVar5 + 0xb4);
150: uVar6 = 0x5d;
151: }
152: puVar10 = puVar4;
153: if (((ulong)puVar4 & 2) != 0) {
154: puVar10 = (undefined8 *)((long)puVar4 + 2);
155: uVar6 = (ulong)((int)uVar6 - 2);
156: *(undefined2 *)puVar4 = 0;
157: }
158: if (((ulong)puVar10 & 4) != 0) {
159: *(undefined4 *)puVar10 = 0;
160: uVar6 = (ulong)((int)uVar6 - 4);
161: puVar10 = (undefined8 *)((long)puVar10 + 4);
162: }
163: uVar7 = uVar6 >> 3;
164: while (uVar7 != 0) {
165: uVar7 = uVar7 - 1;
166: *puVar10 = 0;
167: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
168: }
169: if ((uVar6 & 4) != 0) {
170: *(undefined4 *)puVar10 = 0;
171: puVar10 = (undefined8 *)((long)puVar10 + 4);
172: }
173: puVar4 = puVar10;
174: if ((uVar6 & 2) != 0) {
175: puVar4 = (undefined8 *)((long)puVar10 + 2);
176: *(undefined2 *)puVar10 = 0;
177: }
178: if (bVar13) {
179: *(undefined *)puVar4 = 0;
180: }
181: *(undefined4 *)(*ppcVar9 + 0x114) = 0;
182: }
183: if (ppcVar12[1] == (code *)0x0) {
184: puVar4 = (undefined8 *)FUN_00116780(param_1);
185: ppcVar12[1] = (code *)puVar4;
186: *puVar4 = 0x101010101030000;
187: puVar4[1] = 0x1010101;
188: *(undefined *)(puVar4 + 2) = 0;
189: pcVar5 = ppcVar12[1];
190: *(undefined8 *)(pcVar5 + 0x11) = 0x706050403020100;
191: *(undefined4 *)(pcVar5 + 0x19) = 0xb0a0908;
192: pcVar5 = ppcVar12[1];
193: uVar6 = 0xf4;
194: puVar4 = (undefined8 *)(pcVar5 + 0x1d);
195: bVar13 = ((ulong)puVar4 & 1) != 0;
196: if (bVar13) {
197: pcVar5[0x1d] = (code)0x0;
198: puVar4 = (undefined8 *)(pcVar5 + 0x1e);
199: uVar6 = 0xf3;
200: }
201: puVar10 = puVar4;
202: if (((ulong)puVar4 & 2) != 0) {
203: puVar10 = (undefined8 *)((long)puVar4 + 2);
204: uVar6 = (ulong)((int)uVar6 - 2);
205: *(undefined2 *)puVar4 = 0;
206: }
207: if (((ulong)puVar10 & 4) != 0) {
208: *(undefined4 *)puVar10 = 0;
209: uVar6 = (ulong)((int)uVar6 - 4);
210: puVar10 = (undefined8 *)((long)puVar10 + 4);
211: }
212: uVar7 = uVar6 >> 3;
213: while (uVar7 != 0) {
214: uVar7 = uVar7 - 1;
215: *puVar10 = 0;
216: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
217: }
218: if ((uVar6 & 4) != 0) {
219: *(undefined4 *)puVar10 = 0;
220: puVar10 = (undefined8 *)((long)puVar10 + 4);
221: }
222: puVar4 = puVar10;
223: if ((uVar6 & 2) != 0) {
224: puVar4 = (undefined8 *)((long)puVar10 + 2);
225: *(undefined2 *)puVar10 = 0;
226: }
227: if (bVar13) {
228: *(undefined *)puVar4 = 0;
229: }
230: *(undefined4 *)(ppcVar12[1] + 0x114) = 0;
231: }
232: if (ppcVar9[1] == (code *)0x0) {
233: puVar4 = (undefined8 *)FUN_00116780(param_1);
234: ppcVar9[1] = (code *)puVar4;
235: puVar10 = (undefined8 *)&DAT_00179020;
236: *puVar4 = 0x304040201020000;
237: puVar4[1] = 0x201000404050704;
238: *(undefined *)(puVar4 + 2) = 0x77;
239: pcVar5 = ppcVar9[1];
240: uVar3 = 0xa2;
241: puVar4 = (undefined8 *)(pcVar5 + 0x11);
242: bVar13 = ((ulong)puVar4 & 1) != 0;
243: if (bVar13) {
244: puVar4 = (undefined8 *)(pcVar5 + 0x12);
245: puVar10 = (undefined8 *)&DAT_00179021;
246: pcVar5[0x11] = (code)0x0;
247: uVar3 = 0xa1;
248: }
249: puVar11 = puVar4;
250: if (((ulong)puVar4 & 2) != 0) {
251: uVar1 = *(undefined2 *)puVar10;
252: puVar11 = (undefined8 *)((long)puVar4 + 2);
253: puVar10 = (undefined8 *)((long)puVar10 + 2);
254: uVar3 = uVar3 - 2;
255: *(undefined2 *)puVar4 = uVar1;
256: }
257: puVar4 = puVar11;
258: if (((ulong)puVar11 & 4) != 0) {
259: uVar2 = *(undefined4 *)puVar10;
260: puVar4 = (undefined8 *)((long)puVar11 + 4);
261: puVar10 = (undefined8 *)((long)puVar10 + 4);
262: uVar3 = uVar3 - 4;
263: *(undefined4 *)puVar11 = uVar2;
264: }
265: lVar8 = 0;
266: uVar6 = (ulong)(uVar3 >> 3);
267: while (uVar6 != 0) {
268: uVar6 = uVar6 - 1;
269: *puVar4 = *puVar10;
270: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
271: puVar4 = puVar4 + (ulong)bVar14 * -2 + 1;
272: }
273: if ((uVar3 & 4) != 0) {
274: *(undefined4 *)puVar4 = *(undefined4 *)puVar10;
275: lVar8 = 4;
276: }
277: if ((uVar3 & 2) != 0) {
278: *(undefined2 *)((long)puVar4 + lVar8) = *(undefined2 *)((long)puVar10 + lVar8);
279: lVar8 = lVar8 + 2;
280: }
281: if (bVar13) {
282: *(undefined *)((long)puVar4 + lVar8) = *(undefined *)((long)puVar10 + lVar8);
283: }
284: pcVar5 = ppcVar9[1];
285: uVar6 = 0x5e;
286: puVar4 = (undefined8 *)(pcVar5 + 0xb3);
287: bVar13 = ((ulong)puVar4 & 1) != 0;
288: if (bVar13) {
289: pcVar5[0xb3] = (code)0x0;
290: puVar4 = (undefined8 *)(pcVar5 + 0xb4);
291: uVar6 = 0x5d;
292: }
293: puVar10 = puVar4;
294: if (((ulong)puVar4 & 2) != 0) {
295: puVar10 = (undefined8 *)((long)puVar4 + 2);
296: uVar6 = (ulong)((int)uVar6 - 2);
297: *(undefined2 *)puVar4 = 0;
298: }
299: if (((ulong)puVar10 & 4) != 0) {
300: *(undefined4 *)puVar10 = 0;
301: uVar6 = (ulong)((int)uVar6 - 4);
302: puVar10 = (undefined8 *)((long)puVar10 + 4);
303: }
304: uVar7 = uVar6 >> 3;
305: while (uVar7 != 0) {
306: uVar7 = uVar7 - 1;
307: *puVar10 = 0;
308: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
309: }
310: if ((uVar6 & 4) != 0) {
311: *(undefined4 *)puVar10 = 0;
312: puVar10 = (undefined8 *)((long)puVar10 + 4);
313: }
314: puVar4 = puVar10;
315: if ((uVar6 & 2) != 0) {
316: puVar4 = (undefined8 *)((long)puVar10 + 2);
317: *(undefined2 *)puVar10 = 0;
318: }
319: if (bVar13) {
320: *(undefined *)puVar4 = 0;
321: }
322: *(undefined4 *)(ppcVar9[1] + 0x114) = 0;
323: }
324: param_1[0x18] = (code *)0x0;
325: param_1[0x1a] = (code *)0x101010101010101;
326: param_1[0x1b] = (code *)0x101010101010101;
327: param_1[0x19] = (code *)0x0;
328: param_1[0x1c] = (code *)0x505050505050505;
329: param_1[0x1d] = (code *)0x505050505050505;
330: param_1[0x1f] = (code *)0x0;
331: *(undefined4 *)(param_1 + 0x1e) = 0;
332: *(undefined4 *)(param_1 + 0x20) = 0;
333: *(undefined4 *)((long)param_1 + 0x104) = 0;
334: *(undefined4 *)(param_1 + 0x21) = 0;
335: if (8 < *(int *)(param_1 + 9)) {
336: *(undefined4 *)(param_1 + 0x21) = 1;
337: }
338: *(undefined4 *)((long)param_1 + 0x10c) = 0;
339: *(undefined4 *)(param_1 + 0x22) = 0;
340: *(undefined4 *)((long)param_1 + 0x114) = 0;
341: *(undefined4 *)(param_1 + 0x23) = 0;
342: *(undefined4 *)((long)param_1 + 0x11c) = 0;
343: *(undefined *)((long)param_1 + 0x124) = 1;
344: *(undefined *)((long)param_1 + 0x125) = 1;
345: *(undefined *)((long)param_1 + 0x126) = 0;
346: *(undefined2 *)(param_1 + 0x25) = 1;
347: *(undefined2 *)((long)param_1 + 0x12a) = 1;
348: FUN_00116e30(param_1);
349: return;
350: }
351: 

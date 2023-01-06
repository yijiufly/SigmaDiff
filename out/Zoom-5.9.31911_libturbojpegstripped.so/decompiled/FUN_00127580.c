1: 
2: void FUN_00127580(long param_1)
3: 
4: {
5: undefined2 uVar1;
6: undefined4 uVar2;
7: uint uVar3;
8: code **ppcVar4;
9: undefined8 *puVar5;
10: ulong uVar6;
11: ulong uVar7;
12: long lVar8;
13: long *plVar9;
14: undefined8 *puVar10;
15: undefined8 *puVar11;
16: long *plVar12;
17: bool bVar13;
18: byte bVar14;
19: 
20: bVar14 = 0;
21: if (*(int *)(param_1 + 0x20) == 0) {
22: plVar12 = (long *)(param_1 + 0x80);
23: plVar9 = (long *)(param_1 + 0xa0);
24: }
25: else {
26: plVar12 = (long *)(param_1 + 0xe8);
27: plVar9 = (long *)(param_1 + 0x108);
28: }
29: if (*plVar12 == 0) {
30: puVar5 = (undefined8 *)FUN_00116780(param_1);
31: *plVar12 = (long)puVar5;
32: *puVar5 = 0x101010105010000;
33: puVar5[1] = 0x101;
34: *(undefined *)(puVar5 + 2) = 0;
35: lVar8 = *plVar12;
36: *(undefined8 *)(lVar8 + 0x11) = 0x706050403020100;
37: *(undefined4 *)(lVar8 + 0x19) = 0xb0a0908;
38: lVar8 = *plVar12;
39: uVar6 = 0xf4;
40: puVar5 = (undefined8 *)(lVar8 + 0x1d);
41: bVar13 = ((ulong)puVar5 & 1) != 0;
42: if (bVar13) {
43: *(undefined *)(lVar8 + 0x1d) = 0;
44: puVar5 = (undefined8 *)(lVar8 + 0x1e);
45: uVar6 = 0xf3;
46: }
47: puVar10 = puVar5;
48: if (((ulong)puVar5 & 2) != 0) {
49: puVar10 = (undefined8 *)((long)puVar5 + 2);
50: uVar6 = (ulong)((int)uVar6 - 2);
51: *(undefined2 *)puVar5 = 0;
52: }
53: if (((ulong)puVar10 & 4) != 0) {
54: *(undefined4 *)puVar10 = 0;
55: uVar6 = (ulong)((int)uVar6 - 4);
56: puVar10 = (undefined8 *)((long)puVar10 + 4);
57: }
58: uVar7 = uVar6 >> 3;
59: while (uVar7 != 0) {
60: uVar7 = uVar7 - 1;
61: *puVar10 = 0;
62: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
63: }
64: if ((uVar6 & 4) != 0) {
65: *(undefined4 *)puVar10 = 0;
66: puVar10 = (undefined8 *)((long)puVar10 + 4);
67: }
68: puVar5 = puVar10;
69: if ((uVar6 & 2) != 0) {
70: puVar5 = (undefined8 *)((long)puVar10 + 2);
71: *(undefined2 *)puVar10 = 0;
72: }
73: if (bVar13) {
74: *(undefined *)puVar5 = 0;
75: }
76: *(undefined4 *)(*plVar12 + 0x114) = 0;
77: }
78: if (*plVar9 == 0) {
79: puVar5 = (undefined8 *)FUN_00116780(param_1);
80: *plVar9 = (long)puVar5;
81: puVar10 = (undefined8 *)&DAT_00189aa0;
82: *puVar5 = 0x402030301020000;
83: puVar5[1] = 0x100000404050503;
84: *(undefined *)(puVar5 + 2) = 0x7d;
85: lVar8 = *plVar9;
86: uVar3 = 0xa2;
87: puVar5 = (undefined8 *)(lVar8 + 0x11);
88: bVar13 = ((ulong)puVar5 & 1) != 0;
89: if (bVar13) {
90: puVar5 = (undefined8 *)(lVar8 + 0x12);
91: puVar10 = (undefined8 *)&DAT_00189aa1;
92: *(undefined *)(lVar8 + 0x11) = 1;
93: uVar3 = 0xa1;
94: }
95: puVar11 = puVar5;
96: if (((ulong)puVar5 & 2) != 0) {
97: uVar1 = *(undefined2 *)puVar10;
98: puVar11 = (undefined8 *)((long)puVar5 + 2);
99: puVar10 = (undefined8 *)((long)puVar10 + 2);
100: uVar3 = uVar3 - 2;
101: *(undefined2 *)puVar5 = uVar1;
102: }
103: puVar5 = puVar11;
104: if (((ulong)puVar11 & 4) != 0) {
105: uVar2 = *(undefined4 *)puVar10;
106: puVar5 = (undefined8 *)((long)puVar11 + 4);
107: puVar10 = (undefined8 *)((long)puVar10 + 4);
108: uVar3 = uVar3 - 4;
109: *(undefined4 *)puVar11 = uVar2;
110: }
111: lVar8 = 0;
112: uVar6 = (ulong)(uVar3 >> 3);
113: while (uVar6 != 0) {
114: uVar6 = uVar6 - 1;
115: *puVar5 = *puVar10;
116: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
117: puVar5 = puVar5 + (ulong)bVar14 * -2 + 1;
118: }
119: if ((uVar3 & 4) != 0) {
120: *(undefined4 *)puVar5 = *(undefined4 *)puVar10;
121: lVar8 = 4;
122: }
123: if ((uVar3 & 2) != 0) {
124: *(undefined2 *)((long)puVar5 + lVar8) = *(undefined2 *)((long)puVar10 + lVar8);
125: lVar8 = lVar8 + 2;
126: }
127: if (bVar13) {
128: *(undefined *)((long)puVar5 + lVar8) = *(undefined *)((long)puVar10 + lVar8);
129: }
130: lVar8 = *plVar9;
131: uVar6 = 0x5e;
132: puVar5 = (undefined8 *)(lVar8 + 0xb3);
133: bVar13 = ((ulong)puVar5 & 1) != 0;
134: if (bVar13) {
135: *(undefined *)(lVar8 + 0xb3) = 0;
136: puVar5 = (undefined8 *)(lVar8 + 0xb4);
137: uVar6 = 0x5d;
138: }
139: puVar10 = puVar5;
140: if (((ulong)puVar5 & 2) != 0) {
141: puVar10 = (undefined8 *)((long)puVar5 + 2);
142: uVar6 = (ulong)((int)uVar6 - 2);
143: *(undefined2 *)puVar5 = 0;
144: }
145: if (((ulong)puVar10 & 4) != 0) {
146: *(undefined4 *)puVar10 = 0;
147: uVar6 = (ulong)((int)uVar6 - 4);
148: puVar10 = (undefined8 *)((long)puVar10 + 4);
149: }
150: uVar7 = uVar6 >> 3;
151: while (uVar7 != 0) {
152: uVar7 = uVar7 - 1;
153: *puVar10 = 0;
154: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
155: }
156: if ((uVar6 & 4) != 0) {
157: *(undefined4 *)puVar10 = 0;
158: puVar10 = (undefined8 *)((long)puVar10 + 4);
159: }
160: puVar5 = puVar10;
161: if ((uVar6 & 2) != 0) {
162: puVar5 = (undefined8 *)((long)puVar10 + 2);
163: *(undefined2 *)puVar10 = 0;
164: }
165: if (bVar13) {
166: *(undefined *)puVar5 = 0;
167: }
168: *(undefined4 *)(*plVar9 + 0x114) = 0;
169: }
170: if (plVar12[1] == 0) {
171: puVar5 = (undefined8 *)FUN_00116780(param_1);
172: plVar12[1] = (long)puVar5;
173: *puVar5 = 0x101010101030000;
174: puVar5[1] = 0x1010101;
175: *(undefined *)(puVar5 + 2) = 0;
176: lVar8 = plVar12[1];
177: *(undefined8 *)(lVar8 + 0x11) = 0x706050403020100;
178: *(undefined4 *)(lVar8 + 0x19) = 0xb0a0908;
179: lVar8 = plVar12[1];
180: uVar6 = 0xf4;
181: puVar5 = (undefined8 *)(lVar8 + 0x1d);
182: bVar13 = ((ulong)puVar5 & 1) != 0;
183: if (bVar13) {
184: *(undefined *)(lVar8 + 0x1d) = 0;
185: puVar5 = (undefined8 *)(lVar8 + 0x1e);
186: uVar6 = 0xf3;
187: }
188: puVar10 = puVar5;
189: if (((ulong)puVar5 & 2) != 0) {
190: puVar10 = (undefined8 *)((long)puVar5 + 2);
191: uVar6 = (ulong)((int)uVar6 - 2);
192: *(undefined2 *)puVar5 = 0;
193: }
194: if (((ulong)puVar10 & 4) != 0) {
195: *(undefined4 *)puVar10 = 0;
196: uVar6 = (ulong)((int)uVar6 - 4);
197: puVar10 = (undefined8 *)((long)puVar10 + 4);
198: }
199: uVar7 = uVar6 >> 3;
200: while (uVar7 != 0) {
201: uVar7 = uVar7 - 1;
202: *puVar10 = 0;
203: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
204: }
205: if ((uVar6 & 4) != 0) {
206: *(undefined4 *)puVar10 = 0;
207: puVar10 = (undefined8 *)((long)puVar10 + 4);
208: }
209: puVar5 = puVar10;
210: if ((uVar6 & 2) != 0) {
211: puVar5 = (undefined8 *)((long)puVar10 + 2);
212: *(undefined2 *)puVar10 = 0;
213: }
214: if (bVar13) {
215: *(undefined *)puVar5 = 0;
216: }
217: *(undefined4 *)(plVar12[1] + 0x114) = 0;
218: }
219: if (plVar9[1] == 0) {
220: puVar5 = (undefined8 *)FUN_00116780(param_1);
221: plVar9[1] = (long)puVar5;
222: puVar10 = (undefined8 *)&DAT_001899a0;
223: *puVar5 = 0x304040201020000;
224: puVar5[1] = 0x201000404050704;
225: *(undefined *)(puVar5 + 2) = 0x77;
226: lVar8 = plVar9[1];
227: uVar3 = 0xa2;
228: puVar5 = (undefined8 *)(lVar8 + 0x11);
229: bVar13 = ((ulong)puVar5 & 1) != 0;
230: if (bVar13) {
231: puVar5 = (undefined8 *)(lVar8 + 0x12);
232: puVar10 = (undefined8 *)&DAT_001899a1;
233: *(undefined *)(lVar8 + 0x11) = 0;
234: uVar3 = 0xa1;
235: }
236: puVar11 = puVar5;
237: if (((ulong)puVar5 & 2) != 0) {
238: uVar1 = *(undefined2 *)puVar10;
239: puVar11 = (undefined8 *)((long)puVar5 + 2);
240: puVar10 = (undefined8 *)((long)puVar10 + 2);
241: uVar3 = uVar3 - 2;
242: *(undefined2 *)puVar5 = uVar1;
243: }
244: puVar5 = puVar11;
245: if (((ulong)puVar11 & 4) != 0) {
246: uVar2 = *(undefined4 *)puVar10;
247: puVar5 = (undefined8 *)((long)puVar11 + 4);
248: puVar10 = (undefined8 *)((long)puVar10 + 4);
249: uVar3 = uVar3 - 4;
250: *(undefined4 *)puVar11 = uVar2;
251: }
252: lVar8 = 0;
253: uVar6 = (ulong)(uVar3 >> 3);
254: while (uVar6 != 0) {
255: uVar6 = uVar6 - 1;
256: *puVar5 = *puVar10;
257: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
258: puVar5 = puVar5 + (ulong)bVar14 * -2 + 1;
259: }
260: if ((uVar3 & 4) != 0) {
261: *(undefined4 *)puVar5 = *(undefined4 *)puVar10;
262: lVar8 = 4;
263: }
264: if ((uVar3 & 2) != 0) {
265: *(undefined2 *)((long)puVar5 + lVar8) = *(undefined2 *)((long)puVar10 + lVar8);
266: lVar8 = lVar8 + 2;
267: }
268: if (bVar13) {
269: *(undefined *)((long)puVar5 + lVar8) = *(undefined *)((long)puVar10 + lVar8);
270: }
271: lVar8 = plVar9[1];
272: uVar6 = 0x5e;
273: puVar5 = (undefined8 *)(lVar8 + 0xb3);
274: bVar13 = ((ulong)puVar5 & 1) != 0;
275: if (bVar13) {
276: *(undefined *)(lVar8 + 0xb3) = 0;
277: puVar5 = (undefined8 *)(lVar8 + 0xb4);
278: uVar6 = 0x5d;
279: }
280: puVar10 = puVar5;
281: if (((ulong)puVar5 & 2) != 0) {
282: puVar10 = (undefined8 *)((long)puVar5 + 2);
283: uVar6 = (ulong)((int)uVar6 - 2);
284: *(undefined2 *)puVar5 = 0;
285: }
286: if (((ulong)puVar10 & 4) != 0) {
287: *(undefined4 *)puVar10 = 0;
288: uVar6 = (ulong)((int)uVar6 - 4);
289: puVar10 = (undefined8 *)((long)puVar10 + 4);
290: }
291: uVar7 = uVar6 >> 3;
292: while (uVar7 != 0) {
293: uVar7 = uVar7 - 1;
294: *puVar10 = 0;
295: puVar10 = puVar10 + (ulong)bVar14 * -2 + 1;
296: }
297: if ((uVar6 & 4) != 0) {
298: *(undefined4 *)puVar10 = 0;
299: puVar10 = (undefined8 *)((long)puVar10 + 4);
300: }
301: puVar5 = puVar10;
302: if ((uVar6 & 2) != 0) {
303: puVar5 = (undefined8 *)((long)puVar10 + 2);
304: *(undefined2 *)puVar10 = 0;
305: }
306: if (bVar13) {
307: *(undefined *)puVar5 = 0;
308: }
309: *(undefined4 *)(plVar9[1] + 0x114) = 0;
310: }
311: ppcVar4 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x170);
312: *(code ***)(param_1 + 0x250) = ppcVar4;
313: ppcVar4[0xc] = (code *)0x0;
314: ppcVar4[0xd] = (code *)0x0;
315: *ppcVar4 = FUN_00125bc0;
316: ppcVar4[1] = FUN_00125fb0;
317: ppcVar4[0xe] = (code *)0x0;
318: ppcVar4[0xf] = (code *)0x0;
319: ppcVar4[8] = (code *)0x0;
320: ppcVar4[9] = (code *)0x0;
321: ppcVar4[10] = (code *)0x0;
322: ppcVar4[0xb] = (code *)0x0;
323: return;
324: }
325: 

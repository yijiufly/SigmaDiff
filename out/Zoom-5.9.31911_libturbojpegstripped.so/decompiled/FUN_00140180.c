1: 
2: void FUN_00140180(code **param_1)
3: 
4: {
5: int iVar1;
6: undefined4 uVar2;
7: code *pcVar3;
8: bool bVar4;
9: bool bVar5;
10: code *pcVar6;
11: ulong uVar7;
12: int iVar8;
13: uint uVar9;
14: ulong uVar10;
15: int *piVar11;
16: long lVar12;
17: undefined8 *puVar13;
18: undefined8 *puVar14;
19: int iVar15;
20: code *pcVar16;
21: byte bVar17;
22: code **ppcStack72;
23: int iStack60;
24: 
25: bVar17 = 0;
26: pcVar3 = param_1[0x4a];
27: if (*(int *)(param_1 + 0x27) == 0) {
28: if ((((*(int *)((long)param_1 + 0x20c) != 0) || (*(int *)((long)param_1 + 0x214) != 0)) ||
29: (*(int *)(param_1 + 0x43) != 0)) || (*(int *)(param_1 + 0x42) < 0x3f)) {
30: pcVar6 = *param_1;
31: *(undefined4 *)(pcVar6 + 0x28) = 0x7a;
32: (**(code **)(pcVar6 + 8))(param_1);
33: }
34: *(code **)(pcVar3 + 8) = FUN_00140bd0;
35: }
36: else {
37: iVar15 = *(int *)((long)param_1 + 0x20c);
38: if (iVar15 == 0) {
39: if (*(int *)(param_1 + 0x42) != 0) goto LAB_001401c2;
40: LAB_00140524:
41: if (((*(int *)((long)param_1 + 0x214) != 0) &&
42: (*(int *)((long)param_1 + 0x214) + -1 != *(int *)(param_1 + 0x43))) ||
43: (0xd < *(int *)(param_1 + 0x43))) goto LAB_001401c2;
44: }
45: else {
46: if (((iVar15 <= *(int *)(param_1 + 0x42)) && (*(int *)(param_1 + 0x42) < 0x40)) &&
47: (*(int *)(param_1 + 0x36) == 1)) goto LAB_00140524;
48: LAB_001401c2:
49: pcVar6 = *param_1;
50: *(int *)(pcVar6 + 0x2c) = iVar15;
51: *(undefined4 *)(pcVar6 + 0x28) = 0x10;
52: *(undefined4 *)(*param_1 + 0x30) = *(undefined4 *)(param_1 + 0x42);
53: *(undefined4 *)(*param_1 + 0x34) = *(undefined4 *)((long)param_1 + 0x214);
54: *(undefined4 *)(*param_1 + 0x38) = *(undefined4 *)(param_1 + 0x43);
55: (**(code **)*param_1)(param_1);
56: iVar15 = *(int *)((long)param_1 + 0x20c);
57: }
58: if (0 < *(int *)(param_1 + 0x36)) {
59: iStack60 = 0;
60: ppcStack72 = param_1;
61: do {
62: iVar1 = *(int *)(ppcStack72[0x37] + 4);
63: pcVar6 = param_1[0x18];
64: iVar8 = 0;
65: if ((iVar15 != 0) && (iVar8 = iVar15, *(int *)(pcVar6 + (long)iVar1 * 0x100) < 0)) {
66: pcVar16 = *param_1;
67: *(int *)(pcVar16 + 0x2c) = iVar1;
68: *(undefined4 *)(pcVar16 + 0x28) = 0x73;
69: *(undefined4 *)(*param_1 + 0x30) = 0;
70: (**(code **)(*param_1 + 8))(param_1);
71: iVar8 = *(int *)((long)param_1 + 0x20c);
72: }
73: iVar15 = iVar8;
74: if (iVar15 <= *(int *)(param_1 + 0x42)) {
75: piVar11 = (int *)((long)(pcVar6 + (long)iVar1 * 0x100) + (long)iVar15 * 4);
76: do {
77: iVar8 = 0;
78: if (-1 < *piVar11) {
79: iVar8 = *piVar11;
80: }
81: if (*(int *)((long)param_1 + 0x214) != iVar8) {
82: pcVar6 = *param_1;
83: *(int *)(pcVar6 + 0x2c) = iVar1;
84: *(undefined4 *)(pcVar6 + 0x28) = 0x73;
85: *(int *)(*param_1 + 0x30) = iVar15;
86: (**(code **)(*param_1 + 8))(param_1);
87: }
88: iVar15 = iVar15 + 1;
89: *piVar11 = *(int *)(param_1 + 0x43);
90: piVar11 = piVar11 + 1;
91: } while (iVar15 <= *(int *)(param_1 + 0x42));
92: iVar15 = *(int *)((long)param_1 + 0x20c);
93: }
94: iStack60 = iStack60 + 1;
95: ppcStack72 = ppcStack72 + 1;
96: } while (*(int *)(param_1 + 0x36) != iStack60 && iStack60 <= *(int *)(param_1 + 0x36));
97: }
98: if (*(int *)((long)param_1 + 0x214) == 0) {
99: pcVar6 = FUN_00141540;
100: if (iVar15 != 0) {
101: pcVar6 = FUN_00141300;
102: }
103: *(code **)(pcVar3 + 8) = pcVar6;
104: iVar15 = *(int *)(param_1 + 0x36);
105: goto joined_r0x00140396;
106: }
107: pcVar6 = FUN_00141240;
108: if (iVar15 != 0) {
109: pcVar6 = FUN_00140fc0;
110: }
111: *(code **)(pcVar3 + 8) = pcVar6;
112: }
113: iVar15 = *(int *)(param_1 + 0x36);
114: joined_r0x00140396:
115: lVar12 = 0;
116: if (0 < iVar15) {
117: do {
118: pcVar6 = param_1[lVar12 + 0x37];
119: if (*(int *)(param_1 + 0x27) == 0) {
120: LAB_001403d4:
121: uVar9 = *(uint *)(pcVar6 + 0x14);
122: if (uVar9 < 0x10) {
123: pcVar16 = pcVar3 + (long)(int)uVar9 * 8;
124: puVar14 = *(undefined8 **)(pcVar16 + 0x50);
125: if (puVar14 == (undefined8 *)0x0) goto LAB_0014061f;
126: LAB_001403f3:
127: puVar13 = puVar14;
128: if (((ulong)puVar14 & 1) != 0) goto LAB_00140650;
129: LAB_00140403:
130: uVar10 = 0x40;
131: bVar4 = false;
132: iVar15 = 0x40;
133: bVar5 = false;
134: if (((ulong)puVar13 & 2) != 0) goto LAB_00140668;
135: LAB_0014040d:
136: uVar9 = (uint)uVar10;
137: }
138: else {
139: pcVar16 = *param_1;
140: *(uint *)(pcVar16 + 0x2c) = uVar9;
141: *(undefined4 *)(pcVar16 + 0x28) = 0x7d;
142: pcVar16 = pcVar3 + (long)(int)uVar9 * 8;
143: (**(code **)*param_1)(param_1);
144: puVar14 = *(undefined8 **)(pcVar16 + 0x50);
145: if (puVar14 != (undefined8 *)0x0) goto LAB_001403f3;
146: LAB_0014061f:
147: puVar14 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x40);
148: *(undefined8 **)(pcVar16 + 0x50) = puVar14;
149: puVar13 = puVar14;
150: if (((ulong)puVar14 & 1) == 0) goto LAB_00140403;
151: LAB_00140650:
152: puVar13 = (undefined8 *)((long)puVar14 + 1);
153: *(undefined *)puVar14 = 0;
154: uVar10 = 0x3f;
155: bVar4 = true;
156: iVar15 = 0x3f;
157: bVar5 = true;
158: if (((ulong)puVar13 & 2) == 0) goto LAB_0014040d;
159: LAB_00140668:
160: bVar4 = bVar5;
161: uVar9 = iVar15 - 2;
162: uVar10 = (ulong)uVar9;
163: *(undefined2 *)puVar13 = 0;
164: puVar13 = (undefined8 *)((long)puVar13 + 2);
165: }
166: if (((ulong)puVar13 & 4) != 0) {
167: *(undefined4 *)puVar13 = 0;
168: uVar10 = (ulong)(uVar9 - 4);
169: puVar13 = (undefined8 *)((long)puVar13 + 4);
170: }
171: uVar7 = uVar10 >> 3;
172: while (uVar7 != 0) {
173: uVar7 = uVar7 - 1;
174: *puVar13 = 0;
175: puVar13 = puVar13 + (ulong)bVar17 * -2 + 1;
176: }
177: if ((uVar10 & 4) != 0) {
178: *(undefined4 *)puVar13 = 0;
179: puVar13 = (undefined8 *)((long)puVar13 + 4);
180: }
181: puVar14 = puVar13;
182: if ((uVar10 & 2) != 0) {
183: puVar14 = (undefined8 *)((long)puVar13 + 2);
184: *(undefined2 *)puVar13 = 0;
185: }
186: if (bVar4) {
187: *(undefined *)puVar14 = 0;
188: }
189: *(undefined4 *)(pcVar3 + lVar12 * 4 + 0x2c) = 0;
190: *(undefined4 *)(pcVar3 + lVar12 * 4 + 0x3c) = 0;
191: if ((*(int *)(param_1 + 0x27) == 0) || (*(int *)((long)param_1 + 0x20c) != 0)) {
192: LAB_0014046a:
193: uVar9 = *(uint *)(pcVar6 + 0x18);
194: if (uVar9 < 0x10) {
195: pcVar6 = pcVar3 + (long)(int)uVar9 * 8;
196: puVar14 = *(undefined8 **)(pcVar6 + 0xd0);
197: if (puVar14 == (undefined8 *)0x0) goto LAB_0014057a;
198: LAB_0014048c:
199: puVar13 = puVar14;
200: if (((ulong)puVar14 & 1) != 0) goto LAB_001405a8;
201: LAB_0014049c:
202: uVar10 = 0x100;
203: bVar5 = false;
204: iVar15 = 0x100;
205: bVar4 = false;
206: if (((ulong)puVar13 & 2) != 0) goto LAB_001405c0;
207: LAB_001404a6:
208: uVar9 = (uint)uVar10;
209: puVar14 = puVar13;
210: bVar4 = bVar5;
211: }
212: else {
213: pcVar6 = *param_1;
214: *(uint *)(pcVar6 + 0x2c) = uVar9;
215: *(undefined4 *)(pcVar6 + 0x28) = 0x7d;
216: pcVar6 = pcVar3 + (long)(int)uVar9 * 8;
217: (**(code **)*param_1)(param_1);
218: puVar14 = *(undefined8 **)(pcVar6 + 0xd0);
219: if (puVar14 != (undefined8 *)0x0) goto LAB_0014048c;
220: LAB_0014057a:
221: puVar14 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x100);
222: *(undefined8 **)(pcVar6 + 0xd0) = puVar14;
223: puVar13 = puVar14;
224: if (((ulong)puVar14 & 1) == 0) goto LAB_0014049c;
225: LAB_001405a8:
226: puVar13 = (undefined8 *)((long)puVar14 + 1);
227: *(undefined *)puVar14 = 0;
228: uVar10 = 0xff;
229: bVar5 = true;
230: iVar15 = 0xff;
231: bVar4 = true;
232: if (((ulong)puVar13 & 2) == 0) goto LAB_001404a6;
233: LAB_001405c0:
234: puVar14 = (undefined8 *)((long)puVar13 + 2);
235: uVar9 = iVar15 - 2;
236: uVar10 = (ulong)uVar9;
237: *(undefined2 *)puVar13 = 0;
238: }
239: if (((ulong)puVar14 & 4) != 0) {
240: *(undefined4 *)puVar14 = 0;
241: uVar10 = (ulong)(uVar9 - 4);
242: puVar14 = (undefined8 *)((long)puVar14 + 4);
243: }
244: uVar7 = uVar10 >> 3;
245: while (uVar7 != 0) {
246: uVar7 = uVar7 - 1;
247: *puVar14 = 0;
248: puVar14 = puVar14 + (ulong)bVar17 * -2 + 1;
249: }
250: if ((uVar10 & 4) != 0) {
251: *(undefined4 *)puVar14 = 0;
252: puVar14 = (undefined8 *)((long)puVar14 + 4);
253: }
254: puVar13 = puVar14;
255: if ((uVar10 & 2) != 0) {
256: puVar13 = (undefined8 *)((long)puVar14 + 2);
257: *(undefined2 *)puVar14 = 0;
258: }
259: if (bVar4) {
260: *(undefined *)puVar13 = 0;
261: }
262: }
263: }
264: else {
265: if (*(int *)((long)param_1 + 0x20c) != 0) goto LAB_0014046a;
266: if (*(int *)((long)param_1 + 0x214) == 0) goto LAB_001403d4;
267: }
268: iVar15 = (int)lVar12;
269: lVar12 = lVar12 + 1;
270: } while (iVar15 + 1 < *(int *)(param_1 + 0x36));
271: }
272: uVar2 = *(undefined4 *)(param_1 + 0x2e);
273: *(undefined8 *)(pcVar3 + 0x18) = 0;
274: *(undefined8 *)(pcVar3 + 0x20) = 0;
275: *(undefined4 *)(pcVar3 + 0x28) = 0xfffffff0;
276: *(undefined4 *)(pcVar3 + 0x4c) = uVar2;
277: return;
278: }
279: 

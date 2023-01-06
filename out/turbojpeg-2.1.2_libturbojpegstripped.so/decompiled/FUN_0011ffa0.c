1: 
2: void FUN_0011ffa0(code **param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: int iVar3;
8: int iVar4;
9: undefined8 *puVar5;
10: ulong uVar6;
11: long lVar7;
12: undefined8 *puVar8;
13: undefined8 *puVar9;
14: undefined8 *puVar10;
15: 
16: iVar4 = *(int *)((long)param_1 + 0x24);
17: iVar1 = *(int *)((long)param_1 + 0x4c);
18: if (iVar4 != 100) {
19: ppcVar2 = (code **)*param_1;
20: *(undefined4 *)(ppcVar2 + 5) = 0x14;
21: *(int *)((long)ppcVar2 + 0x2c) = iVar4;
22: (**ppcVar2)();
23: }
24: if (iVar1 == 3) {
25: iVar4 = 10;
26: if (*(int *)(param_1 + 10) != 3) goto LAB_001201d8;
27: LAB_0011ffda:
28: puVar5 = (undefined8 *)param_1[0x3f];
29: if (puVar5 == (undefined8 *)0x0) goto LAB_0011ffea;
30: LAB_001201f0:
31: if (*(int *)(param_1 + 0x40) < iVar4) goto LAB_0011ffea;
32: }
33: else {
34: if (4 < iVar1) {
35: iVar4 = iVar1 * 6;
36: goto LAB_0011ffda;
37: }
38: LAB_001201d8:
39: puVar5 = (undefined8 *)param_1[0x3f];
40: iVar4 = iVar1 * 4 + 2;
41: if (puVar5 != (undefined8 *)0x0) goto LAB_001201f0;
42: LAB_0011ffea:
43: iVar3 = 10;
44: if (9 < iVar4) {
45: iVar3 = iVar4;
46: }
47: *(int *)(param_1 + 0x40) = iVar3;
48: puVar5 = (undefined8 *)(**(code **)param_1[1])(param_1,0,(long)iVar3 * 0x24);
49: param_1[0x3f] = (code *)puVar5;
50: }
51: param_1[0x1f] = (code *)puVar5;
52: *(int *)(param_1 + 0x1e) = iVar4;
53: if (iVar1 == 3) {
54: if (*(int *)(param_1 + 10) == 3) {
55: *(undefined4 *)((long)puVar5 + 0x24) = 1;
56: *(undefined4 *)(puVar5 + 5) = 0;
57: *(undefined4 *)((long)puVar5 + 0x14) = 0;
58: *(undefined4 *)(puVar5 + 3) = 0;
59: *(undefined4 *)((long)puVar5 + 0x1c) = 0;
60: *(undefined4 *)(puVar5 + 4) = 1;
61: *(undefined4 *)(puVar5 + 9) = 1;
62: *(undefined4 *)((long)puVar5 + 0x4c) = 2;
63: *(undefined4 *)((long)puVar5 + 0x6c) = 1;
64: *(undefined4 *)(puVar5 + 0xe) = 1;
65: *(undefined4 *)(puVar5 + 0x12) = 1;
66: *(undefined4 *)((long)puVar5 + 0x94) = 0;
67: *(undefined4 *)(puVar5 + 7) = 1;
68: *(undefined4 *)((long)puVar5 + 0x3c) = 5;
69: *(undefined4 *)(puVar5 + 8) = 0;
70: *(undefined4 *)((long)puVar5 + 0x44) = 2;
71: *(undefined4 *)((long)puVar5 + 0xb4) = 1;
72: *(undefined4 *)(puVar5 + 0x17) = 0;
73: *(undefined4 *)puVar5 = 3;
74: *(undefined4 *)((long)puVar5 + 4) = 0;
75: *(undefined4 *)(puVar5 + 1) = 1;
76: *(undefined4 *)((long)puVar5 + 0xc) = 2;
77: *(undefined4 *)(puVar5 + 0x1b) = 3;
78: *(undefined4 *)((long)puVar5 + 0xdc) = 0;
79: *(undefined4 *)(puVar5 + 0x1c) = 1;
80: *(undefined4 *)((long)puVar5 + 0xe4) = 2;
81: *(undefined4 *)((long)puVar5 + 0xfc) = 1;
82: *(undefined4 *)(puVar5 + 0x20) = 2;
83: *(undefined4 *)(puVar5 + 0x24) = 1;
84: *(undefined4 *)((long)puVar5 + 0x124) = 1;
85: *(undefined4 *)((long)puVar5 + 0x5c) = 1;
86: *(undefined4 *)(puVar5 + 0xc) = 0x3f;
87: *(undefined4 *)((long)puVar5 + 100) = 0;
88: *(undefined4 *)(puVar5 + 0xd) = 1;
89: *(undefined4 *)(puVar5 + 0x10) = 1;
90: *(undefined4 *)((long)puVar5 + 0x84) = 0x3f;
91: *(undefined4 *)(puVar5 + 0x11) = 0;
92: *(undefined4 *)((long)puVar5 + 0x8c) = 1;
93: *(undefined4 *)((long)puVar5 + 0xec) = 0;
94: *(undefined4 *)(puVar5 + 0x1e) = 0;
95: *(undefined4 *)((long)puVar5 + 0xf4) = 1;
96: *(undefined4 *)(puVar5 + 0x1f) = 0;
97: *(undefined4 *)((long)puVar5 + 0xa4) = 6;
98: *(undefined4 *)(puVar5 + 0x15) = 0x3f;
99: *(undefined4 *)((long)puVar5 + 0xac) = 0;
100: *(undefined4 *)(puVar5 + 0x16) = 2;
101: *(undefined4 *)(puVar5 + 0x22) = 1;
102: *(undefined4 *)((long)puVar5 + 0x114) = 0x3f;
103: *(undefined4 *)(puVar5 + 0x23) = 1;
104: *(undefined4 *)((long)puVar5 + 0x11c) = 0;
105: *(undefined4 *)(puVar5 + 0x19) = 1;
106: *(undefined4 *)((long)puVar5 + 0xcc) = 0x3f;
107: *(undefined4 *)(puVar5 + 0x1a) = 2;
108: *(undefined4 *)((long)puVar5 + 0xd4) = 1;
109: *(undefined4 *)((long)puVar5 + 0x134) = 1;
110: *(undefined4 *)(puVar5 + 0x27) = 0x3f;
111: *(undefined4 *)((long)puVar5 + 0x13c) = 1;
112: *(undefined4 *)(puVar5 + 0x28) = 0;
113: *(undefined4 *)(puVar5 + 0x2b) = 1;
114: *(undefined4 *)((long)puVar5 + 0x15c) = 0x3f;
115: *(undefined4 *)(puVar5 + 0x2c) = 1;
116: *(undefined4 *)((long)puVar5 + 0x164) = 0;
117: *(undefined4 *)((long)puVar5 + 0x144) = 1;
118: *(undefined4 *)(puVar5 + 0x29) = 0;
119: return;
120: }
121: *puVar5 = 3;
122: *(undefined4 *)(puVar5 + 1) = 1;
123: LAB_00120048:
124: *(undefined4 *)((long)puVar5 + 0xc) = 2;
125: if (iVar1 != 3) {
126: *(undefined4 *)(puVar5 + 2) = 3;
127: }
128: LAB_0012005b:
129: puVar10 = (undefined8 *)((long)puVar5 + 0x24);
130: uVar6 = (ulong)(iVar1 - 1);
131: *(undefined4 *)((long)puVar5 + 0x14) = 0;
132: *(undefined4 *)(puVar5 + 3) = 0;
133: *(undefined4 *)((long)puVar5 + 0x1c) = 0;
134: *(undefined4 *)(puVar5 + 4) = 1;
135: if (0 < iVar1) goto LAB_00120076;
136: *(int *)((long)puVar5 + 0x24) = iVar1;
137: }
138: else {
139: if (iVar1 < 5) {
140: *(int *)puVar5 = iVar1;
141: if (((0 < iVar1) && (*(undefined4 *)((long)puVar5 + 4) = 0, iVar1 != 1)) &&
142: (*(undefined4 *)(puVar5 + 1) = 1, 2 < iVar1)) goto LAB_00120048;
143: goto LAB_0012005b;
144: }
145: uVar6 = (ulong)(iVar1 - 1);
146: iVar4 = 0;
147: puVar8 = puVar5;
148: do {
149: *(int *)((long)puVar8 + 4) = iVar4;
150: *(undefined4 *)puVar8 = 1;
151: puVar10 = (undefined8 *)((long)puVar8 + 0x24);
152: *(undefined4 *)((long)puVar8 + 0x14) = 0;
153: *(undefined4 *)(puVar8 + 3) = 0;
154: iVar4 = iVar4 + 1;
155: *(undefined4 *)((long)puVar8 + 0x1c) = 0;
156: *(undefined4 *)(puVar8 + 4) = 1;
157: puVar8 = puVar10;
158: } while (puVar10 != (undefined8 *)((long)puVar5 + (uVar6 * 9 + 9) * 4));
159: LAB_00120076:
160: iVar4 = 0;
161: lVar7 = (uVar6 * 9 + 9) * 4;
162: puVar5 = puVar10;
163: do {
164: *(int *)((long)puVar5 + 4) = iVar4;
165: *(undefined4 *)puVar5 = 1;
166: puVar8 = (undefined8 *)((long)puVar5 + 0x24);
167: *(undefined4 *)((long)puVar5 + 0x14) = 1;
168: *(undefined4 *)(puVar5 + 3) = 5;
169: iVar4 = iVar4 + 1;
170: *(undefined4 *)((long)puVar5 + 0x1c) = 0;
171: *(undefined4 *)(puVar5 + 4) = 2;
172: puVar5 = puVar8;
173: } while (puVar8 != (undefined8 *)((long)puVar10 + lVar7));
174: iVar4 = 0;
175: do {
176: *(int *)((long)puVar5 + 4) = iVar4;
177: *(undefined4 *)puVar5 = 1;
178: puVar9 = (undefined8 *)((long)puVar5 + 0x24);
179: *(undefined4 *)((long)puVar5 + 0x14) = 6;
180: *(undefined4 *)(puVar5 + 3) = 0x3f;
181: iVar4 = iVar4 + 1;
182: *(undefined4 *)((long)puVar5 + 0x1c) = 0;
183: *(undefined4 *)(puVar5 + 4) = 2;
184: puVar5 = puVar9;
185: } while (puVar9 != (undefined8 *)((long)puVar8 + lVar7));
186: iVar4 = 0;
187: puVar10 = puVar9;
188: do {
189: puVar5 = puVar10;
190: *(int *)((long)puVar5 + 4) = iVar4;
191: *(undefined4 *)puVar5 = 1;
192: puVar10 = (undefined8 *)((long)puVar5 + 0x24);
193: *(undefined4 *)((long)puVar5 + 0x14) = 1;
194: *(undefined4 *)(puVar5 + 3) = 0x3f;
195: iVar4 = iVar4 + 1;
196: *(undefined4 *)((long)puVar5 + 0x1c) = 2;
197: *(undefined4 *)(puVar5 + 4) = 1;
198: } while (puVar10 != (undefined8 *)(lVar7 + (long)puVar9));
199: iVar4 = 0;
200: if (4 < iVar1) {
201: do {
202: *(int *)((long)puVar10 + 4) = iVar4;
203: iVar4 = iVar4 + 1;
204: *(undefined4 *)puVar10 = 1;
205: *(undefined4 *)((long)puVar10 + 0x14) = 0;
206: *(undefined4 *)(puVar10 + 3) = 0;
207: puVar5 = (undefined8 *)((long)puVar10 + 0x24);
208: *(undefined4 *)((long)puVar10 + 0x1c) = 1;
209: *(undefined4 *)(puVar10 + 4) = 0;
210: puVar10 = puVar5;
211: } while (iVar4 < iVar1);
212: goto LAB_00120180;
213: }
214: *(int *)puVar10 = iVar1;
215: *(undefined4 *)(puVar5 + 5) = 0;
216: if (((iVar1 != 1) && (*(undefined4 *)((long)puVar5 + 0x2c) = 1, iVar1 != 2)) &&
217: (*(undefined4 *)(puVar5 + 6) = 2, iVar1 == 4)) {
218: *(undefined4 *)((long)puVar5 + 0x34) = 3;
219: }
220: }
221: puVar5 = (undefined8 *)((long)puVar10 + 0x24);
222: *(undefined4 *)((long)puVar10 + 0x14) = 0;
223: *(undefined4 *)(puVar10 + 3) = 0;
224: *(undefined4 *)((long)puVar10 + 0x1c) = 1;
225: *(undefined4 *)(puVar10 + 4) = 0;
226: LAB_00120180:
227: iVar4 = 0;
228: if (0 < iVar1) {
229: do {
230: *(int *)((long)puVar5 + 4) = iVar4;
231: iVar4 = iVar4 + 1;
232: *(undefined4 *)puVar5 = 1;
233: *(undefined4 *)((long)puVar5 + 0x14) = 1;
234: *(undefined4 *)(puVar5 + 3) = 0x3f;
235: *(undefined4 *)((long)puVar5 + 0x1c) = 1;
236: *(undefined4 *)(puVar5 + 4) = 0;
237: puVar5 = (undefined8 *)((long)puVar5 + 0x24);
238: } while (iVar1 != iVar4);
239: }
240: return;
241: }
242: 

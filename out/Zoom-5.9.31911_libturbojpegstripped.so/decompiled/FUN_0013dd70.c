1: 
2: void FUN_0013dd70(code **param_1,byte *param_2)
3: 
4: {
5: long *plVar1;
6: byte bVar2;
7: code *pcVar3;
8: char **ppcVar4;
9: char *pcVar5;
10: code **ppcVar6;
11: undefined8 *puVar7;
12: undefined *puVar8;
13: long *plVar9;
14: int iVar10;
15: long lVar11;
16: long lVar12;
17: ulong uVar13;
18: int iVar14;
19: long lVar15;
20: 
21: bVar2 = *param_2;
22: pcVar3 = param_1[0x3e];
23: lVar12 = *(long *)(&DAT_0018b5e0 + (ulong)(bVar2 & 0x7f) * 8);
24: lVar15 = lVar12 >> 0x10;
25: lVar11 = *(long *)(pcVar3 + 0x20) - lVar15;
26: *(long *)(pcVar3 + 0x20) = lVar11;
27: if ((bVar2 & 0x80) == 0) {
28: if (lVar15 <= lVar11) {
29: *(long *)(pcVar3 + 0x18) = *(long *)(pcVar3 + 0x18) + lVar11;
30: *(long *)(pcVar3 + 0x20) = lVar15;
31: }
32: *param_2 = bVar2 & 0x80 ^ (byte)lVar12;
33: }
34: else {
35: if (0x7fff < lVar11) {
36: return;
37: }
38: if (lVar11 < lVar15) {
39: *(long *)(pcVar3 + 0x18) = *(long *)(pcVar3 + 0x18) + lVar11;
40: *(long *)(pcVar3 + 0x20) = lVar15;
41: }
42: *param_2 = bVar2 & 0x80 ^ (byte)((ulong)lVar12 >> 8);
43: }
44: lVar12 = *(long *)(pcVar3 + 0x20);
45: uVar13 = *(ulong *)(pcVar3 + 0x18);
46: iVar10 = *(int *)(pcVar3 + 0x38);
47: do {
48: iVar10 = iVar10 + -1;
49: lVar12 = lVar12 * 2;
50: uVar13 = uVar13 * 2;
51: *(long *)(pcVar3 + 0x20) = lVar12;
52: *(ulong *)(pcVar3 + 0x18) = uVar13;
53: *(int *)(pcVar3 + 0x38) = iVar10;
54: if (iVar10 == 0) {
55: lVar11 = (long)uVar13 >> 0x13;
56: if (lVar11 < 0x100) {
57: if (lVar11 == 0xff) {
58: *(long *)(pcVar3 + 0x28) = *(long *)(pcVar3 + 0x28) + 1;
59: }
60: else {
61: iVar10 = *(int *)(pcVar3 + 0x3c);
62: if (iVar10 == 0) {
63: *(long *)(pcVar3 + 0x30) = *(long *)(pcVar3 + 0x30) + 1;
64: }
65: else {
66: if (-1 < iVar10) {
67: if (*(long *)(pcVar3 + 0x30) != 0) {
68: do {
69: while( true ) {
70: puVar7 = (undefined8 *)param_1[5];
71: puVar8 = (undefined *)*puVar7;
72: *puVar7 = puVar8 + 1;
73: *puVar8 = 0;
74: lVar12 = puVar7[1];
75: puVar7[1] = lVar12 + -1;
76: if (lVar12 + -1 == 0) break;
77: plVar1 = (long *)(pcVar3 + 0x30);
78: *plVar1 = *plVar1 + -1;
79: if (*plVar1 == 0) goto LAB_0013e0d2;
80: }
81: iVar10 = (*(code *)puVar7[3])(param_1);
82: if (iVar10 == 0) {
83: ppcVar6 = (code **)*param_1;
84: *(undefined4 *)(ppcVar6 + 5) = 0x18;
85: (**ppcVar6)(param_1);
86: }
87: plVar1 = (long *)(pcVar3 + 0x30);
88: *plVar1 = *plVar1 + -1;
89: } while (*plVar1 != 0);
90: LAB_0013e0d2:
91: iVar10 = *(int *)(pcVar3 + 0x3c);
92: }
93: plVar9 = (long *)param_1[5];
94: puVar8 = (undefined *)*plVar9;
95: *plVar9 = (long)(puVar8 + 1);
96: *puVar8 = (char)iVar10;
97: plVar1 = plVar9 + 1;
98: *plVar1 = *plVar1 + -1;
99: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar9[3])(param_1), iVar10 == 0)) {
100: ppcVar6 = (code **)*param_1;
101: *(undefined4 *)(ppcVar6 + 5) = 0x18;
102: (**ppcVar6)(param_1);
103: }
104: }
105: }
106: if (*(long *)(pcVar3 + 0x28) != 0) {
107: lVar12 = *(long *)(pcVar3 + 0x30);
108: while (lVar12 != 0) {
109: puVar7 = (undefined8 *)param_1[5];
110: puVar8 = (undefined *)*puVar7;
111: *puVar7 = puVar8 + 1;
112: *puVar8 = 0;
113: lVar12 = puVar7[1];
114: puVar7[1] = lVar12 + -1;
115: if ((lVar12 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
116: ppcVar6 = (code **)*param_1;
117: *(undefined4 *)(ppcVar6 + 5) = 0x18;
118: (**ppcVar6)(param_1);
119: }
120: plVar1 = (long *)(pcVar3 + 0x30);
121: *plVar1 = *plVar1 + -1;
122: lVar12 = *plVar1;
123: }
124: do {
125: while( true ) {
126: puVar7 = (undefined8 *)param_1[5];
127: puVar8 = (undefined *)*puVar7;
128: *puVar7 = puVar8 + 1;
129: *puVar8 = 0xff;
130: lVar12 = puVar7[1];
131: puVar7[1] = lVar12 + -1;
132: if ((lVar12 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
133: ppcVar6 = (code **)*param_1;
134: *(undefined4 *)(ppcVar6 + 5) = 0x18;
135: (**ppcVar6)(param_1);
136: }
137: puVar7 = (undefined8 *)param_1[5];
138: puVar8 = (undefined *)*puVar7;
139: *puVar7 = puVar8 + 1;
140: *puVar8 = 0;
141: lVar12 = puVar7[1];
142: puVar7[1] = lVar12 + -1;
143: if ((lVar12 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0))
144: break;
145: plVar1 = (long *)(pcVar3 + 0x28);
146: *plVar1 = *plVar1 + -1;
147: if (*plVar1 == 0) goto LAB_0013e000;
148: }
149: ppcVar6 = (code **)*param_1;
150: *(undefined4 *)(ppcVar6 + 5) = 0x18;
151: (**ppcVar6)(param_1);
152: plVar1 = (long *)(pcVar3 + 0x28);
153: *plVar1 = *plVar1 + -1;
154: } while (*plVar1 != 0);
155: }
156: LAB_0013e000:
157: uVar13 = *(ulong *)(pcVar3 + 0x18);
158: iVar10 = *(int *)(pcVar3 + 0x38);
159: *(uint *)(pcVar3 + 0x3c) = (uint)lVar11 & 0xff;
160: lVar12 = *(long *)(pcVar3 + 0x20);
161: }
162: }
163: else {
164: iVar14 = *(int *)(pcVar3 + 0x3c);
165: if (-1 < iVar14) {
166: if (*(long *)(pcVar3 + 0x30) != 0) {
167: do {
168: while( true ) {
169: puVar7 = (undefined8 *)param_1[5];
170: puVar8 = (undefined *)*puVar7;
171: *puVar7 = puVar8 + 1;
172: *puVar8 = 0;
173: lVar12 = puVar7[1];
174: puVar7[1] = lVar12 + -1;
175: if (lVar12 + -1 == 0) break;
176: plVar1 = (long *)(pcVar3 + 0x30);
177: *plVar1 = *plVar1 + -1;
178: if (*plVar1 == 0) goto LAB_0013df0a;
179: }
180: iVar10 = (*(code *)puVar7[3])(param_1);
181: if (iVar10 == 0) {
182: ppcVar6 = (code **)*param_1;
183: *(undefined4 *)(ppcVar6 + 5) = 0x18;
184: (**ppcVar6)(param_1);
185: }
186: plVar1 = (long *)(pcVar3 + 0x30);
187: *plVar1 = *plVar1 + -1;
188: } while (*plVar1 != 0);
189: LAB_0013df0a:
190: iVar14 = *(int *)(pcVar3 + 0x3c);
191: }
192: ppcVar4 = (char **)param_1[5];
193: pcVar5 = *ppcVar4;
194: *ppcVar4 = pcVar5 + 1;
195: *pcVar5 = (char)iVar14 + '\x01';
196: pcVar5 = ppcVar4[1];
197: ppcVar4[1] = pcVar5 + -1;
198: if ((pcVar5 + -1 == (char *)0x0) && (iVar10 = (*(code *)ppcVar4[3])(param_1), iVar10 == 0)
199: ) {
200: ppcVar6 = (code **)*param_1;
201: *(undefined4 *)(ppcVar6 + 5) = 0x18;
202: (**ppcVar6)(param_1);
203: iVar10 = *(int *)(pcVar3 + 0x3c);
204: }
205: else {
206: iVar10 = *(int *)(pcVar3 + 0x3c);
207: }
208: if (iVar10 == 0xfe) {
209: puVar7 = (undefined8 *)param_1[5];
210: puVar8 = (undefined *)*puVar7;
211: *puVar7 = puVar8 + 1;
212: *puVar8 = 0;
213: lVar12 = puVar7[1];
214: puVar7[1] = lVar12 + -1;
215: if ((lVar12 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
216: ppcVar6 = (code **)*param_1;
217: *(undefined4 *)(ppcVar6 + 5) = 0x18;
218: (**ppcVar6)(param_1);
219: }
220: }
221: uVar13 = *(ulong *)(pcVar3 + 0x18);
222: iVar10 = *(int *)(pcVar3 + 0x38);
223: lVar12 = *(long *)(pcVar3 + 0x20);
224: }
225: *(long *)(pcVar3 + 0x30) = *(long *)(pcVar3 + 0x30) + *(long *)(pcVar3 + 0x28);
226: *(undefined8 *)(pcVar3 + 0x28) = 0;
227: *(uint *)(pcVar3 + 0x3c) = (uint)lVar11 & 0xff;
228: }
229: uVar13 = (ulong)((uint)uVar13 & 0x7ffff);
230: iVar10 = iVar10 + 8;
231: *(ulong *)(pcVar3 + 0x18) = uVar13;
232: *(int *)(pcVar3 + 0x38) = iVar10;
233: }
234: if (0x7fff < lVar12) {
235: return;
236: }
237: } while( true );
238: }
239: 

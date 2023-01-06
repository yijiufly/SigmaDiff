1: 
2: void FUN_0014b3d0(code **param_1)
3: 
4: {
5: char **ppcVar1;
6: long *plVar2;
7: code *pcVar3;
8: char **ppcVar4;
9: char *pcVar5;
10: code **ppcVar6;
11: long lVar7;
12: undefined8 *puVar8;
13: undefined *puVar9;
14: long *plVar10;
15: int iVar11;
16: ulong uVar12;
17: long lVar13;
18: 
19: pcVar3 = param_1[0x3e];
20: uVar12 = (ulong)((int)*(long *)(pcVar3 + 0x18) + -1 + (int)*(undefined8 *)(pcVar3 + 0x20) &
21: 0xffff0000);
22: iVar11 = *(int *)(pcVar3 + 0x3c);
23: if ((long)uVar12 < *(long *)(pcVar3 + 0x18)) {
24: uVar12 = uVar12 + 0x8000;
25: }
26: uVar12 = uVar12 << ((byte)*(undefined4 *)(pcVar3 + 0x38) & 0x3f);
27: *(ulong *)(pcVar3 + 0x18) = uVar12;
28: if ((uVar12 & 0xf8000000) == 0) {
29: if (iVar11 == 0) {
30: *(long *)(pcVar3 + 0x30) = *(long *)(pcVar3 + 0x30) + 1;
31: }
32: else {
33: if (-1 < iVar11) {
34: if (*(long *)(pcVar3 + 0x30) != 0) {
35: do {
36: puVar8 = (undefined8 *)param_1[5];
37: puVar9 = (undefined *)*puVar8;
38: *puVar8 = puVar9 + 1;
39: *puVar9 = 0;
40: plVar2 = puVar8 + 1;
41: *plVar2 = *plVar2 + -1;
42: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
43: ppcVar6 = (code **)*param_1;
44: *(undefined4 *)(ppcVar6 + 5) = 0x18;
45: (**ppcVar6)(param_1);
46: }
47: plVar2 = (long *)(pcVar3 + 0x30);
48: *plVar2 = *plVar2 + -1;
49: } while (*plVar2 != 0);
50: iVar11 = *(int *)(pcVar3 + 0x3c);
51: }
52: plVar10 = (long *)param_1[5];
53: puVar9 = (undefined *)*plVar10;
54: *plVar10 = (long)(puVar9 + 1);
55: *puVar9 = (char)iVar11;
56: plVar2 = plVar10 + 1;
57: *plVar2 = *plVar2 + -1;
58: if ((*plVar2 == 0) && (iVar11 = (*(code *)plVar10[3])(param_1), iVar11 == 0)) {
59: ppcVar6 = (code **)*param_1;
60: *(undefined4 *)(ppcVar6 + 5) = 0x18;
61: (**ppcVar6)(param_1);
62: }
63: }
64: }
65: if (*(long *)(pcVar3 + 0x28) != 0) {
66: lVar13 = *(long *)(pcVar3 + 0x30);
67: while (lVar13 != 0) {
68: puVar8 = (undefined8 *)param_1[5];
69: puVar9 = (undefined *)*puVar8;
70: *puVar8 = puVar9 + 1;
71: *puVar9 = 0;
72: plVar2 = puVar8 + 1;
73: *plVar2 = *plVar2 + -1;
74: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
75: ppcVar6 = (code **)*param_1;
76: *(undefined4 *)(ppcVar6 + 5) = 0x18;
77: (**ppcVar6)(param_1);
78: }
79: plVar2 = (long *)(pcVar3 + 0x30);
80: *plVar2 = *plVar2 + -1;
81: lVar13 = *plVar2;
82: }
83: do {
84: puVar8 = (undefined8 *)param_1[5];
85: puVar9 = (undefined *)*puVar8;
86: *puVar8 = puVar9 + 1;
87: *puVar9 = 0xff;
88: plVar2 = puVar8 + 1;
89: *plVar2 = *plVar2 + -1;
90: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
91: ppcVar6 = (code **)*param_1;
92: *(undefined4 *)(ppcVar6 + 5) = 0x18;
93: (**ppcVar6)(param_1);
94: }
95: puVar8 = (undefined8 *)param_1[5];
96: puVar9 = (undefined *)*puVar8;
97: *puVar8 = puVar9 + 1;
98: *puVar9 = 0;
99: plVar2 = puVar8 + 1;
100: *plVar2 = *plVar2 + -1;
101: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
102: ppcVar6 = (code **)*param_1;
103: *(undefined4 *)(ppcVar6 + 5) = 0x18;
104: (**ppcVar6)(param_1);
105: }
106: plVar2 = (long *)(pcVar3 + 0x28);
107: *plVar2 = *plVar2 + -1;
108: } while (*plVar2 != 0);
109: }
110: uVar12 = *(ulong *)(pcVar3 + 0x18);
111: }
112: else {
113: lVar13 = *(long *)(pcVar3 + 0x30);
114: if (-1 < iVar11) {
115: if (lVar13 != 0) {
116: do {
117: puVar8 = (undefined8 *)param_1[5];
118: puVar9 = (undefined *)*puVar8;
119: *puVar8 = puVar9 + 1;
120: *puVar9 = 0;
121: plVar2 = puVar8 + 1;
122: *plVar2 = *plVar2 + -1;
123: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
124: ppcVar6 = (code **)*param_1;
125: *(undefined4 *)(ppcVar6 + 5) = 0x18;
126: (**ppcVar6)(param_1);
127: }
128: plVar2 = (long *)(pcVar3 + 0x30);
129: *plVar2 = *plVar2 + -1;
130: } while (*plVar2 != 0);
131: iVar11 = *(int *)(pcVar3 + 0x3c);
132: }
133: ppcVar4 = (char **)param_1[5];
134: pcVar5 = *ppcVar4;
135: *ppcVar4 = pcVar5 + 1;
136: *pcVar5 = (char)iVar11 + '\x01';
137: ppcVar1 = ppcVar4 + 1;
138: *ppcVar1 = *ppcVar1 + -1;
139: if ((*ppcVar1 == (char *)0x0) && (iVar11 = (*(code *)ppcVar4[3])(param_1), iVar11 == 0)) {
140: ppcVar6 = (code **)*param_1;
141: *(undefined4 *)(ppcVar6 + 5) = 0x18;
142: (**ppcVar6)(param_1);
143: }
144: if (*(int *)(pcVar3 + 0x3c) == 0xfe) {
145: puVar8 = (undefined8 *)param_1[5];
146: puVar9 = (undefined *)*puVar8;
147: *puVar8 = puVar9 + 1;
148: *puVar9 = 0;
149: plVar2 = puVar8 + 1;
150: *plVar2 = *plVar2 + -1;
151: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
152: ppcVar6 = (code **)*param_1;
153: *(undefined4 *)(ppcVar6 + 5) = 0x18;
154: (**ppcVar6)(param_1);
155: }
156: }
157: lVar13 = *(long *)(pcVar3 + 0x30);
158: uVar12 = *(ulong *)(pcVar3 + 0x18);
159: }
160: lVar7 = *(long *)(pcVar3 + 0x28);
161: *(undefined8 *)(pcVar3 + 0x28) = 0;
162: *(long *)(pcVar3 + 0x30) = lVar13 + lVar7;
163: }
164: if ((uVar12 & 0x7fff800) != 0) {
165: if (*(long *)(pcVar3 + 0x30) != 0) {
166: do {
167: puVar8 = (undefined8 *)param_1[5];
168: puVar9 = (undefined *)*puVar8;
169: *puVar8 = puVar9 + 1;
170: *puVar9 = 0;
171: plVar2 = puVar8 + 1;
172: *plVar2 = *plVar2 + -1;
173: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
174: ppcVar6 = (code **)*param_1;
175: *(undefined4 *)(ppcVar6 + 5) = 0x18;
176: (**ppcVar6)(param_1);
177: }
178: plVar2 = (long *)(pcVar3 + 0x30);
179: *plVar2 = *plVar2 + -1;
180: } while (*plVar2 != 0);
181: uVar12 = *(ulong *)(pcVar3 + 0x18);
182: }
183: plVar10 = (long *)param_1[5];
184: puVar9 = (undefined *)*plVar10;
185: *plVar10 = (long)(puVar9 + 1);
186: *puVar9 = (char)((long)uVar12 >> 0x13);
187: plVar2 = plVar10 + 1;
188: *plVar2 = *plVar2 + -1;
189: if ((*plVar2 == 0) && (iVar11 = (*(code *)plVar10[3])(param_1), iVar11 == 0)) {
190: ppcVar6 = (code **)*param_1;
191: *(undefined4 *)(ppcVar6 + 5) = 0x18;
192: (**ppcVar6)(param_1);
193: }
194: uVar12 = *(ulong *)(pcVar3 + 0x18);
195: if (((long)uVar12 >> 0x13 & 0xffU) == 0xff) {
196: puVar8 = (undefined8 *)param_1[5];
197: puVar9 = (undefined *)*puVar8;
198: *puVar8 = puVar9 + 1;
199: *puVar9 = 0;
200: plVar2 = puVar8 + 1;
201: *plVar2 = *plVar2 + -1;
202: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
203: ppcVar6 = (code **)*param_1;
204: *(undefined4 *)(ppcVar6 + 5) = 0x18;
205: (**ppcVar6)(param_1);
206: }
207: uVar12 = *(ulong *)(pcVar3 + 0x18);
208: }
209: if ((uVar12 & 0x7f800) != 0) {
210: plVar10 = (long *)param_1[5];
211: puVar9 = (undefined *)*plVar10;
212: *plVar10 = (long)(puVar9 + 1);
213: *puVar9 = (char)((long)uVar12 >> 0xb);
214: plVar2 = plVar10 + 1;
215: *plVar2 = *plVar2 + -1;
216: if ((*plVar2 == 0) && (iVar11 = (*(code *)plVar10[3])(param_1), iVar11 == 0)) {
217: ppcVar6 = (code **)*param_1;
218: *(undefined4 *)(ppcVar6 + 5) = 0x18;
219: (**ppcVar6)(param_1);
220: }
221: if ((*(long *)(pcVar3 + 0x18) >> 0xb & 0xffU) == 0xff) {
222: puVar8 = (undefined8 *)param_1[5];
223: puVar9 = (undefined *)*puVar8;
224: *puVar8 = puVar9 + 1;
225: *puVar9 = 0;
226: plVar2 = puVar8 + 1;
227: *plVar2 = *plVar2 + -1;
228: if ((*plVar2 == 0) && (iVar11 = (*(code *)puVar8[3])(param_1), iVar11 == 0)) {
229: ppcVar6 = (code **)*param_1;
230: *(undefined4 *)(ppcVar6 + 5) = 0x18;
231: /* WARNING: Could not recover jumptable at 0x0014b73b. Too many branches */
232: /* WARNING: Treating indirect jump as call */
233: (**ppcVar6)(param_1);
234: return;
235: }
236: }
237: }
238: }
239: return;
240: }
241: 

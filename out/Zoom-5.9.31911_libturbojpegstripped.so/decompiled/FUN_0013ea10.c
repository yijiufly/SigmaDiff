1: 
2: void FUN_0013ea10(code **param_1)
3: 
4: {
5: long *plVar1;
6: code *pcVar2;
7: char **ppcVar3;
8: char *pcVar4;
9: long *plVar5;
10: undefined *puVar6;
11: undefined8 *puVar7;
12: long lVar8;
13: code **ppcVar9;
14: int iVar10;
15: ulong uVar11;
16: 
17: pcVar2 = param_1[0x3e];
18: uVar11 = (ulong)((int)*(long *)(pcVar2 + 0x18) + -1 + (int)*(undefined8 *)(pcVar2 + 0x20) &
19: 0xffff0000);
20: if ((long)uVar11 < *(long *)(pcVar2 + 0x18)) {
21: uVar11 = uVar11 + 0x8000;
22: }
23: uVar11 = uVar11 << ((byte)*(undefined4 *)(pcVar2 + 0x38) & 0x3f);
24: *(ulong *)(pcVar2 + 0x18) = uVar11;
25: if ((uVar11 & 0xf8000000) == 0) {
26: iVar10 = *(int *)(pcVar2 + 0x3c);
27: if (iVar10 == 0) {
28: *(long *)(pcVar2 + 0x30) = *(long *)(pcVar2 + 0x30) + 1;
29: }
30: else {
31: if (-1 < iVar10) {
32: if (*(long *)(pcVar2 + 0x30) != 0) {
33: do {
34: puVar7 = (undefined8 *)param_1[5];
35: puVar6 = (undefined *)*puVar7;
36: *puVar7 = puVar6 + 1;
37: *puVar6 = 0;
38: lVar8 = puVar7[1];
39: puVar7[1] = lVar8 + -1;
40: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
41: ppcVar9 = (code **)*param_1;
42: *(undefined4 *)(ppcVar9 + 5) = 0x18;
43: (**ppcVar9)(param_1);
44: }
45: plVar1 = (long *)(pcVar2 + 0x30);
46: *plVar1 = *plVar1 + -1;
47: } while (*plVar1 != 0);
48: iVar10 = *(int *)(pcVar2 + 0x3c);
49: }
50: plVar5 = (long *)param_1[5];
51: puVar6 = (undefined *)*plVar5;
52: *plVar5 = (long)(puVar6 + 1);
53: *puVar6 = (char)iVar10;
54: plVar1 = plVar5 + 1;
55: *plVar1 = *plVar1 + -1;
56: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar5[3])(param_1), iVar10 == 0)) {
57: ppcVar9 = (code **)*param_1;
58: *(undefined4 *)(ppcVar9 + 5) = 0x18;
59: (**ppcVar9)(param_1);
60: }
61: }
62: }
63: if (*(long *)(pcVar2 + 0x28) != 0) {
64: lVar8 = *(long *)(pcVar2 + 0x30);
65: while (lVar8 != 0) {
66: puVar7 = (undefined8 *)param_1[5];
67: puVar6 = (undefined *)*puVar7;
68: *puVar7 = puVar6 + 1;
69: *puVar6 = 0;
70: lVar8 = puVar7[1];
71: puVar7[1] = lVar8 + -1;
72: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
73: ppcVar9 = (code **)*param_1;
74: *(undefined4 *)(ppcVar9 + 5) = 0x18;
75: (**ppcVar9)(param_1);
76: }
77: plVar1 = (long *)(pcVar2 + 0x30);
78: *plVar1 = *plVar1 + -1;
79: lVar8 = *plVar1;
80: }
81: do {
82: while( true ) {
83: puVar7 = (undefined8 *)param_1[5];
84: puVar6 = (undefined *)*puVar7;
85: *puVar7 = puVar6 + 1;
86: *puVar6 = 0xff;
87: lVar8 = puVar7[1];
88: puVar7[1] = lVar8 + -1;
89: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
90: ppcVar9 = (code **)*param_1;
91: *(undefined4 *)(ppcVar9 + 5) = 0x18;
92: (**ppcVar9)(param_1);
93: }
94: puVar7 = (undefined8 *)param_1[5];
95: puVar6 = (undefined *)*puVar7;
96: *puVar7 = puVar6 + 1;
97: *puVar6 = 0;
98: lVar8 = puVar7[1];
99: puVar7[1] = lVar8 + -1;
100: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) break;
101: plVar1 = (long *)(pcVar2 + 0x28);
102: *plVar1 = *plVar1 + -1;
103: if (*plVar1 == 0) goto LAB_0013edd8;
104: }
105: ppcVar9 = (code **)*param_1;
106: *(undefined4 *)(ppcVar9 + 5) = 0x18;
107: (**ppcVar9)(param_1);
108: plVar1 = (long *)(pcVar2 + 0x28);
109: *plVar1 = *plVar1 + -1;
110: } while (*plVar1 != 0);
111: }
112: LAB_0013edd8:
113: uVar11 = *(ulong *)(pcVar2 + 0x18);
114: }
115: else {
116: iVar10 = *(int *)(pcVar2 + 0x3c);
117: if (-1 < iVar10) {
118: if (*(long *)(pcVar2 + 0x30) != 0) {
119: do {
120: while( true ) {
121: puVar7 = (undefined8 *)param_1[5];
122: puVar6 = (undefined *)*puVar7;
123: *puVar7 = puVar6 + 1;
124: *puVar6 = 0;
125: lVar8 = puVar7[1];
126: puVar7[1] = lVar8 + -1;
127: if (lVar8 + -1 == 0) break;
128: plVar1 = (long *)(pcVar2 + 0x30);
129: *plVar1 = *plVar1 + -1;
130: if (*plVar1 == 0) goto LAB_0013ebda;
131: }
132: iVar10 = (*(code *)puVar7[3])(param_1);
133: if (iVar10 == 0) {
134: ppcVar9 = (code **)*param_1;
135: *(undefined4 *)(ppcVar9 + 5) = 0x18;
136: (**ppcVar9)(param_1);
137: }
138: plVar1 = (long *)(pcVar2 + 0x30);
139: *plVar1 = *plVar1 + -1;
140: } while (*plVar1 != 0);
141: LAB_0013ebda:
142: iVar10 = *(int *)(pcVar2 + 0x3c);
143: }
144: ppcVar3 = (char **)param_1[5];
145: pcVar4 = *ppcVar3;
146: *ppcVar3 = pcVar4 + 1;
147: *pcVar4 = (char)iVar10 + '\x01';
148: pcVar4 = ppcVar3[1];
149: ppcVar3[1] = pcVar4 + -1;
150: if ((pcVar4 + -1 == (char *)0x0) && (iVar10 = (*(code *)ppcVar3[3])(param_1), iVar10 == 0)) {
151: ppcVar9 = (code **)*param_1;
152: *(undefined4 *)(ppcVar9 + 5) = 0x18;
153: (**ppcVar9)(param_1);
154: }
155: if (*(int *)(pcVar2 + 0x3c) == 0xfe) {
156: puVar7 = (undefined8 *)param_1[5];
157: puVar6 = (undefined *)*puVar7;
158: *puVar7 = puVar6 + 1;
159: *puVar6 = 0;
160: lVar8 = puVar7[1];
161: puVar7[1] = lVar8 + -1;
162: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
163: ppcVar9 = (code **)*param_1;
164: *(undefined4 *)(ppcVar9 + 5) = 0x18;
165: (**ppcVar9)(param_1);
166: }
167: }
168: uVar11 = *(ulong *)(pcVar2 + 0x18);
169: }
170: *(long *)(pcVar2 + 0x30) = *(long *)(pcVar2 + 0x30) + *(long *)(pcVar2 + 0x28);
171: *(undefined8 *)(pcVar2 + 0x28) = 0;
172: }
173: if ((uVar11 & 0x7fff800) != 0) {
174: if (*(long *)(pcVar2 + 0x30) != 0) {
175: do {
176: while( true ) {
177: puVar7 = (undefined8 *)param_1[5];
178: puVar6 = (undefined *)*puVar7;
179: *puVar7 = puVar6 + 1;
180: *puVar6 = 0;
181: lVar8 = puVar7[1];
182: puVar7[1] = lVar8 + -1;
183: if (lVar8 + -1 == 0) break;
184: plVar1 = (long *)(pcVar2 + 0x30);
185: *plVar1 = *plVar1 + -1;
186: if (*plVar1 == 0) goto LAB_0013eb52;
187: }
188: iVar10 = (*(code *)puVar7[3])(param_1);
189: if (iVar10 == 0) {
190: ppcVar9 = (code **)*param_1;
191: *(undefined4 *)(ppcVar9 + 5) = 0x18;
192: (**ppcVar9)(param_1);
193: }
194: plVar1 = (long *)(pcVar2 + 0x30);
195: *plVar1 = *plVar1 + -1;
196: } while (*plVar1 != 0);
197: LAB_0013eb52:
198: uVar11 = *(ulong *)(pcVar2 + 0x18);
199: }
200: plVar5 = (long *)param_1[5];
201: puVar6 = (undefined *)*plVar5;
202: *plVar5 = (long)(puVar6 + 1);
203: *puVar6 = (char)((long)uVar11 >> 0x13);
204: plVar1 = plVar5 + 1;
205: *plVar1 = *plVar1 + -1;
206: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar5[3])(param_1), iVar10 == 0)) {
207: ppcVar9 = (code **)*param_1;
208: *(undefined4 *)(ppcVar9 + 5) = 0x18;
209: (**ppcVar9)(param_1);
210: }
211: uVar11 = *(ulong *)(pcVar2 + 0x18);
212: if ((char)((long)uVar11 >> 0x13) == -1) {
213: puVar7 = (undefined8 *)param_1[5];
214: puVar6 = (undefined *)*puVar7;
215: *puVar7 = puVar6 + 1;
216: *puVar6 = 0;
217: lVar8 = puVar7[1];
218: puVar7[1] = lVar8 + -1;
219: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
220: ppcVar9 = (code **)*param_1;
221: *(undefined4 *)(ppcVar9 + 5) = 0x18;
222: (**ppcVar9)(param_1);
223: }
224: uVar11 = *(ulong *)(pcVar2 + 0x18);
225: }
226: if ((uVar11 & 0x7f800) != 0) {
227: plVar5 = (long *)param_1[5];
228: puVar6 = (undefined *)*plVar5;
229: *plVar5 = (long)(puVar6 + 1);
230: *puVar6 = (char)((long)uVar11 >> 0xb);
231: plVar1 = plVar5 + 1;
232: *plVar1 = *plVar1 + -1;
233: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar5[3])(param_1), iVar10 == 0)) {
234: ppcVar9 = (code **)*param_1;
235: *(undefined4 *)(ppcVar9 + 5) = 0x18;
236: (**ppcVar9)(param_1);
237: }
238: if ((char)(*(long *)(pcVar2 + 0x18) >> 0xb) == -1) {
239: puVar7 = (undefined8 *)param_1[5];
240: puVar6 = (undefined *)*puVar7;
241: *puVar7 = puVar6 + 1;
242: *puVar6 = 0;
243: lVar8 = puVar7[1];
244: puVar7[1] = lVar8 + -1;
245: if ((lVar8 + -1 == 0) && (iVar10 = (*(code *)puVar7[3])(param_1), iVar10 == 0)) {
246: ppcVar9 = (code **)*param_1;
247: *(undefined4 *)(ppcVar9 + 5) = 0x18;
248: /* WARNING: Could not recover jumptable at 0x0013ed7a. Too many branches */
249: /* WARNING: Treating indirect jump as call */
250: (**ppcVar9)(param_1);
251: return;
252: }
253: }
254: }
255: }
256: return;
257: }
258: 

1: 
2: void FUN_00112bb0(code **param_1,undefined param_2)
3: 
4: {
5: char **ppcVar1;
6: undefined4 uVar2;
7: undefined8 *puVar3;
8: undefined *puVar4;
9: long lVar5;
10: long *plVar6;
11: char **ppcVar7;
12: char *pcVar8;
13: code **ppcVar9;
14: code *pcVar10;
15: int iVar11;
16: undefined4 *puVar12;
17: int iVar13;
18: 
19: puVar3 = (undefined8 *)param_1[5];
20: puVar4 = (undefined *)*puVar3;
21: *puVar3 = puVar4 + 1;
22: *puVar4 = 0xff;
23: lVar5 = puVar3[1];
24: puVar3[1] = lVar5 + -1;
25: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)puVar3[3])(param_1), iVar13 == 0)) {
26: ppcVar9 = (code **)*param_1;
27: *(undefined4 *)(ppcVar9 + 5) = 0x18;
28: (**ppcVar9)(param_1);
29: }
30: plVar6 = (long *)param_1[5];
31: puVar4 = (undefined *)*plVar6;
32: *plVar6 = (long)(puVar4 + 1);
33: *puVar4 = param_2;
34: lVar5 = plVar6[1];
35: plVar6[1] = lVar5 + -1;
36: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
37: ppcVar9 = (code **)*param_1;
38: *(undefined4 *)(ppcVar9 + 5) = 0x18;
39: (**ppcVar9)(param_1);
40: }
41: iVar13 = *(int *)((long)param_1 + 0x4c) * 3 + 8;
42: plVar6 = (long *)param_1[5];
43: puVar4 = (undefined *)*plVar6;
44: *plVar6 = (long)(puVar4 + 1);
45: *puVar4 = (char)((uint)iVar13 >> 8);
46: lVar5 = plVar6[1];
47: plVar6[1] = lVar5 + -1;
48: if ((lVar5 + -1 == 0) && (iVar11 = (*(code *)plVar6[3])(param_1), iVar11 == 0)) {
49: ppcVar9 = (code **)*param_1;
50: *(undefined4 *)(ppcVar9 + 5) = 0x18;
51: (**ppcVar9)(param_1);
52: }
53: plVar6 = (long *)param_1[5];
54: puVar4 = (undefined *)*plVar6;
55: *plVar6 = (long)(puVar4 + 1);
56: *puVar4 = (char)iVar13;
57: lVar5 = plVar6[1];
58: plVar6[1] = lVar5 + -1;
59: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
60: ppcVar9 = (code **)*param_1;
61: *(undefined4 *)(ppcVar9 + 5) = 0x18;
62: (**ppcVar9)(param_1);
63: }
64: if ((0xffff < *(uint *)((long)param_1 + 0x34)) || (0xffff < *(uint *)(param_1 + 6))) {
65: pcVar10 = *param_1;
66: *(undefined4 *)(pcVar10 + 0x28) = 0x29;
67: *(undefined4 *)(pcVar10 + 0x2c) = 0xffff;
68: (**(code **)*param_1)(param_1);
69: }
70: plVar6 = (long *)param_1[5];
71: uVar2 = *(undefined4 *)(param_1 + 9);
72: puVar4 = (undefined *)*plVar6;
73: *plVar6 = (long)(puVar4 + 1);
74: *puVar4 = (char)uVar2;
75: lVar5 = plVar6[1];
76: plVar6[1] = lVar5 + -1;
77: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
78: ppcVar9 = (code **)*param_1;
79: *(undefined4 *)(ppcVar9 + 5) = 0x18;
80: (**ppcVar9)(param_1);
81: }
82: plVar6 = (long *)param_1[5];
83: uVar2 = *(undefined4 *)((long)param_1 + 0x34);
84: puVar4 = (undefined *)*plVar6;
85: *plVar6 = (long)(puVar4 + 1);
86: *puVar4 = (char)((uint)uVar2 >> 8);
87: lVar5 = plVar6[1];
88: plVar6[1] = lVar5 + -1;
89: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
90: ppcVar9 = (code **)*param_1;
91: *(undefined4 *)(ppcVar9 + 5) = 0x18;
92: (**ppcVar9)(param_1);
93: }
94: plVar6 = (long *)param_1[5];
95: puVar4 = (undefined *)*plVar6;
96: *plVar6 = (long)(puVar4 + 1);
97: *puVar4 = (char)uVar2;
98: lVar5 = plVar6[1];
99: plVar6[1] = lVar5 + -1;
100: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
101: ppcVar9 = (code **)*param_1;
102: *(undefined4 *)(ppcVar9 + 5) = 0x18;
103: (**ppcVar9)(param_1);
104: }
105: plVar6 = (long *)param_1[5];
106: uVar2 = *(undefined4 *)(param_1 + 6);
107: puVar4 = (undefined *)*plVar6;
108: *plVar6 = (long)(puVar4 + 1);
109: *puVar4 = (char)((uint)uVar2 >> 8);
110: lVar5 = plVar6[1];
111: plVar6[1] = lVar5 + -1;
112: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
113: ppcVar9 = (code **)*param_1;
114: *(undefined4 *)(ppcVar9 + 5) = 0x18;
115: (**ppcVar9)(param_1);
116: }
117: plVar6 = (long *)param_1[5];
118: puVar4 = (undefined *)*plVar6;
119: *plVar6 = (long)(puVar4 + 1);
120: *puVar4 = (char)uVar2;
121: lVar5 = plVar6[1];
122: plVar6[1] = lVar5 + -1;
123: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
124: ppcVar9 = (code **)*param_1;
125: *(undefined4 *)(ppcVar9 + 5) = 0x18;
126: (**ppcVar9)(param_1);
127: }
128: plVar6 = (long *)param_1[5];
129: uVar2 = *(undefined4 *)((long)param_1 + 0x4c);
130: puVar4 = (undefined *)*plVar6;
131: *plVar6 = (long)(puVar4 + 1);
132: *puVar4 = (char)uVar2;
133: lVar5 = plVar6[1];
134: plVar6[1] = lVar5 + -1;
135: if ((lVar5 + -1 == 0) && (iVar13 = (*(code *)plVar6[3])(param_1), iVar13 == 0)) {
136: ppcVar9 = (code **)*param_1;
137: *(undefined4 *)(ppcVar9 + 5) = 0x18;
138: (**ppcVar9)(param_1);
139: }
140: iVar13 = 0;
141: puVar12 = (undefined4 *)param_1[0xb];
142: if (0 < *(int *)((long)param_1 + 0x4c)) {
143: do {
144: while( true ) {
145: plVar6 = (long *)param_1[5];
146: uVar2 = *puVar12;
147: puVar4 = (undefined *)*plVar6;
148: *plVar6 = (long)(puVar4 + 1);
149: *puVar4 = (char)uVar2;
150: lVar5 = plVar6[1];
151: plVar6[1] = lVar5 + -1;
152: if ((lVar5 + -1 == 0) && (iVar11 = (*(code *)plVar6[3])(param_1), iVar11 == 0)) {
153: ppcVar9 = (code **)*param_1;
154: *(undefined4 *)(ppcVar9 + 5) = 0x18;
155: (**ppcVar9)(param_1);
156: }
157: ppcVar7 = (char **)param_1[5];
158: iVar11 = puVar12[2];
159: pcVar8 = *ppcVar7;
160: uVar2 = puVar12[3];
161: *ppcVar7 = pcVar8 + 1;
162: *pcVar8 = (char)(iVar11 << 4) + (char)uVar2;
163: ppcVar1 = ppcVar7 + 1;
164: *ppcVar1 = *ppcVar1 + -1;
165: if ((*ppcVar1 == (char *)0x0) && (iVar11 = (*(code *)ppcVar7[3])(param_1), iVar11 == 0)) {
166: ppcVar9 = (code **)*param_1;
167: *(undefined4 *)(ppcVar9 + 5) = 0x18;
168: (**ppcVar9)(param_1);
169: }
170: plVar6 = (long *)param_1[5];
171: uVar2 = puVar12[4];
172: puVar4 = (undefined *)*plVar6;
173: *plVar6 = (long)(puVar4 + 1);
174: *puVar4 = (char)uVar2;
175: lVar5 = plVar6[1];
176: plVar6[1] = lVar5 + -1;
177: if ((lVar5 + -1 == 0) && (iVar11 = (*(code *)plVar6[3])(param_1), iVar11 == 0)) break;
178: iVar13 = iVar13 + 1;
179: puVar12 = puVar12 + 0x18;
180: if (*(int *)((long)param_1 + 0x4c) == iVar13 || *(int *)((long)param_1 + 0x4c) < iVar13) {
181: return;
182: }
183: }
184: ppcVar9 = (code **)*param_1;
185: iVar13 = iVar13 + 1;
186: puVar12 = puVar12 + 0x18;
187: *(undefined4 *)(ppcVar9 + 5) = 0x18;
188: (**ppcVar9)(param_1);
189: } while (*(int *)((long)param_1 + 0x4c) != iVar13 && iVar13 <= *(int *)((long)param_1 + 0x4c));
190: }
191: return;
192: }
193: 

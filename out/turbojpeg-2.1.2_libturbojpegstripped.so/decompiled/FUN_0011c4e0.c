1: 
2: void FUN_0011c4e0(code **param_1,undefined param_2)
3: 
4: {
5: long *plVar1;
6: char **ppcVar2;
7: undefined4 uVar3;
8: undefined8 *puVar4;
9: undefined *puVar5;
10: code **ppcVar6;
11: long *plVar7;
12: char **ppcVar8;
13: char *pcVar9;
14: int iVar10;
15: int iVar11;
16: undefined4 *puVar12;
17: 
18: puVar4 = (undefined8 *)param_1[5];
19: puVar5 = (undefined *)*puVar4;
20: *puVar4 = puVar5 + 1;
21: *puVar5 = 0xff;
22: plVar1 = puVar4 + 1;
23: *plVar1 = *plVar1 + -1;
24: if ((*plVar1 == 0) && (iVar10 = (*(code *)puVar4[3])(), iVar10 == 0)) {
25: ppcVar6 = (code **)*param_1;
26: *(undefined4 *)(ppcVar6 + 5) = 0x18;
27: (**ppcVar6)(param_1);
28: }
29: plVar7 = (long *)param_1[5];
30: puVar5 = (undefined *)*plVar7;
31: *plVar7 = (long)(puVar5 + 1);
32: *puVar5 = param_2;
33: plVar1 = plVar7 + 1;
34: *plVar1 = *plVar1 + -1;
35: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
36: ppcVar6 = (code **)*param_1;
37: *(undefined4 *)(ppcVar6 + 5) = 0x18;
38: (**ppcVar6)(param_1);
39: }
40: iVar10 = *(int *)((long)param_1 + 0x4c) * 3 + 8;
41: plVar7 = (long *)param_1[5];
42: puVar5 = (undefined *)*plVar7;
43: *plVar7 = (long)(puVar5 + 1);
44: *puVar5 = (char)((uint)iVar10 >> 8);
45: plVar1 = plVar7 + 1;
46: *plVar1 = *plVar1 + -1;
47: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar7[3])(param_1), iVar11 == 0)) {
48: ppcVar6 = (code **)*param_1;
49: *(undefined4 *)(ppcVar6 + 5) = 0x18;
50: (**ppcVar6)(param_1);
51: }
52: plVar7 = (long *)param_1[5];
53: puVar5 = (undefined *)*plVar7;
54: *plVar7 = (long)(puVar5 + 1);
55: *puVar5 = (char)iVar10;
56: plVar1 = plVar7 + 1;
57: *plVar1 = *plVar1 + -1;
58: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
59: ppcVar6 = (code **)*param_1;
60: *(undefined4 *)(ppcVar6 + 5) = 0x18;
61: (**ppcVar6)(param_1);
62: }
63: if ((0xffff < *(uint *)((long)param_1 + 0x34)) || (0xffff < *(uint *)(param_1 + 6))) {
64: ppcVar6 = (code **)*param_1;
65: ppcVar6[5] = (code *)0xffff00000029;
66: (**ppcVar6)(param_1);
67: }
68: plVar7 = (long *)param_1[5];
69: uVar3 = *(undefined4 *)(param_1 + 9);
70: puVar5 = (undefined *)*plVar7;
71: *plVar7 = (long)(puVar5 + 1);
72: *puVar5 = (char)uVar3;
73: plVar1 = plVar7 + 1;
74: *plVar1 = *plVar1 + -1;
75: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
76: ppcVar6 = (code **)*param_1;
77: *(undefined4 *)(ppcVar6 + 5) = 0x18;
78: (**ppcVar6)(param_1);
79: }
80: plVar7 = (long *)param_1[5];
81: uVar3 = *(undefined4 *)((long)param_1 + 0x34);
82: puVar5 = (undefined *)*plVar7;
83: *plVar7 = (long)(puVar5 + 1);
84: *puVar5 = (char)((uint)uVar3 >> 8);
85: plVar1 = plVar7 + 1;
86: *plVar1 = *plVar1 + -1;
87: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
88: ppcVar6 = (code **)*param_1;
89: *(undefined4 *)(ppcVar6 + 5) = 0x18;
90: (**ppcVar6)(param_1);
91: }
92: plVar7 = (long *)param_1[5];
93: puVar5 = (undefined *)*plVar7;
94: *plVar7 = (long)(puVar5 + 1);
95: *puVar5 = (char)uVar3;
96: plVar1 = plVar7 + 1;
97: *plVar1 = *plVar1 + -1;
98: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
99: ppcVar6 = (code **)*param_1;
100: *(undefined4 *)(ppcVar6 + 5) = 0x18;
101: (**ppcVar6)(param_1);
102: }
103: plVar7 = (long *)param_1[5];
104: uVar3 = *(undefined4 *)(param_1 + 6);
105: puVar5 = (undefined *)*plVar7;
106: *plVar7 = (long)(puVar5 + 1);
107: *puVar5 = (char)((uint)uVar3 >> 8);
108: plVar1 = plVar7 + 1;
109: *plVar1 = *plVar1 + -1;
110: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
111: ppcVar6 = (code **)*param_1;
112: *(undefined4 *)(ppcVar6 + 5) = 0x18;
113: (**ppcVar6)(param_1);
114: }
115: plVar7 = (long *)param_1[5];
116: puVar5 = (undefined *)*plVar7;
117: *plVar7 = (long)(puVar5 + 1);
118: *puVar5 = (char)uVar3;
119: plVar1 = plVar7 + 1;
120: *plVar1 = *plVar1 + -1;
121: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
122: ppcVar6 = (code **)*param_1;
123: *(undefined4 *)(ppcVar6 + 5) = 0x18;
124: (**ppcVar6)(param_1);
125: }
126: plVar7 = (long *)param_1[5];
127: uVar3 = *(undefined4 *)((long)param_1 + 0x4c);
128: puVar5 = (undefined *)*plVar7;
129: *plVar7 = (long)(puVar5 + 1);
130: *puVar5 = (char)uVar3;
131: plVar1 = plVar7 + 1;
132: *plVar1 = *plVar1 + -1;
133: if ((*plVar1 == 0) && (iVar10 = (*(code *)plVar7[3])(param_1), iVar10 == 0)) {
134: ppcVar6 = (code **)*param_1;
135: *(undefined4 *)(ppcVar6 + 5) = 0x18;
136: (**ppcVar6)(param_1);
137: }
138: puVar12 = (undefined4 *)param_1[0xb];
139: if (0 < *(int *)((long)param_1 + 0x4c)) {
140: iVar10 = 0;
141: do {
142: plVar7 = (long *)param_1[5];
143: uVar3 = *puVar12;
144: puVar5 = (undefined *)*plVar7;
145: *plVar7 = (long)(puVar5 + 1);
146: *puVar5 = (char)uVar3;
147: plVar1 = plVar7 + 1;
148: *plVar1 = *plVar1 + -1;
149: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar7[3])(param_1), iVar11 == 0)) {
150: ppcVar6 = (code **)*param_1;
151: *(undefined4 *)(ppcVar6 + 5) = 0x18;
152: (**ppcVar6)(param_1);
153: }
154: ppcVar8 = (char **)param_1[5];
155: iVar11 = puVar12[2];
156: pcVar9 = *ppcVar8;
157: uVar3 = puVar12[3];
158: *ppcVar8 = pcVar9 + 1;
159: *pcVar9 = (char)(iVar11 << 4) + (char)uVar3;
160: ppcVar2 = ppcVar8 + 1;
161: *ppcVar2 = *ppcVar2 + -1;
162: if ((*ppcVar2 == (char *)0x0) && (iVar11 = (*(code *)ppcVar8[3])(param_1), iVar11 == 0)) {
163: ppcVar6 = (code **)*param_1;
164: *(undefined4 *)(ppcVar6 + 5) = 0x18;
165: (**ppcVar6)(param_1);
166: }
167: plVar7 = (long *)param_1[5];
168: uVar3 = puVar12[4];
169: puVar5 = (undefined *)*plVar7;
170: *plVar7 = (long)(puVar5 + 1);
171: *puVar5 = (char)uVar3;
172: plVar1 = plVar7 + 1;
173: *plVar1 = *plVar1 + -1;
174: if ((*plVar1 == 0) && (iVar11 = (*(code *)plVar7[3])(param_1), iVar11 == 0)) {
175: ppcVar6 = (code **)*param_1;
176: *(undefined4 *)(ppcVar6 + 5) = 0x18;
177: (**ppcVar6)(param_1);
178: }
179: iVar10 = iVar10 + 1;
180: puVar12 = puVar12 + 0x18;
181: } while (*(int *)((long)param_1 + 0x4c) != iVar10 && iVar10 <= *(int *)((long)param_1 + 0x4c));
182: }
183: return;
184: }
185: 

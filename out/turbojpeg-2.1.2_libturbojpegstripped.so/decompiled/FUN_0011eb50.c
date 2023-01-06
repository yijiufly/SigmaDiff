1: 
2: void FUN_0011eb50(code **param_1)
3: 
4: {
5: int *piVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: undefined8 uVar5;
10: int iVar6;
11: undefined8 uVar7;
12: 
13: pcVar2 = param_1[0x36];
14: iVar6 = *(int *)(pcVar2 + 0x20);
15: if (iVar6 == 1) {
16: if (param_1[0x1f] == (code *)0x0) {
17: iVar6 = *(int *)((long)param_1 + 0x4c);
18: if (4 < iVar6) {
19: ppcVar3 = (code **)*param_1;
20: *(int *)((long)ppcVar3 + 0x2c) = iVar6;
21: *(undefined4 *)(ppcVar3 + 5) = 0x1a;
22: *(undefined4 *)(ppcVar3 + 6) = 4;
23: (**ppcVar3)();
24: iVar6 = *(int *)((long)param_1 + 0x4c);
25: }
26: *(int *)((long)param_1 + 0x144) = iVar6;
27: if (0 < iVar6) {
28: pcVar4 = param_1[0xb];
29: param_1[0x29] = pcVar4;
30: if (((iVar6 != 1) && (param_1[0x2a] = pcVar4 + 0x60, iVar6 != 2)) &&
31: (param_1[0x2b] = pcVar4 + 0xc0, iVar6 != 3)) {
32: param_1[0x2c] = pcVar4 + 0x120;
33: }
34: }
35: uVar7 = 0x3f00000000;
36: *(undefined8 *)((long)param_1 + 0x19c) = 0x3f00000000;
37: *(undefined8 *)((long)param_1 + 0x1a4) = 0;
38: }
39: else {
40: piVar1 = (int *)(param_1[0x1f] + (long)*(int *)(pcVar2 + 0x2c) * 0x24);
41: iVar6 = *piVar1;
42: *(int *)((long)param_1 + 0x144) = iVar6;
43: if (0 < iVar6) {
44: pcVar4 = param_1[0xb];
45: param_1[0x29] = pcVar4 + (long)piVar1[1] * 0x60;
46: if (((iVar6 != 1) && (param_1[0x2a] = pcVar4 + (long)piVar1[2] * 0x60, iVar6 != 2)) &&
47: (param_1[0x2b] = pcVar4 + (long)piVar1[3] * 0x60, iVar6 != 3)) {
48: param_1[0x2c] = pcVar4 + (long)piVar1[4] * 0x60;
49: }
50: }
51: uVar7 = *(undefined8 *)(piVar1 + 5);
52: uVar5 = *(undefined8 *)(piVar1 + 7);
53: *(undefined8 *)((long)param_1 + 0x19c) = uVar7;
54: *(undefined8 *)((long)param_1 + 0x1a4) = uVar5;
55: }
56: FUN_0011e8e0(uVar7);
57: if (((*(int *)((long)param_1 + 0x19c) != 0) || (*(int *)((long)param_1 + 0x1a4) == 0)) ||
58: (*(int *)((long)param_1 + 0x104) != 0)) {
59: (**(code **)param_1[0x3e])(param_1,1);
60: (**(code **)param_1[0x39])(param_1,2);
61: *(undefined4 *)(pcVar2 + 0x18) = 0;
62: goto LAB_0011eb83;
63: }
64: *(int *)(pcVar2 + 0x24) = *(int *)(pcVar2 + 0x24) + 1;
65: *(undefined4 *)(pcVar2 + 0x20) = 2;
66: }
67: else {
68: if (iVar6 == 0) {
69: if (param_1[0x1f] == (code *)0x0) {
70: iVar6 = *(int *)((long)param_1 + 0x4c);
71: if (4 < iVar6) {
72: ppcVar3 = (code **)*param_1;
73: *(int *)((long)ppcVar3 + 0x2c) = iVar6;
74: *(undefined4 *)(ppcVar3 + 5) = 0x1a;
75: *(undefined4 *)(ppcVar3 + 6) = 4;
76: (**ppcVar3)();
77: iVar6 = *(int *)((long)param_1 + 0x4c);
78: }
79: *(int *)((long)param_1 + 0x144) = iVar6;
80: if (0 < iVar6) {
81: pcVar4 = param_1[0xb];
82: param_1[0x29] = pcVar4;
83: if (((iVar6 != 1) && (param_1[0x2a] = pcVar4 + 0x60, iVar6 != 2)) &&
84: (param_1[0x2b] = pcVar4 + 0xc0, iVar6 != 3)) {
85: param_1[0x2c] = pcVar4 + 0x120;
86: }
87: }
88: uVar7 = 0x3f00000000;
89: *(undefined8 *)((long)param_1 + 0x19c) = 0x3f00000000;
90: *(undefined8 *)((long)param_1 + 0x1a4) = 0;
91: }
92: else {
93: piVar1 = (int *)(param_1[0x1f] + (long)*(int *)(pcVar2 + 0x2c) * 0x24);
94: iVar6 = *piVar1;
95: *(int *)((long)param_1 + 0x144) = iVar6;
96: if (0 < iVar6) {
97: pcVar4 = param_1[0xb];
98: param_1[0x29] = pcVar4 + (long)piVar1[1] * 0x60;
99: if (((iVar6 != 1) && (param_1[0x2a] = pcVar4 + (long)piVar1[2] * 0x60, iVar6 != 2)) &&
100: (param_1[0x2b] = pcVar4 + (long)piVar1[3] * 0x60, iVar6 != 3)) {
101: param_1[0x2c] = pcVar4 + (long)piVar1[4] * 0x60;
102: }
103: }
104: uVar7 = *(undefined8 *)(piVar1 + 5);
105: uVar5 = *(undefined8 *)(piVar1 + 7);
106: *(undefined8 *)((long)param_1 + 0x19c) = uVar7;
107: *(undefined8 *)((long)param_1 + 0x1a4) = uVar5;
108: }
109: FUN_0011e8e0(uVar7,param_1);
110: if (*(int *)(param_1 + 0x20) == 0) {
111: (**(code **)param_1[0x3b])(param_1);
112: (**(code **)param_1[0x3c])(param_1);
113: (**(code **)param_1[0x38])(param_1,0);
114: }
115: (**(code **)param_1[0x3d])(param_1);
116: (**(code **)param_1[0x3e])(param_1,*(undefined4 *)(param_1 + 0x21));
117: (**(code **)param_1[0x39])(param_1,(1 < *(int *)(pcVar2 + 0x28)) * '\x03');
118: (**(code **)param_1[0x37])(param_1,0);
119: *(uint *)(pcVar2 + 0x18) = (uint)(*(int *)(param_1 + 0x21) == 0);
120: goto LAB_0011eb83;
121: }
122: if (iVar6 != 2) {
123: ppcVar3 = (code **)*param_1;
124: *(undefined4 *)(ppcVar3 + 5) = 0x30;
125: (**ppcVar3)();
126: goto LAB_0011eb83;
127: }
128: }
129: if (*(int *)(param_1 + 0x21) == 0) {
130: if (param_1[0x1f] == (code *)0x0) {
131: iVar6 = *(int *)((long)param_1 + 0x4c);
132: if (4 < iVar6) {
133: ppcVar3 = (code **)*param_1;
134: *(int *)((long)ppcVar3 + 0x2c) = iVar6;
135: *(undefined4 *)(ppcVar3 + 5) = 0x1a;
136: *(undefined4 *)(ppcVar3 + 6) = 4;
137: (**ppcVar3)(param_1);
138: iVar6 = *(int *)((long)param_1 + 0x4c);
139: }
140: *(int *)((long)param_1 + 0x144) = iVar6;
141: if (0 < iVar6) {
142: pcVar4 = param_1[0xb];
143: param_1[0x29] = pcVar4;
144: if (((iVar6 != 1) && (param_1[0x2a] = pcVar4 + 0x60, iVar6 != 2)) &&
145: (param_1[0x2b] = pcVar4 + 0xc0, iVar6 != 3)) {
146: param_1[0x2c] = pcVar4 + 0x120;
147: }
148: }
149: uVar7 = 0x3f00000000;
150: *(undefined8 *)((long)param_1 + 0x19c) = 0x3f00000000;
151: *(undefined8 *)((long)param_1 + 0x1a4) = 0;
152: }
153: else {
154: piVar1 = (int *)(param_1[0x1f] + (long)*(int *)(param_1[0x36] + 0x2c) * 0x24);
155: iVar6 = *piVar1;
156: *(int *)((long)param_1 + 0x144) = iVar6;
157: if (0 < iVar6) {
158: pcVar4 = param_1[0xb];
159: param_1[0x29] = pcVar4 + (long)piVar1[1] * 0x60;
160: if (((iVar6 != 1) && (param_1[0x2a] = pcVar4 + (long)piVar1[2] * 0x60, iVar6 != 2)) &&
161: (param_1[0x2b] = pcVar4 + (long)piVar1[3] * 0x60, iVar6 != 3)) {
162: param_1[0x2c] = pcVar4 + (long)piVar1[4] * 0x60;
163: }
164: }
165: uVar7 = *(undefined8 *)(piVar1 + 5);
166: uVar5 = *(undefined8 *)(piVar1 + 7);
167: *(undefined8 *)((long)param_1 + 0x19c) = uVar7;
168: *(undefined8 *)((long)param_1 + 0x1a4) = uVar5;
169: }
170: FUN_0011e8e0(uVar7,param_1);
171: }
172: (**(code **)param_1[0x3e])(param_1,0);
173: (**(code **)param_1[0x39])(param_1,2);
174: if (*(int *)(pcVar2 + 0x2c) == 0) {
175: (**(code **)(param_1[0x3a] + 8))(param_1);
176: }
177: (**(code **)(param_1[0x3a] + 0x10))(param_1);
178: *(undefined4 *)(pcVar2 + 0x18) = 0;
179: LAB_0011eb83:
180: iVar6 = *(int *)(pcVar2 + 0x28);
181: *(uint *)(pcVar2 + 0x1c) = (uint)(iVar6 + -1 == *(int *)(pcVar2 + 0x24));
182: pcVar4 = param_1[2];
183: if (pcVar4 != (code *)0x0) {
184: *(int *)(pcVar4 + 0x18) = *(int *)(pcVar2 + 0x24);
185: *(int *)(pcVar4 + 0x1c) = iVar6;
186: }
187: return;
188: }
189: 

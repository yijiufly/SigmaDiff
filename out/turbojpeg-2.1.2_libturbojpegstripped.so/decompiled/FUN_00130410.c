1: 
2: void FUN_00130410(long *param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined4 uVar3;
8: long lVar4;
9: uint uVar5;
10: long lVar6;
11: bool bVar7;
12: 
13: lVar4 = param_1[0x4a];
14: if (((*(int *)((long)param_1 + 0x20c) != 0) || (param_1[0x42] != 0x3f)) ||
15: (*(int *)(param_1 + 0x43) != 0)) {
16: lVar6 = *param_1;
17: *(undefined4 *)(lVar6 + 0x28) = 0x7a;
18: (**(code **)(lVar6 + 8))();
19: }
20: if (0 < *(int *)(param_1 + 0x36)) {
21: lVar6 = 1;
22: do {
23: iVar1 = *(int *)(param_1[lVar6 + 0x36] + 0x14);
24: iVar2 = *(int *)(param_1[lVar6 + 0x36] + 0x18);
25: FUN_0012fb00(param_1,1,iVar1,lVar4 + 0x40 + (long)iVar1 * 8);
26: FUN_0012fb00(param_1,0,iVar2,lVar4 + 0x60 + (long)iVar2 * 8);
27: *(undefined4 *)(lVar4 + 0x24 + lVar6 * 4) = 0;
28: iVar1 = (int)lVar6;
29: lVar6 = lVar6 + 1;
30: } while (*(int *)(param_1 + 0x36) != iVar1 && iVar1 <= *(int *)(param_1 + 0x36));
31: }
32: iVar1 = *(int *)(param_1 + 0x3c);
33: if (0 < iVar1) {
34: lVar6 = param_1[(long)*(int *)((long)param_1 + 0x1e4) + 0x37];
35: bVar7 = *(int *)(lVar6 + 0x30) != 0;
36: *(undefined8 *)(lVar4 + 0x80) = *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8)
37: ;
38: *(undefined8 *)(lVar4 + 0xd0) = *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8)
39: ;
40: if (bVar7) {
41: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
42: }
43: else {
44: uVar5 = 0;
45: }
46: *(uint *)(lVar4 + 0x148) = uVar5;
47: *(uint *)(lVar4 + 0x120) = (uint)bVar7;
48: if (iVar1 != 1) {
49: lVar6 = param_1[(long)*(int *)(param_1 + 0x3d) + 0x37];
50: bVar7 = *(int *)(lVar6 + 0x30) == 0;
51: *(undefined8 *)(lVar4 + 0x88) =
52: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
53: *(undefined8 *)(lVar4 + 0xd8) =
54: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
55: if (bVar7) {
56: uVar5 = 0;
57: }
58: else {
59: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
60: }
61: *(uint *)(lVar4 + 0x14c) = uVar5;
62: *(uint *)(lVar4 + 0x124) = (uint)!bVar7;
63: if (iVar1 != 2) {
64: lVar6 = param_1[(long)*(int *)((long)param_1 + 0x1ec) + 0x37];
65: bVar7 = *(int *)(lVar6 + 0x30) == 0;
66: *(undefined8 *)(lVar4 + 0x90) =
67: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
68: *(undefined8 *)(lVar4 + 0xe0) =
69: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
70: if (bVar7) {
71: uVar5 = 0;
72: }
73: else {
74: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
75: }
76: *(uint *)(lVar4 + 0x150) = uVar5;
77: *(uint *)(lVar4 + 0x128) = (uint)!bVar7;
78: if (iVar1 != 3) {
79: lVar6 = param_1[(long)*(int *)(param_1 + 0x3e) + 0x37];
80: bVar7 = *(int *)(lVar6 + 0x30) == 0;
81: *(undefined8 *)(lVar4 + 0x98) =
82: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
83: *(undefined8 *)(lVar4 + 0xe8) =
84: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
85: if (bVar7) {
86: uVar5 = 0;
87: }
88: else {
89: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
90: }
91: *(uint *)(lVar4 + 0x154) = uVar5;
92: *(uint *)(lVar4 + 300) = (uint)!bVar7;
93: if (iVar1 != 4) {
94: lVar6 = param_1[(long)*(int *)((long)param_1 + 500) + 0x37];
95: bVar7 = *(int *)(lVar6 + 0x30) == 0;
96: *(undefined8 *)(lVar4 + 0xa0) =
97: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
98: *(undefined8 *)(lVar4 + 0xf0) =
99: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
100: if (bVar7) {
101: uVar5 = 0;
102: }
103: else {
104: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
105: }
106: *(uint *)(lVar4 + 0x158) = uVar5;
107: *(uint *)(lVar4 + 0x130) = (uint)!bVar7;
108: if (iVar1 != 5) {
109: lVar6 = param_1[(long)*(int *)(param_1 + 0x3f) + 0x37];
110: bVar7 = *(int *)(lVar6 + 0x30) != 0;
111: *(undefined8 *)(lVar4 + 0xa8) =
112: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
113: *(undefined8 *)(lVar4 + 0xf8) =
114: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
115: if (bVar7) {
116: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
117: }
118: else {
119: uVar5 = 0;
120: }
121: *(uint *)(lVar4 + 0x15c) = uVar5;
122: *(uint *)(lVar4 + 0x134) = (uint)bVar7;
123: if (iVar1 != 6) {
124: lVar6 = param_1[(long)*(int *)((long)param_1 + 0x1fc) + 0x37];
125: bVar7 = *(int *)(lVar6 + 0x30) == 0;
126: *(undefined8 *)(lVar4 + 0xb0) =
127: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
128: *(undefined8 *)(lVar4 + 0x100) =
129: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
130: if (bVar7) {
131: uVar5 = 0;
132: }
133: else {
134: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
135: }
136: *(uint *)(lVar4 + 0x160) = uVar5;
137: *(uint *)(lVar4 + 0x138) = (uint)!bVar7;
138: if (iVar1 != 7) {
139: lVar6 = param_1[(long)*(int *)(param_1 + 0x40) + 0x37];
140: bVar7 = *(int *)(lVar6 + 0x30) == 0;
141: *(undefined8 *)(lVar4 + 0xb8) =
142: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
143: *(undefined8 *)(lVar4 + 0x108) =
144: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
145: if (bVar7) {
146: uVar5 = 0;
147: }
148: else {
149: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
150: }
151: *(uint *)(lVar4 + 0x164) = uVar5;
152: *(uint *)(lVar4 + 0x13c) = (uint)!bVar7;
153: if (iVar1 != 8) {
154: lVar6 = param_1[(long)*(int *)((long)param_1 + 0x204) + 0x37];
155: *(undefined8 *)(lVar4 + 0xc0) =
156: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
157: *(undefined8 *)(lVar4 + 0x110) =
158: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
159: bVar7 = *(int *)(lVar6 + 0x30) == 0;
160: if (bVar7) {
161: uVar5 = 0;
162: }
163: else {
164: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
165: }
166: *(uint *)(lVar4 + 0x168) = uVar5;
167: *(uint *)(lVar4 + 0x140) = (uint)!bVar7;
168: if (iVar1 != 9) {
169: lVar6 = param_1[(long)*(int *)(param_1 + 0x41) + 0x37];
170: *(undefined8 *)(lVar4 + 200) =
171: *(undefined8 *)(lVar4 + 0x40 + (long)*(int *)(lVar6 + 0x14) * 8);
172: *(undefined8 *)(lVar4 + 0x118) =
173: *(undefined8 *)(lVar4 + 0x60 + (long)*(int *)(lVar6 + 0x18) * 8);
174: bVar7 = *(int *)(lVar6 + 0x30) == 0;
175: if (bVar7) {
176: uVar5 = 0;
177: }
178: else {
179: uVar5 = (uint)(1 < *(int *)(lVar6 + 0x24));
180: }
181: *(uint *)(lVar4 + 0x16c) = uVar5;
182: *(uint *)(lVar4 + 0x144) = (uint)!bVar7;
183: }
184: }
185: }
186: }
187: }
188: }
189: }
190: }
191: }
192: }
193: uVar3 = *(undefined4 *)(param_1 + 0x2e);
194: *(undefined4 *)(lVar4 + 0x20) = 0;
195: *(undefined8 *)(lVar4 + 0x18) = 0;
196: *(undefined4 *)(lVar4 + 0x10) = 0;
197: *(undefined4 *)(lVar4 + 0x38) = uVar3;
198: return;
199: }
200: 

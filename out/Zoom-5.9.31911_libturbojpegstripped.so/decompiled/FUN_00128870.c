1: 
2: undefined8 FUN_00128870(code **param_1)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: int iVar5;
10: undefined4 uVar6;
11: undefined8 uVar7;
12: int iVar8;
13: long lVar9;
14: code *pcVar10;
15: int iVar11;
16: int iVar12;
17: int iVar13;
18: 
19: pcVar2 = param_1[0x48];
20: if (*(int *)(pcVar2 + 0x24) == 0) {
21: uVar7 = (**(code **)(param_1[0x49] + 8))();
22: if ((int)uVar7 == 1) {
23: if (*(int *)(pcVar2 + 0x28) == 0) {
24: if (*(int *)(pcVar2 + 0x20) == 0) {
25: ppcVar3 = (code **)*param_1;
26: *(undefined4 *)(ppcVar3 + 5) = 0x23;
27: (**ppcVar3)(param_1);
28: }
29: FUN_00128130(param_1);
30: return 1;
31: }
32: if ((0xffdc < *(uint *)((long)param_1 + 0x34)) || (0xffdc < *(uint *)(param_1 + 6))) {
33: pcVar10 = *param_1;
34: *(undefined4 *)(pcVar10 + 0x28) = 0x29;
35: *(undefined4 *)(pcVar10 + 0x2c) = 0xffdc;
36: (**(code **)*param_1)();
37: }
38: if (*(int *)(param_1 + 0x25) != 8) {
39: pcVar10 = *param_1;
40: *(int *)(pcVar10 + 0x2c) = *(int *)(param_1 + 0x25);
41: ppcVar3 = (code **)*param_1;
42: *(undefined4 *)(pcVar10 + 0x28) = 0xf;
43: (**ppcVar3)();
44: }
45: iVar13 = *(int *)(param_1 + 7);
46: if (10 < iVar13) {
47: pcVar10 = *param_1;
48: *(int *)(pcVar10 + 0x2c) = iVar13;
49: *(undefined4 *)(pcVar10 + 0x28) = 0x1a;
50: *(undefined4 *)(*param_1 + 0x30) = 10;
51: (**(code **)*param_1)();
52: iVar13 = *(int *)(param_1 + 7);
53: }
54: *(undefined4 *)(param_1 + 0x33) = 1;
55: *(undefined4 *)((long)param_1 + 0x19c) = 1;
56: pcVar10 = param_1[0x26];
57: if (iVar13 < 1) {
58: *(undefined4 *)(param_1 + 0x34) = 8;
59: }
60: else {
61: iVar5 = 1;
62: iVar11 = 1;
63: iVar12 = 0;
64: do {
65: iVar1 = *(int *)(pcVar10 + 8);
66: if ((3 < iVar1 - 1U) || (iVar8 = *(int *)(pcVar10 + 0xc), 3 < iVar8 - 1U)) {
67: *(undefined4 *)(*param_1 + 0x28) = 0x12;
68: (**(code **)*param_1)();
69: iVar1 = *(int *)(pcVar10 + 8);
70: iVar8 = *(int *)(pcVar10 + 0xc);
71: iVar11 = *(int *)(param_1 + 0x33);
72: iVar5 = *(int *)((long)param_1 + 0x19c);
73: iVar13 = *(int *)(param_1 + 7);
74: }
75: if (iVar11 < iVar1) {
76: iVar11 = iVar1;
77: }
78: if (iVar5 < iVar8) {
79: iVar5 = iVar8;
80: }
81: iVar12 = iVar12 + 1;
82: pcVar10 = pcVar10 + 0x60;
83: *(int *)(param_1 + 0x33) = iVar11;
84: *(int *)((long)param_1 + 0x19c) = iVar5;
85: } while (iVar12 < iVar13);
86: *(undefined4 *)(param_1 + 0x34) = 8;
87: if (0 < iVar13) {
88: iVar13 = 0;
89: pcVar10 = param_1[0x26];
90: while( true ) {
91: *(undefined4 *)(pcVar10 + 0x24) = 8;
92: uVar6 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar10 + 8),
93: (long)(iVar11 << 3));
94: *(undefined4 *)(pcVar10 + 0x1c) = uVar6;
95: uVar6 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) *
96: (long)*(int *)(pcVar10 + 0xc),
97: (long)(*(int *)((long)param_1 + 0x19c) * 8));
98: iVar11 = *(int *)(pcVar10 + 0x1c);
99: *(undefined4 *)(pcVar10 + 0x20) = uVar6;
100: lVar9 = (long)iVar13;
101: pcVar4 = param_1[0x44];
102: iVar13 = iVar13 + 1;
103: *(undefined4 *)(pcVar4 + lVar9 * 4 + 0x1c) = 0;
104: *(int *)(pcVar4 + lVar9 * 4 + 0x44) = iVar11 + -1;
105: uVar6 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar10 + 8),
106: (long)*(int *)(param_1 + 0x33));
107: *(undefined4 *)(pcVar10 + 0x28) = uVar6;
108: uVar6 = FUN_0013be20();
109: *(undefined4 *)(pcVar10 + 0x30) = 1;
110: *(undefined4 *)(pcVar10 + 0x2c) = uVar6;
111: *(undefined8 *)(pcVar10 + 0x50) = 0;
112: if (*(int *)(param_1 + 7) <= iVar13) break;
113: iVar11 = *(int *)(param_1 + 0x33);
114: pcVar10 = pcVar10 + 0x60;
115: }
116: }
117: }
118: uVar6 = FUN_0013be20(*(undefined4 *)((long)param_1 + 0x34));
119: *(undefined4 *)((long)param_1 + 0x1a4) = uVar6;
120: if ((*(int *)(param_1 + 0x36) < *(int *)(param_1 + 7)) || (*(int *)(param_1 + 0x27) != 0)) {
121: *(undefined4 *)(param_1[0x48] + 0x20) = 1;
122: }
123: else {
124: *(undefined4 *)(param_1[0x48] + 0x20) = 0;
125: }
126: *(undefined4 *)(pcVar2 + 0x28) = 0;
127: return 1;
128: }
129: if ((int)uVar7 != 2) {
130: return uVar7;
131: }
132: *(undefined4 *)(pcVar2 + 0x24) = 1;
133: if (*(int *)(pcVar2 + 0x28) == 0) {
134: iVar13 = *(int *)((long)param_1 + 0xac);
135: if (*(int *)((long)param_1 + 0xb4) != iVar13 && iVar13 <= *(int *)((long)param_1 + 0xb4)) {
136: *(int *)((long)param_1 + 0xb4) = iVar13;
137: }
138: }
139: else {
140: if (*(int *)(param_1[0x49] + 0x1c) != 0) {
141: ppcVar3 = (code **)*param_1;
142: *(undefined4 *)(ppcVar3 + 5) = 0x3b;
143: (**ppcVar3)(param_1);
144: return 2;
145: }
146: }
147: }
148: return 2;
149: }
150: 

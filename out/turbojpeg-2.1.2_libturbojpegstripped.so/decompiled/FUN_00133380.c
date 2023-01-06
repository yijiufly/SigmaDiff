1: 
2: int FUN_00133380(code **param_1)
3: 
4: {
5: int iVar1;
6: uint uVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: int iVar6;
11: int iVar7;
12: undefined4 uVar8;
13: int iVar9;
14: long lVar10;
15: code *pcVar11;
16: int iVar12;
17: int iVar13;
18: int iVar14;
19: 
20: pcVar3 = param_1[0x48];
21: if (*(int *)(pcVar3 + 0x24) != 0) {
22: return 2;
23: }
24: iVar6 = (**(code **)(param_1[0x49] + 8))();
25: if (iVar6 == 1) {
26: if (*(int *)(pcVar3 + 0x28) == 0) {
27: if (*(int *)(pcVar3 + 0x20) == 0) {
28: ppcVar4 = (code **)*param_1;
29: *(undefined4 *)(ppcVar4 + 5) = 0x23;
30: (**ppcVar4)(param_1);
31: }
32: FUN_00132db0(param_1);
33: return 1;
34: }
35: if ((0xffdc < *(uint *)((long)param_1 + 0x34)) || (0xffdc < *(uint *)(param_1 + 6))) {
36: ppcVar4 = (code **)*param_1;
37: ppcVar4[5] = (code *)0xffdc00000029;
38: (**ppcVar4)();
39: }
40: iVar14 = *(int *)(param_1 + 0x25);
41: if (iVar14 != 8) {
42: ppcVar4 = (code **)*param_1;
43: *(undefined4 *)(ppcVar4 + 5) = 0xf;
44: *(int *)((long)ppcVar4 + 0x2c) = iVar14;
45: (**ppcVar4)();
46: }
47: iVar14 = *(int *)(param_1 + 7);
48: if (10 < iVar14) {
49: ppcVar4 = (code **)*param_1;
50: *(int *)((long)ppcVar4 + 0x2c) = iVar14;
51: *(undefined4 *)(ppcVar4 + 5) = 0x1a;
52: *(undefined4 *)(ppcVar4 + 6) = 10;
53: (**ppcVar4)();
54: iVar14 = *(int *)(param_1 + 7);
55: }
56: pcVar11 = param_1[0x26];
57: param_1[0x33] = (code *)0x100000001;
58: if (iVar14 < 1) {
59: *(undefined4 *)(param_1 + 0x34) = 8;
60: }
61: else {
62: iVar7 = 1;
63: iVar12 = 1;
64: iVar13 = 0;
65: do {
66: iVar1 = *(int *)(pcVar11 + 8);
67: if ((3 < iVar1 - 1U) || (iVar9 = *(int *)(pcVar11 + 0xc), 3 < iVar9 - 1U)) {
68: ppcVar4 = (code **)*param_1;
69: *(undefined4 *)(ppcVar4 + 5) = 0x12;
70: (**ppcVar4)();
71: iVar1 = *(int *)(pcVar11 + 8);
72: iVar9 = *(int *)(pcVar11 + 0xc);
73: iVar12 = *(int *)(param_1 + 0x33);
74: iVar7 = *(int *)((long)param_1 + 0x19c);
75: iVar14 = *(int *)(param_1 + 7);
76: }
77: if (iVar12 < iVar1) {
78: iVar12 = iVar1;
79: }
80: if (iVar7 < iVar9) {
81: iVar7 = iVar9;
82: }
83: iVar13 = iVar13 + 1;
84: pcVar11 = pcVar11 + 0x60;
85: *(int *)(param_1 + 0x33) = iVar12;
86: *(int *)((long)param_1 + 0x19c) = iVar7;
87: } while (iVar13 < iVar14);
88: *(undefined4 *)(param_1 + 0x34) = 8;
89: if (0 < iVar14) {
90: iVar14 = 0;
91: pcVar11 = param_1[0x26];
92: while( true ) {
93: *(undefined4 *)(pcVar11 + 0x24) = 8;
94: uVar8 = FUN_001489d0((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar11 + 8),
95: (long)(iVar12 << 3));
96: *(undefined4 *)(pcVar11 + 0x1c) = uVar8;
97: uVar8 = FUN_001489d0((ulong)*(uint *)((long)param_1 + 0x34) *
98: (long)*(int *)(pcVar11 + 0xc),
99: (long)(*(int *)((long)param_1 + 0x19c) * 8));
100: *(undefined4 *)(pcVar11 + 0x20) = uVar8;
101: pcVar5 = param_1[0x44];
102: lVar10 = (long)iVar14;
103: uVar2 = *(uint *)(param_1 + 6);
104: iVar12 = *(int *)(param_1 + 0x33);
105: iVar14 = iVar14 + 1;
106: *(undefined4 *)(pcVar5 + lVar10 * 4 + 0x1c) = 0;
107: *(int *)(pcVar5 + lVar10 * 4 + 0x44) = *(int *)(pcVar11 + 0x1c) + -1;
108: uVar8 = FUN_001489d0((ulong)uVar2 * (long)*(int *)(pcVar11 + 8),(long)iVar12);
109: *(undefined4 *)(pcVar11 + 0x28) = uVar8;
110: uVar8 = FUN_001489d0();
111: *(undefined4 *)(pcVar11 + 0x30) = 1;
112: *(undefined4 *)(pcVar11 + 0x2c) = uVar8;
113: *(undefined8 *)(pcVar11 + 0x50) = 0;
114: if (*(int *)(param_1 + 7) <= iVar14) break;
115: iVar12 = *(int *)(param_1 + 0x33);
116: pcVar11 = pcVar11 + 0x60;
117: }
118: }
119: }
120: uVar8 = FUN_001489d0(*(undefined4 *)((long)param_1 + 0x34));
121: *(undefined4 *)((long)param_1 + 0x1a4) = uVar8;
122: if ((*(int *)(param_1 + 0x36) < *(int *)(param_1 + 7)) || (*(int *)(param_1 + 0x27) != 0)) {
123: *(undefined4 *)(param_1[0x48] + 0x20) = 1;
124: }
125: else {
126: *(undefined4 *)(param_1[0x48] + 0x20) = 0;
127: }
128: *(undefined4 *)(pcVar3 + 0x28) = 0;
129: }
130: else {
131: if (iVar6 == 2) {
132: *(undefined4 *)(pcVar3 + 0x24) = 1;
133: if (*(int *)(pcVar3 + 0x28) == 0) {
134: iVar14 = *(int *)((long)param_1 + 0xac);
135: if (*(int *)((long)param_1 + 0xb4) == iVar14 || *(int *)((long)param_1 + 0xb4) < iVar14) {
136: return 2;
137: }
138: *(int *)((long)param_1 + 0xb4) = iVar14;
139: }
140: else {
141: if (*(int *)(param_1[0x49] + 0x1c) == 0) {
142: return 2;
143: }
144: ppcVar4 = (code **)*param_1;
145: *(undefined4 *)(ppcVar4 + 5) = 0x3b;
146: (**ppcVar4)(param_1);
147: }
148: }
149: }
150: return iVar6;
151: }
152: 

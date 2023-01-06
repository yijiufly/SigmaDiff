1: 
2: void FUN_0011f0b0(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: uint uVar3;
8: int iVar4;
9: undefined4 uVar5;
10: code **ppcVar6;
11: int iVar7;
12: code *pcVar8;
13: int iVar9;
14: long lVar10;
15: int iVar11;
16: int iVar12;
17: 
18: ppcVar6 = (code **)(**(code **)param_1[1])(param_1,1,0x38);
19: param_1[0x36] = (code *)ppcVar6;
20: *(undefined4 *)((long)ppcVar6 + 0x1c) = 0;
21: *ppcVar6 = FUN_0011eb50;
22: ppcVar6[1] = FUN_0011e820;
23: ppcVar6[2] = FUN_0011e850;
24: uVar3 = *(uint *)((long)param_1 + 0x34);
25: if ((((uVar3 == 0) || (*(int *)(param_1 + 6) == 0)) || (*(int *)((long)param_1 + 0x4c) < 1)) ||
26: (*(int *)(param_1 + 7) < 1)) {
27: ppcVar2 = (code **)*param_1;
28: *(undefined4 *)(ppcVar2 + 5) = 0x20;
29: (**ppcVar2)();
30: uVar3 = *(uint *)((long)param_1 + 0x34);
31: }
32: if ((0xffdc < uVar3) || (uVar3 = *(uint *)(param_1 + 6), 0xffdc < uVar3)) {
33: ppcVar2 = (code **)*param_1;
34: ppcVar2[5] = (code *)0xffdc00000029;
35: (**ppcVar2)();
36: uVar3 = *(uint *)(param_1 + 6);
37: }
38: if ((long)*(int *)(param_1 + 7) * (ulong)uVar3 -
39: ((long)*(int *)(param_1 + 7) * (ulong)uVar3 & 0xffffffff) != 0) {
40: ppcVar2 = (code **)*param_1;
41: *(undefined4 *)(ppcVar2 + 5) = 0x46;
42: (**ppcVar2)();
43: }
44: iVar12 = *(int *)(param_1 + 9);
45: if (iVar12 != 8) {
46: ppcVar2 = (code **)*param_1;
47: *(undefined4 *)(ppcVar2 + 5) = 0xf;
48: *(int *)((long)ppcVar2 + 0x2c) = iVar12;
49: (**ppcVar2)();
50: }
51: iVar12 = *(int *)((long)param_1 + 0x4c);
52: if (10 < iVar12) {
53: ppcVar2 = (code **)*param_1;
54: *(int *)((long)ppcVar2 + 0x2c) = iVar12;
55: *(undefined4 *)(ppcVar2 + 5) = 0x1a;
56: *(undefined4 *)(ppcVar2 + 6) = 10;
57: (**ppcVar2)();
58: iVar12 = *(int *)((long)param_1 + 0x4c);
59: }
60: pcVar8 = param_1[0xb];
61: param_1[0x27] = (code *)0x100000001;
62: if (iVar12 < 1) {
63: lVar10 = 8;
64: }
65: else {
66: iVar4 = 1;
67: iVar9 = 1;
68: iVar11 = 0;
69: do {
70: iVar1 = *(int *)(pcVar8 + 8);
71: if ((3 < iVar1 - 1U) || (iVar7 = *(int *)(pcVar8 + 0xc), 3 < iVar7 - 1U)) {
72: ppcVar2 = (code **)*param_1;
73: *(undefined4 *)(ppcVar2 + 5) = 0x12;
74: (**ppcVar2)();
75: iVar1 = *(int *)(pcVar8 + 8);
76: iVar7 = *(int *)(pcVar8 + 0xc);
77: iVar9 = *(int *)(param_1 + 0x27);
78: iVar4 = *(int *)((long)param_1 + 0x13c);
79: iVar12 = *(int *)((long)param_1 + 0x4c);
80: }
81: if (iVar9 < iVar1) {
82: iVar9 = iVar1;
83: }
84: if (iVar4 < iVar7) {
85: iVar4 = iVar7;
86: }
87: iVar11 = iVar11 + 1;
88: pcVar8 = pcVar8 + 0x60;
89: *(int *)(param_1 + 0x27) = iVar9;
90: *(int *)((long)param_1 + 0x13c) = iVar4;
91: } while (iVar11 < iVar12);
92: if (iVar12 < 1) {
93: lVar10 = (long)(iVar4 << 3);
94: }
95: else {
96: iVar12 = 0;
97: pcVar8 = param_1[0xb];
98: while( true ) {
99: *(int *)(pcVar8 + 4) = iVar12;
100: *(undefined4 *)(pcVar8 + 0x24) = 8;
101: iVar12 = iVar12 + 1;
102: uVar5 = FUN_001489d0((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar8 + 8),
103: (long)(iVar9 << 3));
104: *(undefined4 *)(pcVar8 + 0x1c) = uVar5;
105: uVar5 = FUN_001489d0((ulong)*(uint *)((long)param_1 + 0x34) * (long)*(int *)(pcVar8 + 0xc),
106: (long)(*(int *)((long)param_1 + 0x13c) * 8));
107: *(undefined4 *)(pcVar8 + 0x20) = uVar5;
108: uVar5 = FUN_001489d0((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar8 + 8),
109: (long)*(int *)(param_1 + 0x27));
110: *(undefined4 *)(pcVar8 + 0x28) = uVar5;
111: uVar5 = FUN_001489d0();
112: *(undefined4 *)(pcVar8 + 0x30) = 1;
113: *(undefined4 *)(pcVar8 + 0x2c) = uVar5;
114: if (*(int *)((long)param_1 + 0x4c) <= iVar12) break;
115: iVar9 = *(int *)(param_1 + 0x27);
116: pcVar8 = pcVar8 + 0x60;
117: }
118: lVar10 = (long)(*(int *)((long)param_1 + 0x13c) * 8);
119: }
120: }
121: uVar5 = FUN_001489d0(*(undefined4 *)((long)param_1 + 0x34),lVar10);
122: *(undefined4 *)(param_1 + 0x28) = uVar5;
123: if (param_1[0x1f] == (code *)0x0) {
124: *(undefined4 *)((long)param_1 + 0x134) = 0;
125: *(undefined4 *)(param_1 + 0x1e) = 1;
126: LAB_0011f374:
127: iVar12 = *(int *)(param_1 + 0x21);
128: if (param_2 == 0) {
129: *(undefined4 *)(ppcVar6 + 4) = 0;
130: *(undefined4 *)((long)ppcVar6 + 0x2c) = 0;
131: *(undefined4 *)((long)ppcVar6 + 0x24) = 0;
132: if (iVar12 != 0) goto LAB_0011f34c;
133: }
134: else {
135: if (iVar12 != 0) goto LAB_0011f331;
136: *(undefined4 *)(ppcVar6 + 4) = 2;
137: *(undefined4 *)((long)ppcVar6 + 0x2c) = 0;
138: *(undefined4 *)((long)ppcVar6 + 0x24) = 0;
139: }
140: iVar12 = *(int *)(param_1 + 0x1e);
141: }
142: else {
143: FUN_0011e220(param_1);
144: if ((*(int *)((long)param_1 + 0x134) == 0) || (*(int *)((long)param_1 + 0x104) != 0))
145: goto LAB_0011f374;
146: *(undefined4 *)(param_1 + 0x21) = 1;
147: if (param_2 == 0) {
148: *(undefined4 *)(ppcVar6 + 4) = 0;
149: *(undefined4 *)((long)ppcVar6 + 0x2c) = 0;
150: *(undefined4 *)((long)ppcVar6 + 0x24) = 0;
151: }
152: else {
153: LAB_0011f331:
154: *(undefined4 *)(ppcVar6 + 4) = 1;
155: *(undefined4 *)((long)ppcVar6 + 0x2c) = 0;
156: *(undefined4 *)((long)ppcVar6 + 0x24) = 0;
157: }
158: LAB_0011f34c:
159: iVar12 = *(int *)(param_1 + 0x1e) * 2;
160: }
161: *(int *)(ppcVar6 + 5) = iVar12;
162: ppcVar6[6] = (code *)"libjpeg-turbo version 2.1.2 (build 20220209)";
163: return;
164: }
165: 

1: 
2: void FUN_00116330(code **param_1,int param_2)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: int iVar3;
8: undefined4 uVar4;
9: code **ppcVar5;
10: int iVar6;
11: int iVar7;
12: code *pcVar8;
13: int iVar9;
14: long lVar10;
15: int iVar11;
16: int iVar12;
17: 
18: ppcVar5 = (code **)(**(code **)param_1[1])(param_1,1,0x38);
19: param_1[0x36] = (code *)ppcVar5;
20: iVar12 = *(int *)((long)param_1 + 0x34);
21: *(undefined4 *)((long)ppcVar5 + 0x1c) = 0;
22: *ppcVar5 = FUN_00116130;
23: ppcVar5[1] = FUN_00115c80;
24: ppcVar5[2] = FUN_00115cb0;
25: if ((((iVar12 == 0) || (*(int *)(param_1 + 6) == 0)) || (*(int *)((long)param_1 + 0x4c) < 1)) ||
26: (*(int *)(param_1 + 7) < 1)) {
27: ppcVar2 = (code **)*param_1;
28: *(undefined4 *)(ppcVar2 + 5) = 0x20;
29: (**ppcVar2)();
30: }
31: if ((0xffdc < *(uint *)((long)param_1 + 0x34)) || (uVar1 = *(uint *)(param_1 + 6), 0xffdc < uVar1)
32: ) {
33: pcVar8 = *param_1;
34: *(undefined4 *)(pcVar8 + 0x28) = 0x29;
35: *(undefined4 *)(pcVar8 + 0x2c) = 0xffdc;
36: (**(code **)*param_1)();
37: uVar1 = *(uint *)(param_1 + 6);
38: }
39: if ((ulong)uVar1 * (long)*(int *)(param_1 + 7) -
40: ((ulong)uVar1 * (long)*(int *)(param_1 + 7) & 0xffffffff) != 0) {
41: ppcVar2 = (code **)*param_1;
42: *(undefined4 *)(ppcVar2 + 5) = 0x46;
43: (**ppcVar2)();
44: }
45: if (*(int *)(param_1 + 9) != 8) {
46: pcVar8 = *param_1;
47: *(int *)(pcVar8 + 0x2c) = *(int *)(param_1 + 9);
48: ppcVar2 = (code **)*param_1;
49: *(undefined4 *)(pcVar8 + 0x28) = 0xf;
50: (**ppcVar2)();
51: }
52: iVar12 = *(int *)((long)param_1 + 0x4c);
53: if (10 < iVar12) {
54: pcVar8 = *param_1;
55: *(int *)(pcVar8 + 0x2c) = iVar12;
56: *(undefined4 *)(pcVar8 + 0x28) = 0x1a;
57: *(undefined4 *)(*param_1 + 0x30) = 10;
58: (**(code **)*param_1)();
59: iVar12 = *(int *)((long)param_1 + 0x4c);
60: }
61: *(undefined4 *)(param_1 + 0x27) = 1;
62: *(undefined4 *)((long)param_1 + 0x13c) = 1;
63: pcVar8 = param_1[0xb];
64: if (iVar12 < 1) {
65: lVar10 = 8;
66: }
67: else {
68: iVar3 = 1;
69: iVar7 = 1;
70: iVar11 = 0;
71: do {
72: iVar6 = *(int *)(pcVar8 + 8);
73: if ((3 < iVar6 - 1U) || (iVar9 = *(int *)(pcVar8 + 0xc), 3 < iVar9 - 1U)) {
74: *(undefined4 *)(*param_1 + 0x28) = 0x12;
75: (**(code **)*param_1)();
76: iVar6 = *(int *)(pcVar8 + 8);
77: iVar9 = *(int *)(pcVar8 + 0xc);
78: iVar7 = *(int *)(param_1 + 0x27);
79: iVar3 = *(int *)((long)param_1 + 0x13c);
80: iVar12 = *(int *)((long)param_1 + 0x4c);
81: }
82: if (iVar7 < iVar6) {
83: iVar7 = iVar6;
84: }
85: if (iVar3 < iVar9) {
86: iVar3 = iVar9;
87: }
88: iVar11 = iVar11 + 1;
89: pcVar8 = pcVar8 + 0x60;
90: *(int *)(param_1 + 0x27) = iVar7;
91: *(int *)((long)param_1 + 0x13c) = iVar3;
92: } while (iVar11 < iVar12);
93: if (iVar12 < 1) {
94: lVar10 = (long)(iVar3 << 3);
95: }
96: else {
97: iVar12 = 0;
98: pcVar8 = param_1[0xb];
99: while( true ) {
100: *(int *)(pcVar8 + 4) = iVar12;
101: *(undefined4 *)(pcVar8 + 0x24) = 8;
102: iVar12 = iVar12 + 1;
103: uVar4 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar8 + 8),
104: (long)(iVar7 << 3),iVar7 << 3);
105: *(undefined4 *)(pcVar8 + 0x1c) = uVar4;
106: uVar4 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * (long)*(int *)(pcVar8 + 0xc),
107: (long)(*(int *)((long)param_1 + 0x13c) * 8));
108: *(undefined4 *)(pcVar8 + 0x20) = uVar4;
109: uVar4 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * (long)*(int *)(pcVar8 + 8),
110: (long)*(int *)(param_1 + 0x27));
111: *(undefined4 *)(pcVar8 + 0x28) = uVar4;
112: uVar4 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * (long)*(int *)(pcVar8 + 0xc),
113: (long)*(int *)((long)param_1 + 0x13c));
114: *(undefined4 *)(pcVar8 + 0x30) = 1;
115: *(undefined4 *)(pcVar8 + 0x2c) = uVar4;
116: if (*(int *)((long)param_1 + 0x4c) <= iVar12) break;
117: iVar7 = *(int *)(param_1 + 0x27);
118: pcVar8 = pcVar8 + 0x60;
119: }
120: lVar10 = (long)(*(int *)((long)param_1 + 0x13c) * 8);
121: }
122: }
123: uVar4 = FUN_0013be20(*(undefined4 *)((long)param_1 + 0x34),lVar10);
124: *(undefined4 *)(param_1 + 0x28) = uVar4;
125: if (param_1[0x1f] == (code *)0x0) {
126: *(undefined4 *)((long)param_1 + 0x134) = 0;
127: *(undefined4 *)(param_1 + 0x1e) = 1;
128: iVar12 = 1;
129: LAB_00116639:
130: iVar7 = *(int *)(param_1 + 0x21);
131: if (param_2 == 0) goto LAB_001165e0;
132: if (iVar7 == 0) {
133: *(undefined4 *)(ppcVar5 + 4) = 2;
134: *(undefined4 *)((long)ppcVar5 + 0x2c) = 0;
135: *(undefined4 *)((long)ppcVar5 + 0x24) = 0;
136: goto LAB_001165ff;
137: }
138: LAB_00116648:
139: *(undefined4 *)(ppcVar5 + 4) = 1;
140: *(undefined4 *)((long)ppcVar5 + 0x2c) = 0;
141: *(undefined4 *)((long)ppcVar5 + 0x24) = 0;
142: }
143: else {
144: FUN_001152d0(param_1);
145: iVar12 = *(int *)(param_1 + 0x1e);
146: if ((*(int *)((long)param_1 + 0x134) == 0) || (*(int *)((long)param_1 + 0x104) != 0))
147: goto LAB_00116639;
148: *(undefined4 *)(param_1 + 0x21) = 1;
149: iVar7 = 1;
150: if (param_2 != 0) goto LAB_00116648;
151: LAB_001165e0:
152: *(undefined4 *)(ppcVar5 + 4) = 0;
153: *(undefined4 *)((long)ppcVar5 + 0x2c) = 0;
154: *(undefined4 *)((long)ppcVar5 + 0x24) = 0;
155: if (iVar7 == 0) goto LAB_001165ff;
156: }
157: iVar12 = iVar12 * 2;
158: LAB_001165ff:
159: *(int *)(ppcVar5 + 5) = iVar12;
160: ppcVar5[6] = (code *)"libjpeg-turbo version 2.0.4 (build 20200904)";
161: return;
162: }
163: 

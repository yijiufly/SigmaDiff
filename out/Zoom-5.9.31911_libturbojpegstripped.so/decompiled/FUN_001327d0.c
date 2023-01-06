1: 
2: void FUN_001327d0(code **param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: code **ppcVar5;
10: bool bVar6;
11: int iVar7;
12: int iVar8;
13: undefined4 uVar9;
14: code *pcVar10;
15: code *pcVar11;
16: code **ppcVar12;
17: code **ppcVar13;
18: code **ppcVar14;
19: code **ppcStack72;
20: 
21: if (*(int *)(param_1[0x44] + 0x6c) == 0) {
22: ppcStack72 = (code **)(**(code **)param_1[1])(param_1,1,0x100);
23: param_1[0x4c] = (code *)ppcStack72;
24: *(undefined4 *)(ppcStack72 + 2) = 0;
25: *ppcStack72 = FUN_00131a00;
26: ppcStack72[1] = FUN_00131a20;
27: }
28: else {
29: ppcStack72 = (code **)param_1[0x4c];
30: }
31: if (*(int *)(param_1 + 0x31) != 0) {
32: ppcVar12 = (code **)*param_1;
33: *(undefined4 *)(ppcVar12 + 5) = 0x19;
34: (**ppcVar12)();
35: }
36: bVar6 = false;
37: if (*(int *)((long)param_1 + 100) != 0) {
38: bVar6 = 1 < *(int *)(param_1 + 0x34);
39: }
40: pcVar11 = param_1[0x26];
41: ppcVar12 = ppcStack72;
42: ppcVar13 = ppcStack72;
43: ppcVar14 = ppcStack72;
44: if (0 < *(int *)(param_1 + 7)) {
45: do {
46: iVar8 = *(int *)(pcVar11 + 0x24);
47: iVar1 = *(int *)(param_1 + 0x34);
48: iVar2 = *(int *)(pcVar11 + 8);
49: iVar3 = *(int *)(param_1 + 0x33);
50: iVar4 = *(int *)((long)param_1 + 0x19c);
51: iVar7 = (*(int *)(pcVar11 + 0xc) * iVar8) / iVar1;
52: *(int *)(ppcVar14 + 0x18) = iVar7;
53: if (*(int *)(pcVar11 + 0x30) == 0) {
54: ppcVar13[0xd] = FUN_00131b70;
55: }
56: else {
57: iVar1 = (iVar2 * iVar8) / iVar1;
58: if ((iVar7 != iVar4) || (iVar1 != iVar3)) {
59: if ((iVar1 * 2 != iVar3) || (iVar7 != iVar4)) {
60: if (((iVar1 != iVar3) || (iVar7 * 2 != iVar4)) || (!bVar6)) {
61: if ((iVar3 == iVar1 * 2) && (iVar7 * 2 == iVar4)) {
62: if ((bVar6) && (2 < *(uint *)(pcVar11 + 0x28))) {
63: iVar8 = FUN_001681a0();
64: pcVar10 = FUN_001322c0;
65: if (iVar8 != 0) {
66: pcVar10 = FUN_00168260;
67: }
68: ppcVar13[0xd] = pcVar10;
69: *(undefined4 *)(ppcStack72 + 2) = 1;
70: }
71: else {
72: iVar8 = FUN_001680c0();
73: if (iVar8 == 0) {
74: ppcVar13[0xd] = FUN_00132550;
75: }
76: else {
77: ppcVar13[0xd] = FUN_00168140;
78: }
79: }
80: }
81: else {
82: if ((iVar3 % iVar1 == 0) && (iVar4 % iVar7 == 0)) {
83: ppcVar13[0xd] = FUN_00132410;
84: *(code *)(ppcVar12 + 0x1d) = SUB41(iVar3 / iVar1,0);
85: *(code *)((long)ppcVar12 + 0xf2) = SUB41(iVar4 / iVar7,0);
86: }
87: else {
88: ppcVar5 = (code **)*param_1;
89: *(undefined4 *)(ppcVar5 + 5) = 0x26;
90: (**ppcVar5)();
91: }
92: }
93: }
94: else {
95: ppcVar13[0xd] = FUN_00132220;
96: *(undefined4 *)(ppcStack72 + 2) = 1;
97: }
98: }
99: else {
100: if ((bVar6) && (2 < *(uint *)(pcVar11 + 0x28))) {
101: iVar8 = FUN_00168200();
102: if (iVar8 == 0) {
103: ppcVar13[0xd] = FUN_00131de0;
104: }
105: else {
106: ppcVar13[0xd] = FUN_00168290;
107: }
108: }
109: else {
110: iVar8 = FUN_00168100();
111: if (iVar8 == 0) {
112: ppcVar13[0xd] = FUN_00131b80;
113: }
114: else {
115: ppcVar13[0xd] = FUN_00168170;
116: }
117: }
118: }
119: if (*(int *)(param_1[0x44] + 0x6c) == 0) {
120: pcVar10 = *(code **)(param_1[1] + 0x10);
121: uVar9 = FUN_0013be30(*(undefined4 *)(param_1 + 0x11),(long)*(int *)(param_1 + 0x33));
122: pcVar10 = (code *)(*pcVar10)(param_1,1,uVar9);
123: ppcVar13[3] = pcVar10;
124: }
125: }
126: else {
127: ppcVar13[0xd] = FUN_00131b60;
128: }
129: }
130: iVar8 = (1 - (int)ppcStack72) + (int)ppcVar12;
131: pcVar11 = pcVar11 + 0x60;
132: ppcVar14 = (code **)((long)ppcVar14 + 4);
133: ppcVar13 = ppcVar13 + 1;
134: ppcVar12 = (code **)((long)ppcVar12 + 1);
135: } while (*(int *)(param_1 + 7) != iVar8 && iVar8 <= *(int *)(param_1 + 7));
136: }
137: return;
138: }
139: 

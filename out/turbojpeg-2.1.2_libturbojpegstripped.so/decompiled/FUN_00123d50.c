1: 
2: void FUN_00123d50(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: code **ppcVar3;
8: uint uVar4;
9: code *pcVar5;
10: code **ppcVar6;
11: int iVar7;
12: 
13: ppcVar3 = (code **)(**(code **)param_1[1])(param_1,1,0x68);
14: iVar7 = *(int *)((long)param_1 + 0x10c);
15: param_1[0x3c] = (code *)ppcVar3;
16: *(undefined4 *)(ppcVar3 + 2) = 0;
17: *ppcVar3 = FUN_00123030;
18: ppcVar3[1] = FUN_00123040;
19: if (iVar7 != 0) {
20: ppcVar6 = (code **)*param_1;
21: *(undefined4 *)(ppcVar6 + 5) = 0x19;
22: (**ppcVar6)();
23: }
24: pcVar5 = param_1[0xb];
25: if (0 < *(int *)((long)param_1 + 0x4c)) {
26: ppcVar6 = ppcVar3 + 3;
27: uVar4 = 1;
28: iVar7 = 0;
29: do {
30: if (*(code **)(pcVar5 + 8) == param_1[0x27]) {
31: if (*(int *)(param_1 + 0x22) == 0) {
32: *ppcVar6 = FUN_00123cc0;
33: }
34: else {
35: *ppcVar6 = FUN_00123ac0;
36: *(undefined4 *)(ppcVar3 + 2) = 1;
37: }
38: }
39: else {
40: if (*(int *)(pcVar5 + 8) * 2 == *(int *)(param_1 + 0x27)) {
41: if (*(int *)(pcVar5 + 0xc) == *(int *)((long)param_1 + 0x13c)) {
42: uVar4 = FUN_0016bf60();
43: if (uVar4 == 0) {
44: *ppcVar6 = FUN_001235b0;
45: }
46: else {
47: uVar4 = 0;
48: *ppcVar6 = FUN_0016bfa0;
49: }
50: }
51: else {
52: if (*(int *)((long)param_1 + 0x13c) != *(int *)(pcVar5 + 0xc) * 2) goto LAB_00123de3;
53: if (*(int *)(param_1 + 0x22) == 0) {
54: iVar2 = FUN_0016bf50();
55: if (iVar2 == 0) {
56: *ppcVar6 = FUN_001236a0;
57: }
58: else {
59: *ppcVar6 = FUN_0016bf80;
60: }
61: }
62: else {
63: *ppcVar6 = FUN_001237b0;
64: *(undefined4 *)(ppcVar3 + 2) = 1;
65: }
66: }
67: }
68: else {
69: LAB_00123de3:
70: if ((*(int *)(param_1 + 0x27) % *(int *)(pcVar5 + 8) == 0) &&
71: (*(int *)((long)param_1 + 0x13c) % *(int *)(pcVar5 + 0xc) == 0)) {
72: uVar4 = 0;
73: *ppcVar6 = FUN_001230d0;
74: }
75: else {
76: ppcVar1 = (code **)*param_1;
77: *(undefined4 *)(ppcVar1 + 5) = 0x26;
78: (**ppcVar1)();
79: }
80: }
81: }
82: iVar7 = iVar7 + 1;
83: pcVar5 = pcVar5 + 0x60;
84: ppcVar6 = ppcVar6 + 1;
85: } while (*(int *)((long)param_1 + 0x4c) != iVar7 && iVar7 <= *(int *)((long)param_1 + 0x4c));
86: if ((*(int *)(param_1 + 0x22) != 0) && ((uVar4 & 1) == 0)) {
87: pcVar5 = *param_1;
88: *(undefined4 *)(pcVar5 + 0x28) = 99;
89: /* WARNING: Could not recover jumptable at 0x00123ed1. Too many branches */
90: /* WARNING: Treating indirect jump as call */
91: (**(code **)(pcVar5 + 8))(param_1,0);
92: return;
93: }
94: }
95: return;
96: }
97: 

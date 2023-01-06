1: 
2: void FUN_0011b570(code **param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: bool bVar3;
8: int iVar4;
9: code **ppcVar5;
10: long lVar6;
11: code *pcVar7;
12: int iVar8;
13: 
14: ppcVar5 = (code **)(**(code **)param_1[1])(param_1,1,0x68);
15: iVar8 = *(int *)((long)param_1 + 0x10c);
16: param_1[0x3c] = (code *)ppcVar5;
17: *(undefined4 *)(ppcVar5 + 2) = 0;
18: *ppcVar5 = FUN_0011a900;
19: ppcVar5[1] = FUN_0011a910;
20: if (iVar8 != 0) {
21: ppcVar2 = (code **)*param_1;
22: *(undefined4 *)(ppcVar2 + 5) = 0x19;
23: (**ppcVar2)(param_1);
24: }
25: iVar8 = 0;
26: pcVar7 = param_1[0xb];
27: bVar3 = true;
28: if (0 < *(int *)((long)param_1 + 0x4c)) {
29: do {
30: while (*(code **)(pcVar7 + 8) != param_1[0x27]) {
31: if (*(int *)(pcVar7 + 8) * 2 == *(int *)(param_1 + 0x27)) {
32: if (*(int *)(pcVar7 + 0xc) == *(int *)((long)param_1 + 0x13c)) {
33: iVar4 = FUN_00168020();
34: if (iVar4 == 0) {
35: bVar3 = false;
36: ppcVar5[(long)iVar8 + 3] = FUN_0011ada0;
37: }
38: else {
39: bVar3 = false;
40: ppcVar5[(long)iVar8 + 3] = FUN_00168090;
41: }
42: }
43: else {
44: if (*(int *)((long)param_1 + 0x13c) != *(int *)(pcVar7 + 0xc) * 2) goto LAB_0011b5f4;
45: if (*(int *)(param_1 + 0x22) == 0) {
46: iVar4 = FUN_00167fe0();
47: if (iVar4 == 0) {
48: ppcVar5[(long)iVar8 + 3] = FUN_0011ae80;
49: }
50: else {
51: ppcVar5[(long)iVar8 + 3] = FUN_00168060;
52: }
53: }
54: else {
55: ppcVar5[(long)iVar8 + 3] = FUN_0011af90;
56: *(undefined4 *)(ppcVar5 + 2) = 1;
57: }
58: }
59: }
60: else {
61: LAB_0011b5f4:
62: if ((*(int *)(param_1 + 0x27) % *(int *)(pcVar7 + 8) == 0) &&
63: (*(int *)((long)param_1 + 0x13c) % *(int *)(pcVar7 + 0xc) == 0)) {
64: bVar3 = false;
65: ppcVar5[(long)iVar8 + 3] = FUN_0011a9a0;
66: }
67: else {
68: ppcVar2 = (code **)*param_1;
69: *(undefined4 *)(ppcVar2 + 5) = 0x26;
70: (**ppcVar2)(param_1);
71: }
72: }
73: LAB_0011b625:
74: iVar8 = iVar8 + 1;
75: pcVar7 = pcVar7 + 0x60;
76: if (*(int *)((long)param_1 + 0x4c) == iVar8 || *(int *)((long)param_1 + 0x4c) < iVar8)
77: goto LAB_0011b678;
78: }
79: lVar6 = (long)iVar8;
80: if (*(int *)(param_1 + 0x22) == 0) {
81: ppcVar5[lVar6 + 3] = FUN_0011b4f0;
82: goto LAB_0011b625;
83: }
84: iVar8 = iVar8 + 1;
85: pcVar7 = pcVar7 + 0x60;
86: iVar4 = *(int *)((long)param_1 + 0x4c);
87: iVar1 = *(int *)((long)param_1 + 0x4c);
88: ppcVar5[lVar6 + 3] = FUN_0011b2c0;
89: *(undefined4 *)(ppcVar5 + 2) = 1;
90: } while (iVar1 != iVar8 && iVar8 <= iVar4);
91: LAB_0011b678:
92: if ((*(int *)(param_1 + 0x22) != 0) && (!bVar3)) {
93: pcVar7 = *param_1;
94: *(undefined4 *)(pcVar7 + 0x28) = 99;
95: /* WARNING: Could not recover jumptable at 0x0011b72b. Too many branches */
96: /* WARNING: Treating indirect jump as call */
97: (**(code **)(pcVar7 + 8))(param_1,0);
98: return;
99: }
100: }
101: return;
102: }
103: 

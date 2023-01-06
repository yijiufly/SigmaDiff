1: 
2: code ** FUN_0016b740(code **param_1,undefined4 param_2,int param_3)
3: 
4: {
5: int *piVar1;
6: int iVar2;
7: int iVar3;
8: code **ppcVar4;
9: uint uVar5;
10: code **ppcVar6;
11: code *pcVar7;
12: uint uVar8;
13: uint uVar9;
14: 
15: ppcVar6 = (code **)(**(code **)param_1[1])(param_1,1,0x68);
16: ppcVar6[3] = (code *)0x0;
17: *(undefined4 *)(ppcVar6 + 7) = param_2;
18: *ppcVar6 = FUN_0016b710;
19: ppcVar6[2] = FUN_0016b5d0;
20: iVar2 = *(int *)(param_1 + 8);
21: if (iVar2 == 1) {
22: LAB_0016b7c8:
23: ppcVar6[1] = FUN_0016add0;
24: }
25: else {
26: if ((iVar2 - 6U < 10) || (iVar2 == 2)) {
27: if (*(int *)((long)param_1 + 0x6c) != 0) goto LAB_0016b7c8;
28: }
29: else {
30: if ((*(int *)((long)param_1 + 0x6c) != 0) || ((iVar2 != 0x10 && (iVar2 != 4)))) {
31: ppcVar4 = (code **)*param_1;
32: *(undefined4 *)(ppcVar4 + 5) = 0x3ed;
33: (**ppcVar4)(param_1);
34: goto LAB_0016b7d3;
35: }
36: }
37: ppcVar6[1] = FUN_0016ab90;
38: }
39: LAB_0016b7d3:
40: FUN_00136eb0(param_1);
41: iVar2 = *(int *)(param_1 + 8);
42: iVar3 = *(int *)(param_1 + 0x11);
43: if (iVar2 == 0x10) {
44: uVar9 = iVar3 * 2;
45: uVar5 = iVar3 * 3;
46: uVar8 = uVar9 & 2;
47: *(uint *)(ppcVar6 + 9) = uVar5;
48: *(uint *)((long)ppcVar6 + 0x4c) = uVar5;
49: while (uVar8 != 0) {
50: uVar9 = uVar9 + 1;
51: uVar8 = uVar9 & 3;
52: }
53: }
54: else {
55: uVar9 = *(int *)((long)param_1 + 0x94) * iVar3;
56: if ((*(int *)((long)param_1 + 0x6c) == 0) &&
57: (((iVar2 - 2U & 0xfffffffd) == 0 || (iVar2 - 6U < 10)))) {
58: uVar5 = iVar3 * 3;
59: *(uint *)(ppcVar6 + 9) = uVar5;
60: *(uint *)((long)ppcVar6 + 0x4c) = uVar5;
61: }
62: else {
63: *(uint *)(ppcVar6 + 9) = uVar9;
64: *(uint *)((long)ppcVar6 + 0x4c) = uVar9;
65: uVar5 = uVar9;
66: }
67: }
68: uVar8 = uVar5;
69: if ((uVar5 & 3) == 0) {
70: *(undefined4 *)(ppcVar6 + 10) = 0;
71: ppcVar4 = (code **)param_1[1];
72: }
73: else {
74: do {
75: uVar8 = uVar8 + 1;
76: } while ((uVar8 & 3) != 0);
77: *(uint *)((long)ppcVar6 + 0x4c) = uVar8;
78: *(uint *)(ppcVar6 + 10) = uVar8 - uVar5;
79: ppcVar4 = (code **)param_1[1];
80: uVar5 = uVar8;
81: }
82: if (param_3 == 0) {
83: pcVar7 = (code *)(**ppcVar4)(param_1,1,uVar5);
84: ppcVar6[0xc] = pcVar7;
85: }
86: else {
87: pcVar7 = (code *)(*ppcVar4[4])(param_1,1,0,uVar5,*(undefined4 *)((long)param_1 + 0x8c),1);
88: ppcVar6[8] = pcVar7;
89: pcVar7 = param_1[2];
90: *(undefined4 *)((long)ppcVar6 + 0x54) = 0;
91: if (pcVar7 != (code *)0x0) {
92: piVar1 = (int *)(pcVar7 + 0x24);
93: *piVar1 = *piVar1 + 1;
94: }
95: }
96: pcVar7 = param_1[1];
97: *(int *)(ppcVar6 + 0xb) = param_3;
98: pcVar7 = (code *)(**(code **)(pcVar7 + 0x10))(param_1,1,uVar9,1);
99: *(undefined4 *)(ppcVar6 + 6) = 1;
100: ppcVar6[5] = pcVar7;
101: return ppcVar6;
102: }
103: 

1: 
2: code ** FUN_001548d0(code **param_1,undefined4 param_2,int param_3)
3: 
4: {
5: int *piVar1;
6: code **ppcVar2;
7: uint uVar3;
8: uint uVar4;
9: code **ppcVar5;
10: code *pcVar6;
11: int iVar7;
12: uint uVar8;
13: 
14: ppcVar5 = (code **)(**(code **)param_1[1])(param_1,1,0x68);
15: ppcVar5[3] = (code *)0x0;
16: *(undefined4 *)(ppcVar5 + 7) = param_2;
17: *ppcVar5 = FUN_001548a0;
18: ppcVar5[2] = FUN_00154770;
19: iVar7 = *(int *)(param_1 + 8);
20: if (iVar7 == 1) {
21: ppcVar5[1] = FUN_00153f40;
22: }
23: else {
24: if ((iVar7 - 6U < 10) || (iVar7 == 2)) {
25: pcVar6 = FUN_00153f40;
26: if (*(int *)((long)param_1 + 0x6c) == 0) {
27: pcVar6 = FUN_00153ce0;
28: }
29: ppcVar5[1] = pcVar6;
30: }
31: else {
32: if ((*(int *)((long)param_1 + 0x6c) == 0) && ((iVar7 == 4 || (iVar7 == 0x10)))) {
33: ppcVar5[1] = FUN_00153ce0;
34: FUN_0012c110();
35: iVar7 = *(int *)(param_1 + 8);
36: goto joined_r0x00154a6b;
37: }
38: ppcVar2 = (code **)*param_1;
39: *(undefined4 *)(ppcVar2 + 5) = 0x3ed;
40: (**ppcVar2)(param_1);
41: }
42: }
43: FUN_0012c110();
44: iVar7 = *(int *)(param_1 + 8);
45: joined_r0x00154a6b:
46: if (iVar7 == 0x10) {
47: uVar8 = *(int *)(param_1 + 0x11) * 2;
48: uVar4 = *(int *)(param_1 + 0x11) * 3;
49: uVar3 = uVar8 & 2;
50: *(uint *)(ppcVar5 + 9) = uVar4;
51: *(uint *)((long)ppcVar5 + 0x4c) = uVar4;
52: while (uVar3 != 0) {
53: uVar8 = uVar8 + 1;
54: uVar3 = uVar8 & 3;
55: }
56: }
57: else {
58: if ((*(int *)((long)param_1 + 0x6c) == 0) &&
59: (((iVar7 == 2 || (iVar7 - 6U < 10)) || (iVar7 == 4)))) {
60: uVar8 = *(int *)((long)param_1 + 0x94) * *(int *)(param_1 + 0x11);
61: uVar4 = *(int *)(param_1 + 0x11) * 3;
62: *(uint *)(ppcVar5 + 9) = uVar4;
63: *(uint *)((long)ppcVar5 + 0x4c) = uVar4;
64: }
65: else {
66: uVar8 = *(int *)((long)param_1 + 0x94) * *(int *)(param_1 + 0x11);
67: *(uint *)(ppcVar5 + 9) = uVar8;
68: *(uint *)((long)ppcVar5 + 0x4c) = uVar8;
69: uVar4 = uVar8;
70: }
71: }
72: uVar3 = uVar4;
73: if ((uVar4 & 3) == 0) {
74: iVar7 = 0;
75: }
76: else {
77: do {
78: uVar3 = uVar3 + 1;
79: } while ((uVar3 & 3) != 0);
80: *(uint *)((long)ppcVar5 + 0x4c) = uVar3;
81: iVar7 = uVar3 - uVar4;
82: uVar4 = uVar3;
83: }
84: *(int *)(ppcVar5 + 10) = iVar7;
85: if (param_3 == 0) {
86: pcVar6 = (code *)(**(code **)param_1[1])(param_1,1,uVar4,uVar4);
87: ppcVar5[0xc] = pcVar6;
88: }
89: else {
90: pcVar6 = (code *)(**(code **)(param_1[1] + 0x20))
91: (param_1,1,0,uVar4,*(undefined4 *)((long)param_1 + 0x8c),1);
92: ppcVar5[8] = pcVar6;
93: pcVar6 = param_1[2];
94: *(undefined4 *)((long)ppcVar5 + 0x54) = 0;
95: if (pcVar6 != (code *)0x0) {
96: piVar1 = (int *)(pcVar6 + 0x24);
97: *piVar1 = *piVar1 + 1;
98: }
99: }
100: pcVar6 = param_1[1];
101: *(int *)(ppcVar5 + 0xb) = param_3;
102: pcVar6 = (code *)(**(code **)(pcVar6 + 0x10))(param_1,1,uVar8,1);
103: *(undefined4 *)(ppcVar5 + 6) = 1;
104: ppcVar5[5] = pcVar6;
105: return ppcVar5;
106: }
107: 

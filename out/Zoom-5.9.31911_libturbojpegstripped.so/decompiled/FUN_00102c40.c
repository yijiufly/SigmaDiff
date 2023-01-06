1: 
2: void FUN_00102c40(code **param_1,int param_2,long param_3)
3: 
4: {
5: code *pcVar1;
6: code *pcVar2;
7: ulong uVar3;
8: int iVar4;
9: uint uVar5;
10: code **ppcVar7;
11: code **ppcVar8;
12: bool bVar9;
13: byte bVar10;
14: ulong uVar6;
15: 
16: bVar10 = 0;
17: param_1[1] = (code *)0x0;
18: if (param_2 != 0x3e) {
19: pcVar1 = *param_1;
20: *(undefined4 *)(pcVar1 + 0x2c) = 0x3e;
21: *(undefined4 *)(pcVar1 + 0x28) = 0xc;
22: *(int *)(*param_1 + 0x30) = param_2;
23: (**(code **)*param_1)();
24: }
25: if (param_3 != 0x208) {
26: pcVar1 = *param_1;
27: *(undefined4 *)(pcVar1 + 0x2c) = 0x208;
28: *(undefined4 *)(pcVar1 + 0x28) = 0x15;
29: *(int *)(*param_1 + 0x30) = (int)param_3;
30: (**(code **)*param_1)(param_1);
31: }
32: bVar9 = ((ulong)param_1 & 1) != 0;
33: pcVar1 = *param_1;
34: pcVar2 = param_1[3];
35: uVar6 = 0x208;
36: iVar4 = 0x208;
37: if (bVar9) {
38: *(undefined *)param_1 = 0;
39: uVar6 = 0x207;
40: iVar4 = 0x207;
41: uVar3 = (ulong)(code **)((long)param_1 + 1) & 2;
42: ppcVar8 = (code **)((long)param_1 + 1);
43: }
44: else {
45: uVar3 = (ulong)param_1 & 2;
46: ppcVar8 = param_1;
47: }
48: if (uVar3 == 0) {
49: uVar5 = (uint)uVar6;
50: ppcVar7 = ppcVar8;
51: }
52: else {
53: ppcVar7 = (code **)((long)ppcVar8 + 2);
54: uVar5 = iVar4 - 2;
55: uVar6 = (ulong)uVar5;
56: *(undefined2 *)ppcVar8 = 0;
57: }
58: if (((ulong)ppcVar7 & 4) != 0) {
59: *(undefined4 *)ppcVar7 = 0;
60: uVar6 = (ulong)(uVar5 - 4);
61: ppcVar7 = (code **)((long)ppcVar7 + 4);
62: }
63: uVar3 = uVar6 >> 3;
64: while (uVar3 != 0) {
65: uVar3 = uVar3 - 1;
66: *ppcVar7 = (code *)0x0;
67: ppcVar7 = ppcVar7 + (ulong)bVar10 * -2 + 1;
68: }
69: if ((uVar6 & 4) != 0) {
70: *(undefined4 *)ppcVar7 = 0;
71: ppcVar7 = (code **)((long)ppcVar7 + 4);
72: }
73: ppcVar8 = ppcVar7;
74: if ((uVar6 & 2) != 0) {
75: ppcVar8 = (code **)((long)ppcVar7 + 2);
76: *(undefined2 *)ppcVar7 = 0;
77: }
78: if (bVar9) {
79: *(undefined *)ppcVar8 = 0;
80: }
81: *param_1 = pcVar1;
82: param_1[3] = pcVar2;
83: *(undefined4 *)(param_1 + 4) = 0;
84: FUN_0013d740(param_1);
85: param_1[2] = (code *)0x0;
86: param_1[5] = (code *)0x0;
87: param_1[0xb] = (code *)0x0;
88: param_1[0xc] = (code *)0x0;
89: param_1[0xd] = (code *)0x0;
90: param_1[8] = (code *)0x3ff0000000000000;
91: param_1[0xe] = (code *)0x0;
92: param_1[0xf] = (code *)0x0;
93: param_1[0x10] = (code *)0x0;
94: param_1[0x11] = (code *)0x0;
95: param_1[0x12] = (code *)0x0;
96: param_1[0x13] = (code *)0x0;
97: param_1[0x14] = (code *)0x0;
98: param_1[0x15] = (code *)0x0;
99: param_1[0x16] = (code *)0x0;
100: param_1[0x17] = (code *)0x0;
101: param_1[0x3f] = (code *)0x0;
102: *(undefined4 *)((long)param_1 + 0x24) = 100;
103: return;
104: }
105: 

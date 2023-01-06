1: 
2: undefined8 FUN_00132b50(code **param_1)
3: 
4: {
5: code *pcVar1;
6: int iVar2;
7: uint uVar3;
8: long lVar4;
9: code **ppcVar5;
10: 
11: iVar2 = *(int *)((long)param_1 + 0x24);
12: if (iVar2 == 0xca) {
13: *(undefined4 *)(param_1 + 0xb) = 1;
14: if (*(int *)((long)param_1 + 0x13c) == 0) {
15: if (*(int *)(param_1 + 0x27) == 0) {
16: FUN_00127580();
17: }
18: else {
19: FUN_001314c0();
20: }
21: }
22: else {
23: FUN_001417a0();
24: }
25: FUN_00120360(param_1);
26: (**(code **)(param_1[1] + 0x30))(param_1);
27: (**(code **)(param_1[0x48] + 0x10))();
28: ppcVar5 = (code **)param_1[2];
29: if (ppcVar5 != (code **)0x0) {
30: if (*(int *)(param_1 + 0x27) == 0) {
31: lVar4 = 1;
32: if (*(int *)(param_1[0x48] + 0x20) != 0) {
33: lVar4 = (long)*(int *)(param_1 + 7);
34: }
35: }
36: else {
37: lVar4 = (long)(*(int *)(param_1 + 7) * 3 + 2);
38: }
39: uVar3 = *(uint *)((long)param_1 + 0x1a4);
40: ppcVar5[1] = (code *)0x0;
41: *(undefined4 *)(ppcVar5 + 3) = 0;
42: *(undefined4 *)((long)ppcVar5 + 0x1c) = 1;
43: ppcVar5[2] = (code *)((ulong)uVar3 * lVar4);
44: }
45: *(undefined4 *)((long)param_1 + 0x24) = 0xd1;
46: }
47: else {
48: if (iVar2 != 0xd1) {
49: if ((iVar2 == 0xcf) || (iVar2 == 0xd2)) {
50: LAB_00132b74:
51: if (*(int *)(param_1 + 0xb) != 0) {
52: return *(undefined8 *)(param_1[0x46] + 0x20);
53: }
54: }
55: pcVar1 = *param_1;
56: *(int *)(pcVar1 + 0x2c) = iVar2;
57: ppcVar5 = (code **)*param_1;
58: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
59: (**ppcVar5)(param_1);
60: return 0;
61: }
62: ppcVar5 = (code **)param_1[2];
63: }
64: LAB_00132b98:
65: if (ppcVar5 == (code **)0x0) goto LAB_00132ba2;
66: LAB_00132b9d:
67: (**ppcVar5)(param_1);
68: LAB_00132ba2:
69: do {
70: uVar3 = (**(code **)param_1[0x48])(param_1);
71: if (uVar3 == 0) {
72: return 0;
73: }
74: while( true ) {
75: if (uVar3 == 2) {
76: *(undefined4 *)((long)param_1 + 0x24) = 0xd2;
77: iVar2 = 0xd2;
78: goto LAB_00132b74;
79: }
80: ppcVar5 = (code **)param_1[2];
81: if (ppcVar5 == (code **)0x0) break;
82: if ((uVar3 & 0xfffffffd) != 1) goto LAB_00132b98;
83: pcVar1 = ppcVar5[1];
84: ppcVar5[1] = pcVar1 + 1;
85: if ((long)(pcVar1 + 1) < (long)ppcVar5[2]) goto LAB_00132b98;
86: ppcVar5[2] = ppcVar5[2] + *(uint *)((long)param_1 + 0x1a4);
87: if (ppcVar5 != (code **)0x0) goto LAB_00132b9d;
88: uVar3 = (**(code **)param_1[0x48])(param_1);
89: if (uVar3 == 0) {
90: return 0;
91: }
92: }
93: } while( true );
94: }
95: 

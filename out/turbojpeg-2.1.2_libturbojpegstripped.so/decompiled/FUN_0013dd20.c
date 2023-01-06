1: 
2: undefined8 FUN_0013dd20(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: int iVar3;
8: uint uVar4;
9: long lVar5;
10: 
11: iVar3 = *(int *)((long)param_1 + 0x24);
12: if (iVar3 == 0xca) {
13: *(undefined4 *)(param_1 + 0xb) = 1;
14: if (*(int *)((long)param_1 + 0x13c) == 0) {
15: if (*(int *)(param_1 + 0x27) == 0) {
16: FUN_00132390();
17: }
18: else {
19: FUN_0013c3d0();
20: }
21: }
22: else {
23: FUN_0014e140();
24: }
25: FUN_00129eb0(param_1);
26: (**(code **)(param_1[1] + 0x30))(param_1);
27: (**(code **)(param_1[0x48] + 0x10))();
28: ppcVar1 = (code **)param_1[2];
29: if (ppcVar1 != (code **)0x0) {
30: if (*(int *)(param_1 + 0x27) == 0) {
31: lVar5 = 1;
32: if (*(int *)(param_1[0x48] + 0x20) != 0) {
33: lVar5 = (long)*(int *)(param_1 + 7);
34: }
35: }
36: else {
37: lVar5 = (long)(*(int *)(param_1 + 7) * 3 + 2);
38: }
39: uVar4 = *(uint *)((long)param_1 + 0x1a4);
40: ppcVar1[1] = (code *)0x0;
41: ppcVar1[2] = (code *)((ulong)uVar4 * lVar5);
42: ppcVar1[3] = (code *)0x100000000;
43: }
44: *(undefined4 *)((long)param_1 + 0x24) = 0xd1;
45: }
46: else {
47: if (iVar3 != 0xd1) {
48: if ((iVar3 == 0xd2) || (iVar3 == 0xcf)) {
49: LAB_0013dd6c:
50: if (*(int *)(param_1 + 0xb) != 0) {
51: return *(undefined8 *)(param_1[0x46] + 0x20);
52: }
53: }
54: ppcVar1 = (code **)*param_1;
55: *(int *)((long)ppcVar1 + 0x2c) = iVar3;
56: *(undefined4 *)(ppcVar1 + 5) = 0x14;
57: (**ppcVar1)(param_1);
58: return 0;
59: }
60: ppcVar1 = (code **)param_1[2];
61: }
62: do {
63: if (ppcVar1 != (code **)0x0) {
64: (**ppcVar1)(param_1);
65: }
66: do {
67: uVar4 = (**(code **)param_1[0x48])(param_1);
68: if (uVar4 == 0) {
69: return 0;
70: }
71: if (uVar4 == 2) {
72: *(undefined4 *)((long)param_1 + 0x24) = 0xd2;
73: iVar3 = 0xd2;
74: goto LAB_0013dd6c;
75: }
76: ppcVar1 = (code **)param_1[2];
77: } while (ppcVar1 == (code **)0x0);
78: if ((uVar4 & 0xfffffffd) == 1) {
79: pcVar2 = ppcVar1[1];
80: ppcVar1[1] = pcVar2 + 1;
81: if ((long)ppcVar1[2] <= (long)(pcVar2 + 1)) {
82: ppcVar1[2] = ppcVar1[2] + *(uint *)((long)param_1 + 0x1a4);
83: }
84: }
85: } while( true );
86: }
87: 

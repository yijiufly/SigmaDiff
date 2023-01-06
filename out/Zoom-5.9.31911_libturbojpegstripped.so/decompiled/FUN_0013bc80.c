1: 
2: void FUN_0013bc80(code **param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: code **ppcVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: undefined8 uVar6;
11: long lVar7;
12: undefined8 *puVar8;
13: 
14: ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x58);
15: iVar2 = *(int *)(param_1 + 0x12);
16: param_1[0x4e] = (code *)ppcVar4;
17: ppcVar4[8] = (code *)0x0;
18: ppcVar4[10] = (code *)0x0;
19: *ppcVar4 = FUN_0013a290;
20: ppcVar4[3] = FUN_0013a280;
21: if (iVar2 != 3) {
22: ppcVar3 = (code **)*param_1;
23: *(undefined4 *)(ppcVar3 + 5) = 0x2f;
24: (**ppcVar3)(param_1);
25: }
26: lVar7 = 0;
27: pcVar5 = (code *)(**(code **)param_1[1])(param_1,1,0x100);
28: ppcVar4[6] = pcVar5;
29: while( true ) {
30: puVar8 = (undefined8 *)(pcVar5 + lVar7);
31: lVar7 = lVar7 + 8;
32: uVar6 = (**(code **)(param_1[1] + 8))(param_1,1,0x1000);
33: *puVar8 = uVar6;
34: if (lVar7 == 0x100) break;
35: pcVar5 = ppcVar4[6];
36: }
37: iVar2 = *(int *)((long)param_1 + 0x84);
38: *(undefined4 *)(ppcVar4 + 7) = 1;
39: if (iVar2 == 0) {
40: iVar2 = *(int *)(param_1 + 0xe);
41: ppcVar4[4] = (code *)0x0;
42: }
43: else {
44: iVar1 = *(int *)(param_1 + 0xf);
45: if (iVar1 < 8) {
46: pcVar5 = *param_1;
47: *(undefined4 *)(pcVar5 + 0x28) = 0x38;
48: *(undefined4 *)(pcVar5 + 0x2c) = 8;
49: (**(code **)*param_1)(param_1);
50: }
51: else {
52: if (0x100 < iVar1) {
53: pcVar5 = *param_1;
54: *(undefined4 *)(pcVar5 + 0x28) = 0x39;
55: *(undefined4 *)(pcVar5 + 0x2c) = 0x100;
56: (**(code **)*param_1)(param_1);
57: }
58: }
59: pcVar5 = (code *)(**(code **)(param_1[1] + 0x10))(param_1,1,iVar1,3);
60: ppcVar4[4] = pcVar5;
61: iVar2 = *(int *)(param_1 + 0xe);
62: *(int *)(ppcVar4 + 5) = iVar1;
63: }
64: if (iVar2 == 0) {
65: return;
66: }
67: *(undefined4 *)(param_1 + 0xe) = 2;
68: pcVar5 = (code *)(**(code **)(param_1[1] + 8))
69: (param_1,1,(ulong)(*(int *)(param_1 + 0x11) + 2) * 6);
70: ppcVar4[8] = pcVar5;
71: FUN_0013a0a0(param_1);
72: return;
73: }
74: 

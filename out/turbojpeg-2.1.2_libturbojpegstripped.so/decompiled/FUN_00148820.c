1: 
2: void FUN_00148820(code **param_1)
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
19: *ppcVar4 = FUN_00146950;
20: ppcVar4[3] = FUN_00146940;
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
46: ppcVar3 = (code **)*param_1;
47: ppcVar3[5] = (code *)0x800000038;
48: (**ppcVar3)(param_1);
49: }
50: else {
51: if (0x100 < iVar1) {
52: ppcVar3 = (code **)*param_1;
53: ppcVar3[5] = (code *)0x10000000039;
54: (**ppcVar3)(param_1);
55: }
56: }
57: pcVar5 = (code *)(**(code **)(param_1[1] + 0x10))(param_1,1,iVar1,3);
58: ppcVar4[4] = pcVar5;
59: iVar2 = *(int *)(param_1 + 0xe);
60: *(int *)(ppcVar4 + 5) = iVar1;
61: }
62: if (iVar2 != 0) {
63: *(undefined4 *)(param_1 + 0xe) = 2;
64: pcVar5 = (code *)(**(code **)(param_1[1] + 8))
65: (param_1,1,(ulong)(*(int *)(param_1 + 0x11) + 2) * 6);
66: ppcVar4[8] = pcVar5;
67: FUN_001465d0(param_1);
68: return;
69: }
70: return;
71: }
72: 

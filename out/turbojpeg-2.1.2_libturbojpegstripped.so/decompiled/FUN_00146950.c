1: 
2: void FUN_00146950(code **param_1,int param_2)
3: 
4: {
5: undefined8 *puVar1;
6: int iVar2;
7: code *pcVar3;
8: undefined8 uVar4;
9: code **ppcVar5;
10: long lVar6;
11: code *pcVar7;
12: long lVar8;
13: undefined8 *puVar9;
14: 
15: pcVar3 = param_1[0x4e];
16: puVar9 = *(undefined8 **)(pcVar3 + 0x30);
17: if (*(int *)(param_1 + 0xe) == 0) {
18: pcVar7 = FUN_00147e10;
19: if (param_2 == 0) goto LAB_001469eb;
20: }
21: else {
22: *(undefined4 *)(param_1 + 0xe) = 2;
23: if (param_2 == 0) {
24: pcVar7 = FUN_00147f30;
25: LAB_001469eb:
26: *(code **)(pcVar3 + 8) = pcVar7;
27: *(code **)(pcVar3 + 0x10) = FUN_00146930;
28: if (*(int *)((long)param_1 + 0x9c) < 1) {
29: ppcVar5 = (code **)*param_1;
30: ppcVar5[5] = (code *)0x100000038;
31: (**ppcVar5)(param_1);
32: LAB_00146a1d:
33: iVar2 = *(int *)(param_1 + 0xe);
34: }
35: else {
36: if (*(int *)((long)param_1 + 0x9c) < 0x101) goto LAB_00146a1d;
37: ppcVar5 = (code **)*param_1;
38: ppcVar5[5] = (code *)0x10000000039;
39: (**ppcVar5)(param_1);
40: iVar2 = *(int *)(param_1 + 0xe);
41: }
42: if (iVar2 == 2) {
43: lVar8 = *(long *)(pcVar3 + 0x40);
44: lVar6 = (ulong)(*(int *)(param_1 + 0x11) + 2) * 6;
45: if (lVar8 == 0) {
46: lVar8 = (**(code **)(param_1[1] + 8))(param_1,1,lVar6);
47: *(long *)(pcVar3 + 0x40) = lVar8;
48: }
49: FUN_00148a80(lVar8,lVar6);
50: if (*(long *)(pcVar3 + 0x50) == 0) {
51: FUN_001465d0(param_1);
52: }
53: *(undefined4 *)(pcVar3 + 0x48) = 0;
54: }
55: if (*(int *)(pcVar3 + 0x38) == 0) {
56: return;
57: }
58: goto LAB_001469a0;
59: }
60: }
61: *(undefined4 *)(pcVar3 + 0x38) = 1;
62: *(code **)(pcVar3 + 8) = FUN_00146530;
63: *(code **)(pcVar3 + 0x10) = FUN_00148350;
64: LAB_001469a0:
65: puVar1 = puVar9 + 0x20;
66: do {
67: uVar4 = *puVar9;
68: puVar9 = puVar9 + 1;
69: FUN_00148a80(uVar4,0x1000);
70: } while (puVar1 != puVar9);
71: *(undefined4 *)(pcVar3 + 0x38) = 0;
72: return;
73: }
74: 

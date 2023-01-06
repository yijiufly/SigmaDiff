1: 
2: void FUN_00118500(long param_1,uint param_2,int param_3)
3: 
4: {
5: long *plVar1;
6: undefined *puVar2;
7: undefined8 *puVar3;
8: code **ppcVar4;
9: int iVar5;
10: ulong uVar6;
11: ulong uVar7;
12: uint uVar8;
13: uint uVar9;
14: 
15: iVar5 = *(int *)(param_1 + 0x48);
16: if (param_3 == 0) {
17: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
18: *(undefined4 *)(ppcVar4 + 5) = 0x28;
19: (**ppcVar4)();
20: }
21: if (*(int *)(param_1 + 0x28) == 0) {
22: uVar9 = iVar5 + param_3;
23: uVar6 = (ulong)((int)(1 << ((byte)param_3 & 0x3f)) - 1U & param_2) <<
24: (0x18U - (char)uVar9 & 0x3f) | *(ulong *)(param_1 + 0x40);
25: uVar8 = uVar9;
26: if (7 < (int)uVar9) {
27: do {
28: while( true ) {
29: uVar7 = uVar6;
30: puVar2 = *(undefined **)(param_1 + 0x30);
31: uVar6 = uVar7 >> 0x10 & 0xff;
32: *(undefined **)(param_1 + 0x30) = puVar2 + 1;
33: *puVar2 = (char)uVar6;
34: plVar1 = (long *)(param_1 + 0x38);
35: *plVar1 = *plVar1 + -1;
36: if (*plVar1 == 0) {
37: puVar3 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
38: iVar5 = (*(code *)puVar3[3])();
39: if (iVar5 == 0) {
40: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
41: *(undefined4 *)(ppcVar4 + 5) = 0x18;
42: (**ppcVar4)();
43: }
44: *(undefined8 *)(param_1 + 0x30) = *puVar3;
45: *(undefined8 *)(param_1 + 0x38) = puVar3[1];
46: }
47: if ((int)uVar6 == 0xff) break;
48: LAB_00118569:
49: uVar8 = uVar8 - 8;
50: uVar6 = uVar7 << 8;
51: if ((int)uVar8 < 8) goto LAB_00118620;
52: }
53: puVar2 = *(undefined **)(param_1 + 0x30);
54: *(undefined **)(param_1 + 0x30) = puVar2 + 1;
55: *puVar2 = 0;
56: plVar1 = (long *)(param_1 + 0x38);
57: *plVar1 = *plVar1 + -1;
58: if (*plVar1 != 0) goto LAB_00118569;
59: puVar3 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
60: iVar5 = (*(code *)puVar3[3])();
61: if (iVar5 == 0) {
62: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
63: *(undefined4 *)(ppcVar4 + 5) = 0x18;
64: (**ppcVar4)();
65: *(undefined8 *)(param_1 + 0x30) = *puVar3;
66: *(undefined8 *)(param_1 + 0x38) = puVar3[1];
67: }
68: else {
69: *(undefined8 *)(param_1 + 0x30) = *puVar3;
70: *(undefined8 *)(param_1 + 0x38) = puVar3[1];
71: }
72: uVar8 = uVar8 - 8;
73: uVar6 = uVar7 << 8;
74: } while (7 < (int)uVar8);
75: LAB_00118620:
76: uVar6 = uVar7 << 8;
77: uVar9 = uVar9 & 7;
78: }
79: *(ulong *)(param_1 + 0x40) = uVar6;
80: *(uint *)(param_1 + 0x48) = uVar9;
81: }
82: return;
83: }
84: 

1: 
2: void FUN_001207a0(long param_1,uint param_2,int param_3)
3: 
4: {
5: uint uVar1;
6: long *plVar2;
7: code **ppcVar3;
8: undefined *puVar4;
9: undefined8 *puVar5;
10: int iVar6;
11: uint uVar7;
12: uint uVar8;
13: ulong uVar9;
14: ulong uVar10;
15: 
16: iVar6 = *(int *)(param_1 + 0x48);
17: if (param_3 == 0) {
18: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
19: *(undefined4 *)(ppcVar3 + 5) = 0x28;
20: (**ppcVar3)();
21: }
22: if (*(int *)(param_1 + 0x28) == 0) {
23: uVar7 = iVar6 + param_3;
24: uVar9 = (ulong)(param_2 & ~(uint)(-1 << ((byte)param_3 & 0x3f))) << (0x18U - (char)uVar7 & 0x3f)
25: | *(ulong *)(param_1 + 0x40);
26: if (7 < (int)uVar7) {
27: uVar1 = uVar7 - 8;
28: uVar8 = uVar1 & 7;
29: LAB_00120830:
30: do {
31: uVar10 = uVar9;
32: puVar4 = *(undefined **)(param_1 + 0x30);
33: *(undefined **)(param_1 + 0x30) = puVar4 + 1;
34: *puVar4 = (char)(uVar10 >> 0x10);
35: plVar2 = (long *)(param_1 + 0x38);
36: *plVar2 = *plVar2 + -1;
37: if (*plVar2 == 0) {
38: puVar5 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
39: iVar6 = (*(code *)puVar5[3])();
40: if (iVar6 == 0) {
41: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
42: *(undefined4 *)(ppcVar3 + 5) = 0x18;
43: (**ppcVar3)();
44: }
45: *(undefined8 *)(param_1 + 0x30) = *puVar5;
46: *(undefined8 *)(param_1 + 0x38) = puVar5[1];
47: }
48: if (((uint)(uVar10 >> 0x10) & 0xff) == 0xff) {
49: puVar4 = *(undefined **)(param_1 + 0x30);
50: *(undefined **)(param_1 + 0x30) = puVar4 + 1;
51: *puVar4 = 0;
52: plVar2 = (long *)(param_1 + 0x38);
53: *plVar2 = *plVar2 + -1;
54: if (*plVar2 == 0) {
55: puVar5 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
56: iVar6 = (*(code *)puVar5[3])();
57: if (iVar6 == 0) {
58: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
59: *(undefined4 *)(ppcVar3 + 5) = 0x18;
60: (**ppcVar3)();
61: }
62: uVar7 = uVar7 - 8;
63: *(undefined8 *)(param_1 + 0x30) = *puVar5;
64: *(undefined8 *)(param_1 + 0x38) = puVar5[1];
65: uVar9 = uVar10 << 8;
66: if (uVar7 == uVar8) break;
67: goto LAB_00120830;
68: }
69: }
70: uVar7 = uVar7 - 8;
71: uVar9 = uVar10 << 8;
72: } while (uVar7 != uVar8);
73: uVar9 = uVar10 << 8;
74: uVar7 = uVar1 & 7;
75: }
76: *(ulong *)(param_1 + 0x40) = uVar9;
77: *(uint *)(param_1 + 0x48) = uVar7;
78: }
79: return;
80: }
81: 

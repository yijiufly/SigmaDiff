1: 
2: void FUN_00120b60(long param_1)
3: 
4: {
5: long lVar1;
6: undefined8 uVar2;
7: undefined8 *puVar3;
8: code **ppcVar4;
9: int iVar5;
10: long lVar6;
11: undefined *puVar7;
12: ulong uVar8;
13: uint uVar9;
14: uint uVar10;
15: 
16: lVar1 = *(long *)(param_1 + 0x1f0);
17: uVar2 = **(undefined8 **)(param_1 + 0x28);
18: *(undefined8 *)(lVar1 + 0x38) = (*(undefined8 **)(param_1 + 0x28))[1];
19: *(undefined8 *)(lVar1 + 0x30) = uVar2;
20: FUN_00120910(lVar1);
21: if (*(int *)(lVar1 + 0x28) == 0) {
22: puVar7 = *(undefined **)(lVar1 + 0x30);
23: uVar10 = *(int *)(lVar1 + 0x48) + 7;
24: uVar8 = 0x7f << (0x18U - (char)uVar10 & 0x3f) | *(ulong *)(lVar1 + 0x40);
25: if ((int)uVar10 < 8) {
26: lVar6 = *(long *)(lVar1 + 0x38);
27: }
28: else {
29: uVar9 = *(int *)(lVar1 + 0x48) - 1U & 7;
30: LAB_00120bef:
31: do {
32: *(undefined **)(lVar1 + 0x30) = puVar7 + 1;
33: *puVar7 = (char)(uVar8 >> 0x10);
34: lVar6 = *(long *)(lVar1 + 0x38) + -1;
35: *(long *)(lVar1 + 0x38) = lVar6;
36: if (lVar6 == 0) {
37: puVar3 = *(undefined8 **)(*(long *)(lVar1 + 0x50) + 0x28);
38: iVar5 = (*(code *)puVar3[3])();
39: if (iVar5 == 0) {
40: ppcVar4 = (code **)**(code ***)(lVar1 + 0x50);
41: *(undefined4 *)(ppcVar4 + 5) = 0x18;
42: (**ppcVar4)();
43: }
44: puVar7 = (undefined *)*puVar3;
45: lVar6 = puVar3[1];
46: *(undefined **)(lVar1 + 0x30) = puVar7;
47: *(long *)(lVar1 + 0x38) = lVar6;
48: }
49: else {
50: puVar7 = *(undefined **)(lVar1 + 0x30);
51: }
52: if (((uint)(uVar8 >> 0x10) & 0xff) == 0xff) {
53: *(undefined **)(lVar1 + 0x30) = puVar7 + 1;
54: *puVar7 = 0;
55: lVar6 = *(long *)(lVar1 + 0x38) + -1;
56: *(long *)(lVar1 + 0x38) = lVar6;
57: if (lVar6 != 0) {
58: uVar8 = uVar8 << 8;
59: uVar10 = uVar10 - 8;
60: puVar7 = *(undefined **)(lVar1 + 0x30);
61: if (uVar9 == uVar10) break;
62: goto LAB_00120bef;
63: }
64: puVar3 = *(undefined8 **)(*(long *)(lVar1 + 0x50) + 0x28);
65: iVar5 = (*(code *)puVar3[3])();
66: if (iVar5 == 0) {
67: ppcVar4 = (code **)**(code ***)(lVar1 + 0x50);
68: *(undefined4 *)(ppcVar4 + 5) = 0x18;
69: (**ppcVar4)();
70: }
71: puVar7 = (undefined *)*puVar3;
72: lVar6 = puVar3[1];
73: *(undefined **)(lVar1 + 0x30) = puVar7;
74: *(long *)(lVar1 + 0x38) = lVar6;
75: }
76: uVar8 = uVar8 << 8;
77: uVar10 = uVar10 - 8;
78: } while (uVar9 != uVar10);
79: }
80: }
81: else {
82: puVar7 = *(undefined **)(lVar1 + 0x30);
83: lVar6 = *(long *)(lVar1 + 0x38);
84: }
85: puVar3 = *(undefined8 **)(param_1 + 0x28);
86: *(undefined8 *)(lVar1 + 0x40) = 0;
87: *(undefined4 *)(lVar1 + 0x48) = 0;
88: *puVar3 = puVar7;
89: puVar3[1] = lVar6;
90: return;
91: }
92: 

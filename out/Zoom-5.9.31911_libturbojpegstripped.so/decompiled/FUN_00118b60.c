1: 
2: void FUN_00118b60(long param_1)
3: 
4: {
5: long lVar1;
6: undefined8 uVar2;
7: code **ppcVar3;
8: undefined8 *puVar4;
9: int iVar5;
10: undefined *puVar6;
11: long lVar7;
12: ulong uVar8;
13: int iVar9;
14: ulong uVar10;
15: 
16: lVar1 = *(long *)(param_1 + 0x1f0);
17: uVar2 = (*(undefined8 **)(param_1 + 0x28))[1];
18: *(undefined8 *)(lVar1 + 0x30) = **(undefined8 **)(param_1 + 0x28);
19: *(undefined8 *)(lVar1 + 0x38) = uVar2;
20: FUN_00118690(lVar1);
21: if (*(int *)(lVar1 + 0x28) == 0) {
22: iVar9 = *(int *)(lVar1 + 0x48) + 7;
23: puVar6 = *(undefined **)(lVar1 + 0x30);
24: uVar8 = 0x7f << (0x11U - (char)*(int *)(lVar1 + 0x48) & 0x3f) | *(ulong *)(lVar1 + 0x40);
25: if (iVar9 < 8) {
26: lVar7 = *(long *)(lVar1 + 0x38);
27: }
28: else {
29: do {
30: while( true ) {
31: uVar10 = uVar8 >> 0x10 & 0xff;
32: *(undefined **)(lVar1 + 0x30) = puVar6 + 1;
33: *puVar6 = (char)uVar10;
34: lVar7 = *(long *)(lVar1 + 0x38) + -1;
35: *(long *)(lVar1 + 0x38) = lVar7;
36: if (lVar7 == 0) {
37: puVar4 = *(undefined8 **)(*(long *)(lVar1 + 0x50) + 0x28);
38: iVar5 = (*(code *)puVar4[3])();
39: if (iVar5 == 0) {
40: ppcVar3 = (code **)**(code ***)(lVar1 + 0x50);
41: *(undefined4 *)(ppcVar3 + 5) = 0x18;
42: (**ppcVar3)();
43: }
44: puVar6 = (undefined *)*puVar4;
45: lVar7 = puVar4[1];
46: *(undefined **)(lVar1 + 0x30) = puVar6;
47: *(long *)(lVar1 + 0x38) = lVar7;
48: }
49: else {
50: puVar6 = *(undefined **)(lVar1 + 0x30);
51: }
52: if ((int)uVar10 == 0xff) break;
53: LAB_00118bdd:
54: iVar9 = iVar9 + -8;
55: uVar8 = uVar8 << 8;
56: if (iVar9 < 8) goto LAB_00118c80;
57: }
58: *(undefined **)(lVar1 + 0x30) = puVar6 + 1;
59: *puVar6 = 0;
60: lVar7 = *(long *)(lVar1 + 0x38) + -1;
61: *(long *)(lVar1 + 0x38) = lVar7;
62: if (lVar7 == 0) {
63: puVar4 = *(undefined8 **)(*(long *)(lVar1 + 0x50) + 0x28);
64: iVar5 = (*(code *)puVar4[3])();
65: if (iVar5 == 0) {
66: ppcVar3 = (code **)**(code ***)(lVar1 + 0x50);
67: *(undefined4 *)(ppcVar3 + 5) = 0x18;
68: (**ppcVar3)();
69: puVar6 = (undefined *)*puVar4;
70: lVar7 = puVar4[1];
71: *(undefined **)(lVar1 + 0x30) = puVar6;
72: *(long *)(lVar1 + 0x38) = lVar7;
73: }
74: else {
75: puVar6 = (undefined *)*puVar4;
76: lVar7 = puVar4[1];
77: *(undefined **)(lVar1 + 0x30) = puVar6;
78: *(long *)(lVar1 + 0x38) = lVar7;
79: }
80: goto LAB_00118bdd;
81: }
82: iVar9 = iVar9 + -8;
83: uVar8 = uVar8 << 8;
84: puVar6 = *(undefined **)(lVar1 + 0x30);
85: } while (7 < iVar9);
86: }
87: }
88: else {
89: puVar6 = *(undefined **)(lVar1 + 0x30);
90: lVar7 = *(long *)(lVar1 + 0x38);
91: }
92: LAB_00118c80:
93: puVar4 = *(undefined8 **)(param_1 + 0x28);
94: *(undefined8 *)(lVar1 + 0x40) = 0;
95: *(undefined4 *)(lVar1 + 0x48) = 0;
96: *puVar4 = puVar6;
97: puVar4[1] = lVar7;
98: return;
99: }
100: 

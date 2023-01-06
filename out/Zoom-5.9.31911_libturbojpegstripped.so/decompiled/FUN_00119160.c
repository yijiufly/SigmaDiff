1: 
2: undefined8 FUN_00119160(long param_1,short **param_2)
3: 
4: {
5: long *plVar1;
6: undefined4 uVar2;
7: long lVar3;
8: undefined8 uVar4;
9: code **ppcVar5;
10: undefined8 *puVar6;
11: int iVar7;
12: undefined *puVar8;
13: int iVar9;
14: ulong uVar10;
15: ulong uVar11;
16: uint uVar12;
17: int iStack84;
18: uint uStack64;
19: byte bStack60;
20: 
21: uVar2 = *(undefined4 *)(param_1 + 0x1a8);
22: lVar3 = *(long *)(param_1 + 0x1f0);
23: iVar7 = *(int *)(param_1 + 0x118);
24: puVar8 = (undefined *)**(undefined8 **)(param_1 + 0x28);
25: uVar4 = (*(undefined8 **)(param_1 + 0x28))[1];
26: *(undefined **)(lVar3 + 0x30) = puVar8;
27: *(undefined8 *)(lVar3 + 0x38) = uVar4;
28: if ((iVar7 != 0) && (*(int *)(lVar3 + 0x80) == 0)) {
29: FUN_00118d20(lVar3,*(undefined4 *)(lVar3 + 0x84));
30: puVar8 = *(undefined **)(lVar3 + 0x30);
31: }
32: iVar7 = *(int *)(param_1 + 0x170);
33: if (0 < iVar7) {
34: uStack64 = *(uint *)(lVar3 + 0x48);
35: iStack84 = 0;
36: do {
37: if (*(int *)(lVar3 + 0x28) == 0) {
38: bStack60 = (byte)uVar2;
39: uVar12 = uStack64 + 1;
40: uVar10 = (ulong)((int)**param_2 >> (bStack60 & 0x1f) & 1) << (0x17U - (char)uStack64 & 0x3f)
41: | *(ulong *)(lVar3 + 0x40);
42: if (7 < (int)uVar12) {
43: do {
44: while( true ) {
45: uVar11 = uVar10;
46: uVar10 = uVar11 >> 0x10 & 0xff;
47: *(undefined **)(lVar3 + 0x30) = puVar8 + 1;
48: *puVar8 = (char)uVar10;
49: plVar1 = (long *)(lVar3 + 0x38);
50: *plVar1 = *plVar1 + -1;
51: if (*plVar1 == 0) {
52: puVar6 = *(undefined8 **)(*(long *)(lVar3 + 0x50) + 0x28);
53: iVar7 = (*(code *)puVar6[3])();
54: if (iVar7 == 0) {
55: ppcVar5 = (code **)**(code ***)(lVar3 + 0x50);
56: *(undefined4 *)(ppcVar5 + 5) = 0x18;
57: (**ppcVar5)();
58: }
59: puVar8 = (undefined *)*puVar6;
60: uVar4 = puVar6[1];
61: *(undefined **)(lVar3 + 0x30) = puVar8;
62: *(undefined8 *)(lVar3 + 0x38) = uVar4;
63: }
64: else {
65: puVar8 = *(undefined **)(lVar3 + 0x30);
66: }
67: if ((int)uVar10 == 0xff) break;
68: LAB_00119235:
69: uVar12 = uVar12 - 8;
70: uVar10 = uVar11 << 8;
71: if ((int)uVar12 < 8) goto LAB_001192c0;
72: }
73: *(undefined **)(lVar3 + 0x30) = puVar8 + 1;
74: *puVar8 = 0;
75: plVar1 = (long *)(lVar3 + 0x38);
76: *plVar1 = *plVar1 + -1;
77: if (*plVar1 == 0) {
78: puVar6 = *(undefined8 **)(*(long *)(lVar3 + 0x50) + 0x28);
79: iVar7 = (*(code *)puVar6[3])();
80: if (iVar7 == 0) {
81: ppcVar5 = (code **)**(code ***)(lVar3 + 0x50);
82: *(undefined4 *)(ppcVar5 + 5) = 0x18;
83: (**ppcVar5)();
84: }
85: puVar8 = (undefined *)*puVar6;
86: uVar4 = puVar6[1];
87: *(undefined **)(lVar3 + 0x30) = puVar8;
88: *(undefined8 *)(lVar3 + 0x38) = uVar4;
89: goto LAB_00119235;
90: }
91: uVar12 = uVar12 - 8;
92: puVar8 = *(undefined **)(lVar3 + 0x30);
93: uVar10 = uVar11 << 8;
94: } while (7 < (int)uVar12);
95: LAB_001192c0:
96: uVar10 = uVar11 << 8;
97: iVar7 = *(int *)(param_1 + 0x170);
98: uVar12 = uStack64 - 7 & 7;
99: }
100: *(ulong *)(lVar3 + 0x40) = uVar10;
101: *(uint *)(lVar3 + 0x48) = uVar12;
102: uStack64 = uVar12;
103: }
104: iStack84 = iStack84 + 1;
105: param_2 = param_2 + 1;
106: } while (iStack84 < iVar7);
107: }
108: puVar6 = *(undefined8 **)(param_1 + 0x28);
109: *puVar6 = puVar8;
110: puVar6[1] = *(undefined8 *)(lVar3 + 0x38);
111: iVar7 = *(int *)(param_1 + 0x118);
112: if (iVar7 != 0) {
113: iVar9 = *(int *)(lVar3 + 0x80);
114: if (*(int *)(lVar3 + 0x80) == 0) {
115: *(uint *)(lVar3 + 0x84) = *(int *)(lVar3 + 0x84) + 1U & 7;
116: iVar9 = iVar7;
117: }
118: *(int *)(lVar3 + 0x80) = iVar9 + -1;
119: }
120: return 1;
121: }
122: 

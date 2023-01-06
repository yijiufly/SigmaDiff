1: 
2: void FUN_00118690(long param_1)
3: 
4: {
5: long *plVar1;
6: byte *pbVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: undefined *puVar6;
11: undefined8 *puVar7;
12: code **ppcVar8;
13: int iVar9;
14: uint uVar10;
15: byte *pbVar11;
16: ulong uVar12;
17: ulong uVar13;
18: uint uStack68;
19: 
20: if (*(int *)(param_1 + 0x6c) == 0) {
21: return;
22: }
23: iVar9 = (byte)(&DAT_00179440)[*(int *)(param_1 + 0x6c)] - 1;
24: if (iVar9 < 0xf) {
25: iVar3 = *(int *)(param_1 + 0x28);
26: iVar4 = *(int *)(param_1 + 0x68);
27: }
28: else {
29: ppcVar8 = (code **)**(code ***)(param_1 + 0x50);
30: *(undefined4 *)(ppcVar8 + 5) = 0x28;
31: (**ppcVar8)();
32: iVar3 = *(int *)(param_1 + 0x28);
33: iVar4 = *(int *)(param_1 + 0x68);
34: }
35: if (iVar3 == 0) {
36: lVar5 = *(long *)(param_1 + 0x88 + (long)iVar4 * 8);
37: FUN_00118500(param_1,*(undefined4 *)(lVar5 + (long)(iVar9 * 0x10) * 4),
38: (int)*(char *)(lVar5 + 0x400 + (long)(iVar9 * 0x10)));
39: }
40: else {
41: plVar1 = (long *)(*(long *)(param_1 + 0xa8 + (long)iVar4 * 8) + (long)(iVar9 * 0x10) * 8);
42: *plVar1 = *plVar1 + 1;
43: }
44: if (iVar9 != 0) {
45: FUN_00118500(param_1,*(undefined4 *)(param_1 + 0x6c),iVar9);
46: }
47: *(undefined4 *)(param_1 + 0x6c) = 0;
48: pbVar11 = *(byte **)(param_1 + 0x78);
49: if ((*(int *)(param_1 + 0x28) == 0) && (*(int *)(param_1 + 0x70) != 0)) {
50: uStack68 = *(uint *)(param_1 + 0x48);
51: pbVar2 = pbVar11 + (ulong)(*(int *)(param_1 + 0x70) - 1) + 1;
52: iVar9 = 0;
53: do {
54: if (iVar9 == 0) {
55: uVar10 = uStack68 + 1;
56: uVar12 = (ulong)(*pbVar11 & 1) << (0x17U - (char)uStack68 & 0x3f) |
57: *(ulong *)(param_1 + 0x40);
58: if (7 < (int)uVar10) {
59: do {
60: while( true ) {
61: uVar13 = uVar12;
62: puVar6 = *(undefined **)(param_1 + 0x30);
63: uVar12 = uVar13 >> 0x10 & 0xff;
64: *(undefined **)(param_1 + 0x30) = puVar6 + 1;
65: *puVar6 = (char)uVar12;
66: plVar1 = (long *)(param_1 + 0x38);
67: *plVar1 = *plVar1 + -1;
68: if (*plVar1 == 0) {
69: puVar7 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
70: iVar9 = (*(code *)puVar7[3])();
71: if (iVar9 == 0) {
72: ppcVar8 = (code **)**(code ***)(param_1 + 0x50);
73: *(undefined4 *)(ppcVar8 + 5) = 0x18;
74: (**ppcVar8)();
75: }
76: *(undefined8 *)(param_1 + 0x30) = *puVar7;
77: *(undefined8 *)(param_1 + 0x38) = puVar7[1];
78: }
79: if ((int)uVar12 == 0xff) break;
80: LAB_001187d1:
81: uVar10 = uVar10 - 8;
82: uVar12 = uVar13 << 8;
83: if ((int)uVar10 < 8) goto LAB_00118890;
84: }
85: puVar6 = *(undefined **)(param_1 + 0x30);
86: *(undefined **)(param_1 + 0x30) = puVar6 + 1;
87: *puVar6 = 0;
88: plVar1 = (long *)(param_1 + 0x38);
89: *plVar1 = *plVar1 + -1;
90: if (*plVar1 != 0) goto LAB_001187d1;
91: puVar7 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
92: iVar9 = (*(code *)puVar7[3])();
93: if (iVar9 == 0) {
94: ppcVar8 = (code **)**(code ***)(param_1 + 0x50);
95: *(undefined4 *)(ppcVar8 + 5) = 0x18;
96: (**ppcVar8)();
97: }
98: uVar10 = uVar10 - 8;
99: *(undefined8 *)(param_1 + 0x30) = *puVar7;
100: *(undefined8 *)(param_1 + 0x38) = puVar7[1];
101: uVar12 = uVar13 << 8;
102: } while (7 < (int)uVar10);
103: LAB_00118890:
104: uVar12 = uVar13 << 8;
105: uVar10 = uStack68 - 7 & 7;
106: }
107: *(ulong *)(param_1 + 0x40) = uVar12;
108: *(uint *)(param_1 + 0x48) = uVar10;
109: uStack68 = uVar10;
110: }
111: pbVar11 = pbVar11 + 1;
112: if (pbVar11 == pbVar2) break;
113: iVar9 = *(int *)(param_1 + 0x28);
114: } while( true );
115: }
116: *(undefined4 *)(param_1 + 0x70) = 0;
117: return;
118: }
119: 

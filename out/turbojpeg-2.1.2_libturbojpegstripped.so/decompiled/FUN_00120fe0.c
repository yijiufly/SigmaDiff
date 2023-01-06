1: 
2: void FUN_00120fe0(long param_1,char param_2)
3: 
4: {
5: long *plVar1;
6: undefined8 *puVar2;
7: code **ppcVar3;
8: undefined8 uVar4;
9: char **ppcVar5;
10: int iVar6;
11: undefined *puVar7;
12: char *pcVar8;
13: undefined *puVar9;
14: ulong uVar10;
15: uint uVar11;
16: uint uVar12;
17: 
18: FUN_00120910();
19: if (*(int *)(param_1 + 0x28) == 0) {
20: puVar7 = *(undefined **)(param_1 + 0x30);
21: uVar12 = *(int *)(param_1 + 0x48) + 7;
22: uVar10 = 0x7f << (0x18U - (char)uVar12 & 0x3f) | *(ulong *)(param_1 + 0x40);
23: if ((int)uVar12 < 8) {
24: puVar9 = puVar7 + 1;
25: }
26: else {
27: puVar9 = puVar7 + 1;
28: uVar11 = *(int *)(param_1 + 0x48) - 1U & 7;
29: do {
30: while( true ) {
31: *(undefined **)(param_1 + 0x30) = puVar9;
32: *puVar7 = (char)(uVar10 >> 0x10);
33: plVar1 = (long *)(param_1 + 0x38);
34: *plVar1 = *plVar1 + -1;
35: if (*plVar1 == 0) {
36: puVar2 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
37: iVar6 = (*(code *)puVar2[3])();
38: if (iVar6 == 0) {
39: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
40: *(undefined4 *)(ppcVar3 + 5) = 0x18;
41: (**ppcVar3)();
42: }
43: puVar7 = (undefined *)*puVar2;
44: uVar4 = puVar2[1];
45: *(undefined **)(param_1 + 0x30) = puVar7;
46: *(undefined8 *)(param_1 + 0x38) = uVar4;
47: }
48: else {
49: puVar7 = *(undefined **)(param_1 + 0x30);
50: }
51: puVar9 = puVar7 + 1;
52: if (((uint)(uVar10 >> 0x10) & 0xff) == 0xff) break;
53: LAB_001210a0:
54: uVar10 = uVar10 << 8;
55: uVar12 = uVar12 - 8;
56: if (uVar11 == uVar12) goto LAB_00121110;
57: }
58: *(undefined **)(param_1 + 0x30) = puVar9;
59: *puVar7 = 0;
60: plVar1 = (long *)(param_1 + 0x38);
61: *plVar1 = *plVar1 + -1;
62: if (*plVar1 == 0) {
63: puVar2 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
64: iVar6 = (*(code *)puVar2[3])();
65: if (iVar6 == 0) {
66: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
67: *(undefined4 *)(ppcVar3 + 5) = 0x18;
68: (**ppcVar3)();
69: }
70: puVar7 = (undefined *)*puVar2;
71: *(undefined8 *)(param_1 + 0x38) = puVar2[1];
72: puVar9 = puVar7 + 1;
73: *(undefined **)(param_1 + 0x30) = puVar7;
74: goto LAB_001210a0;
75: }
76: puVar7 = *(undefined **)(param_1 + 0x30);
77: uVar10 = uVar10 << 8;
78: uVar12 = uVar12 - 8;
79: puVar9 = puVar7 + 1;
80: } while (uVar11 != uVar12);
81: }
82: LAB_00121110:
83: *(undefined8 *)(param_1 + 0x40) = 0;
84: *(undefined4 *)(param_1 + 0x48) = 0;
85: *(undefined **)(param_1 + 0x30) = puVar9;
86: *puVar7 = 0xff;
87: plVar1 = (long *)(param_1 + 0x38);
88: *plVar1 = *plVar1 + -1;
89: if (*plVar1 == 0) {
90: ppcVar5 = *(char ***)(*(long *)(param_1 + 0x50) + 0x28);
91: iVar6 = (*(code *)ppcVar5[3])();
92: if (iVar6 == 0) {
93: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
94: *(undefined4 *)(ppcVar3 + 5) = 0x18;
95: (**ppcVar3)();
96: }
97: pcVar8 = *ppcVar5;
98: *(char **)(param_1 + 0x38) = ppcVar5[1];
99: }
100: else {
101: pcVar8 = *(char **)(param_1 + 0x30);
102: }
103: *(char **)(param_1 + 0x30) = pcVar8 + 1;
104: *pcVar8 = param_2 + -0x30;
105: plVar1 = (long *)(param_1 + 0x38);
106: *plVar1 = *plVar1 + -1;
107: if (*plVar1 == 0) {
108: puVar2 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
109: iVar6 = (*(code *)puVar2[3])();
110: if (iVar6 == 0) {
111: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
112: *(undefined4 *)(ppcVar3 + 5) = 0x18;
113: (**ppcVar3)();
114: }
115: *(undefined8 *)(param_1 + 0x30) = *puVar2;
116: *(undefined8 *)(param_1 + 0x38) = puVar2[1];
117: }
118: }
119: if (*(int *)(*(long *)(param_1 + 0x50) + 0x19c) == 0) {
120: iVar6 = *(int *)(*(long *)(param_1 + 0x50) + 0x144);
121: if (0 < iVar6) {
122: memset((void *)(param_1 + 0x58),0,(ulong)(iVar6 - 1) * 4 + 4);
123: return;
124: }
125: }
126: else {
127: *(undefined8 *)(param_1 + 0x6c) = 0;
128: }
129: return;
130: }
131: 

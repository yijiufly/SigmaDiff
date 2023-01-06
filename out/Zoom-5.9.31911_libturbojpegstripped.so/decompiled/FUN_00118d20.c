1: 
2: void FUN_00118d20(long param_1,char param_2)
3: 
4: {
5: long *plVar1;
6: undefined8 uVar2;
7: undefined8 *puVar3;
8: code **ppcVar4;
9: char **ppcVar5;
10: int iVar6;
11: int iVar7;
12: undefined *puVar8;
13: char *pcVar9;
14: ulong uVar10;
15: ulong uVar11;
16: 
17: FUN_00118690();
18: if (*(int *)(param_1 + 0x28) != 0) {
19: LAB_00118d40:
20: if (*(int *)(*(long *)(param_1 + 0x50) + 0x19c) == 0) {
21: iVar7 = *(int *)(*(long *)(param_1 + 0x50) + 0x144);
22: if (0 < iVar7) {
23: memset((void *)(param_1 + 0x58),0,(long)iVar7 << 2);
24: return;
25: }
26: }
27: else {
28: *(undefined4 *)(param_1 + 0x6c) = 0;
29: *(undefined4 *)(param_1 + 0x70) = 0;
30: }
31: return;
32: }
33: iVar7 = *(int *)(param_1 + 0x48) + 7;
34: puVar8 = *(undefined **)(param_1 + 0x30);
35: uVar10 = 0x7f << (0x11U - (char)*(int *)(param_1 + 0x48) & 0x3f) | *(ulong *)(param_1 + 0x40);
36: joined_r0x00118dc2:
37: if (7 < iVar7) {
38: do {
39: uVar11 = uVar10 >> 0x10 & 0xff;
40: *(undefined **)(param_1 + 0x30) = puVar8 + 1;
41: *puVar8 = (char)uVar11;
42: plVar1 = (long *)(param_1 + 0x38);
43: *plVar1 = *plVar1 + -1;
44: if (*plVar1 == 0) {
45: puVar3 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
46: iVar6 = (*(code *)puVar3[3])();
47: if (iVar6 == 0) {
48: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
49: *(undefined4 *)(ppcVar4 + 5) = 0x18;
50: (**ppcVar4)();
51: }
52: puVar8 = (undefined *)*puVar3;
53: uVar2 = puVar3[1];
54: *(undefined **)(param_1 + 0x30) = puVar8;
55: *(undefined8 *)(param_1 + 0x38) = uVar2;
56: }
57: else {
58: puVar8 = *(undefined **)(param_1 + 0x30);
59: }
60: if ((int)uVar11 == 0xff) {
61: *(undefined **)(param_1 + 0x30) = puVar8 + 1;
62: *puVar8 = 0;
63: plVar1 = (long *)(param_1 + 0x38);
64: *plVar1 = *plVar1 + -1;
65: if (*plVar1 != 0) goto code_r0x00118e5a;
66: puVar3 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
67: iVar6 = (*(code *)puVar3[3])();
68: if (iVar6 == 0) {
69: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
70: *(undefined4 *)(ppcVar4 + 5) = 0x18;
71: (**ppcVar4)();
72: }
73: puVar8 = (undefined *)*puVar3;
74: uVar2 = puVar3[1];
75: *(undefined **)(param_1 + 0x30) = puVar8;
76: *(undefined8 *)(param_1 + 0x38) = uVar2;
77: }
78: iVar7 = iVar7 + -8;
79: uVar10 = uVar10 << 8;
80: if (iVar7 < 8) break;
81: } while( true );
82: }
83: *(undefined8 *)(param_1 + 0x40) = 0;
84: *(undefined4 *)(param_1 + 0x48) = 0;
85: *(undefined **)(param_1 + 0x30) = puVar8 + 1;
86: *puVar8 = 0xff;
87: plVar1 = (long *)(param_1 + 0x38);
88: *plVar1 = *plVar1 + -1;
89: if (*plVar1 == 0) {
90: ppcVar5 = *(char ***)(*(long *)(param_1 + 0x50) + 0x28);
91: iVar7 = (*(code *)ppcVar5[3])();
92: if (iVar7 == 0) {
93: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
94: *(undefined4 *)(ppcVar4 + 5) = 0x18;
95: (**ppcVar4)();
96: }
97: pcVar9 = *ppcVar5;
98: *(char **)(param_1 + 0x38) = ppcVar5[1];
99: }
100: else {
101: pcVar9 = *(char **)(param_1 + 0x30);
102: }
103: *(char **)(param_1 + 0x30) = pcVar9 + 1;
104: *pcVar9 = param_2 + -0x30;
105: plVar1 = (long *)(param_1 + 0x38);
106: *plVar1 = *plVar1 + -1;
107: if (*plVar1 == 0) {
108: puVar3 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
109: iVar7 = (*(code *)puVar3[3])();
110: if (iVar7 == 0) {
111: ppcVar4 = (code **)**(code ***)(param_1 + 0x50);
112: *(undefined4 *)(ppcVar4 + 5) = 0x18;
113: (**ppcVar4)();
114: }
115: *(undefined8 *)(param_1 + 0x30) = *puVar3;
116: *(undefined8 *)(param_1 + 0x38) = puVar3[1];
117: }
118: goto LAB_00118d40;
119: code_r0x00118e5a:
120: iVar7 = iVar7 + -8;
121: uVar10 = uVar10 << 8;
122: puVar8 = *(undefined **)(param_1 + 0x30);
123: goto joined_r0x00118dc2;
124: }
125: 

1: 
2: void FUN_00120d20(long param_1)
3: 
4: {
5: undefined8 *puVar1;
6: long lVar2;
7: int iVar3;
8: int iVar4;
9: undefined8 uVar5;
10: long lVar6;
11: long lVar7;
12: long in_FS_OFFSET;
13: undefined auStack72 [16];
14: long lStack48;
15: 
16: lVar2 = *(long *)(param_1 + 0x1f0);
17: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
18: FUN_00120910();
19: iVar4 = *(int *)(param_1 + 0x144);
20: auStack72 = (undefined  [16])0x0;
21: if (0 < iVar4) {
22: if (*(int *)(param_1 + 0x19c) == 0) {
23: lVar6 = 1;
24: do {
25: if (*(int *)(param_1 + 0x1a4) == 0) {
26: lVar7 = (long)*(int *)(*(long *)(param_1 + 0x140 + lVar6 * 8) + 0x14);
27: if (*(int *)(auStack72 + lVar7 * 4) == 0) {
28: puVar1 = (undefined8 *)(param_1 + (lVar7 + 0x10) * 8);
29: if (*(long *)(param_1 + (lVar7 + 0x10) * 8) == 0) {
30: uVar5 = FUN_0011f530(param_1);
31: *puVar1 = uVar5;
32: }
33: else {
34: uVar5 = *puVar1;
35: }
36: FUN_0011b860(param_1,uVar5,*(undefined8 *)(lVar2 + 0xa8 + lVar7 * 8));
37: iVar4 = *(int *)(param_1 + 0x144);
38: *(undefined4 *)(auStack72 + lVar7 * 4) = 1;
39: }
40: }
41: iVar3 = (int)lVar6;
42: lVar6 = lVar6 + 1;
43: } while (iVar3 < iVar4);
44: }
45: else {
46: lVar6 = (long)*(int *)(*(long *)(param_1 + 0x148) + 0x18);
47: if (*(int *)(auStack72 + lVar6 * 4) == 0) {
48: puVar1 = (undefined8 *)(param_1 + (lVar6 + 0x14) * 8);
49: if (*(long *)(param_1 + (lVar6 + 0x14) * 8) == 0) {
50: uVar5 = FUN_0011f530(0,param_1);
51: *puVar1 = uVar5;
52: }
53: else {
54: uVar5 = *puVar1;
55: }
56: FUN_0011b860(param_1,uVar5,*(undefined8 *)(lVar2 + 0xa8 + lVar6 * 8));
57: *(undefined4 *)(auStack72 + lVar6 * 4) = 1;
58: iVar4 = *(int *)(param_1 + 0x144);
59: }
60: if (1 < iVar4) {
61: lVar6 = (long)*(int *)(*(long *)(param_1 + 0x150) + 0x18);
62: if (*(int *)(auStack72 + lVar6 * 4) == 0) {
63: puVar1 = (undefined8 *)(param_1 + (lVar6 + 0x14) * 8);
64: if (*(long *)(param_1 + (lVar6 + 0x14) * 8) == 0) {
65: uVar5 = FUN_0011f530(param_1);
66: *puVar1 = uVar5;
67: }
68: else {
69: uVar5 = *puVar1;
70: }
71: FUN_0011b860(param_1,uVar5,*(undefined8 *)(lVar2 + 0xa8 + lVar6 * 8));
72: *(undefined4 *)(auStack72 + lVar6 * 4) = 1;
73: iVar4 = *(int *)(param_1 + 0x144);
74: }
75: if (2 < iVar4) {
76: lVar6 = (long)*(int *)(*(long *)(param_1 + 0x158) + 0x18);
77: if (*(int *)(auStack72 + lVar6 * 4) == 0) {
78: puVar1 = (undefined8 *)(param_1 + (lVar6 + 0x14) * 8);
79: if (*(long *)(param_1 + (lVar6 + 0x14) * 8) == 0) {
80: uVar5 = FUN_0011f530(param_1);
81: *puVar1 = uVar5;
82: }
83: else {
84: uVar5 = *puVar1;
85: }
86: FUN_0011b860(param_1,uVar5,*(undefined8 *)(lVar2 + 0xa8 + lVar6 * 8));
87: *(undefined4 *)(auStack72 + lVar6 * 4) = 1;
88: iVar4 = *(int *)(param_1 + 0x144);
89: }
90: if (3 < iVar4) {
91: lVar6 = (long)*(int *)(*(long *)(param_1 + 0x160) + 0x18);
92: if (*(int *)(auStack72 + lVar6 * 4) == 0) {
93: puVar1 = (undefined8 *)(param_1 + (lVar6 + 0x14) * 8);
94: if (*(long *)(param_1 + (lVar6 + 0x14) * 8) == 0) {
95: uVar5 = FUN_0011f530(param_1);
96: *puVar1 = uVar5;
97: }
98: else {
99: uVar5 = *puVar1;
100: }
101: if (lStack48 == *(long *)(in_FS_OFFSET + 0x28)) {
102: FUN_0011b860(param_1,uVar5,*(undefined8 *)(lVar2 + 0xa8 + lVar6 * 8));
103: return;
104: }
105: goto LAB_00120fd4;
106: }
107: }
108: }
109: }
110: }
111: }
112: if (lStack48 == *(long *)(in_FS_OFFSET + 0x28)) {
113: return;
114: }
115: LAB_00120fd4:
116: /* WARNING: Subroutine does not return */
117: __stack_chk_fail();
118: }
119: 

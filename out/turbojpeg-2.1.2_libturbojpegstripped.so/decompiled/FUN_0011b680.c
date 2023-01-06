1: 
2: void FUN_0011b680(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: uint uVar2;
7: uint uVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: undefined4 uVar6;
11: code *pcVar7;
12: undefined8 *puVar8;
13: ulong uVar9;
14: code *pcVar10;
15: long lVar11;
16: byte bVar12;
17: 
18: bVar12 = 0;
19: pcVar10 = FUN_0011bce0;
20: pcVar4 = param_1[0x3e];
21: if (param_2 == 0) {
22: pcVar10 = FUN_0011b0e0;
23: }
24: pcVar7 = FUN_00109240;
25: if (param_2 == 0) {
26: pcVar7 = FUN_00109620;
27: }
28: *(code **)(pcVar4 + 0x10) = pcVar10;
29: *(code **)(pcVar4 + 8) = pcVar7;
30: uVar6 = FUN_0016c270();
31: iVar1 = *(int *)((long)param_1 + 0x144);
32: *(undefined4 *)(pcVar4 + 0xc0) = uVar6;
33: if (0 < iVar1) {
34: lVar11 = 1;
35: do {
36: uVar2 = *(uint *)(param_1[lVar11 + 0x28] + 0x14);
37: uVar3 = *(uint *)(param_1[lVar11 + 0x28] + 0x18);
38: if (param_2 == 0) {
39: FUN_0011b2f0(param_1,1,uVar2,pcVar4 + (long)(int)uVar2 * 8 + 0x40);
40: FUN_0011b2f0(param_1,0,(long)(int)uVar3 & 0xffffffff);
41: }
42: else {
43: if (3 < uVar2) {
44: ppcVar5 = (code **)*param_1;
45: *(undefined4 *)(ppcVar5 + 5) = 0x32;
46: *(uint *)((long)ppcVar5 + 0x2c) = uVar2;
47: (**ppcVar5)(param_1);
48: }
49: if (3 < uVar3) {
50: ppcVar5 = (code **)*param_1;
51: *(undefined4 *)(ppcVar5 + 5) = 0x32;
52: *(uint *)((long)ppcVar5 + 0x2c) = uVar3;
53: (**ppcVar5)(param_1);
54: }
55: puVar8 = *(undefined8 **)(pcVar4 + (long)(int)uVar2 * 8 + 0x80);
56: if (puVar8 == (undefined8 *)0x0) {
57: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
58: *(undefined8 **)(pcVar4 + (long)(int)uVar2 * 8 + 0x80) = puVar8;
59: }
60: *puVar8 = 0;
61: puVar8[0x100] = 0;
62: uVar9 = (ulong)(((int)puVar8 - (int)(undefined8 *)((ulong)(puVar8 + 1) & 0xfffffffffffffff8)
63: ) + 0x808U >> 3);
64: puVar8 = (undefined8 *)((ulong)(puVar8 + 1) & 0xfffffffffffffff8);
65: while (uVar9 != 0) {
66: uVar9 = uVar9 - 1;
67: *puVar8 = 0;
68: puVar8 = puVar8 + (ulong)bVar12 * -2 + 1;
69: }
70: puVar8 = *(undefined8 **)(pcVar4 + (long)(int)uVar3 * 8 + 0xa0);
71: if (puVar8 == (undefined8 *)0x0) {
72: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
73: *(undefined8 **)(pcVar4 + (long)(int)uVar3 * 8 + 0xa0) = puVar8;
74: }
75: *puVar8 = 0;
76: puVar8[0x100] = 0;
77: uVar9 = (ulong)(((int)puVar8 - (int)(undefined8 *)((ulong)(puVar8 + 1) & 0xfffffffffffffff8)
78: ) + 0x808U >> 3);
79: puVar8 = (undefined8 *)((ulong)(puVar8 + 1) & 0xfffffffffffffff8);
80: while (uVar9 != 0) {
81: uVar9 = uVar9 - 1;
82: *puVar8 = 0;
83: puVar8 = puVar8 + (ulong)bVar12 * -2 + 1;
84: }
85: }
86: *(undefined4 *)(pcVar4 + lVar11 * 4 + 0x20) = 0;
87: iVar1 = (int)lVar11;
88: lVar11 = lVar11 + 1;
89: } while (*(int *)((long)param_1 + 0x144) != iVar1 && iVar1 <= *(int *)((long)param_1 + 0x144));
90: }
91: uVar6 = *(undefined4 *)(param_1 + 0x23);
92: *(undefined8 *)(pcVar4 + 0x18) = 0;
93: *(undefined4 *)(pcVar4 + 0x20) = 0x40;
94: *(undefined4 *)(pcVar4 + 0x3c) = 0;
95: *(undefined4 *)(pcVar4 + 0x38) = uVar6;
96: return;
97: }
98: 

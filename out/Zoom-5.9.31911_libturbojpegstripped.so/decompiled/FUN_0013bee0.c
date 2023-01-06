1: 
2: long FUN_0013bee0(code **param_1,uint param_2,ulong param_3)
3: 
4: {
5: long *plVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code *pcVar4;
9: ulong uVar5;
10: undefined8 *puVar6;
11: long lVar7;
12: undefined8 *puVar8;
13: ulong uVar9;
14: ulong uVar10;
15: 
16: pcVar2 = param_1[1];
17: if (1000000000 < param_3) {
18: pcVar3 = *param_1;
19: *(undefined4 *)(pcVar3 + 0x28) = 0x36;
20: *(undefined4 *)(pcVar3 + 0x2c) = 7;
21: (**(code **)*param_1)();
22: }
23: uVar10 = param_3 + 0x1f & 0xffffffffffffffe0;
24: if (1000000000 < uVar10 + 0x37) {
25: pcVar3 = *param_1;
26: *(undefined4 *)(pcVar3 + 0x28) = 0x36;
27: *(undefined4 *)(pcVar3 + 0x2c) = 1;
28: (**(code **)*param_1)(param_1);
29: }
30: if (1 < param_2) {
31: pcVar3 = *param_1;
32: *(undefined4 *)(pcVar3 + 0x28) = 0xe;
33: *(uint *)(pcVar3 + 0x2c) = param_2;
34: (**(code **)*param_1)(param_1);
35: }
36: lVar7 = (long)(int)param_2;
37: pcVar3 = pcVar2 + lVar7 * 8;
38: puVar8 = *(undefined8 **)(pcVar3 + 0x68);
39: if (puVar8 == (undefined8 *)0x0) {
40: uVar5 = *(ulong *)(&DAT_0018b5c0 + lVar7 * 8);
41: LAB_0013bf87:
42: uVar9 = 0x3b9ac9c9 - uVar10;
43: if (uVar5 <= 0x3b9ac9c9 - uVar10) {
44: uVar9 = uVar5;
45: }
46: while( true ) {
47: lVar7 = uVar9 + uVar10 + 0x37;
48: puVar6 = (undefined8 *)FUN_0013d8e0(param_1,lVar7);
49: if (puVar6 != (undefined8 *)0x0) break;
50: uVar9 = uVar9 >> 1;
51: if (uVar9 < 0x32) {
52: pcVar4 = *param_1;
53: *(undefined4 *)(pcVar4 + 0x28) = 0x36;
54: *(undefined4 *)(pcVar4 + 0x2c) = 2;
55: (**(code **)*param_1)(param_1);
56: }
57: }
58: uVar9 = uVar9 + uVar10;
59: plVar1 = (long *)(pcVar2 + 0x98);
60: *plVar1 = *plVar1 + lVar7;
61: *puVar6 = 0;
62: puVar6[1] = 0;
63: puVar6[2] = uVar9;
64: if (puVar8 == (undefined8 *)0x0) {
65: *(undefined8 **)(pcVar3 + 0x68) = puVar6;
66: lVar7 = 0;
67: }
68: else {
69: *puVar8 = puVar6;
70: lVar7 = 0;
71: }
72: }
73: else {
74: uVar9 = puVar8[2];
75: puVar6 = puVar8;
76: while (uVar9 < uVar10) {
77: puVar8 = (undefined8 *)*puVar6;
78: if (puVar8 == (undefined8 *)0x0) {
79: uVar5 = *(ulong *)(&DAT_0018b5b0 + lVar7 * 8);
80: puVar8 = puVar6;
81: goto LAB_0013bf87;
82: }
83: uVar9 = puVar8[2];
84: puVar6 = puVar8;
85: }
86: lVar7 = puVar6[1];
87: }
88: puVar8 = puVar6 + 3;
89: if (((ulong)puVar8 & 0x1f) != 0) {
90: puVar8 = (undefined8 *)((long)puVar8 + (0x20 - (ulong)((uint)puVar8 & 0x1f)));
91: }
92: puVar6[2] = uVar9 - uVar10;
93: puVar6[1] = lVar7 + uVar10;
94: return (long)puVar8 + lVar7;
95: }
96: 

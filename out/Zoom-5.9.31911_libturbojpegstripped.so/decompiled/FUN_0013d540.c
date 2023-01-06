1: 
2: void FUN_0013d540(code **param_1,uint param_2,undefined4 param_3,undefined4 param_4,
3: undefined4 param_5,undefined4 param_6)
4: 
5: {
6: code *pcVar1;
7: code *pcVar2;
8: undefined8 uVar3;
9: ulong uVar4;
10: undefined8 *puVar5;
11: undefined8 *puVar6;
12: long lVar7;
13: long lVar8;
14: long lVar9;
15: code *pcVar10;
16: ulong uVar11;
17: 
18: lVar7 = (long)(int)param_2;
19: pcVar1 = param_1[1];
20: pcVar10 = pcVar1;
21: if (param_2 != 1) {
22: pcVar10 = *param_1;
23: *(undefined4 *)(pcVar10 + 0x28) = 0xe;
24: *(uint *)(pcVar10 + 0x2c) = param_2;
25: (**(code **)*param_1)();
26: pcVar10 = param_1[1];
27: if (1 < param_2) {
28: pcVar2 = *param_1;
29: *(undefined4 *)(pcVar2 + 0x28) = 0xe;
30: *(uint *)(pcVar2 + 0x2c) = param_2;
31: (**(code **)*param_1)(param_1);
32: }
33: }
34: puVar6 = *(undefined8 **)(pcVar10 + lVar7 * 8 + 0x68);
35: if (puVar6 == (undefined8 *)0x0) {
36: uVar4 = *(ulong *)(&DAT_0018b5c0 + lVar7 * 8);
37: LAB_0013d5f2:
38: uVar11 = 0x3b9ac929;
39: if (uVar4 < 0x3b9ac92a) {
40: uVar11 = uVar4;
41: }
42: while( true ) {
43: puVar5 = (undefined8 *)FUN_0013d8e0(param_1);
44: if (puVar5 != (undefined8 *)0x0) break;
45: uVar11 = uVar11 >> 1;
46: if (uVar11 < 0x32) {
47: pcVar2 = *param_1;
48: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
49: *(undefined4 *)(pcVar2 + 0x2c) = 2;
50: (**(code **)*param_1)(param_1);
51: }
52: }
53: uVar4 = uVar11 + 0xa0;
54: *(ulong *)(pcVar10 + 0x98) = *(long *)(pcVar10 + 0x98) + uVar11 + 0xd7;
55: *puVar5 = 0;
56: puVar5[1] = 0;
57: puVar5[2] = uVar4;
58: if (puVar6 == (undefined8 *)0x0) {
59: lVar9 = 0xa0;
60: lVar8 = 0;
61: *(undefined8 **)(pcVar10 + lVar7 * 8 + 0x68) = puVar5;
62: }
63: else {
64: *puVar6 = puVar5;
65: lVar9 = 0xa0;
66: lVar8 = 0;
67: }
68: }
69: else {
70: uVar4 = puVar6[2];
71: puVar5 = puVar6;
72: while (uVar4 < 0xa0) {
73: puVar6 = (undefined8 *)*puVar5;
74: if (puVar6 == (undefined8 *)0x0) {
75: uVar4 = *(ulong *)(&DAT_0018b5b0 + lVar7 * 8);
76: puVar6 = puVar5;
77: goto LAB_0013d5f2;
78: }
79: uVar4 = puVar6[2];
80: puVar5 = puVar6;
81: }
82: lVar8 = puVar5[1];
83: lVar9 = lVar8 + 0xa0;
84: }
85: puVar6 = puVar5 + 3;
86: if (((ulong)puVar6 & 0x1f) != 0) {
87: puVar6 = (undefined8 *)((long)puVar6 + (0x20 - (ulong)((uint)puVar6 & 0x1f)));
88: }
89: puVar6 = (undefined8 *)((long)puVar6 + lVar8);
90: puVar5[1] = lVar9;
91: puVar5[2] = uVar4 - 0xa0;
92: uVar3 = *(undefined8 *)(pcVar1 + 0x88);
93: *(undefined4 *)(puVar6 + 1) = param_5;
94: *puVar6 = 0;
95: *(undefined4 *)((long)puVar6 + 0xc) = param_4;
96: *(undefined4 *)((long)puVar6 + 0x2c) = 0;
97: *(undefined4 *)(puVar6 + 2) = param_6;
98: puVar6[6] = uVar3;
99: *(undefined4 *)((long)puVar6 + 0x24) = param_3;
100: *(undefined8 **)(pcVar1 + 0x88) = puVar6;
101: return;
102: }
103: 

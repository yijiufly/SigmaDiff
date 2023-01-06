1: 
2: undefined8 *
3: FUN_00149d00(code **param_1,uint param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
4: undefined4 param_6)
5: 
6: {
7: code *pcVar1;
8: code **ppcVar2;
9: undefined8 *puVar3;
10: undefined8 *puVar4;
11: ulong uVar5;
12: long lVar6;
13: long lVar7;
14: code *pcVar8;
15: 
16: pcVar1 = param_1[1];
17: pcVar8 = pcVar1;
18: if (param_2 != 1) {
19: ppcVar2 = (code **)*param_1;
20: *(undefined4 *)(ppcVar2 + 5) = 0xe;
21: *(uint *)((long)ppcVar2 + 0x2c) = param_2;
22: (**ppcVar2)();
23: pcVar8 = param_1[1];
24: if (1 < param_2) {
25: ppcVar2 = (code **)*param_1;
26: *(undefined4 *)(ppcVar2 + 5) = 0xe;
27: *(uint *)((long)ppcVar2 + 0x2c) = param_2;
28: (**ppcVar2)(param_1);
29: }
30: }
31: lVar6 = (long)(int)param_2;
32: puVar3 = *(undefined8 **)(pcVar8 + lVar6 * 8 + 0x68);
33: puVar4 = puVar3;
34: if (puVar3 == (undefined8 *)0x0) {
35: uVar5 = *(ulong *)(&DAT_0018f260 + lVar6 * 8);
36: LAB_00149db3:
37: if (0x3b9ac929 < uVar5) {
38: uVar5 = 0x3b9ac929;
39: }
40: while( true ) {
41: puVar3 = (undefined8 *)FUN_0014a5a0(param_1);
42: if (puVar3 != (undefined8 *)0x0) break;
43: uVar5 = uVar5 >> 1;
44: if (uVar5 < 0x32) {
45: ppcVar2 = (code **)*param_1;
46: ppcVar2[5] = (code *)0x200000036;
47: (**ppcVar2)(param_1);
48: }
49: }
50: *(ulong *)(pcVar8 + 0x98) = *(long *)(pcVar8 + 0x98) + uVar5 + 0xd7;
51: uVar5 = uVar5 + 0xa0;
52: *puVar3 = 0;
53: puVar3[1] = 0;
54: puVar3[2] = uVar5;
55: if (puVar4 == (undefined8 *)0x0) {
56: lVar7 = 0xa0;
57: *(undefined8 **)(pcVar8 + lVar6 * 8 + 0x68) = puVar3;
58: lVar6 = 0;
59: }
60: else {
61: *puVar4 = puVar3;
62: lVar7 = 0xa0;
63: lVar6 = 0;
64: }
65: }
66: else {
67: uVar5 = puVar3[2];
68: if (uVar5 < 0xa0) {
69: do {
70: puVar3 = (undefined8 *)*puVar4;
71: if (puVar3 == (undefined8 *)0x0) {
72: uVar5 = *(ulong *)(&DAT_0018f250 + lVar6 * 8);
73: goto LAB_00149db3;
74: }
75: uVar5 = puVar3[2];
76: puVar4 = puVar3;
77: } while (uVar5 < 0xa0);
78: lVar6 = puVar3[1];
79: lVar7 = lVar6 + 0xa0;
80: }
81: else {
82: lVar6 = puVar3[1];
83: lVar7 = lVar6 + 0xa0;
84: }
85: }
86: puVar4 = puVar3 + 3;
87: if (((ulong)puVar4 & 0x1f) != 0) {
88: puVar4 = (undefined8 *)((long)puVar4 + (0x20 - (ulong)((uint)puVar4 & 0x1f)));
89: }
90: puVar3[1] = lVar7;
91: puVar4 = (undefined8 *)((long)puVar4 + lVar6);
92: puVar3[2] = uVar5 - 0xa0;
93: *puVar4 = 0;
94: *(undefined4 *)((long)puVar4 + 0x2c) = 0;
95: *(undefined4 *)(puVar4 + 1) = param_5;
96: *(undefined4 *)((long)puVar4 + 0xc) = param_4;
97: *(undefined4 *)(puVar4 + 2) = param_6;
98: *(undefined4 *)((long)puVar4 + 0x24) = param_3;
99: puVar4[6] = *(undefined8 *)(pcVar1 + 0x88);
100: *(undefined8 **)(pcVar1 + 0x88) = puVar4;
101: return puVar4;
102: }
103: 

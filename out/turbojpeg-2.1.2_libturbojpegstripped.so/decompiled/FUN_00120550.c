1: 
2: void FUN_00120550(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: undefined4 uVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: int iVar5;
10: int iVar6;
11: code *pcVar7;
12: undefined8 *puVar8;
13: undefined8 uVar9;
14: ulong uVar10;
15: uint uVar11;
16: long lVar12;
17: byte bVar13;
18: 
19: bVar13 = 0;
20: pcVar3 = param_1[0x3e];
21: iVar1 = *(int *)((long)param_1 + 0x19c);
22: *(int *)(pcVar3 + 0x28) = param_2;
23: iVar6 = *(int *)((long)param_1 + 0x1a4);
24: *(code ***)(pcVar3 + 0x50) = param_1;
25: if (iVar6 == 0) {
26: pcVar7 = FUN_00121240;
27: if (iVar1 != 0) {
28: pcVar7 = FUN_001215b0;
29: }
30: *(code **)(pcVar3 + 8) = pcVar7;
31: iVar6 = FUN_0016c290();
32: if (iVar6 == 0) {
33: *(code **)(pcVar3 + 0x18) = FUN_00120400;
34: }
35: else {
36: *(code **)(pcVar3 + 0x18) = FUN_0016c2a0;
37: }
38: }
39: else {
40: if (iVar1 == 0) {
41: *(code **)(pcVar3 + 8) = FUN_00121b20;
42: }
43: else {
44: *(code **)(pcVar3 + 8) = FUN_00121da0;
45: iVar6 = FUN_0016c2b0();
46: pcVar7 = FUN_00120490;
47: if (iVar6 != 0) {
48: pcVar7 = FUN_0016c2c0;
49: }
50: *(code **)(pcVar3 + 0x20) = pcVar7;
51: if (*(long *)(pcVar3 + 0x78) == 0) {
52: uVar9 = (**(code **)param_1[1])(param_1,1,1000);
53: *(undefined8 *)(pcVar3 + 0x78) = uVar9;
54: }
55: }
56: }
57: pcVar7 = FUN_00120d20;
58: if (param_2 == 0) {
59: pcVar7 = FUN_00120b60;
60: }
61: *(code **)(pcVar3 + 0x10) = pcVar7;
62: iVar6 = *(int *)((long)param_1 + 0x144);
63: if (0 < iVar6) {
64: lVar12 = 1;
65: do {
66: pcVar7 = param_1[lVar12 + 0x28];
67: *(undefined4 *)(pcVar3 + lVar12 * 4 + 0x54) = 0;
68: if (iVar1 == 0) {
69: if (*(int *)((long)param_1 + 0x1a4) == 0) {
70: uVar11 = *(uint *)(pcVar7 + 0x14);
71: if (param_2 == 0) goto LAB_00120720;
72: LAB_00120634:
73: if (3 < uVar11) {
74: ppcVar4 = (code **)*param_1;
75: *(undefined4 *)(ppcVar4 + 5) = 0x32;
76: *(uint *)((long)ppcVar4 + 0x2c) = uVar11;
77: (**ppcVar4)(param_1);
78: }
79: puVar8 = *(undefined8 **)(pcVar3 + (long)(int)uVar11 * 8 + 0xa8);
80: if (puVar8 == (undefined8 *)0x0) {
81: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
82: *(undefined8 **)(pcVar3 + (long)(int)uVar11 * 8 + 0xa8) = puVar8;
83: }
84: *puVar8 = 0;
85: puVar8[0x100] = 0;
86: uVar10 = (ulong)(((int)puVar8 -
87: (int)(undefined8 *)((ulong)(puVar8 + 1) & 0xfffffffffffffff8)) + 0x808U
88: >> 3);
89: puVar8 = (undefined8 *)((ulong)(puVar8 + 1) & 0xfffffffffffffff8);
90: while (uVar10 != 0) {
91: uVar10 = uVar10 - 1;
92: *puVar8 = 0;
93: puVar8 = puVar8 + (ulong)bVar13 * -2 + 1;
94: }
95: iVar6 = *(int *)((long)param_1 + 0x144);
96: }
97: }
98: else {
99: uVar11 = *(uint *)(pcVar7 + 0x18);
100: *(uint *)(pcVar3 + 0x68) = uVar11;
101: if (param_2 != 0) goto LAB_00120634;
102: LAB_00120720:
103: FUN_0011b2f0(param_1,iVar1 == 0,uVar11);
104: iVar6 = *(int *)((long)param_1 + 0x144);
105: }
106: iVar5 = (int)lVar12;
107: lVar12 = lVar12 + 1;
108: } while (iVar5 < iVar6);
109: }
110: *(undefined8 *)(pcVar3 + 0x6c) = 0;
111: uVar2 = *(undefined4 *)(param_1 + 0x23);
112: *(undefined8 *)(pcVar3 + 0x40) = 0;
113: *(undefined4 *)(pcVar3 + 0x48) = 0;
114: *(undefined4 *)(pcVar3 + 0x84) = 0;
115: *(undefined4 *)(pcVar3 + 0x80) = uVar2;
116: return;
117: }
118: 

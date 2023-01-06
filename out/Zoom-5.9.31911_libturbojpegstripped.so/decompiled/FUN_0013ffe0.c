1: 
2: void FUN_0013ffe0(long param_1)
3: 
4: {
5: code **ppcVar1;
6: ulong uVar2;
7: int iVar3;
8: uint uVar4;
9: code **ppcVar6;
10: code **ppcVar7;
11: bool bVar8;
12: byte bVar9;
13: ulong uVar5;
14: 
15: bVar9 = 0;
16: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x170);
17: *(code ***)(param_1 + 0x1f0) = ppcVar1;
18: ppcVar6 = ppcVar1 + 0xd;
19: uVar5 = 0x80;
20: iVar3 = 0x80;
21: *ppcVar1 = FUN_0013d980;
22: bVar8 = ((ulong)ppcVar6 & 1) != 0;
23: ppcVar1[2] = FUN_0013ea10;
24: if (bVar8) {
25: ppcVar6 = (code **)((long)ppcVar1 + 0x69);
26: *(undefined *)(ppcVar1 + 0xd) = 0;
27: uVar5 = 0x7f;
28: iVar3 = 0x7f;
29: }
30: if (((ulong)ppcVar6 & 2) == 0) {
31: uVar4 = (uint)uVar5;
32: }
33: else {
34: uVar4 = iVar3 - 2;
35: uVar5 = (ulong)uVar4;
36: *(undefined2 *)ppcVar6 = 0;
37: ppcVar6 = (code **)((long)ppcVar6 + 2);
38: }
39: if (((ulong)ppcVar6 & 4) != 0) {
40: *(undefined4 *)ppcVar6 = 0;
41: uVar5 = (ulong)(uVar4 - 4);
42: ppcVar6 = (code **)((long)ppcVar6 + 4);
43: }
44: uVar2 = uVar5 >> 3;
45: while (uVar2 != 0) {
46: uVar2 = uVar2 - 1;
47: *ppcVar6 = (code *)0x0;
48: ppcVar6 = ppcVar6 + (ulong)bVar9 * -2 + 1;
49: }
50: if ((uVar5 & 4) != 0) {
51: *(undefined4 *)ppcVar6 = 0;
52: ppcVar6 = (code **)((long)ppcVar6 + 4);
53: }
54: ppcVar7 = ppcVar6;
55: if ((uVar5 & 2) != 0) {
56: ppcVar7 = (code **)((long)ppcVar6 + 2);
57: *(undefined2 *)ppcVar6 = 0;
58: }
59: if (bVar8) {
60: *(undefined *)ppcVar7 = 0;
61: }
62: ppcVar6 = ppcVar1 + 0x1d;
63: uVar5 = 0x80;
64: iVar3 = 0x80;
65: bVar8 = ((ulong)ppcVar6 & 1) != 0;
66: if (bVar8) {
67: ppcVar6 = (code **)((long)ppcVar1 + 0xe9);
68: *(undefined *)(ppcVar1 + 0x1d) = 0;
69: uVar5 = 0x7f;
70: iVar3 = 0x7f;
71: }
72: if (((ulong)ppcVar6 & 2) == 0) {
73: uVar4 = (uint)uVar5;
74: ppcVar7 = ppcVar6;
75: }
76: else {
77: ppcVar7 = (code **)((long)ppcVar6 + 2);
78: uVar4 = iVar3 - 2;
79: uVar5 = (ulong)uVar4;
80: *(undefined2 *)ppcVar6 = 0;
81: }
82: if (((ulong)ppcVar7 & 4) != 0) {
83: *(undefined4 *)ppcVar7 = 0;
84: uVar5 = (ulong)(uVar4 - 4);
85: ppcVar7 = (code **)((long)ppcVar7 + 4);
86: }
87: uVar2 = uVar5 >> 3;
88: while (uVar2 != 0) {
89: uVar2 = uVar2 - 1;
90: *ppcVar7 = (code *)0x0;
91: ppcVar7 = ppcVar7 + (ulong)bVar9 * -2 + 1;
92: }
93: if ((uVar5 & 4) != 0) {
94: *(undefined4 *)ppcVar7 = 0;
95: ppcVar7 = (code **)((long)ppcVar7 + 4);
96: }
97: ppcVar6 = ppcVar7;
98: if ((uVar5 & 2) != 0) {
99: ppcVar6 = (code **)((long)ppcVar7 + 2);
100: *(undefined2 *)ppcVar7 = 0;
101: }
102: if (bVar8) {
103: *(undefined *)ppcVar6 = 0;
104: }
105: *(undefined *)(ppcVar1 + 0x2d) = 0x71;
106: return;
107: }
108: 

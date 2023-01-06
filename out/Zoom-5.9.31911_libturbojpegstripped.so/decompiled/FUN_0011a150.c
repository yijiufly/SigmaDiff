1: 
2: void FUN_0011a150(long param_1,long param_2,uint *param_3,uint param_4,undefined8 *param_5,
3: uint *param_6,uint param_7)
4: 
5: {
6: undefined4 uVar1;
7: int iVar2;
8: undefined8 uVar3;
9: uint uVar4;
10: uint uVar5;
11: int iVar6;
12: uint uVar7;
13: int iVar8;
14: int iVar9;
15: int iVar10;
16: long lVar11;
17: int iVar12;
18: undefined8 *puStack128;
19: long lStack120;
20: 
21: lVar11 = *(long *)(param_1 + 0x1c0);
22: while( true ) {
23: uVar7 = *param_3;
24: if (param_4 <= uVar7) {
25: return;
26: }
27: if (param_7 <= *param_6) break;
28: uVar5 = *(int *)(param_1 + 0x13c) - *(int *)(lVar11 + 100);
29: uVar4 = param_4 - uVar7;
30: if (uVar5 < param_4 - uVar7) {
31: uVar4 = uVar5;
32: }
33: (**(code **)(*(long *)(param_1 + 0x1d8) + 8))
34: (param_1,param_2 + (ulong)uVar7 * 8,lVar11 + 0x10,*(int *)(lVar11 + 100),uVar4);
35: *param_3 = *param_3 + uVar4;
36: iVar6 = *(int *)(lVar11 + 0x60) - uVar4;
37: iVar9 = *(int *)(lVar11 + 100) + uVar4;
38: *(int *)(lVar11 + 100) = iVar9;
39: *(int *)(lVar11 + 0x60) = iVar6;
40: if ((iVar6 == 0) && (iVar6 = *(int *)(param_1 + 0x13c), iVar9 < iVar6)) {
41: if (0 < *(int *)(param_1 + 0x4c)) {
42: iVar2 = 0;
43: lStack120 = lVar11;
44: while( true ) {
45: uVar1 = *(undefined4 *)(param_1 + 0x30);
46: uVar3 = *(undefined8 *)(lStack120 + 0x10);
47: if (iVar9 < iVar6) {
48: iVar8 = iVar9;
49: do {
50: iVar10 = iVar8 + 1;
51: FUN_0013be50(uVar3,iVar9 + -1,uVar3,iVar8,1,uVar1);
52: iVar8 = iVar10;
53: } while (iVar10 != iVar6);
54: iVar6 = *(int *)(param_1 + 0x13c);
55: }
56: iVar2 = iVar2 + 1;
57: lStack120 = lStack120 + 8;
58: if (*(int *)(param_1 + 0x4c) == iVar2 || *(int *)(param_1 + 0x4c) < iVar2) break;
59: iVar9 = *(int *)(lVar11 + 100);
60: }
61: }
62: iVar9 = iVar6;
63: *(int *)(lVar11 + 100) = iVar9;
64: }
65: if (*(int *)(param_1 + 0x13c) == iVar9) {
66: (**(code **)(*(long *)(param_1 + 0x1e0) + 8))(param_1,lVar11 + 0x10,0);
67: *(undefined4 *)(lVar11 + 100) = 0;
68: *param_6 = *param_6 + 1;
69: }
70: if ((*(int *)(lVar11 + 0x60) == 0) && (uVar7 = *param_6, uVar7 < param_7)) {
71: lVar11 = *(long *)(param_1 + 0x58);
72: iVar6 = 0;
73: iVar9 = *(int *)(param_1 + 0x4c);
74: puStack128 = param_5;
75: if (0 < iVar9) {
76: while( true ) {
77: iVar10 = param_7 * *(int *)(lVar11 + 0xc);
78: iVar8 = *(int *)(lVar11 + 0xc) * uVar7;
79: iVar2 = *(int *)(lVar11 + 0x1c);
80: uVar3 = *puStack128;
81: if (iVar8 < iVar10) {
82: iVar9 = iVar8;
83: do {
84: iVar12 = iVar9 + 1;
85: FUN_0013be50(uVar3,iVar8 + -1,uVar3,iVar9,1,iVar2 * 8);
86: iVar9 = iVar12;
87: } while (iVar10 != iVar12);
88: iVar9 = *(int *)(param_1 + 0x4c);
89: }
90: iVar6 = iVar6 + 1;
91: lVar11 = lVar11 + 0x60;
92: puStack128 = puStack128 + 1;
93: if (iVar9 <= iVar6) break;
94: uVar7 = *param_6;
95: }
96: }
97: *param_6 = param_7;
98: return;
99: }
100: }
101: return;
102: }
103: 

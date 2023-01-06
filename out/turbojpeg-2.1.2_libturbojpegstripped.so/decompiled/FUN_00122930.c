1: 
2: void FUN_00122930(long param_1,long param_2,uint *param_3,uint param_4,undefined8 param_5,
3: uint *param_6,uint param_7)
4: 
5: {
6: undefined8 *puVar1;
7: uint uVar2;
8: undefined4 uVar3;
9: long lVar4;
10: undefined8 uVar5;
11: int iVar6;
12: int iVar7;
13: int iVar8;
14: int iVar9;
15: undefined8 *puVar10;
16: uint uVar11;
17: int iVar12;
18: long lVar13;
19: 
20: lVar4 = *(long *)(param_1 + 0x1c0);
21: iVar6 = *(int *)(param_1 + 0x13c) * 3;
22: puVar1 = (undefined8 *)(lVar4 + 0x10);
23: do {
24: uVar11 = *param_6;
25: LAB_001229aa:
26: if (param_7 <= uVar11) {
27: return;
28: }
29: uVar2 = *param_3;
30: if (uVar2 < param_4) {
31: uVar11 = *(int *)(lVar4 + 0x6c) - *(int *)(lVar4 + 100);
32: if (param_4 - uVar2 < uVar11) {
33: uVar11 = param_4 - uVar2;
34: }
35: (**(code **)(*(long *)(param_1 + 0x1d8) + 8))(param_1,param_2 + (ulong)uVar2 * 8,puVar1);
36: if ((*(int *)(lVar4 + 0x60) == *(int *)(param_1 + 0x34)) &&
37: (iVar9 = *(int *)(param_1 + 0x4c), 0 < iVar9)) {
38: iVar7 = *(int *)(param_1 + 0x13c);
39: iVar8 = 0;
40: puVar10 = puVar1;
41: do {
42: iVar12 = 1;
43: if (0 < iVar7) {
44: do {
45: iVar9 = -iVar12;
46: iVar12 = iVar12 + 1;
47: FUN_00148a00(*puVar10,0,*puVar10,iVar9,1,*(undefined4 *)(param_1 + 0x30));
48: iVar7 = *(int *)(param_1 + 0x13c);
49: } while (iVar12 <= iVar7);
50: iVar9 = *(int *)(param_1 + 0x4c);
51: }
52: iVar8 = iVar8 + 1;
53: puVar10 = puVar10 + 1;
54: } while (iVar8 < iVar9);
55: }
56: *param_3 = *param_3 + uVar11;
57: *(int *)(lVar4 + 0x60) = *(int *)(lVar4 + 0x60) - uVar11;
58: iVar9 = *(int *)(lVar4 + 0x6c);
59: iVar7 = *(int *)(lVar4 + 100) + uVar11;
60: *(int *)(lVar4 + 100) = iVar7;
61: uVar11 = *param_6;
62: LAB_001229a1:
63: if (iVar7 == iVar9) goto LAB_00122b54;
64: goto LAB_001229aa;
65: }
66: if (*(int *)(lVar4 + 0x60) != 0) {
67: return;
68: }
69: iVar7 = *(int *)(lVar4 + 100);
70: iVar9 = *(int *)(lVar4 + 0x6c);
71: if (iVar9 <= iVar7) goto LAB_001229a1;
72: iVar8 = *(int *)(param_1 + 0x4c);
73: if (0 < iVar8) {
74: lVar13 = 1;
75: while( true ) {
76: uVar3 = *(undefined4 *)(param_1 + 0x30);
77: uVar5 = *(undefined8 *)(lVar4 + 8 + lVar13 * 8);
78: if (iVar7 < iVar9) {
79: iVar8 = iVar7;
80: do {
81: iVar12 = iVar8 + 1;
82: FUN_00148a00(uVar5,iVar7 + -1,uVar5,iVar8,1,uVar3);
83: iVar8 = iVar12;
84: } while (iVar12 != iVar9);
85: iVar8 = *(int *)(param_1 + 0x4c);
86: iVar9 = *(int *)(lVar4 + 0x6c);
87: }
88: iVar7 = (int)lVar13;
89: lVar13 = lVar13 + 1;
90: if (iVar8 <= iVar7) break;
91: iVar7 = *(int *)(lVar4 + 100);
92: }
93: }
94: *(int *)(lVar4 + 100) = iVar9;
95: LAB_00122b54:
96: (**(code **)(*(long *)(param_1 + 0x1e0) + 8))(param_1,puVar1,*(undefined4 *)(lVar4 + 0x68));
97: *param_6 = *param_6 + 1;
98: iVar9 = *(int *)(param_1 + 0x13c);
99: iVar7 = *(int *)(lVar4 + 0x68) + iVar9;
100: if (iVar6 <= iVar7) {
101: iVar7 = 0;
102: }
103: *(int *)(lVar4 + 0x68) = iVar7;
104: if (*(int *)(lVar4 + 100) < iVar6) {
105: iVar9 = iVar9 + *(int *)(lVar4 + 100);
106: }
107: else {
108: *(undefined4 *)(lVar4 + 100) = 0;
109: }
110: *(int *)(lVar4 + 0x6c) = iVar9;
111: } while( true );
112: }
113: 

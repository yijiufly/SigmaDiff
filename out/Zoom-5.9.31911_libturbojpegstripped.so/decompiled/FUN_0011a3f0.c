1: 
2: void FUN_0011a3f0(long param_1,long param_2,uint *param_3,uint param_4,undefined8 param_5,
3: uint *param_6,uint param_7)
4: 
5: {
6: uint uVar1;
7: undefined4 uVar2;
8: long lVar3;
9: undefined8 uVar4;
10: int iVar5;
11: int iVar6;
12: int iVar7;
13: int iVar8;
14: uint uVar9;
15: uint uVar10;
16: long lVar11;
17: int iVar12;
18: int iStack124;
19: 
20: lVar3 = *(long *)(param_1 + 0x1c0);
21: iVar5 = *(int *)(param_1 + 0x13c) * 3;
22: do {
23: uVar10 = *param_6;
24: joined_r0x0011a452:
25: if (param_7 <= uVar10) {
26: return;
27: }
28: uVar1 = *param_3;
29: if (uVar1 < param_4) {
30: uVar9 = *(int *)(lVar3 + 0x6c) - *(int *)(lVar3 + 100);
31: uVar10 = param_4 - uVar1;
32: if (uVar9 < param_4 - uVar1) {
33: uVar10 = uVar9;
34: }
35: (**(code **)(*(long *)(param_1 + 0x1d8) + 8))(param_1,param_2 + (ulong)uVar1 * 8,lVar3 + 0x10)
36: ;
37: if ((*(int *)(lVar3 + 0x60) == *(int *)(param_1 + 0x34)) &&
38: (iVar6 = *(int *)(param_1 + 0x4c), 0 < iVar6)) {
39: iVar8 = *(int *)(param_1 + 0x13c);
40: iVar7 = 0;
41: lVar11 = lVar3;
42: do {
43: if (0 < iVar8) {
44: iVar6 = 1;
45: do {
46: iVar8 = -iVar6;
47: iVar6 = iVar6 + 1;
48: FUN_0013be50(*(undefined8 *)(lVar11 + 0x10),0,*(undefined8 *)(lVar11 + 0x10),iVar8,1,
49: *(undefined4 *)(param_1 + 0x30));
50: iVar8 = *(int *)(param_1 + 0x13c);
51: } while (iVar6 <= iVar8);
52: iVar6 = *(int *)(param_1 + 0x4c);
53: }
54: iVar7 = iVar7 + 1;
55: lVar11 = lVar11 + 8;
56: } while (iVar7 < iVar6);
57: }
58: *param_3 = *param_3 + uVar10;
59: *(int *)(lVar3 + 0x60) = *(int *)(lVar3 + 0x60) - uVar10;
60: iVar8 = *(int *)(lVar3 + 0x6c);
61: iVar6 = *(int *)(lVar3 + 100) + uVar10;
62: *(int *)(lVar3 + 100) = iVar6;
63: uVar10 = *param_6;
64: LAB_0011a584:
65: if (iVar6 == iVar8) goto LAB_0011a5ba;
66: goto joined_r0x0011a452;
67: }
68: if (*(int *)(lVar3 + 0x60) != 0) {
69: return;
70: }
71: iVar6 = *(int *)(lVar3 + 100);
72: iVar8 = *(int *)(lVar3 + 0x6c);
73: if (iVar8 <= iVar6) goto LAB_0011a584;
74: iVar7 = *(int *)(param_1 + 0x4c);
75: if (0 < iVar7) {
76: iStack124 = 0;
77: lVar11 = lVar3;
78: while( true ) {
79: uVar4 = *(undefined8 *)(lVar11 + 0x10);
80: uVar2 = *(undefined4 *)(param_1 + 0x30);
81: if (iVar6 < iVar8) {
82: iVar7 = iVar6;
83: do {
84: iVar12 = iVar7 + 1;
85: FUN_0013be50(uVar4,iVar6 + -1,uVar4,iVar7,1,uVar2);
86: iVar7 = iVar12;
87: } while (iVar12 != iVar8);
88: iVar8 = *(int *)(lVar3 + 0x6c);
89: iVar7 = *(int *)(param_1 + 0x4c);
90: }
91: iStack124 = iStack124 + 1;
92: lVar11 = lVar11 + 8;
93: if (iVar7 <= iStack124) break;
94: iVar6 = *(int *)(lVar3 + 100);
95: }
96: }
97: *(int *)(lVar3 + 100) = iVar8;
98: LAB_0011a5ba:
99: (**(code **)(*(long *)(param_1 + 0x1e0) + 8))
100: (param_1,lVar3 + 0x10,*(undefined4 *)(lVar3 + 0x68));
101: *param_6 = *param_6 + 1;
102: iVar6 = *(int *)(param_1 + 0x13c);
103: iVar7 = *(int *)(lVar3 + 0x68) + iVar6;
104: iVar8 = 0;
105: if (iVar7 < iVar5) {
106: iVar8 = iVar7;
107: }
108: *(int *)(lVar3 + 0x68) = iVar8;
109: iVar8 = *(int *)(lVar3 + 100);
110: if (iVar5 <= iVar8) {
111: *(undefined4 *)(lVar3 + 100) = 0;
112: iVar8 = 0;
113: }
114: *(int *)(lVar3 + 0x6c) = iVar8 + iVar6;
115: } while( true );
116: }
117: 

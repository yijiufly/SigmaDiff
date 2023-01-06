1: 
2: void FUN_00122670(long param_1,long param_2,uint *param_3,uint param_4,long param_5,uint *param_6,
3: uint param_7)
4: 
5: {
6: int *piVar1;
7: undefined4 uVar2;
8: undefined8 uVar3;
9: int iVar4;
10: uint uVar5;
11: uint uVar6;
12: int iVar7;
13: int iVar8;
14: int iVar9;
15: long lVar10;
16: long lVar11;
17: int iVar12;
18: long lStack112;
19: 
20: lVar10 = *(long *)(param_1 + 0x1c0);
21: LAB_001226a8:
22: uVar6 = *param_3;
23: do {
24: if ((param_4 <= uVar6) || (param_7 <= *param_6)) {
25: return;
26: }
27: uVar5 = *(int *)(param_1 + 0x13c) - *(int *)(lVar10 + 100);
28: if (param_4 - uVar6 < uVar5) {
29: uVar5 = param_4 - uVar6;
30: }
31: (**(code **)(*(long *)(param_1 + 0x1d8) + 8))(param_1,param_2 + (ulong)uVar6 * 8,lVar10 + 0x10);
32: *param_3 = *param_3 + uVar5;
33: iVar9 = *(int *)(lVar10 + 100) + uVar5;
34: piVar1 = (int *)(lVar10 + 0x60);
35: *piVar1 = *piVar1 - uVar5;
36: *(int *)(lVar10 + 100) = iVar9;
37: if (*piVar1 == 0) {
38: iVar8 = *(int *)(param_1 + 0x13c);
39: if (iVar9 < iVar8) {
40: iVar4 = *(int *)(param_1 + 0x4c);
41: if (0 < iVar4) {
42: lVar11 = 1;
43: while( true ) {
44: uVar2 = *(undefined4 *)(param_1 + 0x30);
45: uVar3 = *(undefined8 *)(lVar10 + 8 + lVar11 * 8);
46: if (iVar9 < iVar8) {
47: iVar4 = iVar9;
48: do {
49: iVar7 = iVar4 + 1;
50: FUN_00148a00(uVar3,iVar9 + -1,uVar3,iVar4,1,uVar2);
51: iVar4 = iVar7;
52: } while (iVar7 != iVar8);
53: iVar4 = *(int *)(param_1 + 0x4c);
54: iVar8 = *(int *)(param_1 + 0x13c);
55: }
56: iVar9 = (int)lVar11;
57: lVar11 = lVar11 + 1;
58: if (iVar4 <= iVar9) break;
59: iVar9 = *(int *)(lVar10 + 100);
60: }
61: }
62: *(int *)(lVar10 + 100) = iVar8;
63: }
64: else {
65: uVar6 = *param_6;
66: if (iVar9 != iVar8) break;
67: }
68: }
69: else {
70: if (iVar9 != *(int *)(param_1 + 0x13c)) goto LAB_001226a8;
71: }
72: (**(code **)(*(long *)(param_1 + 0x1e0) + 8))(param_1,lVar10 + 0x10,0);
73: *(undefined4 *)(lVar10 + 100) = 0;
74: uVar6 = *param_6 + 1;
75: *param_6 = uVar6;
76: if (*(int *)(lVar10 + 0x60) == 0) break;
77: uVar6 = *param_3;
78: } while( true );
79: if (uVar6 < param_7) {
80: iVar9 = *(int *)(param_1 + 0x4c);
81: lVar10 = *(long *)(param_1 + 0x58);
82: if (0 < iVar9) {
83: lStack112 = 1;
84: while( true ) {
85: iVar7 = param_7 * *(int *)(lVar10 + 0xc);
86: iVar4 = *(int *)(lVar10 + 0xc) * uVar6;
87: iVar8 = *(int *)(lVar10 + 0x1c);
88: uVar3 = *(undefined8 *)(param_5 + -8 + lStack112 * 8);
89: if (iVar4 < iVar7) {
90: iVar9 = iVar4;
91: do {
92: iVar12 = iVar9 + 1;
93: FUN_00148a00(uVar3,iVar4 + -1,uVar3,iVar9,1,iVar8 * 8);
94: iVar9 = iVar12;
95: } while (iVar7 != iVar12);
96: iVar9 = *(int *)(param_1 + 0x4c);
97: }
98: iVar8 = (int)lStack112;
99: lVar10 = lVar10 + 0x60;
100: lStack112 = lStack112 + 1;
101: if (iVar9 <= iVar8) break;
102: uVar6 = *param_6;
103: }
104: }
105: *param_6 = param_7;
106: return;
107: }
108: goto LAB_001226a8;
109: }
110: 

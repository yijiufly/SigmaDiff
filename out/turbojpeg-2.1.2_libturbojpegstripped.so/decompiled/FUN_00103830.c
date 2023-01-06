1: 
2: void FUN_00103830(long param_1,undefined8 *param_2)
3: 
4: {
5: undefined2 uVar1;
6: uint uVar2;
7: uint uVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: uint uVar7;
12: long *plVar8;
13: undefined2 *puVar9;
14: uint uVar10;
15: uint uVar11;
16: undefined2 *puVar12;
17: long *plVar13;
18: uint uVar14;
19: long lVar15;
20: undefined2 *puVar16;
21: undefined8 uVar17;
22: long lStack144;
23: undefined8 *puStack136;
24: long lStack120;
25: uint uStack84;
26: 
27: lVar4 = *(long *)(param_1 + 0x1c8);
28: lStack144 = *(long *)(param_1 + 0x58);
29: uVar7 = *(int *)(param_1 + 0x140) - 1;
30: if (0 < *(int *)(param_1 + 0x4c)) {
31: lStack120 = 1;
32: puStack136 = param_2;
33: do {
34: uVar17 = 0x1038b6;
35: plVar8 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
36: (param_1,*(undefined8 *)(lVar4 + 0x68 + lStack120 * 8),
37: *(int *)(lVar4 + 0x10) * *(int *)(lStack144 + 0xc),
38: *(int *)(lStack144 + 0xc),1);
39: uVar10 = *(uint *)(lVar4 + 0x10);
40: if (uVar10 < uVar7) {
41: uStack84 = *(uint *)(lStack144 + 0xc);
42: }
43: else {
44: uStack84 = *(uint *)(lStack144 + 0x20) % *(uint *)(lStack144 + 0xc);
45: if (uStack84 == 0) {
46: uStack84 = *(uint *)(lStack144 + 0xc);
47: }
48: }
49: uVar2 = *(uint *)(lStack144 + 0x1c);
50: uVar3 = *(uint *)(lStack144 + 8);
51: uVar11 = uVar2 % uVar3;
52: uVar14 = uVar3 - uVar11;
53: if ((int)uVar11 < 1) {
54: uVar14 = uVar11;
55: }
56: if (0 < (int)uStack84) {
57: plVar13 = plVar8;
58: do {
59: while( true ) {
60: lVar15 = *plVar13;
61: (**(code **)(*(long *)(param_1 + 0x1e8) + 8))
62: (param_1,lStack144,*puStack136,lVar15,(int)plVar13 - (int)plVar8,0,uVar2,
63: uVar17);
64: if ((int)uVar14 < 1) break;
65: puVar12 = (undefined2 *)(lVar15 + (ulong)uVar2 * 0x80);
66: uVar17 = 0x10399d;
67: FUN_00148a80();
68: uVar1 = puVar12[-0x40];
69: puVar16 = puVar12 + (ulong)(uVar14 - 1) * 0x40 + 0x40;
70: do {
71: *puVar12 = uVar1;
72: puVar12 = puVar12 + 0x40;
73: } while (puVar16 != puVar12);
74: plVar13 = plVar13 + 1;
75: if (plVar13 == plVar8 + (ulong)(uStack84 - 1) + 1) goto LAB_001039c7;
76: }
77: plVar13 = plVar13 + 1;
78: } while (plVar13 != plVar8 + (ulong)(uStack84 - 1) + 1);
79: LAB_001039c7:
80: uVar10 = *(uint *)(lVar4 + 0x10);
81: }
82: if (uVar7 == uVar10) {
83: uVar10 = (uVar14 + uVar2) / uVar3;
84: if ((int)uStack84 < *(int *)(lStack144 + 0xc)) {
85: lVar15 = (long)(int)uVar3;
86: plVar8 = plVar8 + (int)uStack84;
87: do {
88: puVar16 = (undefined2 *)*plVar8;
89: lVar5 = plVar8[-1];
90: FUN_00148a80(puVar16,(ulong)(uVar14 + uVar2) << 7);
91: if ((uVar10 != 0) && (0 < (int)uVar3)) {
92: puVar12 = (undefined2 *)(lVar5 + lVar15 * 0x80 + -0x80);
93: uVar11 = 0;
94: do {
95: uVar1 = *puVar12;
96: puVar9 = puVar16;
97: do {
98: *puVar9 = uVar1;
99: puVar9 = puVar9 + 0x40;
100: } while (puVar9 != puVar16 + (ulong)(uVar3 - 1) * 0x40 + 0x40);
101: uVar11 = uVar11 + 1;
102: puVar16 = puVar16 + lVar15 * 0x40;
103: puVar12 = puVar12 + lVar15 * 0x40;
104: } while (uVar10 != uVar11);
105: }
106: uStack84 = uStack84 + 1;
107: plVar8 = plVar8 + 1;
108: } while (*(uint *)(lStack144 + 0xc) != uStack84 &&
109: (int)uStack84 <= (int)*(uint *)(lStack144 + 0xc));
110: }
111: }
112: lStack144 = lStack144 + 0x60;
113: puStack136 = puStack136 + 1;
114: iVar6 = (int)lStack120;
115: lStack120 = lStack120 + 1;
116: } while (*(int *)(param_1 + 0x4c) != iVar6 && iVar6 <= *(int *)(param_1 + 0x4c));
117: }
118: FUN_00103350(param_1,param_2);
119: return;
120: }
121: 

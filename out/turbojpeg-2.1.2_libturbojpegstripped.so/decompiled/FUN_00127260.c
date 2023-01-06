1: 
2: ulong FUN_00127260(long param_1,long *param_2)
3: 
4: {
5: long *plVar1;
6: int iVar2;
7: code *pcVar3;
8: int iVar4;
9: ulong uVar5;
10: long lVar6;
11: long lVar7;
12: uint uVar8;
13: uint uVar9;
14: long lVar10;
15: uint uVar11;
16: long lVar12;
17: long lStack128;
18: long *plStack112;
19: undefined8 *puStack80;
20: long *plStack72;
21: int iStack64;
22: 
23: lVar10 = *(long *)(param_1 + 0x230);
24: iVar2 = *(int *)(param_1 + 0x1a4);
25: while ((*(int *)(param_1 + 0xac) < *(int *)(param_1 + 0xb4) ||
26: ((uVar11 = *(uint *)(param_1 + 0xb8), *(int *)(param_1 + 0xac) == *(int *)(param_1 + 0xb4)
27: && (*(uint *)(param_1 + 0xb0) < uVar11 || *(uint *)(param_1 + 0xb0) == uVar11))))) {
28: uVar5 = (***(code ***)(param_1 + 0x240))();
29: if ((int)uVar5 == 0) {
30: return uVar5;
31: }
32: }
33: iVar4 = *(int *)(param_1 + 0x38);
34: lVar12 = *(long *)(param_1 + 0x130);
35: if (0 < iVar4) {
36: iStack64 = 0;
37: puStack80 = (undefined8 *)(lVar10 + 0x90);
38: plStack72 = param_2;
39: do {
40: if (*(int *)(lVar12 + 0x30) != 0) {
41: plStack112 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
42: (param_1,*puStack80,uVar11 * *(int *)(lVar12 + 0xc),
43: *(int *)(lVar12 + 0xc),0);
44: uVar11 = *(uint *)(param_1 + 0xb8);
45: uVar9 = *(uint *)(lVar12 + 0xc);
46: if ((iVar2 - 1U <= uVar11) && (uVar8 = *(uint *)(lVar12 + 0x20) % uVar9, uVar8 != 0)) {
47: uVar9 = uVar8;
48: }
49: lVar10 = (long)iStack64;
50: pcVar3 = *(code **)(*(long *)(param_1 + 600) + 8 + lVar10 * 8);
51: lStack128 = *plStack72;
52: if ((int)uVar9 < 1) {
53: iVar4 = *(int *)(param_1 + 0x38);
54: }
55: else {
56: lVar7 = *(long *)(param_1 + 0x220);
57: plVar1 = plStack112 + (ulong)(uVar9 - 1) + 1;
58: uVar11 = *(uint *)(lVar7 + 0x44 + lVar10 * 4);
59: do {
60: uVar9 = *(uint *)(lVar7 + 0xc + (lVar10 + 4) * 4);
61: uVar5 = (ulong)uVar9;
62: lVar6 = uVar5 * 0x80 + *plStack112;
63: if (uVar11 < uVar9) {
64: iVar4 = *(int *)(lVar12 + 0x24);
65: }
66: else {
67: do {
68: (*pcVar3)(param_1,lVar12,lVar6,lStack128);
69: lVar7 = *(long *)(param_1 + 0x220);
70: iVar4 = *(int *)(lVar12 + 0x24);
71: uVar9 = (int)uVar5 + 1;
72: uVar5 = (ulong)uVar9;
73: lVar6 = lVar6 + 0x80;
74: uVar11 = *(uint *)(lVar7 + 4 + (lVar10 + 0x10) * 4);
75: } while (uVar9 <= uVar11);
76: }
77: plStack112 = plStack112 + 1;
78: lStack128 = lStack128 + (long)iVar4 * 8;
79: } while (plVar1 != plStack112);
80: iVar4 = *(int *)(param_1 + 0x38);
81: uVar11 = *(uint *)(param_1 + 0xb8);
82: }
83: }
84: iStack64 = iStack64 + 1;
85: lVar12 = lVar12 + 0x60;
86: plStack72 = plStack72 + 1;
87: puStack80 = puStack80 + 1;
88: } while (iStack64 < iVar4);
89: }
90: *(uint *)(param_1 + 0xb8) = uVar11 + 1;
91: return (ulong)((*(uint *)(param_1 + 0x1a4) <= uVar11 + 1) + 3);
92: }
93: 

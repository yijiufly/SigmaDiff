1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: ulong FUN_0011f2e0(long param_1,long param_2)
5: 
6: {
7: long *plVar1;
8: int iVar2;
9: long lVar3;
10: code *pcVar4;
11: uint uVar5;
12: ulong uVar6;
13: int iVar7;
14: uint uVar8;
15: long lVar9;
16: long lVar10;
17: uint uVar11;
18: long lVar12;
19: long lVar13;
20: long lStack120;
21: long *plStack104;
22: long lStack96;
23: 
24: lVar3 = *(long *)(param_1 + 0x230);
25: iVar2 = *(int *)(param_1 + 0x1a4);
26: while ((*(int *)(param_1 + 0xac) < *(int *)(param_1 + 0xb4) ||
27: ((uVar5 = *(uint *)(param_1 + 0xb8), *(int *)(param_1 + 0xac) == *(int *)(param_1 + 0xb4)
28: && (*(uint *)(param_1 + 0xb0) < uVar5 || *(uint *)(param_1 + 0xb0) == uVar5))))) {
29: uVar6 = (***(code ***)(param_1 + 0x240))();
30: if ((int)uVar6 == 0) {
31: return uVar6;
32: }
33: }
34: iVar7 = *(int *)(param_1 + 0x38);
35: lVar10 = *(long *)(param_1 + 0x130);
36: if (0 < iVar7) {
37: lStack96 = 0;
38: do {
39: lVar12 = (long)(int)lStack96;
40: if (*(int *)(lVar10 + 0x30) != 0) {
41: plStack104 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
42: (param_1,*(undefined8 *)(lVar3 + 0x90 + lStack96 * 8),
43: uVar5 * *(int *)(lVar10 + 0xc),*(int *)(lVar10 + 0xc),0);
44: uVar5 = *(uint *)(param_1 + 0xb8);
45: uVar11 = *(uint *)(lVar10 + 0xc);
46: if ((iVar2 - 1U <= uVar5) && (uVar8 = *(uint *)(lVar10 + 0x20) % uVar11, uVar8 != 0)) {
47: uVar11 = uVar8;
48: }
49: pcVar4 = *(code **)(*(long *)(param_1 + 600) + 8 + lVar12 * 8);
50: lStack120 = *(long *)(param_2 + lStack96 * 8);
51: if ((int)uVar11 < 1) {
52: iVar7 = *(int *)(param_1 + 0x38);
53: }
54: else {
55: lVar9 = *(long *)(param_1 + 0x220);
56: plVar1 = plStack104 + (ulong)(uVar11 - 1) + 1;
57: uVar5 = *(uint *)(lVar9 + 0x44 + lVar12 * 4);
58: do {
59: uVar11 = *(uint *)(lVar9 + 0x1c + lVar12 * 4);
60: lVar13 = (ulong)uVar11 * 0x80 + *plStack104;
61: if (uVar5 < uVar11) {
62: iVar7 = *(int *)(lVar10 + 0x24);
63: }
64: else {
65: do {
66: (*pcVar4)(param_1,lVar10,lVar13,lStack120);
67: lVar9 = *(long *)(param_1 + 0x220);
68: iVar7 = *(int *)(lVar10 + 0x24);
69: uVar11 = uVar11 + 1;
70: lVar13 = lVar13 + 0x80;
71: uVar5 = *(uint *)(lVar9 + 0x44 + lVar12 * 4);
72: } while (uVar11 <= uVar5);
73: }
74: plStack104 = plStack104 + 1;
75: lStack120 = lStack120 + (long)iVar7 * 8;
76: } while (plStack104 != plVar1);
77: uVar5 = *(uint *)(param_1 + 0xb8);
78: iVar7 = *(int *)(param_1 + 0x38);
79: }
80: }
81: lVar10 = lVar10 + 0x60;
82: lStack96 = lStack96 + 1;
83: } while ((int)lStack96 + 1 < iVar7);
84: }
85: *(uint *)(param_1 + 0xb8) = uVar5 + 1;
86: return (ulong)(4 - (uVar5 + 1 < *(uint *)(param_1 + 0x1a4)));
87: }
88: 

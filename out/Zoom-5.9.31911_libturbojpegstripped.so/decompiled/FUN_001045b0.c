1: 
2: void FUN_001045b0(long param_1)
3: 
4: {
5: long *plVar1;
6: undefined8 *puVar2;
7: ulong uVar3;
8: long lVar4;
9: long lVar5;
10: ulong uVar6;
11: ulong uVar7;
12: ulong uVar8;
13: ulong uVar9;
14: ulong uVar10;
15: ulong uStack128;
16: ulong uStack112;
17: ulong uStack96;
18: ulong uStack80;
19: 
20: lVar4 = *(long *)(param_1 + 0x1d8);
21: puVar2 = (undefined8 *)(***(code ***)(param_1 + 8))(param_1,1,0x4000);
22: *(undefined8 **)(lVar4 + 0x10) = puVar2;
23: lVar4 = (long)puVar2 << 0x3c;
24: if (lVar4 < 0) {
25: *puVar2 = 0;
26: puVar2[0x100] = 0;
27: puVar2[0x200] = 0x8000;
28: puVar2[0x300] = 0;
29: puVar2[0x400] = 0;
30: puVar2[0x500] = 0x807fff;
31: puVar2[0x600] = 0;
32: puVar2[0x700] = 0;
33: }
34: uVar7 = (ulong)(lVar4 < 0);
35: uVar6 = (lVar4 >> 0x3f) + 0x100;
36: lVar4 = (lVar4 >> 0x3f) * -8;
37: lVar5 = 0;
38: uVar3 = 0;
39: uVar8 = uVar7;
40: uVar9 = uVar7 + 1;
41: do {
42: uVar3 = uVar3 + 1;
43: uVar10 = uVar9 >> 0x20;
44: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4);
45: *plVar1 = (uVar8 & 0xffffffff) * 0x4c8b + ((uVar8 >> 0x20) * 0x4c8b << 0x20);
46: plVar1[1] = (uVar9 & 0xffffffff) * 0x4c8b + (uVar10 * 0x4c8b << 0x20);
47: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x800);
48: *plVar1 = (uVar8 & 0xffffffff) * 0x9646 + ((uVar8 >> 0x20) * 0x9646 << 0x20);
49: plVar1[1] = (uVar9 & 0xffffffff) * 0x9646 +
50: (uVar10 * 0x9646 + (uStack128 & 0xffffffff) * (uVar9 & 0xffffffff) << 0x20);
51: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x1000);
52: *plVar1 = uVar8 * 0x1d2f + 0x8000;
53: plVar1[1] = uVar9 * 0x1d2f + 0x8000;
54: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x1800);
55: *plVar1 = (uVar8 & 0xffffffff) * 0xffffd4cd +
56: ((uVar8 >> 0x20) * 0xffffd4cd + (uVar8 & 0xffffffff) * 0xffffffff << 0x20);
57: plVar1[1] = (uVar9 & 0xffffffff) * 0xffffd4cd +
58: (uVar10 * 0xffffd4cd + (uStack112 & 0xffffffff) * (uVar9 & 0xffffffff) << 0x20);
59: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x2000);
60: *plVar1 = (uVar8 & 0xffffffff) * 0xffffab33 +
61: ((uVar8 >> 0x20) * 0xffffab33 + (uVar8 & 0xffffffff) * 0xffffffff << 0x20);
62: plVar1[1] = (uVar9 & 0xffffffff) * 0xffffab33 +
63: (uVar10 * 0xffffab33 + (uStack96 & 0xffffffff) * (uVar9 & 0xffffffff) << 0x20);
64: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x2800);
65: *plVar1 = (uVar8 + 0x101) * 0x8000 + -1;
66: plVar1[1] = (uVar9 + 0x101) * 0x8000 + -1;
67: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x3000);
68: *plVar1 = (uVar8 & 0xffffffff) * 0xffff94d1 +
69: ((uVar8 >> 0x20) * 0xffff94d1 + (uVar8 & 0xffffffff) * 0xffffffff << 0x20);
70: plVar1[1] = (uVar9 & 0xffffffff) * 0xffff94d1 +
71: (uVar10 * 0xffff94d1 + (uStack80 & 0xffffffff) * (uVar9 & 0xffffffff) << 0x20);
72: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x3800);
73: *plVar1 = (uVar8 & 0xffffffff) * 0xffffeb2f +
74: ((uVar8 >> 0x20) * 0xffffeb2f + (uVar8 & 0xffffffff) * 0xffffffff << 0x20);
75: plVar1[1] = (uVar9 & 0xffffffff) * 0xffffeb2f +
76: (uVar10 * 0xffffeb2f + (uVar9 & 0xffffffff) * 0xffffffff << 0x20);
77: lVar5 = lVar5 + 0x10;
78: uVar8 = uVar8 + 2;
79: uVar9 = uVar9 + 2;
80: } while (uVar3 < uVar6 >> 1);
81: lVar4 = uVar7 + (uVar6 & 0xfffffffffffffffe);
82: if (uVar6 != (uVar6 & 0xfffffffffffffffe)) {
83: puVar2[lVar4] = lVar4 * 0x4c8b;
84: puVar2[lVar4 + 0x100] = lVar4 * 0x9646;
85: puVar2[lVar4 + 0x200] = lVar4 * 0x1d2f + 0x8000;
86: puVar2[lVar4 + 0x300] = lVar4 * -0x2b33;
87: puVar2[lVar4 + 0x400] = lVar4 * -0x54cd;
88: puVar2[lVar4 + 0x500] = lVar4 * 0x8000 + 0x807fff;
89: puVar2[lVar4 + 0x600] = lVar4 * -0x6b2f;
90: puVar2[lVar4 + 0x700] = lVar4 * -0x14d1;
91: }
92: return;
93: }
94: 

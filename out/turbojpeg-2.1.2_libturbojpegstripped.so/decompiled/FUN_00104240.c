1: 
2: void FUN_00104240(long param_1)
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
13: bool bVar9;
14: ulong uVar10;
15: ulong uVar11;
16: ulong uStack96;
17: ulong uStack80;
18: ulong uStack64;
19: ulong uStack48;
20: 
21: lVar4 = *(long *)(param_1 + 0x1d8);
22: puVar2 = (undefined8 *)(***(code ***)(param_1 + 8))(param_1,1,0x4000);
23: *(undefined8 **)(lVar4 + 0x10) = puVar2;
24: uVar3 = (ulong)((uint)((ulong)puVar2 >> 3) & 1);
25: bVar9 = ((ulong)puVar2 >> 3 & 1) != 0;
26: if (bVar9) {
27: *puVar2 = 0;
28: puVar2[0x100] = 0;
29: puVar2[0x200] = 0x8000;
30: puVar2[0x300] = 0;
31: puVar2[0x400] = 0;
32: puVar2[0x500] = 0x807fff;
33: puVar2[0x600] = 0;
34: puVar2[0x700] = 0;
35: }
36: uVar6 = (ulong)bVar9;
37: uVar8 = 0x100 - uVar3;
38: lVar4 = uVar3 * 8;
39: lVar5 = 0;
40: uVar7 = 0;
41: uVar3 = uVar6;
42: uVar10 = uVar6 + 1;
43: do {
44: uVar7 = uVar7 + 1;
45: uVar11 = uVar10 >> 0x20;
46: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4);
47: *plVar1 = ((uVar3 >> 0x20) * 0x4c8b << 0x20) + (uVar3 & 0xffffffff) * 0x4c8b;
48: plVar1[1] = (uVar11 * 0x4c8b << 0x20) + (uVar10 & 0xffffffff) * 0x4c8b;
49: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x800);
50: *plVar1 = ((uVar3 >> 0x20) * 0x9646 << 0x20) + (uVar3 & 0xffffffff) * 0x9646;
51: plVar1[1] = (uVar11 * 0x9646 << 0x20) + (uVar10 & 0xffffffff) * 0x9646;
52: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x1000);
53: *plVar1 = uVar3 * 0x1d2f + 0x8000;
54: plVar1[1] = uVar10 * 0x1d2f + 0x8000;
55: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x1800);
56: *plVar1 = ((uVar3 >> 0x20) * 0xffffd4cd + (uVar3 & 0xffffffff) * 0xffffffff << 0x20) +
57: (uVar3 & 0xffffffff) * 0xffffd4cd;
58: plVar1[1] = (uVar11 * 0xffffd4cd + (uStack96 & 0xffffffff) * (uVar10 & 0xffffffff) << 0x20) +
59: (uVar10 & 0xffffffff) * 0xffffd4cd;
60: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x2000);
61: *plVar1 = ((uVar3 >> 0x20) * 0xffffab33 + (uVar3 & 0xffffffff) * 0xffffffff << 0x20) +
62: (uVar3 & 0xffffffff) * 0xffffab33;
63: plVar1[1] = (uVar11 * 0xffffab33 + (uStack80 & 0xffffffff) * (uVar10 & 0xffffffff) << 0x20) +
64: (uVar10 & 0xffffffff) * 0xffffab33;
65: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x2800);
66: *plVar1 = (uVar3 + 0x101) * 0x8000 + -1;
67: plVar1[1] = (uVar10 + 0x101) * 0x8000 + -1;
68: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x3000);
69: *plVar1 = ((uVar3 >> 0x20) * 0xffff94d1 + (uVar3 & 0xffffffff) * 0xffffffff << 0x20) +
70: (uVar3 & 0xffffffff) * 0xffff94d1;
71: plVar1[1] = (uVar11 * 0xffff94d1 + (uStack64 & 0xffffffff) * (uVar10 & 0xffffffff) << 0x20) +
72: (uVar10 & 0xffffffff) * 0xffff94d1;
73: plVar1 = (long *)((long)puVar2 + lVar5 + lVar4 + 0x3800);
74: *plVar1 = ((uVar3 >> 0x20) * 0xffffeb2f + (uVar3 & 0xffffffff) * 0xffffffff << 0x20) +
75: (uVar3 & 0xffffffff) * 0xffffeb2f;
76: plVar1[1] = (uVar11 * 0xffffeb2f + (uStack48 & 0xffffffff) * (uVar10 & 0xffffffff) << 0x20) +
77: (uVar10 & 0xffffffff) * 0xffffeb2f;
78: lVar5 = lVar5 + 0x10;
79: uVar3 = uVar3 + 2;
80: uVar10 = uVar10 + 2;
81: } while (uVar7 < uVar8 >> 1);
82: lVar4 = uVar6 + (uVar8 & 0xfffffffffffffffe);
83: if (uVar8 != (uVar8 & 0xfffffffffffffffe)) {
84: puVar2[lVar4] = lVar4 * 0x4c8b;
85: puVar2[lVar4 + 0x100] = lVar4 * 0x9646;
86: puVar2[lVar4 + 0x200] = lVar4 * 0x1d2f + 0x8000;
87: puVar2[lVar4 + 0x300] = lVar4 * -0x2b33;
88: puVar2[lVar4 + 0x400] = lVar4 * -0x54cd;
89: puVar2[lVar4 + 0x500] = lVar4 * 0x8000 + 0x807fff;
90: puVar2[lVar4 + 0x600] = lVar4 * -0x6b2f;
91: puVar2[lVar4 + 0x700] = lVar4 * -0x14d1;
92: }
93: return;
94: }
95: 

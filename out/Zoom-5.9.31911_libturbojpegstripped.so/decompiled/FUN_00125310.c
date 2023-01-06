1: 
2: void FUN_00125310(long param_1)
3: 
4: {
5: int iVar1;
6: bool bVar2;
7: bool bVar3;
8: code **ppcVar4;
9: long lVar5;
10: undefined8 *puVar6;
11: ulong uVar7;
12: int iVar8;
13: int iVar9;
14: uint uVar10;
15: ulong uVar11;
16: undefined8 *puVar12;
17: long lVar13;
18: byte bVar14;
19: 
20: bVar14 = 0;
21: iVar8 = 0;
22: ppcVar4 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x80);
23: iVar9 = *(int *)(param_1 + 0x38);
24: *(code ***)(param_1 + 600) = ppcVar4;
25: lVar13 = *(long *)(param_1 + 0x130);
26: *ppcVar4 = FUN_00124560;
27: if (0 < iVar9) {
28: do {
29: puVar6 = (undefined8 *)(***(code ***)(param_1 + 8))(param_1,1,0x100);
30: *(undefined8 **)(lVar13 + 0x58) = puVar6;
31: uVar11 = 0x100;
32: bVar2 = false;
33: iVar9 = 0x100;
34: bVar3 = false;
35: if (((ulong)puVar6 & 1) == 0) {
36: if (((ulong)puVar6 & 2) == 0) goto LAB_0012536a;
37: LAB_00125400:
38: uVar10 = iVar9 - 2;
39: uVar11 = (ulong)uVar10;
40: *(undefined2 *)puVar6 = 0;
41: puVar6 = (undefined8 *)((long)puVar6 + 2);
42: bVar2 = bVar3;
43: }
44: else {
45: puVar12 = (undefined8 *)((long)puVar6 + 1);
46: *(undefined *)puVar6 = 0;
47: uVar11 = 0xff;
48: bVar2 = true;
49: iVar9 = 0xff;
50: bVar3 = true;
51: puVar6 = puVar12;
52: if (((ulong)puVar12 & 2) != 0) goto LAB_00125400;
53: LAB_0012536a:
54: uVar10 = (uint)uVar11;
55: }
56: if (((ulong)puVar6 & 4) != 0) {
57: *(undefined4 *)puVar6 = 0;
58: uVar11 = (ulong)(uVar10 - 4);
59: puVar6 = (undefined8 *)((long)puVar6 + 4);
60: }
61: uVar7 = uVar11 >> 3;
62: while (uVar7 != 0) {
63: uVar7 = uVar7 - 1;
64: *puVar6 = 0;
65: puVar6 = puVar6 + (ulong)bVar14 * -2 + 1;
66: }
67: if ((uVar11 & 4) != 0) {
68: *(undefined4 *)puVar6 = 0;
69: puVar6 = (undefined8 *)((long)puVar6 + 4);
70: }
71: puVar12 = puVar6;
72: if ((uVar11 & 2) != 0) {
73: puVar12 = (undefined8 *)((long)puVar6 + 2);
74: *(undefined2 *)puVar6 = 0;
75: }
76: if (bVar2) {
77: *(undefined *)puVar12 = 0;
78: }
79: lVar5 = (long)iVar8;
80: lVar13 = lVar13 + 0x60;
81: iVar8 = iVar8 + 1;
82: iVar9 = *(int *)(param_1 + 0x38);
83: iVar1 = *(int *)(param_1 + 0x38);
84: *(undefined4 *)((long)ppcVar4 + lVar5 * 4 + 0x58) = 0xffffffff;
85: } while (iVar1 != iVar8 && iVar8 <= iVar9);
86: }
87: return;
88: }
89: 

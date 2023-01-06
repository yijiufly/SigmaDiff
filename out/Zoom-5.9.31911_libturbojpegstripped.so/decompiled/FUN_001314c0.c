1: 
2: void FUN_001314c0(long param_1)
3: 
4: {
5: bool bVar1;
6: bool bVar2;
7: code **ppcVar3;
8: undefined8 *puVar4;
9: ulong uVar5;
10: int iVar6;
11: uint uVar7;
12: ulong uVar8;
13: undefined8 *puVar9;
14: undefined8 *puVar10;
15: int iVar11;
16: byte bVar12;
17: 
18: bVar12 = 0;
19: ppcVar3 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x68);
20: *(code ***)(param_1 + 0x250) = ppcVar3;
21: ppcVar3[8] = (code *)0x0;
22: ppcVar3[9] = (code *)0x0;
23: ppcVar3[10] = (code *)0x0;
24: *ppcVar3 = FUN_001302f0;
25: ppcVar3[0xb] = (code *)0x0;
26: puVar4 = (undefined8 *)
27: (***(code ***)(param_1 + 8))(param_1,1,(long)(*(int *)(param_1 + 0x38) << 6) * 4);
28: *(undefined8 **)(param_1 + 0xc0) = puVar4;
29: if (0 < *(int *)(param_1 + 0x38)) {
30: iVar11 = 0;
31: do {
32: uVar8 = 0x100;
33: bVar2 = false;
34: iVar6 = 0x100;
35: bVar1 = false;
36: if (((ulong)puVar4 & 1) == 0) {
37: puVar10 = puVar4;
38: puVar9 = puVar4;
39: if (((ulong)puVar4 & 2) != 0) goto LAB_001315c8;
40: LAB_00131556:
41: uVar7 = (uint)uVar8;
42: bVar1 = bVar2;
43: }
44: else {
45: puVar10 = (undefined8 *)((long)puVar4 + 1);
46: *(undefined *)puVar4 = 0xff;
47: uVar8 = 0xff;
48: bVar2 = true;
49: iVar6 = 0xff;
50: bVar1 = true;
51: puVar9 = puVar10;
52: if (((ulong)puVar10 & 2) == 0) goto LAB_00131556;
53: LAB_001315c8:
54: puVar10 = (undefined8 *)((long)puVar9 + 2);
55: uVar7 = iVar6 - 2;
56: uVar8 = (ulong)uVar7;
57: *(undefined2 *)puVar9 = 0xffff;
58: }
59: if (((ulong)puVar10 & 4) != 0) {
60: *(undefined4 *)puVar10 = 0xffffffff;
61: uVar8 = (ulong)(uVar7 - 4);
62: puVar10 = (undefined8 *)((long)puVar10 + 4);
63: }
64: uVar5 = uVar8 >> 3;
65: while (uVar5 != 0) {
66: uVar5 = uVar5 - 1;
67: *puVar10 = 0xffffffffffffffff;
68: puVar10 = puVar10 + (ulong)bVar12 * -2 + 1;
69: }
70: if ((uVar8 & 4) != 0) {
71: *(undefined4 *)puVar10 = 0xffffffff;
72: puVar10 = (undefined8 *)((long)puVar10 + 4);
73: }
74: puVar9 = puVar10;
75: if ((uVar8 & 2) != 0) {
76: puVar9 = (undefined8 *)((long)puVar10 + 2);
77: *(undefined2 *)puVar10 = 0xffff;
78: }
79: if (bVar1) {
80: *(undefined *)puVar9 = 0xff;
81: }
82: puVar4 = puVar4 + 0x20;
83: iVar11 = iVar11 + 1;
84: } while (*(int *)(param_1 + 0x38) != iVar11 && iVar11 <= *(int *)(param_1 + 0x38));
85: }
86: return;
87: }
88: 

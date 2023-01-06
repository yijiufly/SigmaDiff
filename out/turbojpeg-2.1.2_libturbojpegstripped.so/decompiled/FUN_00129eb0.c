1: 
2: void FUN_00129eb0(long param_1,int param_2)
3: 
4: {
5: code **ppcVar1;
6: undefined4 uVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: undefined8 uVar5;
10: uint uVar6;
11: long lVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: bool bVar11;
16: 
17: ppcVar3 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0xe8);
18: *(code ***)(param_1 + 0x230) = ppcVar3;
19: ppcVar3[0x1c] = (code *)0x0;
20: *ppcVar3 = FUN_00126cd0;
21: ppcVar3[2] = FUN_001274b0;
22: if (param_2 == 0) {
23: pcVar4 = (code *)(**(code **)(*(long *)(param_1 + 8) + 8))(param_1,1,0x500);
24: bVar11 = ((ulong)(ppcVar3 + 7) >> 3 & 1) == 0;
25: if (bVar11) {
26: iVar8 = 10;
27: }
28: else {
29: ppcVar3[7] = pcVar4;
30: iVar8 = 9;
31: }
32: uVar6 = (uint)!bVar11;
33: ppcVar1 = ppcVar3 + (ulong)((uint)((ulong)(ppcVar3 + 7) >> 3) & 1) + 7;
34: ppcVar1[2] = pcVar4 + (ulong)(uVar6 + 2) * 0x80;
35: ppcVar1[3] = pcVar4 + (ulong)(uVar6 + 3) * 0x80;
36: *ppcVar1 = pcVar4 + (ulong)uVar6 * 0x80;
37: ppcVar1[1] = pcVar4 + (ulong)(uVar6 + 1) * 0x80;
38: *(undefined (*) [16])(ppcVar1 + 6) =
39: CONCAT412((int)((ulong)(pcVar4 + (ulong)(uVar6 + 7) * 0x80) >> 0x20),
40: CONCAT48((int)(pcVar4 + (ulong)(uVar6 + 7) * 0x80),
41: pcVar4 + (ulong)(uVar6 + 6) * 0x80));
42: ppcVar1[4] = pcVar4 + (ulong)(uVar6 + 4) * 0x80;
43: ppcVar1[5] = pcVar4 + (ulong)(uVar6 + 5) * 0x80;
44: ppcVar3[(long)(int)(uVar6 + 8) + 7] = pcVar4 + (long)(int)(uVar6 + 8) * 0x80;
45: if (iVar8 != 9) {
46: ppcVar3[(long)(int)(uVar6 + 9) + 7] = pcVar4 + 0x480;
47: }
48: ppcVar3[4] = (code *)0x0;
49: ppcVar3[1] = FUN_00126d30;
50: ppcVar3[3] = FUN_001277e0;
51: }
52: else {
53: if (0 < *(int *)(param_1 + 0x38)) {
54: lVar10 = 1;
55: lVar9 = *(long *)(param_1 + 0x130);
56: do {
57: iVar8 = *(int *)(lVar9 + 0xc);
58: lVar7 = (long)iVar8;
59: if (*(int *)(param_1 + 0x138) != 0) {
60: iVar8 = iVar8 * 5;
61: }
62: pcVar4 = *(code **)(*(long *)(param_1 + 8) + 0x28);
63: uVar5 = FUN_001489e0(*(undefined4 *)(lVar9 + 0x20),lVar7);
64: uVar2 = FUN_001489e0(*(undefined4 *)(lVar9 + 0x1c),(long)*(int *)(lVar9 + 8));
65: pcVar4 = (code *)(*pcVar4)(param_1,1,1,uVar2,uVar5,iVar8);
66: ppcVar3[lVar10 + 0x11] = pcVar4;
67: iVar8 = (int)lVar10;
68: lVar10 = lVar10 + 1;
69: lVar9 = lVar9 + 0x60;
70: } while (*(int *)(param_1 + 0x38) != iVar8 && iVar8 <= *(int *)(param_1 + 0x38));
71: }
72: ppcVar3[1] = FUN_00126d40;
73: ppcVar3[3] = FUN_00127260;
74: ppcVar3[4] = (code *)(ppcVar3 + 0x12);
75: }
76: pcVar4 = (code *)(***(code ***)(param_1 + 8))(param_1,1,0x80);
77: ppcVar3[0x11] = pcVar4;
78: return;
79: }
80: 

1: 
2: void FUN_00104050(long param_1,int param_2)
3: 
4: {
5: code **ppcVar1;
6: ulong uVar2;
7: undefined4 uVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: undefined8 uVar6;
11: uint uVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: bool bVar11;
16: 
17: ppcVar4 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0xc0);
18: *(code ***)(param_1 + 0x1c8) = ppcVar4;
19: *ppcVar4 = FUN_00103260;
20: if (param_2 == 0) {
21: pcVar5 = (code *)(**(code **)(*(long *)(param_1 + 8) + 8))(param_1,1,0x500);
22: uVar2 = ((ulong)ppcVar4 & 0xffffffff) >> 3;
23: bVar11 = (uVar2 & 1) == 0;
24: if (bVar11) {
25: iVar8 = 10;
26: }
27: else {
28: ppcVar4[4] = pcVar5;
29: iVar8 = 9;
30: }
31: uVar7 = (uint)!bVar11;
32: ppcVar1 = ppcVar4 + (ulong)((uint)uVar2 & 1) + 4;
33: ppcVar1[2] = pcVar5 + (ulong)(uVar7 + 2) * 0x80;
34: ppcVar1[3] = pcVar5 + (ulong)(uVar7 + 3) * 0x80;
35: *ppcVar1 = pcVar5 + (ulong)uVar7 * 0x80;
36: ppcVar1[1] = pcVar5 + (ulong)(uVar7 + 1) * 0x80;
37: *(undefined (*) [16])(ppcVar1 + 6) =
38: CONCAT412((int)((ulong)(pcVar5 + (ulong)(uVar7 + 7) * 0x80) >> 0x20),
39: CONCAT48((int)(pcVar5 + (ulong)(uVar7 + 7) * 0x80),
40: pcVar5 + (ulong)(uVar7 + 6) * 0x80));
41: ppcVar1[4] = pcVar5 + (ulong)(uVar7 + 4) * 0x80;
42: ppcVar1[5] = pcVar5 + (ulong)(uVar7 + 5) * 0x80;
43: ppcVar4[(long)(int)(uVar7 + 8) + 4] = pcVar5 + (long)(int)(uVar7 + 8) * 0x80;
44: if (iVar8 != 9) {
45: ppcVar4[(long)(int)(uVar7 + 9) + 4] = pcVar5 + 0x480;
46: }
47: ppcVar4[0xe] = (code *)0x0;
48: }
49: else {
50: lVar10 = 1;
51: lVar9 = *(long *)(param_1 + 0x58);
52: if (0 < *(int *)(param_1 + 0x4c)) {
53: do {
54: iVar8 = *(int *)(lVar9 + 0xc);
55: pcVar5 = *(code **)(*(long *)(param_1 + 8) + 0x28);
56: uVar6 = FUN_001489e0(*(undefined4 *)(lVar9 + 0x20),(long)iVar8);
57: uVar3 = FUN_001489e0(*(undefined4 *)(lVar9 + 0x1c),(long)*(int *)(lVar9 + 8));
58: pcVar5 = (code *)(*pcVar5)(param_1,1,0,uVar3,uVar6,(long)iVar8 & 0xffffffff);
59: ppcVar4[lVar10 + 0xd] = pcVar5;
60: iVar8 = (int)lVar10;
61: lVar10 = lVar10 + 1;
62: lVar9 = lVar9 + 0x60;
63: } while (*(int *)(param_1 + 0x4c) != iVar8 && iVar8 <= *(int *)(param_1 + 0x4c));
64: return;
65: }
66: }
67: return;
68: }
69: 

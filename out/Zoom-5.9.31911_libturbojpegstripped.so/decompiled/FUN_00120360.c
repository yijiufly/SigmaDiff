1: 
2: void FUN_00120360(long param_1,int param_2)
3: 
4: {
5: undefined4 uVar1;
6: undefined4 uVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: uint uVar5;
10: long lVar6;
11: int iVar7;
12: code **ppcVar8;
13: 
14: ppcVar3 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0xe8);
15: *(code ***)(param_1 + 0x230) = ppcVar3;
16: ppcVar3[0x1c] = (code *)0x0;
17: *ppcVar3 = FUN_0011ffa0;
18: ppcVar3[2] = FUN_0011f500;
19: if (param_2 == 0) {
20: pcVar4 = (code *)(**(code **)(*(long *)(param_1 + 8) + 8))(param_1,1,0x500);
21: lVar6 = (long)(ppcVar3 + 7) << 0x3c;
22: if (-1 < lVar6) {
23: iVar7 = 10;
24: }
25: else {
26: ppcVar3[7] = pcVar4;
27: iVar7 = 9;
28: }
29: uVar5 = (uint)(-1 >= lVar6);
30: ppcVar8 = ppcVar3 + (7 - (lVar6 >> 0x3f));
31: ppcVar8[2] = pcVar4 + (ulong)(uVar5 + 2) * 0x80;
32: ppcVar8[3] = pcVar4 + (ulong)(uVar5 + 3) * 0x80;
33: ppcVar8[4] = pcVar4 + (ulong)(uVar5 + 4) * 0x80;
34: ppcVar8[5] = pcVar4 + (ulong)(uVar5 + 5) * 0x80;
35: *ppcVar8 = pcVar4 + (ulong)uVar5 * 0x80;
36: ppcVar8[1] = pcVar4 + (ulong)(uVar5 + 1) * 0x80;
37: ppcVar8[6] = pcVar4 + (ulong)(uVar5 + 6) * 0x80;
38: ppcVar8[7] = pcVar4 + (ulong)(uVar5 + 7) * 0x80;
39: ppcVar3[(long)(int)(uVar5 + 8) + 7] = pcVar4 + (long)(int)(uVar5 + 8) * 0x80;
40: if (iVar7 != 9) {
41: ppcVar3[(long)(int)(uVar5 + 9) + 7] = pcVar4 + (long)(int)(uVar5 + 9) * 0x80;
42: }
43: ppcVar3[1] = FUN_0011ec80;
44: ppcVar3[3] = FUN_00120010;
45: ppcVar3[4] = (code *)0x0;
46: }
47: else {
48: iVar7 = 0;
49: lVar6 = *(long *)(param_1 + 0x130);
50: ppcVar8 = ppcVar3;
51: if (0 < *(int *)(param_1 + 0x38)) {
52: do {
53: pcVar4 = *(code **)(*(long *)(param_1 + 8) + 0x28);
54: iVar7 = iVar7 + 1;
55: uVar1 = FUN_0013be30(*(undefined4 *)(lVar6 + 0x20));
56: uVar2 = FUN_0013be30(*(undefined4 *)(lVar6 + 0x1c),(long)*(int *)(lVar6 + 8));
57: pcVar4 = (code *)(*pcVar4)(param_1,1,1,uVar2,uVar1);
58: ppcVar8[0x12] = pcVar4;
59: lVar6 = lVar6 + 0x60;
60: ppcVar8 = ppcVar8 + 1;
61: } while (*(int *)(param_1 + 0x38) != iVar7 && iVar7 <= *(int *)(param_1 + 0x38));
62: }
63: ppcVar3[3] = FUN_0011f2e0;
64: ppcVar3[1] = FUN_0011ec90;
65: ppcVar3[4] = (code *)(ppcVar3 + 0x12);
66: }
67: pcVar4 = (code *)(***(code ***)(param_1 + 8))(param_1,1,0x80);
68: ppcVar3[0x11] = pcVar4;
69: return;
70: }
71: 

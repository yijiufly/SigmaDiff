1: 
2: void FUN_00132220(long param_1,long param_2,long param_3,long *param_4)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: int iVar3;
8: long lVar4;
9: uint uVar5;
10: long lVar6;
11: long *plVar7;
12: long lVar8;
13: int iVar9;
14: long lVar10;
15: int iVar11;
16: 
17: lVar10 = *param_4;
18: if (0 < *(int *)(param_1 + 0x19c)) {
19: uVar5 = *(uint *)(param_2 + 0x28);
20: iVar11 = 0;
21: plVar7 = (long *)(param_3 + -8);
22: do {
23: lVar6 = 0;
24: do {
25: lVar1 = plVar7[1];
26: if ((int)lVar6 == 0) {
27: lVar8 = *plVar7;
28: iVar9 = 1;
29: }
30: else {
31: lVar8 = plVar7[2];
32: iVar9 = 2;
33: }
34: lVar2 = *(long *)(lVar10 + lVar6 * 8);
35: if (uVar5 != 0) {
36: lVar4 = 0;
37: do {
38: iVar3 = (int)lVar4;
39: *(char *)(lVar2 + lVar4) =
40: (char)((int)((uint)*(byte *)(lVar8 + lVar4) +
41: (uint)*(byte *)(lVar1 + lVar4) + (uint)*(byte *)(lVar1 + lVar4) * 2 +
42: iVar9) >> 2);
43: uVar5 = *(uint *)(param_2 + 0x28);
44: lVar4 = lVar4 + 1;
45: } while (iVar3 + 1U < uVar5);
46: }
47: lVar6 = lVar6 + 1;
48: } while (lVar6 != 2);
49: iVar11 = iVar11 + 2;
50: lVar10 = lVar10 + 0x10;
51: plVar7 = plVar7 + 1;
52: } while (*(int *)(param_1 + 0x19c) != iVar11 && iVar11 <= *(int *)(param_1 + 0x19c));
53: }
54: return;
55: }
56: 

1: 
2: void FUN_0013d340(long param_1,long param_2,long *param_3,long *param_4)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: uint uVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: int iVar8;
13: long lVar9;
14: int iVar10;
15: 
16: lVar6 = *param_4;
17: if (0 < *(int *)(param_1 + 0x19c)) {
18: uVar3 = *(uint *)(param_2 + 0x28);
19: iVar10 = 0;
20: do {
21: lVar5 = 0;
22: lVar9 = *param_3;
23: lVar7 = param_3[-1];
24: iVar8 = 1;
25: while( true ) {
26: lVar1 = *(long *)(lVar6 + lVar5 * 8);
27: if (uVar3 != 0) {
28: lVar4 = 0;
29: do {
30: iVar2 = (int)lVar4;
31: *(char *)(lVar1 + lVar4) =
32: (char)((int)((uint)*(byte *)(lVar9 + lVar4) + (uint)*(byte *)(lVar9 + lVar4) * 2 +
33: (uint)*(byte *)(lVar7 + lVar4) + iVar8) >> 2);
34: uVar3 = *(uint *)(param_2 + 0x28);
35: lVar4 = lVar4 + 1;
36: } while (iVar2 + 1U < uVar3);
37: }
38: if (lVar5 == 1) break;
39: lVar9 = *param_3;
40: lVar5 = 1;
41: lVar7 = param_3[1];
42: iVar8 = 2;
43: }
44: iVar10 = iVar10 + 2;
45: lVar6 = lVar6 + 0x10;
46: param_3 = param_3 + 1;
47: } while (*(int *)(param_1 + 0x19c) != iVar10 && iVar10 <= *(int *)(param_1 + 0x19c));
48: }
49: return;
50: }
51: 

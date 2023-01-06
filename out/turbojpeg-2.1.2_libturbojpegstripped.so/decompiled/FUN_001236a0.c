1: 
2: void FUN_001236a0(long param_1,long param_2,long *param_3,long param_4)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: uint uVar7;
12: long lVar8;
13: long *plVar9;
14: void *__s;
15: long lVar10;
16: 
17: uVar7 = *(uint *)(param_1 + 0x30);
18: iVar1 = *(int *)(param_2 + 0x1c) * 8;
19: iVar6 = *(int *)(param_2 + 0x1c) * 0x10 - uVar7;
20: if ((0 < iVar6) && (iVar2 = *(int *)(param_1 + 0x13c), 0 < iVar2)) {
21: plVar9 = param_3;
22: do {
23: lVar10 = *plVar9;
24: plVar9 = plVar9 + 1;
25: __s = (void *)(lVar10 + (ulong)uVar7);
26: memset(__s,(uint)*(byte *)((long)__s + -1),(long)(iVar6 + -1) + 1);
27: } while (param_3 + (ulong)(iVar2 - 1) + 1 != plVar9);
28: }
29: if ((0 < *(int *)(param_2 + 0xc)) && (iVar1 != 0)) {
30: lVar10 = 1;
31: do {
32: lVar3 = *(long *)(param_4 + -8 + lVar10 * 8);
33: lVar4 = *param_3;
34: lVar8 = 0;
35: lVar5 = param_3[1];
36: uVar7 = 1;
37: do {
38: iVar6 = (uint)*(byte *)(lVar4 + lVar8 * 2) + (uint)*(byte *)(lVar4 + 1 + lVar8 * 2) +
39: (uint)*(byte *)(lVar5 + lVar8 * 2) + (uint)*(byte *)(lVar5 + 1 + lVar8 * 2) + uVar7;
40: uVar7 = uVar7 ^ 3;
41: *(char *)(lVar3 + lVar8) = (char)(iVar6 >> 2);
42: lVar8 = lVar8 + 1;
43: } while ((ulong)(iVar1 - 1) + 1 != lVar8);
44: iVar6 = (int)lVar10;
45: param_3 = param_3 + 2;
46: lVar10 = lVar10 + 1;
47: } while (iVar6 < *(int *)(param_2 + 0xc));
48: }
49: return;
50: }
51: 

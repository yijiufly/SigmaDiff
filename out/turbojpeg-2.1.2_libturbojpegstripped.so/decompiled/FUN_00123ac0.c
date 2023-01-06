1: 
2: void FUN_00123ac0(long param_1,long param_2,long param_3,long param_4)
3: 
4: {
5: long *plVar1;
6: byte bVar2;
7: uint uVar3;
8: int iVar4;
9: undefined *puVar5;
10: byte *pbVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: int iVar9;
14: ulong uVar10;
15: long lVar11;
16: long lVar12;
17: void *__s;
18: long lVar13;
19: int iVar14;
20: long lVar15;
21: long lVar16;
22: long lVar17;
23: long lVar18;
24: 
25: uVar3 = *(uint *)(param_1 + 0x30);
26: iVar14 = *(int *)(param_2 + 0x1c) * 8;
27: iVar9 = iVar14 - uVar3;
28: if ((0 < iVar9) && (iVar4 = *(int *)(param_1 + 0x13c), -2 < iVar4)) {
29: lVar17 = param_3;
30: do {
31: plVar1 = (long *)(lVar17 + -8);
32: lVar17 = lVar17 + 8;
33: __s = (void *)(*plVar1 + (ulong)uVar3);
34: memset(__s,(uint)*(byte *)((long)__s + -1),(long)(iVar9 + -1) + 1);
35: } while (param_3 + 8 + (ulong)(iVar4 + 1) * 8 != lVar17);
36: }
37: lVar16 = (0x80 - (long)*(int *)(param_1 + 0x110)) * 0x200;
38: lVar17 = (long)(*(int *)(param_1 + 0x110) << 6);
39: if (0 < *(int *)(param_2 + 0xc)) {
40: uVar10 = (ulong)(iVar14 - 3);
41: lVar18 = 1;
42: do {
43: puVar5 = *(undefined **)(param_4 + -8 + lVar18 * 8);
44: pbVar6 = *(byte **)(param_3 + -8 + lVar18 * 8);
45: pbVar7 = *(byte **)(param_3 + lVar18 * 8);
46: pbVar8 = *(byte **)(param_3 + -0x10 + lVar18 * 8);
47: bVar2 = *pbVar6;
48: lVar11 = (long)(int)((uint)*pbVar8 + (uint)*pbVar7 + (uint)bVar2);
49: iVar14 = (uint)pbVar7[1] + (uint)pbVar8[1] + (uint)pbVar6[1];
50: *puVar5 = (char)(lVar16 * (ulong)bVar2 + 0x8000 +
51: ((lVar11 * 2 - (ulong)bVar2) + (long)iVar14) * lVar17 >> 0x10);
52: lVar12 = 2;
53: lVar13 = (long)iVar14;
54: do {
55: lVar15 = lVar13;
56: iVar9 = (uint)pbVar8[lVar12] + (uint)pbVar7[lVar12] + (uint)pbVar6[lVar12];
57: lVar13 = (long)iVar9;
58: puVar5[lVar12 + -1] =
59: (char)(lVar16 * (ulong)pbVar6[lVar12 + -1] + 0x8000 +
60: ((lVar15 - (ulong)pbVar6[lVar12 + -1]) + lVar11 + lVar13) * lVar17 >> 0x10);
61: lVar12 = lVar12 + 1;
62: lVar11 = (long)iVar14;
63: iVar14 = iVar9;
64: } while (uVar10 + 3 != lVar12);
65: puVar5[uVar10 + 2] =
66: (char)(lVar16 * (ulong)pbVar6[uVar10 + 2] + 0x8000 +
67: (lVar15 + (lVar13 * 2 - (ulong)pbVar6[uVar10 + 2])) * lVar17 >> 0x10);
68: iVar14 = (int)lVar18;
69: lVar18 = lVar18 + 1;
70: } while (*(int *)(param_2 + 0xc) != iVar14 && iVar14 <= *(int *)(param_2 + 0xc));
71: }
72: return;
73: }
74: 

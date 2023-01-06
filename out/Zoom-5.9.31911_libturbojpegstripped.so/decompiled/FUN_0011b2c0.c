1: 
2: void FUN_0011b2c0(long param_1,long param_2,byte **param_3,long *param_4)
3: 
4: {
5: byte **ppbVar1;
6: byte bVar2;
7: uint uVar3;
8: undefined *puVar4;
9: byte *pbVar5;
10: byte *pbVar6;
11: byte *pbVar7;
12: int iVar8;
13: ulong uVar9;
14: long lVar10;
15: long lVar11;
16: byte *pbVar12;
17: byte *pbVar13;
18: uint uVar14;
19: long lVar15;
20: long lVar16;
21: int iVar17;
22: long lVar18;
23: byte **ppbVar19;
24: long lVar20;
25: byte **ppbStack112;
26: long *plStack104;
27: int iStack84;
28: 
29: uVar3 = *(uint *)(param_1 + 0x30);
30: iVar8 = *(int *)(param_2 + 0x1c) * 8;
31: iVar17 = *(int *)(param_1 + 0x13c);
32: uVar14 = iVar8 - uVar3;
33: if ((0 < (int)uVar14) && (-2 < iVar17)) {
34: ppbVar19 = param_3;
35: do {
36: ppbVar1 = ppbVar19 + -1;
37: ppbVar19 = ppbVar19 + 1;
38: memset(*ppbVar1 + uVar3,(uint)(*ppbVar1 + uVar3)[-1],(ulong)uVar14);
39: } while (ppbVar19 != param_3 + (ulong)(iVar17 + 1) + 1);
40: }
41: lVar20 = (long)(*(int *)(param_1 + 0x110) << 6);
42: lVar18 = (0x80 - (long)*(int *)(param_1 + 0x110)) * 0x200;
43: if (0 < *(int *)(param_2 + 0xc)) {
44: iStack84 = 0;
45: uVar9 = (ulong)(iVar8 - 3);
46: ppbStack112 = param_3;
47: plStack104 = param_4;
48: do {
49: puVar4 = (undefined *)*plStack104;
50: pbVar5 = *ppbStack112;
51: pbVar6 = ppbStack112[-1];
52: pbVar7 = ppbStack112[1];
53: bVar2 = *pbVar5;
54: lVar15 = (long)(int)((uint)*pbVar6 + (uint)*pbVar7 + (uint)bVar2);
55: iVar17 = (uint)pbVar6[1] + (uint)pbVar7[1] + (uint)pbVar5[1];
56: *puVar4 = (char)((ulong)bVar2 * lVar18 + 0x8000 +
57: ((lVar15 * 2 - (ulong)bVar2) + (long)iVar17) * lVar20 >> 0x10);
58: lVar10 = 0;
59: pbVar12 = pbVar5 + 1;
60: lVar16 = (long)iVar17;
61: while( true ) {
62: pbVar13 = pbVar12 + 1;
63: iVar8 = (uint)pbVar6[lVar10 + 2] + (uint)pbVar7[lVar10 + 2] + (uint)*pbVar13;
64: lVar11 = (long)iVar8;
65: puVar4[lVar10 + 1] =
66: (char)((ulong)*pbVar12 * lVar18 + 0x8000 +
67: (lVar15 + (lVar16 - (ulong)*pbVar12) + lVar11) * lVar20 >> 0x10);
68: lVar10 = lVar10 + 1;
69: if (pbVar13 == pbVar5 + uVar9 + 2) break;
70: lVar15 = (long)iVar17;
71: pbVar12 = pbVar13;
72: lVar16 = lVar11;
73: iVar17 = iVar8;
74: }
75: iStack84 = iStack84 + 1;
76: plStack104 = plStack104 + 1;
77: ppbStack112 = ppbStack112 + 1;
78: puVar4[uVar9 + 2] =
79: (char)((ulong)pbVar5[uVar9 + 2] * lVar18 + 0x8000 +
80: (lVar16 + (lVar11 * 2 - (ulong)pbVar5[uVar9 + 2])) * lVar20 >> 0x10);
81: } while (*(int *)(param_2 + 0xc) != iStack84 && iStack84 <= *(int *)(param_2 + 0xc));
82: }
83: return;
84: }
85: 

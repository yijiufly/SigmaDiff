1: 
2: void FUN_0013a110(long param_1,long *param_2,uint param_3,ushort **param_4)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: byte bVar4;
9: uint uVar5;
10: int iVar6;
11: int iVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: uint uVar13;
18: uint uVar14;
19: ulong uVar15;
20: ushort *puVar16;
21: byte *pbVar17;
22: int iVar18;
23: long lVar19;
24: byte *pbVar20;
25: byte *pbVar21;
26: 
27: uVar15 = (ulong)param_3;
28: lVar8 = *(long *)(param_1 + 0x260);
29: lVar9 = *(long *)(param_1 + 0x1a8);
30: lVar10 = *(long *)(lVar8 + 0x30);
31: lVar11 = *(long *)(lVar8 + 0x20);
32: lVar12 = *(long *)(lVar8 + 0x28);
33: lVar8 = *(long *)(lVar8 + 0x38);
34: puVar16 = *param_4;
35: pbVar17 = *(byte **)(*param_2 + uVar15 * 8);
36: pbVar20 = *(byte **)(param_2[1] + uVar15 * 8);
37: pbVar21 = *(byte **)(param_2[2] + uVar15 * 8);
38: uVar5 = *(uint *)(param_1 + 0x88);
39: uVar13 = uVar5 >> 1;
40: if (uVar13 != 0) {
41: lVar19 = 0;
42: do {
43: uVar14 = (uint)pbVar17[lVar19 * 2 + 1];
44: iVar6 = *(int *)(lVar11 + (ulong)pbVar21[lVar19] * 4);
45: iVar7 = *(int *)(lVar12 + (ulong)pbVar20[lVar19] * 4);
46: bVar1 = pbVar17[lVar19 * 2];
47: bVar2 = *(byte *)(lVar9 + (int)(iVar6 + uVar14));
48: iVar18 = (int)((ulong)(*(long *)(lVar10 + (ulong)pbVar21[lVar19] * 8) +
49: *(long *)(lVar8 + (ulong)pbVar20[lVar19] * 8)) >> 0x10);
50: bVar3 = *(byte *)(lVar9 + (int)(iVar7 + uVar14));
51: bVar4 = *(byte *)(lVar9 + (int)(uVar14 + iVar18));
52: puVar16[lVar19 * 2] =
53: (ushort)((*(byte *)(lVar9 + (int)(iVar6 + (uint)bVar1)) & 0xf8) << 8) |
54: (ushort)(*(byte *)(lVar9 + (int)(iVar7 + (uint)bVar1)) >> 3) |
55: (ushort)((*(byte *)(lVar9 + (int)((uint)bVar1 + iVar18)) & 0xfc) << 3);
56: puVar16[lVar19 * 2 + 1] =
57: (ushort)((bVar4 & 0xfc) << 3) | (ushort)(bVar3 >> 3) | (ushort)((bVar2 & 0xf8) << 8);
58: lVar19 = lVar19 + 1;
59: } while (lVar19 != (ulong)(uVar13 - 1) + 1);
60: pbVar17 = pbVar17 + lVar19 * 2;
61: puVar16 = puVar16 + lVar19 * 2;
62: pbVar20 = pbVar20 + lVar19;
63: pbVar21 = pbVar21 + lVar19;
64: }
65: if ((uVar5 & 1) != 0) {
66: bVar1 = *pbVar17;
67: *puVar16 = (ushort)*(byte *)(lVar9 + (int)((uint)bVar1 +
68: (int)((ulong)(*(long *)(lVar8 + (ulong)*pbVar20 * 8) +
69: *(long *)(lVar10 + (ulong)*pbVar21 * 8))
70: >> 0x10))) * 8 & 0x7e0 |
71: (ushort)((*(byte *)(lVar9 + (int)(*(int *)(lVar11 + (ulong)*pbVar21 * 4) +
72: (uint)bVar1)) & 0xf8) << 8) |
73: (ushort)(*(byte *)(lVar9 + (int)(*(int *)(lVar12 + (ulong)*pbVar20 * 4) + (uint)bVar1
74: )) >> 3);
75: }
76: return;
77: }
78: 

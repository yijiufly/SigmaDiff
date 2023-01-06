1: 
2: void FUN_00139460(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: byte *pbVar1;
6: int iVar2;
7: long lVar3;
8: long *plVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: byte *pbVar11;
16: byte *pbVar12;
17: uint uVar13;
18: long lVar14;
19: char *pcVar15;
20: long lVar16;
21: long lVar17;
22: uint uStack84;
23: 
24: lVar3 = *(long *)(param_1 + 0x270);
25: plVar4 = *(long **)(lVar3 + 0x30);
26: lVar5 = *plVar4;
27: lVar6 = plVar4[1];
28: lVar7 = plVar4[2];
29: iVar2 = *(int *)(param_1 + 0x88);
30: if (0 < param_4) {
31: uStack84 = *(uint *)(lVar3 + 0x4c);
32: lVar17 = 0;
33: do {
34: pbVar11 = *(byte **)(param_2 + lVar17 * 8);
35: lVar16 = (long)(int)uStack84 * 0x40;
36: pcVar15 = *(char **)(param_3 + lVar17 * 8);
37: lVar8 = *(long *)(lVar3 + 0x50);
38: lVar9 = *(long *)(lVar3 + 0x58);
39: lVar10 = *(long *)(lVar3 + 0x60);
40: pbVar1 = pbVar11 + (ulong)(iVar2 - 1) * 3 + 3;
41: uVar13 = 0;
42: if (iVar2 != 0) {
43: do {
44: lVar14 = (long)(int)uVar13;
45: pbVar12 = pbVar11 + 3;
46: uVar13 = uVar13 + 1 & 0xf;
47: *pcVar15 = *(char *)(lVar7 + (int)((uint)pbVar11[2] +
48: *(int *)(lVar16 + lVar10 + lVar14 * 4))) +
49: *(char *)(lVar5 + (int)((uint)*pbVar11 + *(int *)(lVar16 + lVar8 + lVar14 * 4))
50: ) +
51: *(char *)(lVar6 + (int)((uint)pbVar11[1] +
52: *(int *)(lVar16 + lVar9 + lVar14 * 4)));
53: pbVar11 = pbVar12;
54: pcVar15 = pcVar15 + 1;
55: } while (pbVar12 != pbVar1);
56: }
57: lVar17 = lVar17 + 1;
58: uStack84 = uStack84 + 1 & 0xf;
59: *(uint *)(lVar3 + 0x4c) = uStack84;
60: } while ((int)lVar17 < param_4);
61: }
62: return;
63: }
64: 

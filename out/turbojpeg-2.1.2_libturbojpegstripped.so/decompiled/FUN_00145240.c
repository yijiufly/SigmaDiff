1: 
2: void FUN_00145240(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: long lVar1;
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
16: uint uVar12;
17: byte *pbVar13;
18: byte *pbVar14;
19: char *pcVar15;
20: long lStack96;
21: uint uStack88;
22: 
23: lVar3 = *(long *)(param_1 + 0x270);
24: iVar2 = *(int *)(param_1 + 0x88);
25: plVar4 = *(long **)(lVar3 + 0x30);
26: lVar5 = *plVar4;
27: lVar6 = plVar4[1];
28: lVar7 = plVar4[2];
29: if (0 < param_4) {
30: uStack88 = *(uint *)(lVar3 + 0x4c);
31: lStack96 = 0;
32: do {
33: lVar8 = *(long *)(lVar3 + 0x50);
34: lVar9 = *(long *)(lVar3 + 0x58);
35: lVar10 = *(long *)(lVar3 + 0x60);
36: pbVar11 = *(byte **)(param_2 + lStack96);
37: if (iVar2 != 0) {
38: uVar12 = 0;
39: pbVar13 = pbVar11;
40: pcVar15 = *(char **)(param_3 + lStack96);
41: do {
42: pbVar14 = pbVar13 + 3;
43: lVar1 = (long)(int)uStack88 * 0x40 + (long)(int)uVar12 * 4;
44: uVar12 = uVar12 + 1 & 0xf;
45: *pcVar15 = *(char *)(lVar5 + (int)((uint)*pbVar13 + *(int *)(lVar8 + lVar1))) +
46: *(char *)(lVar6 + (int)((uint)pbVar13[1] + *(int *)(lVar9 + lVar1))) +
47: *(char *)(lVar7 + (int)((uint)pbVar13[2] + *(int *)(lVar10 + lVar1)));
48: pbVar13 = pbVar14;
49: pcVar15 = pcVar15 + 1;
50: } while (pbVar14 != pbVar11 + (ulong)(iVar2 - 1) * 3 + 3);
51: }
52: lStack96 = lStack96 + 8;
53: uStack88 = uStack88 + 1 & 0xf;
54: *(uint *)(lVar3 + 0x4c) = uStack88;
55: } while ((ulong)(param_4 - 1) * 8 + 8 != lStack96);
56: }
57: return;
58: }
59: 

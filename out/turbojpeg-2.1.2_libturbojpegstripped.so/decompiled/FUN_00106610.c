1: 
2: void FUN_00106610(long param_1,byte **param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: byte bVar4;
9: byte bVar5;
10: byte bVar6;
11: int iVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: byte **ppbVar13;
18: ulong uVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: byte *pbVar18;
23: 
24: iVar7 = *(int *)(param_1 + 0x30);
25: lVar8 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
26: while (param_5 = param_5 + -1, -1 < param_5) {
27: ppbVar13 = param_2 + 1;
28: uVar14 = (ulong)param_4;
29: pbVar18 = *param_2;
30: param_4 = param_4 + 1;
31: lVar9 = *(long *)(*param_3 + uVar14 * 8);
32: lVar10 = *(long *)(param_3[1] + uVar14 * 8);
33: lVar11 = *(long *)(param_3[2] + uVar14 * 8);
34: lVar12 = *(long *)(param_3[3] + uVar14 * 8);
35: param_2 = ppbVar13;
36: if (iVar7 != 0) {
37: lVar16 = 0;
38: do {
39: bVar4 = *pbVar18;
40: bVar5 = pbVar18[2];
41: bVar6 = pbVar18[1];
42: *(byte *)(lVar12 + lVar16) = pbVar18[3];
43: lVar15 = (long)(int)(0xff - (uint)bVar6) + 0x100;
44: lVar1 = lVar15 * 8;
45: lVar17 = (long)(int)(0xff - (uint)bVar5) + 0x200;
46: lVar2 = (long)(int)(0xff - (uint)bVar4) * 8;
47: lVar3 = lVar17 * 8;
48: *(char *)(lVar9 + lVar16) =
49: (char)((ulong)(*(long *)(lVar8 + lVar15 * 8) +
50: *(long *)(lVar8 + (long)(int)(0xff - (uint)bVar4) * 8) +
51: *(long *)(lVar8 + lVar17 * 8)) >> 0x10);
52: *(char *)(lVar10 + lVar16) =
53: (char)((ulong)(*(long *)(lVar8 + 0x1800 + lVar1) + *(long *)(lVar8 + 0x1800 + lVar2) +
54: *(long *)(lVar8 + 0x1800 + lVar3)) >> 0x10);
55: *(char *)(lVar11 + lVar16) =
56: (char)((ulong)(*(long *)(lVar8 + 0x2800 + lVar1) + *(long *)(lVar8 + 0x2800 + lVar2) +
57: *(long *)(lVar8 + 0x2800 + lVar3)) >> 0x10);
58: lVar16 = lVar16 + 1;
59: pbVar18 = pbVar18 + 4;
60: } while ((ulong)(iVar7 - 1) + 1 != lVar16);
61: }
62: }
63: return;
64: }
65: 

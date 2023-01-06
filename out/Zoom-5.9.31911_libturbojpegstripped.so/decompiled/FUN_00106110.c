1: 
2: void FUN_00106110(long param_1,byte **param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: byte bVar4;
9: uint uVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: byte **ppbVar11;
16: long lVar12;
17: ulong uVar13;
18: long lVar14;
19: byte *pbVar15;
20: long lVar16;
21: byte **ppbStack72;
22: uint uStack64;
23: int iStack60;
24: 
25: uVar5 = *(uint *)(param_1 + 0x30);
26: lVar6 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
27: ppbStack72 = param_2;
28: uStack64 = param_4;
29: iStack60 = param_5;
30: do {
31: iStack60 = iStack60 + -1;
32: if (iStack60 < 0) {
33: return;
34: }
35: while( true ) {
36: uVar13 = (ulong)uStack64;
37: ppbVar11 = ppbStack72 + 1;
38: uStack64 = uStack64 + 1;
39: lVar7 = *(long *)(*param_3 + uVar13 * 8);
40: pbVar15 = *ppbStack72;
41: lVar8 = *(long *)(param_3[1] + uVar13 * 8);
42: lVar9 = *(long *)(param_3[2] + uVar13 * 8);
43: lVar10 = *(long *)(param_3[3] + uVar13 * 8);
44: lVar12 = 0;
45: ppbStack72 = ppbVar11;
46: if (uVar5 == 0) break;
47: do {
48: bVar4 = *pbVar15;
49: lVar1 = (long)(int)(0xff - (uint)bVar4) * 8;
50: lVar14 = (long)(int)(0xff - (uint)pbVar15[1]) + 0x100;
51: lVar2 = lVar14 * 8;
52: lVar16 = (long)(int)(0xff - (uint)pbVar15[2]) + 0x200;
53: *(byte *)(lVar10 + lVar12) = pbVar15[3];
54: lVar3 = lVar16 * 8;
55: *(char *)(lVar7 + lVar12) =
56: (char)((ulong)(*(long *)(lVar6 + (long)(int)(0xff - (uint)bVar4) * 8) +
57: *(long *)(lVar6 + lVar14 * 8) + *(long *)(lVar6 + lVar16 * 8)) >> 0x10);
58: *(char *)(lVar8 + lVar12) =
59: (char)((ulong)(*(long *)(lVar6 + 0x1800 + lVar1) + *(long *)(lVar6 + 0x1800 + lVar2) +
60: *(long *)(lVar6 + 0x1800 + lVar3)) >> 0x10);
61: *(char *)(lVar9 + lVar12) =
62: (char)((ulong)(*(long *)(lVar6 + 0x2800 + lVar1) + *(long *)(lVar6 + 0x2800 + lVar2) +
63: *(long *)(lVar6 + 0x2800 + lVar3)) >> 0x10);
64: lVar12 = lVar12 + 1;
65: pbVar15 = pbVar15 + 4;
66: } while ((uint)lVar12 < uVar5);
67: iStack60 = iStack60 + -1;
68: if (iStack60 < 0) {
69: return;
70: }
71: }
72: } while( true );
73: }
74: 

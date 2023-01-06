1: 
2: void FUN_0012e530(long param_1,long *param_2,uint param_3,uint **param_4,int param_5)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: long lVar3;
8: uint *puVar4;
9: ulong uVar5;
10: ulong uVar6;
11: uint *puVar7;
12: uint *puVar8;
13: byte *pbVar9;
14: byte *pbVar10;
15: long lVar11;
16: uint uVar12;
17: 
18: lVar3 = *(long *)(param_1 + 0x1a8);
19: uVar12 = *(uint *)(param_1 + 0x88);
20: param_5 = param_5 + -1;
21: uVar6 = *(ulong *)(&DAT_0018cf00 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
22: while (-1 < param_5) {
23: puVar4 = *param_4;
24: pbVar10 = *(byte **)(*param_2 + (ulong)param_3 * 8);
25: puVar7 = puVar4;
26: if (((ulong)puVar4 & 3) != 0) {
27: bVar1 = *pbVar10;
28: puVar7 = (uint *)((long)puVar4 + 2);
29: uVar12 = uVar12 - 1;
30: pbVar10 = pbVar10 + 1;
31: bVar1 = *(byte *)((ulong)bVar1 + lVar3 + (uVar6 & 0xff));
32: *(ushort *)puVar4 =
33: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
34: }
35: if (uVar12 >> 1 != 0) {
36: lVar11 = (ulong)((uVar12 >> 1) - 1) + 1;
37: puVar4 = puVar7 + lVar11;
38: puVar8 = puVar7;
39: pbVar9 = pbVar10;
40: do {
41: puVar7 = puVar8 + 1;
42: bVar1 = *(byte *)((ulong)*pbVar9 + lVar3 + (uVar6 & 0xff));
43: uVar5 = (ulong)((uint)(uVar6 >> 8) & 0xffffff);
44: bVar2 = *(byte *)((ulong)pbVar9[1] + lVar3 + (uVar5 & 0xff));
45: uVar6 = (uVar5 & 0xff) << 0x18 | (long)((uVar6 & 0xff) << 0x18 | uVar5) >> 8;
46: *puVar8 = ((bVar2 & 0xf8) << 8 | (uint)bVar2 * 8 & 0x7e0 | (uint)(bVar2 >> 3)) << 0x10 |
47: (bVar1 & 0xf8) << 8 | (uint)bVar1 * 8 & 0x7e0 | (uint)(bVar1 >> 3);
48: puVar8 = puVar7;
49: pbVar9 = pbVar9 + 2;
50: } while (puVar7 != puVar4);
51: pbVar10 = pbVar10 + lVar11 * 2;
52: }
53: if ((uVar12 & 1) != 0) {
54: bVar1 = *(byte *)((ulong)*pbVar10 + lVar3 + (uVar6 & 0xff));
55: *(ushort *)puVar7 =
56: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
57: }
58: param_5 = param_5 + -1;
59: param_4 = param_4 + 1;
60: param_3 = param_3 + 1;
61: }
62: return;
63: }
64: 

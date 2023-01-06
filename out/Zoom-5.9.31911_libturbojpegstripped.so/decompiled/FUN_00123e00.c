1: 
2: void FUN_00123e00(long param_1,long *param_2,uint param_3,uint **param_4,int param_5)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: long lVar3;
8: ulong uVar4;
9: uint *puVar5;
10: ulong uVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: uint *puVar9;
14: byte *pbVar10;
15: uint uVar11;
16: ulong uVar12;
17: long lVar13;
18: 
19: uVar11 = *(uint *)(param_1 + 0x88);
20: lVar3 = *(long *)(param_1 + 0x1a8);
21: param_5 = param_5 + -1;
22: uVar6 = *(ulong *)(&DAT_001896c0 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
23: while (-1 < param_5) {
24: puVar9 = *param_4;
25: pbVar10 = *(byte **)(*param_2 + (ulong)param_3 * 8);
26: puVar5 = puVar9;
27: if (((ulong)puVar9 & 3) != 0) {
28: bVar1 = *pbVar10;
29: puVar5 = (uint *)((long)puVar9 + 2);
30: uVar11 = uVar11 - 1;
31: pbVar10 = pbVar10 + 1;
32: bVar1 = *(byte *)((ulong)bVar1 + lVar3 + (uVar6 & 0xff));
33: *(ushort *)puVar9 =
34: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
35: }
36: if (uVar11 >> 1 != 0) {
37: uVar12 = (ulong)((uVar11 >> 1) - 1);
38: pbVar7 = pbVar10;
39: puVar9 = puVar5;
40: do {
41: pbVar8 = pbVar7 + 2;
42: bVar1 = *(byte *)((ulong)*pbVar7 + lVar3 + (uVar6 & 0xff));
43: uVar4 = (ulong)((uint)(uVar6 >> 8) & 0xffffff);
44: bVar2 = *(byte *)((ulong)pbVar7[1] + lVar3 + (uVar4 & 0xff));
45: uVar6 = (uVar4 & 0xff) << 0x18 | (long)(uVar4 | (uVar6 & 0xff) << 0x18) >> 8;
46: *puVar9 = (bVar1 & 0xf8) << 8 | (uint)bVar1 * 8 & 0x7e0 | (uint)(bVar1 >> 3) |
47: ((bVar2 & 0xf8) << 8 | (uint)bVar2 * 8 & 0x7e0 | (uint)(bVar2 >> 3)) << 0x10;
48: pbVar7 = pbVar8;
49: puVar9 = puVar9 + 1;
50: } while (pbVar8 != pbVar10 + uVar12 * 2 + 2);
51: lVar13 = uVar12 + 1;
52: pbVar10 = pbVar10 + lVar13 * 2;
53: puVar5 = puVar5 + lVar13;
54: }
55: if ((uVar11 & 1) != 0) {
56: bVar1 = *(byte *)((ulong)*pbVar10 + lVar3 + (uVar6 & 0xff));
57: *(ushort *)puVar5 =
58: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
59: }
60: param_5 = param_5 + -1;
61: param_4 = param_4 + 1;
62: param_3 = param_3 + 1;
63: }
64: return;
65: }
66: 

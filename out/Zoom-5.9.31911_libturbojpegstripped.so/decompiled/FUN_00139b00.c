1: 
2: void FUN_00139b00(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: char *pcVar1;
6: byte bVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: char *pcVar9;
14: uint uVar10;
15: byte *pbVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: 
20: iVar3 = *(int *)(param_1 + 0x90);
21: lVar6 = *(long *)(param_1 + 0x270);
22: iVar4 = *(int *)(param_1 + 0x88);
23: if (0 < param_4) {
24: lVar14 = 0;
25: do {
26: FUN_0013bed0(*(undefined8 *)(param_3 + lVar14));
27: iVar5 = *(int *)(lVar6 + 0x4c);
28: if (0 < iVar3) {
29: lVar13 = 0;
30: do {
31: lVar7 = *(long *)(lVar6 + 0x50 + lVar13 * 8);
32: pbVar11 = (byte *)(lVar13 + *(long *)(param_2 + lVar14));
33: pcVar9 = *(char **)(param_3 + lVar14);
34: lVar8 = *(long *)(*(long *)(lVar6 + 0x30) + lVar13 * 8);
35: uVar10 = 0;
36: pcVar1 = pcVar9 + (ulong)(iVar4 - 1) + 1;
37: if (iVar4 != 0) {
38: do {
39: bVar2 = *pbVar11;
40: lVar12 = (long)(int)uVar10;
41: pbVar11 = pbVar11 + iVar3;
42: uVar10 = uVar10 + 1 & 0xf;
43: *pcVar9 = *pcVar9 + *(char *)(lVar8 + (int)((uint)bVar2 +
44: *(int *)((long)iVar5 * 0x40 + lVar7 +
45: lVar12 * 4)));
46: pcVar9 = pcVar9 + 1;
47: } while (pcVar9 != pcVar1);
48: }
49: lVar13 = lVar13 + 1;
50: } while ((int)lVar13 < iVar3);
51: }
52: lVar14 = lVar14 + 8;
53: *(uint *)(lVar6 + 0x4c) = iVar5 + 1U & 0xf;
54: } while (lVar14 != (ulong)(param_4 - 1) * 8 + 8);
55: }
56: return;
57: }
58: 

1: 
2: void FUN_00145bf0(long param_1,long *param_2,char **param_3,int param_4)
3: 
4: {
5: char *pcVar1;
6: char **ppcVar2;
7: byte bVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: uint uVar11;
16: char *pcVar12;
17: byte *pbVar13;
18: long lVar14;
19: 
20: iVar4 = *(int *)(param_1 + 0x90);
21: lVar7 = *(long *)(param_1 + 0x270);
22: iVar5 = *(int *)(param_1 + 0x88);
23: if (0 < param_4) {
24: ppcVar2 = param_3 + (ulong)(param_4 - 1) + 1;
25: do {
26: FUN_00148a80(*param_3,iVar5);
27: iVar6 = *(int *)(lVar7 + 0x4c);
28: if ((0 < iVar4) && (iVar5 != 0)) {
29: lVar14 = 0;
30: do {
31: pcVar12 = *param_3;
32: uVar11 = 0;
33: lVar8 = *(long *)(lVar7 + 0x50 + lVar14 * 8);
34: lVar9 = *(long *)(*(long *)(lVar7 + 0x30) + lVar14 * 8);
35: pcVar1 = pcVar12 + (ulong)(iVar5 - 1) + 1;
36: pbVar13 = (byte *)(*param_2 + lVar14);
37: do {
38: lVar10 = (long)(int)uVar11;
39: bVar3 = *pbVar13;
40: uVar11 = uVar11 + 1 & 0xf;
41: pbVar13 = pbVar13 + iVar4;
42: *pcVar12 = *pcVar12 +
43: *(char *)(lVar9 + (int)((uint)bVar3 +
44: *(int *)(lVar8 + lVar10 * 4 + (long)iVar6 * 0x40)));
45: pcVar12 = pcVar12 + 1;
46: } while (pcVar12 != pcVar1);
47: lVar14 = lVar14 + 1;
48: } while ((int)lVar14 < iVar4);
49: }
50: param_3 = param_3 + 1;
51: param_2 = param_2 + 1;
52: *(uint *)(lVar7 + 0x4c) = iVar6 + 1U & 0xf;
53: } while (ppcVar2 != param_3);
54: }
55: return;
56: }
57: 

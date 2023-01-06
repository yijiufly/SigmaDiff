1: 
2: void FUN_00139310(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: long lVar1;
6: byte *pbVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: char *pcVar6;
11: long lVar7;
12: char cVar8;
13: long lVar9;
14: long lVar10;
15: char *pcVar11;
16: char *pcVar12;
17: 
18: lVar9 = 0;
19: iVar3 = *(int *)(param_1 + 0x88);
20: iVar4 = *(int *)(param_1 + 0x90);
21: lVar5 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
22: if (0 < param_4) {
23: do {
24: lVar10 = *(long *)(param_2 + lVar9 * 8);
25: pcVar6 = *(char **)(param_3 + lVar9 * 8);
26: if (iVar3 != 0) {
27: pcVar11 = pcVar6;
28: do {
29: if (iVar4 < 1) {
30: cVar8 = '\0';
31: }
32: else {
33: lVar7 = 0;
34: cVar8 = '\0';
35: do {
36: pbVar2 = (byte *)(lVar10 + lVar7);
37: lVar1 = lVar7 * 8;
38: lVar7 = lVar7 + 1;
39: cVar8 = cVar8 + *(char *)(*(long *)(lVar5 + lVar1) + (ulong)*pbVar2);
40: } while ((int)lVar7 < iVar4);
41: lVar10 = lVar10 + (ulong)(iVar4 - 1) + 1;
42: }
43: pcVar12 = pcVar11 + 1;
44: *pcVar11 = cVar8;
45: pcVar11 = pcVar12;
46: } while (pcVar12 != pcVar6 + (ulong)(iVar3 - 1) + 1);
47: }
48: lVar9 = lVar9 + 1;
49: } while ((int)lVar9 < param_4);
50: }
51: return;
52: }
53: 

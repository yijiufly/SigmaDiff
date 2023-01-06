1: 
2: void FUN_00146530(long param_1,byte **param_2,undefined8 param_3,int param_4)
3: 
4: {
5: byte *pbVar1;
6: byte **ppbVar2;
7: int iVar3;
8: long lVar4;
9: short sVar5;
10: short *psVar6;
11: byte *pbVar7;
12: 
13: lVar4 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
14: iVar3 = *(int *)(param_1 + 0x88);
15: if ((0 < param_4) && (iVar3 != 0)) {
16: ppbVar2 = param_2 + (ulong)(param_4 - 1) + 1;
17: do {
18: pbVar7 = *param_2;
19: pbVar1 = pbVar7 + (ulong)(iVar3 - 1) * 3 + 3;
20: do {
21: psVar6 = (short *)((ulong)(pbVar7[1] >> 2) * 0x40 + (ulong)(pbVar7[2] >> 3) * 2 +
22: *(long *)(lVar4 + (ulong)(*pbVar7 >> 3) * 8));
23: sVar5 = *psVar6 + 1;
24: if (sVar5 == 0) {
25: sVar5 = -1;
26: }
27: pbVar7 = pbVar7 + 3;
28: *psVar6 = sVar5;
29: } while (pbVar1 != pbVar7);
30: param_2 = param_2 + 1;
31: } while (ppbVar2 != param_2);
32: return;
33: }
34: return;
35: }
36: 

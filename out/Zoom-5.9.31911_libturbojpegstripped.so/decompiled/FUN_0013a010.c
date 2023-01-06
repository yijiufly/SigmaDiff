1: 
2: void FUN_0013a010(long param_1,long param_2,undefined8 param_3,int param_4)
3: 
4: {
5: byte *pbVar1;
6: short *psVar2;
7: int iVar3;
8: long lVar4;
9: byte *pbVar5;
10: short sVar6;
11: long lVar7;
12: 
13: iVar3 = *(int *)(param_1 + 0x88);
14: lVar4 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
15: if (0 < param_4) {
16: lVar7 = 0;
17: do {
18: pbVar5 = *(byte **)(param_2 + lVar7 * 8);
19: pbVar1 = pbVar5 + (ulong)(iVar3 - 1) * 3 + 3;
20: if (iVar3 != 0) {
21: do {
22: psVar2 = (short *)((ulong)(pbVar5[1] >> 2) * 0x40 +
23: *(long *)(lVar4 + (ulong)(*pbVar5 >> 3) * 8) +
24: (ulong)(pbVar5[2] >> 3) * 2);
25: sVar6 = *psVar2 + 1;
26: if (sVar6 != 0) {
27: *psVar2 = sVar6;
28: }
29: pbVar5 = pbVar5 + 3;
30: } while (pbVar5 != pbVar1);
31: }
32: lVar7 = lVar7 + 1;
33: } while ((int)lVar7 < param_4);
34: }
35: return;
36: }
37: 

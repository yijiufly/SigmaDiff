1: 
2: void FUN_00106a90(long *param_1,uint param_2,short *param_3)
3: 
4: {
5: byte *pbVar1;
6: short *psVar2;
7: short *psVar3;
8: 
9: psVar2 = param_3;
10: do {
11: pbVar1 = (byte *)((ulong)param_2 + *param_1);
12: psVar3 = psVar2 + 8;
13: param_1 = param_1 + 1;
14: *psVar2 = *pbVar1 - 0x80;
15: psVar2[1] = pbVar1[1] - 0x80;
16: psVar2[2] = pbVar1[2] - 0x80;
17: psVar2[3] = pbVar1[3] - 0x80;
18: psVar2[4] = pbVar1[4] - 0x80;
19: psVar2[5] = pbVar1[5] - 0x80;
20: psVar2[6] = pbVar1[6] - 0x80;
21: psVar2[7] = pbVar1[7] - 0x80;
22: psVar2 = psVar3;
23: } while (psVar3 != param_3 + 0x40);
24: return;
25: }
26: 

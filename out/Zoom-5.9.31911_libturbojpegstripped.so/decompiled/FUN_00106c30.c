1: 
2: void FUN_00106c30(long *param_1,uint param_2,float *param_3)
3: 
4: {
5: byte *pbVar1;
6: float *pfVar2;
7: float *pfVar3;
8: 
9: pfVar2 = param_3;
10: do {
11: pbVar1 = (byte *)((ulong)param_2 + *param_1);
12: pfVar3 = pfVar2 + 8;
13: param_1 = param_1 + 1;
14: *pfVar2 = (float)(*pbVar1 - 0x80);
15: pfVar2[1] = (float)(pbVar1[1] - 0x80);
16: pfVar2[2] = (float)(pbVar1[2] - 0x80);
17: pfVar2[3] = (float)(pbVar1[3] - 0x80);
18: pfVar2[4] = (float)(pbVar1[4] - 0x80);
19: pfVar2[5] = (float)(pbVar1[5] - 0x80);
20: pfVar2[6] = (float)(pbVar1[6] - 0x80);
21: pfVar2[7] = (float)(pbVar1[7] - 0x80);
22: pfVar2 = pfVar3;
23: } while (pfVar3 != param_3 + 0x40);
24: return;
25: }
26: 

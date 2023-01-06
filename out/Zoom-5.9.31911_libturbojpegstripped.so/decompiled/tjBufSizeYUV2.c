1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long tjBufSizeYUV2(undefined4 param_1,int param_2,undefined4 param_3,uint param_4)
5: 
6: {
7: int iVar1;
8: int iVar2;
9: int iVar3;
10: long lVar4;
11: 
12: if (5 < param_4) {
13: s_No_error_003a6000._0_8_ = 0x7a69536675426a74;
14: ram0x003a6008 = 0x3a29283256555965;
15: _DAT_003a6010 = 0x64696c61766e4920;
16: _DAT_003a6018 = 0x6e656d7567726120;
17: _DAT_003a6020 = 0x74;
18: return -1;
19: }
20: iVar3 = 0;
21: lVar4 = 0;
22: while( true ) {
23: iVar1 = tjPlaneWidth(iVar3,param_1,param_4);
24: iVar2 = tjPlaneHeight(iVar3,param_3,param_4);
25: if ((iVar2 < 0) || (iVar1 < 0)) break;
26: iVar3 = iVar3 + 1;
27: lVar4 = lVar4 + (long)(iVar1 + -1 + param_2 & -param_2) * (long)iVar2;
28: if ((int)((param_4 != 3) + 1 + (uint)(param_4 != 3)) <= iVar3) {
29: return lVar4;
30: }
31: }
32: return -1;
33: }
34: 

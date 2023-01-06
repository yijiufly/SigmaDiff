1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long tjBufSize(int param_1,int param_2,uint param_3)
5: 
6: {
7: int iVar1;
8: int iVar2;
9: long lVar3;
10: 
11: if (((0 < param_1) && (0 < param_2)) && (param_3 < 6)) {
12: iVar1 = *(int *)(&DAT_0018bc90 + (long)(int)param_3 * 4);
13: iVar2 = *(int *)(&DAT_0018bc70 + (long)(int)param_3 * 4);
14: lVar3 = 2;
15: if (param_3 != 3) {
16: lVar3 = (long)(int)(0x100 / (long)(iVar1 * iVar2)) + 2;
17: }
18: return lVar3 * ((iVar1 + -1 + param_1 & -iVar1) * (iVar2 + -1 + param_2 & -iVar2)) + 0x800;
19: }
20: s_No_error_003a6000._0_8_ = 0x7a69536675426a74;
21: ram0x003a6008 = 0x766e49203a292865;
22: _DAT_003a6010 = 0x6772612064696c61;
23: _DAT_003a6018 = 0x6e656d75;
24: _DAT_003a601c = 0x74;
25: return -1;
26: }
27: 

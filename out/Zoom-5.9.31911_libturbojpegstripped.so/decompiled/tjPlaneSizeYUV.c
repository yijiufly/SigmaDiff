1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long tjPlaneSizeYUV(ulong param_1,undefined8 param_2,uint param_3,int param_4,uint param_5)
5: 
6: {
7: int iVar1;
8: int iVar2;
9: long lVar3;
10: ulong uVar4;
11: 
12: if (((0 < (int)param_2) && (0 < param_4)) && (param_5 < 6)) {
13: iVar1 = tjPlaneWidth(param_1,param_2,param_5);
14: uVar4 = SEXT48(iVar1);
15: iVar2 = tjPlaneHeight(param_1 & 0xffffffff,param_4,param_5);
16: if ((iVar2 < 0) || ((uVar4 & 0xffffffff) >> 0x1f != 0)) {
17: lVar3 = -1;
18: }
19: else {
20: if (param_3 != 0) {
21: iVar1 = (param_3 ^ (int)param_3 >> 0x1f) - ((int)param_3 >> 0x1f);
22: }
23: lVar3 = (long)iVar1 * (long)(iVar2 + -1) + uVar4;
24: }
25: return lVar3;
26: }
27: s_No_error_003a6000._0_8_ = 0x53656e616c506a74;
28: ram0x003a6008 = 0x2928565559657a69;
29: _DAT_003a6010 = 0x696c61766e49203a;
30: _DAT_003a6018 = 0x656d756772612064;
31: _DAT_003a6020 = 0x746e;
32: DAT_003a6022 = 0;
33: return -1;
34: }
35: 

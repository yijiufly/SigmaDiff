1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjCompressFromYUV(long param_1,long param_2,int param_3,int param_4,int param_5,uint param_6,
6: undefined8 param_7,undefined8 param_8,undefined4 param_9,undefined4 param_10)
7: 
8: {
9: int iVar1;
10: int iVar2;
11: int iVar3;
12: undefined8 uVar4;
13: uint uStack104;
14: uint uStack100;
15: uint uStack96;
16: long lStack88;
17: long lStack80;
18: long lStack72;
19: 
20: if (param_1 == 0) {
21: _DAT_003a6020 = 0x656c64;
22: s_No_error_003a6000._0_8_ = 0x6572706d6f436a74;
23: ram0x003a6008 = 0x55596d6f72467373;
24: _DAT_003a6010 = 0x766e49203a292856;
25: _DAT_003a6018 = 0x6e61682064696c61;
26: uVar4 = 0xffffffff;
27: }
28: else {
29: *(undefined4 *)(param_1 + 0x6d0) = 0;
30: if ((((param_2 == 0) || (param_3 < 1)) || (param_4 < 1)) || ((param_5 < 1 || (5 < param_6)))) {
31: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
32: *(undefined2 *)(param_1 + 0x62c) = 0x74;
33: *(undefined8 *)(param_1 + 0x610) = 0x55596d6f72467373;
34: s_No_error_003a6000._0_8_ = 0x6572706d6f436a74;
35: *(undefined8 *)(param_1 + 0x618) = 0x766e49203a292856;
36: ram0x003a6008 = 0x55596d6f72467373;
37: *(undefined8 *)(param_1 + 0x620) = 0x6772612064696c61;
38: *(undefined4 *)(param_1 + 0x628) = 0x6e656d75;
39: *(undefined4 *)(param_1 + 0x6d0) = 1;
40: _DAT_003a6010 = 0x766e49203a292856;
41: _DAT_003a6018 = 0x6772612064696c61;
42: _DAT_003a6020 = 0x6e656d75;
43: _DAT_003a6024 = 0x74;
44: return 0xffffffff;
45: }
46: iVar1 = tjPlaneWidth(0,param_3,param_6);
47: iVar2 = tjPlaneHeight(0,param_5,param_6);
48: uStack104 = iVar1 + -1 + param_4 & -param_4;
49: lStack88 = param_2;
50: if (param_6 == 3) {
51: uStack96 = 0;
52: lStack72 = 0;
53: lStack80 = 0;
54: }
55: else {
56: iVar1 = tjPlaneWidth(1,param_3,param_6);
57: iVar3 = tjPlaneHeight(1,param_5,param_6);
58: uStack96 = iVar1 + -1 + param_4 & -param_4;
59: lStack80 = (int)(iVar2 * uStack104) + lStack88;
60: lStack72 = lStack80 + (int)(iVar3 * uStack96);
61: }
62: uStack100 = uStack96;
63: uVar4 = tjCompressFromYUVPlanes
64: (param_1,&lStack88,param_3,&uStack104,param_5,param_6,param_7,param_8,param_9,
65: param_10);
66: }
67: return uVar4;
68: }
69: 

1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjDecodeYUV(long param_1,long param_2,uint param_3,uint param_4,undefined8 param_5,int param_6,
6: undefined4 param_7,int param_8,undefined4 param_9,undefined4 param_10)
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
21: s_No_error_003a6000._0_8_ = 0x65646f6365446a74;
22: ram0x003a6008 = 0x49203a2928565559;
23: _DAT_003a6010 = 0x682064696c61766e;
24: _DAT_003a6018 = _DAT_003a6018 & 0xffff000000000000 | 0x656c646e61;
25: uVar4 = 0xffffffff;
26: }
27: else {
28: *(undefined4 *)(param_1 + 0x6d0) = 0;
29: if ((((param_2 == 0) || ((int)param_3 < 0)) || ((param_3 - 1 & param_3) != 0)) ||
30: (((5 < param_4 || (param_6 < 1)) || (param_8 < 1)))) {
31: *(undefined4 *)(param_1 + 0x6d0) = 1;
32: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
33: s_No_error_003a6000._0_8_ = 0x65646f6365446a74;
34: *(undefined8 *)(param_1 + 0x610) = 0x49203a2928565559;
35: *(undefined8 *)(param_1 + 0x618) = 0x612064696c61766e;
36: ram0x003a6008 = 0x49203a2928565559;
37: *(undefined8 *)(param_1 + 0x620) = 0x746e656d756772;
38: _DAT_003a6010 = 0x612064696c61766e;
39: _DAT_003a6018 = 0x746e656d756772;
40: return 0xffffffff;
41: }
42: iVar1 = tjPlaneWidth(0,param_6,param_4);
43: iVar2 = tjPlaneHeight(0,param_8,param_4);
44: uStack104 = iVar1 + -1 + param_3 & -param_3;
45: lStack88 = param_2;
46: if (param_4 == 3) {
47: uStack96 = 0;
48: lStack72 = 0;
49: lStack80 = 0;
50: }
51: else {
52: iVar1 = tjPlaneWidth(1,param_6,param_4);
53: iVar3 = tjPlaneHeight(1,param_8,param_4);
54: uStack96 = iVar1 + -1 + param_3 & -param_3;
55: lStack80 = (int)(iVar2 * uStack104) + lStack88;
56: lStack72 = lStack80 + (int)(iVar3 * uStack96);
57: }
58: uStack100 = uStack96;
59: uVar4 = tjDecodeYUVPlanes(param_1,&lStack88,&uStack104,param_4,param_5,param_6,param_7,param_8,
60: param_9,param_10);
61: }
62: return uVar4;
63: }
64: 

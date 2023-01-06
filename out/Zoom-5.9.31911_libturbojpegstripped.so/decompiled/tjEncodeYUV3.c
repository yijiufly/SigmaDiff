1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjEncodeYUV3(long param_1,undefined8 param_2,int param_3,undefined4 param_4,int param_5,
6: undefined4 param_6,long param_7,uint param_8,uint param_9,undefined4 param_10)
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
21: s_No_error_003a6000._0_8_ = 0x65646f636e456a74;
22: ram0x003a6008 = 0x203a292833565559;
23: _DAT_003a6010 = 0x2064696c61766e49;
24: _DAT_003a6018 = _DAT_003a6018 & 0xff00000000000000 | 0x656c646e6168;
25: uVar4 = 0xffffffff;
26: }
27: else {
28: *(undefined4 *)(param_1 + 0x6d0) = 0;
29: if ((((param_3 < 1) || (param_5 < 1)) || (param_7 == 0)) ||
30: ((((int)param_8 < 0 || ((param_8 - 1 & param_8) != 0)) || (5 < param_9)))) {
31: *(undefined8 *)(param_1 + 0x608) = 0x65646f636e456a74;
32: *(undefined8 *)(param_1 + 0x610) = 0x203a292833565559;
33: s_No_error_003a6000._0_8_ = 0x65646f636e456a74;
34: *(undefined8 *)(param_1 + 0x618) = 0x2064696c61766e49;
35: *(undefined8 *)(param_1 + 0x620) = 0x746e656d75677261;
36: *(undefined *)(param_1 + 0x628) = 0;
37: *(undefined4 *)(param_1 + 0x6d0) = 1;
38: ram0x003a6008 = 0x203a292833565559;
39: _DAT_003a6010 = 0x2064696c61766e49;
40: _DAT_003a6018 = 0x746e656d75677261;
41: DAT_003a6020 = 0;
42: return 0xffffffff;
43: }
44: iVar1 = tjPlaneWidth(0,param_3,param_9);
45: iVar2 = tjPlaneHeight(0,param_5,param_9);
46: lStack88 = param_7;
47: uStack104 = iVar1 + -1 + param_8 & -param_8;
48: if (param_9 == 3) {
49: uStack96 = 0;
50: lStack72 = 0;
51: lStack80 = 0;
52: }
53: else {
54: iVar1 = tjPlaneWidth(1,param_3,param_9);
55: iVar3 = tjPlaneHeight(1,param_5,param_9);
56: uStack96 = iVar1 + -1 + param_8 & -param_8;
57: lStack80 = (int)(iVar2 * uStack104) + lStack88;
58: lStack72 = lStack80 + (int)(iVar3 * uStack96);
59: }
60: uStack100 = uStack96;
61: uVar4 = tjEncodeYUVPlanes(param_1,param_2,param_3,param_4,param_5,param_6,&lStack88,&uStack104,
62: param_9,param_10);
63: }
64: return uVar4;
65: }
66: 

1: 
2: undefined8
3: tjCompressFromYUV(long param_1,long param_2,int param_3,int param_4,int param_5,uint param_6,
4: undefined8 param_7,undefined8 param_8,undefined4 param_9,undefined4 param_10)
5: 
6: {
7: int iVar1;
8: int iVar2;
9: int iVar3;
10: undefined8 uVar4;
11: undefined4 *puVar5;
12: uint uVar6;
13: long in_FS_OFFSET;
14: uint uStack100;
15: undefined8 uStack96;
16: long lStack88;
17: long lStack80;
18: long lStack72;
19: long lStack64;
20: 
21: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
22: if (param_1 == 0) {
23: puVar5 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
24: puVar5[8] = 0x656c64;
25: *puVar5 = 0x6f436a74;
26: puVar5[1] = 0x6572706d;
27: puVar5[2] = 0x72467373;
28: puVar5[3] = 0x55596d6f;
29: puVar5[4] = 0x3a292856;
30: puVar5[5] = 0x766e4920;
31: puVar5[6] = 0x64696c61;
32: puVar5[7] = 0x6e616820;
33: uVar4 = 0xffffffff;
34: }
35: else {
36: *(undefined4 *)(param_1 + 0x6d0) = 0;
37: if ((((param_2 == 0) || (param_3 < 1)) || (param_4 < 1)) || ((param_5 < 1 || (5 < param_6)))) {
38: *(undefined4 *)(param_1 + 0x628) = 0x6e656d75;
39: *(undefined2 *)(param_1 + 0x62c) = 0x74;
40: *(undefined4 *)(param_1 + 0x6d0) = 1;
41: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
42: *(undefined8 *)(param_1 + 0x610) = 0x55596d6f72467373;
43: *(undefined8 *)(param_1 + 0x618) = 0x766e49203a292856;
44: *(undefined8 *)(param_1 + 0x620) = 0x6772612064696c61;
45: puVar5 = (undefined4 *)__tls_get_addr(0x766e49203a292856,0x6572706d6f436a74,&PTR_00398fc0);
46: puVar5[8] = 0x6e656d75;
47: *(undefined2 *)(puVar5 + 9) = 0x74;
48: *puVar5 = 0x6f436a74;
49: puVar5[1] = 0x6572706d;
50: puVar5[2] = 0x72467373;
51: puVar5[3] = 0x55596d6f;
52: puVar5[4] = 0x3a292856;
53: puVar5[5] = 0x766e4920;
54: puVar5[6] = 0x64696c61;
55: puVar5[7] = 0x67726120;
56: uVar4 = 0xffffffff;
57: }
58: else {
59: iVar1 = tjPlaneWidth(0,param_3,param_6);
60: iVar2 = tjPlaneHeight(0,param_5,param_6);
61: uStack100 = iVar1 + -1 + param_4 & -param_4;
62: lStack88 = param_2;
63: if (param_6 == 3) {
64: uStack96 = 0;
65: lStack72 = 0;
66: lStack80 = 0;
67: }
68: else {
69: iVar1 = tjPlaneWidth(1,param_3,param_6);
70: iVar3 = tjPlaneHeight(1,param_5,param_6);
71: uVar6 = iVar1 + -1 + param_4 & -param_4;
72: uStack96 = CONCAT44(uVar6,uVar6);
73: lStack80 = (int)(iVar2 * uStack100) + lStack88;
74: lStack72 = lStack80 + (int)(uVar6 * iVar3);
75: }
76: uVar4 = tjCompressFromYUVPlanes
77: (param_1,&lStack88,param_3,&uStack100,param_5,param_6,param_7,param_8,
78: param_9,param_10);
79: }
80: }
81: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
82: return uVar4;
83: }
84: /* WARNING: Subroutine does not return */
85: __stack_chk_fail();
86: }
87: 

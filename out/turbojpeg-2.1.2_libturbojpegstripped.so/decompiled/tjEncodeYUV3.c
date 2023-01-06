1: 
2: undefined8
3: tjEncodeYUV3(long param_1,undefined8 param_2,int param_3,undefined4 param_4,int param_5,
4: undefined4 param_6,long param_7,uint param_8,uint param_9,undefined4 param_10)
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
24: *(undefined8 *)(puVar5 + 4) = 0x2064696c61766e49;
25: puVar5[6] = 0x646e6168;
26: *puVar5 = 0x6e456a74;
27: puVar5[1] = 0x65646f63;
28: puVar5[2] = 0x33565559;
29: puVar5[3] = 0x203a2928;
30: *(undefined2 *)(puVar5 + 7) = 0x656c;
31: *(undefined *)((long)puVar5 + 0x1e) = 0;
32: uVar4 = 0xffffffff;
33: }
34: else {
35: *(undefined4 *)(param_1 + 0x6d0) = 0;
36: if ((((param_3 < 1) || (param_5 < 1)) || (param_7 == 0)) ||
37: ((((int)param_8 < 0 || ((param_8 - 1 & param_8) != 0)) || (5 < param_9)))) {
38: *(undefined *)(param_1 + 0x628) = 0;
39: *(undefined4 *)(param_1 + 0x6d0) = 1;
40: *(undefined8 *)(param_1 + 0x608) = 0x65646f636e456a74;
41: *(undefined8 *)(param_1 + 0x610) = 0x203a292833565559;
42: *(undefined8 *)(param_1 + 0x618) = 0x2064696c61766e49;
43: *(undefined8 *)(param_1 + 0x620) = 0x746e656d75677261;
44: puVar5 = (undefined4 *)__tls_get_addr(0x2064696c61766e49,0x65646f636e456a74,&PTR_00398fc0);
45: *(undefined *)(puVar5 + 8) = 0;
46: *puVar5 = 0x6e456a74;
47: puVar5[1] = 0x65646f63;
48: puVar5[2] = 0x33565559;
49: puVar5[3] = 0x203a2928;
50: puVar5[4] = 0x61766e49;
51: puVar5[5] = 0x2064696c;
52: puVar5[6] = 0x75677261;
53: puVar5[7] = 0x746e656d;
54: uVar4 = 0xffffffff;
55: }
56: else {
57: iVar1 = tjPlaneWidth(0,param_3,param_9);
58: iVar2 = tjPlaneHeight(0,param_5,param_9);
59: lStack88 = param_7;
60: uStack100 = iVar1 + -1 + param_8 & -param_8;
61: if (param_9 == 3) {
62: uStack96 = 0;
63: lStack72 = 0;
64: lStack80 = 0;
65: }
66: else {
67: iVar1 = tjPlaneWidth(1,param_3,param_9);
68: iVar3 = tjPlaneHeight(1,param_5,param_9);
69: uVar6 = -param_8 & iVar1 + -1 + param_8;
70: uStack96 = CONCAT44(uVar6,uVar6);
71: lStack80 = (int)(iVar2 * uStack100) + lStack88;
72: lStack72 = lStack80 + (int)(uVar6 * iVar3);
73: }
74: uVar4 = tjEncodeYUVPlanes(param_1,param_2,param_3,param_4,param_5,param_6,&lStack88,&uStack100
75: ,param_9,param_10);
76: }
77: }
78: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
79: return uVar4;
80: }
81: /* WARNING: Subroutine does not return */
82: __stack_chk_fail();
83: }
84: 

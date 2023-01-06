1: 
2: undefined8
3: tjDecodeYUV(long param_1,long param_2,uint param_3,uint param_4,undefined8 param_5,int param_6,
4: undefined4 param_7,int param_8,undefined4 param_9,undefined4 param_10)
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
24: *(undefined8 *)(puVar5 + 4) = 0x682064696c61766e;
25: puVar5[6] = 0x6c646e61;
26: *puVar5 = 0x65446a74;
27: puVar5[1] = 0x65646f63;
28: puVar5[2] = 0x28565559;
29: puVar5[3] = 0x49203a29;
30: *(undefined2 *)(puVar5 + 7) = 0x65;
31: uVar4 = 0xffffffff;
32: }
33: else {
34: *(undefined4 *)(param_1 + 0x6d0) = 0;
35: if (param_2 != 0) {
36: if ((-1 < (int)param_3) && ((param_3 - 1 & param_3) == 0)) {
37: if ((param_4 < 6 && 0 < param_6) && (0 < param_8)) {
38: iVar1 = tjPlaneWidth(0,param_6,param_4);
39: iVar2 = tjPlaneHeight(0,param_8,param_4);
40: uStack100 = iVar1 + -1 + param_3 & -param_3;
41: lStack88 = param_2;
42: if (param_4 == 3) {
43: uStack96 = 0;
44: lStack72 = 0;
45: lStack80 = 0;
46: }
47: else {
48: iVar1 = tjPlaneWidth(1,param_6,param_4);
49: iVar3 = tjPlaneHeight(1,param_8,param_4);
50: uVar6 = iVar1 + -1 + param_3 & -param_3;
51: uStack96 = CONCAT44(uVar6,uVar6);
52: lStack80 = (int)(iVar2 * uStack100) + lStack88;
53: lStack72 = lStack80 + (int)(uVar6 * iVar3);
54: }
55: uVar4 = tjDecodeYUVPlanes(param_1,&lStack88,&uStack100,param_4,param_5,param_6,param_7,
56: param_8,param_9,param_10);
57: goto LAB_001555c6;
58: }
59: }
60: }
61: *(undefined4 *)(param_1 + 0x6d0) = 1;
62: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
63: *(undefined8 *)(param_1 + 0x610) = 0x49203a2928565559;
64: *(undefined8 *)(param_1 + 0x618) = 0x612064696c61766e;
65: *(undefined8 *)(param_1 + 0x620) = 0x746e656d756772;
66: puVar5 = (undefined4 *)__tls_get_addr(0x612064696c61766e,0x65646f6365446a74,&PTR_00398fc0);
67: *puVar5 = 0x65446a74;
68: puVar5[1] = 0x65646f63;
69: puVar5[2] = 0x28565559;
70: puVar5[3] = 0x49203a29;
71: puVar5[4] = 0x6c61766e;
72: puVar5[5] = 0x61206469;
73: puVar5[6] = 0x6d756772;
74: puVar5[7] = 0x746e65;
75: uVar4 = 0xffffffff;
76: }
77: LAB_001555c6:
78: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
79: return uVar4;
80: }
81: /* WARNING: Subroutine does not return */
82: __stack_chk_fail();
83: }
84: 

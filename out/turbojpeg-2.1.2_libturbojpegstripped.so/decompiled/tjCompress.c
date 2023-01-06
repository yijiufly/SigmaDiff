1: 
2: void tjCompress(undefined8 param_1,undefined8 param_2,undefined4 param_3,ulong param_4,ulong param_5
3: ,uint param_6,undefined8 param_7,undefined8 *param_8,undefined4 param_9,
4: undefined4 param_10,uint param_11)
5: 
6: {
7: long lVar1;
8: uint uVar2;
9: long in_FS_OFFSET;
10: undefined8 uVar3;
11: undefined8 uStack80;
12: undefined8 uStack72;
13: long lStack64;
14: 
15: uStack80 = param_7;
16: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
17: if ((param_11 & 0x200) == 0) {
18: if (param_6 == 1) {
19: uVar2 = 6;
20: }
21: else {
22: if (param_6 == 3) {
23: uVar2 = param_11 & 1;
24: }
25: else {
26: if (param_6 == 4) {
27: if ((param_11 & 0x40) == 0) {
28: uVar2 = (param_11 & 1) + 2;
29: }
30: else {
31: uVar2 = 4;
32: if ((param_11 & 1) == 0) {
33: uVar2 = 5;
34: }
35: }
36: }
37: else {
38: uVar2 = 0xffffffff;
39: }
40: }
41: }
42: tjCompress2(param_1,param_2,param_3,param_4,param_5,uVar2,&uStack80,&uStack72,param_9,param_10,
43: param_11 | 0x400);
44: }
45: else {
46: uVar3 = 0x15166b;
47: uStack72 = tjBufSizeYUV(param_3,param_5 & 0xffffffff,param_9);
48: if (param_6 == 1) {
49: param_6 = 6;
50: }
51: else {
52: if (param_6 == 3) {
53: param_6 = param_11 & 1;
54: }
55: else {
56: if (param_6 == 4) {
57: if ((param_11 & 0x40) == 0) {
58: param_6 = (param_11 & 1) + 2;
59: }
60: else {
61: if ((param_11 & 1) == 0) {
62: param_6 = 5;
63: }
64: }
65: }
66: else {
67: param_6 = 0xffffffff;
68: }
69: }
70: }
71: tjEncodeYUV2(param_1,param_2,param_3,param_4 & 0xffffffff,param_5 & 0xffffffff,param_6,uStack80,
72: param_9,param_11,uVar3);
73: }
74: lVar1 = *(long *)(in_FS_OFFSET + 0x28);
75: *param_8 = uStack72;
76: if (lStack64 != lVar1) {
77: /* WARNING: Subroutine does not return */
78: __stack_chk_fail();
79: }
80: return;
81: }
82: 

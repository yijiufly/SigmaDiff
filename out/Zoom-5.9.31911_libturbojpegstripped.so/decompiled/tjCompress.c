1: 
2: void tjCompress(undefined8 param_1,undefined8 param_2,undefined4 param_3,ulong param_4,ulong param_5
3: ,int param_6,undefined8 param_7,undefined8 *param_8,undefined4 param_9,
4: undefined4 param_10,uint param_11)
5: 
6: {
7: undefined4 uVar1;
8: uint uVar2;
9: uint uVar3;
10: undefined8 in_stack_ffffffffffffff90;
11: undefined4 uVar4;
12: undefined8 auStack72 [3];
13: 
14: uVar2 = param_11;
15: uVar1 = param_9;
16: uVar4 = (undefined4)((ulong)in_stack_ffffffffffffff90 >> 0x20);
17: if ((param_11 & 0x200) == 0) {
18: uVar2 = 6;
19: if (param_6 != 1) {
20: if (param_6 == 3) {
21: uVar2 = param_11 & 1;
22: }
23: else {
24: uVar2 = 0xffffffff;
25: if (param_6 == 4) {
26: if ((param_11 & 0x40) == 0) {
27: uVar2 = 3 - ((param_11 & 1) == 0);
28: }
29: else {
30: uVar2 = 5 - (param_11 & 1);
31: }
32: }
33: }
34: }
35: tjCompress2(param_1,param_2,param_3,param_4,param_5,uVar2,&param_7,auStack72,param_9,param_10,
36: param_11 | 0x400);
37: }
38: else {
39: auStack72[0] = tjBufSizeYUV(param_3,param_5 & 0xffffffff,param_9);
40: uVar3 = 6;
41: if (((param_6 != 1) && (uVar3 = uVar2 & 1, param_6 != 3)) && (uVar3 = 0xffffffff, param_6 == 4))
42: {
43: if ((uVar2 & 0x40) == 0) {
44: uVar3 = 3 - ((uVar2 & 1) == 0);
45: }
46: else {
47: uVar3 = 5 - (uVar2 & 1);
48: }
49: }
50: tjEncodeYUV2(param_1,param_2,param_3,param_4 & 0xffffffff,param_5 & 0xffffffff,uVar3,param_7,
51: CONCAT44(uVar4,uVar1),uVar2);
52: }
53: *param_8 = auStack72[0];
54: return;
55: }
56: 

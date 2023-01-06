1: 
2: void FUN_0012bcb0(code **param_1,int param_2,uint param_3)
3: 
4: {
5: code *pcVar1;
6: code *pcVar2;
7: 
8: pcVar1 = param_1[0x49];
9: if (*(long *)(param_1[1] + 0x60) + -0x20 < (long)(ulong)param_3) {
10: param_3 = (uint)(*(long *)(param_1[1] + 0x60) + -0x20);
11: }
12: if (param_3 == 0) {
13: if ((param_2 == 0xee) || (pcVar2 = FUN_00129a10, param_2 == 0xe0)) {
14: pcVar2 = FUN_0012b740;
15: }
16: joined_r0x0012bd25:
17: if (param_2 == 0xfe) {
18: *(code **)(pcVar1 + 0x28) = pcVar2;
19: *(uint *)(pcVar1 + 0xb0) = param_3;
20: return;
21: }
22: }
23: else {
24: if ((param_3 < 0xe) && (param_2 == 0xe0)) {
25: param_3 = 0xe;
26: }
27: else {
28: if ((0xb < param_3) || (param_2 != 0xee)) {
29: pcVar2 = FUN_0012b340;
30: goto joined_r0x0012bd25;
31: }
32: param_3 = 0xc;
33: }
34: pcVar2 = FUN_0012b340;
35: }
36: if (0xf < param_2 - 0xe0U) {
37: pcVar1 = *param_1;
38: *(undefined4 *)(pcVar1 + 0x28) = 0x44;
39: *(int *)(pcVar1 + 0x2c) = param_2;
40: /* WARNING: Could not recover jumptable at 0x0012bd96. Too many branches */
41: /* WARNING: Treating indirect jump as call */
42: (**(code **)*param_1)();
43: return;
44: }
45: *(code **)(pcVar1 + (long)(param_2 + -0xe0) * 8 + 0x30) = pcVar2;
46: *(uint *)(pcVar1 + (long)(param_2 + -0xe0) * 4 + 0xb4) = param_3;
47: return;
48: }
49: 

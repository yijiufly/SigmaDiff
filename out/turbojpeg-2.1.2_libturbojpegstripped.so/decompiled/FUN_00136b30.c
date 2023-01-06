1: 
2: void FUN_00136b30(code **param_1,int param_2,uint param_3)
3: 
4: {
5: code *pcVar1;
6: uint uVar2;
7: code *pcVar3;
8: 
9: pcVar1 = param_1[0x49];
10: if (*(long *)(param_1[1] + 0x60) + -0x20 < (long)(ulong)param_3) {
11: param_3 = (uint)(*(long *)(param_1[1] + 0x60) + -0x20);
12: }
13: if (param_3 == 0) {
14: if ((param_2 == 0xee) || (pcVar3 = FUN_00134990, param_2 == 0xe0)) {
15: pcVar3 = FUN_00136200;
16: }
17: }
18: else {
19: pcVar3 = FUN_00136510;
20: if ((param_3 < 0xe) && (param_2 == 0xe0)) {
21: param_3 = 0xe;
22: goto LAB_00136b6d;
23: }
24: if ((param_2 == 0xee) && (param_3 < 0xc)) {
25: param_3 = 0xc;
26: goto LAB_00136b6d;
27: }
28: }
29: if (param_2 == 0xfe) {
30: *(code **)(pcVar1 + 0x28) = pcVar3;
31: *(uint *)(pcVar1 + 0xb0) = param_3;
32: return;
33: }
34: LAB_00136b6d:
35: uVar2 = param_2 - 0xe0;
36: if (0xf < uVar2) {
37: param_1 = (code **)*param_1;
38: *(undefined4 *)(param_1 + 5) = 0x44;
39: *(int *)((long)param_1 + 0x2c) = param_2;
40: /* WARNING: Could not recover jumptable at 0x00136b85. Too many branches */
41: /* WARNING: Treating indirect jump as call */
42: (**param_1)();
43: return;
44: }
45: *(code **)(pcVar1 + (long)(int)uVar2 * 8 + 0x30) = pcVar3;
46: *(uint *)(pcVar1 + (long)(int)uVar2 * 4 + 0xb4) = param_3;
47: return;
48: }
49: 

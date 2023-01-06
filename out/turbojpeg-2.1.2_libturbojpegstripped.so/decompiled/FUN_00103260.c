1: 
2: void FUN_00103260(code **param_1,int param_2)
3: 
4: {
5: undefined4 uVar1;
6: int iVar2;
7: code *pcVar3;
8: 
9: iVar2 = *(int *)((long)param_1 + 0x144);
10: pcVar3 = param_1[0x39];
11: *(undefined4 *)(pcVar3 + 0x10) = 0;
12: if (iVar2 < 2) {
13: if (*(int *)(param_1 + 0x28) != 1) {
14: uVar1 = *(undefined4 *)(param_1[0x29] + 0xc);
15: *(undefined8 *)(pcVar3 + 0x14) = 0;
16: *(undefined4 *)(pcVar3 + 0x1c) = uVar1;
17: goto joined_r0x001032f1;
18: }
19: *(undefined4 *)(pcVar3 + 0x1c) = *(undefined4 *)(param_1[0x29] + 0x48);
20: }
21: else {
22: *(undefined4 *)(pcVar3 + 0x1c) = 1;
23: }
24: *(undefined8 *)(pcVar3 + 0x14) = 0;
25: joined_r0x001032f1:
26: if (param_2 == 2) {
27: if (*(long *)(pcVar3 + 0x70) == 0) {
28: param_1 = (code **)*param_1;
29: *(undefined4 *)(param_1 + 5) = 4;
30: (**param_1)();
31: }
32: *(code **)(pcVar3 + 8) = FUN_00103350;
33: return;
34: }
35: if (param_2 != 3) {
36: if (param_2 == 0) {
37: if (*(long *)(pcVar3 + 0x70) != 0) {
38: param_1 = (code **)*param_1;
39: *(undefined4 *)(param_1 + 5) = 4;
40: (**param_1)();
41: }
42: *(code **)(pcVar3 + 8) = FUN_00103b30;
43: return;
44: }
45: param_1 = (code **)*param_1;
46: *(undefined4 *)(param_1 + 5) = 4;
47: /* WARNING: Could not recover jumptable at 0x001032a7. Too many branches */
48: /* WARNING: Treating indirect jump as call */
49: (**param_1)();
50: return;
51: }
52: if (*(long *)(pcVar3 + 0x70) == 0) {
53: param_1 = (code **)*param_1;
54: *(undefined4 *)(param_1 + 5) = 4;
55: (**param_1)();
56: }
57: *(code **)(pcVar3 + 8) = FUN_00103830;
58: return;
59: }
60: 

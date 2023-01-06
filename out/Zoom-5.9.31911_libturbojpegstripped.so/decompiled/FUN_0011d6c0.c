1: 
2: undefined8 FUN_0011d6c0(code **param_1)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: uint uVar4;
9: undefined8 uVar5;
10: 
11: iVar1 = *(int *)((long)param_1 + 0x24);
12: if (iVar1 == 0xca) {
13: FUN_0012c8f0();
14: if (*(int *)(param_1 + 0xb) != 0) {
15: *(undefined4 *)((long)param_1 + 0x24) = 0xcf;
16: return 1;
17: }
18: *(undefined4 *)((long)param_1 + 0x24) = 0xcb;
19: }
20: else {
21: if (iVar1 != 0xcb) {
22: if (iVar1 != 0xcc) {
23: pcVar2 = *param_1;
24: *(int *)(pcVar2 + 0x2c) = iVar1;
25: ppcVar3 = (code **)*param_1;
26: *(undefined4 *)(pcVar2 + 0x28) = 0x14;
27: (**ppcVar3)();
28: }
29: uVar5 = FUN_0011d5b0(param_1);
30: return uVar5;
31: }
32: }
33: if (*(int *)(param_1[0x48] + 0x20) != 0) {
34: ppcVar3 = (code **)param_1[2];
35: do {
36: if (ppcVar3 != (code **)0x0) {
37: (**ppcVar3)(param_1);
38: }
39: do {
40: uVar4 = (**(code **)param_1[0x48])(param_1);
41: if (uVar4 == 0) {
42: return 0;
43: }
44: if (uVar4 == 2) goto LAB_0011d790;
45: ppcVar3 = (code **)param_1[2];
46: } while (ppcVar3 == (code **)0x0);
47: if ((uVar4 & 0xfffffffd) == 1) {
48: pcVar2 = ppcVar3[1];
49: ppcVar3[1] = pcVar2 + 1;
50: if ((long)ppcVar3[2] <= (long)(pcVar2 + 1)) {
51: ppcVar3[2] = ppcVar3[2] + *(uint *)((long)param_1 + 0x1a4);
52: }
53: }
54: } while( true );
55: }
56: LAB_0011d790:
57: *(undefined4 *)((long)param_1 + 0xb4) = *(undefined4 *)((long)param_1 + 0xac);
58: uVar5 = FUN_0011d5b0(param_1);
59: return uVar5;
60: }
61: 

1: 
2: void FUN_001124c0(code **param_1,undefined *param_2,uint param_3)
3: 
4: {
5: undefined *puVar1;
6: undefined uVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: uint uVar5;
10: uint uVar6;
11: int iVar7;
12: undefined *puVar8;
13: bool bVar9;
14: 
15: if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
16: ppcVar4 = (code **)*param_1;
17: *(undefined4 *)(ppcVar4 + 5) = 0x17;
18: (**ppcVar4)(param_1);
19: iVar7 = *(int *)((long)param_1 + 0x24);
20: }
21: else {
22: iVar7 = *(int *)((long)param_1 + 0x24);
23: }
24: if (iVar7 < 0x65) {
25: pcVar3 = *param_1;
26: *(int *)(pcVar3 + 0x2c) = iVar7;
27: ppcVar4 = (code **)*param_1;
28: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
29: (**ppcVar4)(param_1);
30: }
31: iVar7 = 1;
32: uVar5 = param_3 / 0xffef;
33: bVar9 = uVar5 * 0xffef != param_3;
34: if (param_3 != 0) {
35: do {
36: uVar6 = 0xffef;
37: if (param_3 < 0xfff0) {
38: uVar6 = param_3;
39: }
40: param_3 = param_3 - uVar6;
41: FUN_001030e0(param_1,0xe2,uVar6 + 0xe);
42: FUN_00103140(param_1,0x49);
43: FUN_00103140(param_1,0x43);
44: FUN_00103140(param_1,0x43);
45: FUN_00103140(param_1,0x5f);
46: FUN_00103140(param_1,0x50);
47: FUN_00103140(param_1,0x52);
48: FUN_00103140(param_1,0x4f);
49: FUN_00103140(param_1,0x46);
50: FUN_00103140(param_1,0x49);
51: FUN_00103140(param_1,0x4c);
52: FUN_00103140(param_1,0x45);
53: FUN_00103140(param_1,0);
54: FUN_00103140(param_1,iVar7);
55: FUN_00103140(param_1,uVar5 + bVar9);
56: if (uVar6 != 0) {
57: puVar1 = param_2 + (ulong)(uVar6 - 1) + 1;
58: puVar8 = param_2;
59: do {
60: uVar2 = *puVar8;
61: puVar8 = puVar8 + 1;
62: FUN_00103140(param_1,uVar2);
63: param_2 = puVar1;
64: } while (puVar8 != puVar1);
65: }
66: iVar7 = iVar7 + 1;
67: } while (param_3 != 0);
68: }
69: return;
70: }
71: 

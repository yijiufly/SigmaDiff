1: 
2: void FUN_0011be70(code **param_1,undefined *param_2,uint param_3)
3: 
4: {
5: undefined *puVar1;
6: undefined uVar2;
7: code **ppcVar3;
8: uint uVar4;
9: uint uVar5;
10: int iVar6;
11: bool bVar7;
12: 
13: if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
14: ppcVar3 = (code **)*param_1;
15: *(undefined4 *)(ppcVar3 + 5) = 0x17;
16: (**ppcVar3)(param_1);
17: }
18: iVar6 = *(int *)((long)param_1 + 0x24);
19: if (iVar6 < 0x65) {
20: ppcVar3 = (code **)*param_1;
21: *(undefined4 *)(ppcVar3 + 5) = 0x14;
22: *(int *)((long)ppcVar3 + 0x2c) = iVar6;
23: (**ppcVar3)(param_1);
24: }
25: iVar6 = 1;
26: uVar4 = param_3 / 0xffef;
27: bVar7 = uVar4 * 0xffef != param_3;
28: if (param_3 != 0) {
29: do {
30: uVar5 = 0xffef;
31: if (param_3 < 0xfff0) {
32: uVar5 = param_3;
33: }
34: param_3 = param_3 - uVar5;
35: FUN_00102f30(param_1,0xe2,uVar5 + 0xe);
36: FUN_00102f90(param_1,0x49);
37: FUN_00102f90(param_1,0x43);
38: FUN_00102f90(param_1,0x43);
39: FUN_00102f90(param_1,0x5f);
40: FUN_00102f90(param_1,0x50);
41: FUN_00102f90(param_1,0x52);
42: FUN_00102f90(param_1,0x4f);
43: FUN_00102f90(param_1,0x46);
44: FUN_00102f90(param_1,0x49);
45: FUN_00102f90(param_1,0x4c);
46: FUN_00102f90(param_1,0x45);
47: FUN_00102f90(param_1,0);
48: FUN_00102f90(param_1,iVar6);
49: FUN_00102f90(param_1,uVar4 + bVar7);
50: puVar1 = param_2 + (ulong)(uVar5 - 1) + 1;
51: do {
52: uVar2 = *param_2;
53: param_2 = param_2 + 1;
54: FUN_00102f90(param_1,uVar2);
55: } while (puVar1 != param_2);
56: iVar6 = iVar6 + 1;
57: } while (param_3 != 0);
58: }
59: return;
60: }
61: 

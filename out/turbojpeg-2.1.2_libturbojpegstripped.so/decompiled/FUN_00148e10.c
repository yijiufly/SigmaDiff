1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8 * FUN_00148e10(code **param_1,uint param_2,ulong param_3)
5: 
6: {
7: ulong uVar1;
8: undefined8 *puVar2;
9: code *pcVar3;
10: code **ppcVar4;
11: undefined8 uVar5;
12: undefined8 *puVar6;
13: ulong uVar7;
14: ulong uVar8;
15: 
16: pcVar3 = param_1[1];
17: if (1000000000 < param_3) {
18: ppcVar4 = (code **)*param_1;
19: ppcVar4[5] = (code *)0x800000036;
20: (**ppcVar4)();
21: }
22: uVar7 = param_3 + 0x1f & 0xffffffffffffffe0;
23: uVar1 = uVar7 + 0x37;
24: if (1000000000 < uVar1) {
25: ppcVar4 = (code **)*param_1;
26: ppcVar4[5] = (code *)0x300000036;
27: (**ppcVar4)(param_1);
28: }
29: if (1 < param_2) {
30: ppcVar4 = (code **)*param_1;
31: *(undefined4 *)(ppcVar4 + 5) = 0xe;
32: *(uint *)((long)ppcVar4 + 0x2c) = param_2;
33: (**ppcVar4)(param_1);
34: }
35: puVar6 = (undefined8 *)FUN_0014a5c0(param_1,uVar1);
36: puVar2 = puVar6 + 3;
37: uVar8 = (ulong)((uint)puVar2 & 0x1f);
38: if (puVar6 == (undefined8 *)0x0) {
39: ppcVar4 = (code **)*param_1;
40: ppcVar4[5] = (code *)0x400000036;
41: (**ppcVar4)(param_1);
42: *(ulong *)(pcVar3 + 0x98) = *(long *)(pcVar3 + 0x98) + uVar1;
43: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar3 + (long)(int)param_2 * 8 + 0x78);
44: _DAT_00000010 = 0;
45: _DAT_00000008 = uVar7;
46: *(undefined8 *)(pcVar3 + (long)(int)param_2 * 8 + 0x78) = 0;
47: }
48: else {
49: *(ulong *)(pcVar3 + 0x98) = *(long *)(pcVar3 + 0x98) + uVar1;
50: uVar5 = *(undefined8 *)(pcVar3 + (long)(int)param_2 * 8 + 0x78);
51: puVar6[1] = uVar7;
52: puVar6[2] = 0;
53: *puVar6 = uVar5;
54: *(undefined8 **)(pcVar3 + (long)(int)param_2 * 8 + 0x78) = puVar6;
55: if (uVar8 == 0) {
56: return puVar2;
57: }
58: }
59: return (undefined8 *)((long)puVar2 + (0x20 - uVar8));
60: }
61: 

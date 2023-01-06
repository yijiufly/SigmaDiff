1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8 * FUN_0013c290(code **param_1,uint param_2,ulong param_3)
5: 
6: {
7: code *pcVar1;
8: code *pcVar2;
9: undefined8 uVar3;
10: undefined8 *puVar4;
11: ulong uVar5;
12: 
13: pcVar1 = param_1[1];
14: if (1000000000 < param_3) {
15: pcVar2 = *param_1;
16: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
17: *(undefined4 *)(pcVar2 + 0x2c) = 8;
18: (**(code **)*param_1)();
19: }
20: uVar5 = param_3 + 0x1f & 0xffffffffffffffe0;
21: if (1000000000 < uVar5 + 0x37) {
22: pcVar2 = *param_1;
23: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
24: *(undefined4 *)(pcVar2 + 0x2c) = 3;
25: (**(code **)*param_1)(param_1);
26: }
27: if (1 < param_2) {
28: pcVar2 = *param_1;
29: *(undefined4 *)(pcVar2 + 0x28) = 0xe;
30: *(uint *)(pcVar2 + 0x2c) = param_2;
31: (**(code **)*param_1)(param_1);
32: }
33: puVar4 = (undefined8 *)FUN_0013d900(param_1,uVar5 + 0x37);
34: if (puVar4 == (undefined8 *)0x0) {
35: pcVar2 = *param_1;
36: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
37: *(undefined4 *)(pcVar2 + 0x2c) = 4;
38: (**(code **)*param_1)(param_1);
39: *(ulong *)(pcVar1 + 0x98) = uVar5 + 0x37 + *(long *)(pcVar1 + 0x98);
40: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
41: _DAT_00000010 = 0;
42: _DAT_00000008 = uVar5;
43: *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = 0;
44: uVar5 = 0x18;
45: puVar4 = (undefined8 *)0x18;
46: }
47: else {
48: *(ulong *)(pcVar1 + 0x98) = uVar5 + 0x37 + *(long *)(pcVar1 + 0x98);
49: uVar3 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
50: puVar4[1] = uVar5;
51: puVar4[2] = 0;
52: *puVar4 = uVar3;
53: *(undefined8 **)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = puVar4;
54: puVar4 = puVar4 + 3;
55: uVar5 = (ulong)((uint)puVar4 & 0x1f);
56: if (((ulong)puVar4 & 0x1f) == 0) {
57: return puVar4;
58: }
59: }
60: return (undefined8 *)((long)puVar4 + (0x20 - uVar5));
61: }
62: 

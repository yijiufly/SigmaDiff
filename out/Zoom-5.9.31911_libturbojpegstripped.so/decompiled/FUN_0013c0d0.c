1: 
2: void FUN_0013c0d0(code **param_1,uint param_2)
3: 
4: {
5: code *pcVar1;
6: code *pcVar2;
7: undefined8 *puVar3;
8: undefined8 *puVar4;
9: long lVar5;
10: 
11: pcVar1 = param_1[1];
12: if (param_2 < 2) {
13: if (param_2 == 1) {
14: lVar5 = *(long *)(pcVar1 + 0x88);
15: while (lVar5 != 0) {
16: while (*(int *)(lVar5 + 0x2c) == 0) {
17: lVar5 = *(long *)(lVar5 + 0x30);
18: if (lVar5 == 0) goto LAB_0013c1e3;
19: }
20: *(undefined4 *)(lVar5 + 0x2c) = 0;
21: (**(code **)(lVar5 + 0x48))(param_1,lVar5 + 0x38);
22: lVar5 = *(long *)(lVar5 + 0x30);
23: }
24: LAB_0013c1e3:
25: lVar5 = *(long *)(pcVar1 + 0x90);
26: *(undefined8 *)(pcVar1 + 0x88) = 0;
27: while (lVar5 != 0) {
28: while (*(int *)(lVar5 + 0x2c) == 0) {
29: lVar5 = *(long *)(lVar5 + 0x30);
30: if (lVar5 == 0) goto LAB_0013c233;
31: }
32: *(undefined4 *)(lVar5 + 0x2c) = 0;
33: (**(code **)(lVar5 + 0x48))(param_1,lVar5 + 0x38);
34: lVar5 = *(long *)(lVar5 + 0x30);
35: }
36: LAB_0013c233:
37: *(undefined8 *)(pcVar1 + 0x90) = 0;
38: }
39: }
40: else {
41: pcVar2 = *param_1;
42: *(undefined4 *)(pcVar2 + 0x28) = 0xe;
43: *(uint *)(pcVar2 + 0x2c) = param_2;
44: (**(code **)*param_1)();
45: }
46: pcVar2 = pcVar1 + (long)(int)param_2 * 8;
47: puVar3 = *(undefined8 **)(pcVar2 + 0x78);
48: *(undefined8 *)(pcVar2 + 0x78) = 0;
49: while (puVar3 != (undefined8 *)0x0) {
50: puVar4 = (undefined8 *)*puVar3;
51: lVar5 = puVar3[1] + puVar3[2] + 0x18;
52: FUN_0013d910(param_1,puVar3,lVar5);
53: *(long *)(pcVar1 + 0x98) = *(long *)(pcVar1 + 0x98) - lVar5;
54: puVar3 = puVar4;
55: }
56: puVar3 = *(undefined8 **)(pcVar2 + 0x68);
57: *(undefined8 *)(pcVar2 + 0x68) = 0;
58: while (puVar3 != (undefined8 *)0x0) {
59: puVar4 = (undefined8 *)*puVar3;
60: lVar5 = puVar3[1] + puVar3[2] + 0x18;
61: FUN_0013d8f0(param_1,puVar3,lVar5);
62: *(long *)(pcVar1 + 0x98) = *(long *)(pcVar1 + 0x98) - lVar5;
63: puVar3 = puVar4;
64: }
65: return;
66: }
67: 

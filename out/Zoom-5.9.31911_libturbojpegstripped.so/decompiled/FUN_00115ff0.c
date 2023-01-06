1: 
2: void FUN_00115ff0(code **param_1)
3: 
4: {
5: int *piVar1;
6: code *pcVar2;
7: code *pcVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: 
12: if (param_1[0x1f] != (code *)0x0) {
13: piVar1 = (int *)(param_1[0x1f] + (long)*(int *)(param_1[0x36] + 0x2c) * 0x24);
14: iVar6 = *piVar1;
15: *(int *)((long)param_1 + 0x144) = iVar6;
16: if (0 < iVar6) {
17: pcVar2 = param_1[0xb];
18: param_1[0x29] = pcVar2 + (long)piVar1[1] * 0x60;
19: if (((1 < iVar6) && (param_1[0x2a] = pcVar2 + (long)piVar1[2] * 0x60, 2 < iVar6)) &&
20: (param_1[0x2b] = pcVar2 + (long)piVar1[3] * 0x60, 3 < iVar6)) {
21: param_1[0x2c] = pcVar2 + (long)piVar1[4] * 0x60;
22: }
23: }
24: iVar6 = piVar1[6];
25: iVar4 = piVar1[7];
26: iVar5 = piVar1[8];
27: *(int *)((long)param_1 + 0x19c) = piVar1[5];
28: *(int *)(param_1 + 0x34) = iVar6;
29: *(int *)((long)param_1 + 0x1a4) = iVar4;
30: *(int *)(param_1 + 0x35) = iVar5;
31: return;
32: }
33: iVar6 = *(int *)((long)param_1 + 0x4c);
34: if (4 < iVar6) {
35: pcVar2 = *param_1;
36: *(int *)(pcVar2 + 0x2c) = iVar6;
37: pcVar3 = *param_1;
38: *(undefined4 *)(pcVar2 + 0x28) = 0x1a;
39: *(undefined4 *)(pcVar3 + 0x30) = 4;
40: (**(code **)*param_1)();
41: iVar6 = *(int *)((long)param_1 + 0x4c);
42: }
43: *(int *)((long)param_1 + 0x144) = iVar6;
44: if (0 < iVar6) {
45: pcVar2 = param_1[0xb];
46: param_1[0x29] = pcVar2;
47: if (((1 < iVar6) && (param_1[0x2a] = pcVar2 + 0x60, 2 < iVar6)) &&
48: (param_1[0x2b] = pcVar2 + 0xc0, 3 < iVar6)) {
49: param_1[0x2c] = pcVar2 + 0x120;
50: }
51: }
52: *(undefined4 *)((long)param_1 + 0x19c) = 0;
53: *(undefined4 *)(param_1 + 0x34) = 0x3f;
54: *(undefined4 *)((long)param_1 + 0x1a4) = 0;
55: *(undefined4 *)(param_1 + 0x35) = 0;
56: return;
57: }
58: 

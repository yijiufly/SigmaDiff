1: 
2: void FUN_001167a0(code **param_1,uint param_2,long param_3,int param_4,int param_5)
3: 
4: {
5: code **ppcVar1;
6: long lVar2;
7: code *pcVar3;
8: bool bVar4;
9: long lVar5;
10: undefined2 uVar6;
11: long lVar7;
12: 
13: if (*(int *)((long)param_1 + 0x24) != 100) {
14: pcVar3 = *param_1;
15: *(int *)(pcVar3 + 0x2c) = *(int *)((long)param_1 + 0x24);
16: ppcVar1 = (code **)*param_1;
17: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
18: (**ppcVar1)();
19: }
20: if (3 < param_2) {
21: pcVar3 = *param_1;
22: *(uint *)(pcVar3 + 0x2c) = param_2;
23: *(undefined4 *)(pcVar3 + 0x28) = 0x1f;
24: (**(code **)*param_1)();
25: }
26: pcVar3 = (param_1 + (int)param_2)[0xc];
27: if (pcVar3 == (code *)0x0) {
28: pcVar3 = (code *)FUN_00116760();
29: (param_1 + (int)param_2)[0xc] = pcVar3;
30: }
31: lVar5 = 0;
32: do {
33: lVar2 = (long)((ulong)*(uint *)(param_3 + lVar5 * 2) * (long)param_4 + 0x32) / 100;
34: lVar7 = 1;
35: if (lVar2 - 1U < 0x7fff) {
36: lVar7 = lVar2;
37: }
38: uVar6 = (undefined2)lVar7;
39: if (0x7fff < lVar2) {
40: uVar6 = 0x7fff;
41: }
42: bVar4 = lVar2 - 1U < 0x7fff && (0xff < lVar2 && param_5 != 0);
43: if (0x7fff < lVar2) {
44: bVar4 = param_5 != 0;
45: }
46: if (!(bool)(bVar4 ^ 1)) {
47: uVar6 = 0xff;
48: }
49: *(undefined2 *)(pcVar3 + lVar5) = uVar6;
50: lVar5 = lVar5 + 2;
51: } while (lVar5 != 0x80);
52: *(undefined4 *)(pcVar3 + 0x80) = 0;
53: return;
54: }
55: 

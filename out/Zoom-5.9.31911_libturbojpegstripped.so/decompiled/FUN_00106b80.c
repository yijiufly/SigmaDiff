1: 
2: void FUN_00106b80(long param_1,long param_2,long param_3,long param_4,uint param_5,int param_6,
3: int param_7)
4: 
5: {
6: code *pcVar1;
7: code *pcVar2;
8: undefined8 uVar3;
9: code *pcVar4;
10: undefined8 uVar5;
11: long lVar6;
12: long lVar7;
13: 
14: lVar6 = *(long *)(param_1 + 0x1e8);
15: pcVar1 = *(code **)(lVar6 + 0x10);
16: pcVar2 = *(code **)(lVar6 + 0x18);
17: uVar3 = *(undefined8 *)(lVar6 + 0x28 + (long)*(int *)(param_2 + 0x10) * 8);
18: pcVar4 = *(code **)(lVar6 + 0x20);
19: uVar5 = *(undefined8 *)(lVar6 + 0x48);
20: if (param_7 != 0) {
21: lVar6 = param_4;
22: do {
23: (*pcVar2)(param_3 + (ulong)param_5 * 8,param_6,uVar5);
24: (*pcVar1)(uVar5);
25: lVar7 = lVar6 + 0x80;
26: (*pcVar4)(lVar6,uVar3,uVar5);
27: lVar6 = lVar7;
28: param_6 = param_6 + 8;
29: } while (lVar7 != param_4 + 0x80 + (ulong)(param_7 - 1) * 0x80);
30: }
31: return;
32: }
33: 

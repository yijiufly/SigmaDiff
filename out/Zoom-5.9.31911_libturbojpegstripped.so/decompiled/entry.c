1: 
2: void entry(long *param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: byte bVar4;
9: byte bVar5;
10: long lVar6;
11: 
12: bVar2 = *(byte *)(param_2 + 7);
13: bVar3 = *(byte *)(param_2 + 8);
14: bVar4 = *(byte *)(param_2 + 10);
15: bVar1 = *(byte *)(param_2 + 0xb);
16: bVar5 = *(byte *)(param_2 + 9);
17: lVar6 = *param_1;
18: *(uint *)(lVar6 + 0x2c) = (uint)*(byte *)(param_2 + 5) * 0x100 + (uint)*(byte *)(param_2 + 6);
19: *(uint *)(lVar6 + 0x30) = (uint)bVar3 + (uint)bVar2 * 0x100;
20: *(uint *)(lVar6 + 0x38) = (uint)bVar1;
21: *(uint *)(lVar6 + 0x34) = (uint)bVar4 + (uint)bVar5 * 0x100;
22: *(undefined4 *)(lVar6 + 0x28) = 0x4c;
23: (**(code **)(lVar6 + 8))(param_1,1);
24: *(undefined4 *)(param_1 + 0x30) = 1;
25: *(byte *)((long)param_1 + 0x184) = bVar1;
26: return;
27: }
28: 

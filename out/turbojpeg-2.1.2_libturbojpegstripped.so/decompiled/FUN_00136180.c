1: 
2: void FUN_00136180(long *param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: byte bVar4;
9: byte bVar5;
10: long lVar6;
11: 
12: bVar1 = *(byte *)(param_2 + 7);
13: bVar2 = *(byte *)(param_2 + 8);
14: bVar3 = *(byte *)(param_2 + 0xb);
15: lVar6 = *param_1;
16: bVar4 = *(byte *)(param_2 + 5);
17: bVar5 = *(byte *)(param_2 + 6);
18: *(uint *)(lVar6 + 0x34) = (uint)*(byte *)(param_2 + 9) * 0x100 + (uint)*(byte *)(param_2 + 10);
19: *(uint *)(lVar6 + 0x30) = (uint)bVar1 * 0x100 + (uint)bVar2;
20: *(uint *)(lVar6 + 0x38) = (uint)bVar3;
21: *(undefined4 *)(lVar6 + 0x28) = 0x4c;
22: *(uint *)(lVar6 + 0x2c) = (uint)bVar5 + (uint)bVar4 * 0x100;
23: (**(code **)(lVar6 + 8))(param_1,1);
24: *(byte *)((long)param_1 + 0x184) = bVar3;
25: *(undefined4 *)(param_1 + 0x30) = 1;
26: return;
27: }
28: 

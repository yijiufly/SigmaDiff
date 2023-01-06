1: 
2: undefined8 FUN_001671d0(long *param_1)
3: 
4: {
5: long lVar1;
6: undefined8 *puVar2;
7: 
8: lVar1 = *param_1;
9: *(undefined4 *)(lVar1 + 0x28) = 0x78;
10: (**(code **)(lVar1 + 8))(param_1,0xffffffff);
11: puVar2 = (undefined8 *)param_1[5];
12: puVar2[1] = 2;
13: *puVar2 = &DAT_001904e8;
14: return 1;
15: }
16: 

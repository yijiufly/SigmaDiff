1: 
2: void thunk_FUN_001166f0(long param_1)
3: 
4: {
5: if (*(long *)(param_1 + 8) != 0) {
6: (**(code **)(*(long *)(param_1 + 8) + 0x48))(param_1,1);
7: if (*(int *)(param_1 + 0x20) != 0) {
8: *(undefined4 *)(param_1 + 0x24) = 200;
9: *(undefined8 *)(param_1 + 400) = 0;
10: return;
11: }
12: *(undefined4 *)(param_1 + 0x24) = 100;
13: }
14: return;
15: }
16: 

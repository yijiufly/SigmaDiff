1: 
2: void thunk_FUN_0011f490(long param_1)
3: 
4: {
5: if (*(long *)(param_1 + 8) == 0) {
6: return;
7: }
8: (**(code **)(*(long *)(param_1 + 8) + 0x48))(param_1,1);
9: if (*(int *)(param_1 + 0x20) == 0) {
10: *(undefined4 *)(param_1 + 0x24) = 100;
11: return;
12: }
13: *(undefined4 *)(param_1 + 0x24) = 200;
14: *(undefined8 *)(param_1 + 400) = 0;
15: return;
16: }
17: 

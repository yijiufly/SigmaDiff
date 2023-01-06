1: 
2: void FUN_00166e30(long param_1,long param_2)
3: 
4: {
5: undefined8 *puVar1;
6: char *pcVar2;
7: 
8: puVar1 = *(undefined8 **)(param_1 + 400);
9: do {
10: if (puVar1 == (undefined8 *)0x0) {
11: return;
12: }
13: pcVar2 = (char *)puVar1[3];
14: if ((*(int *)(param_2 + 0x120) == 0) || (*(char *)(puVar1 + 1) != -0x20)) {
15: if (((*(int *)(param_2 + 300) == 0) ||
16: (((*(char *)(puVar1 + 1) != -0x12 || (*(uint *)(puVar1 + 2) < 5)) || (*pcVar2 != 'A'))))
17: || ((((pcVar2[1] != 'd' || (pcVar2[2] != 'o')) || (pcVar2[3] != 'b')) || (pcVar2[4] != 'e')
18: ))) goto LAB_00166e50;
19: }
20: else {
21: if (((*(uint *)(puVar1 + 2) < 5) || (*pcVar2 != 'J')) ||
22: ((pcVar2[1] != 'F' || (((pcVar2[2] != 'I' || (pcVar2[3] != 'F')) || (pcVar2[4] != '\0')))))
23: ) {
24: LAB_00166e50:
25: FUN_00102e90();
26: }
27: }
28: puVar1 = (undefined8 *)*puVar1;
29: } while( true );
30: }
31: 

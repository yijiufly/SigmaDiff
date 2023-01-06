1: 
2: void FUN_0014ff50(long param_1,long param_2)
3: 
4: {
5: char cVar1;
6: undefined8 *puVar2;
7: uint uVar3;
8: char *pcVar4;
9: 
10: puVar2 = *(undefined8 **)(param_1 + 400);
11: do {
12: if (puVar2 == (undefined8 *)0x0) {
13: return;
14: }
15: if (*(int *)(param_2 + 0x120) == 0) {
16: cVar1 = *(char *)(puVar2 + 1);
17: uVar3 = *(uint *)(puVar2 + 2);
18: pcVar4 = (char *)puVar2[3];
19: LAB_0014ff7b:
20: if ((((*(int *)(param_2 + 300) == 0) || (cVar1 != -0x12)) || (uVar3 < 5)) ||
21: (((*pcVar4 != 'A' || (pcVar4[1] != 'd')) ||
22: ((pcVar4[2] != 'o' || ((pcVar4[3] != 'b' || (pcVar4[4] != 'e')))))))) {
23: LAB_0014ff8b:
24: FUN_00103030(param_2);
25: }
26: }
27: else {
28: cVar1 = *(char *)(puVar2 + 1);
29: uVar3 = *(uint *)(puVar2 + 2);
30: pcVar4 = (char *)puVar2[3];
31: if (cVar1 != -0x20) goto LAB_0014ff7b;
32: if ((uVar3 < 5) ||
33: ((((*pcVar4 != 'J' || (pcVar4[1] != 'F')) || (pcVar4[2] != 'I')) ||
34: ((pcVar4[3] != 'F' || (pcVar4[4] != '\0')))))) goto LAB_0014ff8b;
35: }
36: puVar2 = (undefined8 *)*puVar2;
37: } while( true );
38: }
39: 

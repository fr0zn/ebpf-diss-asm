mov32     r9,       #-1
jne       r9,       #-1, +2
mov       r0,       #0
exit
lddw      r1,       r9,  #3
ldw       r0,       r0,  #0
mov       r1,       r9
mov       r2,       r10
add       r2,       #-4
stw       [r10-4],  #0
call      #1
jne       r0,       #0,  +1
exit
ldxdw     r6,       [r0]
mov       r1,       r9
mov       r2,       r10
add       r2,       #-4
stw       [r10-4],  #1
call      #1
jne       r0,       #0,  +1
exit
ldxdw     r7,       [r0]
mov       r1,       r9
mov       r2,       r10
add       r2,       #-4
stw       [r10-4],  #2
call      #1
jne       r0,       #0,  +1
exit
ldxdw     r8,       [r0]
mov       r2,       r0
mov       r0,       #0
jne       r6,       #0,  +3
ldxdw     r3,       [r7]
stxdw     [r2],     r3
exit
jne       r6,       #1,  +2
stxdw     [r2],     r10
exit
stxdw     [r7],     r8
exit

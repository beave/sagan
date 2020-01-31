/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*  strstr_sse2.S
 *
 * This "hooks" in the "Sagan_strstr" function for CPUs supporting SSE2.
 * This code is based on work by Ondra B�lk and the glibc projects.
 *
 * His code/original post can be found at:
 *
 * http://comments.gmane.org/gmane.comp.lib.glibc.alpha/34531
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifndef WITH_SYSSTRSTR              /* If NOT using system built in strstr */

#ifdef HAVE_SSE2

#ifndef ALIGN
# define ALIGN(n) .p2align n
#endif

.text
.globl  __strstr_sse2_unaligned
.type   __strstr_sse2_unaligned, @function

__strstr_sse2_unaligned:
.LFB0:

 .cfi_startproc
 movzbl (%rsi), %eax
 testb %al, %al
 je .Lempty
 movzbl 1(%rsi), %edx
 testb %dl, %dl
 je .Lstrchr
 movd %eax, %xmm1
 movd %edx, %xmm2
 movq %rdi, %rax
 andl $4095, %eax
 punpcklbw %xmm1, %xmm1
 cmpq $4031, %rax
 punpcklbw %xmm2, %xmm2
 punpcklwd %xmm1, %xmm1
 punpcklwd %xmm2, %xmm2
 pshufd $0, %xmm1, %xmm1
 pshufd $0, %xmm2, %xmm2
 ja .Lcross_page
 movdqu (%rdi), %xmm3
 pxor %xmm5, %xmm5
 movdqu 1(%rdi), %xmm4
 movdqa %xmm3, %xmm6
 pcmpeqb %xmm1, %xmm3
 pcmpeqb %xmm2, %xmm4
 movdqu 16(%rdi), %xmm0
 pcmpeqb %xmm5, %xmm6
 pminub %xmm4, %xmm3
 movdqa %xmm3, %xmm4
 movdqu 17(%rdi), %xmm3
 pcmpeqb %xmm0, %xmm5
 pcmpeqb %xmm2, %xmm3
 por %xmm6, %xmm4
 pcmpeqb %xmm1, %xmm0
 pminub %xmm3, %xmm0
 por %xmm5, %xmm0
 pmovmskb %xmm4, %r8d
 pmovmskb %xmm0, %eax
 salq $16, %rax
 orq %rax, %r8
 je .Lnext_32_bytes

.Lnext_pair_index:
 bsf %r8, %rax
 addq %rdi, %rax
 cmpb $0, (%rax)
 je .Lzero1
 movzbl 2(%rsi), %edx
 testb %dl, %dl
 je .Lfound1
 cmpb 2(%rax), %dl
 jne .Lnext_pair
 xorl %edx, %edx
 jmp .Lpair_loop_start

 ALIGN (4)
.Lstrchr:
 movzbl %al, %esi
 jmp strchr@PLT

 ALIGN (4)
.Lpair_loop:
 addq $1, %rdx
 cmpb 2(%rax,%rdx), %cl
 jne .Lnext_pair

.Lpair_loop_start:
 movzbl 3(%rsi,%rdx), %ecx
 testb %cl, %cl
 jne .Lpair_loop

.Lfound1:
 ret

.Lzero1:
 xorl %eax, %eax
 ret

 ALIGN (4)

.Lnext_pair:
 leaq -1(%r8), %rax
 andq %rax, %r8
 jne .Lnext_pair_index

 ALIGN (4)

.Lnext_32_bytes:
 movdqu 32(%rdi), %xmm3
 pxor %xmm5, %xmm5
 movdqu 33(%rdi), %xmm4
 movdqa %xmm3, %xmm6
 pcmpeqb %xmm1, %xmm3
 pcmpeqb %xmm2, %xmm4
 movdqu 48(%rdi), %xmm0
 pcmpeqb %xmm5, %xmm6
 pminub %xmm4, %xmm3
 movdqa %xmm3, %xmm4
 movdqu 49(%rdi), %xmm3
 pcmpeqb %xmm0, %xmm5
 pcmpeqb %xmm2, %xmm3
 por %xmm6, %xmm4
 pcmpeqb %xmm1, %xmm0
 pminub %xmm3, %xmm0
 por %xmm5, %xmm0
 pmovmskb %xmm4, %eax
 salq $32, %rax
 pmovmskb %xmm0, %r8d
 salq $48, %r8
 orq %rax, %r8
 je .Lloop_header

.Lnext_pair2_index:
 bsfq %r8, %rax
 addq %rdi, %rax
 cmpb $0, (%rax)
 je .Lzero2
 movzbl 2(%rsi), %edx
 testb %dl, %dl
 je .Lfound2
 cmpb 2(%rax), %dl
 jne .Lnext_pair2
 xorl %edx, %edx
 jmp .Lpair_loop2_start

 ALIGN (4)

.Lpair_loop2:
 addq $1, %rdx
 cmpb 2(%rax,%rdx), %cl
 jne .Lnext_pair2

.Lpair_loop2_start:
 movzbl 3(%rsi,%rdx), %ecx
 testb %cl, %cl
 jne .Lpair_loop2

.Lfound2:
 ret

 .Lzero2:
 xorl %eax, %eax
 ret

.Lempty:
 mov %rdi, %rax
 ret

 ALIGN (4)

.Lnext_pair2:
 leaq -1(%r8), %rax
 andq %rax, %r8
 jne .Lnext_pair2_index

.Lloop_header:
 movq $-512, %r11
 movq %rdi, %r9
 pxor %xmm7, %xmm7
 andq $-64, %rdi

 ALIGN (4)

.Lloop:
 movdqa 64(%rdi), %xmm3
 movdqu 63(%rdi), %xmm6
 movdqa %xmm3, %xmm0
 pxor %xmm2, %xmm3
 pxor %xmm1, %xmm6
 movdqa 80(%rdi), %xmm10
 por %xmm3, %xmm6
 pminub %xmm10, %xmm0
 movdqu 79(%rdi), %xmm3
 pxor %xmm2, %xmm10
 pxor %xmm1, %xmm3
 movdqa 96(%rdi), %xmm9
 por %xmm10, %xmm3
 pminub %xmm9, %xmm0
 pxor %xmm2, %xmm9
 movdqa 112(%rdi), %xmm8
 addq $64, %rdi
 pminub %xmm6, %xmm3
 movdqu 31(%rdi), %xmm4
 pminub %xmm8, %xmm0
 pxor %xmm2, %xmm8
 pxor %xmm1, %xmm4
 por %xmm9, %xmm4
 pminub %xmm4, %xmm3
 movdqu 47(%rdi), %xmm5
 pxor %xmm1, %xmm5
 por %xmm8, %xmm5
 pminub %xmm5, %xmm3
 pminub %xmm3, %xmm0
 pcmpeqb %xmm7, %xmm0
 pmovmskb %xmm0, %eax
 testl %eax, %eax
 je .Lloop
 pminub (%rdi), %xmm6
 pminub 32(%rdi),%xmm4
 pminub 48(%rdi),%xmm5
 pcmpeqb %xmm7, %xmm6
 pcmpeqb %xmm7, %xmm5
 pmovmskb %xmm6, %edx
 movdqa 16(%rdi), %xmm8
 pcmpeqb %xmm7, %xmm4
 movdqu 15(%rdi), %xmm0
 pmovmskb %xmm5, %r8d
 movdqa %xmm8, %xmm3
 pmovmskb %xmm4, %ecx
 pcmpeqb %xmm1,%xmm0
 pcmpeqb %xmm2,%xmm3
 salq $32, %rcx
 pcmpeqb %xmm7,%xmm8
 salq $48, %r8
 pminub %xmm0,%xmm3
 orq %rcx, %rdx
 por %xmm3,%xmm8
 orq %rdx, %r8
 pmovmskb %xmm8, %eax
 salq $16, %rax
 orq %rax, %r8

.Lnext_pair_index3:
 bsfq %r8, %rcx
 addq %rdi, %rcx
 cmpb $0, (%rcx)
 je .Lzero
 xorl %eax, %eax
 movzbl 2(%rsi), %edx
 testb %dl, %dl
 je .Lsuccess3
 cmpb 1(%rcx), %dl
 jne .Lnext_pair3
 jmp .Lpair_loop_start3

 ALIGN (4)
.Lpair_loop3:
 addq $1, %rax
 cmpb 1(%rcx,%rax), %dl
 jne .Lnext_pair3

.Lpair_loop_start3:
 movzbl 3(%rsi,%rax), %edx
 testb %dl, %dl
 jne .Lpair_loop3

.Lsuccess3:
 lea -1(%rcx), %rax
 ret

 ALIGN (4)
.Lnext_pair3:
 addq %rax, %r11
 movq %rdi, %rax
 subq %r9, %rax
 cmpq %r11, %rax
 jl .Lswitch_strstr
 leaq -1(%r8), %rax
 andq %rax, %r8
 jne .Lnext_pair_index3
 jmp .Lloop

 ALIGN (4)
.Lswitch_strstr:
 movq %rdi, %rdi
 jmp	strstr@PLT

 ALIGN (4)
.Lcross_page:
 movq %rdi, %rax
 pxor %xmm0, %xmm0
 andq $-64, %rax
 movdqa (%rax), %xmm3
 movdqu -1(%rax), %xmm4
 movdqa %xmm3, %xmm8
 movdqa 16(%rax), %xmm5
 pcmpeqb %xmm1, %xmm4
 pcmpeqb %xmm0, %xmm8
 pcmpeqb %xmm2, %xmm3
 movdqa %xmm5, %xmm7
 pminub %xmm4, %xmm3
 movdqu 15(%rax), %xmm4
 pcmpeqb %xmm0, %xmm7
 por %xmm3, %xmm8
 movdqa %xmm5, %xmm3
 movdqa 32(%rax), %xmm5
 pcmpeqb %xmm1, %xmm4
 pcmpeqb %xmm2, %xmm3
 movdqa %xmm5, %xmm6
 pmovmskb %xmm8, %ecx
 pminub %xmm4, %xmm3
 movdqu 31(%rax), %xmm4
 por %xmm3, %xmm7
 movdqa %xmm5, %xmm3
 pcmpeqb %xmm0, %xmm6
 movdqa 48(%rax), %xmm5
 pcmpeqb %xmm1, %xmm4
 pmovmskb %xmm7, %r8d
 pcmpeqb %xmm2, %xmm3
 pcmpeqb %xmm5, %xmm0
 pminub %xmm4, %xmm3
 movdqu 47(%rax), %xmm4
 por %xmm3, %xmm6
 movdqa %xmm5, %xmm3
 salq $16, %r8
 pcmpeqb %xmm1, %xmm4
 pcmpeqb %xmm2, %xmm3
 pmovmskb %xmm6, %r10d
 pminub %xmm4, %xmm3
 por %xmm3, %xmm0
 salq $32, %r10
 orq %r10, %r8
 orq %rcx, %r8
 movl %edi, %ecx
 pmovmskb %xmm0, %edx
 subl %eax, %ecx
 salq $48, %rdx
 orq %rdx, %r8
 shrq %cl, %r8
 je .Lloop_header

.Lnext_pair_index4:
 bsfq %r8, %rax
 addq %rdi, %rax
 cmpb $0, (%rax)
 je .Lzero
 cmpq %rax,%rdi
 je .Lnext_pair4
 movzbl 2(%rsi), %edx
 testb %dl, %dl
 je .Lfound3
 cmpb 1(%rax), %dl
 jne .Lnext_pair4
 xorl %edx, %edx
 jmp .Lpair_loop_start4

 ALIGN (4)
.Lpair_loop4:
 addq $1, %rdx
 cmpb 1(%rax,%rdx), %cl
 jne .Lnext_pair4

.Lpair_loop_start4:
 movzbl 3(%rsi,%rdx), %ecx
 testb %cl, %cl
 jne .Lpair_loop4

.Lfound3:
 subq $1, %rax
 ret

 ALIGN (4)
.Lnext_pair4:
 leaq -1(%r8), %rax
 andq %rax, %r8
 jne .Lnext_pair_index4
 jmp .Lloop_header

 ALIGN (4)
.Lfound:
 rep
 ret
 
 ALIGN (4)
.Lzero:
 xorl %eax, %eax
 ret

.cfi_endproc

.LFE0:

.size   __strstr_sse2_unaligned, .-__strstr_sse2_unaligned
.ident  "Sagan builtin strstr_sse2_unligned function"
.section        .note.GNU-stack,"",@progbits

#endif

#endif


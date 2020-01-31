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

/* strstr_sse4_2.S
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


# sse4_2 __strstr_sse42 black
	.file	"strstr.c"
	.section	.text.sse4.2,"ax",@progbits
	.p2align 4,,15
	.globl	__strstr_sse42
	.type	__strstr_sse42, @function
__strstr_sse42:
.LFB638:
	.cfi_startproc
	movzbl	(%rsi), %edx
	movq	%rdi, %r10
	testb	%dl, %dl
	je	.L118
	movzbl	(%rdi), %eax
	testb	%al, %al
	je	.L117
	cmpb	$0, 1(%rdi)
	je	.L123
	movq	%rdi, %rax
	andl	$4095, %eax
	cmpl	$4080, %eax
	jg	.L124
.L6:
	movdqu	(%r10), %xmm1
.L7:
	cmpb	$0, 1(%rsi)
	jne	.L125
	pxor	%xmm2, %xmm2
	pinsrb	$0, (%rsi), %xmm2
.L11:
	pcmpistri	$12, %xmm1, %xmm2
	movl	$0, %eax
	movl	$0, %r8d
	movdqa	%xmm2, %xmm4
	setc	%al
	sets	%r8b
	sete	%dl
	testl	%eax, %r8d
	movl	%ecx, %edi
	movzbl	%dl, %edx
	je	.L12
	pxor	%xmm1, %xmm1
	movslq	%ecx, %rax
	movdqa	%xmm2, %xmm3
	addq	%rax, %r10
	pcmpeqb	%xmm1, %xmm3
	pmovmskb	%xmm3, %r9d
#APP
# 222 "strstr.c" 1
	bsfl %r9d, %r9d
# 0 "" 2
#NO_APP
	addl	%r9d, %edi
	cmpl	$16, %edi
	jle	.L118
	movq	%r10, %rax
	andl	$4095, %eax
	cmpl	$4080, %eax
	jg	.L126
.L13:
	movdqu	(%r10), %xmm1
.L14:
	pcmpistri	$12, %xmm1, %xmm4
	movslq	%ecx, %rdi
	setc	%al
	sets	%r8b
	sete	%dl
	addl	%edi, %r9d
	movzbl	%al, %eax
	cmpl	$16, %r9d
	movzbl	%r8b, %r8d
	movzbl	%dl, %edx
	jg	.L12
	addq	%rdi, %r10
	jmp	.L118
	.p2align 4,,10
	.p2align 3
.L12:
	testl	%r8d, %r8d
	jne	.L15
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	leaq	16(%rsi), %r11
	movq	%rsi, %rdi
	xorl	%r9d, %r9d
	pxor	%xmm4, %xmm4
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movl	$3, %r14d
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	movq	%rsi, %r13
	andl	$15, %r13d
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	subq	%r13, %rdi
	movq	%r11, %r12
	andl	$15, %r12d
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	movl	%r11d, %ebp
	andl	$4095, %ebp
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	movl	%esi, %ebx
	andl	$4095, %ebx
	movq	%rdi, -32(%rsp)
	movq	%r11, %rdi
	movb	%r13b, -10(%rsp)
	subq	%r12, %rdi
	testl	%eax, %eax
	movb	%r12b, -9(%rsp)
	movq	%rdi, -24(%rsp)
	je	.L26
	.p2align 4,,10
	.p2align 3
.L132:
	testl	%ecx, %ecx
	jne	.L27
	testl	%edx, %edx
	jne	.L2
	cmpl	$4080, %ebp
	leaq	16(%r10), %rax
	jg	.L127
.L28:
	movdqu	(%r11), %xmm2
.L29:
	movq	%r11, %rdx
.L30:
	movq	%rax, %rcx
	andl	$4095, %ecx
	cmpl	$4080, %ecx
	jg	.L128
.L31:
	movdqu	(%rax), %xmm3
.L32:
	pcmpistri	$12, %xmm3, %xmm2
	sete	%r8b
	movl	%ecx, %edi
	sets	%cl
	movzbl	%r8b, %r8d
	movl	%edi, %r15d
	movzbl	%cl, %ecx
	orl	%r8d, %r15d
	orl	%ecx, %r15d
	jne	.L33
	.p2align 4,,10
	.p2align 3
.L90:
	addq	$16, %rdx
	addq	$16, %rax
	movq	%rdx, %rcx
	andl	$4095, %ecx
	cmpl	$4080, %ecx
	jg	.L129
.L34:
	movdqu	(%rdx), %xmm2
.L35:
	movq	%rax, %rcx
	andl	$4095, %ecx
	cmpl	$4080, %ecx
	jg	.L130
.L36:
	movdqu	(%rax), %xmm3
.L37:
	pcmpistri	$12, %xmm3, %xmm2
	sete	%r8b
	sets	%dil
	movl	%ecx, %r15d
	movzbl	%r8b, %r8d
	movzbl	%dil, %edi
	orl	%r8d, %r15d
	orl	%edi, %r15d
	je	.L90
	movl	%edi, %eax
	movl	%ecx, %edi
	movl	%eax, %ecx
.L33:
	testl	%edi, %edi
	sete	%al
	movzbl	%al, %edx
	testl	%ecx, %edx
	jne	.L2
	testl	%r8d, %r8d
	je	.L39
	testl	%ecx, %ecx
	je	.L5
	pcmpeqb	%xmm4, %xmm2
	pcmpeqb	%xmm4, %xmm3
	pmovmskb	%xmm2, %edx
	pmovmskb	%xmm3, %eax
#APP
# 350 "strstr.c" 1
	bsfl %edx, %edx
# 0 "" 2
# 352 "strstr.c" 1
	bsfl %eax, %eax
# 0 "" 2
#NO_APP
	cmpl	%eax, %edx
	jge	.L5
.L40:
	cmpl	$4080, %ebx
	jg	.L131
.L41:
	movdqu	(%rsi), %xmm2
.L42:
	testl	%r9d, %r9d
	jne	.L43
	movdqa	%xmm2, %xmm0
	movb	$16, %r9b
	movdqa	%xmm2, %xmm1
	punpcklbw	%xmm2, %xmm0
	psrldq	$1, %xmm1
	punpcklbw	%xmm0, %xmm0
	pshufd	$0, %xmm0, %xmm0
	pcmpeqb	%xmm1, %xmm0
	pmovmskb	%xmm0, %eax
#APP
# 144 "strstr.c" 1
	bsfl %eax, %edx
# 0 "" 2
#NO_APP
	testl	%eax, %eax
	je	.L43
	cmpl	$32767, %eax
	movb	$1, %r9b
	je	.L43
	leal	1(%rdx), %r9d
	testl	%edx, %edx
	cmove	%r14d, %r9d
	.p2align 4,,10
	.p2align 3
.L43:
	cmpl	%edi, %r9d
	cmovle	%r9d, %edi
	movslq	%edi, %rdi
	addq	%rdi, %r10
	cmpb	$0, (%r10)
	je	.L5
	movq	%r10, %rax
	andl	$4095, %eax
	cmpl	$4080, %eax
	jg	.L121
.L24:
	movdqu	(%r10), %xmm1
.L25:
	pcmpistri	$12, %xmm1, %xmm2
	setc	%al
	sete	%dl
	movzbl	%al, %eax
	movzbl	%dl, %edx
	testl	%eax, %eax
	jne	.L132
.L26:
	testl	%edx, %edx
	jne	.L5
	addq	$16, %r10
	movq	%r10, %rax
	andl	$4095, %eax
	cmpl	$4080, %eax
	jle	.L24
.L121:
	movq	%r10, %rcx
	movq	%r10, %rax
	andl	$15, %ecx
	subq	%rcx, %rax
	movdqu	(%rax), %xmm0
	movdqa	%xmm0, %xmm1
	pcmpeqb	%xmm4, %xmm1
	pmovmskb	%xmm1, %eax
	sarl	%cl, %eax
	testl	%eax, %eax
	je	.L24
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm1
	pshufb	%xmm1, %xmm0
	movdqa	%xmm0, %xmm1
	jmp	.L25
	.p2align 4,,10
	.p2align 3
.L15:
	.cfi_def_cfa_offset 8
	.cfi_restore 3
	.cfi_restore 6
	.cfi_restore 12
	.cfi_restore 13
	.cfi_restore 14
	.cfi_restore 15
	testl	%edx, %edx
	pxor	%xmm2, %xmm2
	je	.L89
	jmp	.L22
	.p2align 4,,10
	.p2align 3
.L113:
	testl	%edx, %edx
	jne	.L22
.L89:
	movslq	%ecx, %rcx
	addq	%rcx, %r10
	movq	%r10, %rax
	andl	$4095, %eax
	cmpl	$4080, %eax
	jg	.L133
.L17:
	movdqu	(%r10), %xmm1
.L18:
	pcmpistri	$12, %xmm1, %xmm4
	movl	$0, %edx
	setc	%al
	sete	%dl
	xorl	%esi, %esi
	testl	%ecx, %ecx
	movzbl	%al, %eax
	sete	%sil
	testl	%eax, %esi
	je	.L113
	xorl	%ecx, %ecx
.L19:
	addq	%rcx, %r10
.L118:
	movq	%r10, %rax
	ret
	.p2align 4,,10
	.p2align 3
.L27:
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	.cfi_offset 6, -48
	.cfi_offset 12, -40
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	movslq	%ecx, %rax
	movq	%rsi, %rdx
	addq	%r10, %rax
	movq	%rax, %r10
	jmp	.L30
	.p2align 4,,10
	.p2align 3
.L39:
	testb	%al, %al
	je	.L40
.L2:
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_restore 14
	.cfi_def_cfa_offset 16
	movq	%r10, %rax
	popq	%r15
	.cfi_restore 15
	.cfi_def_cfa_offset 8
	ret
.L125:
	movq	%rsi, %rax
	andl	$4095, %eax
	cmpl	$4080, %eax
	jg	.L134
.L9:
	movdqu	(%rsi), %xmm2
	jmp	.L11
.L5:
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	.cfi_offset 6, -48
	.cfi_offset 12, -40
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 24
	xorl	%r10d, %r10d
	popq	%r14
	.cfi_restore 14
	.cfi_def_cfa_offset 16
	movq	%r10, %rax
	popq	%r15
	.cfi_restore 15
	.cfi_def_cfa_offset 8
	ret
.L22:
	testl	%eax, %eax
	movslq	%ecx, %rcx
	jne	.L19
.L117:
	xorl	%r10d, %r10d
	jmp	.L118
	.p2align 4,,10
	.p2align 3
.L129:
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	.cfi_offset 6, -48
	.cfi_offset 12, -40
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	movq	%rdx, %rcx
	movq	%rdx, %rdi
	andl	$15, %ecx
	subq	%rcx, %rdi
	movdqu	(%rdi), %xmm0
	movdqa	%xmm0, %xmm1
	pcmpeqb	%xmm4, %xmm1
	pmovmskb	%xmm1, %edi
	sarl	%cl, %edi
	testl	%edi, %edi
	je	.L34
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm1
	pshufb	%xmm1, %xmm0
	movdqa	%xmm0, %xmm2
	jmp	.L35
.L130:
	movq	%rax, %rcx
	movq	%rax, %rdi
	andl	$15, %ecx
	subq	%rcx, %rdi
	movdqu	(%rdi), %xmm0
	movdqa	%xmm0, %xmm1
	pcmpeqb	%xmm4, %xmm1
	pmovmskb	%xmm1, %edi
	sarl	%cl, %edi
	testl	%edi, %edi
	je	.L36
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm1
	pshufb	%xmm1, %xmm0
	movdqa	%xmm0, %xmm3
	jmp	.L37
.L126:
	.cfi_def_cfa_offset 8
	.cfi_restore 3
	.cfi_restore 6
	.cfi_restore 12
	.cfi_restore 13
	.cfi_restore 14
	.cfi_restore 15
	movq	%r10, %rcx
	movq	%r10, %rax
	andl	$15, %ecx
	subq	%rcx, %rax
	movdqu	(%rax), %xmm3
	pcmpeqb	%xmm3, %xmm1
	pmovmskb	%xmm1, %eax
	sarl	%cl, %eax
	testl	%eax, %eax
	je	.L13
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm1
	pshufb	%xmm1, %xmm3
	movdqa	%xmm3, %xmm1
	jmp	.L14
.L127:
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	.cfi_offset 6, -48
	.cfi_offset 12, -40
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	movq	-24(%rsp), %rdx
	movzbl	-9(%rsp), %ecx
	movdqu	(%rdx), %xmm0
	movdqa	%xmm0, %xmm1
	pcmpeqb	%xmm4, %xmm1
	pmovmskb	%xmm1, %edx
	sarl	%cl, %edx
	testl	%edx, %edx
	je	.L28
	movq	%r12, %rdx
	addq	___m128i_shift_right@GOTPCREL(%rip), %rdx
	movdqu	(%rdx), %xmm1
	pshufb	%xmm1, %xmm0
	movdqa	%xmm0, %xmm2
	jmp	.L29
.L128:
	movq	%rax, %rcx
	movq	%rax, %rdi
	andl	$15, %ecx
	subq	%rcx, %rdi
	movdqu	(%rdi), %xmm0
	movdqa	%xmm0, %xmm1
	pcmpeqb	%xmm4, %xmm1
	pmovmskb	%xmm1, %edi
	sarl	%cl, %edi
	testl	%edi, %edi
	je	.L31
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm1
	pshufb	%xmm1, %xmm0
	movdqa	%xmm0, %xmm3
	jmp	.L32
.L131:
	movq	-32(%rsp), %rax
	movzbl	-10(%rsp), %ecx
	movdqu	(%rax), %xmm0
	movdqa	%xmm0, %xmm1
	pcmpeqb	%xmm4, %xmm1
	pmovmskb	%xmm1, %eax
	sarl	%cl, %eax
	testl	%eax, %eax
	je	.L41
	movq	%r13, %rax
	addq	___m128i_shift_right@GOTPCREL(%rip), %rax
	movdqu	(%rax), %xmm1
	pshufb	%xmm1, %xmm0
	movdqa	%xmm0, %xmm2
	jmp	.L42
.L124:
	.cfi_def_cfa_offset 8
	.cfi_restore 3
	.cfi_restore 6
	.cfi_restore 12
	.cfi_restore 13
	.cfi_restore 14
	.cfi_restore 15
	movq	%rdi, %rcx
	movq	%rdi, %rax
	andl	$15, %ecx
	pxor	%xmm0, %xmm0
	subq	%rcx, %rax
	movdqu	(%rax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pmovmskb	%xmm0, %eax
	sarl	%cl, %eax
	testl	%eax, %eax
	je	.L6
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm0
	pshufb	%xmm0, %xmm1
	jmp	.L7
.L123:
	cmpb	$0, 1(%rsi)
	jne	.L117
	cmpb	%al, %dl
	jne	.L117
	.p2align 4,,5
	jmp	.L118
.L134:
	movq	%rsi, %rcx
	movq	%rsi, %rax
	andl	$15, %ecx
	pxor	%xmm0, %xmm0
	subq	%rcx, %rax
	movdqu	(%rax), %xmm2
	pcmpeqb	%xmm2, %xmm0
	pmovmskb	%xmm0, %eax
	sarl	%cl, %eax
	testl	%eax, %eax
	je	.L9
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm0
	pshufb	%xmm0, %xmm2
	jmp	.L11
.L133:
	movq	%r10, %rcx
	movq	%r10, %rax
	andl	$15, %ecx
	subq	%rcx, %rax
	movdqu	(%rax), %xmm1
	movdqa	%xmm1, %xmm3
	pcmpeqb	%xmm2, %xmm3
	pmovmskb	%xmm3, %eax
	sarl	%cl, %eax
	testl	%eax, %eax
	je	.L17
	addq	___m128i_shift_right@GOTPCREL(%rip), %rcx
	movdqu	(%rcx), %xmm3
	pshufb	%xmm3, %xmm1
	jmp	.L18
	.cfi_endproc
.LFE638:
	.size	__strstr_sse42, .-__strstr_sse42

	.file	"varshift.c"
	.globl	___m128i_shift_right
	.section	.rodata
	.align 16
	.type	___m128i_shift_right, @object
	.size	___m128i_shift_right, 31
___m128i_shift_right:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.ident	"Sagan builtin __strstr_sse42 function"
	.section	.note.GNU-stack,"",@progbits
	.ident	"Sagan builtin __strstr_sse42 function"
	.section	.note.GNU-stack,"",@progbits

#endif

#endif

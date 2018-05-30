;;
;; aPLib compression library  -  the smaller the better :)
;;
;; TASM / MASM / WASM safe assembler depacker
;;
;; Copyright (c) 1998-2008 by Joergen Ibsen / Jibz
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

.386p
.model flat, c
option casemap:none

getbitM MACRO
LOCAL stillbitsleft
    add    dl, dl
    jnz    stillbitsleft

    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    dl, [esi]
    inc    esi

    add    dl, dl
    inc    dl
stillbitsleft:
ENDM getbitM

domatchM MACRO reg
    push   ecx
    mov    ecx, [esp + 60]    ; ecx = dstlen
    sub    ecx, [esp + 4]     ; ecx = num written
    cmp    reg, ecx
    pop    ecx
    ja     return_error

    sub    [esp], ecx         ; write ecx bytes to destination
    jc     return_error       ;

    push   esi
    mov    esi, edi
    sub    esi, reg
    rep    movsb
    pop    esi
ENDM domatchM

getgammaM MACRO reg
LOCAL getmorebits
    mov    reg, 1
getmorebits:
    getbitM
    adc    reg, reg
    jc     return_error
    getbitM
    jc     getmorebits
ENDM getgammaM

.CODE
option prologue:none
option epilogue:none
PUBLIC depack_aplib

depack_aplib:
    pushad
    mov    esi, [esp + 36]    ; C calling convention
    mov    eax, [esp + 40]
    mov    edi, [esp + 44]
    mov    ecx, [esp + 48]

    push   eax
    push   ecx

    test   esi, esi
    jz     return_error

    test   edi, edi
    jz     return_error

    cld
    xor    edx, edx

literal:
    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    add    esi, 1

    sub    dword ptr [esp], 1 ; write one byte to destination
    jc     return_error       ;

    mov    [edi], al
    add    edi, 1

    mov    ebx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    eax, eax
    getbitM
    jnc    shortmatch

    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    jz     thewrite

    mov    ebx, [esp + 56]    ; ebx = dstlen
    sub    ebx, [esp]         ; ebx = num written
    cmp    eax, ebx
    ja     return_error

    mov    ebx, edi
    sub    ebx, eax
    mov    al, [ebx]

thewrite:
    sub    dword ptr [esp], 1 ; write one byte to destination
    jc     return_error       ;

    mov    [edi], al
    inc    edi

    mov    ebx, 2

    jmp    nexttag

codepair:
    getgammaM eax

    sub    eax, ebx

    mov    ebx, 1

    jnz    normalcodepair

    getgammaM ecx

    domatchM ebp

    jmp    nexttag

normalcodepair:
    dec    eax

    test   eax, 0ff000000h
    jnz    return_error

    shl    eax, 8

    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    inc    esi

    mov    ebp, eax

    getgammaM ecx

    cmp    eax, 32000
    sbb    ecx, -1

    cmp    eax, 1280
    sbb    ecx, -1

    cmp    eax, 128
    adc    ecx, 0

    cmp    eax, 128
    adc    ecx, 0

    domatchM eax

    jmp    nexttag

shortmatch:
    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    inc    esi

    xor    ecx, ecx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    ecx, 2

    mov    ebp, eax

    domatchM eax

    mov    ebx, 1

    jmp    nexttag

return_error:
    add    esp, 8

    popad

    or     eax, -1            ; return APLIB_ERROR in eax

    ret

donedepacking:
    add    esp, 8

    sub    edi, [esp + 40]
    mov    [esp + 28], edi    ; return unpacked length in eax

    popad

    ret
depack_aplibend proc export
    ret
depack_aplibend endp
END

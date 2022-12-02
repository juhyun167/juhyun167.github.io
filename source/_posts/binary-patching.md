---
title: 바이너리 패치
date: 2022-11-27 09:20:03
tags:
categories: [Security, Reverse Engineering]
---

## 개요

바이너리 패치의 의미와 방법을 살펴보고, 코드 수정과 삽입을 통해 취약점을 패치해 보겠습니다.


## 바이너리 패치

바이너리 패치(binary patching)란 바이너리의 내용을 수정하여 다르게 동작하도록 하는 과정을 의미합니다. 바이너리 패치는 소스 코드의 확보가 제한되는 바이너리를 대상으로 분석이나 연구, 또는 취약점을 보완할 필요가 있는 상황에서 유용합니다. 예를 들어 사물인터넷(IoT) 장치의 펌웨어에서 제조사가 패치하지 못한 취약점을 자체적으로 보완하여 사용하거나, 디버거를 탐지하면 종료하는 등 분석을 방해하는 악성 코드의 기능을 무력화하기 위해 바이너리 패치 기술을 사용할 수 있습니다.


### 방법론

바이너리 패치는 바이너리의 동작을 얼마나 변형할 것인지에 따라 다양한 방법을 사용할 수 있습니다. 아주 사소한 버그를 수정하거나, 일부 코드를 무력화하는 등 기존의 동작을 조금 변형하는 정도라면 헥스 에디터를 이용하여 해당하는 인스트럭션을 수정하는 것으로도 충분합니다. 그러나 특정 함수의 동작 자체를 수정하거나, 원하는 코드를 추가적으로 실행하는 등 변형의 정도가 큰 경우에는 코드를 삽입하기 위한 다양한 방법을 사용해야 합니다.

이 글에서는 예제 바이너리에 존재하는 두 가지 취약점을 패치하는 상황을 가정하고, 헥스 에디터를 이용한 간단한 수정과 코드를 삽입하여 패치하는 방법을 모두 연습해 보겠습니다. 실습에 사용할 바이너리는 다음 링크에서 내려받을 수 있습니다.
[example.zip](/uploads/binary-patching/example.zip)


## 간단한 수정의 경우

바이너리의 동작을 조금만 변형하는 간단한 수정의 경우, 헥스 에디터를 사용하는 방법이 직관적이고 간편합니다. 헥스 에디터를 사용하는 방법은 기초적인 도구만으로도 간편하게 패치를 할 수 있다는 장점이 있습니다. 패치의 과정은 먼저 디스어셈블러를 이용해 패치할 코드와 위치를 확인한 후, 헥스 에디터로 바이너리를 열고 해당 위치의 인스트럭션을 원하는 인스트럭션으로 덮어씁니다. 아래 그림은 헥스 에디터를 사용하여 특정 함수의 호출을 무력화하는 간단한 수정의 예시를 나타내고 있습니다.

![1.png](/images/binary-patching/1.png)

다만 이 방법은 패치할 부분을 제외한 나머지 바이트들이 제자리에 위치한 상태에서만 수정이 가능하다는 분명한 한계가 있습니다. 예를 들어 원래의 인스트럭션보다 수정할 인스트럭션의 길이가 길다면, 인스트럭션을 덮어쓸 때 이후의 인스트럭션 내용까지 덮어쓰게 되어 바이너리가 정상 동작하지 않을 수 있습니다. 코드 섹션의 사용하지 않는 여유 공간에 새로운 코드를 추가할 수도 있겠지만, 대부분의 바이너리는 코드를 추가할 만큼 충분한 여유 공간을 가지고 있지 않습니다.


### off-by-one 버그 패치하기

바이너리에 존재하는 off-by-one 버그를 헥스 에디터를 사용한 방법으로 패치해 보겠습니다. 압축 파일에서 `example1/main` 파일이 패치할 바이너리입니다. 바이너리를 실행하면 add, delete, show 등의 메뉴를 확인할 수 있고, 각각의 메뉴를 선택해 보면 사용자로부터 문자열을 입력받아 관리하고 보여주는 프로그램임을 짐작할 수 있습니다.

```
$ ./main
1. add data
2. delete data
3. show data
4. exit
>
```

add 메뉴에 해당하는 `add_data` 함수를 디컴파일하면 다음과 같습니다. 11행에서 길이를 입력받고, 16보다 작거나 같으면 14행에서 20바이트 크기의 구조체를 할당한 후 오프셋 16에 길이를 저장합니다. 17행의 반복문에서는 입력받은 길이만큼 1바이트씩 문자를 입력받아 구조체의 오프셋 0에서부터 저장하는 것처럼 보입니다. 20행의 조건문은 입력받은 문자가 개행 문자면 널(null) 문자로 바꾼 후 반복문을 탈출하도록 합니다.

```c
_DWORD *add_data()
{
  char buf; // [rsp+7h] [rbp-19h] BYREF
  unsigned int v2; // [rsp+8h] [rbp-18h] BYREF
  unsigned int i; // [rsp+Ch] [rbp-14h]
  _DWORD *v4; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("length: ");
  __isoc99_scanf("%u", &v2);
  if ( v2 <= 0x10 )
  {
    v4 = malloc(0x14uLL);
    v4[4] = v2;
    printf("contents: ");
    for ( i = 0; i <= v2; ++i )
    {
      read(0, &buf, 1uLL);
      if ( buf == '\n' )
      {
        *((_BYTE *)v4 + (int)i) = '\0';
        return v4;
      }
      *((_BYTE *)v4 + (int)i) = buf;
    }
    return v4;
  }
  else
  {
    puts("sorry, not enough space");
    return 0LL;
  }
}
```

그런데 반복문의 탈출 조건을 잘 보면 `i < v2` 가 아닌 `i <= v2` 로, 길이만큼 입력받도록 한 개발자의 의도와는 달리 실제로는 한 바이트를 더 입력할 수 있습니다. 만약 허용되는 최대 길이인 16을 입력한 후 17바이트를 입력한다면, 마지막 바이트는 구조체의 오프셋 16에 저장되면서 해당 위치에 있는 길이 값을 아래 그림과 같이 덮어쓸 것입니다.

![2.png](/images/binary-patching/2.png)

show 메뉴에 해당하는 `show_data` 함수를 보면 오프셋 16의 5행에서 반복문의 탈출 조건에 사용되고 있습니다. 반복문은 구조체의 내용을 1바이트씩 출력하므로, 길이 값이 모두 몇 바이트를 출력할지 결정하고 있는 것입니다. 위의 그림과 같이 길이 값이 16보다 큰 값으로 오염된 상태라면, 힙 메모리에 대한 out-of-bounds 읽기가 발생하여 메모리 주소가 노출되는 취약점으로까지 연계될 수 있습니다.

```c
int __fastcall show_data(__int64 a1)
{
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; *(_DWORD *)(a1 + 16) > i; ++i )
    write(1, (const void *)((int)i + a1), 1uLL);
  return putchar(10);
}
```

실제로 길이 값이 오염된 구조체 이후에 해제된 힙 메모리가 위치하도록 한 후, show 메뉴를 이용해 출력해보면 힙 영역의 메모리 주소가 노출되는 것을 확인할 수 있습니다.

```
1. add data
2. delete data
3. show data
4. exit
[DEBUG] Received 0x2 bytes:
    b'> '
> 3
...
aaaaaaaaaaaa[DEBUG] Received 0x42 bytes:
    00000000  61 61 61 61  61 00 00 00  00 00 00 00  21 00 00 00  │aaaa│a···│····│!···│
    00000010  00 00 00 00  42 5a 7d 5d  05 00 00 00  b7 84 16 a4  │····│BZ}]│····│····│
    00000020  7d 43 8d e4  04 00 00 00  00 00 00 00  21 00 00 00  │}C··│····│····│!···│
    00000030  00 00 00 00  63 63 63 00  00 00 00 00  00 00 00 00  │····│ccc·│····│····│
    00000040  00 00                                               │··│
    00000042
aaaaa!BZ}]���}C��!ccc[DEBUG] Received 0x46 bytes:
```

이와 같이 `add_data` 함수에 존재하는 off-by-one 버그를 헥스 에디터를 사용해 패치하여 취약점을 보완해 보겠습니다. 우선 디스어셈블러를 이용해 버그의 원인이 된 반복문 탈출 조건이 `add_data` 함수에서 어떤 인스트럭션에 해당하는지 조사해야 합니다. 다음은 GDB로 `add_data` 함수를 디스어셈블한 결과의 일부입니다. 반복문의 카운터 역할을 하는 `[rbp-0x14]` 에 1을 더하고 지역 변수 `[rbp-0x18]` 과 비교하는 부분에서 탈출 조건에 해당하는 코드임을 알 수 있습니다.

```
pwndbg> disass add_data
Dump of assembler code for function add_data:
...
   0x0000000000001428 <+221>:   add    DWORD PTR [rbp-0x14],0x1
   0x000000000000142c <+225>:   mov    edx,DWORD PTR [rbp-0x14]
   0x000000000000142f <+228>:   mov    eax,DWORD PTR [rbp-0x18]
   0x0000000000001432 <+231>:   cmp    edx,eax
   0x0000000000001434 <+233>:   jbe    0x13eb <add_data+160>
   0x0000000000001436 <+235>:   mov    rax,QWORD PTR [rbp-0x10]
```

여기서 정확히 off-by-one 버그의 정확한 원인이 되는 인스트럭션은 `main+233` 의 `jbe` 인스트럭션입니다. `jbe` 인스트럭션은 "jump if below or equal"을 의미하는 조건부 점프 인스트럭션으로, 버그를 패치하기 위해서는 "jump below"에 해당하는 `jb` 인스트럭션으로 바꿔야 합니다. 

그런데 GDB의 내장 디스어셈블러가 편의상 `jbe 0x13eb` 와 같이 출력하는 것과 달리, 조건부 점프 인스트럭션은 실제로는 점프할 주소까지의 상대적인 오프셋을 인자로 인코딩합니다. 따라서 먼저 바꿔야 하는 인스트럭션의 정확한 opcode를 확인한 후, 인자를 정확하게 표현하는 디스어셈블러로 인스트럭션의 원래 형태를 파악하는 것이 좋습니다. GDB를 사용하여 확인한 `jbe` 인스트럭션의 opcode는 `\x76\xb5` 입니다.

```
pwndbg> x/2bx 0x1434
0x1434 <add_data+233>:  0x76    0xb5
```

인스트럭션의 디스어셈블과 어셈블에는 shell-storm.org에서 운영하는 [웹페이지](https://shell-storm.org/online/Online-Assembler-and-Disassembler/)를 사용하는 방법이 가장 간단합니다. 아래와 같이 웹페이지 하단에서 opcode를 입력하고 x86 (64)를 선택한 다음 Disassemble 버튼을 클릭하면, 인스트럭션의 원래 형태는 `jbe 0xffffffffffffffb7` 임을 파악할 수 있습니다.

![3.png](/images/binary-patching/3.png)

다음으로 웹페이지 상단에서 `jb 0xffffffffffffffb7` 를 입력한 후 동일하게 Assemble 버튼을 클릭하면, 새로 바꿀 opcode `\x72\xb5` 를 얻을 수 있습니다.

![4.png](/images/binary-patching/4.png)

이제 헥스 에디터를 이용하여 바이너리를 수정할 차례입니다. 헥스 에디터는 무료 소프트웨어인 [HxD](https://mh-nexus.de/en/hxd/), 상용 소프트웨어인 [010 Editor](https://www.sweetscape.com/010editor/) 등 잘 알려진 소프트웨어가 많으므로 자신이 사용하기 편한 것을 사용하면 됩니다. 이 글에서는 편의상 커맨드라인에서 편집이 가능한 hexedit을 사용하겠습니다. hexedit은 APT를 이용하여 설치할 수 있습니다.

```
sudo apt update && sudo apt install hexedit -y
```

hexedit은 인자로 바이너리의 경로를 전달하여 실행합니다. 주요 단축키는 다음과 같습니다.

|단축키|기능|
|---|---|
|Ctrl+G|지정한 파일 오프셋으로 이동|
|F2|저장|
|Ctrl+X|저장하고 종료|
|Ctrl+C|저장하지 않고 종료|

`main` 바이너리의 복사본 `main.patched` 를 만들고 hexedit으로 열어 오프셋 `0x1434` 로 이동하면 아래와 같이 원래의 인스트럭션에 해당하는 `76 b5` 가 있습니다.

![5.png](/images/binary-patching/5.png)

새로 바꿀 opcode인 `72 b5` 를 입력하고, 저장한 후 종료합니다. 패치된 바이너리의 `add_data` 함수를 GDB로 디스어셈블해보면 `jbe` 인스트럭션이 `jb` 로 바뀐 것을 확인할 수 있습니다.

```
pwndbg> disass add_data
Dump of assembler code for function add_data:
...
   0x0000000000001428 <+221>:   add    DWORD PTR [rbp-0x14],0x1
   0x000000000000142c <+225>:   mov    edx,DWORD PTR [rbp-0x14]
   0x000000000000142f <+228>:   mov    eax,DWORD PTR [rbp-0x18]
   0x0000000000001432 <+231>:   cmp    edx,eax
   0x0000000000001434 <+233>:   jb     0x13eb <add_data+160>
   0x0000000000001436 <+235>:   mov    rax,QWORD PTR [rbp-0x10]
```

패치된 바이너리는 앞서 힙 메모리가 노출되도록 하였던 입력을 전달하여도 더 이상 구조체의 길이 필드가 오염되지 않아 트리거에 실패합니다. 따라서 off-by-one 버그로 인해 발생하였던 취약점이 잘 보완되었음을 알 수 있습니다.

```
$ ./main.patched
...
1. add data
2. delete data
3. show data
4. exit
> 3
index: 0
aaaaaaaaaaaaaaaa
```


## 코드를 삽입해야 하는 경우

이전 문단에서는 간단한 수정이 필요한 경우 헥스 에디터를 사용하여 바이너리를 패치하는 방법을 살펴보았습니다. 그러나 이 방법은 앞서 언급하였던 대로 수정해야 할 내용이 조금만 늘어나도 바꿀 코드를 위치시킬 공간이 부족하여 적용하기 어렵습니다. 예를 들어 패치할 함수가 입력값에 대한 검증을 충분히 하고 있지 않아 검증하는 코드를 직접 추가해야 하는 경우에는 직접 바이너리에 새로운 코드를 삽입하여 메모리에 로드한 후 분기나 호출 부분을 수정하여 실행 흐름을 옮겨야 합니다.

코드를 삽입해야 하는 경우는 새로운 코드를 메모리상에서 로드할 위치와, 기존의 실행 흐름을 돌려 새로운 코드를 실행할 방법을 모두 고려하여야 합니다. 이 글에서는 바이너리에서 실제 동작과 무관한 부분에 코드를 삽입하고, 실행 가능한 영역으로 변경하여 로드하는 방법을 소개합니다. 이 방법의 이해를 위해서는 바이너리의 섹션과 세그먼트 개념에 대한 기초적인 숙지가 필요합니다.


### 섹션과 세그먼트

바이너리의 코드와 데이터들은 논리적으로 섹션(sections)이라는 부분들로 구분되어 있습니다. 모든 섹션에 대해 섹션의 성질이나 섹션에 해당하는 바이트들의 위치를 나타내는 섹션 헤더(section headers)가 존재하며, 모든 섹션 헤더는 섹션 헤더 테이블에 위치하고 있습니다. 유의해야 할 내용은 섹션의 구분은 링커(linker)의 편의를 위한 것으로, 프로세스를 실행하기 위해 모든 섹션이 필요한 것은 아니라는 점입니다. 

다음은 `/usr/include/elf.h` 파일에 정의된 섹션 헤더의 구조입니다. 

```c
typedef struct
{
  Elf64_Word    sh_name;        /* Section name (string tbl index) */
  Elf64_Word    sh_type;        /* Section type */
  Elf64_Xword   sh_flags;       /* Section flags */
  Elf64_Addr    sh_addr;        /* Section virtual addr at execution */
  Elf64_Off sh_offset;      /* Section file offset */
  Elf64_Xword   sh_size;        /* Section size in bytes */
  Elf64_Word    sh_link;        /* Link to another section */
  Elf64_Word    sh_info;        /* Additional section information */
  Elf64_Xword   sh_addralign;       /* Section alignment */
  Elf64_Xword   sh_entsize;     /* Entry size if section holds table */
} Elf64_Shdr;
```

섹션 헤더에서 눈여겨볼 필드들은 다음과 같습니다.

- `sh_type` 필드는 섹션의 타입을 나타내며, 타입은 섹션의 내용 및 구조에 대한 정보를 알려줍니다.
    - `SHT_PROGBITS` 타입은 섹션이 인스트럭션이나 상수와 같은 프로그램 데이터로 이루어져 있음을 나타냅니다.
- `sh_flags` 필드는 섹션 플래그들이며, 섹션에 대한 추가적인 정보를 나타냅니다.
    - `SHF_WRITE` 플래그는 섹션이 런타임에 쓰기 가능함을 나타냅니다.
    - `SHF_ALLOC` 플래그는 섹션의 내용물이 바이너리를 실행할 때 가상 메모리로 로드됨을 나타냅니다.
    - `SHF_EXECINSTR` 플래그는 섹션이 실행 가능한 인스트럭션들을 포함하고 있음을 나타냅니다.
- `sh_addr` , `sh_offset` , `sh_size` 는 각각 섹션의 가상 주소, 파일 오프셋과 크기를 나타냅니다.

```c
#define SHT_PROGBITS      1             /* Program data */

#define SHF_WRITE            (1 << 0)   /* Writable */
#define SHF_ALLOC            (1 << 1)   /* Occupies memory during execution */
#define SHF_EXECINSTR        (1 << 2)   /* Executable */
```

readelf 도구를 이용하여 ELF 바이너리의 섹션에 대한 정보를 확인할 수 있습니다. 다음은 아래의 실습 문단에서 사용할 `example2/main` 바이너리의 섹션 정보를 확인한 예시입니다.

```
$ readelf --sections --wide main
There are 31 section headers, starting at offset 0x3978:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000000318 000318 00001c 00   A  0   0  1
  [ 2] .note.gnu.property NOTE            0000000000000338 000338 000030 00   A  0   0  8
  [ 3] .note.gnu.build-id NOTE            0000000000000368 000368 000024 00   A  0   0  4
  [ 4] .note.ABI-tag     NOTE            000000000000038c 00038c 000020 00   A  0   0  4
  [ 5] .gnu.hash         GNU_HASH        00000000000003b0 0003b0 000030 00   A  6   0  8
  [ 6] .dynsym           DYNSYM          00000000000003e0 0003e0 0001e0 18   A  7   1  8
  [ 7] .dynstr           STRTAB          00000000000005c0 0005c0 000108 00   A  0   0  1
  [ 8] .gnu.version      VERSYM          00000000000006c8 0006c8 000028 02   A  6   0  2
  [ 9] .gnu.version_r    VERNEED         00000000000006f0 0006f0 000050 00   A  7   1  8
  [10] .rela.dyn         RELA            0000000000000740 000740 0000f0 18   A  6   0  8
  [11] .rela.plt         RELA            0000000000000830 000830 000120 18  AI  6  24  8
  [12] .init             PROGBITS        0000000000001000 001000 00001b 00  AX  0   0  4
  [13] .plt              PROGBITS        0000000000001020 001020 0000d0 10  AX  0   0 16
  [14] .plt.got          PROGBITS        00000000000010f0 0010f0 000010 10  AX  0   0 16
  [15] .plt.sec          PROGBITS        0000000000001100 001100 0000c0 10  AX  0   0 16
  [16] .text             PROGBITS        00000000000011c0 0011c0 000539 00  AX  0   0 16
  [17] .fini             PROGBITS        00000000000016fc 0016fc 00000d 00  AX  0   0  4
  [18] .rodata           PROGBITS        0000000000002000 002000 00008e 00   A  0   0  4
  [19] .eh_frame_hdr     PROGBITS        0000000000002090 002090 00005c 00   A  0   0  4
  [20] .eh_frame         PROGBITS        00000000000020f0 0020f0 000148 00   A  0   0  8
  [21] .init_array       INIT_ARRAY      0000000000003d60 002d60 000008 08  WA  0   0  8
  [22] .fini_array       FINI_ARRAY      0000000000003d68 002d68 000008 08  WA  0   0  8
  [23] .dynamic          DYNAMIC         0000000000003d70 002d70 0001f0 10  WA  7   0  8
  [24] .got              PROGBITS        0000000000003f60 002f60 0000a0 08  WA  0   0  8
  [25] .data             PROGBITS        0000000000004000 003000 000010 00  WA  0   0  8
  [26] .bss              NOBITS          0000000000004010 003010 000020 00  WA  0   0 16
  [27] .comment          PROGBITS        0000000000000000 003010 00002b 01  MS  0   0  1
  [28] .symtab           SYMTAB          0000000000000000 003040 000510 18     29  18  8
  [29] .strtab           STRTAB          0000000000000000 003550 000309 00      0   0  1
  [30] .shstrtab         STRTAB          0000000000000000 003859 00011a 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

섹션의 구분은 링커의 편의를 위한 것입니다. 반면 바이너리를 로드할 때 관련있는 코드나 데이터를 함께 취급하거나, 특정 영역의 데이터를 로드할지 여부를 결정하기 위해서 바이너리를 세그먼트(segments) 관점으로도 구분합니다. 세그먼트는 단순히 여러 섹션을 하나로 합쳐 놓은 것입니다. 섹션과 마찬가지로, 모든 세그먼트에 대해 세그먼트의 정보를 나타내는 프로그램 헤더(program headers)가 존재합니다. 모든 프로그램 헤더는 바이너리에서 프로그램 헤더 테이블에 위치하고 있습니다.

다음은 `/usr/include/elf.h` 파일에 정의된 프로그램 헤더의 구조입니다. 

```c
typedef struct
{
  Elf64_Word    p_type;         /* Segment type */
  Elf64_Word    p_flags;        /* Segment flags */
  Elf64_Off p_offset;       /* Segment file offset */
  Elf64_Addr    p_vaddr;        /* Segment virtual address */
  Elf64_Addr    p_paddr;        /* Segment physical address */
  Elf64_Xword   p_filesz;       /* Segment size in file */
  Elf64_Xword   p_memsz;        /* Segment size in memory */
  Elf64_Xword   p_align;        /* Segment alignment */
} Elf64_Phdr;
```

프로그램 헤더에서 눈여겨볼 필드들은 다음과 같습니다.

- `p_type` 필드는 세그먼트의 타입을 나타냅니다.
    - `PT_LOAD` 타입은 프로세스를 실행할 때 메모리에 로드되는 세그먼트를 나타냅니다.
- `p_flags` 필드는 세그먼트 플래그로, 세그먼트에 대한 런타임에서의 권한을 나타냅니다.
    - `PF_X` , `PF_W` , `PF_R` 플래그는 각각 런타임에서 실행 가능, 쓰기 가능, 읽기 가능함을 나타냅니다.
- `p_offset` , `p_vaddr` , `p_filesz` 필드는 각각 세그먼트의 파일 오프셋, 가상 주소와 크기를 나타냅니다.

```c
#define PT_LOAD         1               /* Loadable program segment */

#define PF_X            (1 << 0)        /* Segment is executable */
#define PF_W            (1 << 1)        /* Segment is writable */
#define PF_R            (1 << 2)        /* Segment is readable */
```

세그먼트에 대한 정보도 readelf를 사용하여 확인할 수 있습니다. 특히 어떤 섹션들이 어떤 세그먼트에 속하는지 대응 관계를 보면, 세그먼트는 단지 여러 섹션이 합쳐진 것임을 분명히 알 수 있습니다.

```
$ readelf --segments --wide main

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x11c0
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0002d8 0x0002d8 R   0x8
  INTERP         0x000318 0x0000000000000318 0x0000000000000318 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000950 0x000950 R   0x1000
  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x000709 0x000709 R E 0x1000
  LOAD           0x002000 0x0000000000002000 0x0000000000002000 0x000238 0x000238 R   0x1000
  LOAD           0x002d60 0x0000000000003d60 0x0000000000003d60 0x0002b0 0x0002d0 RW  0x1000
  DYNAMIC        0x002d70 0x0000000000003d70 0x0000000000003d70 0x0001f0 0x0001f0 RW  0x8
  NOTE           0x000338 0x0000000000000338 0x0000000000000338 0x000030 0x000030 R   0x8
  NOTE           0x000368 0x0000000000000368 0x0000000000000368 0x000044 0x000044 R   0x4
  GNU_PROPERTY   0x000338 0x0000000000000338 0x0000000000000338 0x000030 0x000030 R   0x8
  GNU_EH_FRAME   0x002090 0x0000000000002090 0x0000000000002090 0x00005c 0x00005c R   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x002d60 0x0000000000003d60 0x0000000000003d60 0x0002a0 0x0002a0 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
   03     .init .plt .plt.got .plt.sec .text .fini
   04     .rodata .eh_frame_hdr .eh_frame
   05     .init_array .fini_array .dynamic .got .data .bss
   06     .dynamic
   07     .note.gnu.property
   08     .note.gnu.build-id .note.ABI-tag
   09     .note.gnu.property
   10     .eh_frame_hdr
   11
   12     .init_array .fini_array .dynamic .got
```

### `PT_NOTE` 세그먼트를 이용한 코드 삽입

바이너리를 실행하기 위해 모든 섹션이 필요한 것은 아닙니다. 다시 말해 바이너리에서 실행에 필요한 코드나 데이터와는 무관한 공간들이 존재한다는 것입니다. 만약 이 공간에 추가할 코드를 삽입하고, 섹션 헤더와 프로그램 헤더를 변경하여 메모리에 로드해야 하는 코드인 것처럼 꾸미면 우리는 삽입한 코드를 바이너리의 일부였던 것처럼 실행할 수 있습니다.

바이너리의 `PT_NOTE` 세그먼트와, 이 세그먼트를 구성하는 `.note.*` 섹션들은 특히 코드를 삽입하기 좋은 공간입니다. 원래 `.note.*` 섹션들은 아래 `file` 커맨드의 실행 결과에서 "BuildID[sha1]~" 부분과 같이 바이너리의 빌드 id나 제조사와 같은 추가적인 정보를 담기 위해 존재하는 공간입니다. 내용이 없어지거나 변형되어도 실행에 전혀 문제가 되지 않으며, 애초에 프로세스의 실행 도중에는 참조조차 되지 않는 데이터들입니다.

```
$ file main
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fb87af9c421d9b446165d9c00800df1664135edc, for GNU/Linux 3.2.0, not stripped
```

앞서 readelf로 세그먼트를 확인한 예시를 보면 오프셋 `0x368` 에 존재하는 `PT_NOTE` 타입의 8번 세그먼트는 `.note.gnu.build-id` , `.note.ABI-tag` 의 두 개 섹션으로 이루어져 있고, 68바이트의 공간을 차지하는 읽기 전용 세그먼트입니다. 바이너리의 특정 함수에 인자를 검증하는 로직을 추가해야 한다고 가정해 보겠습니다. 추가할 코드를 해당 세그먼트에 삽입하고 기존 코드를 패치해 분기하도록 한 후, 아래와 같이 섹션 헤더와 프로그램 헤더를 변경하면 실행 흐름을 옮길 수 있습니다.

![6.png](/images/binary-patching/6.png)

이 방법을 조금 응용하면 코드의 크기가 68바이트보다 크다고 하여도 새로운 섹션 자체를 추가하여 삽입할 수 있습니다. 코드를 바이너리의 끝부분 이후에 삽입하여 새로운 공간을 만든 후, 섹션 헤더와 프로그램 헤더를 변경하여 새로운 공간의 오프셋을 가리키도록 하면 됩니다. 다만 이 경우에는 가상 주소와 오프셋 필드뿐만 아니라 크기 필드까지 새로운 공간의 크기에 해당하는 값으로 변경해야 합니다. 또한 바이너리의 크기나 섹션의 위치 등을 변경할 수 없다는 제약이 있다면 적용할 수 없습니다.


### double free 버그 패치하기

이번에는 바이너리에 존재하는 double free 버그를 코드를 삽입하는 방법으로 패치해 보겠습니다. `example2/main` 파일이 패치할 바이너리이며, 핵심적인 로직은 이전의 `example1/main` 바이너리와 거의 차이가 없습니다.

`main` 함수를 보면 add 메뉴의 경우 22행에서 `add_data` 함수가 반환한 구조체 포인터를 `s[i]` 에 저장합니다. `s` 는 스택에 존재하는 배열이며, `i` 는 16행의 반복문에서 `s[i]` 가 `NULL` 인 인덱스를 자동으로 선택합니다. delete 메뉴에 해당하는 33행은 인덱스 `i` 를 입력받고, 16보다 작다면 `s[i]` 가 가리키는 구조체를 해제하기 위해 `delete_data` 함수를 호출합니다.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // [rsp+0h] [rbp-A0h] BYREF
  unsigned int i; // [rsp+4h] [rbp-9Ch] BYREF
  __int64 v5; // [rsp+8h] [rbp-98h]
  __int64 s[18]; // [rsp+10h] [rbp-90h] BYREF

  s[17] = __readfsqword(0x28u);
  setup(argc, argv, envp);
  memset(s, 0, 0x80uLL);
  while ( 1 )
  {
  // ...
      if ( v3 == 1 )
      {
        for ( i = 0; i <= 0xF && s[i]; ++i )
          ;
        if ( i <= 0xF )
        {
          v5 = add_data();
          if ( v5 )
            s[i] = v5;
        }
  // ...
      else
      {
        if ( v3 != 2 )
        {
LABEL_22:
          puts("byebye!");
          exit(0);
        }
        printf("index: ");
        __isoc99_scanf("%u", &i);
        if ( i > 0xF )
LABEL_17:
          puts("sorry, there is no data");
        else
          delete_data(s[i]);
      }
    }
  }
}
```

그런데 `delete_data` 함수는 단순히 `free` 함수를 호출하는 것 이외에 별다른 기능을 하지 않습니다. 또한 `main` 함수에서 `s[i]` 를 `NULL` 로 초기화하는 등의 조치를 하지 않고 있어, 해제한 힙 메모리를 다시 해제할 수 있는 double free 버그가 발생합니다. double free 버그를 악용하면 동적 메모리 할당자가 할당 시 임의 주소를 반환하도록 하는 프리미티브를 구성할 수 있습니다. 또한 경우에 따라 임의 읽기 및 쓰기나 코드 실행 취약점으로 연계할 수 있습니다.

다음은 바이너리에서 delete 메뉴를 두 번 선택하고 동일한 인덱스를 입력한 결과입니다. 동적 메모리 할당자 내부에서 double free 버그의 발생을 탐지하여 실행이 강제로 종료되었음을 확인할 수 있습니다.

```
$ ./main
...
1. add data
2. delete data
3. show data
4. exit
> 2
index: 0
1. add data
2. delete data
3. show data
4. exit
> 2
index: 0
free(): double free detected in tcache 2
[1]    20241 IOT instruction  ./main
```

double free 버그를 패치하기 위해서는 `free` 함수의 호출 이후 `s[i]` 가 해제된 힙 포인터를 저장하지 않도록 `NULL` 로 초기화하는 코드를 추가해야 합니다. 원칙적으로는 `free` 함수를 호출하기 이전에 `s[i]` 가 `NULL` 인지 검사하는 조건문 또한 필요하겠으나, 사실 glibc의 `free` 함수 구현체인 `__libc_free` 는 다음과 같이 인자로 주어진 포인터가 `NULL` 인 경우 아무 동작도 하지 않기 때문에 문제가 없습니다. 추가할 코드 길이도 단축할 겸 조건문은 생략하겠습니다.

```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  if (mem == 0)                              /* free(0) has no effect */
    return;
  // ...
```

패치를 위해 `main` 함수에서 delete 메뉴를 처리하는 부분을 살펴보겠습니다. `main+366` 에서 `s[i]` 의 값을 레지스터 `rax` 에 대입한 후, `main+374` 에서 레지스터 `rdi` 로 옮겨 `main+377` 에서 호출하는 `delete_data` 함수의 인자가 되도록 하고 있습니다. 패치에는 여러 방법이 있겠으나, 여기서는 `main+366` 에서 새로 삽입한 코드를 호출하여 `s[i]` 의 초기화와 `free` 함수 호출을 처리하도록 하겠습니다. 호출 이후 `main+382` 의 분기까지는 `nop` 로 덮어 기존의 인스트럭션을 무시하도록 합니다.

```
pwndbg> disass main
Dump of assembler code for function main:
...
   0x000000000000161c <+342>:   call   0x11a0 <__isoc99_scanf@plt>
   0x0000000000001621 <+347>:   mov    eax,DWORD PTR [rbp-0x9c]
   0x0000000000001627 <+353>:   cmp    eax,0xf
   0x000000000000162a <+356>:   ja     0x1649 <main+387>
   0x000000000000162c <+358>:   mov    eax,DWORD PTR [rbp-0x9c]
   0x0000000000001632 <+364>:   mov    eax,eax
   0x0000000000001634 <+366>:   mov    rax,QWORD PTR [rbp+rax*8-0x90]
   0x000000000000163c <+374>:   mov    rdi,rax
   0x000000000000163f <+377>:   call   0x1450 <delete_data>
   0x0000000000001644 <+382>:   jmp    0x16f4 <main+558>
```

새로운 코드를 삽입하기 전 먼저 섹션 헤더와 세그먼트 헤더를 수정하여 코드를 삽입할 공간이 실행 가능한 영역으로 로드되도록 해야 합니다. 섹션 헤더와 세그먼트 헤더를 수정하기 위해서는 바이너리의 섹션 헤더 테이블과 프로그램 헤더 테이블에서 해당하는 부분을 직접 고쳐야 합니다. 상용 프로그램인 010 Editor의 템플릿 기능을 사용하는 방법이 가장 빠르긴 하나, 바이너리를 파싱하여 편집할 수 있도록 도와주는 무료 웹페이지를 사용하는 방법도 못지 않게 간편합니다.

[@preview](https://elfy.io/)

페이지 좌상단의 Open 버튼을 클릭하여 바이너리를 업로드한 후, 왼쪽의 Section headers 메뉴를 클릭하면 섹션 헤더들이 나열됩니다. 이들 중 Elf_Shdr3 , Elf_Shdr4 섹션 헤더가 코드를 삽입할 `.note.gnu.build-id` , `.note.ABI-tag` 섹션에 해당합니다. 각각의 필드를 클릭하면 아래와 같이 페이지 우측에 헥스 에디터와 같은 인터페이스가 표시됩니다. 

![7.png](/images/binary-patching/7.png)

인터페이스의 edit 버튼을 클릭하여 바이트 단위로 편집하고, commit 버튼을 클릭하면 바이너리에 반영할 수 있습니다. 이전 문단의 그림과 같이 `.note.gnu.build-id` , `.note.ABI-tag` 섹션 헤더의 `sh_type` 과 `sh_flags` 필드를 각각 `SHT_PROGBITS` , `SHF_ALLOC | SHF_EXECINSTR` 로 변경합니다. 변경해야 할 값은 섹션 헤더와 프로그램 헤더를 소개한 문단에서 `/usr/include/elf.h` 파일에 정의된 내용을 참고하면 됩니다.

동일한 방법으로 Elf_Phdr8 프로그램 헤더의 `p_type` 필드와 `p_flags` 필드를 `PT_LOAD` , `PF_R | PX_X` 로 변경합니다. 변경을 마친 후 페이지 좌상단의 Save 버튼을 클릭하면 수정사항이 반영된 바이너리를 내려받을 수 있습니다. readelf로 섹션과 세그먼트를 조사해 보면 잘 변경되었음을 확인할 수 있습니다.

```
$ readelf --sections --wide .\main.patched.1
There are 31 section headers, starting at offset 0x3978:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000000318 000318 00001c 00   A  0   0  1
  [ 2] .note.gnu.property NOTE            0000000000000338 000338 000030 00   A  0   0  8
  [ 3] .note.gnu.build-id PROGBITS        0000000000000368 000368 000024 00  AX  0   0  4
  [ 4] .note.ABI-tag     PROGBITS        000000000000038c 00038c 000020 00  AX  0   0  4
...
$ readelf --segments --wide .\main.patched.1

Elf file type is DYN (Shared object file)
Entry point 0x11c0
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0002d8 0x0002d8 R   0x8
  INTERP         0x000318 0x0000000000000318 0x0000000000000318 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000950 0x000950 R   0x1000
  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x000709 0x000709 R E 0x1000
  LOAD           0x002000 0x0000000000002000 0x0000000000002000 0x000238 0x000238 R   0x1000
  LOAD           0x002d60 0x0000000000003d60 0x0000000000003d60 0x0002b0 0x0002d0 RW  0x1000
  DYNAMIC        0x002d70 0x0000000000003d70 0x0000000000003d70 0x0001f0 0x0001f0 RW  0x8
  NOTE           0x000338 0x0000000000000338 0x0000000000000338 0x000030 0x000030 R   0x8
  LOAD           0x000368 0x0000000000000368 0x0000000000000368 0x000044 0x000044 R E 0x4
```

다음으로 삽입할 코드를 작성해 보겠습니다. 삽입할 코드는 `delete_data` 함수를 대신하여 호출되며, 이 코드에서 수행해야 할 작업을 의사코드로 나타내면 다음과 같습니다.

```c
free(s[i]);
s[i] = NULL;
```

따라서 다음과 같이 어셈블리 코드로 옮길 수 있습니다. `call` 인스트럭션은 이후 opcode로 옮길 때 인스트럭션의 위치와 `free@plt` 의 상대적인 오프셋을 인자로 전달해야 하므로, `call 0xd86` 이 되어야 함에 유의합니다.

```x86asm
lea rax, qword ptr [rbp + rax*8 - 0x90]
mov rdi, qword ptr [rax]
mov qword ptr [rax], 0
call free@plt
ret
```

어셈블리 코드를 위에서 사용한 온라인 어셈블러 [웹페이지](https://shell-storm.org/online/Online-Assembler-and-Disassembler/)에서 opcode로 옮긴 후, 헥스 에디터를 이용해 `.note.gnu.build-id` 섹션의 위치인 오프셋 `0x368` 에 덮어씁니다. 또한 `main+366` 부터 `main+382` 까지는 삽입한 코드를 호출하는 `call` 인스트럭션과 `nop` 인스트럭션으로 덮어씁니다. 패치된 바이너리를 디스어셈블하면 최종적으로 다음과 같아야 합니다.

```
pwndbg> disass main
Dump of assembler code for function main:
...
   0x000000000000161c <+342>:   call   0x11a0 <__isoc99_scanf@plt>
   0x0000000000001621 <+347>:   mov    eax,DWORD PTR [rbp-0x9c]
   0x0000000000001627 <+353>:   cmp    eax,0xf
   0x000000000000162a <+356>:   ja     0x1649 <main+387>
   0x000000000000162c <+358>:   mov    eax,DWORD PTR [rbp-0x9c]
   0x0000000000001632 <+364>:   mov    eax,eax
   0x0000000000001634 <+366>:   call   0x368
   0x0000000000001639 <+371>:   nop
   0x000000000000163a <+372>:   nop
   0x000000000000163b <+373>:   nop
   0x000000000000163c <+374>:   nop
   0x000000000000163d <+375>:   nop
   0x000000000000163e <+376>:   nop
   0x000000000000163f <+377>:   nop
   0x0000000000001640 <+378>:   nop
   0x0000000000001641 <+379>:   nop
   0x0000000000001642 <+380>:   nop
   0x0000000000001643 <+381>:   nop
   0x0000000000001644 <+382>:   jmp    0x16f4 <main+558>
...
pwndbg> x/5i 0x368
   0x368:       lea    rax,[rbp+rax*8-0x90]
   0x370:       mov    rdi,QWORD PTR [rax]
   0x373:       mov    QWORD PTR [rax],0x0
   0x37a:       call   0x1100 <free@plt>
   0x37f:       ret
```

패치된 바이너리는 동일한 구조체를 연속으로 해제하려 시도하여도 동적 메모리 할당자에 의해 강제 종료되지 않습니다. 따라서 double free 버그로 인해 발생한 취약점이 잘 보완되었음을 확인할 수 있습니다.

```
$ ./main.patched
...
> 2
index: 0
1. add data
2. delete data
3. show data
4. exit
> 2
index: 0
1. add data
2. delete data
3. show data
4. exit
>
```

## 결론

바이너리 패치는 소스 코드가 없는 바이너리의 동작을 변형해야 하는 상황에서 유용합니다. 패치를 위해서는 디스어셈블러로 패치할 인스트럭션의 위치와 정확한 형태를 먼저 파악한 후, 헥스 에디터로 직접 편집하거나 코드를 삽입한 후 삽입된 코드를 호출하도록 해야 합니다. 코드 삽입에는 섹션 헤더와 프로그램 헤더를 수정하여 실행에 직접적으로 필요하지 않는 섹션을 사용하였으며, 바이너리의 취약점을 패치로 보완하는 실습을 통해 실제로 코드를 삽입하고 실행 흐름을 변형하는 것이 가능함을 확인하였습니다.


## 참고문헌

[1] D. Andriesse, “Chapter 2: The ELF Format,” in *Practical Binary Analysis*. San Francisco, CA: No Starch Press, 2019, pp. 31-55.
[2] D. Andriesse, “Chapter 7: Simple Code Injection Techniques,” in *Practical Binary Analysis*. San Francisco, CA: No Starch Press, 2019, pp. 155-187.
---
title: "C++ 예외 처리의 구현"
date: 2022-07-17 22:49:43
tags:
categories: [Security, Reverse Engineering]
---

## 개요

C++의 예외 처리에 사용되는 try-catch 구문을 컴파일러 수준에서 어떻게 구현하고 있는지 살펴보겠습니다.


## 예외 처리

### try-catch 구문

예외 처리(exception handling)는 프로그램의 실행 중 발생하는 비정상적인 상황에 대응하기 위한 방법론을 의미합니다. 예외 처리를 사용하는 프로그램은 보통 비정상 상황을 발견하고 예외를 일으키는 부분과 예외에 대응하는 부분이 나누어져 있습니다. C++의 예외 처리는 throw 구문으로 예외를 일으키고, try-catch 구문으로 예외에 대응하는 방식을 사용하고 있습니다.

throw 구문은 인자를 받아 예외를 일으킵니다. 일반적으로 `std::exception` 을 상속한 `std::runtime_error` 등의 예외 클래스를 인자로 사용하지만, 실제로는 정수형 값이나 문자열 등 아무 값이나 인자로 전달할 수 있습니다.

```cpp
if (password.length() < 8) {
    throw std::runtime_error("Error");
}
```

try-catch 구문은 try 블록과 catch 블록으로 나누어집니다. try 블록 이후에 하나 이상의 catch 블록이 이어지며, try 블록의 코드에서 발생한 예외에 대해 catch 블록의 코드가 대응합니다. catch 블록은 자신이 대응할 예외의 타입을 선언하여 해당하는 타입의 예외가 발생하였을 경우에만 코드를 실행합니다. 만약 발생한 예외에 해당하는 catch 블록이 존재하지 않아 예외를 처리할 수 없으면 내부적으로 `std::terminate` 함수를 호출하여 프로그램을 종료합니다.

```cpp
std::string s = "hello";

try {
    s.substr(11);
} catch (const std::exception& e) {
    std::cout << e.what() << "\n";  // basic_string::substr: __pos (which is 11) > this->size() (which is 5)
}
```

throw 구문이 예외를 일으키면 프로그램은 호출 스택을 거슬러 올라가며 예외를 처리해줄 catch 블록을 검색합니다. 이 과정을 스택 되감기(stack unwinding)라고 합니다. 스택을 되감는 도중 예외가 발생한 지점과 catch 블록 사이의 코드에서 선언한 객체에 대해서는 자동으로 소멸자를 호출하도록 되어 있습니다. 이는 C++의 RAII(Resource Acquision is Initialization) 원칙을 따르기 위함입니다. RAII는 자원의 누수(leak)를 막기 위해 객체의 수명이 끝날 때 객체가 획득한 자원도 해제하도록 하는 원칙입니다. 예외가 발생한 경우 생성한 객체의 소멸자를 호출하는 코드에 도달할 수 없으므로 직접 호출해주는 것입니다.

다음 그림이 나타내는 코드는 `main` 함수의 try 블록에서 `func` 함수를 호출합니다. `func` 함수는 `MyClass` 객체를 할당한 후 `func2` 함수를 호출하고, `func2` 함수 내에서 예외가 발생합니다. 보라색으로 표시한 코드는 스택을 되감는 부분으로, 스택을 한 번 되감은 후 `func` 함수가 할당한 `MyClass` 객채의 소멸자를 호출하고 있습니다.

![1.png](/images/cpp-exception-handling/1.png)

위의 내용을 코드로 나타내면 다음과 같습니다. 컴파일하고 실행하면 `main` 함수의 catch 블록에 도달하기 전 `MyClass` 객체의 소멸자가 호출되며 "destructor called." 문자열을 출력합니다.

```cpp
#include <stdio.h>

class MyClass {
public:
    MyClass() { printf("constructor called.\n"); }
    ~MyClass() { printf("destructor called.\n"); }
};

void func2(int n) {
    printf("n: %d\n", n);

    if (n == 0) { throw 1; }
}

void func() {
    MyClass m;

    printf("calling func2.\n");
    func2(0);
}

int main() {
    try {
        printf("calling func.\n");
        func();
    } catch (const int& e) {
        printf("catch block in main.\n");
    }

    return 0;
}
```

```
$ g++ eh1.cc -o eh1 -no-pie
$ ./eh1
calling func.
constructor called.
calling func2.
n: 0
destructor called.
catch block in main.
```


### SJLJ

try-catch 구문을 이용한 예외처리를 구현하기 위해서는 함수의 범위를 뛰어넘는(non-local) 분기를 사용해야 합니다. 예외가 발생하는 부분과 예외에 대응하는 catch 블록이 항상 같은 함수 내에 있다는 보장이 없기 때문입니다. 초기의 컴파일러들은 try-catch 구문을 `setjmp` , `longjmp` 라이브러리 함수를 이용하여 구현하였습니다. 이 방식을 SJLJ 방식이라 합니다. 

`setjmp` 함수는 분기를 통해 실행 흐름이 돌아올 곳을 지정합니다. `jmp_buf` 타입을 인자로 받고, 최초 실행 시 `jmp_buf` 에 실행 환경(e.g. 스택 포인터, 인스트럭션 포인터 등)을 저장한 후 0을 반환합니다. `longjmp` 함수는 `jmp_buf` 타입과 정수형 값 `val` 을 인자로 받고, 실행 환경을 저장했던 위치로 흐름을 돌려 `setjmp` 함수를 호출합니다. 호출된 `setjmp` 함수는 `val` 을 반환합니다. 이전 문단의 예외 처리 예제를 `setjmp` , `longjmp` 함수로 작성하면 다음과 같습니다.

```cpp
#include <stdio.h>
#include <setjmp.h>

class MyClass {
public:
    MyClass() { printf("constructor called.\n"); }
    ~MyClass() { printf("destructor called.\n"); }
};

jmp_buf env;

void func2(int n) {
    printf("n: %d\n", n);

    if (n == 0) { longjmp(env, 1); }
}

void func() {
    MyClass m;

    printf("calling func2.\n");
    func2(0);
}

int main() {
    if (setjmp(env) == 0) {                 // try
        printf("calling func.\n");
        func();
    } else {                                // catch
        printf("catch block in main.\n");
    }

    return 0;
}
```

```
$ ./eh2
calling func.
constructor called.
calling func2.
n: 0
catch block in main.
```

그런데 컴파일하고 실행하면 try-catch 구문을 사용하였을 때와는 다르게 `MyClass` 의 소멸자가 자동으로 호출되지 않습니다. `setjmp` 와 `longjmp` 함수는 단순히 분기만을 수행하기 때문입니다. 따라서 SJLJ 방식의 예외 처리에서 도중에 생성된 객체를 소멸시키기 위해서는 그림과 같이 스택을 하나 두고, 객체를 생성할 때마다 객체와 소멸자를 푸시하여야 합니다. 이후 예외를 발생시킬 때 스택을 순회하며 소멸자를 호출한 후 `longjmp` 함수를 호출해야 합니다.

![2.png](/images/cpp-exception-handling/2.png)


### Zero-cost 예외 처리

SJLJ 방식의 예외 처리는 구현이 단순하지만 예외가 발생하지 않는 상황에서도 오버헤드를 강제한다는 단점이 있습니다. try 블록 하나 당 스택과 `jmp_buf` 가 하나씩 필요하며, 예외 발생 여부와 관계없이 객체를 생성할 때마다 푸시와 팝을 반복해야 하기 때문입니다. 이 경우 복잡한 프로그램에서는 예외 처리를 사용하는 것만으로 적지 않은 성능 저하를 일으킬 수 있습니다.

인텔(Intel) 사는 2001년 아이테니엄(Itanium, IA-64) 아키텍처를 설계하면서 예외가 없으면 오버헤드도 없는 예외 처리 방식을 제안하였습니다. 이 방식을 zero-cost 예외 처리(zero-cost exception handling)이라고 합니다. 새로운 방식은 컴파일러 개발자들에 의해 채택되어 다른 아키텍처로도 포팅되었고, 지금은 일반적으로 컴파일을 수행하면 기본값으로 적용하는 표준 방식이 되었습니다. Zero-cost 예외 처리의 구현을 살펴보기 위해서는 먼저 랜딩 패드의 개념을 이해해야 합니다.

랜딩 패드(landing pad)는 프로그램 코드의 일부로, 예외가 발생했을 때 대응하거나 객체의 자원 할당을 해제하는 등의 cleanup 작업을 위한 부분입니다. 앞서 컴파일한 `eh1` 바이너리에는 두 개의 랜딩 패드가 존재합니다. `func` 함수의 `MyClass` 객체를 소멸시키는 코드와 `main` 함수의 catch 블록입니다. `func` 함수의 그래프를 보면 보라색 블록과 같이 실행 흐름과 동떨어진 코드가 있습니다. 이 코드가 바로 `MyClass` 객체의 소멸자를 호출하는 랜딩 패드입니다.

![3.png](/images/cpp-exception-handling/3.png)

`main` 함수의 그래프에서도 보라색 블록으로 나타낸, 문자열을 출력하고 0을 반환하는 블록으로 이어지는 코드가 있습니다. 이 코드 또한 랜딩 패드이며, 소스 코드 상에서 catch 블록에 해당합니다. 예외가 발생하면 스택 되감기를 수행하면서 `func` 함수의 랜딩 패드와 `main` 함수의 랜딩 패드를 순서대로 방문하게 됩니다. 전자는 소멸자 호출 후 `_Unwind_Resume` 함수를 호출하여 스택 되감기를 계속하지만, 후자는 스택 되감기를 마치고 실행 흐름으로 돌아온다는 차이가 있습니다.

![4.png](/images/cpp-exception-handling/4.png)

앞서 try-catch 구문을 사용하면 호출 스택의 중간에서 생성된 객체는 자동으로 소멸자를 호출한다고 하였습니다. 이는 사실 컴파일러가 소멸자 호출이 필요한 함수에 미리 랜딩 패드를 준비하고, 스택 되감기 과정에서 랜딩 패드를 순서대로 방문하도록 하기 때문입니다. 그런데 어떻게 프로그램이 `setjmp` , `longjmp` 함수를 사용하지 않고도 실행 흐름을 되돌리고, 랜딩 패드를 찾아서 방문할 수 있을까요? Zero-cost 예외 처리 방식의 내부 원리에 대해 더 깊이 살펴보겠습니다.


## DWARF CFI

프로그램이 `setjmp` , `longjmp` 함수 없이도 실행 흐름을 돌릴 수 있는 이유는 바이너리의 디버그 데이터에 스택 되감기에 필요한 정보가 인코딩되어있기 때문입니다. DWARF는 ELF 실행 파일을 위한 디버그 데이터 형식으로 소스 코드 수준의 디버깅을 위한 다양한 정보를 제공하고 있습니다. 이 중 호출 프레임 정보(call frame information)가 기록된 `.eh_frame` 섹션이 바로 스택 되감기에 필요한 부분입니다.

일반적으로 함수를 호출할 때 리턴 주소를 스택에 푸시합니다. 이후 함수 프롤로그에서 이전 함수의 프레임 포인터를 푸시하고, 값을 보존해야 할 레지스터들이 있다면 추가로 푸시합니다. 그렇기 때문에 그림과 같이 스택에서 특정 주소를 기준으로 조사하면 이전 함수의 인스트럭션 포인터, 프레임 포인터, 레지스터 값들을 모두 알아낼 수 있습니다. 이 때 기준이 되는 주소를 CFA(cannonical frame address)라고 하며, 보통 함수를 호출하기 직전의 스택 포인터를 CFA로 정의합니다.

![5.png](/images/cpp-exception-handling/5.png)

이전 함수의 프레임에서 사용하는 값을 모두 복원할 수 있다면 스택을 되감을 수 있습니다. `.eh_frame` 섹션은 이를 위해 개념적으로 다음과 같은 호출 프레임 테이블을 준비합니다.

```
LOC CFA R0  R1  ... RN
L0
L1
...
LN
```

테이블에서 LOC 열은 코드 영역의 모든 주소를 나타냅니다. CFA 열은 해당 주소의 코드 문맥에서 CFA를 어떻게 계산하는지 나타냅니다. (e.g. `RSP + 8`) R1, ... , RN 열은 아키텍처의 범용 레지스터들에 대응하며, 이전 프레임에서 사용 중이던 해당 레지스터의 값이 CFA를 기준으로 어디에 대응하는지 나타냅니다. (e.g. `*(CFA - 24)`) 즉, 이 테이블은 코드 상의 모든 주소에서 이전 함수로 스택을 되감을 수 있도록 필요한 정보를 제공하고 있는 것입니다.

그런데 실제로 모든 주소에 대한 호출 프레임 테이블을 인코딩한다면 바이너리에서 프로그램 코드보다 테이블이 차지하는 비중이 너무 많아 용량이 상당히 커질 것입니다. 따라서 `.eh_frame` 섹션은 사실 테이블이 아니라 테이블의 특정 행을 어떻게 구성해야 하는지 지시하는 바이트코드로 되어 있습니다. 이 바이트코드는 호출 프레임 인스트럭션(call frame instruction)이라는 별도의 형식을 갖고 있으며, CIE(common information entry)와 FDE(frame description entry)라는 구조체에 나누어 저장되어 있습니다. 런타임에서는 예외가 발생한 주소에 해당하는 CIE와 FDE를 찾은 후 바이트코드가 지시하는 대로 이전 프레임에서 사용하는 값들을 복원하면서 호출 스택을 한 단계씩 되감습니다.


### CIE와 FDE

CIE와 FDE는 이전 프레임의 값들을 복원하기 위한 호출 프레임 인스트럭션들을 비롯하여 여러 가지 정보가 저장된 구조체입니다. CIE는 여러 개의 FDE에서 공통적으로 사용하는 정보을 포함하고 있으며, CIE의 인스트럭션은 FDE의 인스트럭션을 실행하기 전 먼저 실행됩니다. FDE는 특정 함수와 같이 제한적인 주소 범위에서만 유효한 정보를 포함하고 있습니다. CIE의 내용 중 중요한 필드들을 나열하면 다음과 같습니다.

1. `CIE_id` 
    - CIE의 식별자입니다.
2. `augmentation` 
    - 스택 되감기에 있어 특정 프로그래밍 언어에서 요구하는 내용이 있는지 나타냅니다. 예외 처리와 관련된 내용으로는 personality 루틴의 존재 여부와 LSDA의 위치를 포함하고 있는데, 후술합니다.
3. `return_address_register` 
    - 테이블의 R1, ... , RN 중 어떤 레지스터의 값이 해당 프레임에서 리턴 주소에 해당하는지 나타냅니다.
4. `code_alignment_factor`
    - 테이블의 행에 해당하는 코드 주소를 계산하기 위해 주어진 오프셋에 곱하는 상수 값인데, 후술합니다.
5. `data_alignment_factor`
    - 스택에서 CFA를 기준으로 특정 주소에 접근하기 위해 주어진 오프셋에 곱하는 상수 값인데, 후술합니다.
6. `initial_instructions`
    - 테이블의 행을 구성하기 위해 가장 먼저 수행해야 하는 호출 프레임 인스트럭션들입니다.

FDE의 내용 중 중요한 필드들은 다음과 같습니다.

1. `CIE_pointer`
    - 이 FDE가 종속된 CIE를 가리킵니다.
2. `initial_location`
    - 테이블에서 이 FDE가 나타내는 행들의 시작 주소를 가리킵니다.
3. `address_range`
    - FDE가 나타내는 행들이 시작 주소로부터 몇 바이트만큼 떨어진 주소까지 유효한지 나타냅니다.
4. `instructions`
    - 테이블의 행을 구성하기 위해 수행하는 호출 프레임 인스트럭션들입니다.

즉, `.eh_frame` 섹션에서 CIE와 FDE들의 관계는 그림과 같습니다.

![6.png](/images/cpp-exception-handling/6.png)


## 호출 프레임 인스트럭션

호출 프레임 인스트럭션은 특정 주소의 코드에서 이전 프레임을 복원하여 스택을 되감을 수 있는 방법을 지시하는 바이트코드 형식입니다. 일반적으로 CIE에서 CFA와 리턴 주소를 복원하고, FDE에서 프레임 포인터와 같은 나머지 범용 레지스터를 복원합니다. 자주 사용되는 호출 프레임 인스트럭션들은 다음과 같습니다.

- `DW_CFA_def_cfa` 
    - 레지스터 `RN` 과 오프셋 `offset` 을 받아, CFA를 `RN + offset` 으로 정의합니다.
- `DW_CFA_def_cfa_offset`
    - 오프셋 `offset` 을 받아, CFA를 `RN + offset` 으로 다시 정의합니다. (`RN` 은 기존 값을 사용합니다)
- `DW_CFA_def_cfa_register`
    - 레지스터 `RN` 을 받아, CFA를 `RN + offset` 으로 다시 정의합니다. (`offset` 은 기존 값을 사용합니다)
- `DW_advance_loc` 
    - 상수 `delta` 를 받아, 코드 주소 `initial_location + delta * code_alignment_factor` 에 해당하는 새로운 테이블 행을 추가합니다.
- `DW_CFA_offset`
    - 레지스터 `RN` 과 오프셋 `offset` 을 받아, `RN` 을 주소 `CFA + offset * data_alignment_factor` 의 값으로 복원합니다.

CIE와 FDE에 저장된 호출 프레임 인스트럭션을 `readelf` 커맨드로 읽기 쉽게 출력할 수 있습니다. `readelf` 에 `--debug-dump=frames` 옵션을 주어 `eh1` 바이너리의 호출 프레임 인스트럭션을 확인해 보겠습니다.

```
$ readelf --debug-dump=frames eh1
Contents of the .eh_frame section:


00000000 0000000000000014 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     1b
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_offset: r16 (rip) at cfa-8
  DW_CFA_nop
  DW_CFA_nop

00000018 0000000000000010 0000001c FDE cie=00000000 pc=0000000000401130..000000000040115f
  DW_CFA_advance_loc: 4 to 0000000000401134
  DW_CFA_undefined: r16 (rip)
...
```

`CIE_id` 가 `00000000` 인 CIE의 각종 필드와 인스트럭션, 그리고 이 CIE에 종속된 FDE들의 인스트럭션들을 확인할 수 있습니다. CIE의 인스트럭션들은 `DW_CFA_def_cfa` 로 CFA를 정의하고 `DW_CFA_offset` 으로 R16 (`rip`)을 복원합니다. `return_address_register` 필드가 16이므로 복원한 R16이 이 프레임의 리턴 주소임을 알 수 있습니다.

`func2` 함수의 주소 범위에 대한 FDE를 살펴보며 호출 프레임 인스트럭션을 분석해 보겠습니다. `func` 함수는 주소 `0x401216` 에 위치하며, 함수 프롤로그에서 이전 함수의 `rbp` 값을 스택에 푸시합니다.

```
pwndbg> disass func2
Dump of assembler code for function func2(int):
   0x0000000000401216 <+0>: endbr64
   0x000000000040121a <+4>: push   rbp
   0x000000000040121b <+5>: mov    rbp,rsp
   0x000000000040121e <+8>: sub    rsp,0x10
   ...
   0x0000000000401266 <+80>:    leave
   0x0000000000401267 <+81>:    ret
```

`grep` 을 사용하여 `readelf` 커맨드의 결과로부터 주소 `401216` 부터 시작하는 FDE를 검색합니다. `pc=0000000000401216..0000000000401268` 에서 이 FDE가 `func2` 함수의 주소 범위에 대응하는 엔트리임을 알 수 있으며, `cie=00000000` 에서 `CIE_id` 가 `00000000` 인 CIE에 종속됨을 알 수 있습니다.

```
$ readelf --debug-dump=frames eh1 | grep 401216 -A 10
000000e4 000000000000001c 000000e8 FDE cie=00000000 pc=0000000000401216..0000000000401268
  DW_CFA_advance_loc: 5 to 000000000040121b
  DW_CFA_def_cfa_offset: 16
  DW_CFA_offset: r6 (rbp) at cfa-16
  DW_CFA_advance_loc: 3 to 000000000040121e
  DW_CFA_def_cfa_register: r6 (rbp)
  DW_CFA_advance_loc1: 73 to 0000000000401267
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_nop
  DW_CFA_nop
```

FDE의 인스트럭션들을 보면 `DW_CFA_advance_loc` 을 통해 새로운 행을 만들고, `DW_CFA_def_cfa_offset` 등으로 CFA를 재정의하고 있습니다. 이는 해당 주소에서 `mov rbp,rsp` , `sub rsp,0x10` 와 같은 코드가 실행되어 CIE에서 CFA 계산의 기준이 되었던 `rsp` 의 값이 계속 바뀌기 때문입니다. `func2` 함수에 대해 CIE와 FDE의 인스트럭션을 종합하여 스택 되감기를 위한 테이블로 나타내면 다음과 같습니다.

![7.png](/images/cpp-exception-handling/7.png)


### LSDA

바이너리의 `.eh_frame` 섹션에 있는 CIE와 FDE를 참조하여 스택 되감기가 가능함을 확인하였습니다. 그런데 예외 처리를 위해서는 예외가 발생하였을 때 단순히 리턴 주소로 돌아가는 것이 아니라, 실행 흐름을 호출 스택 상에서 가장 가까운 랜딩 패드로 정확히 돌려야 합니다. 스택 되감기 이후에 추가적인 작업이 필요한 것입니다.

런타임에서 예외 발생 후 스택 되감기를 수행하고 나면, C++ 라이브러리에 구현된 함수가 개입하여 발생한 예외에 해당하는 랜딩 패드로 실행 흐름을 옮깁니다. 이 함수와 같이 특정 언어만의 예외 처리를 위해 제공된 함수를 personality 루틴이라고 합니다. Personality 루틴은 LSDA(language specific data area)라는 영역에 위치한 여러 가지 정보를 해석하여 적절한 랜딩 패드의 위치를 찾아냅니다. `g++` 컴파일러로 컴파일된 바이너리에서 LSDA는 `.gcc_except_table` 섹션에 위치합니다.

C++ 소스 코드상에서 각각의 함수는 서로 다른 LSDA를 가집니다. LSDA는 헤더와 call-site 테이블, 액션 테이블로 이루어져 있습니다. Personality 루틴은 LSDA 헤더를 읽어 함수 코드 내에서 랜딩 패드의 시작 오프셋을 얻습니다. 그리고 Call-site 테이블에서 예외가 발생한 주소에 해당하는 레코드를 찾아 랜딩 패드 내에서 분기해야 할 최종 오프셋을 얻으며, action 테이블에서 해당하는 레코드의 오프셋을 얻어 실행 흐름을 돌릴 목적지가 catch 블록인지 cleanup 코드인지 구별합니다. 


## Itanium C++ ABI

런타임에 실제로 스택 되감기와 예외 처리를 수행하는 로직은 인텔이 제안한 아이테니엄 C++ ABI의 예외 처리 부분을 구현한 라이브러리 함수들입니다. 아이테니엄 C++ ABI는 스택 되감기를 구현하는 unwind 라이브러리와, unwind 라이브러리를 기반으로 예외 처리 구현을 위해 작성된 C++ ABI로 구성되어 있습니다. Unwind 라이브러리와 C++ ABI의 소스 코드는 각각 GCC 프로젝트의 `libgcc` , `libstdc++-v3` 경로에 위치합니다.

[@preview](https://github.com/gcc-mirror/gcc)


### Unwind 라이브러리

Unwind 라이브러리에서 스택 되감기는 예외를 발생시키는 것으로 시작합니다. 예외 발생 시 예외 구조체가 전달되며, 라이브러리에서는 이를 다음의 두 단계에 걸쳐 처리합니다.

1. search 단계
    - 스택을 계속 되감으면서 personality 루틴을 반복하여 호출합니다. Personality 루틴이 랜딩 패드를 찾으면 성공하며, 찾지 못할 경우 예외 처리에 실패합니다. 이 단계는 스택을 되감으면서 각 프레임의 내용을 참조하지만, 실제로 실행 흐름까지 되돌리지는 않습니다.
2. cleanup 단계
    - 다시 스택을 되감으면서 personality 루틴을 반복하여 호출합니다. 랜딩 패드를 찾는 순간 레지스터 값들을 복원하여 실행 흐름을 랜딩 패드로 옮깁니다.

Unwind 라이브러리에서 사용하는 중요한 구조체로는 `_Unwind_Exception` 과 `_Unwind_Context` 가 있습니다. `_Unwind_Exception` 는 발생한 예외를 나타내는 구조체입니다. 구조체에서 `exception_class` 필드는 예외를 발생시킨 프로그래밍 언어와 구현체에 대한 정보를 나타내며, C++ 예외는 하위 4바이트가 `"C++\0"` 로 되어 있습니다. 나머지 필드는 Java와 같은 외부 언어에서 발생한 예외와 관련된 필드입니다.

```cpp
/* The unwind interface uses a pointer to an exception header object
   as its representation of an exception being thrown. In general, the
   full representation of an exception object is language- and
   implementation-specific, but it will be prefixed by a header
   understood by the unwind interface.  */

struct _Unwind_Exception
{
  _Unwind_Exception_Class exception_class;
  _Unwind_Exception_Cleanup_Fn exception_cleanup;

#if !defined (__USING_SJLJ_EXCEPTIONS__) && defined (__SEH__)
  _Unwind_Word private_[6];
#else
  _Unwind_Word private_1;
  _Unwind_Word private_2;
#endif

  /* @@@ The IA-64 ABI says that this structure must be double-word aligned.
     Taking that literally does not make much sense generically.  Instead we
     provide the maximum alignment required by any type for the machine.  */
} __attribute__((__aligned__));
```

`_Unwind_Context` 는 특정 프레임에서 레지스터들의 값과 CFA, 리턴 주소 등 스택 되감기를 위해 필요한 정보들을 나타내는 구조체입니다. `reg` 배열은 호출 프레임 테이블에서 R1, ... , R16 레지스터의 값에 해당합니다. `cfa` 와 `ra` 필드는 각각 CFA와 리턴 주소를 가리킵니다. `lsda` 필드에는 런타임에 LSDA의 주소를 찾아 대입합니다.

```cpp
/* This is the register and unwind state for a particular frame.  This
   provides the information necessary to unwind up past a frame and return
   to its caller.  */
struct _Unwind_Context {
    _Unwind_Context_Reg_Val reg[__LIBGCC_DWARF_FRAME_REGISTERS__ + 1];
    void *cfa;
    void *ra;
    void *lsda;
    struct dwarf_eh_bases bases;
    /* Signal frame context.  */
#define SIGNAL_FRAME_BIT ((~(_Unwind_Word)0 >> 1) + 1)
    /* Context which has version/args_size/by_value fields.  */
#define EXTENDED_CONTEXT_BIT ((~(_Unwind_Word)0 >> 2) + 1)
    /* Bit reserved on AArch64, return address has been signed with A or B
       key.  */
#define RA_SIGNED_BIT ((~(_Unwind_Word)0 >> 3) + 1)
    _Unwind_Word flags;
    /* 0 for now, can be increased when further fields are added to
       struct _Unwind_Context.  */
    _Unwind_Word version;
    _Unwind_Word args_size;
    char by_value[__LIBGCC_DWARF_FRAME_REGISTERS__ + 1];
};
```

이외에도 CIE와 FDE의 인스트럭션을 해석하여 구성한 호출 프레임 테이블의 행을 나타내는 `_Unwind_FrameState` 구조체가 있습니다. 아래 정의에서 `reg` 배열은 R1, ... , RN 레지스터들의 값을 복원해야 하는지, 복원한다면 CFA와 오프셋을 기준으로 복원하는지, 다른 레지스터의 값으로 복원하는지 등의 방법을 나타냅니다. `cfa_offset` 과 `cfa_reg` 필드는 CFA를 정의하는 레지스터와 오프셋을 나타냅니다. `personality` 필드에는 런타임에 CIE의 `augmentation` 필드를 읽고 personality 루틴의 주소를 대입합니다.

```cpp
/* The result of interpreting the frame unwind info for a frame.
   This is all symbolic at this point, as none of the values can
   be resolved until the target pc is located.  */
typedef struct
{
  /* Each register save state can be described in terms of a CFA slot,
     another register, or a location expression.  */
  struct frame_state_reg_info
  {
    struct {
      union {
	_Unwind_Word reg;
	_Unwind_Sword offset;
	const unsigned char *exp;
      } loc;
      enum {
	REG_UNSAVED,
	REG_SAVED_OFFSET,
	REG_SAVED_REG,
	REG_SAVED_EXP,
	REG_SAVED_VAL_OFFSET,
	REG_SAVED_VAL_EXP,
	REG_UNDEFINED
      } how;
    } reg[__LIBGCC_DWARF_FRAME_REGISTERS__+1];

    /* Used to implement DW_CFA_remember_state.  */
    struct frame_state_reg_info *prev;

    /* The CFA can be described in terms of a reg+offset or a
       location expression.  */
    _Unwind_Sword cfa_offset;
    _Unwind_Word cfa_reg;
    const unsigned char *cfa_exp;
    enum {
      CFA_UNSET,
      CFA_REG_OFFSET,
      CFA_EXP
    } cfa_how;
  } regs;

  /* The PC described by the current frame state.  */
  void *pc;

  /* The information we care about from the CIE/FDE.  */
  _Unwind_Personality_Fn personality;
  _Unwind_Sword data_align;
  _Unwind_Word code_align;
  _Unwind_Word retaddr_column;
  unsigned char fde_encoding;
  unsigned char lsda_encoding;
  unsigned char saw_z;
  unsigned char signal_frame;
  void *eh_ptr;
} _Unwind_FrameState;
```

이제 Unwind 라이브러리에서 예외를 처리하는 함수들이 어떻게 구현되어 있는지 살펴보겠습니다. 라이브러리에서 반환값이 있는 대부분의 함수는 `_Unwind_Reason_Code` 열거형을 반환합니다. 각각의 값들은 합수의 성공 및 실패 여부, 스택 되감기를 계속 수행해야 하는지 등을 나타냅니다.

```cpp
/* The unwind interface uses reason codes in several contexts to
   identify the reasons for failures or other actions.  */
typedef enum
{
  _URC_NO_REASON = 0,
  _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
  _URC_FATAL_PHASE2_ERROR = 2,
  _URC_FATAL_PHASE1_ERROR = 3,
  _URC_NORMAL_STOP = 4,
  _URC_END_OF_STACK = 5,
  _URC_HANDLER_FOUND = 6,
  _URC_INSTALL_CONTEXT = 7,
  _URC_CONTINUE_UNWIND = 8
} _Unwind_Reason_Code;
```

`_Unwind_RaiseException` 함수는 `_Unwind_Exception` 구조체를 받아 예외를 일으키는 함수입니다. 10행은 `this_context` 와 `cur_context` 를 현재 스택 프레임의 내용으로 초기화합니다. 15행은 search 단계에 해당하는 반복문으로, personality 루틴이 랜딩 패드를 찾아낸 경우에만 탈출할 수 있습니다. 20행은 `cur_context` 프레임에 해당하는 CIE와 FDE를 읽고 `_Unwind_FrameState` 구조체 `fs` 를 초기화하는 내장 함수를 호출합니다. 32행은 personality 루틴이 있다면 호출합니다. 42행은 `fs` 를 반영하여 `cur_context` 가 이전 프레임의 내용을 나타내도록 합니다.

 반복문 이후는 cleanup 단계를 수행하고 실행 흐름을 되돌리는 부분입니다. 51행은 `_Unwind_RaiseException_Phase2` 함수를 호출하여 cleanup 단계를 수행합니다. 이 함수가 반환하면 `cur_context` 는 실행 흐름을 옮길 랜딩 패드의 내용을, `frames` 변수는 되감아야 할 스택 프레임의 개수를 나타내게 됩니다. 55행은 `cur_context` 의 내용을 실제 레지스터에 반영하여 실행 흐름을 옮기는 매크로를 호출합니다. 따라서 랜딩 패드를 찾지 못하는 등의 실패가 발생하지 않는 이상 `_Unwind_RaiseException` 함수는 반환하지 않으며, 랜딩 패드로 곧바로 분기하여 실행 흐름을 이어갑니다.

```cpp
/* Raise an exception, passing along the given exception object.  */

_Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_RaiseException(struct _Unwind_Exception *exc) {
    struct _Unwind_Context this_context, cur_context;
    _Unwind_Reason_Code code;
    unsigned long frames;

    /* Set up this_context to describe the current stack frame.  */
    uw_init_context(&this_context);
    cur_context = this_context;

    /* Phase 1: Search.  Unwind the stack, calling the personality routine
       with the _UA_SEARCH_PHASE flag set.  Do not modify the stack yet.  */
    while (1) {
        _Unwind_FrameState fs;

        /* Set up fs to describe the FDE for the caller of cur_context.  The
       first time through the loop, that means __cxa_throw.  */
        code = uw_frame_state_for(&cur_context, &fs);

        if (code == _URC_END_OF_STACK)
            /* Hit end of stack with no handler found.  */
            return _URC_END_OF_STACK;

        if (code != _URC_NO_REASON)
            /* Some error encountered.  Usually the unwinder doesn't
               diagnose these and merely crashes.  */
            return _URC_FATAL_PHASE1_ERROR;

        /* Unwind successful.  Run the personality routine, if any.  */
        if (fs.personality) {
            code = (*fs.personality)(1, _UA_SEARCH_PHASE, exc->exception_class,
                                     exc, &cur_context);
            if (code == _URC_HANDLER_FOUND)
                break;
            else if (code != _URC_CONTINUE_UNWIND)
                return _URC_FATAL_PHASE1_ERROR;
        }

        /* Update cur_context to describe the same frame as fs.  */
        uw_update_context(&cur_context, &fs);
    }

    /* Indicate to _Unwind_Resume and associated subroutines that this
       is not a forced unwind.  Further, note where we found a handler.  */
    exc->private_1 = 0;
    exc->private_2 = uw_identify_context(&cur_context);

    cur_context = this_context;
    code = _Unwind_RaiseException_Phase2(exc, &cur_context, &frames);
    if (code != _URC_INSTALL_CONTEXT)
        return code;

    uw_install_context(&this_context, &cur_context, frames);
}
```

`uw_frame_state_for` 내장 함수는 `_Unwind_Context` 구조체 `context` 를 받아 프레임에 해당하는 CIE와 FDE의 호출 프레임 인스트럭션을 해석하여 `_Unwind_FrameState` 구조체 `fs` 를 초기화합니다. 19행과 34행에서 CIE와 FDE의 주소를 찾고, 35행에서 `extract_cie_info` 내장 함수를 호출하여 CIE의 필드를 읽고 `fs` 구조체에서 해당하는 값들을 초기화합니다. `fs` 의 `personality` 필드는 이 함수 내에서 초기화됩니다. 이후 42행과 64행에서 `execute_cfa_program` 내장 함수를 호출하여 호출 프레임 인스트럭션을 해석하고 CFA 및 레지스터들과 관련된 내용을 초기화합니다.

```cpp
/* Given the _Unwind_Context CONTEXT for a stack frame, look up the FDE for
   its caller and decode it into FS.  This function also sets the
   args_size and lsda members of CONTEXT, as they are really information
   about the caller's frame.  */

static _Unwind_Reason_Code
uw_frame_state_for(struct _Unwind_Context *context, _Unwind_FrameState *fs) {
    const struct dwarf_fde *fde;
    const struct dwarf_cie *cie;
    const unsigned char *aug, *insn, *end;

    memset(fs, 0, sizeof(*fs));
    context->args_size = 0;
    context->lsda = 0;

    if (context->ra == 0)
        return _URC_END_OF_STACK;

    fde = _Unwind_Find_FDE(context->ra + _Unwind_IsSignalFrame(context) - 1,
                           &context->bases);
    if (fde == NULL) {
#ifdef MD_FALLBACK_FRAME_STATE_FOR
        /* Couldn't find frame unwind info for this function.  Try a
       target-specific fallback mechanism.  This will necessarily
       not provide a personality routine or LSDA.  */
        return MD_FALLBACK_FRAME_STATE_FOR(context, fs);
#else
        return _URC_END_OF_STACK;
#endif
    }

    fs->pc = context->bases.func;

    cie = get_cie(fde);
    insn = extract_cie_info(cie, context, fs);
    if (insn == NULL)
        /* CIE contained unknown augmentation.  */
        return _URC_FATAL_PHASE1_ERROR;

    /* First decode all the insns in the CIE.  */
    end = (const unsigned char *)next_fde((const struct dwarf_fde *)cie);
    execute_cfa_program(insn, end, context, fs);

    /* Locate augmentation for the fde.  */
    aug = (const unsigned char *)fde + sizeof(*fde);
    aug += 2 * size_of_encoded_value(fs->fde_encoding);
    insn = NULL;
    if (fs->saw_z) {
        _uleb128_t i;
        aug = read_uleb128(aug, &i);
        insn = aug + i;
    }
    if (fs->lsda_encoding != DW_EH_PE_omit) {
        _Unwind_Ptr lsda;

        aug = read_encoded_value(context, fs->lsda_encoding, aug, &lsda);
        context->lsda = (void *)lsda;
    }

    /* Then the insns in the FDE up to our target PC.  */
    if (insn == NULL)
        insn = aug;
    end = (const unsigned char *)next_fde(fde);
    execute_cfa_program(insn, end, context, fs);

    return _URC_NO_REASON;
}
```

`_Unwind_RaiseException_Phase2` 함수는 cleanup 단계를 분리하여 작성한 함수입니다. 전반적인 로직은 호출자인 `_Unwind_RaiseException` 함수와 거의 동일합니다. `frames` 변수를 통해 되감을 스택 프레임의 개수를 세고, personality 루틴을 호출할 때 `_UA_CLEANUP_PHASE` 플래그를 전달하여 cleanup 단계임을 알 수 있도록 하는 차이가 있습니다. Personality 루틴이 랜딩 패드를 찾아 `_URC_INSTALL_CONTEXT` 코드를 반환하면 반복문을 탈출합니다.

```cpp
/* Subroutine of _Unwind_RaiseException also invoked from _Unwind_Resume.

   Unwind the stack calling the personality routine to find both the
   exception handler and intermediary cleanup code.  We'll only locate
   the first such frame here.  Cleanup code will call back into
   _Unwind_Resume and we'll continue Phase 2 there.  */

static _Unwind_Reason_Code
_Unwind_RaiseException_Phase2(struct _Unwind_Exception *exc,
                              struct _Unwind_Context *context,
                              unsigned long *frames_p) {
    _Unwind_Reason_Code code;
    unsigned long frames = 1;

    while (1) {
        _Unwind_FrameState fs;
        int match_handler;

        code = uw_frame_state_for(context, &fs);

        /* Identify when we've reached the designated handler context.  */
        match_handler = (uw_identify_context(context) == exc->private_2
                             ? _UA_HANDLER_FRAME
                             : 0);

        if (code != _URC_NO_REASON)
            /* Some error encountered.  Usually the unwinder doesn't
               diagnose these and merely crashes.  */
            return _URC_FATAL_PHASE2_ERROR;

        /* Unwind successful.  Run the personality routine, if any.  */
        if (fs.personality) {
            code = (*fs.personality)(1, _UA_CLEANUP_PHASE | match_handler,
                                     exc->exception_class, exc, context);
            if (code == _URC_INSTALL_CONTEXT)
                break;
            if (code != _URC_CONTINUE_UNWIND)
                return _URC_FATAL_PHASE2_ERROR;
        }

        /* Don't let us unwind past the handler context.  */
        gcc_assert(!match_handler);

        uw_update_context(context, &fs);
        _Unwind_Frames_Increment(context, frames);
    }

    *frames_p = frames;
    return code;
}
```

`_Unwind_Resume` 함수는 catch 블록이 아닌, 자원 해제 등을 수행하는 cleanup 코드에서 필요한 작업을 마치고 스택을 계속 되감기 위해 호출하는 함수입니다. 앞서 `eh1` 바이너리의 `func` 함수 그래프를 캡쳐한 그림을 보면 랜딩 패드의 마지막 부분에서 `_Unwind_Resume` 함수를 호출하는 것을 확인할 수 있습니다. 이 함수를 호출하는 시점에서는 이미 search 단계를 수행하여 호출 스택 상에서 catch 블록의 존재가 확인된 상태입니다. 따라서 곧바로 `_Unwind_RaiseException_Phase2` 함수를 호출해 cleanup 단계를 진행하면서 다음 랜딩 패드으로 실행 흐름을 옮깁니다.

```cpp
/* Resume propagation of an existing exception.  This is used after
   e.g. executing cleanup code, and not to implement rethrowing.  */

void LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_Resume(struct _Unwind_Exception *exc) {
    struct _Unwind_Context this_context, cur_context;
    _Unwind_Reason_Code code;
    unsigned long frames;

    uw_init_context(&this_context);
    cur_context = this_context;

    /* Choose between continuing to process _Unwind_RaiseException
       or _Unwind_ForcedUnwind.  */
    if (exc->private_1 == 0)
        code = _Unwind_RaiseException_Phase2(exc, &cur_context, &frames);
    else
        code = _Unwind_ForcedUnwind_Phase2(exc, &cur_context, &frames);

    gcc_assert(code == _URC_INSTALL_CONTEXT);

    uw_install_context(&this_context, &cur_context, frames);
}
```

Unwind 라이브러리 내부에서 예외를 일으키고 스택을 되감는 전반적인 로직을 그림으로 나타내면 다음과 같습니다.

![8.png](/images/cpp-exception-handling/8.png)


### C++ ABI

C\+\+ ABI는 C\+\+ 코드에서 발생한 예외와 unwind 라이브러리 사이를 연결하는 다리 역할을 합니다. C\+\+ ABI에서 사용하는 중요한 구조체로는 `__cxa_exception` 과 `__cxa_eh_globals` 가 있습니다.

`__cxa_exception` 은 C\+\+ 예외를 나타내는 구조체입니다. Unwind 라이브러리에서 사용하는 예외 구조체인 `_Unwind_Exception` 을 포함하면서 추가적인 정보를 갖추고 있습니다. `exceptionType` 필드는 throw 구문에서 전달한 인자의 타입을 나타냅니다. `nextException` 필드는 C\+\+ 예외 구조체들의 스택을 만들기 위해 사용하는데, 후술합니다.

```cpp
// A primary C++ exception object consists of a header, which is a wrapper
// around an unwind object header with additional C++ specific information,
// followed by the exception object itself.

struct __cxa_exception
{
  // Manage the exception object itself.
  std::type_info *exceptionType;
  void (_GLIBCXX_CDTOR_CALLABI *exceptionDestructor)(void *);

  // The C++ standard has entertaining rules wrt calling set_terminate
  // and set_unexpected in the middle of the exception cleanup process.
  std::terminate_handler unexpectedHandler;
  std::terminate_handler terminateHandler;

  // The caught exception stack threads through here.
  __cxa_exception *nextException;

  // How many nested handlers have caught this exception.  A negated
  // value is a signal that this object has been rethrown.
  int handlerCount;

#ifdef __ARM_EABI_UNWINDER__
  // Stack of exceptions in cleanups.
  __cxa_exception* nextPropagatingException;

  // The number of active cleanup handlers for this exception.
  int propagationCount;
#else
  // Cache parsed handler data from the personality routine Phase 1
  // for Phase 2 and __cxa_call_unexpected.
  int handlerSwitchValue;
  const unsigned char *actionRecord;
  const unsigned char *languageSpecificData;
  _Unwind_Ptr catchTemp;
  void *adjustedPtr;
#endif

  // The generic exception header.  Must be last.
  _Unwind_Exception unwindHeader;
};
```

`__cxa_eh_globals` 는 스레드마다 하나씩 존재하는 C\+\+ 예외 구조체들의 스택입니다. `caughtExceptions` 필드는 예외 발생 후 처리가 끝난 예외 구조체들의 연결 리스트입니다. `uncaughtExceptions` 필드는 발생했지만 아직 처리되지 않은 예외들의 개수를 나타냅니다. 현재 스레드의 `__cxa_eh_globals` 구조체는 `__cxa_get_globals` 또는 `__cxa_get_globals_fast` 함수를 통해서 접근할 수 있습니다.

```cpp
// Each thread in a C++ program has access to a __cxa_eh_globals object.
struct __cxa_eh_globals
{
  __cxa_exception *caughtExceptions;
  unsigned int uncaughtExceptions;
#ifdef __ARM_EABI_UNWINDER__
  __cxa_exception* propagatingExceptions;
#endif
};
```

C++ ABI에서 throw 구문으로 발생한 예외를 처리하는 과정은 대략 다음과 같습니다.

1. `__cxa_allocate_exception` 함수를 호출하여 `__cxa_exception` 구조체를 동적 할당합니다.
2. `__cxa_throw` 함수를 호출하면서 할당한 예외 구조체를 인자로 전달합니다. `__cxa_throw` 함수는 반환하지 않으며, 내부적으로 unwind 라이브러리의 `_Unwind_RaiseException` 함수를 호출합니다.
3. `_Unwind_RaiseException` 함수 내부에서 personality 루틴을 호출합니다. Personality 루틴은 LSDA를 해석하여 랜딩 패드의 주소를 구합니다.
4. 랜딩 패드로 점프합니다. 랜딩 패드가 catch 블록인 경우 `__cxa_begin_catch` 함수를 호출하여 예외 구조체를 스택의 꼭대기에 푸시합니다.
5. catch 블록의 끝나면 `__cxa_end_catch` 함수를 호출하여 스택에서 예외 구조체를 팝하고 소멸시킵니다.

대부분의 함수가 위에 작성한 내용과 같이 직관적이고 구현이 단순합니다. 따라서 이 문단에서는 personality 루틴의 구현을 중점적으로 살펴보겠습니다.

GCC의 C++ ABI 구현체에서 personality 루틴의 이름은 `__gxx_personality_v0` 입니다. (LLVM도 동일한 이름을 사용하지만 구현체가 다릅니다) 이 함수는 소스 코드가 복잡하고 ARM 아키텍처를 위한 코드도 중간중간 섞여 있습니다. 이해를 돕기 위해 아래 코드는 원본 코드에서 필요하지 않은 부분은 제외하였습니다.

25행에서 LSDA의 주소를 얻습니다. 44행은 반복문을 사용해 LSDA의 call-site 테이블을 순회하면서 예외가 발생한 코드 주소에 해당하는 레코드를 찾아 랜딩 패드의 주소를 계산하고, 액션 테이블에서의 해당하는 레코드의 오프셋 `action_record` 를 얻습니다. 77행에서 `action_record` 가 0이면 랜딩 패드는 cleanup 코드로, `found_type` 에 `found_cleanup` 을 대입합니다. 이외의 경우 catch 블록에 해당하며, 94행부터 LSDA의 action 테이블을 순회합니다. 발생한 예외의 타입에 대응하는 catch 블록이 존재하는지 확인하고 catch 블록을 찾은 경우 `found_type` 에 `found_handler` 를 대입합니다.

Personality 루틴은 스택 되감기의 search 단계와 cleanup 단계 중 어느 시점에서 호출되었는지에 따라 동작이 다릅니다. 어느 시점에서 호출되었는지는 두 번째 인자 `actions` 의 값이 `_UA_SEARCH_PHASE` 와 `_UA_CLEANUP_PHASE` 중 무엇인지로 구분합니다. 145행에서 현재 search 단계인 경우 발견한 랜딩 패드가 cleanup 코드면 `_URC_CONTINUE_UNWIND`, catch 블록이면 `_URC_HANDLER_FOUND` 를 반환합니다. 반대로 cleanup 단계인 경우 180행에서 `_Unwind_SetIP` 내장 함수를 호출하여 `context->ra` 필드에 랜딩 패드의 주소를 대입하고 `_URC_INSTALL_CONTEXT` 를 반환합니다.

```cpp
#define CONTINUE_UNWINDING                                     \
    do {                                                       \
        if (__gnu_unwind_frame(ue_header, context) != _URC_OK) \
            return _URC_FAILURE;                               \
        return _URC_CONTINUE_UNWIND;                           \
    } while (0)

#define PERSONALITY_FUNCTION __gxx_personality_v0

_Unwind_Reason_Code PERSONALITY_FUNCTION(int version,
                         _Unwind_Action actions,
                         _Unwind_Exception_Class exception_class,
                         struct _Unwind_Exception *ue_header,
                         struct _Unwind_Context *context)
{
    // ...
    // Shortcut for phase 2 found handler for domestic exception.
    if (actions == (_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME) && !foreign_exception) {
        restore_caught_exception(ue_header, handler_switch_value,
                                 language_specific_data, landing_pad);
        found_type = (landing_pad == 0 ? found_terminate : found_handler);
        goto install_context;
    }

    language_specific_data = (const unsigned char *)
        _Unwind_GetLanguageSpecificData(context);

    // If no LSDA, then there are no handlers or cleanups.
    if (!language_specific_data)
        CONTINUE_UNWINDING;

    // Parse the LSDA header.
    p = parse_lsda_header(context, language_specific_data, &info);
    info.ttype_base = base_of_encoded_value(info.ttype_encoding, context);
    ip = _Unwind_GetIP(context);

    if (!ip_before_insn)
        --ip;
    landing_pad = 0;
    action_record = 0;
    handler_switch_value = 0;

    // Search the call-site table for the action associated with this IP.
    while (p < info.action_table) {
        _Unwind_Ptr cs_start, cs_len, cs_lp;
        _uleb128_t cs_action;

        // Note that all call-site encodings are "absolute" displacements.
        p = read_encoded_value(0, info.call_site_encoding, p, &cs_start);
        p = read_encoded_value(0, info.call_site_encoding, p, &cs_len);
        p = read_encoded_value(0, info.call_site_encoding, p, &cs_lp);
        p = read_uleb128(p, &cs_action);

        // The table is sorted, so if we've passed the ip, stop.
        if (ip < info.Start + cs_start)
            p = info.action_table;
        else if (ip < info.Start + cs_start + cs_len) {
            if (cs_lp)
                landing_pad = info.LPStart + cs_lp;
            if (cs_action)
                action_record = info.action_table + cs_action - 1;
            goto found_something;
        }
    }

    // If ip is not present in the table, call terminate.  This is for
    // a destructor inside a cleanup, or a library routine the compiler
    // was not expecting to throw.
    found_type = found_terminate;
    goto do_something;

found_something:
    if (landing_pad == 0) {
        // If ip is present, and has a null landing pad, there are
        // no cleanups or handlers to be run.
        found_type = found_nothing;
    } else if (action_record == 0) {
        // If ip is present, has a non-null landing pad, and a null
        // action table offset, then there are only cleanups present.
        // Cleanups use a zero switch value, as set above.
        found_type = found_cleanup;
    } else {
        // Otherwise we have a catch handler or exception specification.

        _sleb128_t ar_filter, ar_disp;
        const std::type_info *catch_type;
        _throw_typet *throw_type;
        bool saw_cleanup = false;
        bool saw_handler = false;

        thrown_ptr = __get_object_from_ue(ue_header);
        throw_type = __get_exception_header_from_obj(thrown_ptr)->exceptionType;

        while (1) {
            p = action_record;
            p = read_sleb128(p, &ar_filter);
            read_sleb128(p, &ar_disp);

            if (ar_filter == 0) {
                // Zero filter values are cleanups.
                saw_cleanup = true;
            } else if (ar_filter > 0) {
                // Positive filter values are handlers.
                catch_type = get_ttype_entry(&info, ar_filter);

                // Null catch type is a catch-all handler; we can catch foreign
                // exceptions with this.  Otherwise we must match types.
                if (!catch_type || (throw_type && get_adjusted_ptr(catch_type, throw_type,
                                                                   &thrown_ptr))) {
                    saw_handler = true;
                    break;
                }
            } else {
                // Negative filter values are exception specifications.
                // ??? How do foreign exceptions fit in?  As far as I can
                // see we can't match because there's no __cxa_exception
                // object to stuff bits in for __cxa_call_unexpected to use.
                // Allow them iff the exception spec is non-empty.  I.e.
                // a throw() specification results in __unexpected.
                if ((throw_type && !(actions & _UA_FORCE_UNWIND) && !foreign_exception)
                        ? !check_exception_spec(&info, throw_type, thrown_ptr,
                                                ar_filter)
                        : empty_exception_spec(&info, ar_filter)) {
                    saw_handler = true;
                    break;
                }
            }

            if (ar_disp == 0)
                break;
            action_record = p + ar_disp;
        }

        if (saw_handler) {
            handler_switch_value = ar_filter;
            found_type = found_handler;
        } else
            found_type = (saw_cleanup ? found_cleanup : found_nothing);
    }

do_something:
    if (found_type == found_nothing)
        CONTINUE_UNWINDING;

    if (actions & _UA_SEARCH_PHASE) {
        if (found_type == found_cleanup)
            CONTINUE_UNWINDING;

        // For domestic exceptions, we cache data from phase 1 for phase 2.
        if (!foreign_exception) {
            save_caught_exception(ue_header, context, thrown_ptr,
                                  handler_switch_value, language_specific_data,
                                  landing_pad, action_record);
        }
        return _URC_HANDLER_FOUND;
    }

install_context:
    // ...
    } else {
        if (found_type == found_terminate)
            __cxa_call_terminate(ue_header);

        // Cache the TType base value for __cxa_call_unexpected, as we won't
        // have an _Unwind_Context then.
        if (handler_switch_value < 0) {
            parse_lsda_header(context, language_specific_data, &info);
            info.ttype_base = base_of_encoded_value(info.ttype_encoding,
                                                    context);
            xh->catchTemp = base_of_encoded_value(info.ttype_encoding, context);
        }
    }

    /* For targets with pointers smaller than the word size, we must extend the
       pointer, and this extension is target dependent.  */
    _Unwind_SetGR(context, __builtin_eh_return_data_regno(0),
                  __builtin_extend_pointer(ue_header));
    _Unwind_SetGR(context, __builtin_eh_return_data_regno(1),
                  handler_switch_value);
    _Unwind_SetIP(context, landing_pad);

    return _URC_INSTALL_CONTEXT;
}
```

Personality 루틴의 반환값은 unwind 라이브러리의 `_Unwind_RaiseException` 함수의 동작과 큰 연관이 있습니다. `_Unwind_RaiseException` 함수는 search 단계에서 personality 루틴이 `_URC_HANDLER_FOUND` 를 반환할 때까지 스택을 되감으면서 `_Unwind_Context` 구조체의 내용을 갱신합니다. `_URC_HANDLER_FOUND` 의 반환은 예외를 처리할 catch 블록을 발견했다는 신호이자 search 단계의 성공을 나타냅니다. 이어지는 cleanup 단계에서는 `_URC_INSTALL_CONTEXT` 의 반환을 신호로 하여 랜딩 패드로 실행 흐름을 옮깁니다. 랜딩 패드가 catch 블록이면 예외 처리가 끝나며, cleanup 코드면 `_Unwind_Resume` 함수를 호출하여 다음 랜딩 패드로 진행하는 스택 되감기를 시작합니다.

예외가 발생했을 때 C++ ABI와 unwind 라이브러리를 거쳐 처리하는 전체 로직은 다음과 같습니다. 보라색 블록은 프로그램 코드의 일부로 예외가 발생하는 부분과 랜딩 패드, 검은색 블록은 C++ ABI, 회색 블록은 unwind 라이브러리를 나타냅니다.

![9.png](/images/cpp-exception-handling/9.png)


## 라이브러리 동적 분석

`eh1` 바이너리를 동적 분석하면서 예외 처리의 핵심 부분인 `_Unwind_RaiseException` 함수 및 personality 루틴의 동작을 직접 살펴보겠습니다. `_Unwind_RaiseException` 함수 내부에서 다음과 같은 5개 위치에 중단점을 설정합니다.

1. search 단계 반복문 내에서 `uw_frame_state_for` 함수를 호출하는 부분

```x86asm
   0x00007f251026f080 <+304>:   mov    rsi,r13
   0x00007f251026f083 <+307>:   mov    rdi,r12
=> 0x00007f251026f086 <+310>:   call   0x7f251026d800
   0x00007f251026f08b <+315>:   cmp    eax,0x5
   0x00007f251026f08e <+318>:   je     0x7f251026f103 <_Unwind_RaiseException+435>
```

2. search 단계 반복문 내에서 `fs.personality` 필드가 존재하는지 확인하는 부분

```x86asm
   0x00007f4fc4d81092 <+322>:   jne    0x7f4fc4d81160 <_Unwind_RaiseException+528>
   0x00007f4fc4d81098 <+328>:   mov    rax,QWORD PTR [rbp-0x70]
=> 0x00007f4fc4d8109c <+332>:   test   rax,rax
   0x00007f4fc4d8109f <+335>:   je     0x7f4fc4d810c8 <_Unwind_RaiseException+376>
   0x00007f4fc4d810a1 <+337>:   mov    rdx,QWORD PTR [r14]
```

3. search 단계 반복문 내에서 personality 루틴을 호출하는 부분

```x86asm
   0x00007f4fc4d810aa <+346>:   mov    esi,0x1
   0x00007f4fc4d810af <+351>:   mov    edi,0x1
=> 0x00007f4fc4d810b4 <+356>:   call   rax
   0x00007f4fc4d810b6 <+358>:   cmp    eax,0x6
   0x00007f4fc4d810b9 <+361>:   je     0x7f4fc4d81170 <_Unwind_RaiseException+544>
```

4. `_Unwind_RaiseException_Phase2` 함수를 호출하는 부분

```x86asm
   0x00007f4fc4d8126e <+798>:   movups XMMWORD PTR [rbp-0x1e0],xmm0
   0x00007f4fc4d81275 <+805>:   movups XMMWORD PTR [rbp-0x1d0],xmm1
=> 0x00007f4fc4d8127c <+812>:   call   0x7f4fc4d80b50
   0x00007f4fc4d81281 <+817>:   cmp    eax,0x7
   0x00007f4fc4d81284 <+820>:   jne    0x7f4fc4d81103 <_Unwind_RaiseException+435>
```

5. `uw_install_context` 매크로 내에서 랜딩 패드로 점프하는 부분

```x86asm
   0x00007f4fc4d812d5 <+901>:   mov    rsp,rcx
   0x00007f4fc4d812d8 <+904>:   pop    rcx
=> 0x00007f4fc4d812d9 <+905>:   jmp    rcx
```

편의를 위해 다음과 같이 `.gdbinit` 파일을 작성하겠습니다. 이후 `gdb` 를 실행하면 즉시 중단점으로 이동합니다.

```
file eh1
start

break *(_Unwind_RaiseException+310)
break *(_Unwind_RaiseException+332)
break *(_Unwind_RaiseException+356)
break *(_Unwind_RaiseException+812)
break *(_Unwind_RaiseException+905)
continue
```

`gdb` 를 실행하면 `uw_frame_state_for` 함수를 호출하는 1번째 중단점에서 멈춥니다. `context->ra` 필드를 확인하면 `__cxa_throw` 함수에서 `_Unwind_RaiseException` 함수를 호출한 직후의 주소입니다. 현재 `context` 구조체는 `_Unwind_RaiseException` 함수의 프레임을 나타내고 있는 것입니다.

```
Breakpoint 2, 0x00007f845bf3b086 in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> pdisass 1
 ► 0x7f845bf3b086 <_Unwind_RaiseException+310>    call   0x7f845bf39800                <0x7f845bf39800>

   0x7f845bf3b08b <_Unwind_RaiseException+315>    cmp    eax, 5
   0x7f845bf3b08e <_Unwind_RaiseException+318>    je     _Unwind_RaiseException+435                <_Unwind_RaiseException+435>
pwndbg> x/20gx $rdi
0x7ffc2f4d0b70: 0x00007ffc2f4d0de8  0x00007ffc2f4d0df0
0x7ffc2f4d0b80: 0x0000000000000000  0x00007ffc2f4d0df8
0x7ffc2f4d0b90: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0ba0: 0x00007ffc2f4d0e20  0x0000000000000000
0x7ffc2f4d0bb0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bc0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bd0: 0x00007ffc2f4d0e00  0x00007ffc2f4d0e08
0x7ffc2f4d0be0: 0x00007ffc2f4d0e10  0x00007ffc2f4d0e18
0x7ffc2f4d0bf0: 0x00007ffc2f4d0e28  0x0000000000000000
0x7ffc2f4d0c00: 0x00007ffc2f4d0e30  0x00007f845bfef69c
pwndbg> x/4i *(uint64_t *)($rdi+8*19)
   0x7f845bfef69c <__cxa_throw+60>: mov    rdi,rbp
   0x7f845bfef69f <__cxa_throw+63>: call   0x7f845bfdf690 <__cxa_begin_catch@plt>
   0x7f845bfef6a4 <__cxa_throw+68>: call   0x7f845bfdf180 <std::terminate()@plt>
   0x7f845bfef6a9:  nop    DWORD PTR [rax+0x0]
```

`continue` 커맨드로 계속 실행하면 personality 루틴이 존재하지 않아 다시 1번째 중단점으로 돌아옵니다. 이번에는 `context->ra` 필드가 `func2` 함수에서 `__cxa_throw` 함수를 호출한 직후의 주소입니다. 반복문에서 스택을 되감으면서 `context` 구조체가 `__cxa_throw` 함수의 프레임을 나타내고 있음을 확인할 수 있습니다.

```
pwndbg> x/20gx $rdi
0x7ffc2f4d0b70: 0x00007ffc2f4d0de8  0x00007ffc2f4d0df0
0x7ffc2f4d0b80: 0x0000000000000000  0x00007ffc2f4d0df8
0x7ffc2f4d0b90: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0ba0: 0x00007ffc2f4d0e30  0x0000000000000000
0x7ffc2f4d0bb0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bc0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bd0: 0x00007ffc2f4d0e38  0x00007ffc2f4d0e40
0x7ffc2f4d0be0: 0x00007ffc2f4d0e10  0x00007ffc2f4d0e18
0x7ffc2f4d0bf0: 0x00007ffc2f4d0e48  0x0000000000000000
0x7ffc2f4d0c00: 0x00007ffc2f4d0e50  0x0000000000401265
pwndbg> x/4i *(uint64_t *)($rdi+8*19)
   0x401265 <func2(int)+79>:    nop
   0x401266 <func2(int)+80>:    leave
   0x401267 <func2(int)+81>:    ret
   0x401268 <func()>:   endbr64
```

이번에도 personality 루틴이 존재하지 않아 1번째 중단점으로 돌아옵니다. `context` 구조체는 이제 `func2` 함수의 프레임을 나타내고 있습니다.

```
Breakpoint 2, 0x00007f845bf3b086 in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> x/20gx $rdi
0x7ffc2f4d0b70: 0x00007ffc2f4d0de8  0x00007ffc2f4d0df0
0x7ffc2f4d0b80: 0x0000000000000000  0x00007ffc2f4d0df8
0x7ffc2f4d0b90: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0ba0: 0x00007ffc2f4d0e60  0x0000000000000000
0x7ffc2f4d0bb0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bc0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bd0: 0x00007ffc2f4d0e38  0x00007ffc2f4d0e40
0x7ffc2f4d0be0: 0x00007ffc2f4d0e10  0x00007ffc2f4d0e18
0x7ffc2f4d0bf0: 0x00007ffc2f4d0e68  0x0000000000000000
0x7ffc2f4d0c00: 0x00007ffc2f4d0e70  0x00000000004012a6
pwndbg> x/4i *(uint64_t *)($rdi+8*19)
   0x4012a6 <func()+62>:    lea    rax,[rbp-0x19]
   0x4012aa <func()+66>:    mov    rdi,rax
   0x4012ad <func()+69>:    call   0x401382 <MyClass::~MyClass()>
   0x4012b2 <func()+74>:    nop
```

`func2` 함수의 프레임에서 스택을 되감으면 `func` 함수 내의 `MyClass` 객체를 소멸하는 랜딩 패드로 이동해야 합니다. 이를 위해 personality 루틴의 주소가 `fs->personality` 필드에 대입되어 계속 실행하면 3번째 중단점에서 멈추게 됩니다. 다만 personality 루틴의 호출 이후에도 `context->ra` 필드가 랜딩 패드의 주소로 바뀌지는 않습니다. 이는 지금이 search 단계이기 때문입니다. 실제 랜딩 패드 주소를 대입하여 실행 흐름을 옮기는 작업은 cleanup 단계에서 이루어집니다.

```
Breakpoint 4, 0x00007f845bf3b0b4 in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> pdisass 1
 ► 0x7f845bf3b0b4 <_Unwind_RaiseException+356>    call   rax                           <__gxx_personality_v0>
        rdi: 0x1
        rsi: 0x1
        rdx: 0x474e5543432b2b00
        rcx: 0x135f320 ◂— 0x474e5543432b2b00

   0x7f845bf3b0b6 <_Unwind_RaiseException+358>    cmp    eax, 6
   0x7f845bf3b0b9 <_Unwind_RaiseException+361>    je     _Unwind_RaiseException+544                <_Unwind_RaiseException+544>
pwndbg> set $context=$r8
pwndbg> ni
pwndbg> x/20gx $context
0x7ffc2f4d0b70: 0x00007ffc2f4d0de8  0x00007ffc2f4d0df0
0x7ffc2f4d0b80: 0x0000000000000000  0x00007ffc2f4d0df8
0x7ffc2f4d0b90: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0ba0: 0x00007ffc2f4d0e60  0x0000000000000000
0x7ffc2f4d0bb0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bc0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bd0: 0x00007ffc2f4d0e38  0x00007ffc2f4d0e40
0x7ffc2f4d0be0: 0x00007ffc2f4d0e10  0x00007ffc2f4d0e18
0x7ffc2f4d0bf0: 0x00007ffc2f4d0e68  0x0000000000000000
0x7ffc2f4d0c00: 0x00007ffc2f4d0e70  0x00000000004012a6
```

Personality 루틴의 반환값은 `_URC_CONTINUE_UNWIND` 에 해당하는 8입니다. 스택 되감기를 반복하여 `func` 함수의 프레임으로 이동합니다.

```
pwndbg> i r rax
rax            0x8                 8
pwndbg> c
Continuing

Breakpoint 2, 0x00007f845bf3b086 in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> pdisass 1
 ► 0x7f845bf3b086 <_Unwind_RaiseException+310>    call   0x7f845bf39800                <0x7f845bf39800>

   0x7f845bf3b08b <_Unwind_RaiseException+315>    cmp    eax, 5
   0x7f845bf3b08e <_Unwind_RaiseException+318>    je     _Unwind_RaiseException+435                <_Unwind_RaiseException+435>
pwndbg> x/20gx $rdi
0x7ffc2f4d0b70: 0x00007ffc2f4d0de8  0x00007ffc2f4d0df0
0x7ffc2f4d0b80: 0x0000000000000000  0x00007ffc2f4d0e88
0x7ffc2f4d0b90: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0ba0: 0x00007ffc2f4d0e90  0x0000000000000000
0x7ffc2f4d0bb0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bc0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bd0: 0x00007ffc2f4d0e38  0x00007ffc2f4d0e40
0x7ffc2f4d0be0: 0x00007ffc2f4d0e10  0x00007ffc2f4d0e18
0x7ffc2f4d0bf0: 0x00007ffc2f4d0e98  0x0000000000000000
0x7ffc2f4d0c00: 0x00007ffc2f4d0ea0  0x000000000040130c
pwndbg> x/4i *(uint64_t *)($rdi+8*19)
   0x40130c <main+30>:  mov    eax,0x0
   0x401311 <main+35>:  jmp    0x40135b <main+109>
   0x401313 <main+37>:  endbr64
   0x401317 <main+41>:  cmp    rdx,0x1
```

`func` 함수에서 스택을 되감으면 `main` 함수의 catch 블록으로 이동해야 합니다. 계속 실행하면 personality 루틴이 호출되며, `_URC_HANDLER_FOUND` 에 해당하는 6을 반환합니다. 

```
pwndbg> pdisass 1
 ► 0x7f845bf3b0b4 <_Unwind_RaiseException+356>    call   rax                           <__gxx_personality_v0>
        rdi: 0x1
        rsi: 0x1
        rdx: 0x474e5543432b2b00
        rcx: 0x135f320 ◂— 0x474e5543432b2b00

   0x7f845bf3b0b6 <_Unwind_RaiseException+358>    cmp    eax, 6
   0x7f845bf3b0b9 <_Unwind_RaiseException+361>    je     _Unwind_RaiseException+544                <_Unwind_RaiseException+544>
pwndbg> ni
pwndbg> i r rax
rax            0x6                 6
```

search 단계의 성공으로 반복문을 탈출합니다. 계속 실행하면 `_Unwind_RaiseException_Phase2` 함수를 호출하는 4번째 중단점에서 멈추게 됩니다.

```
Breakpoint 5, 0x00007f845bf3b27c in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> pdisass 1
 ► 0x7f845bf3b27c <_Unwind_RaiseException+812>    call   0x7f845bf3ab50                <0x7f845bf3ab50>

   0x7f845bf3b281 <_Unwind_RaiseException+817>    cmp    eax, 7
   0x7f845bf3b284 <_Unwind_RaiseException+820>    jne    _Unwind_RaiseException+435                <_Unwind_RaiseException+435>
```

`_Unwind_RaiseException_Phase2` 함수 내에서 personality 루틴을 호출하는 부분에 추가로 중단점을 두겠습니다.

```
pwndbg> x/43i 0x7f845bf3ab50
   0x7f845bf3ab50:  push   r15
   0x7f845bf3ab52:  push   r14
   # ...
   0x7f845bf3abe5:  or     esi,0x2
   0x7f845bf3abe8:  mov    edi,0x1
   0x7f845bf3abed:  call   rax                    # call personality routine 
   0x7f845bf3abef:  cmp    eax,0x7
   0x7f845bf3abf2:  je     0x7f845bf3ac90
pwndbg> break *0x7f845bf3abed
Breakpoint 7 at 0x7f845bf3abed
```

계속 실행하면 cleanup 단계를 수행하는 `_Unwind_RaiseException_Phase2` 함수 내부로 진입합니다. 새로 설정한 중단점에서 멈추며, personality 루틴을 호출하기 전 `context->ra` 필드의 값은 `0x4012a6` 으로 `func` 함수에서 `func2` 함수를 호출한 직후의 주소입니다.

```
Breakpoint 7, 0x00007f845bf3abed in ?? () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> pdisass 1
   0x7f845bf3abe8    mov    edi, 1
 ► 0x7f845bf3abed    call   rax                           <__gxx_personality_v0>
        rdi: 0x1
        rsi: 0x2
        rdx: 0x474e5543432b2b00
        rcx: 0x135f320 ◂— 0x474e5543432b2b00

   0x7f845bf3abef    cmp    eax, 7
pwndbg> x/20gx $context
0x7ffc2f4d0b70: 0x00007ffc2f4d0de8  0x00007ffc2f4d0df0
0x7ffc2f4d0b80: 0x0000000000000000  0x00007ffc2f4d0df8
0x7ffc2f4d0b90: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0ba0: 0x00007ffc2f4d0e60  0x0000000000000000
0x7ffc2f4d0bb0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bc0: 0x0000000000000000  0x0000000000000000
0x7ffc2f4d0bd0: 0x00007ffc2f4d0e38  0x00007ffc2f4d0e40
0x7ffc2f4d0be0: 0x00007ffc2f4d0e10  0x00007ffc2f4d0e18
0x7ffc2f4d0bf0: 0x00007ffc2f4d0e68  0x0000000000000000
0x7ffc2f4d0c00: 0x00007ffc2f4d0e70  0x00000000004012a6
pwndbg> x/4i *(uint64_t *)($context+8*19)
   0x4012a6 <func()+62>:    lea    rax,[rbp-0x19]
   0x4012aa <func()+66>:    mov    rdi,rax
   0x4012ad <func()+69>:    call   0x401382 <MyClass::~MyClass()>
   0x4012b2 <func()+74>:    nop
```

Personality 루틴을 호출하면 `_URC_INSTALL_CONTEXT` 에 해당하는 7을 반환하며, `context->ra` 필드의 값이 `0x4012c4` 로 바뀌어 있습니다. 이는 `func` 함수에서 `MyClass` 의 소멸자를 호출하는 랜딩 패드의 시작 주소입니다. 이와 같이 cleanup 단계에서는 LSDA를 해석하여 랜딩 패드의 주소를 찾아 `context->ra` 필드에 대입하여 실행 흐름이 랜딩 패드로 옮겨질 수 있도록 합니다.

```
Breakpoint 6, 0x00007f845bf3b2d9 in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> ni
pwndbg> i r rax
rax            0x7                 7
pwndbg> x/8i *(uint64_t *)($context+8*19)
   0x4012c4 <func()+92>:    endbr64
   0x4012c8 <func()+96>:    mov    rbx,rax
   0x4012cb <func()+99>:    lea    rax,[rbp-0x19]
   0x4012cf <func()+103>:   mov    rdi,rax
   0x4012d2 <func()+106>:   call   0x401382 <MyClass::~MyClass()>
   0x4012d7 <func()+111>:   mov    rax,rbx
   0x4012da <func()+114>:   mov    rdi,rax
   0x4012dd <func()+117>:   call   0x401120 <_Unwind_Resume@plt>
```

cleanup 단계의 성공으로 반복문을 탈출합니다. 계속 실행하면 `uw_install_context` 매크로의 내부인 마지막 중단점에서 멈추게 됩니다. 이 매크로는 `context` 구조체의 내용을 실제 레지스터에 반영하는 코드로 구성되어 있습니다. 매크로의 끝에서 점프를 수행하면 랜딩 패드로 실행 흐름을 옮기면서 `MyClass` 의 소멸차를 호출하는 코드를 실행합니다.

```
Breakpoint 6, 0x00007f845bf3b2d9 in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
pwndbg> emu 3
 ► 0x7f845bf3b2d9 <_Unwind_RaiseException+905>    jmp    rcx                           <func()+92>
    ↓
   0x4012c4       <func()+92>                     endbr64
   0x4012c8       <func()+96>                     mov    rbx, rax
   0x4012cb       <func()+99>                     lea    rax, [rbp - 0x19]
   0x4012cf       <func()+103>                    mov    rdi, rax
   0x4012d2       <func()+106>                    call   MyClass::~MyClass()                      <MyClass::~MyClass()>

   0x4012d7       <func()+111>                    mov    rax, rbx
```


## 참고자료

[1] S. B. Lippman, J. Lajoie and B. E. Moo, "18.1 Exception Handling," in *C++ Primer*, 5th ed. Boston, MA: Addison-Wesley, 2012, pp. 772-784.
[2] *DWARF Debugging Information Format, Version 5*, DWARF Debugging Information Format Committee, 2012.
[3] *Exception Handling*, Itanium C++ ABI, 2012. [Online] Available: https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html
[4] *Exception Handling Tables*, HP aC++ A.01.15 - Public version, 2012. [Online] Available: https://itanium-cxx-abi.github.io/cxx-abi/exceptions.pdf

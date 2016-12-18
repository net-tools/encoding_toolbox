# net-tools/encoding_toolbox

## Composer library providing client-side Javascript encoding/PHP-obfuscating functionnalities

This package contains an HTML page (and also required CSS and JS files) you can use to quickly :

- encode/decode data to/from base64
- compute sha256 and md5 for some data
- obfuscate/un-obfuscate sensitive strings in PHP scripts


### Setup instructions

To install net-tools/encoding_toolbox package, just require it through composer : `require net-tools/encoding_toolbox:^1.0.0`.

You can also download the full release and copy the files in any folder (that's **pure client-side code**, no PHP, no autoloading, etc.) and open your browser with `encoding_toolbox.html`.


### How to use ?

The HTML page is rather simple. 

The left side provides **encoding** functionnalities, and the right side contains the **decoding** stuff. You enter (or paste) the data to encode/decode, obfuscate/unobfuscate, compute in the top textarea and you click on the desired action button. The encoded/decoded, obfuscated/un-obfuscated data will be displayed in the bottom textarea, and selected when you click on it (allowing an easy CTRL+C copy).

You will note that there's no decoding actions for sha256 and md5. If this is not obvious for you, please refer to Wikipedia or any other source about sha256 and md5 : they are hash algorithms, not crypt-algorithm that can be reversed.


### Confidentiality 

As this is pure client-side Javascript code, all processes run on your computer, so your sensitive data won't never 'go outside'. 


### Obfuscation 

The obfuscate functionnality can be useful when you don't want a password (or any sensitive data) to appear clearly in a PHP script. In case your host is hacked, the PHP files could be automatically scanned for passwords. Clear passwords in source code are not a good practice.

That's why we must write passwords in another way. The easiest way would be something like `$pass = base64_decode('MTIzNA==')`, encoding the `'1234'` password. However, a base64 string can also be easily scanned in a script by an hacker automated process (looking for strings with only letters, digits, +, / and =) and immediately decoded to the password.

My obfuscation process uses base64, but also string 'crypting' functions and variable functions. I wrote 'crypting' with quotes, as the functions used are not cryptographic functions ; they just transform the original string with a simple code algorithm.

The aim is not to produce strong-crypted strings, but to write sensitive data in script with some minimal encoding that an automated process may not reverse (without guidance for an human eye, understanding the encoding process used).


### Un-obfuscation

If one day you wan't to get the original data obfuscated, just copy paste the obfuscate code, and hit 'un-obfuscate'. Please be sure to copy/paste the exact data `eval(base64_decode(...))`.

In case one day this library or my website are not online anymore, you may copy this package on you computer. That will allow you to unobfuscate the data (remember, this is pure client-side Javascript code, you don't need a web server to run the code).

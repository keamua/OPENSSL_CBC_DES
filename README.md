# OPENSSL_CBC_DES
用openssl库里面简单的一些函数实现，cbc模式下的des加密
具体要求如下：

                        Exercise 1 CBC Modes of DES


	DES encryption / decryption
In this project, we will be coding a tool to encrypt and decrypt files using DES in mode CBC (Cipher Block Chaining). “tempdes.c” is a skeleton file that encrypts/decrypts a fixed 64-bit block. In this assignment, you will extend this skeleton code to take an arbitrarily sized input file and encrypt/decrypt it, by implementing the Cipher Block Chaining DES mode of operation. You must actually implement the CBC mode, and you are not allowed to use any built-in function besides what is present in tempdes.c. You can find information about DES-CBC in your text book.

在这个项目内，我们将写一个CBC模式的DES加解密程序，“tempdes.c”是个模板文件来加解密一个固定的64比特的块。在这次任务中，你要把这个模板代码扩展成一个任意尺寸的输入文件并完成加解密，通过完成CBC-DES的模式。你一定要完成CBC模式，同时不允许用任何除了模板文件外的任何内涵函数，你可以找到资料在你的书里。
You may want to check your work against the input file "test.txt". If you have implemented the algorithm correctly, you should get the output in "test.des". 
你可能想检查一下你的对test.txt的加密成果，如果你完成的正确，你应该能得到输出在test.des。

	Requirements
	需求

a.Just use the built in functions that appear in tempdes.c
	只用在tempdes.c 出现的函数
b.Your code should result in an executable of the following form:
	应该得到一个可执行文件有下面的输入格式
./tempdes	iv	key	inputfile	outputfile

	The parameters description is as follows:
参数的描述如下
- iv: the actual IV to use: this must be represented as a string comprised only of hexadecimal digits.
初始化向量，一定是个16进制的数
- key: the actual key to use: this must be represented as a string comprised only of hexadecimal digits.
密钥，也是个16进制的数
- inputfile: input file name
	输入文件名字
- outputfile: output file name
输出文件名字
 	For example:
	./tempdes	fecdba9876543210 	0123456789abcdef 	test.txt 		test.des
	例子

	If any of the arguments is invalid, your code should return an appropriate 	message to the user. Be sure to consider the case when the keys are invalid.
如果某个参数是无效的，你应该返回一个信息给使用者，确保考虑当密钥无效时的情况



Built in functions information:

We will give a brief description of the merely built in functions you are
allowed to use.
You can find information on most of the built in functions we are using in the
sample source codes at http://www.openssl.org/docs/crypto/crypto.html

- des_encrypt1
You will use a built in function called des_encrypt1 to do the actual DES encryption / decryption.
As a reference on how to use this function, you can view the file tempdes.c.

des_encrypt1(long *data, des_key_schedule *ks, int enc)

        a. data: This argument is a pointer to a two element array of type long (4 bytes) that will
        contain the data you will read from the file but packed in a type long variable.
	NOTE: Characters are loaded into this function in little endian format. For example, the string 
	{0xA0,0xB7,0x07,0x08} is 08 07 B7 A0 in little endian format (least significant bit goes first).
        b. ks: is a pointer to the actual key array. Don.t worry about this argument data type.
        c. enc: has a value of 1 for encryption and 0 for decryption.

- des_set_key_checked
This function will check that the key passed is of odd parity and is not a week or semi-weak key. If 
the parity is wrong, then -1 is returned. If the key is a weak key, then -2 is returned. If an error 
is returned, the key schedule is not generated.

des_set_key_checked(const_des_cblock *key, des_key_schedule *schedule)
	a. key: is a pointer to the actual key array. Don.t worry about this argument data type.
	b. schedule: is the new key, that will be used as an input argument to
	   the function des_encrypt1


In this folder you will find the following files:

- tempdes.c : is a sample code for encrypting / decrypting using DES


  Key and IV values used are as follows.
	- Key = 40fedf386da13d57 (Hexadecimal values)
	- IV  = fedcba9876543210 (Hexadecimal values)


All the c codes can be compiled and executed using the following commands:

- In the linux command line, execute "gcc -o tempdes tempdes.c -lcrypto", where tempdes.c 
is the source code and tempdes is the name of the executable that sill be generated This 
command will compile your code and generate an executable.
- To execute the program you just created (tempdes in our example), in the linux command 
line write "./tempdes"

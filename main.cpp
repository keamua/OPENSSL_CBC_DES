/*
* author：		朱一鸣
* date：		2021/05/05
* description：	CBC模式下的DES加解密的实现
*/
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#pragma comment(lib, "C:\\Users\\Dreaming\\Desktop\\大三下\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\libeay32.lib") 
#pragma comment(lib, "C:\\Users\\Dreaming\\Desktop\\大三下\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\ssleay32.lib")

#include <openssl/des.h>

#define ENC 1
#define DEC 0
DES_key_schedule key;

// 无符号字符串转无符号16进制字符
void strToHex(const_DES_cblock input, unsigned char *output) {
    unsigned int byte;
    for(int i=0; i<8; i++) {
        if(sscanf((const char*)(char*)input, "%2x", &byte) != 1) {
            break;
        }
        output[i] = byte;
        input += 2;
    }
}

// 把一个无符号字符串复制到另一个字符串
void copyValue(const_DES_cblock val1, unsigned char *val2, int size) {
    for(int i=0; i<size; i++) {
        val2[i] = val1[i];
    }
}

// 用两个无符号长字符（4字节），对上次加密结果和这次的明文data进行异或
void LongXor(DES_LONG *xor, DES_LONG* data, const_DES_cblock iv) {
    DES_LONG temp[2];
    memcpy(temp, iv, 8*sizeof(unsigned char));	// 转换成相同的类型
    for(int i=0; i<2; i++) {
        xor[i] = temp[i] ^ data[i];
    }
}

// 打印一个8字节的des块
void printvalueOfDesBlock(const_DES_cblock val) {
    for(int i=0; i<7; i++) {
        printf("0x%x,", val[i]);
    }
	printf("0x%x", val[7]);
    printf("\n");
}
int checkhex(char* ch)
{
	if (strlen(ch)!= 16)
		return -1;
	for (int i=0;i<16;i++){
		if(!(((ch[i]>='0')&&(ch[i]<='9'))
			||((ch[i]>='A')&&(ch[i]<='F'))
			||((ch[i]>='a')&&(ch[i]<='f'))))
		return -1;
	}
	return 0;
}

/*
* author：		朱一鸣
* date：		2021/05/05
* description：	CBC模式下的DES加密函数
*/
void CBCenc(FILE *inpFile,FILE *outFile,const_DES_cblock IV){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));
	DES_LONG data[2] = {0,0},temp[2] = {0,0}; // data用来储存每次读取的8字节64比特的数据，temp用来储存加密后的数据
	int mRead = fread(data, 1, 8, inpFile); // 从明文中读取8字节的数据
	while(mRead > 0){ // 当能够从明文中读到数据的时候
		LongXor(temp, data, iv); // 先将数据和iv异或
		DES_encrypt1(temp,&key,ENC); // 异或的结果进行加密
		fwrite(temp, 8, 1, outFile); // 将加密的结果写到密文中
		memcpy(iv, temp, 2*sizeof(DES_LONG)); // 将加密的结果作为下一次的iv进行异或
		data[0]=0;data[1]=0; // 用0填充data
		mRead = fread(data, 1, 8, inpFile);
	}
	printf("加密完成\n");	//加密完成
}

/*
* author：		朱一鸣
* date：		2021/05/05
* description：	CBC模式下的DES解密函数
*/

void CBCdec(FILE *inpFile,FILE *outFile,const_DES_cblock IV){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));
	DES_LONG data[2] = {0,0}; //data为读取的密文，temp1用来储存下一步的iv，temp2用来储存解密后的结果
	int cRead = fread(data, 1, 8, inpFile); // 读取8字节的密文
	while(cRead > 0){ // 当还有密文没有读取完的时候
		DES_LONG temp1[2],temp2[2];
		memcpy(temp1, data, 2*sizeof(DES_LONG)); // 将本轮的密文作为下一次的iv进行异或
		DES_encrypt1(data,&key,DEC); // 将密文解密
		LongXor(temp2, data, iv); // 解密后的再与iv异或一次得到明文
		fwrite(temp2, 8, 1, outFile); // 将得到的明文写到文件中
		memcpy(iv, temp1, 2*sizeof(DES_LONG)); // 把这一轮的密文作为下一轮的iv
		data[0]=0;data[1]=0; // 用来进行填充0
		cRead = fread(data, 1, 8, inpFile); // 读取下一个8字节块
	}
	printf("解密完成\n");
}

int main(int argc, char** argv)
{
    if(argc != 5) {
        printf("USAGE ERROR \nusage: ./exec_file IV key input_file out_file\n");
		/*
		*	param:
		*  ./cbcdes iv key inputfile outputfile
		*	iv initial vector 初始参数,16个16进制字符
		*	key 初始密钥，16个16进制字符
		*	inputfile 输入文件，即明文
		*	outputfile 输出文件，即密文
		*/
    }
	else {
        const_DES_cblock cbc_key ;
        const_DES_cblock IV ;
        int k;
		if(checkhex(argv[1])!=0)
			{printf("请输入16个16进制数作为初始向量IV！\n");return 0;}
		if(checkhex(argv[2])!=0)
			{printf("请输入16个16进制数作为初始密钥key！\n");return 0;}

        strToHex((unsigned char*)argv[1], IV);
        strToHex((unsigned char*)argv[2], cbc_key);
        printvalueOfDesBlock(IV);
        printvalueOfDesBlock(cbc_key);

        if ((k = DES_set_key_checked(&cbc_key,&key)) != 0)
			{printf("\n生成密钥不符合要求！\n");return 0;}


		//对明文进行加密
        FILE *inpFile = fopen(argv[3], "rb");
        FILE *outFile = fopen(argv[4], "wb");
        if(inpFile && outFile) {
			printf("加密文件创建成功！\n");
			CBCenc(inpFile,outFile,IV);
        } else {
            printf("打开文件失败！\n");
        }
        fclose(inpFile);
        fclose(outFile);

		//对密文进行解密
		FILE *incFile = fopen(argv[4], "rb");
		FILE *decFile = fopen("decfile.txt", "wb");
		if(incFile && decFile) {
			printf("解密文件创建成功！\n");
			CBCdec(incFile,decFile,IV);
        } else {
            printf("打开文件失败！\n");
        }
		fclose(incFile);
		fclose(decFile);
		/*
		*按字节读取文件
		FILE *mFile = fopen("decfile.txt", "rb");
		unsigned char ch[1];
		int read1 = fread(ch, 1, 1, mFile); // 读取8字节的密文
		while(read1 > 0){ // 当还有密文没有读取完的时候
			printf("%c ", ch[0]);
			ch[0] = '\0';
			read1 = fread(ch, 1, 1, mFile); // 读取下一个8字节块
		}
		fclose(mFile);
		*/
        printf("\n");
    }
	return 0;
}




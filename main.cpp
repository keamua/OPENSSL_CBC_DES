#include <openssl/des.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\课件\\大三下\\算法协议\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\libeay32.lib") 
#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\课件\\大三下\\算法协议\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\ssleay32.lib")

#define ENC 1
#define DEC 0

DES_key_schedule key;

// 无符号字符串转无符号16进制字符
void strToHex(const_DES_cblock input, unsigned char *output) {
    int arSize = 8;
    unsigned int byte;
    for(int i=0; i<arSize; i++) {
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
void doBitwiseXor(DES_LONG *xorValue, DES_LONG* data, const_DES_cblock roundOutput) {
    DES_LONG temp[2];
    memcpy(temp, roundOutput, 8*sizeof(unsigned char));	// 转换成相同的类型
    for(int i=0; i<2; i++) {
        xorValue[i] = temp[i] ^ data[i];
    }
}

// 打印一个8字节的des块
void printvalueOfDesBlock(const_DES_cblock val) {
    for(int i=0; i<8; i++) {
        printf("0x%x,", val[i]);
    }
    printf("\n");
}



/*
* author：		朱一鸣
* date：		2021/05/05
* description：	CBC模式下的DES加密函数
*/
void CBCenc(FILE *inpFile,FILE *outFile,const_DES_cblock iv){
	DES_LONG data[2] = {0,0},temp[2] = {0,0}; // data用来储存每次读取的8字节64比特的数据，temp用来储存加密后的数据
	int successfulBlockReadSize = fread(data, 1, 8, inpFile); // 从明文中读取8字节的数据
	while(successfulBlockReadSize == 8){ // 当能够从明文中读到数据的时候
		doBitwiseXor(temp, data, iv); // 先将数据和iv异或
		DES_encrypt1(temp,&key,ENC); // 异或的结果进行加密
		fwrite(temp, 8, 1, outFile); // 将加密的结果写到密文中
		memcpy(iv, temp, 2*sizeof(DES_LONG)); // 将加密的结果作为下一次的iv进行异或
		data[0]=0;data[1]=0; // 用0填充data
		successfulBlockReadSize = fread(data, 1, 8, inpFile);
		printf("%d,",successfulBlockReadSize);
	}
	if(successfulBlockReadSize > 0) {
        doBitwiseXor(temp, data, iv); // 先将数据和iv异或
		DES_encrypt1(temp,&key,ENC); // 异或的结果进行加密
		fwrite(temp, 8, 1, outFile); // 将加密的结果写到密文中
		printf("加密完成最后一块，填充前的大小为%d。\n",successfulBlockReadSize);
    }
	printf("加密完成\n");	//加密完成
}

/*
* author：		朱一鸣
* date：		2021/05/05
* description：	CBC模式下的DES解密函数
*/

void CBCdec(FILE *inpFile,FILE *outFile,const_DES_cblock iv){
	DES_LONG data[2] = {0,0}; //data为读取的密文，temp1用来储存下一步的iv，temp2用来储存解密后的结果
	int successfulBlockReadSize = fread(data, 1, 8, inpFile); // 读取8字节的密文
	while(successfulBlockReadSize == 8){ // 当还有密文没有读取完的时候
		DES_LONG temp1[2],temp2[2];
		memcpy(temp1, data, 2*sizeof(DES_LONG)); // 将本轮的密文作为下一次的iv进行异或
		DES_encrypt1(data,&key,DEC); // 将密文解密
		doBitwiseXor(temp2, data, iv); // 解密后的再与iv异或一次得到明文
		fwrite(temp2, 8, 1, outFile); // 将得到的明文写到文件中
		memcpy(iv, temp1, 2*sizeof(DES_LONG)); // 把这一轮的密文作为下一轮的iv
		data[0]=0;data[1]=0; // 用来进行填充0
		successfulBlockReadSize = fread(data, 1, 8, inpFile); // 读取下一个8字节块
	}
	if(successfulBlockReadSize > 0) {
		DES_LONG temp1[2],temp2[2];
        DES_encrypt1(data,&key,DEC); // 将密文解密
		doBitwiseXor(temp2, data, iv); // 解密后的再与iv异或一次得到明文
		fwrite(temp2, 8, 1, outFile); // 将得到的明文写到文件中
		printf("解密密完成最后一块，填充前的大小为%d。\n",successfulBlockReadSize);
    }
	printf("解密完成\n");
}

int main(int argc, char** argv)
{
    if(argc != 5) {
        printf("USAGE ERROR \nusage: ./exec_file IV key input_file out_file\n");
    }
	else {
        const_DES_cblock cbc_key = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
        const_DES_cblock IV = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
        const_DES_cblock IV2;
        int k;

        strToHex((unsigned char*)argv[1], IV);
		strToHex((unsigned char*)argv[1], IV2);
        strToHex((unsigned char*)argv[2], cbc_key);

        printvalueOfDesBlock(IV);
        printvalueOfDesBlock(cbc_key);

        if ((k = DES_set_key_checked(&cbc_key,&key)) != 0)
		    printf("\nkey error\n");

		//char *decname = argv[4];
		//strcat(decname,".dec");
        //DES_LONG data[2] = {0, 0};
        FILE *inpFile = fopen(argv[3], "rb");
        FILE *outFile = fopen(argv[4], "wb");


        if(inpFile && outFile) {
			printf("加密文件创建成功\n");
			CBCenc(inpFile,outFile,IV);
        } else {
            printf("Error in opening file\n");
        }

	
		
        fclose(inpFile);
        fclose(outFile);

		FILE *incFile = fopen(argv[4], "rb");
		FILE *decFile = fopen("decfile.txt", "wb");

		if(incFile && decFile) {
			printf("解密文件创建成功\n");
			CBCdec(incFile,decFile,IV2);
        } else {
            printf("Error in opening file\n");
        }
		/*
		int read1 = fread(ch, 1, 1, inpFile); // 读取8字节的密文
		while(read1 > 0){ // 当还有密文没有读取完的时候
			printf("%c ", ch[0]);
			ch[0] = '\0';
			read1 = fread(ch, 1, 1, inpFile); // 读取下一个8字节块
		}
		*/

		fclose(incFile);
		fclose(decFile);

		FILE *mFile = fopen("decfile.txt", "rb");
		unsigned char ch[1];
		int read1 = fread(ch, 1, 1, mFile); // 读取8字节的密文
		while(read1 > 0){ // 当还有密文没有读取完的时候
			printf("%c ", ch[0]);
			ch[0] = '\0';
			read1 = fread(ch, 1, 1, mFile); // 读取下一个8字节块
		}
		printf("\n");
		fclose(mFile);
        
    }
	return 0;
}


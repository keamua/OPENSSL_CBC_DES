#include <openssl/des.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\�μ�\\������\\�㷨Э��\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\libeay32.lib") 
#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\�μ�\\������\\�㷨Э��\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\ssleay32.lib")

#define ENC 1
#define DEC 0

DES_key_schedule key;

// �޷����ַ���ת�޷���16�����ַ�
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

// ��һ���޷����ַ������Ƶ���һ���ַ���
void copyValue(const_DES_cblock val1, unsigned char *val2, int size) {
    
    for(int i=0; i<size; i++) {
        val2[i] = val1[i];
    }
}

// �������޷��ų��ַ���4�ֽڣ������ϴμ��ܽ������ε�����data�������
void doBitwiseXor(DES_LONG *xorValue, DES_LONG* data, const_DES_cblock roundOutput) {
    DES_LONG temp[2];
    memcpy(temp, roundOutput, 8*sizeof(unsigned char));	// ת������ͬ������
    for(int i=0; i<2; i++) {
        xorValue[i] = temp[i] ^ data[i];
    }
}

// ��ӡһ��8�ֽڵ�des��
void printvalueOfDesBlock(const_DES_cblock val) {
    for(int i=0; i<8; i++) {
        printf("0x%x,", val[i]);
    }
    printf("\n");
}



/*
* author��		��һ��
* date��		2021/05/05
* description��	CBCģʽ�µ�DES���ܺ���
*/
void CBCenc(FILE *inpFile,FILE *outFile,const_DES_cblock iv){
	DES_LONG data[2] = {0,0},temp[2] = {0,0}; // data��������ÿ�ζ�ȡ��8�ֽ�64���ص����ݣ�temp����������ܺ������
	int successfulBlockReadSize = fread(data, 1, 8, inpFile); // �������ж�ȡ8�ֽڵ�����
	while(successfulBlockReadSize == 8){ // ���ܹ��������ж������ݵ�ʱ��
		doBitwiseXor(temp, data, iv); // �Ƚ����ݺ�iv���
		DES_encrypt1(temp,&key,ENC); // ���Ľ�����м���
		fwrite(temp, 8, 1, outFile); // �����ܵĽ��д��������
		memcpy(iv, temp, 2*sizeof(DES_LONG)); // �����ܵĽ����Ϊ��һ�ε�iv�������
		data[0]=0;data[1]=0; // ��0���data
		successfulBlockReadSize = fread(data, 1, 8, inpFile);
		printf("%d,",successfulBlockReadSize);
	}
	if(successfulBlockReadSize > 0) {
        doBitwiseXor(temp, data, iv); // �Ƚ����ݺ�iv���
		DES_encrypt1(temp,&key,ENC); // ���Ľ�����м���
		fwrite(temp, 8, 1, outFile); // �����ܵĽ��д��������
		printf("����������һ�飬���ǰ�Ĵ�СΪ%d��\n",successfulBlockReadSize);
    }
	printf("�������\n");	//�������
}

/*
* author��		��һ��
* date��		2021/05/05
* description��	CBCģʽ�µ�DES���ܺ���
*/

void CBCdec(FILE *inpFile,FILE *outFile,const_DES_cblock iv){
	DES_LONG data[2] = {0,0}; //dataΪ��ȡ�����ģ�temp1����������һ����iv��temp2����������ܺ�Ľ��
	int successfulBlockReadSize = fread(data, 1, 8, inpFile); // ��ȡ8�ֽڵ�����
	while(successfulBlockReadSize == 8){ // ����������û�ж�ȡ���ʱ��
		DES_LONG temp1[2],temp2[2];
		memcpy(temp1, data, 2*sizeof(DES_LONG)); // �����ֵ�������Ϊ��һ�ε�iv�������
		DES_encrypt1(data,&key,DEC); // �����Ľ���
		doBitwiseXor(temp2, data, iv); // ���ܺ������iv���һ�εõ�����
		fwrite(temp2, 8, 1, outFile); // ���õ�������д���ļ���
		memcpy(iv, temp1, 2*sizeof(DES_LONG)); // ����һ�ֵ�������Ϊ��һ�ֵ�iv
		data[0]=0;data[1]=0; // �����������0
		successfulBlockReadSize = fread(data, 1, 8, inpFile); // ��ȡ��һ��8�ֽڿ�
	}
	if(successfulBlockReadSize > 0) {
		DES_LONG temp1[2],temp2[2];
        DES_encrypt1(data,&key,DEC); // �����Ľ���
		doBitwiseXor(temp2, data, iv); // ���ܺ������iv���һ�εõ�����
		fwrite(temp2, 8, 1, outFile); // ���õ�������д���ļ���
		printf("������������һ�飬���ǰ�Ĵ�СΪ%d��\n",successfulBlockReadSize);
    }
	printf("�������\n");
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
			printf("�����ļ������ɹ�\n");
			CBCenc(inpFile,outFile,IV);
        } else {
            printf("Error in opening file\n");
        }

	
		
        fclose(inpFile);
        fclose(outFile);

		FILE *incFile = fopen(argv[4], "rb");
		FILE *decFile = fopen("decfile.txt", "wb");

		if(incFile && decFile) {
			printf("�����ļ������ɹ�\n");
			CBCdec(incFile,decFile,IV2);
        } else {
            printf("Error in opening file\n");
        }
		/*
		int read1 = fread(ch, 1, 1, inpFile); // ��ȡ8�ֽڵ�����
		while(read1 > 0){ // ����������û�ж�ȡ���ʱ��
			printf("%c ", ch[0]);
			ch[0] = '\0';
			read1 = fread(ch, 1, 1, inpFile); // ��ȡ��һ��8�ֽڿ�
		}
		*/

		fclose(incFile);
		fclose(decFile);

		FILE *mFile = fopen("decfile.txt", "rb");
		unsigned char ch[1];
		int read1 = fread(ch, 1, 1, mFile); // ��ȡ8�ֽڵ�����
		while(read1 > 0){ // ����������û�ж�ȡ���ʱ��
			printf("%c ", ch[0]);
			ch[0] = '\0';
			read1 = fread(ch, 1, 1, mFile); // ��ȡ��һ��8�ֽڿ�
		}
		printf("\n");
		fclose(mFile);
        
    }
	return 0;
}


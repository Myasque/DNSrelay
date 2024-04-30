#pragma once
#define LOCAL_ADDRESS "127.0.0.1"		//����DNS��������ַ
#define MAX_BUF_SIZE 1024          //��󻺴泤��
#define DNS_PORT 53                //�˿ں�
#define MAX_ID_TRANS_TABLE_SIZE 16 // ת�����С
#define ID_EXPIRE_TIME 10          //��ʱʱ��
#define MAX_CACHE_SIZE 5           //cache��С
#define DNS_HEAD_SIZE 12		   //header��С
#define AMOUNT 300     
#define TRUE  1
#define FLASE 0
#define D 1                        //���Եȼ�D
#define DD 2                       //���Եȼ�DD����ϸ��

#include <WinSock2.h>
#include<stdio.h>
#include<time.h>
#pragma comment(lib, "ws2_32.lib")	
#pragma warning(disable:4996)//��strcpy_s�Ĵ�����ʾ����

//IDת����ṹ
typedef struct IDChange
{
	unsigned short oldID;			            //ԭ��ID
	BOOL done;						            //����Ƿ���ɽ���
	SOCKADDR_IN client;				            //�������׽��ֵ�ַ
	int expireTime;                            //��ʱʱ��
} IDTransform;

//DNS����������ṹ
typedef struct translate
{
	char IP[16];						       //IP��ַ
	char domain[65];					       //����
} Translate;

int IDcount = 0;					           //IDת�����е���Ŀ����
int cacheCount = 0;
int DNSNum = 0;                        //DNS��������������Ŀ
int debugLevel = 0;                           //���Եȼ�
char dnsServerIP[16] = "10.3.179.118";
char filePath[AMOUNT]="dnsrelay.txt";


Translate DNSTable[AMOUNT];		           //DNS����������
Translate cache[MAX_CACHE_SIZE];           //cache��
IDTransform IDTransTable[MAX_ID_TRANS_TABLE_SIZE];	           //IDת����


WSADATA wsaData;  /* Store Windows Sockets initialization information */
SOCKET local_sock, extern_sock;

struct sockaddr_in local_name, extern_name;//IPv4 ����Э���ַ
struct sockaddr_in client, external;
int length_client = sizeof(client);


//��Ҫ����
void initIDTable();//��ʼ��IDת����
void dealPara(int argc, char* argv[]);//�����������
int readLocalData();//�������ļ�
void receiveFromExtern();//��extern���ձ��ģ���������
void receiveFromLocal();//��client���ձ���
//��������
int ifLegalIP(char* ip);            //�ж�����IP�Ϸ�
void addToCache(char* url, char* ip);//��ӵ�cache
void outputCache();                 //���cache
void addToTable(char* url, char* ip);//��ӵ�DNS����������
void addToFile(char* url, char* ip);//��ӵ��ļ���
void setIDExpire(IDTransform* record, int ttl);//���ó�ʱʱ��
int checkIDExpired(IDTransform* record);//��鳬ʱ
unsigned short registerNewID(unsigned short ID, SOCKADDR_IN temp);//��IDת���������ID
void getUrl(char* buf, char* dest);//ת��������ʽ
void outputPacket(char* buf, int length);//�������












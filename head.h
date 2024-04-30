#pragma once
#define LOCAL_ADDRESS "127.0.0.1"		//本地DNS服务器地址
#define MAX_BUF_SIZE 1024          //最大缓存长度
#define DNS_PORT 53                //端口号
#define MAX_ID_TRANS_TABLE_SIZE 16 // 转换表大小
#define ID_EXPIRE_TIME 10          //超时时间
#define MAX_CACHE_SIZE 5           //cache大小
#define DNS_HEAD_SIZE 12		   //header大小
#define AMOUNT 300     
#define TRUE  1
#define FLASE 0
#define D 1                        //调试等级D
#define DD 2                       //调试等级DD（详细）

#include <WinSock2.h>
#include<stdio.h>
#include<time.h>
#pragma comment(lib, "ws2_32.lib")	
#pragma warning(disable:4996)//把strcpy_s的错误提示消除

//ID转换表结构
typedef struct IDChange
{
	unsigned short oldID;			            //原有ID
	BOOL done;						            //标记是否完成解析
	SOCKADDR_IN client;				            //请求者套接字地址
	int expireTime;                            //超时时间
} IDTransform;

//DNS域名解析表结构
typedef struct translate
{
	char IP[16];						       //IP地址
	char domain[65];					       //域名
} Translate;

int IDcount = 0;					           //ID转换表中的条目个数
int cacheCount = 0;
int DNSNum = 0;                        //DNS域名解析表中数目
int debugLevel = 0;                           //调试等级
char dnsServerIP[16] = "10.3.179.118";
char filePath[AMOUNT]="dnsrelay.txt";


Translate DNSTable[AMOUNT];		           //DNS域名解析表
Translate cache[MAX_CACHE_SIZE];           //cache表
IDTransform IDTransTable[MAX_ID_TRANS_TABLE_SIZE];	           //ID转换表


WSADATA wsaData;  /* Store Windows Sockets initialization information */
SOCKET local_sock, extern_sock;

struct sockaddr_in local_name, extern_name;//IPv4 网络协议地址
struct sockaddr_in client, external;
int length_client = sizeof(client);


//主要函数
void initIDTable();//初始化ID转换表
void dealPara(int argc, char* argv[]);//分析输入参数
int readLocalData();//读本地文件
void receiveFromExtern();//从extern接收报文，解析后发送
void receiveFromLocal();//从client接收报文
//辅助函数
int ifLegalIP(char* ip);            //判断输入IP合法
void addToCache(char* url, char* ip);//添加到cache
void outputCache();                 //输出cache
void addToTable(char* url, char* ip);//添加到DNS域名解析表
void addToFile(char* url, char* ip);//添加到文件内
void setIDExpire(IDTransform* record, int ttl);//设置超时时间
int checkIDExpired(IDTransform* record);//检查超时
unsigned short registerNewID(unsigned short ID, SOCKADDR_IN temp);//在ID转换表中添加ID
void getUrl(char* buf, char* dest);//转换域名格式
void outputPacket(char* buf, int length);//输出报文












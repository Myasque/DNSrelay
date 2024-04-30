#include"head.h"

int main(int argc, char* argv[])
{
	dealPara(argc, argv);//分析输入（调试等级）
	initIDTable();//初始化ID转换表

	WSAStartup(MAKEWORD(2, 2), &wsaData);//使用2.2版本的Socket  

	local_sock = socket(AF_INET, SOCK_DGRAM, 0);
	extern_sock = socket(AF_INET, SOCK_DGRAM, 0);

	//使用非阻塞性socket
	int non_block = 1;
	ioctlsocket(extern_sock, FIONBIO, (u_long FAR*) & non_block);
	ioctlsocket(local_sock, FIONBIO, (u_long FAR*) & non_block);
	if (local_sock < 0)
	{
		if (debugLevel >= D) printf("socket创建失败.\n");
		exit(1);
	}
	printf("socket创建成功.\n");
	//设置local socket
	local_name.sin_family = AF_INET; //协议簇设为TCP/IP
	local_name.sin_addr.s_addr = INADDR_ANY; //IP地址设为any
	local_name.sin_port = htons(DNS_PORT);  //把端口设为53
	//设置extern socket
	extern_name.sin_family = AF_INET;
	extern_name.sin_addr.s_addr = inet_addr(dnsServerIP);
	extern_name.sin_port = htons(DNS_PORT);

	int reuse = 1;
	setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
	//SO_REUSEADDER：允许重用本地地址和端口

	if (bind(local_sock, (struct sockaddr*)&local_name, sizeof(local_name)) < 0)
	{
		if (debugLevel >= 1) printf("Bind socket port failed.\n");
		exit(1);
	}
	printf("Bind socket port successfully.\n");

	DNSNum=readLocalData();

	while (TRUE)
	{
		receiveFromLocal();
		receiveFromExtern();
	}

	return 0;
}

//初始化ID转换表
void initIDTable()
{
	int i;
	IDcount = 0;
	for (i = 0; i < MAX_ID_TRANS_TABLE_SIZE; i++)
	{
		IDTransTable[i].oldID = 0;
		IDTransTable[i].done = TRUE;
		IDTransTable[i].expireTime = 0;
		memset(&(IDTransTable[i].client), 0, sizeof(SOCKADDR_IN));
	}
}

void dealPara(int argc, char* argv[])
{
	switch (argc)
	{
	case 1: debugLevel = 0; break;
	case 2:
		if (strcmp(argv[1], "-d") == 0) debugLevel = D;
		if (strcmp(argv[1], "-dd") == 0) debugLevel = DD;
		break;
	case 3:
		if (strcmp(argv[1], "-d") == 0)
			debugLevel = D;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = DD;
		if (ifLegalIP(argv[2]))//判断输入IP是否合法
		{
			strcpy(dnsServerIP, argv[2]);
			printf("DNS server 已设置为 : %s\n", argv[2]);
		}
		else 
		{
			printf("Warning:%s不是合法的ip地址\n", argv[2]);
		}
		break;

	case 4:
		if (strcmp(argv[1], "-d") == 0)
			debugLevel = D;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = DD;
		if (ifLegalIP(argv[2]))//判断输入IP是否合法
		{
			strcpy(dnsServerIP, argv[2]);
			printf("DNS server 已设置为 : %s\n", argv[2]);
		}
		else
		{
			printf("Warning:%s不是合法的ip地址\n", argv[2]);
		}
		strcpy(filePath, argv[3]);//使用用户输入的配置文件路径
		break;
	default:
		printf("输入格式错误\n");
	}
}

void outputCache()
{
	printf("\n\n--------------  Cache  --------------\n");
	int i = 0;
	for (i = 0; i < cacheCount; i++)
	{
		printf("#%d Url:%s -> IP:%s\n", i + 1, cache[i].domain, cache[i].IP);
	}
}

//判断输入IP地址合法
int ifLegalIP(char* ip) 
{
	int a, b, c, d;
	if (4 == sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)) 
	{
		if (0 <= a && a <= 255 && 0 <= b && b <= 255 && 0 <= c && c <= 255 && 0 <= d && d <= 255) 
		{
			return 1;
		}
		else  return 0;
	}
	else  return 0;
	
}

//从dnsrelay.txt中读取DNS域名解析表
int readLocalData()
{
	int i = 0;
	FILE* file;
	char ip[16], url[65];
	if ((file = fopen(filePath, "r")) == NULL)//文件不存在
	{
		printf("文件打开错误！");
		return -1;
	}
	while (fscanf(file, "%s %s", ip, url) != EOF && i < AMOUNT)//当文件没有读完并且解析表没有满时
	{
		if (debugLevel == DD)
			printf("从文件 “%s”中读入：[Url:% s, IP : % s]\n",filePath, url, ip);
		strcpy(DNSTable[i].IP, ip);
		strcpy(DNSTable[i].domain, url);
		i++;
	}
	if (i == AMOUNT - 1) printf("域名解析表已满！");
	fclose(file);
	printf("文件已成功读入。\n");
	return i - 1;//返回域名解析表中的条目个数
}

//设立超时时间
void setIDExpire(IDTransform* record, int ttl)
{
	record->expireTime = time(NULL) + ttl;
}

//检查超时
int checkIDExpired(IDTransform* record)
{
	return record->expireTime > 0 && time(NULL) > record->expireTime;
}


void addToCache(char* url, char* ip) //利用LRU算法，使最近使用的域名排在最前面，提升效率
{
	int i, j;
	int place = -1;
	for (i = 0; i < cacheCount; i++)
	{
		if (strcmp(url, cache[i].domain) == 0) { place = i; break; }
	}
	if (place > -1)//如果在cache内
	{
		for (j = i - 1; j >= 0; j--)
		{
			cache[j + 1] = cache[j];
		}
	}
	else//不在
	{
		for (i = cacheCount - 2; i >= 0; i--)
		{
			cache[i + 1] = cache[i];
		}
		if (cacheCount < MAX_CACHE_SIZE) cacheCount++;
	}
	strcpy(cache[0].domain, url);
	strcpy(cache[0].IP, ip);
}

//把新的对应关系添加到DNS域名解析表中
void addToTable(char* url, char* ip)
{
	strcpy(DNSTable[DNSNum].domain, url);
	strcpy(DNSTable[DNSNum].IP, ip);
	DNSNum++;
}
//添加到文件中
void addToFile(char* url, char* ip)
{
	FILE* file;
	if ((file = fopen(filePath, "a")) == NULL)//文件不存在
	{
		printf("文件打开错误！");
	}
	fputs("\n", file);
	fputs(ip, file);
	fputs(" ", file);
	fputs(url, file);
	fclose(file);
	printf("已成功把新IP写入文件。\n");
}

//更新ID转换表中ID
unsigned short registerNewID(unsigned short ID, SOCKADDR_IN temp)
{
	int i = 0;
	//int flag = 0;
	for (i = 0; i != MAX_ID_TRANS_TABLE_SIZE; ++i)
	{
		if (checkIDExpired(&IDTransTable[i]) == 1 || IDTransTable[i].done == TRUE)//如果是需要更新的条目
		{
			IDTransTable[i].oldID = ID;
			IDTransTable[i].client = temp;
			IDTransTable[i].done = FLASE;
			setIDExpire(&IDTransTable[i], ID_EXPIRE_TIME);
			IDcount++;
			if (debugLevel >= D)
			{
				printf("ID%d注册成功。\n现有ID数目：%d\n", i + 1, IDcount);
			}
			//flag = 1;
			break;
		}
	}
	if (i == MAX_ID_TRANS_TABLE_SIZE)
		return 0;
	return (unsigned short)i + 1;
}

//组装DNS请求报文中的域名
void getUrl(char* buf, char* dest)
{
	int i = 0, j = 0, k = 0;
	int len = strlen(buf);
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)//如果是数字
		{
			for (j = buf[i], i++; j > 0; j--, i++, k++)
				dest[k] = buf[i];
		}
		if (buf[i] != 0)
		{
			dest[k] = '.';
			k++;
		}
	}
	dest[k] = '\0';
}

//输出整个包
void outputPacket(char* buf, int length)
{
	unsigned char unit;
	printf("Packet长度 = %d\n", length);
	printf("Package:\n");
	for (int i = 0; i < length; i++)
	{
		unit = (unsigned char)buf[i];
		printf("%02x ", unit);
	}
	printf("\n");
}

//从外部主机接收数据
void receiveFromExtern()
{
	int i;

	//得到buf
	char buf[MAX_BUF_SIZE], url[65];
	memset(buf, 0, MAX_BUF_SIZE);
	int length = -1;
	length = recvfrom(extern_sock, buf, sizeof(buf), 0, (struct sockaddr*)&external, &length_client);

	if (length > -1)
	{
		if (debugLevel >= D)
		{
			printf("\n\n---- Recv : Extern [IP:%s]----\n", inet_ntoa(external.sin_addr));
			time_t t = time(NULL);
			char temp[64];
			strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
			printf("%s\n", temp);

			if (debugLevel == DD)
				outputPacket(buf, length);
		}

		//首先进行ID转换
		unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
		memcpy(pID, buf, sizeof(unsigned short));
		int idIndex = (*pID) - 1;//得到ID编号index
		free(pID);
		memcpy(buf, &IDTransTable[idIndex].oldID, sizeof(unsigned short));//buf的前16位赋给ID
		IDcount--;
		IDTransTable[idIndex].done = TRUE;
		client = IDTransTable[idIndex].client;
		//if (debugLevel >= D) printf("#ID Count : %d\n", IDcount);

		//开始分析Header
		int queryN = ntohs(*((unsigned short*)(buf + 4)));//question section的问题个数
		int responseN = ntohs(*((unsigned short*)(buf + 6)));//answer section的RR个数

		//开始分析Question
		char* p = buf + 12;
		char ip[16];
		int ip1, ip2, ip3, ip4;
		for (i = 0; i < queryN; i++)//得到quesion中存储的url
		{
			getUrl(p, url);
			//跳过操作
			while (*p > 0) p += (*p) + 1;
			p += 5;
		}
		if (responseN > 0 && debugLevel >= D) printf("Receive from extern [Url : %s]\n", url);


		//开始分析Answer
		for (int i = 0; i < responseN; ++i)
		{
			if ((unsigned char)*p == 0xc0) //name field是指针，从wireshark读出来的
				p += 2;
			else
			{
				while (*p > 0)
					p += (*p) + 1;
				++p;
			}
			unsigned short type = ntohs(*(unsigned short*)p);
			p += 2;
			unsigned short class = ntohs(*(unsigned short*)p);
			p += 2;
			unsigned short high = ntohs(*(unsigned short*)p);
			p += 2;
			unsigned short low = ntohs(*(unsigned short*)p);
			p += 2;
			int ttl = (((int)high) << 16) | low;
			int datalen = ntohs(*(unsigned short*)p);
			p += 2;

			if (debugLevel == DD) printf("Type -> %d,  Class -> %d,  TTL -> %d\n", type, class, ttl);

			if (type == 1) //如果是IPv4类型的地址
			{
				ip1 = (unsigned char)*p++;
				ip2 = (unsigned char)*p++;
				ip3 = (unsigned char)*p++;
				ip4 = (unsigned char)*p++;
				//打印资源记录里的IP地址
				sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
				if (debugLevel >= D) printf("IP address : %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
				//加到cache中
				addToCache(url, ip);
				addToTable(url, ip);
				addToFile(url, ip);

				break;
			}
			else p += datalen; //不是typeA就忽略
		}

		//发送给客户端

		length = sendto(local_sock, buf, length, 0, (SOCKADDR*)&client, sizeof(client));

	}
}

//从客户端接收
void receiveFromLocal()
{
	int i, j;
	int flag_txt = -1;
	int flag_cache = -1;
	char buf[MAX_BUF_SIZE], url[65];
	memset(buf, 0, MAX_BUF_SIZE);
	//从客户端接收到buf
	int length = -1;
	length = recvfrom(local_sock, buf, sizeof buf, 0, (struct sockaddr*)&client, &length_client);
	if (length > 0)
	{
		char urlTmp[65]; //允许url最大长度为65
		memcpy(urlTmp, &(buf[DNS_HEAD_SIZE]), sizeof(urlTmp));

		getUrl(urlTmp, url); //得到url
		if (debugLevel >= D)
		{
			printf("\n\n---- Recv : Client [IP:%s]----\n", inet_ntoa(client.sin_addr));
			time_t t = time(NULL);
			char temp[64];
			strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
			printf("%s\n", temp);
			printf("Receive from client [Query : %s]\n", url);
		}

		for (i = 0; i < MAX_CACHE_SIZE; i++)//先在cache中查找
		{
			if (strcmp(url, cache[i].domain) == 0) flag_cache = i;
		}

		if (flag_cache == -1)//当在cache内没有找到时再到域名解析表中查找
		{
			for (i = 0; i < DNSNum; i++)
			{
				if (strcmp(url, DNSTable[i].domain) == 0)
				{
					flag_txt = i;//与DNSTable中第i条相等
					break;
				}
			}
		}

		char ip[16];
		//当文件和cache中都找不到时
		if (flag_txt == -1 && flag_cache == -1)
		{
			printf("[Url : %s] 没有在文件或cache中找到。\n", url);

			//存到ID转换表中
			unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
			memcpy(pID, buf, sizeof(unsigned short));
			unsigned short nID = registerNewID(*pID, client);

			if (nID == 0)
			{
				if (debugLevel >= D)printf("ID转换表已满，添加失败！\n");
			}
			else
			{
				memcpy(buf, &nID, sizeof(unsigned short));//更改buf中的id

				//发送给外部DNS
				length = sendto(extern_sock, buf, length, 0, (struct sockaddr*)&extern_name, sizeof(extern_name));
				if (debugLevel >= D) printf("发送给 external DNS server [Url : %s]\n", url);
			}
			free(pID);
		}
		else //在文件或cache中找到了
		{
			//在文件中找到时
			if (flag_txt != -1 && flag_cache == -1)
			{
				strcpy(ip, DNSTable[flag_txt].IP);
				addToCache(url, ip);
				if (debugLevel >= D) printf("从本地文件中读取: [Url:%s -> IP:%s]\n", url, ip);
			}

			//在cache中找到时
			if (flag_txt == -1 && flag_cache != -1)
			{
				strcpy(ip, cache[flag_cache].IP);
				addToCache(url, ip);
				if (debugLevel >= D) printf("从cache中读取： [Url:%s -> IP:%s]\n", url, ip);
			}

			//开始构造响应报文
			char bufSend[MAX_BUF_SIZE];
			//添加请求报文部分
			memcpy(bufSend, buf, length);

			//如果是屏蔽网址，把rcode改为3直接发回
			if (strcmp(ip, "0.0.0.0") == 0)
			{
				unsigned short a = htons(0x8183);
				memcpy(&bufSend[2], &a, sizeof(unsigned short));
				if (debugLevel > D)  printf("Warning: URL[%s] 为非法网址.\n", url);
				sendto(local_sock, bufSend, length, 0, (SOCKADDR*)&client, sizeof(client));
			}

			//如果是非屏蔽地址
			
			//FLAG部分
			unsigned short a;
			a = htons(0x8180);//wireshark
			memcpy(&bufSend[2], &a, sizeof(unsigned short));

			//ANCOUNT answer section部分RR个数
			a = htons(0x0001);
			memcpy(&bufSend[6], &a, sizeof(unsigned short));

			//Answer部分 
			unsigned short tmp;
			unsigned long tmpl;
			char answer[16];
			int len = 0;
			//Name
			tmp = htons(0xc00c); // 开头两个11代表指向域名的指针
			memcpy(answer, &tmp, sizeof(unsigned short));
			len += sizeof(unsigned short);
			//Type
			tmp = htons(0x0001); //typeA
			memcpy(answer + len, &tmp, sizeof(unsigned short));
			len += sizeof(unsigned short);
			//Class
			tmp = htons(0x0001);//固定为1，表示IN
			memcpy(answer + len, &tmp, sizeof(unsigned short));
			len += sizeof(unsigned short);
			//TTL
			tmpl = htonl(0x64);
			memcpy(answer + len, &tmpl, sizeof(unsigned long));
			len += sizeof(unsigned long);
			//RDLength
			tmp = htons(0x0004);
			memcpy(answer + len, &tmp, sizeof(unsigned short));
			len += sizeof(unsigned short);
			//RData
			tmpl = (unsigned long)inet_addr(ip);
			memcpy(answer + len, &tmpl, sizeof(unsigned long));
			len += sizeof(unsigned long);
			//组装
			len += length;
			memcpy(bufSend + length, answer, sizeof(answer));//把answer附加到要发送的buf后

			//发送
			length = sendto(local_sock, bufSend, len, 0, (SOCKADDR*)&client, sizeof(client));
			//输出调试信息
			if (length == -1 && debugLevel > D)
				printf("Sendto:发送给客户失败。 错误代码 = %d\n", WSAGetLastError());
			else if (length == 0)
			{
				if (debugLevel > D) printf("Sendto: 连接失败。\n");
			}
			else if (debugLevel > D)
				printf("Sendto: 成功把响应报文发送给客户。\n");
			char* p;
			p = bufSend + length - 4;
			if (debugLevel >= D)
				printf("Send packet [Url:%s -> IP:%u.%u.%u.%u]\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));

			if (flag_cache != -1 && debugLevel >= D) outputCache();
		}
	}

}







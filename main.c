#include"head.h"

int main(int argc, char* argv[])
{
	dealPara(argc, argv);//�������루���Եȼ���
	initIDTable();//��ʼ��IDת����

	WSAStartup(MAKEWORD(2, 2), &wsaData);//ʹ��2.2�汾��Socket  

	local_sock = socket(AF_INET, SOCK_DGRAM, 0);
	extern_sock = socket(AF_INET, SOCK_DGRAM, 0);

	//ʹ�÷�������socket
	int non_block = 1;
	ioctlsocket(extern_sock, FIONBIO, (u_long FAR*) & non_block);
	ioctlsocket(local_sock, FIONBIO, (u_long FAR*) & non_block);
	if (local_sock < 0)
	{
		if (debugLevel >= D) printf("socket����ʧ��.\n");
		exit(1);
	}
	printf("socket�����ɹ�.\n");
	//����local socket
	local_name.sin_family = AF_INET; //Э�����ΪTCP/IP
	local_name.sin_addr.s_addr = INADDR_ANY; //IP��ַ��Ϊany
	local_name.sin_port = htons(DNS_PORT);  //�Ѷ˿���Ϊ53
	//����extern socket
	extern_name.sin_family = AF_INET;
	extern_name.sin_addr.s_addr = inet_addr(dnsServerIP);
	extern_name.sin_port = htons(DNS_PORT);

	int reuse = 1;
	setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
	//SO_REUSEADDER���������ñ��ص�ַ�Ͷ˿�

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

//��ʼ��IDת����
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
		if (ifLegalIP(argv[2]))//�ж�����IP�Ƿ�Ϸ�
		{
			strcpy(dnsServerIP, argv[2]);
			printf("DNS server ������Ϊ : %s\n", argv[2]);
		}
		else 
		{
			printf("Warning:%s���ǺϷ���ip��ַ\n", argv[2]);
		}
		break;

	case 4:
		if (strcmp(argv[1], "-d") == 0)
			debugLevel = D;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = DD;
		if (ifLegalIP(argv[2]))//�ж�����IP�Ƿ�Ϸ�
		{
			strcpy(dnsServerIP, argv[2]);
			printf("DNS server ������Ϊ : %s\n", argv[2]);
		}
		else
		{
			printf("Warning:%s���ǺϷ���ip��ַ\n", argv[2]);
		}
		strcpy(filePath, argv[3]);//ʹ���û�����������ļ�·��
		break;
	default:
		printf("�����ʽ����\n");
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

//�ж�����IP��ַ�Ϸ�
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

//��dnsrelay.txt�ж�ȡDNS����������
int readLocalData()
{
	int i = 0;
	FILE* file;
	char ip[16], url[65];
	if ((file = fopen(filePath, "r")) == NULL)//�ļ�������
	{
		printf("�ļ��򿪴���");
		return -1;
	}
	while (fscanf(file, "%s %s", ip, url) != EOF && i < AMOUNT)//���ļ�û�ж��겢�ҽ�����û����ʱ
	{
		if (debugLevel == DD)
			printf("���ļ� ��%s���ж��룺[Url:% s, IP : % s]\n",filePath, url, ip);
		strcpy(DNSTable[i].IP, ip);
		strcpy(DNSTable[i].domain, url);
		i++;
	}
	if (i == AMOUNT - 1) printf("����������������");
	fclose(file);
	printf("�ļ��ѳɹ����롣\n");
	return i - 1;//���������������е���Ŀ����
}

//������ʱʱ��
void setIDExpire(IDTransform* record, int ttl)
{
	record->expireTime = time(NULL) + ttl;
}

//��鳬ʱ
int checkIDExpired(IDTransform* record)
{
	return record->expireTime > 0 && time(NULL) > record->expireTime;
}


void addToCache(char* url, char* ip) //����LRU�㷨��ʹ���ʹ�õ�����������ǰ�棬����Ч��
{
	int i, j;
	int place = -1;
	for (i = 0; i < cacheCount; i++)
	{
		if (strcmp(url, cache[i].domain) == 0) { place = i; break; }
	}
	if (place > -1)//�����cache��
	{
		for (j = i - 1; j >= 0; j--)
		{
			cache[j + 1] = cache[j];
		}
	}
	else//����
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

//���µĶ�Ӧ��ϵ��ӵ�DNS������������
void addToTable(char* url, char* ip)
{
	strcpy(DNSTable[DNSNum].domain, url);
	strcpy(DNSTable[DNSNum].IP, ip);
	DNSNum++;
}
//��ӵ��ļ���
void addToFile(char* url, char* ip)
{
	FILE* file;
	if ((file = fopen(filePath, "a")) == NULL)//�ļ�������
	{
		printf("�ļ��򿪴���");
	}
	fputs("\n", file);
	fputs(ip, file);
	fputs(" ", file);
	fputs(url, file);
	fclose(file);
	printf("�ѳɹ�����IPд���ļ���\n");
}

//����IDת������ID
unsigned short registerNewID(unsigned short ID, SOCKADDR_IN temp)
{
	int i = 0;
	//int flag = 0;
	for (i = 0; i != MAX_ID_TRANS_TABLE_SIZE; ++i)
	{
		if (checkIDExpired(&IDTransTable[i]) == 1 || IDTransTable[i].done == TRUE)//�������Ҫ���µ���Ŀ
		{
			IDTransTable[i].oldID = ID;
			IDTransTable[i].client = temp;
			IDTransTable[i].done = FLASE;
			setIDExpire(&IDTransTable[i], ID_EXPIRE_TIME);
			IDcount++;
			if (debugLevel >= D)
			{
				printf("ID%dע��ɹ���\n����ID��Ŀ��%d\n", i + 1, IDcount);
			}
			//flag = 1;
			break;
		}
	}
	if (i == MAX_ID_TRANS_TABLE_SIZE)
		return 0;
	return (unsigned short)i + 1;
}

//��װDNS�������е�����
void getUrl(char* buf, char* dest)
{
	int i = 0, j = 0, k = 0;
	int len = strlen(buf);
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)//���������
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

//���������
void outputPacket(char* buf, int length)
{
	unsigned char unit;
	printf("Packet���� = %d\n", length);
	printf("Package:\n");
	for (int i = 0; i < length; i++)
	{
		unit = (unsigned char)buf[i];
		printf("%02x ", unit);
	}
	printf("\n");
}

//���ⲿ������������
void receiveFromExtern()
{
	int i;

	//�õ�buf
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

		//���Ƚ���IDת��
		unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
		memcpy(pID, buf, sizeof(unsigned short));
		int idIndex = (*pID) - 1;//�õ�ID���index
		free(pID);
		memcpy(buf, &IDTransTable[idIndex].oldID, sizeof(unsigned short));//buf��ǰ16λ����ID
		IDcount--;
		IDTransTable[idIndex].done = TRUE;
		client = IDTransTable[idIndex].client;
		//if (debugLevel >= D) printf("#ID Count : %d\n", IDcount);

		//��ʼ����Header
		int queryN = ntohs(*((unsigned short*)(buf + 4)));//question section���������
		int responseN = ntohs(*((unsigned short*)(buf + 6)));//answer section��RR����

		//��ʼ����Question
		char* p = buf + 12;
		char ip[16];
		int ip1, ip2, ip3, ip4;
		for (i = 0; i < queryN; i++)//�õ�quesion�д洢��url
		{
			getUrl(p, url);
			//��������
			while (*p > 0) p += (*p) + 1;
			p += 5;
		}
		if (responseN > 0 && debugLevel >= D) printf("Receive from extern [Url : %s]\n", url);


		//��ʼ����Answer
		for (int i = 0; i < responseN; ++i)
		{
			if ((unsigned char)*p == 0xc0) //name field��ָ�룬��wireshark��������
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

			if (type == 1) //�����IPv4���͵ĵ�ַ
			{
				ip1 = (unsigned char)*p++;
				ip2 = (unsigned char)*p++;
				ip3 = (unsigned char)*p++;
				ip4 = (unsigned char)*p++;
				//��ӡ��Դ��¼���IP��ַ
				sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
				if (debugLevel >= D) printf("IP address : %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
				//�ӵ�cache��
				addToCache(url, ip);
				addToTable(url, ip);
				addToFile(url, ip);

				break;
			}
			else p += datalen; //����typeA�ͺ���
		}

		//���͸��ͻ���

		length = sendto(local_sock, buf, length, 0, (SOCKADDR*)&client, sizeof(client));

	}
}

//�ӿͻ��˽���
void receiveFromLocal()
{
	int i, j;
	int flag_txt = -1;
	int flag_cache = -1;
	char buf[MAX_BUF_SIZE], url[65];
	memset(buf, 0, MAX_BUF_SIZE);
	//�ӿͻ��˽��յ�buf
	int length = -1;
	length = recvfrom(local_sock, buf, sizeof buf, 0, (struct sockaddr*)&client, &length_client);
	if (length > 0)
	{
		char urlTmp[65]; //����url��󳤶�Ϊ65
		memcpy(urlTmp, &(buf[DNS_HEAD_SIZE]), sizeof(urlTmp));

		getUrl(urlTmp, url); //�õ�url
		if (debugLevel >= D)
		{
			printf("\n\n---- Recv : Client [IP:%s]----\n", inet_ntoa(client.sin_addr));
			time_t t = time(NULL);
			char temp[64];
			strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
			printf("%s\n", temp);
			printf("Receive from client [Query : %s]\n", url);
		}

		for (i = 0; i < MAX_CACHE_SIZE; i++)//����cache�в���
		{
			if (strcmp(url, cache[i].domain) == 0) flag_cache = i;
		}

		if (flag_cache == -1)//����cache��û���ҵ�ʱ�ٵ������������в���
		{
			for (i = 0; i < DNSNum; i++)
			{
				if (strcmp(url, DNSTable[i].domain) == 0)
				{
					flag_txt = i;//��DNSTable�е�i�����
					break;
				}
			}
		}

		char ip[16];
		//���ļ���cache�ж��Ҳ���ʱ
		if (flag_txt == -1 && flag_cache == -1)
		{
			printf("[Url : %s] û�����ļ���cache���ҵ���\n", url);

			//�浽IDת������
			unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
			memcpy(pID, buf, sizeof(unsigned short));
			unsigned short nID = registerNewID(*pID, client);

			if (nID == 0)
			{
				if (debugLevel >= D)printf("IDת�������������ʧ�ܣ�\n");
			}
			else
			{
				memcpy(buf, &nID, sizeof(unsigned short));//����buf�е�id

				//���͸��ⲿDNS
				length = sendto(extern_sock, buf, length, 0, (struct sockaddr*)&extern_name, sizeof(extern_name));
				if (debugLevel >= D) printf("���͸� external DNS server [Url : %s]\n", url);
			}
			free(pID);
		}
		else //���ļ���cache���ҵ���
		{
			//���ļ����ҵ�ʱ
			if (flag_txt != -1 && flag_cache == -1)
			{
				strcpy(ip, DNSTable[flag_txt].IP);
				addToCache(url, ip);
				if (debugLevel >= D) printf("�ӱ����ļ��ж�ȡ: [Url:%s -> IP:%s]\n", url, ip);
			}

			//��cache���ҵ�ʱ
			if (flag_txt == -1 && flag_cache != -1)
			{
				strcpy(ip, cache[flag_cache].IP);
				addToCache(url, ip);
				if (debugLevel >= D) printf("��cache�ж�ȡ�� [Url:%s -> IP:%s]\n", url, ip);
			}

			//��ʼ������Ӧ����
			char bufSend[MAX_BUF_SIZE];
			//��������Ĳ���
			memcpy(bufSend, buf, length);

			//�����������ַ����rcode��Ϊ3ֱ�ӷ���
			if (strcmp(ip, "0.0.0.0") == 0)
			{
				unsigned short a = htons(0x8183);
				memcpy(&bufSend[2], &a, sizeof(unsigned short));
				if (debugLevel > D)  printf("Warning: URL[%s] Ϊ�Ƿ���ַ.\n", url);
				sendto(local_sock, bufSend, length, 0, (SOCKADDR*)&client, sizeof(client));
			}

			//����Ƿ����ε�ַ
			
			//FLAG����
			unsigned short a;
			a = htons(0x8180);//wireshark
			memcpy(&bufSend[2], &a, sizeof(unsigned short));

			//ANCOUNT answer section����RR����
			a = htons(0x0001);
			memcpy(&bufSend[6], &a, sizeof(unsigned short));

			//Answer���� 
			unsigned short tmp;
			unsigned long tmpl;
			char answer[16];
			int len = 0;
			//Name
			tmp = htons(0xc00c); // ��ͷ����11����ָ��������ָ��
			memcpy(answer, &tmp, sizeof(unsigned short));
			len += sizeof(unsigned short);
			//Type
			tmp = htons(0x0001); //typeA
			memcpy(answer + len, &tmp, sizeof(unsigned short));
			len += sizeof(unsigned short);
			//Class
			tmp = htons(0x0001);//�̶�Ϊ1����ʾIN
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
			//��װ
			len += length;
			memcpy(bufSend + length, answer, sizeof(answer));//��answer���ӵ�Ҫ���͵�buf��

			//����
			length = sendto(local_sock, bufSend, len, 0, (SOCKADDR*)&client, sizeof(client));
			//���������Ϣ
			if (length == -1 && debugLevel > D)
				printf("Sendto:���͸��ͻ�ʧ�ܡ� ������� = %d\n", WSAGetLastError());
			else if (length == 0)
			{
				if (debugLevel > D) printf("Sendto: ����ʧ�ܡ�\n");
			}
			else if (debugLevel > D)
				printf("Sendto: �ɹ�����Ӧ���ķ��͸��ͻ���\n");
			char* p;
			p = bufSend + length - 4;
			if (debugLevel >= D)
				printf("Send packet [Url:%s -> IP:%u.%u.%u.%u]\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));

			if (flag_cache != -1 && debugLevel >= D) outputCache();
		}
	}

}







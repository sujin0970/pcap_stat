#if !defined(WIN32) && !defined(WINx64)

#include <in.h> 

#endif
#include <iostream>
#include <string>
#include <vector>
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "RawPacket.h"
#include <bits/stdc++.h>
#include "json/json.h"
#include <unistd.h>   
#include <sys/stat.h>
#include <errno.h>      

using namespace std;


u_char ftp_data[1111111];
u_char smtp_data[1111111];
u_char smtp_data_file[1111111];
u_char http_data[111][1111111];
int smtp_data_flag, http_get_flag;
unsigned int ftp_data_size, ftp_data_idx, smtp_data_idx, smtp_data_file_idx;
string http_get_filename;
int http_data_idx[111];
unsigned long http_sequence_num[111];
int server_port = 0;
int client_port = 0;

vector<pair<int, string>> http_get_data_port; // HTTP 데이터 수집을 위해 선언
vector<pair<int, string>> FTP_LOG;
queue<pair<string, string>> FTP_QUEUE;
int ftp_response_code;
string ftp_response_arg, ftp_request_cmd, ftp_request_arg;

Json::Value root;
Json::Value smtp;
Json::Value http;

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType) {
   switch (protocolType) {
      case pcpp::Ethernet:
      return "Ethernet";

      case pcpp::IPv4:
      return "IPv4";

      case pcpp::TCP:
      return "TCP";

      case pcpp::HTTPRequest:
      case pcpp::HTTPResponse:
      return "HTTP";

      default:
      return "Unknown";
   }
}

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer) {
   std::string result = "";

   if (tcpLayer->getTcpHeader()->synFlag == 1) result += "SYN ";
   if (tcpLayer->getTcpHeader()->ackFlag == 1) result += "ACK ";
   if (tcpLayer->getTcpHeader()->pshFlag == 1) result += "PSH ";
   if (tcpLayer->getTcpHeader()->cwrFlag == 1) result += "CWR ";
   if (tcpLayer->getTcpHeader()->urgFlag == 1) result += "URG ";
   if (tcpLayer->getTcpHeader()->eceFlag == 1) result += "ECE ";
   if (tcpLayer->getTcpHeader()->rstFlag == 1) result += "RST ";
   if (tcpLayer->getTcpHeader()->finFlag == 1) result += "FIN ";

   return result;
}

std::string printTcpOptionType(pcpp::TcpOptionType optionType) {
   switch (optionType) {
   case pcpp::PCPP_TCPOPT_NOP:
   return "NOP";

   case pcpp::PCPP_TCPOPT_TIMESTAMP:
   return "Timestamp";

   default:
   return "Other";
   }
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod) {
   switch (httpMethod) {
   case pcpp::HttpRequestLayer::HttpGET:
   return "GET";

   case pcpp::HttpRequestLayer::HttpPOST:
   return "POST";

   default:
   return "Other";
   }
}

uint8_t my_ntohs(uint8_t n) {
   return (n & 0xf0) >> 4 | (n & 0x0f) << 4;
}

//===================================BOB9_FINAL_WORK==============================================
struct pcap_by_IP 
{ string IP_address; 
  int send_packet_num;
  int receive_packet_num;
  vector<int> send_packet_byte;
  vector<int> receive_packet_byte;
};

vector<pcap_by_IP> vec_by_IP;
//=================================================================================================

int main(int argc, char* argv[]) {

   char* filename = argv[1];
   int ftpResult = mkdir( "FTP_directory" , 0777);
   int smtpResult = mkdir( "SMTP_directory" , 0777);
   int httpResult = mkdir( "HTTP_directory" , 0777);

   // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
   // and create an interface instance that both readers implement
   pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename);

   // verify that a reader interface was indeed created
   if (reader == NULL) {
      printf("Cannot determine reader for file type\n");
      exit(1);
   }

   // open the reader for reading
   if (!reader->open()) {
      printf("Cannot open input.pcap for reading\n");
      exit(1);
   }

   unsigned int ftp_data_port = 0;
   unsigned int packet_num = 1;

   // 패킷 반복적으로 읽어오기
   while(1) {
      pcpp::RawPacket rawPacket;

      if (!reader->getNextPacket(rawPacket)) {
         break;
      }

      // parse the raw packet
      pcpp::Packet parsedPacket(&rawPacket);

      //각 계층마다 : type, total length, header length, payload length
      printf("\n\n=========================================================================================================\n");
      int is_tcp =0;
      int payload_length =0;
      int total_length =0;

      for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()) {
         is_tcp++;
         if (is_tcp == 1) total_length = (int)curLayer->getDataLen();
         if (is_tcp == 4) payload_length = (int)curLayer->getDataLen();

         printf("Layer type: %s; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
         getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
         (int)curLayer->getDataLen(), // get total length of the layer
         (int)curLayer->getHeaderLen(), // get the header length of the layer
         (int)curLayer->getLayerPayloadSize()); // get the payload length of the layer (equals total length minus header length)
      }

      //****************Ethernet layer*****************
      pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
      if (ethernetLayer == NULL) {
         printf("Something went wrong, couldn't find Ethernet layer\n");
         continue;
      }
      // 이더넷 헤더에서 SrcMac, DstMac, Ether type 출력
      printf("\nSource MAC address: %s\n", ethernetLayer->getSourceMac().toString().c_str());
      printf("Destination MAC address: %s\n", ethernetLayer->getDestMac().toString().c_str());
      printf("Ether type = 0x%X\n", ntohs(ethernetLayer->getEthHeader()->etherType));



      //****************IPv4 layer*****************
      pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
      if (ipLayer == NULL) {
         printf("Couldn't find IPv4 layer\n");
         continue;
      }
      // IP 헤더에서 SrcIP, DstIP, IP ID , TTL 출력
      printf("\nSource IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
      printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
      printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
      printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);






      //===================================BOB9_FINAL_WORK==============================================
      string ip_address_check = ipLayer->getSrcIpAddress().toString(); // src IP
      bool is_ip_same = 0;
      for (int i =0; i< vec_by_IP.size(); i++){
         if ( vec_by_IP[i].IP_address ==  ip_address_check) {
            is_ip_same = 1;
            vec_by_IP[i].send_packet_num ++;
            vec_by_IP[i].send_packet_byte.push_back(total_length);
         }
      }
      if(is_ip_same == 0){
         pcap_by_IP temp_send_struct;
         temp_send_struct.IP_address = ip_address_check;
         temp_send_struct.send_packet_num = 1;
         temp_send_struct.receive_packet_num = 0;
         temp_send_struct.send_packet_byte.push_back(total_length);
         vec_by_IP.push_back(temp_send_struct);
      }
      
      ip_address_check = ipLayer->getDstIpAddress().toString(); // dest IP
      is_ip_same = 0;
      for (int i =0; i< vec_by_IP.size(); i++){
         if ( vec_by_IP[i].IP_address ==  ip_address_check) {
            is_ip_same = 1;
            vec_by_IP[i].receive_packet_num ++;
            vec_by_IP[i].receive_packet_byte.push_back(total_length);
         }
      }
      if(is_ip_same == 0){
         pcap_by_IP temp_receive_struct;
         temp_receive_struct.IP_address = ip_address_check;
         temp_receive_struct.receive_packet_num = 1;
         temp_receive_struct.send_packet_num = 0;
         temp_receive_struct.receive_packet_byte.push_back(total_length);
         vec_by_IP.push_back(temp_receive_struct);
      }
      //=================================================================================================






      //****************TCP layer*****************
      pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
      if (tcpLayer == NULL) {
         printf("Couldn't find TCP layer\n");
         continue;
      }
      // TCP 헤더에서 SrcPort, DstPort, window size, TCP flags 출력
      printf("\nSource TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portSrc));
      printf("Destination TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portDst));
      printf("Window size: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->windowSize));
      printf("TCP flags: %s\n", printTcpFlags(tcpLayer).c_str());
      printf("TCP Sequence Number : %lu\n", ntohl(tcpLayer->getTcpHeader()->sequenceNumber));
      printf("TCP Ack Number : %lu\n", ntohl(tcpLayer->getTcpHeader()->ackNumber));
      // HTTP, SMTP, FTP 의 구분을 위해서 src, dst의 port번호 저장
      int src_port = (int)ntohs(tcpLayer->getTcpHeader()->portSrc); 
      int dst_port = (int)ntohs(tcpLayer->getTcpHeader()->portDst);

      pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
      int payload_start = total_length - payload_length;


      //HTTP : 서버에서 SrcPort 80으로 오는 패킷의 데이터 합치기
      if (http_get_data_port.size() >= 1 && src_port == 80) { 
         int flag1 = 0; 
         int port_num = -1;
         for (int i = 0; i < http_get_data_port.size(); i++) {
            if (dst_port == http_get_data_port[i].first) {
               flag1 = 1;  //데이터가 들어오기 시작한 포트번호인 경우
               port_num = i;  
               break;
            }
         }
         if (flag1) { //해당 포트번호로 들어오는 패킷 합치기
            if (http_sequence_num[port_num] == 0) {
               http_sequence_num[port_num] = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
            } else if (http_sequence_num[port_num] < ntohl(tcpLayer->getTcpHeader()->sequenceNumber)) {
               const u_char* packet;
               packet = (u_char*) rawPacket.getRawData();
               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;
               int payload_start = total_length - payload_length;
               uint16_t TOTAL_LENGTH = ntohs(ipLayer->getIPv4Header()->totalLength) + 14;
               if (!(packet[payload_start] == 0x48 && packet[payload_start + 1] == 0x54 &&
               packet[payload_start + 2] == 0x54 && packet[payload_start + 3] == 0x50)) {
                  for (int i = payload_start; i < total_length; i++) {
                     http_data[port_num][http_data_idx[port_num]++] = packet[i];
                  }
               } 
            }               
         }
      }


      //*************** HTTP ? SMTP ? FTP ? *****************
      if (is_tcp == 4) { //payload 있음
         if (httpRequestLayer == NULL) {

            //*********************SMTP 패킷*********************
            if ((src_port == 25 || src_port == 465 || src_port == 587 ) || (dst_port == 25 || dst_port == 465 || dst_port == 587)) {  
               printf("\n[ SMTP Packet ]\n");

               const u_char* packet;
               packet = (u_char*) rawPacket.getRawData();
               string smtp_response_code = "";

               //SMTP response code 가져오기
               for (int i = payload_start; i < payload_start + 3; i++) {
                     smtp_response_code += packet[i];
                  }

               if(smtp_response_code == "220"){  // 220이면 TCP 연결 시작, 서버 준비완료, SMTP 통신 시작
                     server_port =  src_port ;
                     client_port =  dst_port ;
               }

               else{
                  if (src_port == server_port ) { // server -> client
                     printf("(server) -> (client)  \n");
       
                     for(int i= payload_start; i < total_length; i++){
                        printf("%c", packet[i]);
                     }

                     if (smtp_response_code == "354") {  // 354이면 서버에서 데이터를 보냄.
                        smtp_data_flag = 1;
                     }

                     if (smtp_data_flag && smtp_response_code == "250") {  // 250이면 서버에서 데이터가 다 도착했음.
                        smtp_data_flag = 0;
                        int temp_int = 0;
                        int temp_flag= 0;

                        printf("\n\n\n --------------  This is DATA  --------------  \n\n\n");
                        for (int i = 0; i < smtp_data_idx; i++) {
                           printf("%c" , smtp_data[i]);
                           //filename 이라는 문자열이 들어오면, smtp_data에서 해당 위치를 저장
                           if(smtp_data[i]=='f'&&  smtp_data[i+1]=='i'&& smtp_data[i+2]=='l'&& smtp_data[i+3]=='e'&& smtp_data[i+4]=='n'&& smtp_data[i+5]=='a'&&smtp_data[i+6]=='m'&&smtp_data[i+7]=='e'){
                              temp_int = i;
                           }
                        }

                        char filename_smtp[111] = "";
                        int filename_idx =0;
                        for(int i = temp_int + 10 ; ; i++){
                           filename_smtp[filename_idx++] = smtp_data[i];  //smtp에 첨부된 파일이름저장
                           if(smtp_data[i+1]=='"' || smtp_data[i+1]=='/r' || smtp_data[i+1]=='/t' || smtp_data[i+1]=='/n') {filename_smtp[filename_idx] = '\0'; break;}
                        }
                        printf("filename : ");
                        for(int i =0; i< filename_idx; i++){printf("%c", filename_smtp[i]);}
                        printf("\n\n");

                        for(int k = temp_int; k < smtp_data_idx; k++){
                           if(smtp_data[k] == '"') {
                              temp_flag = k;
                              break;
                           }
                        }

                        for(int k = temp_flag+1 ; k < smtp_data_idx; k++){
                           if(smtp_data[k] == '"') {
                              temp_flag = k+4;
                              break;
                           }
                        }

                        for(int i = temp_flag; i < smtp_data_idx; i++){
                           smtp_data_file[smtp_data_file_idx++] = smtp_data[i];
                           //여러 패킷으로 나눠져서 들어오는 부분중에서  --------=NextPart_~~ 부분을 삭제하고 저장.
                           if(  smtp_data[i+1]=='-'&& smtp_data[i+2]=='-'&& smtp_data[i+3]=='-'&& smtp_data[i+4]=='-'&& smtp_data[i+5]=='-'&&smtp_data[i+6]=='-'&&smtp_data[i+7]=='='&&smtp_data[i+8]=='_'){
                              smtp_data_file[smtp_data_file_idx]='\0';
                              break;
                           }
                        }

                        //첨부된 파일을 형식에 맞게 추출. 파일 이름에 .dat와 같은 식으로 명시되어 있음.
                        char smtp_file_path[111111] = "SMTP_directory/";
                        strcat(smtp_file_path, filename_smtp);
                        FILE * file = fopen(smtp_file_path, "wb");
                        fwrite (smtp_data_file, sizeof(smtp_data_file), 1, file);
                        fclose (file);

                        printf("\n\n\n --------------  DATA END  --------------  \n\n\n");
                        smtp_data_idx = 0;

                        Json::Value temp;
                        temp["Packet Number"] = packet_num++;
                        temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
                        temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
                        temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
                        temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
                        temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
                        temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
                        temp["Protocol"] = "SMTP-DATA";

                        smtp.append(temp);
                     }  


                  } else if (dst_port == server_port ) { // client -> server
                     printf("(client) -> (server)\n");
                     if (smtp_data_flag) {
                        for (int i = payload_start; i < total_length; i++) {
                           smtp_data[smtp_data_idx++] = packet[i];
                        }
                        printf(" == DATA fragment == \n");
                     }
                     else{
                        for(int i= payload_start; i < total_length; i++){
                           printf("%c", packet[i]);
                        }
                     }

                     Json::Value temp;
                     temp["Packet Number"] = packet_num++;
                     temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
                     temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
                     temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
                     temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
                     temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
                     temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
                     temp["Protocol"] = "SMTP client -> server";

                     smtp.append(temp);
                  }

               }


            //*********************FTP 패킷*********************
            } else if (src_port == 21) { // FTP Response 패킷이라면...
               printf("\n[ FTP Response Packet ]\n");
               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;
               uint16_t TOTAL_LENGTH = ntohs(ipLayer->getIPv4Header()->totalLength) + 14;

               printf("TCP header len is %d\n", my_ntohs(packet[46]) * 4);
               printf("start index is %d\n", start);
               printf("total length is %d\n", total_length);
               printf("\nResponse: ");

               for (int i = payload_start; i<total_length; i++) {
                  printf("%c", packet[i]);
               }

               std::string ftp_command = "";

               //FTP response code 가져오기
               printf("\nResponse Code : ");
               for (int i = start; i < start + 3; i++) {
                  ftp_command += (u_char) packet[i];
               }
               ftp_response_code = atoi(ftp_command.c_str());
               printf("%d", ftp_response_code);

               ftp_command = "";
            
               printf("\nResponse Arg : ");
               for (int i = start + 4; i < TOTAL_LENGTH; i++) {
                  if (packet[i] == 0x0d) break; // \r을 만나면 바로 종료... 끝이니까...
                  ftp_command += (u_char) packet[i];
                  printf("%c", packet[i]);
               }
               printf("\n");
               
               ftp_response_arg = ftp_command;
               std::cout << ftp_response_arg << '\n';
               
               //FTP_LOG 벡터에 response code, arg 저장
               FTP_LOG.push_back({ ftp_response_code, ftp_response_arg });
               
               
               //Passive Mode 227
               if (ftp_response_code == 227) { 
                  ftp_data_port = 0;
                  std::string port_temp = "";
                  for (int i = 23; i < ftp_command.length(); i++) {
                     if (ftp_command[i] == ')') break;
                     port_temp += ftp_command[i];
                  }
                  char* num_arr = new char[1000];
                  strcpy(num_arr, port_temp.c_str());

                  char* tok = strtok(num_arr, ",");
                  int cnt = 0;
                  while (tok != NULL) {
                     cnt++;
                     if (cnt == 5) {
                        ftp_data_port += atoi(tok) * 256;
                     } else if (cnt == 6) {
                        ftp_data_port += atoi(tok);
                     }
                     tok = strtok(NULL, ",");
                  }
               }

               //파일 전송 완료 226
               if (ftp_response_code == 226 && ftp_data_size != 0) { 
                  printf("ftp data size : %d\n", ftp_data_size);
               
                  // 추출한 데이터를 파일로 저장
                  ofstream myfile;
                  string ftp_file_path = "FTP_directory/";
                  ftp_file_path = ftp_file_path + ftp_request_arg;
                  myfile.open(ftp_file_path, ios::binary);
                  myfile.write((const char*) ftp_data, ftp_data_size);
                  myfile.close();
                  memset(ftp_data, 0, sizeof(ftp_data));
                  ftp_data_size = ftp_data_idx = 0;
               }
               printf("ftp_data_port : %d\n", ftp_data_port);


               Json::Value temp;
               temp["Packet Number"] = packet_num++;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP";
               temp["Response code"] = ftp_response_code;
               temp["Response arg"] = ftp_response_arg;

               root.append(temp);

            } else if (dst_port == 21) { // FTP Request 패킷이라면...
               printf("\n[ FTP Request Packet ]\n");
               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;
               uint16_t TOTAL_LENGTH = ntohs(ipLayer->getIPv4Header()->totalLength) + 14;

               std::string ftp_command = "";

               printf("TCP header len is %d\n", my_ntohs(packet[46]) * 4);
               printf("start index is %d\n", start);
               printf("total length is %d\n", TOTAL_LENGTH);
               printf("\nRequest: ");

               for (int i = payload_start; i<total_length; i++) {
                  printf("%c", packet[i]);
               }
               int cmd_flag = 0;
               printf("\nResponse Arg : ");
               for (int i = start; i < TOTAL_LENGTH; i++) {
                  if (packet[i] == ' ') {
                     ftp_request_cmd = ftp_command;
                     ftp_command = "";
                     cmd_flag = 1;
                     continue;
                  }
                  if (packet[i] == 0x0d) break; // \r을 만나면 바로 종료
                  ftp_command += (u_char) packet[i];
                  printf("%c", packet[i]);
               }
               printf("\n");
               std::cout << ftp_command << '\n';
               if (cmd_flag == 1) { // 인자가 2개일 경우...
                  ftp_request_arg = ftp_command;
                  FTP_QUEUE.push({ ftp_request_cmd, ftp_command });
                  FTP_LOG.push_back({ 1, ftp_request_cmd + " " + ftp_command });
               } else {
                  ftp_request_cmd = ftp_command;
                  ftp_request_arg = "";
                  FTP_QUEUE.push({ ftp_request_cmd, ftp_request_arg });
                  FTP_LOG.push_back({ 1, ftp_command });
               }

               Json::Value temp;
               temp["Packet Number"] = packet_num++;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP";
               temp["Request cmd"] = ftp_request_cmd + " " + ftp_request_arg;

               root.append(temp);

            } else if (src_port == ftp_data_port) { // 받는 FTP-DATA 패킷이라면...

               FTP_LOG.push_back({ 2, ftp_request_cmd + " " + ftp_request_arg });

               Json::Value temp;
               temp["Packet Number"] = packet_num++;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP-DATA";

               root.append(temp);

               if (ftp_request_cmd != "RETR") continue;

               printf("\n[ FTP DATA Packet ] - (server -> client)\n");

               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;

               printf("start index is %d\n", start);
               printf("total length is %d\n", total_length);

               for (int i = start; i < total_length; i++) {
                  ftp_data[ftp_data_idx++] = packet[i];
               }
               ftp_data_size += total_length - start;

            } else if (dst_port == ftp_data_port) { // 보내는. 업로드하는 FTP-DATA 패킷이라면...

               FTP_LOG.push_back({ 3, ftp_request_cmd + " " + ftp_request_arg });

               Json::Value temp;
               temp["Packet Number"] = packet_num++;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP-DATA";

               root.append(temp);

               if (ftp_request_cmd != "STOR") continue;
               printf("\n[ FTP DATA Packet ] - (client -> server)\n");

               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;

               printf("start index is %d\n", start);
               printf("total length is %d\n", total_length);

               for (int i = start; i < total_length; i++) {
                  ftp_data[ftp_data_idx++] = packet[i];
               }
               ftp_data_size += total_length - start;
            }
         }
      }
      // If It's HTTP Packet Print method, URI, host, user-agent ...
      if (httpRequestLayer != NULL) {
         printf("\n[ HTTP Packet ]\n");
         printf("\nHTTP method: %s\n", printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()).c_str());
         printf("HTTP URI: %s\n", httpRequestLayer->getFirstLine()->getUri().c_str());
         printf("HTTP host: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue().c_str());
         printf("HTTP user-agent: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue().c_str());
         //printf("HTTP cookie: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue().c_str());
         printf("HTTP full URL: %s\n", httpRequestLayer->getUrl().c_str());

         Json::Value temp;
         temp["Packet Number"] = packet_num++;
         temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
         temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
         temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
         temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
         temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
         temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
         temp["Protocol"] = "HTTP";
         temp["HTTP method"] = printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()).c_str();
         temp["HTTP URI"] = httpRequestLayer->getFirstLine()->getUri().c_str();
         temp["HTTP host"] = httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue().c_str();
         temp["HTTP user-agent"] = httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue().c_str();
         //temp["HTTP cookie"] = httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue().c_str();
         temp["HTTP full URL"] = httpRequestLayer->getUrl().c_str();


         http.append(temp);

         string http_cmd = printHttpMethod(httpRequestLayer->getFirstLine()->getMethod());
         if (http_cmd == "GET") {
            char* http_temp = new char[1000];
            strcpy(http_temp, httpRequestLayer->getUrl().c_str());

            char* tok = strtok(http_temp, ",");

            char* http_tok = strtok(http_temp, "/");
            vector<string> http_tok_arr;
            http_tok_arr.clear();
            while (http_tok != NULL) {
               http_tok_arr.push_back((string) http_tok);
               http_tok = strtok(NULL, "/");
            }
            http_get_filename = http_tok_arr[http_tok_arr.size() - 1];
            cout << http_get_filename << '\n';
            for (int i = 0; i < http_get_data_port.size(); i++) {
               //HTTP 에서 추출한 데이터 파일 형태로 추출
               if (http_get_data_port[i].first == src_port) {
                  ofstream file;
                  string http_file_path = "HTTP_directory/";
                  http_file_path = http_file_path+ http_get_data_port[i].second;
                  file.open(http_file_path, ios::binary);
                  file.write((const char*) http_data[i], http_data_idx[i]);
                  file.close();
                  memset(http_data[i], 0, sizeof(http_data[i]));
                  http_get_data_port[i].first = -1;
               }
               
            }
            http_get_data_port.push_back({ src_port, http_get_filename });
         }
      }
   }

   for (int i = 0; i < FTP_LOG.size(); i++) {
      if (FTP_LOG[i].first == 1) { // FTP Request
         cout << "Request : " << FTP_LOG[i].second << "\n";
      } else if (FTP_LOG[i].first == 2) { // FTP-DATA (server -> client)
         cout << "FTP-DATA [server -> client] : (" << FTP_LOG[i].second << ")\n";
      } else if (FTP_LOG[i].first == 3) { // FTP-DATA (client -> server)
         cout << "FTP-DATA [client -> server] : (" << FTP_LOG[i].second << ")\n";
      } else {
         cout << "Response : " << FTP_LOG[i].first << " " << FTP_LOG[i].second << '\n';
      }
   }

   /*
   while (!FTP_QUEUE.empty()) {
      cout << FTP_QUEUE.front().first << " " << FTP_QUEUE.front().second << "\n";
      FTP_QUEUE.pop();
   }
   */


   cout << "\n\n\n\n\n";

   //===================================BOB9_FINAL_WORK==============================================
   for(int i =0; i< vec_by_IP.size(); i++){
      cout <<"["<< vec_by_IP[i].IP_address << "]" << endl;
      cout << "send_packet_number  :  " << vec_by_IP[i].send_packet_num<< endl;
      cout << '{';
      for(int j =0 ; j< vec_by_IP[i].send_packet_byte.size(); j++){
         cout << vec_by_IP[i].send_packet_byte[j] << " bytes, ";
      }
      cout << '}' << endl;
      cout << "receive_packet_number  :  " << vec_by_IP[i].receive_packet_num<< endl;
      cout << '{';
      for(int j =0 ; j< vec_by_IP[i].receive_packet_byte.size(); j++){
         cout << vec_by_IP[i].receive_packet_byte[j] << " bytes, ";
      }
      cout << '}' << endl << endl;
   }
   //=================================================================================================






  //JSON 쓰기
   char ftp_file_path[111111] = "FTP_directory/";
   strcat(ftp_file_path, "log_ftp.json");
   std::ofstream ftpFile(ftp_file_path, ios::out);
   ftpFile << root;
   ftpFile.close();


   char http_file_path[111111] = "HTTP_directory/";
   strcat(http_file_path, "log_http.json");
   std::ofstream httpFile(http_file_path, ios::out);
   httpFile << http;
   httpFile.close();


   char smtp_file_path[111111] = "SMTP_directory/";
   strcat(smtp_file_path, "log_smtp.json");
   std::ofstream smtpFile(smtp_file_path, ios::out);
   smtpFile << smtp;
   smtpFile.close();


   reader->close();

  
};

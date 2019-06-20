#include<cstdlib>
#include<string.h>
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<mysql/mysql.h>
#include<string>
#include <time.h>
#include<pthread.h>

using namespace std;

string nodename = "'/scut/hnlg4'";
MYSQL *conn;
int executesql(const char * sql) {
    /*query the database according the sql*/
    if (mysql_real_query(conn, sql, strlen(sql))) // 如果失败
        return -1; // 表示失败

    return 0; // 成功执行
}

void* uploadMysql(void*)
{

    char server[] = "121.15.171.84"; //server's address
    char user[] = "root"; //server's name
    char password[] = "123"; //password
    char database[] = "dataDB";  //the name of database ,mysql connection attribute



    conn = mysql_init(NULL); //initialize mysql
    if (!mysql_real_connect(conn, server,user, password, database,3306, NULL, 0)) //connect to local mysql MYSQL,server name,user name, password, port
    {

        printf("mysql connect error!\n");
        exit(-1);
    }
    clock_t start = clock();
    while(1)
    {
        if((clock() - start)/CLOCKS_PER_SEC >=30)
        {
            system("nfdc status report > RIB.txt");
            system("route > route.txt");



            Json::Value root;//json 对象
            //root["type"] = Json::Value(31);
            Json::Value route;


            char line[5000];
            memset(line,0,sizeof(line));



            std::fstream fin("RIB.txt",std::ios::in);
            std::fstream fin2("route.txt",std::ios::in);

            char buf[300];
            while(fin.getline (line, 4999))
            {
                //cout<<line<<endl;
                if(strcmp(line,"FIB:") == 0)
                {
                    while(1)
                    {
                        fin.getline (line, 4999);
                        if(strcmp(line,"RIB:") == 0)
                            break;
                        string s(line);
                        s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                        int t = s.find("nexthop",0);
                        string str = s.substr(0,t);
                        //cout<<str<<endl;

                        root["FIB"].append(str);
                    }
                }
                if(strcmp(line,"CS information:") == 0)
                {
                    while(1)
                    {
                        fin.getline (line, 4999);
                        if(strcmp(line,"Strategy choices:") == 0)
                            break;

                        string s(line);
                        s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                        int t = s.find("=",0);
                        string str = s.substr(t+1);
                        //cout<<"CS:"<<str<<endl;
                        root["CS"].append(str);
                    }
                    break;
                }
            }
            int temp = 2;
            Json::Value routeINFO;
            while(temp-- > 0) fin2.getline (line, 4999);
            while(fin2.getline(line, 4999))
            {
                string s(line);
                int t = s.find(" ",0);

                string sip = s.substr(s.find_first_not_of(' '),t);
                s = s.substr(t);
                routeINFO["IP"] = sip;

                s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                t = s.find(" ",0);
                string gw = s.substr(s.find_first_not_of(' '),t);
                s = s.substr(t);
                routeINFO["GW"] = gw;

                s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                t = s.find(" ",0);
                string mask = s.substr(s.find_first_not_of(' '),t);
                s = s.substr(t);
                routeINFO["MASK"] = mask;

                s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                t = s.find(" ",0);
                s = s.substr(t);

                s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                t = s.find(" ",0);
                s = s.substr(t);

                s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                t = s.find(" ",0);
                s = s.substr(t);

                s = s.substr(s.find_first_not_of(' '),s.find_last_not_of(' ')+1);
                t = s.find(" ",0);
                s = s.substr(t);
                string interface= s.substr(s.find_first_not_of(' '),s.find_last_not_of(' '));
                routeINFO["INTERFACE"] = interface;
                root["route"].append(routeINFO);
                //if(temp == 2) break;
            }

            /*Json::Value array;
            //array["array"] = Json::Value(root);
            Json::StyledWriter styled_writer;
            std::cout << styled_writer.write(root) << std::endl;*/

            string del = "delete from FIB where node="+nodename;
            if (executesql(del.data()))
                printf("ERROR:delete FIB error!\n");

            del = "delete from RIB where node="+nodename;
            if (executesql(del.data()))
                printf("ERROR:delete CS error!\n");

            del = "delete from ROUTE where node="+nodename;
            if (executesql(del.data()))
                printf("ERROR:delete ROUTE error!\n");
            del = "delete from CS where node="+nodename;
            if (executesql(del.data()))
                printf("ERROR:delete CS error!\n");

            int FIBsize = root["FIB"].size();
            if(FIBsize > 0)
            {
                for(int i = 0; i < FIBsize; i++)
                {
                    string name = root["FIB"][i].asString();
                    string sqls = "insert into FIB(node,name) values("+nodename+",'"+name+"');";

                    if (executesql(sqls.data()))
                        cout<<sqls,printf("ERROR:insert FIB error!\n");
                }

            }

            int CSsize = root["CS"].size();
            if(CSsize > 0)
            {
                string sqls = "insert into CS values("+nodename+",";
                for(int i = 0; i < CSsize-1; i++)
                {
                    string name = root["CS"][i].asString();
                    if(i == 2 || i ==1)
                    {
                        if(name == "on")
                            sqls = sqls + "1"+",";
                        else
                            sqls = sqls + "0"+",";
                        continue;
                    }
                    sqls = sqls + name+",";

                }
                string name = root["CS"][CSsize-1].asString();
                sqls = sqls + name+");";
                if (executesql(sqls.data()))
                    cout<<sqls,printf("ERROR:insert CS error!\n");
            }



            int routesize = root["route"].size();
            if(routesize > 0)
            {
                for(int i = 0; i < routesize; i++)
                {
                    string sqls = "insert into ROUTE(node,IP,GW,MASK,INTERFACE) values("+nodename+",'";
                    string name = root["route"][i]["IP"].asString();

                    sqls = sqls + name+"','";
                    name = root["route"][i]["GW"].asString();

                    sqls = sqls + name+"','";
                    name = root["route"][i]["MASK"].asString();

                    sqls = sqls + name+"','";
                    name = root["route"][i]["INTERFACE"].asString();

                    sqls = sqls + name+"');";
                    if (executesql(sqls.data()))
                        cout<<sqls,printf("ERROR:insert ROUTE error!\n");

                }
            }




            printf("********************** over ! *****************************\n");
            fin.close();
            fin2.close();
            start = clock();
        }

    }
    mysql_close(conn);
}

int main()
{



    pthread_t tomysql;
    pthread_attr_t attr1; // the attributes of thread
    int s1 =pthread_attr_init(&attr1); //initialize
    if( s1 !=0) {
        printf("ERROR:pthread_attr_init\n");
    }


    if(pthread_create(&tomysql,&attr1,uploadMysql,NULL) !=0 ){

        printf("ERROR:create pthread1 error!\n");

    }

    pthread_join(tomysql,NULL);



    return 0;
}

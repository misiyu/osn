// Created by liuxinwei on 2019/6/11.
//


#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <jsoncpp/json/json.h>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <fstream>

#include<boost/asio.hpp>
#include<sqlite3.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace ndn ;
using namespace std ;

const string regP = "/RP";
const char* trustList = "tlist.json";
const char* trustdb = "tlist.db";

unordered_map<string,vector<int>> outMap;
unordered_map<string,int> signId;
unordered_map<int,string> idSign;

using namespace boost;

class Transfer : noncopyable
{
public:
    Transfer()
    {
        opensql3();
	add_prefix();
    }
    ~Transfer()
    {
        sqlite3_close(db);
    }
     void add_prefix()
    {
	    cout << "load data prefix " << endl ;
	    std::ifstream infile("./dataprefix.conf", ios::binary);
	    if(!infile.is_open()){
		    cout << "can not find ./dataprefix.conf " << endl;
		    exit(1);
	    }
	    string line ;
	    while(getline(infile,line))
	    {
		    this->dataPrefix.push_back(line);
		    cout<<"data listen on: "<<line<<endl;
	    }
    }   

    void run()
    {
	for(int i = 0; i < dataPrefix.size(); i++)
	{
		string tmp = regP + dataPrefix[i];
		m_face.setInterestFilter(tmp.c_str(),
				bind(&Transfer::onInterest_reg, this, _1, _2),
				RegisterPrefixSuccessCallback(),
				bind(&Transfer::onRegisterFailed, this, _1, _2));
		cout<<"reg listen on :"<<tmp<<endl;
	}

 	for(int i = 0; i < dataPrefix.size(); i++)
		m_face.setInterestFilter(dataPrefix[i].c_str(),
				bind(&Transfer::onInterest, this, _1, _2),
				RegisterPrefixSuccessCallback(),
				bind(&Transfer::onRegisterFailed, this, _1, _2)); 
	     m_face.processEvents();

    }

private:
    void opensql3(){
        int rc;

        rc = sqlite3_open(trustdb,&this->db);
        if( rc ){
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            exit(0);
        }else{
            fprintf(stderr, "Opened database successfully\n");
        }

    }
    string wgh_get_timestamp(){
	timeval start;  
	gettimeofday(&start, NULL); 
	return ctime(&start.tv_sec);
    }
    void lxw_sendm(string msg)
    {
	string ip("121.15.171.86");
	boost::asio::io_service ios;
	boost::asio::ip::tcp::socket socket(ios);
	boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address_v4::from_string(ip.c_str()),8010);
	boost::system::error_code ec;
	socket.connect(ep,ec);
	if(ec){
	    cout<<boost::system::system_error(ec).what()<<endl;
	   // exit(0);
	    return ;
	}
	int len = msg.size();
	string lens((char*)(&len),sizeof(int));
	socket.send(boost::asio::buffer(lens));
	socket.send(boost::asio::buffer(msg));
	socket.close();
    }
    string getPublikkty(){
	string res = "";
	for(int i = 0; i < 4; i++)
	{
	    clock_t start = clock();
	    srand((unsigned)start);
	    int ran = rand();
	    cout<<"random number :" << ran<<endl;
	    char filename[10];
	    sprintf(filename,"%d.txt",1);
	    FILE *fp = fopen(filename,"a+");
	    fprintf(fp,"%d",ran);
	    fclose(fp);

	    FILE *stream;
	    string cmd = "md5sum " + string(filename);
	    stream = popen(cmd.c_str(),"r");
	    char buf[1024];
	    fread(buf,sizeof(char),sizeof(buf),stream);
	    pclose(stream);
	    printf("buf : %s\n",buf);
	    res += string(buf, 32);
	}
	return res;
    }
    void onInterest_reg(const InterestFilter& filter, const Interest& interest)
    {
        string iName = interest.getName().toUri();
        int tmp = iName.find_last_of('/');
        string tsign = iName.substr(0, tmp);
        
	tmp = tsign.find_last_of('/');
        string sign = tsign.substr(tmp+1, tsign.length()-tmp-1);

        Name dataName(interest.getName());

        // Create Data packet
        std::shared_ptr<Data> data = make_shared<Data>();
        data->setName(dataName);
        data->setFreshnessPeriod(10_s); // 10 seconds

        //query sql
        char *zErrMsg = 0;
        char **dbResult;
        int nRow, nColumn;

        string sql1 = "select * from trustlist where sign = '" + sign + "';";
        cout<<"sql1:"<<sql1<<endl;

        int rc = sqlite3_get_table(this->db, sql1.c_str(), &dbResult,  &nRow, &nColumn,  &zErrMsg);
        if(rc == SQLITE_OK)
        {
            if(nRow != 0)
            {
                cout<<"sign has been inserted!"<<endl;
                static const string content = "in";
                data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());
                sqlite3_free_table(dbResult);
            }
            else
            {
                sqlite3_free_table(dbResult);
                //send interest
                string sql2 = "insert into trustlist(sign) values('" + sign + "');";
                cout<<"sql2:"<<sql2<<endl;

                rc = sqlite3_exec(this->db, sql2.c_str(), NULL, NULL, &zErrMsg);
                if (rc == SQLITE_OK)
                {
                    cout<<"insert OK! "<<endl;
                    static const string content = "yes";
                    data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());
		  
  		    string md5 = getPublikkty();
		    cout<<"md5 "<<md5<<endl;
		    Json::Value root;
		    root["type"]="NDN-IP";
		    root["data"]["command"]="Log";
		    root["data"]["QueryCode"]= 22;
		    root["data"]["pubkey"]=md5;
		    root["data"]["real_msg"] = sign;
		    root["data"]["timestamp"] = wgh_get_timestamp();

		    string log = root.toStyledString();
		    lxw_sendm(log);
                }
                else
                {
                    fprintf(stderr, "SQL error: %s\n", zErrMsg);
                    sqlite3_free(zErrMsg);
                    static const string content = "no";
                    data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());
                }
                // Sign Data packet with default identity
            }

        }
        else
        {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            exit(0);
        }




        m_keyChain.sign(*data);

        m_face.put(*data);
    }

    void onInterest(const InterestFilter& filter, const Interest& interest)
    {
        std::cout << "<< I: " << interest.getName() << std::endl;

        // Create new name, based on Interest's name
        string iName = interest.getName().toUri();
        string sigName;

        int tmp1 = iName.find_first_of('~');
        if(tmp1 == -1)
        {
            cout<<"the name must have ~ component"<<endl;
            exit(0);
        }

        string versionName = "";

        int tmp3 = iName.find_first_of('/',tmp1+2);
        if(tmp3 == -1)
        {
            sigName = iName.substr(tmp1+2 , iName.length()-tmp1-2);
        }
        else
        {
            sigName = iName.substr(tmp1+2 , tmp3-tmp1-2);
            versionName = iName.substr(tmp3,iName.length()-tmp3);
        }
        cout<<"sigName: "<<sigName<<endl;

        unordered_map<string,int>::iterator it;
        it = signId.find(sigName);

        if(it == signId.end())
        {
            //query sql
            char *zErrMsg = 0;
            char **dbResult;
            int nRow, nColumn;

            string sql = "select * from trustlist where sign = '" + sigName + "';";
            cout<<"sql:"<<sql<<endl;

            int rc = sqlite3_get_table(this->db, sql.c_str(), &dbResult,  &nRow, &nColumn,  &zErrMsg);

            //send interest
            if (rc == SQLITE_OK)
            {

                if(nRow >1)
                {
                    cout<<"select sql error!"<<endl;
                    sqlite3_free_table(dbResult);
                    return;
                }
                if(nRow == 0)
		{
                    cout << "ERROR:**********illegal sign!*****************"<<endl;
		    Name dataName(interest.getName());
		    static const std::string content = "HELLO KITTY";

		    // Create Data packet
		    std::shared_ptr<Data> data = make_shared<Data>();
		    data->setName(dataName);
		    data->setFreshnessPeriod(10_s); // 10 seconds
		    data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());

		    m_keyChain.sign(*data);
		    m_face.put(*data);
		    cout<<data->getContent().value()<<endl;
		}
		else
                {
                    //legal
                    int tmp2 = iName.find_first_of('/', 1);
                    string outI = iName.substr(tmp2, tmp1 - tmp2+1);

                    int index = atoi(dbResult[nColumn]);
                    cout<<"index : "<<index<<endl;

                    signId[sigName] = index;
                    idSign[index] = sigName;

                    //save the source sign
                    unordered_map<string,vector<int>>::iterator iter;

                    iter = outMap.find(outI);

                    if(iter != outMap.end())
                    {
                        //iter->second.push_back(index);
                        vector<int> & tvector = iter->second;
                        vector<int>::iterator result = find( tvector.begin( ), tvector.end( ), index );
                        if(result == tvector.end())
                        {
                            tvector.push_back(index);
                        }
                    }
                    else
                    {
                        outMap.insert(unordered_map<string,vector<int>>::value_type(outI,vector<int>(1,index)));
                    }

                    cout<<"outI: "<<outI<<endl;
                    outI += versionName;
                    //express interest
                    cout << "express interest : " << outI << endl ;
                    Interest outInterest(Name(outI.data()));
                    outInterest.setInterestLifetime(2_s);
                    this->m_face.expressInterest(outInterest,
                                                 bind(&Transfer::onData,this,_1,_2),
                                                 bind(&Transfer::onNack,this,_1,_2),
                                                 bind(&Transfer::onTimeout,this,_1));
                }



            }
            else
            {

                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            }
            sqlite3_free_table(dbResult);

        }
        else
        {
            //legal and cached
            int index = it->second;

            //legal
            int tmp2 = iName.find_first_of('/', 1);
            string outI = iName.substr(tmp2, tmp1 - tmp2+1);

            cout<<"index : "<<index<<endl;


            //save the source sign
            unordered_map<string,vector<int>>::iterator iter;

            iter = outMap.find(outI);

            if(iter != outMap.end())
            {
                //iter->second.push_back(index);
                vector<int> & tvector = iter->second;
                vector<int>::iterator result = find( tvector.begin( ), tvector.end( ), index );
                if(result == tvector.end())
                {
                    tvector.push_back(index);
                }
            }
            else
            {
                outMap.insert(unordered_map<string,vector<int>>::value_type(outI,vector<int>(1,index)));
            }

            cout<<"outI: "<<outI<<endl;
            outI += versionName;
            //express interest
            cout << "express interest : " << outI << endl ;
            Interest outInterest(Name(outI.data()));
            outInterest.setInterestLifetime(2_s);
            this->m_face.expressInterest(outInterest,
                                         bind(&Transfer::onData,this,_1,_2),
                                         bind(&Transfer::onNack,this,_1,_2),
                                         bind(&Transfer::onTimeout,this,_1));
        }




    }


    void onRegisterFailed(const Name& prefix, const std::string& reason)
    {
        std::cerr << "ERROR: Failed to register prefix \""
                  << prefix << "\" in local hub's daemon (" << reason << ")"
                  << std::endl;
        m_face.shutdown();
    }

    void onData(const Interest& interest, const Data& data)
    {
        std::cout << "\nOn data : "<<data.getName() << std::endl;
        // Create Data packet

        string dName = data.getName().toUri();

        int tmp1 = dName.find_first_of('~');

        string tmpName = "";
        string tailName = "";

        if(tmp1 != dName.length()-1)
        {
            tmpName= dName.substr(0 , tmp1+1);


            tailName= dName.substr(tmp1+2,dName.length()-tmp1);
        }
        else
            tmpName += dName;

        cout<<"tmpName: "<<tmpName<<"  tail: "<<tailName<<endl;


        int vsize = outMap[tmpName].size();
        cout <<"the size is： "<<vsize<<endl;
        for(int i = 0; i < vsize; i++)
        {
            int index = outMap[tmpName][i];
            std::shared_ptr<Data> tmpdata = make_shared<Data>();
            string oriName;
            string tmps;

            unordered_map<int, string>::iterator it;
            it = idSign.find(index);

            if(it == idSign.end())
            {
                //query sql
                char *zErrMsg = 0;
                char **dbResult;
                int nRow, nColumn;
                string sql = "select * from trustlist where id = '" + to_string(index) + "';";
                cout<<"data sql:"<<sql<<endl;

                int rc = sqlite3_get_table(this->db, sql.c_str(), &dbResult,  &nRow, &nColumn,  &zErrMsg);
                if(rc != SQLITE_OK)
                {
                    fprintf(stderr, "SQL error: %s\n", zErrMsg);
                    sqlite3_free_table(dbResult);
                    sqlite3_free(zErrMsg);
                    break;
                }

                tmps = string(dbResult[nColumn+1]);
                idSign[index] = tmps;
                signId[tmps] = index;
                sqlite3_free_table(dbResult);

            }
            else
            {
                tmps = idSign[index];
            }



            //put data
           /* oriName = ListenPrefix + tmpName + '/' + tmps;
            if(tailName.length() !=0)
                oriName +='/' + tailName;
		*/
            oriName = tmpName + '/' + tmps;
	    if(tailName.length() !=0)
		oriName +='/' + tailName;
	    //tmpdata->setName(oriName);
            tmpdata->setFreshnessPeriod(10_s); // 10 seconds
            tmpdata->setContent(reinterpret_cast<const uint8_t*>(data.getContent().value()), data.getContent().value_size());

            // Sign Data packet with default identity
	    for(int i = 0; i < this->dataPrefix.size(); i++){
		    string tmpori = this->dataPrefix[i] + oriName;
		    Name tm(tmpori);
		    tmpdata->setName(tm);
		    m_keyChain.sign(*tmpdata);
		    m_face.put(*tmpdata);
	    }


        }

    }

    void onNack(const Interest& interest, const lp::Nack& nack)
    {
        //std::cout << "received Nack with reason " << nack.getReason()
        //<< " for interest " << interest << std::endl;
    }

    void onTimeout(const Interest& interest)
    {
        //std::cout << "Timeout " << interest << std::endl;
    }

private:
    Face m_face;
    KeyChain m_keyChain;

    vector<string> dataPrefix;
    sqlite3 *db;
};


int main(int argc, char** argv)
{
    Transfer tf;
    try {
        tf.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}

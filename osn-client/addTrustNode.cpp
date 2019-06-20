//
// Created by liuxinwei on 2019/6/12.
//
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <jsoncpp/json/json.h>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <sys/time.h>

using namespace ndn ;
using namespace std ;

const char* registerprefix = "/RP/";

class Register : noncopyable
{
public:
    Register(string sn, string ss)
    {
        signName = registerprefix + sn + "/" + ss +"/";
        timeval start;
        gettimeofday(&start,NULL);
        signName += to_string(start.tv_sec);
	//cout<<signName<<endl;
    }

    void run()
    {
        Interest interest(Name(signName.c_str()));
        interest.setInterestLifetime(2_s); // 2 seconds
        interest.setMustBeFresh(true);

        m_face.expressInterest(interest,
                               bind(&Register::onData, this,  _1, _2),
                               bind(&Register::onNack, this, _1, _2),
                               bind(&Register::onTimeout, this, _1));

//        std::cout << "Sending " << interest << std::endl;

        // processEvents will block until the requested data received or timeout occurs
        //m_face.processEvents();
    }

    void onData(const Interest& interest, const Data& data)
    {
	FILE * fp = fopen("lxw.txt","w+");
	if(fp == NULL){
	    cout<<"open lxw.txt failed!"<<endl;
	    exit(0);
	}
	
        unsigned char result[4];
        memcpy(result, data.getContent().value(), data.getContent().value_size());
        result[data.getContent().value_size()] = '\0';

        string tmps= (char*) result;
 //       cout << "\nresult : "<<tmps<<"  length is : "<<tmps.length()<<endl;
        if(tmps == "yes") {
	    cout << "insert OK!" << endl;
	    fprintf(fp,"insert OK!");
	}
        else if(tmps == "in"){
	    cout<<"has been inserted!"<<endl ;
	    fprintf(fp,"has been inserted!"); 
	}
        else {
	    cout << "insert failed! "<< endl;
	    fprintf(fp, "insert failed!");
	} 
    }

    void onNack(const Interest& interest, const lp::Nack& nack)
    {
        std::cout << "received Nack with reason " << nack.getReason()
                  << " for interest " << interest << std::endl;
    }

    void onTimeout(const Interest& interest)
    {
        std::cout << "Timeout " << interest << std::endl;
    }

    Face m_face;
    string signName;
};

int main(int argc, char** argv)
{
    if(argc < 5)
    {
        cout<<"Usage : ./main signdata"<<"   argc : "<<argc <<endl;
        exit(0);
    }
    string sname(argv[1]);
    string phone(argv[2]);
    string username(argv[3]);
    string key(argv[4]);

   // cout<<phone.length()<<endl;
    Register reg(sname,phone);
    reg.run();
//cout<<reg.signName<<endl;
        reg.m_face.processEvents();
    return 0;
}

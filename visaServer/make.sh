sudo apt install libmysqlclient-dev
g++ -g -o getCS  getCS.cpp -lmysqlclient -ljsoncpp -lpthread
nohup ./getCS &

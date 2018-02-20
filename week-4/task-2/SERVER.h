
#if !defined SERVER_H
#define SERVER_H

#include <list>

#include "ClientConnection.h"


class SERVER{

	private:
  		
  		int port;
  		int msock;
  		std::list<ClientConnection*> connection_list;

	public:

  		SERVER(int port = 21);
  		void run();
  		void stop();
};

#endif
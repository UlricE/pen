#include "config.h"
#include "conn.h"
#include "diag.h"
#include "idlers.h"
#include "server.h"

int idlers = 0, idlers_wanted = 0;

void close_idlers(int n)
{
	int conn;

	DEBUG(2, "close_idlers(%d)", n);
	for (conn = 0; n > 0 && conn < connections_max; conn++) {
		if (idler(conn)) {
			DEBUG(3, "Closing idling connection %d", conn);
			close_conn(conn);
			n--;
		}
	}
}

int add_idler(void)
{
#ifdef HAVE_LIBSSL
	int conn = store_conn(-1, NULL, -1);
#else
	int conn = store_conn(-1, -1);
#endif
	if (conn == -1) return 0;
	conns[conn].initial = server_by_roundrobin();
	if (conns[conn].initial == -1) {
		close_conn(conn);
		return 0;
	}
	if (!try_server(conns[conn].initial, conn)) {
		if (!failover_server(conn)) {
			close_conn(conn);
			return 0;
		}
	}
	idlers++;
	return 1;
}


#include <stdlib.h>
#include "pen.h"

/* circular doubly linked lists, used for pending and closing connections */

struct node {
        int value;       /* index into connection table */
        int prev;       /* back pointer */
        int next;       /* forward pointer */
};

static struct node *nodes;
static int nodes_max;

/* This finishes in almost-constant time if there are plenty of free nodes */
static int alloc_node(void)
{
        static int last_node = 0;
        int start = last_node;
        do {
                if (nodes[last_node].value == -1) return last_node;
                last_node = (last_node+1)%nodes_max;
        } while (last_node != start);
        return -1;      /* all nodes used */
}

/* Insert value into a new node. Return the resulting list. */
int dlist_insert(int list, int value)
{
        int new_node = alloc_node();
        if (new_node == -1) return -1;
        if (list == -1) {       /* empty */
		nodes[new_node].prev = new_node;
		nodes[new_node].next = new_node;
		
        } else {
                int prev = nodes[list].prev;
		nodes[prev].next = new_node;
		nodes[new_node].prev = prev;
		nodes[new_node].next = list;
		nodes[list].prev = new_node;
        }
        nodes[new_node].value = value;
        return new_node;
}

/* Remove a node from its list. Return the resulting list. */
int dlist_remove(int node)
{
        int prev, next;
        if (node == -1) return -1;
        nodes[node].value = -1;         /* mark as unused */
        if (nodes[node].next == node) { /* last node */
                return -1;              /* empty list */
        }
        prev = nodes[node].prev;
        next = nodes[node].next;
        nodes[prev].next = next;
        nodes[next].prev = prev;
        return next;
}

/* Free an entire list by marking all nodes as unused. */
void dlist_free(int list)
{
	int start = list;
	if (list == -1) return;
	do {
		nodes[list].value = -1;
		list = (list+1)%nodes_max;
	} while (list != start);
}

/* Return next node in the list. Valid even for freed nodes. */
int dlist_next(int node)
{
	return nodes[node].next;
}

int dlist_value(int node)
{
	return nodes[node].value;
}

/* Allocate enough nodes for all the doubly linked lists we'll ever need. */
void dlist_init(int size)
{
	int i;
	nodes_max = size;
	nodes = pen_malloc(nodes_max * sizeof *nodes);
	for (i = 0; i < size; i++) {
		nodes[i].value = -1;	/* unused */
	}
}


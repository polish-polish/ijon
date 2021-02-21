#ifndef _HAVE_IJON_MIN_H
#define _HAVE_IJON_MIN_H

#include "config.h"

#define IJON_MAX_INPUT_SIZE (64*1024)

typedef struct{
  char* filename;
  int slot_id;
  size_t len;
} ijon_input_info;


typedef struct{
  uint64_t max_map[MAXMAP_SIZE];
  ijon_input_info* infos[MAXMAP_SIZE];
  size_t num_entries;
	size_t num_updates;
  char* max_dir;
  int schedule_prob;
} ijon_min_state;

struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

typedef struct ijon_rule{
	int s_offset;
	u8* s_chunk;
	int s_len;
	int t_offset;
	u8* t_chunk;
	int t_len;
	struct ijon_rule * next;
} ijon_rule;

extern ijon_rule * ijon_rules;
extern ijon_rule * candidate_rules;//link list

extern char * old_max_filename;

static void destroy_rule(ijon_rule * rule){
	free(rule->s_chunk);
	free(rule->t_chunk);
	rule->next=NULL;
	free(rule);
}

static void destroy_rules(ijon_rule * head_rule){
	ijon_rule * tmp=NULL;
	while(head_rule){
		tmp=head_rule;
		head_rule=head_rule->next;
		destroy_rule(tmp);
	}
}

static void insert_rules_to_ijon_rules(ijon_rule * rule_head){
	if(!rule_head) return;

	if(!ijon_rules){
		ijon_rules=rule_head;
		return;
	}
	ijon_rule * rule_tail=rule_head;
	while(rule_tail->next){
		rule_tail=rule_tail->next;
	}
	rule_tail->next=ijon_rules;
	ijon_rules=rule_head;
}



typedef struct linked_int{
	int v;
	int idx;
	struct linked_int *next;
}linked_int;

extern linked_int * slots_focused;




ijon_min_state* new_ijon_min_state();

u8 ijon_should_schedule(ijon_min_state* self);

ijon_input_info* ijon_get_input(ijon_min_state* self);

int ijon_update_max(ijon_min_state* self, shared_data_t* shared, uint8_t* data, size_t len, u32 parent_id);


#endif

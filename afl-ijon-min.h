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

static struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

ijon_min_state* new_ijon_min_state();

u8 ijon_should_schedule(ijon_min_state* self);

ijon_input_info* ijon_get_input(ijon_min_state* self);

int ijon_update_max(ijon_min_state* self, shared_data_t* shared, uint8_t* data, size_t len, u32 parent_id,u32 *p_extras_cnt,struct extra_data** p_extras);


#endif

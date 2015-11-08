#include <pteid/pteiddefines.h>


typedef struct
{
	char name[PTEID_MAX_NAME_LEN];
	char numBI[PTEID_MAX_NUMBI_LEN];
} UserData;

int getUserData(UserData *data);
#include <stdio.h>
#include <stdlib.h>
#include <pteid/pteiddefines.h>
#include <pteid/pteidlib.h>


static void
pteiderror ( char * msg, long code )
{
    fprintf ( stderr, "Error in %s: (%ld)\n",
    		msg, /*PTEID_errorString ( code ),*/ code );
}

int 
getUserData(UserData *data)
{
	long ret;
    PTEID_ID pteid_id;

	ret = PTEID_Init ( 0 );
	if (ret != PTEID_OK) {
		pteiderror ( "PTEID_Init", ret );
	}
	
	ret = PTEID_SetSODChecking(0);
	if (ret != PTEID_OK) {
		pteiderror ( "PTEID_SetSODChecking", ret );
	return 0;
	}

	ret = PTEID_GetID ( &pteid_id );
	if (ret != PTEID_OK) {
		pteiderror ( "PTEID_GetID", ret );
	}
	
	ret = PTEID_Exit ( 0 );
	if (ret != PTEID_OK) {
		pteiderror ( "PTEID_Exit", ret );
	}
	
	strncpy(data->name, pteid_id.name, PTEID_MAX_NAME_LEN);
	data->name[PTEID_MAX_NAME_LEN -1] = '\0';
	strncpy(data->numBI, pteid_id.numBI, PTEID_MAX_NUMBI_LEN);
	data->numBI[PTEID_MAX_NUMBI_LEN -1] = '\0';

	return 0;
}
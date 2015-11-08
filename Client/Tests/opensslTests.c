#include <openssl/dh.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#define PRIME_LEN 256 //bits
#define GENERATOR 2 // or 5, openssl
int
main(void)
{
	DH *param;
	DH *vazia;
	unsigned char *keyParam;
	unsigned char *keyVazia;

	printf("Criando as estruturas!\n");
	//criar as estruturas de dados
	param = DH_generate_parameters(PRIME_LEN, GENERATOR, NULL, NULL);//com parametros
	vazia = DH_new();//vazia

	printf("Com parametros: \n");
	DHparams_print_fp(stdout, param);

	printf("O valor de g: ");
	BN_print_fp(stdout, param->g);
	printf("\n");

	printf("O valor de p: ");
	BN_print_fp(stdout, param->p);
	printf("\n");


	printf("\n\nAplicando DH_generate_key!\n");
	DH_generate_key(param);


	printf("Com parametros: \n");
	printf("O valor de g: ");
	BN_print_fp(stdout, param->g);
	printf("\n");

	printf("O valor de p: ");
	BN_print_fp(stdout, param->p);
	printf("\n");

	printf("O valor de pub_key: ");
	BN_print_fp(stdout, param->pub_key);
	printf("\n");

	printf("O valor de priv_key: ");
	BN_print_fp(stdout, param->priv_key);
	printf("\n");


	printf("\n\nVazia, que preenchida com p e g da anterior: \n");

	vazia->g = BN_dup(param->g);
	vazia->p = BN_dup(param->p);
	DHparams_print_fp(stdout, vazia);

	printf("Aplicando à vazia DH_generate_key!\n");
	DH_generate_key(vazia);

	printf("Com parametros: \n");
	printf("O valor de g: ");
	BN_print_fp(stdout, vazia->g);
	printf("\n");

	printf("O valor de p: ");
	BN_print_fp(stdout, vazia->p);
	printf("\n");

	printf("O valor de pub_key: ");
	BN_print_fp(stdout, vazia->pub_key);
	printf("\n");

	printf("O valor de priv_key: ");
	BN_print_fp(stdout, vazia->priv_key);
	printf("\n");

	printf("Calculando o segredo comum: \n");
	//preparar espaco
	keyParam = (char *) malloc(DH_size(param));
	keyVazia = (char *) malloc(DH_size(vazia));

	DH_compute_key(keyParam, param->pub_key, vazia);
	DH_compute_key(keyVazia, vazia->pub_key, param);

	printf("O valor de keyParam: %.*s.\n", DH_size(param), keyParam);
	printf("O valor de keyVazia: %.*s.\n", DH_size(vazia), keyVazia);

	DH_free(param);
	DH_free(vazia);

	return 0;
}

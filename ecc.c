#include "ecc.h"


void init_point(point **p) 
{
	*p = (point*) malloc(sizeof(point));
	mpz_init((*p)->x);
	mpz_init((*p)->y);
}


void destroy_point(point *p)
{
	if (p) {
		mpz_clears(p->x, p->y, NULL);
		free(p);
		p = NULL;
	}
}


point* ecc_scalar_mul(elliptic_curve *ec, mpz_t m, point *p) {

	if (mpz_cmp_ui(m, 1) == 0) {
		return p;
	} else if (mpz_even_p(m) == 0) {
		mpz_sub_ui(m, m, 1);
		return ecc_addition(ec, p, ecc_scalar_mul(ec,m,p));
	} else {
		mpz_div_ui(m, m, 2);
		return ecc_scalar_mul(ec, m, ecc_doubling(ec, p));
	}
}


point* ecc_doubling(elliptic_curve *ec, point *p)
{
	point *r = malloc(sizeof(point));
	mpz_init(r->x);
	mpz_init(r->y);
	mpz_mod(p->x, p->x, ec->p);
	mpz_mod(p->y, p->y, ec->p);
	mpz_t temp, slope;
	mpz_init(temp);
	mpz_init_set_ui(slope, 0);
	mpz_mul_ui(temp, p->y, 2);
	mpz_invert(temp, temp, ec->p);
	mpz_mul(slope, p->x, p->x);
	mpz_mul_ui(slope, slope, 3);
	mpz_add(slope, slope, ec->a);
    mpz_mul(slope, slope, temp);
	mpz_mod(slope, slope, ec->p);
	mpz_mul(r->x, slope, slope);
	mpz_sub(r->x, r->x, p->x);
	mpz_sub(r->x, r->x, p->x);
	mpz_mod(r->x, r->x, ec->p);
	mpz_sub(temp, p->x, r->x);
	mpz_mul(r->y, slope, temp);
	mpz_sub(r->y, r->y, p->y);
	mpz_mod(r->y, r->y, ec->p);

	mpz_clears(temp, slope, NULL);
	return r;
}





point* ecc_addition(elliptic_curve *ec, point *p, point *q)
{
	point *r = malloc(sizeof(point));
	mpz_init(r->x);
	mpz_init(r->y);
	mpz_mod(p->x, p->x, ec->p);
	mpz_mod(p->y, p->y, ec->p);
	mpz_mod(q->x, q->x, ec->p);
	mpz_mod(q->y, q->y, ec->p);
	mpz_t temp,slope;
	mpz_init(temp);
	mpz_init_set_ui(slope, 0);
	mpz_sub(temp, p->x, q->x);
	mpz_mod(temp, temp, ec->p);
	mpz_invert(temp, temp, ec->p);
	mpz_sub(slope, p->y, q->y);
	mpz_mul(slope, slope, temp);
	mpz_mod(slope, slope, ec->p);
	mpz_mul(r->x, slope, slope);
	mpz_sub(r->x, r->x, p->x);
	mpz_sub(r->x, r->x, q->x);
	mpz_mod(r->x, r->x, ec->p);
	mpz_sub(temp, p->x, r->x);
	mpz_mul(r->y, slope, temp);
	mpz_sub(r->y, r->y, p->y);
	mpz_mod(r->y, r->y, ec->p);
	mpz_clears(temp, slope, NULL);
	return r;
}




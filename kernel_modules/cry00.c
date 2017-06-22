#include <linux/module.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/raid/pq.h>
static void *cry_alloc_pages(loff_t max_size, size_t *allocated_size, int last_warn)
{
	void *ptr;
	int order = 100;
	gfp_t gfp_mask = __GFP_RECLAIM | __GFP_NOWARN | __GFP_NORETRY;

	if (order)
		order = min(get_order(max_size), order);

	for (; order; order--) {
		ptr = (void *)__get_free_pages(gfp_mask, order);
		if (ptr) {
			*allocated_size = PAGE_SIZE << order;
			return ptr;
		}
	}

	/* order is zero - one page */

	gfp_mask = GFP_KERNEL;

	if (!last_warn)
		gfp_mask |= __GFP_NOWARN;

	ptr = (void *)__get_free_pages(gfp_mask, 0);
	if (ptr) {
		*allocated_size = PAGE_SIZE;
		return ptr;
	}

	*allocated_size = 0;
	return NULL;
}
static int __init hello_init(void)
{

	struct scatterlist sg[1];
	char *rbuf[2] = {NULL,};
	struct crypto_ahash *tfm;
	struct ahash_request *req;
        struct ahash_completion res;
        char *buf = "12345678";
        loff_t i_size, offset;
        i_size = 4096;
	size_t rbuf_size[2];

	tfm = crypto_alloc_ahash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)){
		printk("crypto_alloc_ahash:\n");
		return 0;
	}

	/* ... set up the scatterlists ... */

	req = ahash_request_alloc(tfm, GFP_ATOMIC);
	if (!req){
		printk("ahash_request_alloc:\n");
		return 0;
	}
        sg_init_one(&sg[0], buf, sizeof(buf));
	ahash_request_set_callback(req, 0, NULL, NULL);
        ahash_wait(crypto_ashah_init(req),&res);
        cry_alloc_pages(i_size,&rbuf_size[0],1);
	ahash_request_set_crypt(req, sg, NULL, 4096);

	if (crypto_ahash_digest(req)){

		printk("crypto_ahash_digest:\n");
		return 0;
	}
	if(result != NULL){ 
		printk("result : %s\n",result);
	}

	ahash_request_free(req);
	crypto_free_ahash(tfm);
	pr_info("hello\n");
	return 0;

}
static void __exit hello_exit(void)
{
	printk("hello,I am leaving\n");
}
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("sam");

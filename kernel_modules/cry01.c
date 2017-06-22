#include <linux/module.h>
#include <linux/hash.h>
#include <crypto/hash.h>
#include <linux/err.h>
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc init_sdesc(struct crypto_shash *alg)
{
    struct sdesc sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = (struct sdesc *)kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(struct crypto_shash alg,
             const unsigned char data, unsigned int datalen,
             unsigned char digest) {
    struct sdesc sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("trusted_key: can't alloc %s\n", hash_alg);
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc.shash, (const u8 *)data, (unsigned int)datalen, (u8 *)digest);
    kfree(&sdesc);
    return ret;
}
static int __init hello_init(void)
{
    struct crypto_shash alg;
    unsigned char data = 50;
    unsigned int datalen = sizeof(data);
    unsigned char digest;
    struct crypto_tfm base;

    alg.descsize = 60;
    alg.base = base;

    calc_hash();
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

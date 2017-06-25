#include <linux/module.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/slab.h>
LIST_HEAD(container_measurement);
struct container_entry{
	int container_id;
	int status;
	struct list_head later;

};
static struct container_entry *container_entry_create(int container_id, int status)
{
	struct container_entry *entry;
	entry = kmalloc(sizeof(*entry),GFP_KERNEL);
	if(entry == NULL){
		pr_err("OUT OF MEMORY ERROR creating container_entry\n");
		return -ENOMEM;
	}
	entry->container_id = container_id;
	entry->status = status;
	INIT_LIST_HEAD(&entry->later);
	list_add(&entry->later,&container_measurement);
	return entry;
}
static struct container_entry *container_entry_lookup(int container_id)
{
	struct container_entry *entry_p;
#if 0
	list_for_each(p, &container_measurement){
		entry_p = list_entry(p, struct container_entry,later);
		printk("Current: container_id:%d,status:%d\n", entry_p->container_id, entry_p->status);

	}
#endif
	list_for_each_entry(entry_p, &container_measurement,later){
		printk("Current: container_id:%d,status:%d\n", entry_p->container_id, entry_p->status);
		if( entry_p->container_id == container_id ){
			printk("Success: %d:status:%d\n", entry_p->container_id, entry_p->status);
			return entry_p;
		}
	}
        return NULL;


}
int container_entry_del(int container_id)
{
	struct container_entry *entry_p;
	
	entry_p = container_entry_lookup(container_id);
	if(entry_p == NULL){
		printk("There is no container_id: %d\n", container_id);
		return -1;
	}
	list_del(&entry_p->later);
	kfree(entry_p);
	return 0;

}
static int __init hello_init(void)
{
	struct container_entry *entry;
	int id;
	id = 200;
	
	entry = container_entry_create(100,0);
	entry = container_entry_create(200,1);
	container_entry_del(200);
	if ( container_entry_lookup(200) == NULL){

		printk("Sorry, container:%d does exist\n", id);
	}
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

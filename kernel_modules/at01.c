#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/ima.h>
#include <linux/integrity.h>
#include <security/integrity/ima/ima.h>
static int __init hello_init(void)
{
	pid_t nr = 2952;
	struct pid pid_rc;
	struct pid *pid_p = &pid_rc;
	struct task_struct task_rc;
	struct task_struct *task_p = &task_rc;
	struct files_struct files;
	struct files_struct *files_p = &files;
	struct fdtable *files_table;
	struct path files_path;
	char *cwd,*buf;
        struct ima_digest_data hash;

	int i = 0;	
	pr_info("hello\n");
	buf = (char *)kmalloc(100*sizeof(char),GFP_KERNEL);
	/*error todo*/
	if(buf == NULL){
		printk("kmalloc() error\n");
		return 0;

	}
#if 1
	pid_p = find_get_pid(nr);
	if(pid_p == NULL){
		printk("%d maybe exit\n",nr);        
		return -1;
	}
	task_p = pid_task(pid_p,0);
	printk("pid:%d\n",task_p->pid);
	files_p = task_p->files;
#endif
	//files_p = current->files;
	/*Comment*/
	files_table = files_fdtable(files_p);
#if 0	
	rcu_read_lock();
	struct file *p = files_p->fd_array[0];
	rcu_read_unlock();
#endif
#if 1
	while( files_table->fd[i] != NULL) {
		//printk("count is : %d\n",(files_p->fdtab.max_fds));
		files_path = files_table->fd[i]->f_path;
                ima_calc_file_hash(fiels_table-fd[i],hash);
		cwd = d_path(&files_path,buf,100*sizeof(char));		
		if(cwd == NULL){
			printk("d_path\n");
			kfree(buf);
			return 0;                
		}
		printk(KERN_ALERT "Open file with fd %d %s ",i,cwd);
		i = i + 1;
		printk("i=%d\n",i);
#if 0
		rcu_read_lock();
		p = files_p->fd_array[i];
		rcu_read_unlock();
#endif
	}
#endif
	kfree(buf);

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

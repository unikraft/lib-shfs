#include <uk/config.h>
#include <uk/print.h>
#include <uk/init.h>
#include <uk/essentials.h>
#include <shfs/shfs.h>

static const unsigned int bd_id[] = {
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	30, 31 };

static int _shfs_automount(void)
{
	int ret __maybe_unused;

	if (!uk_blkdev_count()) {
		uk_pr_err("No block device found. Failed to mount an SHFS volume.\n");
		goto err_out;
	}

	uk_pr_debug("Found %d block devices. Try to mount an SHFS volume...\n",
		    uk_blkdev_count());
	ret = mount_shfs(bd_id, uk_blkdev_count());
	if (ret < 0) {
		uk_pr_err("Failed to mount an SHFS volume: %d\n", ret);
		goto err_out;
	}

	uk_pr_info("SHFS volume '%s' mounted\n",
		   shfs_vol.volname);

	return 0;

err_out:
#if CONFIG_LIBSHFS_AUTOMOUNT_TRYONLY
	return 0;
#else
	return 1;
#endif
}

uk_rootfs_initcall(_shfs_automount);

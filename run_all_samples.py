from backup_restore_sample import BackupRestoreSample
from soft_delete_sample import SoftDeleteSample

if __name__ == "__main__":
    sample1 = BackupRestoreSample()
    sample1.run_samples()
    sample2 = SoftDeleteSample()
    sample2.run_samples()
